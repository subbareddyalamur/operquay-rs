#![forbid(unsafe_code)]

//! Multi-Database Explorer & SQL Guard (`crates/operquay-db`):
//! Object-oriented `DatabaseEngineDriver` polymorphism across PostgreSQL, `ClickHouse`,
//! `DuckDB` (native embedded columnar analytics + HTTP gateway), `MySQL`, and Redis,
//! with default TLS (`webpki-roots`), bounded query timeouts/rows, and strict `/api/db/query`
//! read-only guardrails.

pub mod clickhouse_driver;
pub mod columnar_engine;
pub mod dlp;
pub mod driver;
pub mod duckdb_driver;
pub mod mysql_driver;
pub mod postgres_driver;
pub mod redis_driver;
mod tls;

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use tokio::sync::RwLock;
use uuid::Uuid;

pub use clickhouse_driver::ClickHouseDriver;
pub use columnar_engine::EmbeddedColumnarEngine;
pub use driver::{
    is_write_sql, strip_leading_comments, validate_ident_quoted, DatabaseEngineDriver, DbColumnDef,
    DbConnectRequest, DbConnectResult, DbConnectionSpec, DbMutateResult, DbOperationError,
    DbQueryResult, DbRowUpdate, DbTableDef,
};
pub use duckdb_driver::DuckDbDriver;
pub use mysql_driver::MySqlDriver;
pub use postgres_driver::PostgresDriver;
pub use redis_driver::RedisDriver;

/// Polymorphic connection manager & SQL executor dispatching via `Arc<dyn DatabaseEngineDriver>`.
pub struct DbExplorer {
    drivers: HashMap<&'static str, Arc<dyn DatabaseEngineDriver>>,
    conns: RwLock<HashMap<String, DbConnectionSpec>>,
    cache: RwLock<HashMap<String, String>>,
}

impl Default for DbExplorer {
    fn default() -> Self {
        Self::new()
    }
}

impl DbExplorer {
    #[must_use]
    pub fn new() -> Self {
        let mut drivers: HashMap<&'static str, Arc<dyn DatabaseEngineDriver>> = HashMap::new();
        let all: [Arc<dyn DatabaseEngineDriver>; 5] = [
            Arc::new(PostgresDriver),
            Arc::new(ClickHouseDriver::new()),
            Arc::new(DuckDbDriver::new()),
            Arc::new(MySqlDriver::new()),
            Arc::new(RedisDriver),
        ];
        for drv in all {
            drivers.insert(drv.engine(), drv);
        }
        Self {
            drivers,
            conns: RwLock::new(HashMap::new()),
            cache: RwLock::new(HashMap::new()),
        }
    }

    pub fn register_driver(&mut self, driver: Arc<dyn DatabaseEngineDriver>) {
        self.drivers.insert(driver.engine(), driver);
    }

    #[must_use]
    pub fn supported_engines(&self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = self.drivers.keys().copied().collect();
        out.sort_unstable();
        out
    }

    fn resolve_driver(&self, engine: &str) -> Result<Arc<dyn DatabaseEngineDriver>, String> {
        let normalized = match engine.trim().to_ascii_lowercase().as_str() {
            "" | "pg" | "postgresql" | "postgres" => "postgres",
            "ch" | "clickhouse" => "clickhouse",
            "duck" | "duckdb" => "duckdb",
            "my" | "mysql" | "mariadb" => "mysql",
            "rd" | "redis" => "redis",
            other => {
                return Err(format!(
                    "unsupported database engine '{other}' (supported: {})",
                    self.supported_engines().join(", ")
                ));
            }
        };
        self.drivers
            .get(normalized)
            .cloned()
            .ok_or_else(|| format!("no driver registered for '{normalized}'"))
    }

    #[must_use]
    pub fn resolve_ssl_mode(req: &DbConnectRequest) -> String {
        if !req.ssl_mode.is_empty() {
            return req.ssl_mode.clone();
        }
        match req.ssl {
            Some(false) => "disable".to_owned(),
            Some(true) | None => "require".to_owned(),
        }
    }

    #[must_use]
    pub fn build_dsn(req: &DbConnectRequest) -> String {
        let spec = DbConnectionSpec {
            tenant: "default".into(),
            engine: req.engine.clone(),
            host: req.host.clone(),
            port: req.port,
            database: req.database.clone(),
            username: req.username.clone(),
            password: req.password.clone(),
            ssl_mode: Self::resolve_ssl_mode(req),
            cache_key: String::new(),
        };
        PostgresDriver::build_dsn(&spec)
    }

    fn build_spec(
        &self,
        tenant: &str,
        req: &DbConnectRequest,
    ) -> Result<
        (
            Arc<dyn DatabaseEngineDriver>,
            DbConnectRequest,
            DbConnectionSpec,
        ),
        String,
    > {
        let driver = self.resolve_driver(&req.engine)?;
        let norm = driver.normalize_request(req);
        let ssl_mode = Self::resolve_ssl_mode(&norm);
        let cache_key = format!(
            "{tenant}|{}|{}:{}|{}|{}|{ssl_mode}",
            driver.engine(),
            norm.host,
            norm.port,
            norm.database,
            norm.username
        );
        let spec = DbConnectionSpec {
            tenant: tenant.to_owned(),
            engine: driver.engine().to_owned(),
            host: norm.host.clone(),
            port: norm.port,
            database: norm.database.clone(),
            username: norm.username.clone(),
            password: norm.password.clone(),
            ssl_mode,
            cache_key,
        };
        Ok((driver, norm, spec))
    }

    pub async fn connect_and_inspect(
        &self,
        tenant: &str,
        req: &DbConnectRequest,
    ) -> Result<DbConnectResult, String> {
        let (driver, norm, spec) = self.build_spec(tenant, req)?;
        let (databases, tables) = driver.connect_and_inspect(&spec).await?;

        let id = Uuid::new_v4().to_string();
        let cache_key = spec.cache_key.clone();
        self.cache.write().await.insert(cache_key, id.clone());
        self.conns.write().await.insert(id.clone(), spec);

        Ok(DbConnectResult {
            connected: true,
            connection_id: id,
            engine: driver.engine().to_owned(),
            host: norm.host,
            port: norm.port,
            database: norm.database,
            databases,
            tables,
        })
    }

    pub async fn connect_or_reuse(
        &self,
        tenant: &str,
        req: &DbConnectRequest,
    ) -> Result<String, String> {
        let (_, _, spec) = self.build_spec(tenant, req)?;
        if let Some(existing_id) = self.cache.read().await.get(&spec.cache_key).cloned() {
            if let Some(entry) = self.conns.read().await.get(&existing_id) {
                if entry.tenant == tenant {
                    return Ok(existing_id);
                }
            }
        }
        let res = self.connect_and_inspect(tenant, req).await?;
        Ok(res.connection_id)
    }

    async fn lookup_spec(
        &self,
        tenant: &str,
        conn_id: &str,
    ) -> Result<(Arc<dyn DatabaseEngineDriver>, DbConnectionSpec), String> {
        let spec = self
            .conns
            .read()
            .await
            .get(conn_id)
            .filter(|e| e.tenant == tenant)
            .cloned()
            .ok_or_else(|| "unknown connection_id for tenant".to_owned())?;
        let driver = self.resolve_driver(&spec.engine)?;
        Ok((driver, spec))
    }

    #[must_use]
    pub fn is_write_sql(&self, sql: &str) -> bool {
        is_write_sql(sql)
    }

    pub fn validate_ident(&self, raw: &str, kind: &str) -> Result<String, String> {
        validate_ident_quoted(raw, kind, '"')
    }

    pub async fn query_readonly(
        &self,
        tenant: &str,
        conn_id: &str,
        sql: &str,
    ) -> Result<DbQueryResult, DbOperationError> {
        self.query(tenant, conn_id, sql, true).await
    }

    pub async fn query(
        &self,
        tenant: &str,
        conn_id: &str,
        sql: &str,
        read_only: bool,
    ) -> Result<DbQueryResult, DbOperationError> {
        let (driver, spec) = self.lookup_spec(tenant, conn_id).await?;
        driver.query(&spec, sql, read_only).await
    }

    pub async fn mutate(&self, tenant: &str, conn_id: &str, sql: &str) -> Result<u64, String> {
        let (driver, spec) = self.lookup_spec(tenant, conn_id).await?;
        driver.mutate_sql(&spec, sql).await
    }

    pub async fn mutate_structured(
        &self,
        tenant: &str,
        conn_id: &str,
        schema: &str,
        table: &str,
        primary_keys: &[String],
        updates: &[DbRowUpdate],
        inserts: &[HashMap<String, Value>],
        deletes: &[HashMap<String, Value>],
    ) -> Result<DbMutateResult, String> {
        let (driver, spec) = self.lookup_spec(tenant, conn_id).await?;
        driver
            .mutate_structured(
                &spec,
                schema,
                table,
                primary_keys,
                updates,
                inserts,
                deletes,
            )
            .await
    }

    pub async fn list_connections(&self) -> Vec<String> {
        self.conns.read().await.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::compact_byte_size;
    use crate::mysql_driver::sha1_digest;
    use axum::extract::State;
    use axum::routing::post;
    use axum::Router;
    use std::sync::Mutex;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    #[test]
    fn enforces_read_write_sql_guard_and_default_tls_require_dsn() {
        let explorer = DbExplorer::new();
        assert!(!explorer.is_write_sql("SELECT * FROM users"));
        assert!(explorer.is_write_sql("-- note\nDELETE FROM users"));
        assert!(explorer.is_write_sql("  /* hi */ DROP TABLE foo"));

        let dsn = DbExplorer::build_dsn(&DbConnectRequest {
            engine: "postgres".into(),
            name: String::new(),
            host: "db.internal".into(),
            port: 5432,
            database: "app".into(),
            username: "ro".into(),
            password: "pw".into(),
            ssl: None,
            ssl_mode: String::new(),
        });
        assert!(dsn.contains("sslmode=require"));
        assert_eq!(compact_byte_size(2048), "2K");
    }

    #[test]
    fn validates_identifiers_and_mysql_sha1_vector() {
        let explorer = DbExplorer::new();
        assert_eq!(
            explorer.validate_ident("users_2", "table").unwrap(),
            "\"users_2\""
        );
        assert!(explorer
            .validate_ident("users; DROP TABLE x", "table")
            .is_err());
        // FIPS 180-4 SHA-1("abc")
        let digest = sha1_digest(b"abc");
        let hex = digest.iter().fold(String::with_capacity(40), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        });
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[tokio::test]
    async fn duckdb_driver_connects_runs_analytics_and_enforces_read_only_guard() {
        let explorer = DbExplorer::new();
        let conn = explorer
            .connect_and_inspect(
                "acme",
                &DbConnectRequest {
                    engine: "duckdb".into(),
                    name: "local-duck".into(),
                    host: "embedded".into(),
                    port: 0,
                    database: "analytics".into(),
                    username: String::new(),
                    password: String::new(),
                    ssl: None,
                    ssl_mode: String::new(),
                },
            )
            .await
            .unwrap();
        assert!(conn.connected);
        assert_eq!(conn.engine, "duckdb");
        assert!(conn.tables.iter().any(|t| t.name == "telemetry_events"));

        let ro_err = explorer
            .query(
                "acme",
                &conn.connection_id,
                "DELETE FROM telemetry_events WHERE protocol = 'rdp'",
                true,
            )
            .await
            .unwrap_err();
        assert!(ro_err.blocked_by_guard);

        let inserted = explorer
            .mutate(
                "acme",
                &conn.connection_id,
                "INSERT INTO telemetry_events (event_id, protocol, preset, fps, latency_ms, tenant_id) VALUES ('evt-003', 'rdp', 'balanced_wan', 60.0, 9.2, 'acme')",
            )
            .await
            .unwrap();
        assert_eq!(inserted, 1);

        let res = explorer
            .query(
                "acme",
                &conn.connection_id,
                "SELECT event_id, fps FROM telemetry_events WHERE tenant_id = 'acme'",
                true,
            )
            .await
            .unwrap();
        assert_eq!(res.row_count, 1);
        assert_eq!(
            res.rows[0].get("event_id"),
            Some(&Value::String("evt-003".into()))
        );
    }

    #[tokio::test]
    async fn clickhouse_driver_speaks_http_json_protocol() {
        let last_sql = Arc::new(Mutex::new(Vec::<String>::new()));
        let state_sql = last_sql.clone();
        let app = Router::new()
            .route(
                "/",
                post(|State(log): State<Arc<Mutex<Vec<String>>>>, body: String| async move {
                    log.lock().unwrap().push(body.clone());
                    let upper = body.to_ascii_uppercase();
                    if upper.contains("SYSTEM.DATABASES") {
                        r#"{"meta":[{"name":"name","type":"String"}],"data":[{"name":"default"}]}"#.to_owned()
                    } else if upper.contains("SYSTEM.TABLES") {
                        r#"{"meta":[{"name":"database","type":"String"},{"name":"name","type":"String"},{"name":"total_rows","type":"UInt64"},{"name":"total_bytes","type":"UInt64"}],"data":[{"database":"default","name":"events","total_rows":"42","total_bytes":"4096"}]}"#.to_owned()
                    } else if upper.contains("SYSTEM.COLUMNS") {
                        r#"{"meta":[{"name":"table","type":"String"},{"name":"name","type":"String"},{"name":"type","type":"String"},{"name":"is_in_primary_key","type":"UInt8"}],"data":[{"table":"events","name":"id","type":"String","is_in_primary_key":1}]}"#.to_owned()
                    } else {
                        r#"{"meta":[{"name":"id","type":"String"}],"data":[{"id":"ch-1"}]}"#.to_owned()
                    }
                }),
            )
            .with_state(state_sql);
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(ln, app).await;
        });

        let explorer = DbExplorer::new();
        let res = explorer
            .connect_and_inspect(
                "acme",
                &DbConnectRequest {
                    engine: "clickhouse".into(),
                    name: "ch".into(),
                    host: "127.0.0.1".into(),
                    port: addr.port(),
                    database: "default".into(),
                    username: "default".into(),
                    password: String::new(),
                    ssl: Some(false),
                    ssl_mode: "disable".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(res.engine, "clickhouse");
        assert_eq!(res.tables.len(), 1);
        assert_eq!(
            res.tables[0].rows[0].get("id"),
            Some(&Value::String("ch-1".into()))
        );
    }

    #[tokio::test]
    async fn redis_driver_connects_over_resp2_and_blocks_writes_when_read_only() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = ln.accept().await {
                tokio::spawn(async move {
                    let (rh, mut wh) = sock.into_split();
                    let mut r = BufReader::new(rh);
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                            break;
                        }
                        if !line.starts_with('*') {
                            continue;
                        }
                        let arg_count: usize = line[1..].trim().parse().unwrap_or(0);
                        let mut args = Vec::with_capacity(arg_count);
                        for _ in 0..arg_count {
                            let mut hdr = String::new();
                            let _ = r.read_line(&mut hdr).await;
                            let mut val = String::new();
                            let _ = r.read_line(&mut val).await;
                            args.push(val.trim_end().to_owned());
                        }
                        let cmd = args.first().map_or_default(|s| s.to_ascii_uppercase());
                        let reply = match cmd.as_str() {
                            "PING" => "+PONG\r\n".to_owned(),
                            "SCAN" => "*2\r\n$1\r\n0\r\n*1\r\n$7\r\napp:ver\r\n".to_owned(),
                            "TYPE" => "+string\r\n".to_owned(),
                            "GET" => "$5\r\n1.2.3\r\n".to_owned(),
                            _ => "+OK\r\n".to_owned(),
                        };
                        let _ = wh.write_all(reply.as_bytes()).await;
                    }
                });
            }
        });

        let explorer = DbExplorer::new();
        let conn = explorer
            .connect_and_inspect(
                "acme",
                &DbConnectRequest {
                    engine: "redis".into(),
                    name: "rd".into(),
                    host: "127.0.0.1".into(),
                    port: addr.port(),
                    database: "0".into(),
                    username: String::new(),
                    password: String::new(),
                    ssl: Some(false),
                    ssl_mode: "disable".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(conn.engine, "redis");
        assert_eq!(conn.tables[0].name, "keys:string");

        let blocked = explorer
            .query("acme", &conn.connection_id, "SET evil 1", true)
            .await
            .unwrap_err();
        assert!(blocked.blocked_by_guard);

        let q = explorer
            .query("acme", &conn.connection_id, "GET app:ver", true)
            .await
            .unwrap();
        assert_eq!(q.rows[0].get("value"), Some(&Value::String("1.2.3".into())));
    }

    fn build_test_tls_acceptor() -> tokio_rustls::TlsAcceptor {
        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
        ])
        .unwrap();
        let cert_der = rustls_pki_types::CertificateDer::from(cert.cert.der().to_vec());
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
    }

    async fn read_pkt<S: tokio::io::AsyncRead + Unpin>(
        s: &mut S,
    ) -> std::io::Result<(u8, Vec<u8>)> {
        use tokio::io::AsyncReadExt as _;
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await?;
        let len = usize::from(hdr[0]) | (usize::from(hdr[1]) << 8) | (usize::from(hdr[2]) << 16);
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).await?;
        Ok((hdr[3], body))
    }

    async fn write_pkt<S: tokio::io::AsyncWrite + Unpin>(
        s: &mut S,
        seq: u8,
        body: &[u8],
    ) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        let l = body.len();
        let hdr = [
            (l & 0xFF) as u8,
            ((l >> 8) & 0xFF) as u8,
            ((l >> 16) & 0xFF) as u8,
            seq,
        ];
        s.write_all(&hdr).await?;
        s.write_all(body).await?;
        s.flush().await
    }

    fn mysql_col_def(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for s in ["def", "", "", "", name] {
            v.push(u8::try_from(s.len()).unwrap_or(0));
            v.extend_from_slice(s.as_bytes());
        }
        v
    }

    #[tokio::test]
    async fn mysql_driver_upgrades_to_tls_by_default_and_rejects_missing_client_ssl() {
        let acceptor = build_test_tls_acceptor();

        // A. Server advertising CLIENT_SSL upgrades to TLS before auth and answers queries.
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let acc = acceptor.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = ln.accept().await {
                let acc_conn = acc.clone();
                tokio::spawn(async move {
                    let mut greet = vec![10u8];
                    greet.extend_from_slice(b"8.0.36-tls\0");
                    greet.extend_from_slice(&[1, 0, 0, 0]);
                    greet.extend_from_slice(b"12345678");
                    greet.push(0);
                    let cap_low: u16 = 0x0200 | 0x8000 | 0x0800; // PROTOCOL_41 | SECURE_CONN | SSL
                    greet.extend_from_slice(&cap_low.to_le_bytes());
                    greet.push(45);
                    greet.extend_from_slice(&[0x02, 0x00]);
                    greet.extend_from_slice(&0x0008u16.to_le_bytes()); // CLIENT_PLUGIN_AUTH
                    greet.push(21);
                    greet.extend_from_slice(&[0u8; 10]);
                    greet.extend_from_slice(b"abcdefghijkl\0");
                    greet.extend_from_slice(b"mysql_native_password\0");
                    let _ = write_pkt(&mut sock, 0, &greet).await;

                    let Ok((seq1, ssl_req)) = read_pkt(&mut sock).await else {
                        return;
                    };
                    assert_eq!(seq1, 1);
                    assert_eq!(ssl_req.len(), 32);
                    let req_flags =
                        u32::from_le_bytes([ssl_req[0], ssl_req[1], ssl_req[2], ssl_req[3]]);
                    assert_ne!(req_flags & 0x0800, 0);

                    let Ok(mut tls_sock) = acc_conn.accept(sock).await else {
                        return;
                    };
                    let Ok((seq2, _auth)) = read_pkt(&mut tls_sock).await else {
                        return;
                    };
                    assert_eq!(seq2, 2);
                    let _ = write_pkt(
                        &mut tls_sock,
                        3,
                        &[0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00],
                    )
                    .await;

                    while let Ok((_qseq, pkt)) = read_pkt(&mut tls_sock).await {
                        if pkt.first().copied() != Some(0x03) {
                            break;
                        }
                        let sql = String::from_utf8_lossy(&pkt[1..]).to_ascii_uppercase();
                        if sql.contains("SHOW DATABASES") {
                            let _ = write_pkt(&mut tls_sock, 1, &[1]).await;
                            let _ = write_pkt(&mut tls_sock, 2, &mysql_col_def("Database")).await;
                            let _ = write_pkt(&mut tls_sock, 3, &[0xFE, 0, 0, 2, 0]).await;
                            let _ = write_pkt(&mut tls_sock, 4, &[3, b'a', b'p', b'p']).await;
                            let _ = write_pkt(&mut tls_sock, 5, &[0xFE, 0, 0, 2, 0]).await;
                        } else if sql.contains("INFORMATION_SCHEMA.COLUMNS")
                            || sql.contains("INFORMATION_SCHEMA.TABLES")
                        {
                            let _ = write_pkt(&mut tls_sock, 1, &[1]).await;
                            let _ = write_pkt(&mut tls_sock, 2, &mysql_col_def("col")).await;
                            let _ = write_pkt(&mut tls_sock, 3, &[0xFE, 0, 0, 2, 0]).await;
                            let _ = write_pkt(&mut tls_sock, 4, &[0xFE, 0, 0, 2, 0]).await;
                        } else {
                            let _ = write_pkt(&mut tls_sock, 1, &[1]).await;
                            let _ = write_pkt(&mut tls_sock, 2, &mysql_col_def("ok")).await;
                            let _ = write_pkt(&mut tls_sock, 3, &[0xFE, 0, 0, 2, 0]).await;
                            let _ = write_pkt(&mut tls_sock, 4, &[1, b'1']).await;
                            let _ = write_pkt(&mut tls_sock, 5, &[0xFE, 0, 0, 2, 0]).await;
                        }
                    }
                });
            }
        });

        let explorer = DbExplorer::new();
        let conn = explorer
            .connect_and_inspect(
                "acme",
                &DbConnectRequest {
                    engine: "mysql".into(),
                    name: "my-tls".into(),
                    host: "127.0.0.1".into(),
                    port: addr.port(),
                    database: "app".into(),
                    username: "root".into(),
                    password: "SecretPassword!1".into(),
                    ssl: None,
                    ssl_mode: String::new(),
                },
            )
            .await
            .unwrap();
        assert_eq!(conn.databases, vec!["app".to_owned()]);
        let q = explorer
            .query("acme", &conn.connection_id, "SELECT 1 AS ok", true)
            .await
            .unwrap();
        assert_eq!(q.rows[0].get("ok"), Some(&Value::String("1".into())));

        // B. Server without CLIENT_SSL must be rejected BEFORE sending credentials.
        let ln_no_ssl = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_no_ssl = ln_no_ssl.local_addr().unwrap();
        let received_auth = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let received_auth_srv = Arc::clone(&received_auth);
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = ln_no_ssl.accept().await {
                let mut greet = vec![10u8];
                greet.extend_from_slice(b"8.0.36-plain\0");
                greet.extend_from_slice(&[1, 0, 0, 0]);
                greet.extend_from_slice(b"12345678");
                greet.push(0);
                let cap_low: u16 = 0x0200 | 0x8000; // no CLIENT_SSL
                greet.extend_from_slice(&cap_low.to_le_bytes());
                greet.push(45);
                greet.extend_from_slice(&[0x02, 0x00]);
                greet.extend_from_slice(&0x0008u16.to_le_bytes());
                greet.push(21);
                greet.extend_from_slice(&[0u8; 10]);
                greet.extend_from_slice(b"abcdefghijkl\0");
                greet.extend_from_slice(b"mysql_native_password\0");
                let _ = write_pkt(&mut sock, 0, &greet).await;
                if read_pkt(&mut sock).await.is_ok() {
                    received_auth_srv.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });
        let err = explorer
            .connect_and_inspect(
                "acme",
                &DbConnectRequest {
                    engine: "mysql".into(),
                    name: "my-nossl".into(),
                    host: "127.0.0.1".into(),
                    port: addr_no_ssl.port(),
                    database: "app".into(),
                    username: "root".into(),
                    password: "SecretPassword!1".into(),
                    ssl: None,
                    ssl_mode: String::new(),
                },
            )
            .await
            .unwrap_err();
        assert!(err.contains("CLIENT_SSL"), "unexpected error: {err}");
        assert!(!received_auth.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn redis_driver_connects_over_tls_by_default() {
        let acceptor = build_test_tls_acceptor();
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = ln.accept().await {
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls_sock) = acc.accept(sock).await else {
                        return;
                    };
                    let (rh, mut wh) = tokio::io::split(tls_sock);
                    let mut r = BufReader::new(rh);
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                            break;
                        }
                        if !line.starts_with('*') {
                            continue;
                        }
                        let arg_count: usize = line[1..].trim().parse().unwrap_or(0);
                        let mut args = Vec::with_capacity(arg_count);
                        for _ in 0..arg_count {
                            let mut hdr = String::new();
                            let _ = r.read_line(&mut hdr).await;
                            let mut val = String::new();
                            let _ = r.read_line(&mut val).await;
                            args.push(val.trim_end().to_owned());
                        }
                        let cmd = args.first().map_or_default(|s| s.to_ascii_uppercase());
                        let reply = match cmd.as_str() {
                            "PING" => "+PONG\r\n".to_owned(),
                            "SCAN" => "*2\r\n$1\r\n0\r\n*1\r\n$7\r\napp:tls\r\n".to_owned(),
                            "TYPE" => "+string\r\n".to_owned(),
                            "GET" => "$3\r\nyes\r\n".to_owned(),
                            _ => "+OK\r\n".to_owned(),
                        };
                        let _ = wh.write_all(reply.as_bytes()).await;
                        let _ = wh.flush().await;
                    }
                });
            }
        });

        let explorer = DbExplorer::new();
        let conn = explorer
            .connect_and_inspect(
                "acme",
                &DbConnectRequest {
                    engine: "redis".into(),
                    name: "rd-tls".into(),
                    host: "127.0.0.1".into(),
                    port: addr.port(),
                    database: "0".into(),
                    username: String::new(),
                    password: String::new(),
                    ssl: None,
                    ssl_mode: String::new(),
                },
            )
            .await
            .unwrap();
        assert_eq!(conn.engine, "redis");
        let q = explorer
            .query("acme", &conn.connection_id, "GET app:tls", true)
            .await
            .unwrap();
        assert_eq!(q.rows[0].get("value"), Some(&Value::String("yes".into())));
    }

    #[test]
    fn compliance_mode_blocks_plaintext_ssl_mode_disable() {
        assert!(crate::tls::should_use_tls_with_compliance("disable", true).is_err());
        assert_eq!(
            crate::tls::should_use_tls_with_compliance("disable", false),
            Ok(false)
        );
        assert_eq!(
            crate::tls::should_use_tls_with_compliance("require", true),
            Ok(true)
        );
    }
}
