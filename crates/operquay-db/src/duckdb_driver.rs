use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::columnar_engine::EmbeddedColumnarEngine;
use crate::driver::{
    is_write_sql, read_only_block_error, validate_ident_quoted, DatabaseEngineDriver,
    DbConnectRequest, DbConnectionSpec, DbMutateResult, DbOperationError, DbQueryResult,
    DbRowUpdate, DbTableDef, MAX_QUERY_ROWS,
};

#[derive(Debug, Deserialize)]
struct RemoteDuckResponse {
    #[serde(default)]
    columns: Vec<String>,
    #[serde(default)]
    rows: Vec<Map<String, Value>>,
    #[serde(default)]
    duration_ms: u64,
    #[serde(default)]
    databases: Vec<String>,
    #[serde(default)]
    tables: Vec<DbTableDef>,
}

/// `DuckDB` driver providing BOTH:
/// 1. Native embedded pure-Rust analytical columnar SQL engine (`host = embedded | memory | *.duckdb`)
///    with optional atomic JSON/WAL file snapshots.
/// 2. Optional remote `DuckDB`/`MotherDuck` HTTP SQL gateway (`http://` or `https://` host).
#[derive(Debug)]
pub struct DuckDbDriver {
    embedded: EmbeddedColumnarEngine,
    http: reqwest::Client,
}

impl Default for DuckDbDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl DuckDbDriver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            embedded: EmbeddedColumnarEngine::new_duckdb(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    fn is_remote_http(spec: &DbConnectionSpec) -> bool {
        let h = spec.host.trim();
        h.starts_with("http://") || h.starts_with("https://")
    }

    fn check_remote_transport_policy(compliance_mode: bool, base_url: &str) -> Result<(), String> {
        if !compliance_mode {
            return Ok(());
        }
        let lower = base_url.trim().to_ascii_lowercase();
        if lower.starts_with("https://")
            || lower.starts_with("http://127.0.0.1")
            || lower.starts_with("http://localhost")
            || lower.starts_with("http://[::1]")
        {
            return Ok(());
        }
        Err("Compliance Mode requires https:// for non-loopback remote DuckDB HTTP gateways".into())
    }

    fn snapshot_path(spec: &DbConnectionSpec) -> Option<&str> {
        let is_file = |p: &str| {
            std::path::Path::new(p).extension().is_some_and(|ext| {
                ext.eq_ignore_ascii_case("duckdb") || ext.eq_ignore_ascii_case("json")
            })
        };
        let h = spec.host.trim();
        if is_file(h) {
            Some(h)
        } else if is_file(&spec.database) {
            Some(spec.database.as_str())
        } else {
            None
        }
    }

    async fn exec_remote(
        &self,
        spec: &DbConnectionSpec,
        sql: &str,
        read_only: bool,
    ) -> Result<RemoteDuckResponse, String> {
        let base = spec.host.trim().trim_end_matches('/');
        Self::check_remote_transport_policy(operquay_core::compliance_mode_enabled(), base)?;
        let url = format!("{base}/query");
        let mut req = self.http.post(&url).json(&serde_json::json!({
            "database": spec.database,
            "sql": sql,
            "read_only": read_only,
        }));
        if !spec.password.is_empty() {
            req = req.bearer_auth(&spec.password);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("DuckDB HTTP request failed: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("DuckDB HTTP {status}: {}", text.trim()));
        }
        resp.json::<RemoteDuckResponse>()
            .await
            .map_err(|e| format!("DuckDB HTTP JSON decode failed: {e}"))
    }
}

#[async_trait]
impl DatabaseEngineDriver for DuckDbDriver {
    fn engine(&self) -> &'static str {
        "duckdb"
    }

    fn default_port(&self) -> u16 {
        1294
    }

    fn normalize_request(&self, req: &DbConnectRequest) -> DbConnectRequest {
        let mut out = req.clone();
        if out.host.trim().is_empty() {
            out.host = "embedded".into();
        }
        if out.port == 0 {
            out.port = self.default_port();
        }
        if out.database.trim().is_empty() {
            out.database = "analytics".into();
        }
        out
    }

    async fn connect_and_inspect(
        &self,
        spec: &DbConnectionSpec,
    ) -> Result<(Vec<String>, Vec<DbTableDef>), String> {
        if Self::is_remote_http(spec) {
            let r = self.exec_remote(spec, "SHOW TABLES", true).await?;
            let dbs = if r.databases.is_empty() {
                vec![spec.database.clone()]
            } else {
                r.databases
            };
            return Ok((dbs, r.tables));
        }
        self.embedded
            .inspect_checked(&spec.database, Self::snapshot_path(spec))
    }

    async fn query(
        &self,
        spec: &DbConnectionSpec,
        sql: &str,
        read_only: bool,
    ) -> Result<DbQueryResult, DbOperationError> {
        if read_only && is_write_sql(sql) {
            return Err(read_only_block_error());
        }
        if Self::is_remote_http(spec) {
            let r = self
                .exec_remote(spec, sql, read_only)
                .await
                .map_err(DbOperationError::err)?;
            let truncated = r.rows.len() > MAX_QUERY_ROWS;
            let rows: Vec<Map<String, Value>> = r.rows.into_iter().take(MAX_QUERY_ROWS).collect();
            let matrix_rows = rows
                .iter()
                .map(|row| {
                    r.columns
                        .iter()
                        .map(|c| row.get(c).cloned().unwrap_or(Value::Null))
                        .collect()
                })
                .collect();
            return Ok(DbQueryResult {
                row_count: rows.len(),
                columns: r.columns,
                rows,
                matrix_rows,
                duration_ms: r.duration_ms,
                truncated,
                dlp_summary: None,
            });
        }
        self.embedded
            .query(&spec.database, Self::snapshot_path(spec), sql, read_only)
    }

    async fn mutate_sql(&self, spec: &DbConnectionSpec, sql: &str) -> Result<u64, String> {
        if Self::is_remote_http(spec) {
            let _ = self.exec_remote(spec, sql, false).await?;
            return Ok(1);
        }
        self.embedded
            .mutate_sql(&spec.database, Self::snapshot_path(spec), sql)
    }

    async fn mutate_structured(
        &self,
        spec: &DbConnectionSpec,
        schema: &str,
        table: &str,
        primary_keys: &[String],
        updates: &[DbRowUpdate],
        inserts: &[HashMap<String, Value>],
        deletes: &[HashMap<String, Value>],
    ) -> Result<DbMutateResult, String> {
        if Self::is_remote_http(spec) {
            let started = std::time::Instant::now();
            let tbl_q = validate_ident_quoted(table, "table", '"')?;
            let qualified = if schema.trim().is_empty() {
                tbl_q
            } else {
                let sch_q = validate_ident_quoted(schema, "schema", '"')?;
                format!("{sch_q}.{tbl_q}")
            };
            let mut upd_cnt = 0u64;
            let mut ins_cnt = 0u64;
            let mut del_cnt = 0u64;

            for upd in updates {
                let (keys, vals) = upd.resolve_keys_and_changes(primary_keys);
                if keys.is_empty() || vals.is_empty() {
                    continue;
                }
                let mut sets = Vec::with_capacity(vals.len());
                for (k, v) in &vals {
                    let kq = validate_ident_quoted(k, "column", '"')?;
                    sets.push(format!("{kq} = {}", sql_literal(v)));
                }
                let where_sql = build_where_eq(&keys)?;
                let sql = format!(
                    "UPDATE {qualified} SET {} WHERE {where_sql}",
                    sets.join(", ")
                );
                let _ = self.exec_remote(spec, &sql, false).await?;
                upd_cnt += 1;
            }
            for row in inserts {
                if row.is_empty() {
                    continue;
                }
                let mut cols = Vec::with_capacity(row.len());
                let mut vals = Vec::with_capacity(row.len());
                for (k, v) in row {
                    cols.push(validate_ident_quoted(k, "column", '"')?);
                    vals.push(sql_literal(v));
                }
                let sql = format!(
                    "INSERT INTO {qualified} ({}) VALUES ({})",
                    cols.join(", "),
                    vals.join(", ")
                );
                let _ = self.exec_remote(spec, &sql, false).await?;
                ins_cnt += 1;
            }
            for row in deletes {
                if row.is_empty() {
                    continue;
                }
                let where_sql = build_where_eq(row)?;
                let sql = format!("DELETE FROM {qualified} WHERE {where_sql}");
                let _ = self.exec_remote(spec, &sql, false).await?;
                del_cnt += 1;
            }
            return Ok(DbMutateResult {
                committed: true,
                updated: upd_cnt,
                inserted: ins_cnt,
                deleted: del_cnt,
                affected_rows: upd_cnt + ins_cnt + del_cnt,
                duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
            });
        }
        self.embedded.mutate_structured(
            &spec.database,
            Self::snapshot_path(spec),
            schema,
            table,
            primary_keys,
            updates,
            inserts,
            deletes,
        )
    }
}

fn sql_literal(val: &Value) -> String {
    match val {
        Value::Null => "NULL".to_owned(),
        Value::Bool(b) => if *b { "TRUE" } else { "FALSE" }.to_owned(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("'{}'", s.replace('\'', "''")),
        other => format!("'{}'", other.to_string().replace('\'', "''")),
    }
}

fn build_where_eq(keys: &HashMap<String, Value>) -> Result<String, String> {
    let mut clauses = Vec::with_capacity(keys.len());
    for (k, v) in keys {
        let kq = validate_ident_quoted(k, "column", '"')?;
        if v.is_null() {
            clauses.push(format!("{kq} IS NULL"));
        } else {
            clauses.push(format!("{kq} = {}", sql_literal(v)));
        }
    }
    Ok(clauses.join(" AND "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use axum::{Json, Router};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn atomic_oqduck01_file_persists_across_restarts_and_rejects_corruption() {
        let dir = std::env::temp_dir().join(format!("operquay-duck-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_file = dir.join("analytics.duckdb");

        let spec = DbConnectionSpec {
            tenant: "acme".into(),
            engine: "duckdb".into(),
            host: db_file.to_string_lossy().into_owned(),
            port: 1294,
            database: "analytics".into(),
            username: String::new(),
            password: String::new(),
            ssl_mode: "disable".into(),
            cache_key: "duck-file-test".into(),
        };

        let d1 = DuckDbDriver::new();
        d1.mutate_sql(
            &spec,
            "CREATE TABLE orders (id VARCHAR PRIMARY KEY, region VARCHAR, amount DOUBLE)",
        )
        .await
        .unwrap();
        d1.mutate_sql(
            &spec,
            "INSERT INTO orders VALUES ('o1', 'us-east-1', 120.5)",
        )
        .await
        .unwrap();
        d1.mutate_sql(&spec, "INSERT INTO orders VALUES ('o2', 'us-east-1', 79.5)")
            .await
            .unwrap();

        let disk_bytes = std::fs::read(&db_file).unwrap();
        assert!(disk_bytes.starts_with(b"OQDUCK01"));

        // Second independent driver instance reloads persisted tables + supports GROUP BY & PRAGMA
        let d2 = DuckDbDriver::new();
        let (_, tables) = d2.connect_and_inspect(&spec).await.unwrap();
        assert!(tables
            .iter()
            .any(|t| t.name == "orders" && t.row_count == 2));

        let grp = d2
            .query(
                &spec,
                "SELECT region, SUM(amount) AS total FROM orders GROUP BY region",
                true,
            )
            .await
            .unwrap();
        assert_eq!(grp.row_count, 1);
        assert_eq!(grp.rows[0]["total"], serde_json::json!(200.0));

        let pragma = d2
            .query(&spec, "PRAGMA table_info(orders)", true)
            .await
            .unwrap();
        assert_eq!(pragma.row_count, 3);

        // Corrupt a byte inside the OQDUCK01 payload and assert CRC32 check rejects it
        let mut bad = disk_bytes.clone();
        let last = bad.len() - 2;
        bad[last] ^= 0xFF;
        std::fs::write(&db_file, bad).unwrap();
        let d3 = DuckDbDriver::new();
        assert!(d3.connect_and_inspect(&spec).await.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn remote_http_duckdb_driver_executes_queries_and_structured_mutations() {
        assert!(
            DuckDbDriver::check_remote_transport_policy(true, "https://duck.example.com").is_ok()
        );
        assert!(DuckDbDriver::check_remote_transport_policy(true, "http://127.0.0.1:1294").is_ok());
        assert!(
            DuckDbDriver::check_remote_transport_policy(true, "http://duck.example.com").is_err()
        );

        let received_sql = Arc::new(Mutex::new(Vec::<String>::new()));
        let app = Router::new().route(
            "/query",
            post({
                let log = received_sql.clone();
                move |Json(body): Json<serde_json::Value>| async move {
                    let sql = body["sql"].as_str().unwrap_or("").to_owned();
                    log.lock().unwrap().push(sql.clone());
                    if sql == "SHOW TABLES" {
                        Json(serde_json::json!({
                            "databases": ["analytics"],
                            "tables": [{
                                "schema": "main",
                                "name": "events",
                                "estimatedRows": 1,
                                "sizeBytes": 4096,
                                "sizePretty": "4.0 KB",
                                "columns": [],
                                "rows": []
                            }]
                        }))
                    } else {
                        Json(serde_json::json!({
                            "columns": ["ok"],
                            "rows": [{ "ok": 1 }],
                            "duration_ms": 2
                        }))
                    }
                }
            }),
        );
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(ln, app).await;
        });

        let drv = DuckDbDriver::new();
        let spec = DbConnectionSpec {
            tenant: "acme".into(),
            engine: "duckdb".into(),
            host: format!("http://{addr}"),
            port: addr.port(),
            database: "analytics".into(),
            username: String::new(),
            password: "tok".into(),
            ssl_mode: "disable".into(),
            cache_key: "duck-http".into(),
        };
        let (dbs, tbls) = drv.connect_and_inspect(&spec).await.unwrap();
        assert_eq!(dbs, vec!["analytics"]);
        assert_eq!(tbls[0].name, "events");

        let mut ins = HashMap::new();
        ins.insert("id".to_owned(), serde_json::json!("e1"));
        let mut del = HashMap::new();
        del.insert("id".to_owned(), serde_json::json!("e0"));
        let mres = drv
            .mutate_structured(&spec, "main", "events", &["id".into()], &[], &[ins], &[del])
            .await
            .unwrap();
        assert_eq!(mres.inserted, 1);
        assert_eq!(mres.deleted, 1);
        let recorded = received_sql.lock().unwrap();
        assert!(recorded
            .iter()
            .any(|s| s.starts_with("INSERT INTO \"main\".\"events\"")));
        assert!(recorded
            .iter()
            .any(|s| s.starts_with("DELETE FROM \"main\".\"events\" WHERE \"id\" = 'e0'")));
    }
}
