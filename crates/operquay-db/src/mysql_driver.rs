use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::columnar_engine::EmbeddedColumnarEngine;
use crate::driver::{
    compact_byte_size, is_write_sql, read_only_block_error, rows_to_objects, validate_ident_quoted,
    DatabaseEngineDriver, DbColumnDef, DbConnectRequest, DbConnectionSpec, DbMutateResult,
    DbOperationError, DbQueryResult, DbRowUpdate, DbTableDef, MAX_QUERY_ROWS, PREVIEW_ROW_LIMIT,
};
use crate::tls::{build_client_tls_connector, resolve_server_name, should_use_tls};

const IO_TIMEOUT: Duration = Duration::from_secs(12);
const CLIENT_LONG_PASSWORD: u32 = 1;
const CLIENT_CONNECT_WITH_DB: u32 = 8;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SSL: u32 = 0x0000_0800;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;

enum MySqlStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for MySqlStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MySqlStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Pure-Rust MySQL / MariaDB v10 wire-protocol driver (`mysql_native_password` + `COM_QUERY` over TLS 1.2+).
#[derive(Debug)]
pub struct MySqlDriver {
    embedded: EmbeddedColumnarEngine,
}

impl Default for MySqlDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl MySqlDriver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            embedded: EmbeddedColumnarEngine::new_duckdb(),
        }
    }

    fn is_embedded(spec: &DbConnectionSpec) -> bool {
        let h = spec.host.trim();
        h.eq_ignore_ascii_case("embedded") || h.eq_ignore_ascii_case("memory")
    }

    async fn connect_and_auth(spec: &DbConnectionSpec) -> Result<MySqlStream, String> {
        let use_tls = should_use_tls(&spec.ssl_mode)?;
        let port = if spec.port == 0 { 3306 } else { spec.port };
        let tcp = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect((spec.host.as_str(), port)))
            .await
            .map_err(|_| format!("MySQL TCP connect timed out to {}:{port}", spec.host))?
            .map_err(|e| format!("MySQL TCP connect failed to {}:{port}: {e}", spec.host))?;

        let mut plain_stream = MySqlStream::Plain(tcp);
        let (_, greeting) = read_mysql_packet(&mut plain_stream).await?;
        if greeting.first().copied() != Some(10) {
            return Err("unsupported MySQL server protocol version (expected v10)".into());
        }
        let nul_pos = greeting[1..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| "malformed MySQL server greeting".to_owned())?;
        let after_ver = 1 + nul_pos + 1;
        if greeting.len() < after_ver + 4 + 8 + 1 + 2 {
            return Err("truncated MySQL server greeting".into());
        }
        let mut scramble = Vec::with_capacity(20);
        scramble.extend_from_slice(&greeting[after_ver + 4..after_ver + 12]);
        // greeting[after_ver + 12] == 0x00 filler
        let cap_low =
            u32::from_le_bytes([greeting[after_ver + 13], greeting[after_ver + 14], 0, 0]);
        let mut cap_high = 0u32;
        if greeting.len() >= after_ver + 18 {
            cap_high =
                u32::from_le_bytes([0, 0, greeting[after_ver + 16], greeting[after_ver + 17]]);
        }
        let srv_caps = cap_low | cap_high;
        if (srv_caps & CLIENT_SECURE_CONNECTION) != 0 && greeting.len() >= after_ver + 39 {
            let extra = &greeting[after_ver + 27..];
            let end = extra
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(extra.len())
                .min(12);
            scramble.extend_from_slice(&extra[..end]);
        }

        let mut flags = CLIENT_LONG_PASSWORD
            | CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH;
        if !spec.database.is_empty() {
            flags |= CLIENT_CONNECT_WITH_DB;
        }

        let (mut stream, auth_seq) = if use_tls {
            if (srv_caps & CLIENT_SSL) == 0 {
                return Err(
                    "MySQL server does not advertise CLIENT_SSL capability; refusing to send credentials in plaintext"
                        .to_owned(),
                );
            }
            flags |= CLIENT_SSL;
            let mut ssl_req = Vec::with_capacity(32);
            ssl_req.extend_from_slice(&flags.to_le_bytes());
            ssl_req.extend_from_slice(&(16u32 * 1024 * 1024).to_le_bytes());
            ssl_req.push(45); // utf8mb4_general_ci
            ssl_req.extend_from_slice(&[0u8; 23]);
            write_mysql_packet(&mut plain_stream, 1, &ssl_req).await?;

            let MySqlStream::Plain(tcp_inner) = plain_stream else {
                unreachable!();
            };
            let connector = build_client_tls_connector(&spec.ssl_mode)?;
            let server_name = resolve_server_name(&spec.host)?;
            let tls = tokio::time::timeout(IO_TIMEOUT, connector.connect(server_name, tcp_inner))
                .await
                .map_err(|_| format!("MySQL TLS handshake timed out to {}:{port}", spec.host))?
                .map_err(|e| format!("MySQL TLS handshake failed to {}:{port}: {e}", spec.host))?;
            (MySqlStream::Tls(Box::new(tls)), 2u8)
        } else {
            (plain_stream, 1u8)
        };

        let auth_resp = if spec.password.is_empty() {
            Vec::new()
        } else {
            mysql_native_scramble(&spec.password, &scramble)
        };

        let mut payload = Vec::with_capacity(96);
        payload.extend_from_slice(&flags.to_le_bytes());
        payload.extend_from_slice(&(16u32 * 1024 * 1024).to_le_bytes());
        payload.push(45); // utf8mb4_general_ci
        payload.extend_from_slice(&[0u8; 23]);
        payload.extend_from_slice(spec.username.as_bytes());
        payload.push(0);
        payload.push(u8::try_from(auth_resp.len()).unwrap_or(20));
        payload.extend_from_slice(&auth_resp);
        if !spec.database.is_empty() {
            payload.extend_from_slice(spec.database.as_bytes());
            payload.push(0);
        }
        payload.extend_from_slice(b"mysql_native_password\0");

        write_mysql_packet(&mut stream, auth_seq, &payload).await?;
        let (_, resp) = read_mysql_packet(&mut stream).await?;
        if resp.first().copied() == Some(0xFF) {
            return Err(format!("MySQL auth rejected: {}", parse_err_packet(&resp)));
        }
        Ok(stream)
    }

    async fn exec_com_query(stream: &mut MySqlStream, sql: &str) -> Result<MySqlResult, String> {
        let mut req = Vec::with_capacity(1 + sql.len());
        req.push(0x03); // COM_QUERY
        req.extend_from_slice(sql.as_bytes());
        write_mysql_packet(stream, 0, &req).await?;

        let (_, first) = read_mysql_packet(stream).await?;
        match first.first().copied() {
            Some(0xFF) => Err(parse_err_packet(&first)),
            Some(0x00) => {
                let (affected, _) = read_lenenc_int(&first[1..]);
                Ok(MySqlResult::Ok(affected))
            }
            Some(_) => {
                let (col_count, _) = read_lenenc_int(&first);
                let col_n = usize::try_from(col_count).unwrap_or(0);
                let mut columns = Vec::with_capacity(col_n);
                for _ in 0..col_n {
                    let (_, pkt) = read_mysql_packet(stream).await?;
                    columns.push(parse_column_def_name(&pkt));
                }
                let (_, eof_or_row) = read_mysql_packet(stream).await?;
                if eof_or_row.first().copied() != Some(0xFE) {
                    return Err("expected EOF marker after MySQL column definitions".into());
                }
                let mut rows = Vec::new();
                loop {
                    let (_, pkt) = read_mysql_packet(stream).await?;
                    let first_b = pkt.first().copied().unwrap_or(0xFE);
                    if (first_b == 0xFE && pkt.len() < 9) || first_b == 0xFF {
                        break;
                    }
                    let mut off = 0usize;
                    let mut row = Vec::with_capacity(col_n);
                    for _ in 0..col_n {
                        if off >= pkt.len() {
                            row.push(Value::Null);
                            continue;
                        }
                        if pkt[off] == 0xFB {
                            off += 1;
                            row.push(Value::Null);
                        } else {
                            let (len, used) = read_lenenc_int(&pkt[off..]);
                            off += used;
                            let take = usize::try_from(len)
                                .unwrap_or(0)
                                .min(pkt.len().saturating_sub(off));
                            let s = String::from_utf8_lossy(&pkt[off..off + take]).into_owned();
                            off += take;
                            row.push(Value::String(s));
                        }
                    }
                    rows.push(row);
                }
                Ok(MySqlResult::Rows { columns, rows })
            }
            None => Err("empty MySQL COM_QUERY response".into()),
        }
    }
}

enum MySqlResult {
    Ok(u64),
    Rows {
        columns: Vec<String>,
        rows: Vec<Vec<Value>>,
    },
}

#[async_trait]
impl DatabaseEngineDriver for MySqlDriver {
    fn engine(&self) -> &'static str {
        "mysql"
    }

    fn default_port(&self) -> u16 {
        3306
    }

    fn normalize_request(&self, req: &DbConnectRequest) -> DbConnectRequest {
        let mut out = req.clone();
        if out.host.trim().is_empty() {
            out.host = "localhost".into();
        }
        if out.port == 0 {
            out.port = self.default_port();
        }
        if out.database.trim().is_empty() {
            out.database = "mysql".into();
        }
        if out.username.trim().is_empty() {
            out.username = "root".into();
        }
        out
    }

    async fn connect_and_inspect(
        &self,
        spec: &DbConnectionSpec,
    ) -> Result<(Vec<String>, Vec<DbTableDef>), String> {
        if Self::is_embedded(spec) {
            return Ok(self.embedded.inspect(&spec.database, None));
        }

        let mut stream = Self::connect_and_auth(spec).await?;
        let databases = match Self::exec_com_query(&mut stream, "SHOW DATABASES").await? {
            MySqlResult::Rows { rows, .. } => rows
                .into_iter()
                .filter_map(|r| r.first().and_then(Value::as_str).map(ToOwned::to_owned))
                .collect(),
            MySqlResult::Ok(_) => Vec::new(),
        };

        let db_esc = spec.database.replace('\'', "''");
        let tbl_sql = format!(
            "SELECT TABLE_SCHEMA, TABLE_NAME, COALESCE(TABLE_ROWS, 0), COALESCE(DATA_LENGTH + INDEX_LENGTH, 0) \
             FROM information_schema.TABLES WHERE TABLE_SCHEMA = '{db_esc}' ORDER BY TABLE_NAME"
        );
        let tbl_rows = match Self::exec_com_query(&mut stream, &tbl_sql).await? {
            MySqlResult::Rows { rows, .. } => rows,
            MySqlResult::Ok(_) => Vec::new(),
        };

        let col_sql = format!(
            "SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY, COLUMN_DEFAULT \
             FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{db_esc}' ORDER BY TABLE_NAME, ORDINAL_POSITION"
        );
        let col_rows = match Self::exec_com_query(&mut stream, &col_sql).await {
            Ok(MySqlResult::Rows { rows, .. }) => rows,
            _ => Vec::new(),
        };
        let mut cols_by_table: HashMap<String, Vec<DbColumnDef>> = HashMap::new();
        for r in col_rows {
            let tbl = r.first().and_then(Value::as_str).unwrap_or("").to_owned();
            cols_by_table.entry(tbl).or_default().push(DbColumnDef {
                name: r.get(1).and_then(Value::as_str).unwrap_or("").to_owned(),
                data_type: r
                    .get(2)
                    .and_then(Value::as_str)
                    .unwrap_or("text")
                    .to_owned(),
                nullable: r.get(3).and_then(Value::as_str) == Some("YES"),
                is_primary_key: r.get(4).and_then(Value::as_str) == Some("PRI"),
                default_value: r.get(5).and_then(Value::as_str).map(ToOwned::to_owned),
            });
        }

        let mut tables = Vec::with_capacity(tbl_rows.len());
        for r in tbl_rows {
            let schema = r
                .first()
                .and_then(Value::as_str)
                .unwrap_or(&spec.database)
                .to_owned();
            let name = r.get(1).and_then(Value::as_str).unwrap_or("").to_owned();
            let est = r
                .get(2)
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            let bytes = r
                .get(3)
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            let columns = cols_by_table.remove(&name).unwrap_or_default();

            let preview = if let (Ok(sq), Ok(tq)) = (
                validate_ident_quoted(&schema, "schema", '`'),
                validate_ident_quoted(&name, "table", '`'),
            ) {
                let psql = format!("SELECT * FROM {sq}.{tq} LIMIT {PREVIEW_ROW_LIMIT}");
                match Self::exec_com_query(&mut stream, &psql).await {
                    Ok(MySqlResult::Rows {
                        columns: pc,
                        rows: pr,
                    }) => rows_to_objects(&pc, &pr),
                    _ => Vec::new(),
                }
            } else {
                Vec::new()
            };

            tables.push(DbTableDef {
                schema,
                name,
                row_count: est,
                size_bytes: bytes,
                size: compact_byte_size(bytes),
                columns,
                rows: preview,
            });
        }

        Ok((databases, tables))
    }

    async fn query(
        &self,
        spec: &DbConnectionSpec,
        sql: &str,
        read_only: bool,
    ) -> Result<DbQueryResult, DbOperationError> {
        if Self::is_embedded(spec) {
            return self.embedded.query(&spec.database, None, sql, read_only);
        }
        if read_only && is_write_sql(sql) {
            return Err(read_only_block_error());
        }
        let started = Instant::now();
        let mut stream = Self::connect_and_auth(spec).await?;
        let res = Self::exec_com_query(&mut stream, sql).await?;
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(0);
        match res {
            MySqlResult::Ok(affected) => {
                let cols = vec!["affected_rows".to_owned()];
                let matrix = vec![vec![serde_json::json!(affected)]];
                let rows = rows_to_objects(&cols, &matrix);
                Ok(DbQueryResult {
                    row_count: 1,
                    columns: cols,
                    rows,
                    matrix_rows: matrix,
                    duration_ms,
                    truncated: false,
                    dlp_summary: None,
                })
            }
            MySqlResult::Rows { columns, rows } => {
                let truncated = rows.len() > MAX_QUERY_ROWS;
                let matrix_rows: Vec<Vec<Value>> = rows.into_iter().take(MAX_QUERY_ROWS).collect();
                let obj_rows = rows_to_objects(&columns, &matrix_rows);
                Ok(DbQueryResult {
                    row_count: obj_rows.len(),
                    columns,
                    rows: obj_rows,
                    matrix_rows,
                    duration_ms,
                    truncated,
                    dlp_summary: None,
                })
            }
        }
    }

    async fn mutate_sql(&self, spec: &DbConnectionSpec, sql: &str) -> Result<u64, String> {
        if Self::is_embedded(spec) {
            return self.embedded.mutate_sql(&spec.database, None, sql);
        }
        let mut stream = Self::connect_and_auth(spec).await?;
        match Self::exec_com_query(&mut stream, sql).await? {
            MySqlResult::Ok(affected) => Ok(affected),
            MySqlResult::Rows { rows, .. } => Ok(u64::try_from(rows.len()).unwrap_or(0)),
        }
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
        if Self::is_embedded(spec) {
            return self.embedded.mutate_structured(
                &spec.database,
                None,
                schema,
                table,
                primary_keys,
                updates,
                inserts,
                deletes,
            );
        }
        let started = Instant::now();
        let db = if schema.is_empty() {
            spec.database.as_str()
        } else {
            schema
        };
        let dq = validate_ident_quoted(db, "schema", '`')?;
        let tq = validate_ident_quoted(table, "table", '`')?;
        let fq = format!("{dq}.{tq}");
        let mut stream = Self::connect_and_auth(spec).await?;

        let mut upd_cnt = 0u64;
        let mut ins_cnt = 0u64;
        let mut del_cnt = 0u64;

        for upd in updates {
            let (keys_map, vals_map) = upd.resolve_keys_and_changes(primary_keys);
            if keys_map.is_empty() || vals_map.is_empty() {
                continue;
            }
            let sets: Vec<String> = vals_map
                .iter()
                .map(|(k, v)| {
                    Ok(format!(
                        "{} = {}",
                        validate_ident_quoted(k, "column", '`')?,
                        mysql_lit(v)
                    ))
                })
                .collect::<Result<_, String>>()?;
            let wheres: Vec<String> = keys_map
                .iter()
                .map(|(k, v)| {
                    Ok(format!(
                        "{} = {}",
                        validate_ident_quoted(k, "key", '`')?,
                        mysql_lit(v)
                    ))
                })
                .collect::<Result<_, String>>()?;
            let sql = format!(
                "UPDATE {fq} SET {} WHERE {}",
                sets.join(", "),
                wheres.join(" AND ")
            );
            if let MySqlResult::Ok(n) = Self::exec_com_query(&mut stream, &sql).await? {
                upd_cnt += n;
            }
        }

        for ins in inserts {
            if ins.is_empty() {
                continue;
            }
            let cols: Vec<String> = ins
                .keys()
                .map(|k| validate_ident_quoted(k, "column", '`'))
                .collect::<Result<_, String>>()?;
            let vals: Vec<String> = ins.values().map(mysql_lit).collect();
            let sql = format!(
                "INSERT INTO {fq} ({}) VALUES ({})",
                cols.join(", "),
                vals.join(", ")
            );
            if let MySqlResult::Ok(n) = Self::exec_com_query(&mut stream, &sql).await? {
                ins_cnt += n;
            }
        }

        for del in deletes {
            if del.is_empty() {
                continue;
            }
            let wheres: Vec<String> = del
                .iter()
                .map(|(k, v)| {
                    Ok(format!(
                        "{} = {}",
                        validate_ident_quoted(k, "key", '`')?,
                        mysql_lit(v)
                    ))
                })
                .collect::<Result<_, String>>()?;
            let sql = format!("DELETE FROM {fq} WHERE {}", wheres.join(" AND "));
            if let MySqlResult::Ok(n) = Self::exec_com_query(&mut stream, &sql).await? {
                del_cnt += n;
            }
        }

        let _ = Map::<String, Value>::new();
        Ok(DbMutateResult {
            committed: true,
            updated: upd_cnt,
            inserted: ins_cnt,
            deleted: del_cnt,
            affected_rows: upd_cnt + ins_cnt + del_cnt,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
        })
    }
}

fn mysql_lit(v: &Value) -> String {
    match v {
        Value::Null => "NULL".to_owned(),
        Value::Bool(b) => if *b { "1" } else { "0" }.to_owned(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "''")),
        other => format!("'{}'", other.to_string().replace('\'', "''")),
    }
}

async fn read_mysql_packet(stream: &mut MySqlStream) -> Result<(u8, Vec<u8>), String> {
    let mut hdr = [0u8; 4];
    stream
        .read_exact(&mut hdr)
        .await
        .map_err(|e| format!("MySQL read header error: {e}"))?;
    let len = usize::from(hdr[0]) | (usize::from(hdr[1]) << 8) | (usize::from(hdr[2]) << 16);
    let seq = hdr[3];
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| format!("MySQL read body error: {e}"))?;
    Ok((seq, body))
}

async fn write_mysql_packet(
    stream: &mut MySqlStream,
    seq: u8,
    payload: &[u8],
) -> Result<(), String> {
    let len = payload.len();
    let hdr = [
        (len & 0xFF) as u8,
        ((len >> 8) & 0xFF) as u8,
        ((len >> 16) & 0xFF) as u8,
        seq,
    ];
    stream
        .write_all(&hdr)
        .await
        .map_err(|e| format!("MySQL write header error: {e}"))?;
    stream
        .write_all(payload)
        .await
        .map_err(|e| format!("MySQL write body error: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("MySQL flush error: {e}"))?;
    Ok(())
}

fn read_lenenc_int(buf: &[u8]) -> (u64, usize) {
    let Some(&first) = buf.first() else {
        return (0, 0);
    };
    match first {
        0..=0xFA => (u64::from(first), 1),
        0xFC if buf.len() >= 3 => (u64::from(u16::from_le_bytes([buf[1], buf[2]])), 3),
        0xFD if buf.len() >= 4 => (
            u64::from(buf[1]) | (u64::from(buf[2]) << 8) | (u64::from(buf[3]) << 16),
            4,
        ),
        0xFE if buf.len() >= 9 => (
            u64::from_le_bytes([
                buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
            ]),
            9,
        ),
        _ => (0, 1),
    }
}

fn parse_column_def_name(pkt: &[u8]) -> String {
    let mut off = 0usize;
    // skip catalog, schema, table, org_table -> 4 lenenc strings, then name (5th)
    for idx in 0..5 {
        if off >= pkt.len() {
            return format!("col_{idx}");
        }
        let (len, used) = read_lenenc_int(&pkt[off..]);
        off += used;
        let take = usize::try_from(len)
            .unwrap_or(0)
            .min(pkt.len().saturating_sub(off));
        if idx == 4 {
            return String::from_utf8_lossy(&pkt[off..off + take]).into_owned();
        }
        off += take;
    }
    "col".to_owned()
}

fn parse_err_packet(pkt: &[u8]) -> String {
    if pkt.len() < 3 {
        return "unknown error".to_owned();
    }
    let code = u16::from_le_bytes([pkt[1], pkt[2]]);
    let msg_start = if pkt.get(3).copied() == Some(b'#') && pkt.len() >= 9 {
        9
    } else {
        3
    };
    format!(
        "errno {code}: {}",
        String::from_utf8_lossy(&pkt[msg_start..])
    )
}

/// Pure-Rust `mysql_native_password`: `SHA1(password) XOR SHA1(scramble || SHA1(SHA1(password)))`.
#[must_use]
pub fn mysql_native_scramble(password: &str, scramble: &[u8]) -> Vec<u8> {
    let stage1 = sha1_digest(password.as_bytes());
    let stage2 = sha1_digest(&stage1);
    let mut cat = Vec::with_capacity(scramble.len() + 20);
    cat.extend_from_slice(scramble);
    cat.extend_from_slice(&stage2);
    let stage3 = sha1_digest(&cat);
    stage1
        .iter()
        .zip(stage3.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

/// Self-contained FIPS 180-4 SHA-1 (zero external deps, `#![forbid(unsafe_code)]`).
#[must_use]
pub fn sha1_digest(input: &[u8]) -> [u8; 20] {
    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}
