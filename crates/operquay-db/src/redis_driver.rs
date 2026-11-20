use std::collections::{BTreeMap, HashMap};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{Map, Value};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf,
};
use tokio::net::TcpStream;

use crate::driver::{
    compact_byte_size, read_only_block_error, rows_to_objects, DatabaseEngineDriver, DbColumnDef,
    DbConnectRequest, DbConnectionSpec, DbMutateResult, DbOperationError, DbQueryResult,
    DbRowUpdate, DbTableDef, PREVIEW_ROW_LIMIT,
};
use crate::tls::{build_client_tls_connector, resolve_server_name, should_use_tls};

const REDIS_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) enum RedisStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for RedisStream {
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

impl AsyncWrite for RedisStream {
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

#[derive(Debug, Clone)]
pub enum RespValue {
    Simple(String),
    Error(String),
    Integer(i64),
    Bulk(Option<Vec<u8>>),
    Array(Option<Vec<RespValue>>),
}

impl RespValue {
    fn as_str_lossy(&self) -> Option<String> {
        match self {
            Self::Simple(s) | Self::Error(s) => Some(s.clone()),
            Self::Integer(n) => Some(n.to_string()),
            Self::Bulk(Some(b)) => Some(String::from_utf8_lossy(b).into_owned()),
            Self::Bulk(None) | Self::Array(None) => None,
            Self::Array(Some(items)) => {
                let parts: Vec<String> = items.iter().filter_map(Self::as_str_lossy).collect();
                Some(parts.join(", "))
            }
        }
    }

    fn to_json(&self) -> Value {
        match self {
            Self::Simple(s) => Value::String(s.clone()),
            Self::Error(e) => Value::String(format!("ERR: {e}")),
            Self::Integer(n) => serde_json::json!(n),
            Self::Bulk(Some(b)) => Value::String(String::from_utf8_lossy(b).into_owned()),
            Self::Bulk(None) | Self::Array(None) => Value::Null,
            Self::Array(Some(items)) => Value::Array(items.iter().map(Self::to_json).collect()),
        }
    }
}

/// Pure-Rust Redis RESP2 TCP client supporting keyspace inspection, previews, read-only guards,
/// and inline Redis commands (`GET`, `KEYS`, `SCAN`, `HGETALL`, `INFO`, `SET`, `DEL`, etc.).
#[derive(Debug, Default)]
pub struct RedisDriver;

impl RedisDriver {
    async fn connect(spec: &DbConnectionSpec) -> Result<BufReader<RedisStream>, String> {
        let use_tls = should_use_tls(&spec.ssl_mode)?;
        let port = if spec.port == 0 { 6379 } else { spec.port };
        let tcp = tokio::time::timeout(
            REDIS_TIMEOUT,
            TcpStream::connect((spec.host.as_str(), port)),
        )
        .await
        .map_err(|_| format!("Redis connect timed out to {}:{port}", spec.host))?
        .map_err(|e| format!("Redis connect failed to {}:{port}: {e}", spec.host))?;

        let stream = if use_tls {
            let connector = build_client_tls_connector(&spec.ssl_mode)?;
            let server_name = resolve_server_name(&spec.host)?;
            let tls = tokio::time::timeout(REDIS_TIMEOUT, connector.connect(server_name, tcp))
                .await
                .map_err(|_| format!("Redis TLS handshake timed out to {}:{port}", spec.host))?
                .map_err(|e| format!("Redis TLS handshake failed to {}:{port}: {e}", spec.host))?;
            RedisStream::Tls(Box::new(tls))
        } else {
            RedisStream::Plain(tcp)
        };

        let mut reader = BufReader::new(stream);
        if !spec.password.is_empty() {
            let args: Vec<&str> = if spec.username.is_empty() || spec.username == "default" {
                vec!["AUTH", &spec.password]
            } else {
                vec!["AUTH", &spec.username, &spec.password]
            };
            let auth = exec_resp(&mut reader, &args).await?;
            if let RespValue::Error(e) = auth {
                return Err(format!("Redis AUTH failed: {e}"));
            }
        }
        if let Ok(db_idx) = spec.database.trim().parse::<u16>() {
            let idx_str = db_idx.to_string();
            let sel = exec_resp(&mut reader, &["SELECT", &idx_str]).await?;
            if let RespValue::Error(e) = sel {
                return Err(format!("Redis SELECT {db_idx} failed: {e}"));
            }
        } else {
            let ping = exec_resp(&mut reader, &["PING"]).await?;
            if let RespValue::Error(e) = ping {
                return Err(format!("Redis PING failed: {e}"));
            }
        }
        Ok(reader)
    }
}

#[async_trait]
impl DatabaseEngineDriver for RedisDriver {
    fn engine(&self) -> &'static str {
        "redis"
    }

    fn default_port(&self) -> u16 {
        6379
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
            out.database = "0".into();
        }
        out
    }

    async fn connect_and_inspect(
        &self,
        spec: &DbConnectionSpec,
    ) -> Result<(Vec<String>, Vec<DbTableDef>), String> {
        let mut reader = Self::connect(spec).await?;
        let scan_res = exec_resp(&mut reader, &["SCAN", "0", "COUNT", "25"]).await?;
        let keys: Vec<String> = match scan_res {
            RespValue::Array(Some(parts)) => parts
                .get(1)
                .and_then(|v| match v {
                    RespValue::Array(Some(ks)) => {
                        Some(ks.iter().filter_map(RespValue::as_str_lossy).collect())
                    }
                    _ => None,
                })
                .unwrap_or_default(),
            _ => Vec::new(),
        };

        let mut rows_by_type: BTreeMap<String, Vec<Map<String, Value>>> = BTreeMap::new();
        for key in keys.into_iter().take(PREVIEW_ROW_LIMIT) {
            let ktype = exec_resp(&mut reader, &["TYPE", &key])
                .await
                .ok()
                .and_then(|v| v.as_str_lossy())
                .unwrap_or_else(|| "string".into());
            let val = match ktype.as_str() {
                "string" => exec_resp(&mut reader, &["GET", &key])
                    .await
                    .map_or(Value::Null, |v| v.to_json()),
                "hash" => exec_resp(&mut reader, &["HGETALL", &key])
                    .await
                    .map_or(Value::Null, |v| v.to_json()),
                "list" => exec_resp(&mut reader, &["LRANGE", &key, "0", "10"])
                    .await
                    .map_or(Value::Null, |v| v.to_json()),
                "set" => exec_resp(&mut reader, &["SMEMBERS", &key])
                    .await
                    .map_or(Value::Null, |v| v.to_json()),
                _ => Value::String(format!("<{ktype}>")),
            };
            let mut m = Map::new();
            m.insert("key".into(), Value::String(key));
            m.insert("type".into(), Value::String(ktype.clone()));
            m.insert("value".into(), val);
            rows_by_type.entry(ktype).or_default().push(m);
        }

        let db_name = if spec.database.is_empty() {
            "0".to_owned()
        } else {
            spec.database.clone()
        };
        let tables: Vec<DbTableDef> = if rows_by_type.is_empty() {
            vec![DbTableDef {
                schema: format!("db{db_name}"),
                name: "keys".into(),
                row_count: 0,
                size_bytes: 0,
                size: compact_byte_size(0),
                columns: redis_columns(),
                rows: Vec::new(),
            }]
        } else {
            rows_by_type
                .into_iter()
                .map(|(ktype, rows)| {
                    let count = i64::try_from(rows.len()).unwrap_or(0);
                    let bytes = count.saturating_mul(128);
                    DbTableDef {
                        schema: format!("db{db_name}"),
                        name: format!("keys:{ktype}"),
                        row_count: count,
                        size_bytes: bytes,
                        size: compact_byte_size(bytes),
                        columns: redis_columns(),
                        rows,
                    }
                })
                .collect()
        };

        Ok((vec![db_name], tables))
    }

    async fn query(
        &self,
        spec: &DbConnectionSpec,
        sql: &str,
        read_only: bool,
    ) -> Result<DbQueryResult, DbOperationError> {
        let tokens = split_redis_cmd(sql);
        if tokens.is_empty() {
            return Err(DbOperationError::err("empty Redis command"));
        }
        let cmd_upper = tokens[0].to_ascii_uppercase();
        if read_only && is_redis_write_cmd(&cmd_upper) {
            return Err(read_only_block_error());
        }

        let started = Instant::now();
        let mut reader = Self::connect(spec).await?;
        let arg_refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
        let resp = exec_resp(&mut reader, &arg_refs).await?;
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(0);

        let columns = vec!["item".to_owned(), "value".to_owned()];
        let matrix = match resp {
            RespValue::Array(Some(items)) => items
                .into_iter()
                .enumerate()
                .map(|(i, v)| vec![serde_json::json!(i), v.to_json()])
                .collect(),
            other => vec![vec![Value::String(cmd_upper), other.to_json()]],
        };
        let rows = rows_to_objects(&columns, &matrix);
        Ok(DbQueryResult {
            row_count: rows.len(),
            columns,
            rows,
            matrix_rows: matrix,
            duration_ms,
            truncated: false,
            dlp_summary: None,
        })
    }

    async fn mutate_sql(&self, spec: &DbConnectionSpec, sql: &str) -> Result<u64, String> {
        let tokens = split_redis_cmd(sql);
        if tokens.is_empty() {
            return Err("empty Redis command".into());
        }
        let mut reader = Self::connect(spec).await?;
        let refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
        let resp = exec_resp(&mut reader, &refs).await?;
        match resp {
            RespValue::Error(e) => Err(format!("Redis error: {e}")),
            RespValue::Integer(n) => Ok(u64::try_from(n).unwrap_or(1)),
            _ => Ok(1),
        }
    }

    async fn mutate_structured(
        &self,
        spec: &DbConnectionSpec,
        _schema: &str,
        _table: &str,
        primary_keys: &[String],
        updates: &[DbRowUpdate],
        inserts: &[HashMap<String, Value>],
        deletes: &[HashMap<String, Value>],
    ) -> Result<DbMutateResult, String> {
        let started = Instant::now();
        let mut reader = Self::connect(spec).await?;
        let mut upd_cnt = 0u64;
        let mut ins_cnt = 0u64;
        let mut del_cnt = 0u64;

        for upd in updates {
            let (keys_map, vals_map) = upd.resolve_keys_and_changes(primary_keys);
            if let (Some(k), Some(v)) = (
                keys_map.get("key").and_then(Value::as_str),
                vals_map.get("value"),
            ) {
                let val_str = v.as_str().map_or_else(|| v.to_string(), ToOwned::to_owned);
                let _ = exec_resp(&mut reader, &["SET", k, &val_str]).await?;
                upd_cnt += 1;
            }
        }
        for ins in inserts {
            if let (Some(k), Some(v)) = (ins.get("key").and_then(Value::as_str), ins.get("value")) {
                let val_str = v.as_str().map_or_else(|| v.to_string(), ToOwned::to_owned);
                let _ = exec_resp(&mut reader, &["SET", k, &val_str]).await?;
                ins_cnt += 1;
            }
        }
        for del in deletes {
            if let Some(k) = del.get("key").and_then(Value::as_str) {
                let _ = exec_resp(&mut reader, &["DEL", k]).await?;
                del_cnt += 1;
            }
        }

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

fn redis_columns() -> Vec<DbColumnDef> {
    vec![
        DbColumnDef {
            name: "key".into(),
            data_type: "string".into(),
            nullable: false,
            is_primary_key: true,
            default_value: None,
        },
        DbColumnDef {
            name: "type".into(),
            data_type: "string".into(),
            nullable: false,
            is_primary_key: false,
            default_value: None,
        },
        DbColumnDef {
            name: "value".into(),
            data_type: "json".into(),
            nullable: true,
            is_primary_key: false,
            default_value: None,
        },
    ]
}

fn is_redis_write_cmd(cmd: &str) -> bool {
    matches!(
        cmd,
        "SET"
            | "DEL"
            | "UNLINK"
            | "MSET"
            | "HSET"
            | "HDEL"
            | "LPUSH"
            | "RPUSH"
            | "LPOP"
            | "RPOP"
            | "SADD"
            | "SREM"
            | "ZADD"
            | "ZREM"
            | "INCR"
            | "DECR"
            | "EXPIRE"
            | "FLUSHDB"
            | "FLUSHALL"
            | "RENAME"
    )
}

fn split_redis_cmd(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for ch in raw.trim().chars() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                cur.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            quote = Some(ch);
        } else if ch.is_whitespace() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(ch);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub(crate) async fn exec_resp(
    reader: &mut BufReader<RedisStream>,
    args: &[&str],
) -> Result<RespValue, String> {
    let mut req = format!("*{}\r\n", args.len()).into_bytes();
    for a in args {
        let b = a.as_bytes();
        req.extend_from_slice(format!("${}\r\n", b.len()).as_bytes());
        req.extend_from_slice(b);
        req.extend_from_slice(b"\r\n");
    }
    tokio::time::timeout(REDIS_TIMEOUT, async {
        reader.get_mut().write_all(&req).await?;
        reader.get_mut().flush().await
    })
    .await
    .map_err(|_| "Redis write timeout".to_owned())?
    .map_err(|e| format!("Redis write error: {e}"))?;

    Box::pin(read_resp_value(reader)).await
}

async fn read_resp_line(reader: &mut BufReader<RedisStream>) -> Result<String, String> {
    let mut line = String::new();
    let n = tokio::time::timeout(REDIS_TIMEOUT, reader.read_line(&mut line))
        .await
        .map_err(|_| "Redis read timeout".to_owned())?
        .map_err(|e| format!("Redis read error: {e}"))?;
    if n == 0 {
        return Err("Redis closed connection".into());
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

async fn read_resp_value(reader: &mut BufReader<RedisStream>) -> Result<RespValue, String> {
    let line = read_resp_line(reader).await?;
    let mut chars = line.chars();
    let prefix = chars.next().unwrap_or(' ');
    let rest = chars.as_str();
    match prefix {
        '+' => Ok(RespValue::Simple(rest.to_owned())),
        '-' => Ok(RespValue::Error(rest.to_owned())),
        ':' => Ok(RespValue::Integer(rest.parse::<i64>().unwrap_or(0))),
        '$' => {
            let len = rest.parse::<isize>().unwrap_or(-1);
            if len < 0 {
                return Ok(RespValue::Bulk(None));
            }
            let ul = usize::try_from(len).unwrap_or(0);
            let mut buf = vec![0u8; ul];
            reader
                .read_exact(&mut buf)
                .await
                .map_err(|e| format!("Redis bulk read error: {e}"))?;
            let mut crlf = [0u8; 2];
            let _ = reader.read_exact(&mut crlf).await;
            Ok(RespValue::Bulk(Some(buf)))
        }
        '*' => {
            let count = rest.parse::<isize>().unwrap_or(-1);
            if count < 0 {
                return Ok(RespValue::Array(None));
            }
            let uc = usize::try_from(count).unwrap_or(0).min(10_000);
            let mut items = Vec::with_capacity(uc);
            for _ in 0..uc {
                items.push(Box::pin(read_resp_value(reader)).await?);
            }
            Ok(RespValue::Array(Some(items)))
        }
        _ => Ok(RespValue::Simple(line)),
    }
}
