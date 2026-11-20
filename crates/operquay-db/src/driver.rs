use std::collections::HashMap;
use std::sync::OnceLock;

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const MAX_QUERY_ROWS: usize = 1000;
pub const PREVIEW_ROW_LIMIT: usize = 25;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DbConnectRequest {
    #[serde(default = "default_engine")]
    pub engine: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub database: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub ssl: Option<bool>,
    #[serde(default)]
    pub ssl_mode: String,
}

fn default_engine() -> String {
    "postgres".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbColumnDef {
    pub name: String,
    #[serde(rename = "type")]
    pub data_type: String,
    pub nullable: bool,
    #[serde(rename = "pk")]
    pub is_primary_key: bool,
    #[serde(rename = "default", skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTableDef {
    pub schema: String,
    pub name: String,
    #[serde(rename = "estimatedRows")]
    pub row_count: i64,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: i64,
    #[serde(rename = "sizePretty")]
    pub size: String,
    #[serde(default)]
    pub columns: Vec<DbColumnDef>,
    #[serde(default)]
    pub rows: Vec<Map<String, Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbConnectResult {
    pub connected: bool,
    pub connection_id: String,
    pub engine: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub databases: Vec<String>,
    pub tables: Vec<DbTableDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbQueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Map<String, Value>>,
    #[serde(default)]
    pub matrix_rows: Vec<Vec<Value>>,
    pub row_count: usize,
    pub duration_ms: u64,
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dlp_summary: Option<crate::dlp::DlpRedactionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbMutateResult {
    pub committed: bool,
    pub updated: u64,
    pub inserted: u64,
    pub deleted: u64,
    pub affected_rows: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbRowUpdate {
    #[serde(default)]
    pub keys: HashMap<String, Value>,
    #[serde(default)]
    pub values: HashMap<String, Value>,
    #[serde(default)]
    pub original: HashMap<String, Value>,
    #[serde(default)]
    pub changes: HashMap<String, Value>,
}

impl DbRowUpdate {
    /// Resolve `(where_keys, set_changes)` from either the Go/Frontend payload
    /// (`original` + `changes` filtered by `primary_keys`) or legacy Rust (`keys` + `values`).
    #[must_use]
    pub fn resolve_keys_and_changes(
        &self,
        primary_keys: &[String],
    ) -> (HashMap<String, Value>, HashMap<String, Value>) {
        if !self.keys.is_empty() || !self.values.is_empty() {
            return (self.keys.clone(), self.values.clone());
        }
        let mut where_keys = HashMap::new();
        if primary_keys.is_empty() {
            where_keys.clone_from(&self.original);
        } else {
            for pk in primary_keys {
                if let Some(val) = self.original.get(pk) {
                    where_keys.insert(pk.clone(), val.clone());
                }
            }
            if where_keys.is_empty() {
                where_keys.clone_from(&self.original);
            }
        }
        (where_keys, self.changes.clone())
    }
}

#[derive(Debug, Clone)]
pub struct DbConnectionSpec {
    pub tenant: String,
    pub engine: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: String,
    pub ssl_mode: String,
    pub cache_key: String,
}

#[derive(Debug, Clone)]
pub struct DbOperationError {
    pub message: String,
    pub blocked_by_guard: bool,
}

impl DbOperationError {
    #[must_use]
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            blocked_by_guard: false,
        }
    }

    #[must_use]
    pub fn blocked(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            blocked_by_guard: true,
        }
    }
}

impl From<String> for DbOperationError {
    fn from(message: String) -> Self {
        Self::err(message)
    }
}

/// Polymorphic Object-Oriented database driver seam implemented uniformly per backend engine
/// (`PostgresDriver`, `ClickHouseDriver`, `DuckDbDriver`, `MySqlDriver`, `RedisDriver`).
#[async_trait]
pub trait DatabaseEngineDriver: Send + Sync {
    fn engine(&self) -> &'static str;
    fn default_port(&self) -> u16;
    fn normalize_request(&self, req: &DbConnectRequest) -> DbConnectRequest;

    async fn connect_and_inspect(
        &self,
        spec: &DbConnectionSpec,
    ) -> Result<(Vec<String>, Vec<DbTableDef>), String>;

    async fn query(
        &self,
        spec: &DbConnectionSpec,
        sql: &str,
        read_only: bool,
    ) -> Result<DbQueryResult, DbOperationError>;

    async fn mutate_sql(&self, spec: &DbConnectionSpec, sql: &str) -> Result<u64, String>;

    async fn mutate_structured(
        &self,
        spec: &DbConnectionSpec,
        schema: &str,
        table: &str,
        primary_keys: &[String],
        updates: &[DbRowUpdate],
        inserts: &[HashMap<String, Value>],
        deletes: &[HashMap<String, Value>],
    ) -> Result<DbMutateResult, String>;
}

fn write_sql_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^\s*(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE|MERGE|COPY|VACUUM|REINDEX|CLUSTER|CALL|DO|ATTACH|DETACH|REPLACE|RENAME|SET\s+GLOBAL|FLUSH|DEL\b)",
        )
        .expect("valid write sql regex")
    })
}

fn ident_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("valid ident regex"))
}

#[must_use]
pub fn strip_leading_comments(sql: &str) -> String {
    let mut s = sql.trim_start();
    loop {
        if s.starts_with("--") {
            s = s.split_once('\n').map_or("", |(_, rest)| rest.trim_start());
        } else if s.starts_with("/*") {
            s = s.split_once("*/").map_or("", |(_, rest)| rest.trim_start());
        } else {
            break;
        }
    }
    s.to_owned()
}

#[must_use]
pub fn is_write_sql(sql: &str) -> bool {
    let cleaned = strip_leading_comments(sql);
    write_sql_regex().is_match(&cleaned)
}

pub fn validate_ident_quoted(raw: &str, kind: &str, quote_char: char) -> Result<String, String> {
    let trimmed = raw.trim();
    if !ident_regex().is_match(trimmed) {
        return Err(format!("invalid {kind} identifier '{raw}'"));
    }
    Ok(format!("{quote_char}{trimmed}{quote_char}"))
}

#[must_use]
pub fn compact_byte_size(bytes: i64) -> String {
    if bytes < 1024 {
        return format!("{bytes}B");
    }
    let kb = bytes / 1024;
    if kb < 1024 {
        return format!("{kb}K");
    }
    let mb = kb / 1024;
    if mb < 1024 {
        return format!("{mb}M");
    }
    format!("{}G", mb / 1024)
}

#[must_use]
pub fn rows_to_objects(columns: &[String], matrix: &[Vec<Value>]) -> Vec<Map<String, Value>> {
    matrix
        .iter()
        .map(|row| {
            let mut obj = Map::with_capacity(columns.len());
            for (idx, col) in columns.iter().enumerate() {
                obj.insert(col.clone(), row.get(idx).cloned().unwrap_or(Value::Null));
            }
            obj
        })
        .collect()
}

#[must_use]
pub fn read_only_block_error() -> DbOperationError {
    DbOperationError::blocked(
        "blocked by read-only guard: write statements require toggling off Read-Only Guard or using /api/db/mutate",
    )
}
