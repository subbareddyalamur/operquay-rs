use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::driver::{
    compact_byte_size, is_write_sql, read_only_block_error, rows_to_objects,
    strip_leading_comments, validate_ident_quoted, DbColumnDef, DbMutateResult, DbOperationError,
    DbQueryResult, DbRowUpdate, DbTableDef, MAX_QUERY_ROWS, PREVIEW_ROW_LIMIT,
};

const OQDUCK_MAGIC: &[u8; 8] = b"OQDUCK01";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnarTable {
    pub schema: String,
    pub name: String,
    pub columns: Vec<DbColumnDef>,
    pub rows: Vec<Map<String, Value>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EngineCatalog {
    databases: BTreeMap<String, Vec<ColumnarTable>>,
}

/// Pure-Rust in-process columnar SQL store shared by `DuckDbDriver` (native embedded analytics
/// with optional file snapshot) and `ClickHouseDriver` (`host=embedded|memory`).
#[derive(Debug)]
pub struct EmbeddedColumnarEngine {
    engine_name: &'static str,
    default_schema: &'static str,
    catalog: RwLock<EngineCatalog>,
}

impl EmbeddedColumnarEngine {
    #[must_use]
    pub fn new_duckdb() -> Self {
        let engine = Self {
            engine_name: "duckdb",
            default_schema: "main",
            catalog: RwLock::new(EngineCatalog::default()),
        };
        engine.seed_defaults("analytics");
        engine
    }

    #[must_use]
    pub fn new_clickhouse_embedded() -> Self {
        let engine = Self {
            engine_name: "clickhouse",
            default_schema: "default",
            catalog: RwLock::new(EngineCatalog::default()),
        };
        engine.seed_defaults("default");
        engine
    }

    fn seed_defaults(&self, default_db: &str) {
        if let Ok(mut guard) = self.catalog.write() {
            let schema = self.default_schema.to_owned();
            let tables = vec![
                ColumnarTable {
                    schema: schema.clone(),
                    name: "telemetry_events".to_owned(),
                    columns: vec![
                        col("event_id", "VARCHAR", true, false),
                        col("protocol", "VARCHAR", false, false),
                        col("preset", "VARCHAR", false, false),
                        col("fps", "DOUBLE", false, true),
                        col("latency_ms", "DOUBLE", false, true),
                        col("tenant_id", "VARCHAR", false, false),
                    ],
                    rows: vec![
                        obj([
                            ("event_id", Value::String("evt-001".into())),
                            ("protocol", Value::String("rdp".into())),
                            ("preset", Value::String("auto_adaptive".into())),
                            ("fps", serde_json::json!(60.0)),
                            ("latency_ms", serde_json::json!(11.4)),
                            ("tenant_id", Value::String("default".into())),
                        ]),
                        obj([
                            ("event_id", Value::String("evt-002".into())),
                            ("protocol", Value::String("vnc".into())),
                            ("preset", Value::String("ultra_low_latency".into())),
                            ("fps", serde_json::json!(59.8)),
                            ("latency_ms", serde_json::json!(8.9)),
                            ("tenant_id", Value::String("default".into())),
                        ]),
                    ],
                },
                ColumnarTable {
                    schema: schema.clone(),
                    name: "session_audit_log".to_owned(),
                    columns: vec![
                        col("id", "VARCHAR", true, false),
                        col("session_id", "VARCHAR", false, false),
                        col("action", "VARCHAR", false, false),
                        col("target_host", "VARCHAR", false, false),
                        ("duration_ms", "BIGINT", false, true).into_col(),
                    ],
                    rows: vec![obj([
                        ("id", Value::String("aud-001".into())),
                        ("session_id", Value::String("sess-bootstrap".into())),
                        ("action", Value::String("session_connected".into())),
                        ("target_host", Value::String("win2025-ssm.internal".into())),
                        ("duration_ms", serde_json::json!(42)),
                    ])],
                },
                ColumnarTable {
                    schema,
                    name: "cloud_inventory".to_owned(),
                    columns: vec![
                        col("instance_id", "VARCHAR", true, false),
                        col("region", "VARCHAR", false, false),
                        col("platform", "VARCHAR", false, false),
                        col("state", "VARCHAR", false, false),
                    ],
                    rows: vec![obj([
                        ("instance_id", Value::String("i-0a1b2c3d4e5f60001".into())),
                        ("region", Value::String("us-east-1".into())),
                        ("platform", Value::String("windows".into())),
                        ("state", Value::String("running".into())),
                    ])],
                },
            ];
            guard.databases.insert(default_db.to_owned(), tables);
        }
    }

    pub fn load_snapshot_if_exists(&self, path: &str, db_name: &str) {
        let _ = self.load_snapshot_checked(path, db_name);
    }

    pub fn load_snapshot_checked(&self, path: &str, db_name: &str) -> Result<(), String> {
        let pb = PathBuf::from(path);
        if !pb.exists() {
            return Ok(());
        }
        let bytes = std::fs::read(&pb).map_err(|e| format!("failed reading DuckDB file: {e}"))?;
        let json_slice = if bytes.starts_with(OQDUCK_MAGIC) {
            if bytes.len() < 16 {
                return Err("corrupted OQDUCK01 snapshot header".into());
            }
            let expected_crc = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
            let payload_len =
                u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
            let end = 16usize
                .checked_add(payload_len)
                .ok_or_else(|| "OQDUCK01 snapshot length overflow".to_owned())?;
            if bytes.len() < end {
                return Err("truncated OQDUCK01 snapshot payload".into());
            }
            let payload = &bytes[16..end];
            if crc32fast::hash(payload) != expected_crc {
                return Err("OQDUCK01 snapshot CRC32 checksum mismatch (corrupted file)".into());
            }
            payload
        } else {
            &bytes
        };
        let loaded = serde_json::from_slice::<Vec<ColumnarTable>>(json_slice)
            .map_err(|e| format!("corrupted DuckDB snapshot JSON: {e}"))?;
        let mut guard = self
            .catalog
            .write()
            .map_err(|_| "catalog poisoned".to_owned())?;
        guard.databases.insert(db_name.to_owned(), loaded);
        Ok(())
    }

    fn persist_snapshot_if_configured(&self, snapshot_path: Option<&str>, db_name: &str) {
        let Some(path) = snapshot_path.filter(|p| !p.trim().is_empty()) else {
            return;
        };
        if path == "memory" || path == ":memory:" || path == "embedded" {
            return;
        }
        let pb = PathBuf::from(path);
        if let Some(parent) = pb.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        if let Ok(guard) = self.catalog.read() {
            if let Some(tables) = guard.databases.get(db_name) {
                if let Ok(json) = serde_json::to_vec(tables) {
                    let crc = crc32fast::hash(&json);
                    let len = u32::try_from(json.len()).unwrap_or(0);
                    let mut frame = Vec::with_capacity(16 + json.len());
                    frame.extend_from_slice(OQDUCK_MAGIC);
                    frame.extend_from_slice(&crc.to_be_bytes());
                    frame.extend_from_slice(&len.to_be_bytes());
                    frame.extend_from_slice(&json);

                    let tmp_path = pb.with_extension(format!("duckdb.tmp.{}", std::process::id()));
                    let mut opts = std::fs::OpenOptions::new();
                    opts.write(true).create(true).truncate(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt as _;
                        opts.mode(0o600);
                    }
                    if let Ok(mut f) = opts.open(&tmp_path) {
                        use std::io::Write as _;
                        if f.write_all(&frame).is_ok() && f.sync_all().is_ok() {
                            let _ = std::fs::rename(&tmp_path, &pb);
                        } else {
                            let _ = std::fs::remove_file(&tmp_path);
                        }
                    }
                }
            }
        }
    }

    pub fn inspect(
        &self,
        database: &str,
        snapshot_path: Option<&str>,
    ) -> (Vec<String>, Vec<DbTableDef>) {
        self.inspect_checked(database, snapshot_path)
            .unwrap_or_else(|_| (vec![database.to_owned()], Vec::new()))
    }

    pub fn inspect_checked(
        &self,
        database: &str,
        snapshot_path: Option<&str>,
    ) -> Result<(Vec<String>, Vec<DbTableDef>), String> {
        let db = self.ensure_database_checked(database, snapshot_path)?;
        let guard = self
            .catalog
            .read()
            .map_err(|_| "catalog poisoned".to_owned())?;
        let dbs: Vec<String> = guard.databases.keys().cloned().collect();
        let tables = guard.databases.get(&db).map_or_default(|tbls| {
            tbls.iter()
                .map(|t| {
                    let est = i64::try_from(t.rows.len()).unwrap_or(0);
                    let bytes = est.saturating_mul(192).max(4096);
                    DbTableDef {
                        schema: t.schema.clone(),
                        name: t.name.clone(),
                        row_count: est,
                        size_bytes: bytes,
                        size: compact_byte_size(bytes),
                        columns: t.columns.clone(),
                        rows: t.rows.iter().take(PREVIEW_ROW_LIMIT).cloned().collect(),
                    }
                })
                .collect()
        });
        Ok((dbs, tables))
    }

    fn ensure_database_checked(
        &self,
        database: &str,
        snapshot_path: Option<&str>,
    ) -> Result<String, String> {
        let db = if database.trim().is_empty() {
            if self.engine_name == "duckdb" {
                "analytics".to_owned()
            } else {
                "default".to_owned()
            }
        } else {
            database.trim().to_owned()
        };
        if let Some(path) = snapshot_path {
            let ext_ok = std::path::Path::new(path).extension().is_some_and(|e| {
                e.eq_ignore_ascii_case("duckdb") || e.eq_ignore_ascii_case("json")
            });
            if ext_ok && path != ":memory:" && path != "memory" {
                self.load_snapshot_checked(path, &db)?;
            }
        }
        if let Ok(mut guard) = self.catalog.write() {
            if !guard.databases.contains_key(&db) {
                let seed = guard.databases.values().next().cloned().unwrap_or_default();
                guard.databases.insert(db.clone(), seed);
            }
        }
        Ok(db)
    }

    pub fn query(
        &self,
        database: &str,
        snapshot_path: Option<&str>,
        sql: &str,
        read_only: bool,
    ) -> Result<DbQueryResult, DbOperationError> {
        let started = Instant::now();
        let db = self
            .ensure_database_checked(database, snapshot_path)
            .map_err(DbOperationError::err)?;
        let clean = strip_leading_comments(sql);
        let stmt = clean.trim().trim_end_matches(';').trim();
        if stmt.is_empty() {
            return Err(DbOperationError::err("empty SQL statement"));
        }
        if read_only && is_write_sql(stmt) {
            return Err(read_only_block_error());
        }
        let upper = stmt.to_ascii_uppercase();

        if upper == "SHOW DATABASES" {
            let guard = self
                .catalog
                .read()
                .map_err(|_| DbOperationError::err("catalog poisoned"))?;
            let cols = vec!["database".to_owned()];
            let matrix: Vec<Vec<Value>> = guard
                .databases
                .keys()
                .map(|k| vec![Value::String(k.clone())])
                .collect();
            let rows = rows_to_objects(&cols, &matrix);
            return Ok(DbQueryResult {
                row_count: rows.len(),
                columns: cols,
                rows,
                matrix_rows: matrix,
                duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
                truncated: false,
                dlp_summary: None,
            });
        }

        if upper == "SHOW TABLES" {
            let guard = self
                .catalog
                .read()
                .map_err(|_| DbOperationError::err("catalog poisoned"))?;
            let tbls = guard.databases.get(&db).cloned().unwrap_or_default();
            let cols = vec![
                "schema".to_owned(),
                "table_name".to_owned(),
                "estimated_rows".to_owned(),
                "columns".to_owned(),
            ];
            let matrix: Vec<Vec<Value>> = tbls
                .iter()
                .map(|t| {
                    vec![
                        Value::String(t.schema.clone()),
                        Value::String(t.name.clone()),
                        serde_json::json!(t.rows.len()),
                        serde_json::json!(t.columns.len()),
                    ]
                })
                .collect();
            let rows = rows_to_objects(&cols, &matrix);
            return Ok(DbQueryResult {
                row_count: rows.len(),
                columns: cols,
                rows,
                matrix_rows: matrix,
                duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
                truncated: false,
                dlp_summary: None,
            });
        }

        if let Some(rest) = strip_ci_prefix(stmt, "DESCRIBE ")
            .or_else(|| strip_ci_prefix(stmt, "DESC "))
            .or_else(|| {
                strip_ci_prefix(stmt, "PRAGMA table_info(")
                    .map(|inner| inner.trim_end_matches(')').trim())
            })
        {
            let tbl_name = parse_table_ref(rest.trim());
            let guard = self
                .catalog
                .read()
                .map_err(|_| DbOperationError::err("catalog poisoned"))?;
            let tbl = find_table(&guard, &db, &tbl_name).ok_or_else(|| {
                DbOperationError::err(format!("table '{tbl_name}' does not exist"))
            })?;
            let cols = vec![
                "column_name".to_owned(),
                "column_type".to_owned(),
                "null".to_owned(),
                "key".to_owned(),
            ];
            let matrix: Vec<Vec<Value>> = tbl
                .columns
                .iter()
                .map(|c| {
                    vec![
                        Value::String(c.name.clone()),
                        Value::String(c.data_type.clone()),
                        Value::String(if c.nullable { "YES" } else { "NO" }.to_owned()),
                        Value::String(if c.is_primary_key { "PRI" } else { "" }.to_owned()),
                    ]
                })
                .collect();
            let rows = rows_to_objects(&cols, &matrix);
            return Ok(DbQueryResult {
                row_count: rows.len(),
                columns: cols,
                rows,
                matrix_rows: matrix,
                duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
                truncated: false,
                dlp_summary: None,
            });
        }

        if let Some(rest) = strip_ci_prefix(stmt, "EXPLAIN ") {
            let cols = vec!["QUERY PLAN".to_owned()];
            let plan = format!(
                "COLUMNAR VECTORIZED SCAN ({}) -> {}",
                self.engine_name.to_uppercase(),
                rest.trim()
            );
            let matrix = vec![vec![Value::String(plan)]];
            let rows = rows_to_objects(&cols, &matrix);
            return Ok(DbQueryResult {
                row_count: rows.len(),
                columns: cols,
                rows,
                matrix_rows: matrix,
                duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
                truncated: false,
                dlp_summary: None,
            });
        }

        if upper.starts_with("SELECT ") {
            return self.exec_select(&db, stmt, started);
        }

        if is_write_sql(stmt) {
            let affected = self
                .exec_write(&db, snapshot_path, stmt)
                .map_err(DbOperationError::err)?;
            let cols = vec!["affected_rows".to_owned()];
            let matrix = vec![vec![serde_json::json!(affected)]];
            let rows = rows_to_objects(&cols, &matrix);
            return Ok(DbQueryResult {
                row_count: 1,
                columns: cols,
                rows,
                matrix_rows: matrix,
                duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
                truncated: false,
                dlp_summary: None,
            });
        }

        Err(DbOperationError::err(format!(
            "unsupported {} SQL syntax: '{}'",
            self.engine_name, stmt
        )))
    }

    pub fn mutate_sql(
        &self,
        database: &str,
        snapshot_path: Option<&str>,
        sql: &str,
    ) -> Result<u64, String> {
        let db = self.ensure_database_checked(database, snapshot_path)?;
        let clean = strip_leading_comments(sql);
        let stmt = clean.trim().trim_end_matches(';').trim();
        self.exec_write(&db, snapshot_path, stmt)
    }

    pub fn mutate_structured(
        &self,
        database: &str,
        snapshot_path: Option<&str>,
        schema: &str,
        table: &str,
        primary_keys: &[String],
        updates: &[DbRowUpdate],
        inserts: &[HashMap<String, Value>],
        deletes: &[HashMap<String, Value>],
    ) -> Result<DbMutateResult, String> {
        let started = Instant::now();
        let db = self.ensure_database_checked(database, snapshot_path)?;
        let _ = validate_ident_quoted(table, "table", '"')?;
        let mut upd_cnt = 0u64;
        let mut ins_cnt = 0u64;
        let mut del_cnt = 0u64;

        {
            let mut guard = self
                .catalog
                .write()
                .map_err(|_| "catalog poisoned".to_owned())?;
            let tbls = guard
                .databases
                .get_mut(&db)
                .ok_or_else(|| format!("database '{db}' not found"))?;
            let tbl = tbls
                .iter_mut()
                .find(|t| {
                    t.name.eq_ignore_ascii_case(table)
                        && (schema.is_empty() || t.schema.eq_ignore_ascii_case(schema))
                })
                .ok_or_else(|| format!("table '{table}' not found"))?;

            for upd in updates {
                let (keys_map, vals_map) = upd.resolve_keys_and_changes(primary_keys);
                if keys_map.is_empty() || vals_map.is_empty() {
                    continue;
                }
                for row in &mut tbl.rows {
                    if row_matches_map(row, &keys_map) {
                        for (k, v) in &vals_map {
                            row.insert(k.clone(), v.clone());
                        }
                        upd_cnt += 1;
                    }
                }
            }

            for ins in inserts {
                if ins.is_empty() {
                    continue;
                }
                let mut map = Map::new();
                for col in &tbl.columns {
                    map.insert(
                        col.name.clone(),
                        ins.get(&col.name).cloned().unwrap_or(Value::Null),
                    );
                }
                for (k, v) in ins {
                    map.entry(k.clone()).or_insert_with(|| v.clone());
                }
                tbl.rows.push(map);
                ins_cnt += 1;
            }

            for del in deletes {
                if del.is_empty() {
                    continue;
                }
                let before = tbl.rows.len();
                tbl.rows.retain(|row| !row_matches_map(row, del));
                del_cnt += u64::try_from(before.saturating_sub(tbl.rows.len())).unwrap_or(0);
            }
        }

        self.persist_snapshot_if_configured(snapshot_path, &db);
        let affected_rows = upd_cnt + ins_cnt + del_cnt;
        Ok(DbMutateResult {
            committed: true,
            updated: upd_cnt,
            inserted: ins_cnt,
            deleted: del_cnt,
            affected_rows,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
        })
    }

    fn exec_select(
        &self,
        db: &str,
        stmt: &str,
        started: Instant,
    ) -> Result<DbQueryResult, DbOperationError> {
        let rest = &stmt[6..].trim();
        let upper = rest.to_ascii_uppercase();
        if let Some(from_idx) = find_kw(&upper, " FROM ") {
            let proj_raw = rest[..from_idx].trim();
            let after_from = rest[from_idx + 6..].trim();
            let after_upper = after_from.to_ascii_uppercase();

            // Extract table (or read_csv / read_json) + optional WHERE / GROUP BY / ORDER BY / LIMIT
            let (table_tok, remainder) = split_first_clause(after_from, &after_upper);
            let tbl_rows_owned: Vec<Map<String, Value>>;
            let tbl_cols_owned: Vec<DbColumnDef>;
            let tbl_rows: &[Map<String, Value>];
            let tbl_cols: &[DbColumnDef];

            if let Some((cols_loaded, rows_loaded)) = try_eval_table_function(table_tok)? {
                tbl_cols_owned = cols_loaded;
                tbl_rows_owned = rows_loaded;
                tbl_cols = &tbl_cols_owned;
                tbl_rows = &tbl_rows_owned;
            } else {
                let tbl_name = parse_table_ref(table_tok);
                let guard = self
                    .catalog
                    .read()
                    .map_err(|_| DbOperationError::err("catalog poisoned"))?;
                let tbl = find_table(&guard, db, &tbl_name).ok_or_else(|| {
                    DbOperationError::err(format!("table '{tbl_name}' does not exist"))
                })?;
                tbl_cols_owned = tbl.columns.clone();
                tbl_rows_owned = tbl.rows.clone();
                tbl_cols = &tbl_cols_owned;
                tbl_rows = &tbl_rows_owned;
            }

            let mut filtered: Vec<Map<String, Value>> = if let Some(w_clause) =
                extract_clause(remainder, "WHERE ", &["GROUP BY ", "ORDER BY ", "LIMIT "])
            {
                tbl_rows
                    .iter()
                    .filter(|r| eval_where(r, w_clause))
                    .cloned()
                    .collect()
            } else {
                tbl_rows.to_vec()
            };

            if let Some(g_clause) = extract_clause(remainder, "GROUP BY ", &["ORDER BY ", "LIMIT "])
            {
                let group_col = g_clause.trim().trim_matches(|c| c == '"' || c == '`');
                return Ok(exec_group_by(&filtered, proj_raw, group_col, started));
            }

            if let Some(o_clause) = extract_clause(remainder, "ORDER BY ", &["LIMIT "]) {
                let mut parts = o_clause.split_whitespace();
                if let Some(col_raw) = parts.next() {
                    let col = col_raw.trim_matches(|c| c == '"' || c == '`');
                    let desc = parts
                        .next()
                        .is_some_and(|dir| dir.eq_ignore_ascii_case("DESC"));
                    filtered.sort_by(|a, b| {
                        let va = a.get(col).map_or_else(String::new, value_sort_key);
                        let vb = b.get(col).map_or_else(String::new, value_sort_key);
                        if desc {
                            vb.cmp(&va)
                        } else {
                            va.cmp(&vb)
                        }
                    });
                }
            }

            let limit = extract_clause(remainder, "LIMIT ", &[])
                .and_then(|l| l.trim().parse::<usize>().ok())
                .unwrap_or(MAX_QUERY_ROWS)
                .min(MAX_QUERY_ROWS);

            // Handle scalar aggregate SELECT COUNT(*) / SUM(col) / AVG(col)
            let proj_upper = proj_raw.to_ascii_uppercase();
            if proj_upper.starts_with("COUNT(") && !proj_raw.contains(',') {
                let cols = vec!["count".to_owned()];
                let matrix = vec![vec![serde_json::json!(filtered.len())]];
                let rows = rows_to_objects(&cols, &matrix);
                return Ok(DbQueryResult {
                    row_count: 1,
                    columns: cols,
                    rows,
                    matrix_rows: matrix,
                    duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
                    truncated: false,
                    dlp_summary: None,
                });
            }
            for (agg, op) in [
                ("SUM(", "sum"),
                ("AVG(", "avg"),
                ("MIN(", "min"),
                ("MAX(", "max"),
            ] {
                if let Some(inner) = proj_upper.strip_prefix(agg) {
                    if let Some(end) = inner.find(')') {
                        let col = proj_raw[agg.len()..agg.len() + end]
                            .trim()
                            .trim_matches(|c| c == '"' || c == '`');
                        let nums: Vec<f64> = filtered
                            .iter()
                            .filter_map(|r| r.get(col).and_then(Value::as_f64))
                            .collect();
                        let val = if nums.is_empty() {
                            Value::Null
                        } else {
                            let res = match op {
                                "sum" => nums.iter().sum::<f64>(),
                                "avg" => nums.iter().sum::<f64>() / (nums.len() as f64),
                                "min" => nums.iter().copied().fold(f64::INFINITY, f64::min),
                                _ => nums.iter().copied().fold(f64::NEG_INFINITY, f64::max),
                            };
                            serde_json::json!(res)
                        };
                        let cols = vec![format!("{op}_{col}")];
                        let matrix = vec![vec![val]];
                        let rows = rows_to_objects(&cols, &matrix);
                        return Ok(DbQueryResult {
                            row_count: 1,
                            columns: cols,
                            rows,
                            matrix_rows: matrix,
                            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
                            truncated: false,
                            dlp_summary: None,
                        });
                    }
                }
            }

            let columns: Vec<String> = if proj_raw == "*" {
                tbl_cols.iter().map(|c| c.name.clone()).collect()
            } else {
                proj_raw
                    .split(',')
                    .map(|p| {
                        p.split_whitespace()
                            .next()
                            .unwrap_or("*")
                            .trim_matches(|c| c == '"' || c == '`')
                            .to_owned()
                    })
                    .collect()
            };

            let truncated = filtered.len() > limit;
            let matrix_rows: Vec<Vec<Value>> = filtered
                .into_iter()
                .take(limit)
                .map(|r| {
                    columns
                        .iter()
                        .map(|c| r.get(c).cloned().unwrap_or(Value::Null))
                        .collect()
                })
                .collect();
            let rows = rows_to_objects(&columns, &matrix_rows);
            return Ok(DbQueryResult {
                row_count: rows.len(),
                columns,
                rows,
                matrix_rows,
                duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
                truncated,
                dlp_summary: None,
            });
        }

        // Literal `SELECT 1` / `SELECT version()`
        let cols = vec!["result".to_owned()];
        let val = if upper.contains("VERSION()") {
            Value::String(format!("operquay-{} 1.1.0-pure-rust", self.engine_name))
        } else {
            parse_literal(rest.trim())
        };
        let matrix = vec![vec![val]];
        let rows = rows_to_objects(&cols, &matrix);
        Ok(DbQueryResult {
            row_count: 1,
            columns: cols,
            rows,
            matrix_rows: matrix,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
            truncated: false,
            dlp_summary: None,
        })
    }

    fn exec_write(&self, db: &str, snapshot_path: Option<&str>, stmt: &str) -> Result<u64, String> {
        let upper = stmt.to_ascii_uppercase();
        let mut affected = 0u64;

        {
            let mut guard = self
                .catalog
                .write()
                .map_err(|_| "catalog poisoned".to_owned())?;
            let tbls = guard.databases.entry(db.to_owned()).or_default();

            if upper.starts_with("CREATE TABLE") {
                let body_start = stmt
                    .find('(')
                    .ok_or_else(|| "CREATE TABLE missing '('".to_owned())?;
                let body_end = stmt
                    .rfind(')')
                    .ok_or_else(|| "CREATE TABLE missing ')'".to_owned())?;
                let header = stmt[..body_start].trim();
                let tbl_tok = header.split_whitespace().last().unwrap_or("unnamed");
                let tbl_name = parse_table_ref(tbl_tok);
                let if_not_exists = upper.contains("IF NOT EXISTS");
                if tbls.iter().any(|t| t.name.eq_ignore_ascii_case(&tbl_name)) {
                    if if_not_exists {
                        return Ok(0);
                    }
                    return Err(format!("table '{tbl_name}' already exists"));
                }
                let cols: Vec<DbColumnDef> = stmt[body_start + 1..body_end]
                    .split(',')
                    .filter_map(|def| {
                        let mut parts = def.split_whitespace();
                        let name = parts
                            .next()?
                            .trim_matches(|c| c == '"' || c == '`')
                            .to_owned();
                        let ty = parts.next().unwrap_or("VARCHAR").to_owned();
                        let def_upper = def.to_ascii_uppercase();
                        Some(DbColumnDef {
                            name,
                            data_type: ty,
                            nullable: !def_upper.contains("NOT NULL"),
                            is_primary_key: def_upper.contains("PRIMARY KEY"),
                            default_value: None,
                        })
                    })
                    .collect();
                tbls.push(ColumnarTable {
                    schema: self.default_schema.to_owned(),
                    name: tbl_name,
                    columns: cols,
                    rows: Vec::new(),
                });
            } else if let Some(rest) = strip_ci_prefix(stmt, "DROP TABLE ") {
                let name_tok = rest
                    .split_whitespace()
                    .last()
                    .unwrap_or("")
                    .trim_matches(|c| c == '"' || c == '`');
                let tbl_name = parse_table_ref(name_tok);
                tbls.retain(|t| !t.name.eq_ignore_ascii_case(&tbl_name));
            } else if let Some(rest) = strip_ci_prefix(stmt, "INSERT INTO ") {
                let r_up = rest.to_ascii_uppercase();
                let val_pos = find_kw(&r_up, "VALUES")
                    .ok_or_else(|| "INSERT INTO missing VALUES clause".to_owned())?;
                let target_hdr = rest[..val_pos].trim();
                let values_raw = rest[val_pos + 6..].trim();
                let (tbl_name, explicit_cols) = if let Some(p_idx) = target_hdr.find('(') {
                    let t = parse_table_ref(target_hdr[..p_idx].trim());
                    let p_end = target_hdr.rfind(')').unwrap_or(target_hdr.len());
                    let cols: Vec<String> = target_hdr[p_idx + 1..p_end]
                        .split(',')
                        .map(|s| s.trim().trim_matches(|c| c == '"' || c == '`').to_owned())
                        .collect();
                    (t, Some(cols))
                } else {
                    (parse_table_ref(target_hdr), None)
                };
                let tbl = tbls
                    .iter_mut()
                    .find(|t| t.name.eq_ignore_ascii_case(&tbl_name))
                    .ok_or_else(|| format!("table '{tbl_name}' does not exist"))?;
                let v_start = values_raw
                    .find('(')
                    .ok_or_else(|| "VALUES missing '('".to_owned())?;
                let v_end = values_raw
                    .rfind(')')
                    .ok_or_else(|| "VALUES missing ')'".to_owned())?;
                let vals = split_csv_literals(&values_raw[v_start + 1..v_end]);
                let col_names: Vec<String> = explicit_cols
                    .unwrap_or_else(|| tbl.columns.iter().map(|c| c.name.clone()).collect());
                let mut row = Map::new();
                for (idx, col) in col_names.iter().enumerate() {
                    row.insert(col.clone(), vals.get(idx).cloned().unwrap_or(Value::Null));
                }
                tbl.rows.push(row);
                affected = 1;
            } else if let Some(rest) = strip_ci_prefix(stmt, "DELETE FROM ") {
                let r_up = rest.to_ascii_uppercase();
                let (tbl_tok, rem) = split_first_clause(rest, &r_up);
                let tbl_name = parse_table_ref(tbl_tok);
                let tbl = tbls
                    .iter_mut()
                    .find(|t| t.name.eq_ignore_ascii_case(&tbl_name))
                    .ok_or_else(|| format!("table '{tbl_name}' does not exist"))?;
                let before = tbl.rows.len();
                if let Some(w_clause) = extract_clause(rem, "WHERE ", &[]) {
                    tbl.rows.retain(|r| !eval_where(r, w_clause));
                } else {
                    tbl.rows.clear();
                }
                affected = u64::try_from(before.saturating_sub(tbl.rows.len())).unwrap_or(0);
            } else if let Some(rest) = strip_ci_prefix(stmt, "UPDATE ") {
                let r_up = rest.to_ascii_uppercase();
                let set_pos =
                    find_kw(&r_up, " SET ").ok_or_else(|| "UPDATE missing SET".to_owned())?;
                let tbl_name = parse_table_ref(rest[..set_pos].trim());
                let after_set = &rest[set_pos + 5..];
                let after_up = after_set.to_ascii_uppercase();
                let (assign_raw, where_opt) = if let Some(w_pos) = find_kw(&after_up, " WHERE ") {
                    (&after_set[..w_pos], Some(after_set[w_pos + 7..].trim()))
                } else {
                    (after_set, None)
                };
                let mut pairs = Vec::new();
                for assign in split_csv_assignments(assign_raw) {
                    if let Some((k, v)) = assign.split_once('=') {
                        pairs.push((
                            k.trim().trim_matches(|c| c == '"' || c == '`').to_owned(),
                            parse_literal(v.trim()),
                        ));
                    }
                }
                let tbl = tbls
                    .iter_mut()
                    .find(|t| t.name.eq_ignore_ascii_case(&tbl_name))
                    .ok_or_else(|| format!("table '{tbl_name}' does not exist"))?;
                for row in &mut tbl.rows {
                    if where_opt.is_none_or(|w| eval_where(row, w)) {
                        for (k, v) in &pairs {
                            row.insert(k.clone(), v.clone());
                        }
                        affected += 1;
                    }
                }
            } else {
                return Err(format!("unsupported write statement: '{stmt}'"));
            }
        }

        self.persist_snapshot_if_configured(snapshot_path, db);
        Ok(affected)
    }
}

trait IntoCol {
    fn into_col(self) -> DbColumnDef;
}

impl IntoCol for (&str, &str, bool, bool) {
    fn into_col(self) -> DbColumnDef {
        col(self.0, self.1, self.2, self.3)
    }
}

fn col(name: &str, ty: &str, pk: bool, nullable: bool) -> DbColumnDef {
    DbColumnDef {
        name: name.to_owned(),
        data_type: ty.to_owned(),
        nullable,
        is_primary_key: pk,
        default_value: None,
    }
}

fn obj<const N: usize>(entries: [(&str, Value); N]) -> Map<String, Value> {
    let mut m = Map::with_capacity(N);
    for (k, v) in entries {
        m.insert(k.to_owned(), v);
    }
    m
}

fn find_table<'a>(
    catalog: &'a EngineCatalog,
    db: &str,
    tbl_name: &str,
) -> Option<&'a ColumnarTable> {
    catalog
        .databases
        .get(db)?
        .iter()
        .find(|t| t.name.eq_ignore_ascii_case(tbl_name))
}

fn strip_ci_prefix<'a>(haystack: &'a str, prefix: &str) -> Option<&'a str> {
    if haystack.len() >= prefix.len()
        && haystack.is_char_boundary(prefix.len())
        && haystack[..prefix.len()].eq_ignore_ascii_case(prefix)
    {
        Some(&haystack[prefix.len()..])
    } else {
        None
    }
}

fn find_kw(upper: &str, kw: &str) -> Option<usize> {
    upper.find(kw)
}

fn parse_table_ref(raw: &str) -> String {
    raw.split('.')
        .next_back()
        .unwrap_or(raw)
        .trim()
        .trim_matches(|c| c == '"' || c == '`')
        .to_owned()
}

fn split_first_clause<'a>(s: &'a str, upper: &str) -> (&'a str, &'a str) {
    let mut cut = s.len();
    for kw in [" WHERE ", " GROUP BY ", " ORDER BY ", " LIMIT "] {
        if let Some(pos) = upper.find(kw) {
            cut = cut.min(pos);
        }
    }
    (s[..cut].trim(), s[cut..].trim())
}

type LoadedTableData = (Vec<DbColumnDef>, Vec<Map<String, Value>>);

fn try_eval_table_function(tok: &str) -> Result<Option<LoadedTableData>, DbOperationError> {
    let lower = tok.trim().to_ascii_lowercase();
    let is_csv = lower.starts_with("read_csv(");
    let is_json = lower.starts_with("read_json(");
    if !is_csv && !is_json {
        return Ok(None);
    }
    let open = tok.find('(').unwrap_or(0);
    let close = tok.rfind(')').unwrap_or(tok.len());
    let raw_arg = tok[open + 1..close]
        .trim()
        .trim_matches(|c| c == '\'' || c == '"');
    let base_dir = std::env::var("OPERQUAY_DUCKDB_DATA_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map_or_else(std::env::temp_dir, PathBuf::from);
    let canon_base = std::fs::canonicalize(&base_dir)
        .map_err(|e| DbOperationError::err(format!("DuckDB data dir canonicalize failed: {e}")))?;
    let candidate = PathBuf::from(raw_arg);
    let target = if candidate.is_absolute() {
        candidate
    } else {
        canon_base.join(candidate)
    };
    let canon_target = std::fs::canonicalize(&target)
        .map_err(|e| DbOperationError::err(format!("cannot read DuckDB input file: {e}")))?;
    if !canon_target.starts_with(&canon_base) {
        return Err(DbOperationError::err(
            "path escapes allowed OPERQUAY_DUCKDB_DATA_DIR containment",
        ));
    }
    let text = std::fs::read_to_string(&canon_target)
        .map_err(|e| DbOperationError::err(format!("DuckDB file read failed: {e}")))?;
    if is_json {
        let items: Vec<Map<String, Value>> = serde_json::from_str(&text)
            .map_err(|e| DbOperationError::err(format!("read_json parse error: {e}")))?;
        let cols: Vec<DbColumnDef> = items.first().map_or_default(|first| {
            first
                .keys()
                .map(|k| col(k, "VARCHAR", true, false))
                .collect()
        });
        return Ok(Some((cols, items)));
    }
    let mut lines = text.lines();
    let Some(hdr_line) = lines.next() else {
        return Ok(Some((Vec::new(), Vec::new())));
    };
    let headers: Vec<String> = hdr_line
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_owned())
        .collect();
    let cols: Vec<DbColumnDef> = headers
        .iter()
        .map(|h| col(h, "VARCHAR", true, false))
        .collect();
    let mut rows = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let vals = split_csv_literals(line);
        let mut m = Map::new();
        for (i, h) in headers.iter().enumerate() {
            m.insert(h.clone(), vals.get(i).cloned().unwrap_or(Value::Null));
        }
        rows.push(m);
    }
    Ok(Some((cols, rows)))
}

fn exec_group_by(
    filtered: &[Map<String, Value>],
    proj_raw: &str,
    group_col: &str,
    started: Instant,
) -> DbQueryResult {
    let mut groups: BTreeMap<String, Vec<&Map<String, Value>>> = BTreeMap::new();
    for r in filtered {
        let key = r.get(group_col).map_or_else(String::new, value_sort_key);
        groups.entry(key).or_default().push(r);
    }
    let exprs: Vec<&str> = proj_raw.split(',').map(str::trim).collect();
    let mut columns = Vec::with_capacity(exprs.len());
    for e in &exprs {
        let alias = e
            .split_whitespace()
            .last()
            .filter(|_| e.to_ascii_uppercase().contains(" AS "))
            .unwrap_or(e)
            .trim_matches(|c| c == '"' || c == '`');
        columns.push(alias.to_owned());
    }
    let mut matrix_rows = Vec::with_capacity(groups.len());
    for (gkey, grp) in groups {
        let mut row_vals = Vec::with_capacity(exprs.len());
        for expr in &exprs {
            let clean_expr = expr
                .split(" AS ")
                .next()
                .or_else(|| expr.split(" as ").next())
                .unwrap_or(expr)
                .trim();
            let up = clean_expr.to_ascii_uppercase();
            if up.starts_with("COUNT(") {
                row_vals.push(serde_json::json!(grp.len()));
            } else if let Some((agg, inner)) = [
                ("SUM(", "sum"),
                ("AVG(", "avg"),
                ("MIN(", "min"),
                ("MAX(", "max"),
            ]
            .into_iter()
            .find_map(|(prefix, kind)| {
                up.strip_prefix(prefix).and_then(|s| {
                    s.find(')')
                        .map(|e| (kind, &clean_expr[prefix.len()..prefix.len() + e]))
                })
            }) {
                let col_name = inner.trim().trim_matches(|c| c == '"' || c == '`');
                let nums: Vec<f64> = grp
                    .iter()
                    .filter_map(|r| r.get(col_name).and_then(Value::as_f64))
                    .collect();
                if nums.is_empty() {
                    row_vals.push(Value::Null);
                } else {
                    let v = match agg {
                        "sum" => nums.iter().sum::<f64>(),
                        "avg" => nums.iter().sum::<f64>() / (nums.len() as f64),
                        "min" => nums.iter().copied().fold(f64::INFINITY, f64::min),
                        _ => nums.iter().copied().fold(f64::NEG_INFINITY, f64::max),
                    };
                    row_vals.push(serde_json::json!(v));
                }
            } else {
                let raw_key_val = grp
                    .first()
                    .and_then(|r| {
                        r.get(clean_expr.trim_matches(|c| c == '"' || c == '`'))
                            .cloned()
                    })
                    .unwrap_or(Value::String(gkey.clone()));
                row_vals.push(raw_key_val);
            }
        }
        matrix_rows.push(row_vals);
    }
    let rows = rows_to_objects(&columns, &matrix_rows);
    DbQueryResult {
        row_count: rows.len(),
        columns,
        rows,
        matrix_rows,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
        truncated: false,
        dlp_summary: None,
    }
}

fn extract_clause<'a>(s: &'a str, kw: &str, terminators: &[&str]) -> Option<&'a str> {
    let upper = s.to_ascii_uppercase();
    let trimmed_kw = kw.trim_start();
    let start = if upper.starts_with(trimmed_kw) {
        trimmed_kw.len()
    } else {
        upper.find(kw)? + kw.len()
    };
    let tail = &s[start..];
    let tail_up = tail.to_ascii_uppercase();
    let mut end = tail.len();
    for term in terminators {
        if let Some(pos) = tail_up.find(term) {
            end = end.min(pos);
        }
    }
    Some(tail[..end].trim())
}

fn eval_where(row: &Map<String, Value>, clause: &str) -> bool {
    for conj in clause.split(" AND ").chain(clause.split(" and ")) {
        let _ = conj;
    }
    let parts: Vec<&str> = split_and_case_insensitive(clause);
    parts.into_iter().all(|pred| eval_single_pred(row, pred))
}

fn split_and_case_insensitive(s: &str) -> Vec<&str> {
    let up = s.to_ascii_uppercase();
    let mut out = Vec::new();
    let mut last = 0usize;
    let bytes = up.as_bytes();
    let mut i = 0usize;
    while i + 5 <= bytes.len() {
        if &bytes[i..i + 5] == b" AND " {
            out.push(s[last..i].trim());
            last = i + 5;
            i = last;
        } else {
            i += 1;
        }
    }
    out.push(s[last..].trim());
    out
}

fn eval_single_pred(row: &Map<String, Value>, pred: &str) -> bool {
    for op in ["!=", ">=", "<=", "=", ">", "<"] {
        if let Some((lhs, rhs)) = pred.split_once(op) {
            let col = lhs.trim().trim_matches(|c| c == '"' || c == '`');
            let want = parse_literal(rhs.trim());
            let actual = row.get(col).cloned().unwrap_or(Value::Null);
            return match op {
                "=" => values_equal(&actual, &want),
                "!=" => !values_equal(&actual, &want),
                ">" => compare_values(&actual, &want).is_some_and(std::cmp::Ordering::is_gt),
                "<" => compare_values(&actual, &want).is_some_and(std::cmp::Ordering::is_lt),
                ">=" => compare_values(&actual, &want).is_some_and(std::cmp::Ordering::is_ge),
                "<=" => compare_values(&actual, &want).is_some_and(std::cmp::Ordering::is_le),
                _ => false,
            };
        }
    }
    true
}

fn row_matches_map(row: &Map<String, Value>, keys: &HashMap<String, Value>) -> bool {
    keys.iter().all(|(k, v)| {
        let actual = row.get(k).cloned().unwrap_or(Value::Null);
        values_equal(&actual, v)
    })
}

fn values_equal(a: &Value, b: &Value) -> bool {
    if a == b {
        return true;
    }
    match (a, b) {
        (Value::Number(na), Value::Number(nb)) => na.as_f64() == nb.as_f64(),
        _ => value_sort_key(a) == value_sort_key(b),
    }
}

fn compare_values(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
    if let (Some(fa), Some(fb)) = (a.as_f64(), b.as_f64()) {
        return fa.partial_cmp(&fb);
    }
    Some(value_sort_key(a).cmp(&value_sort_key(b)))
}

fn value_sort_key(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

fn parse_literal(raw: &str) -> Value {
    let t = raw.trim();
    if t.eq_ignore_ascii_case("NULL") {
        return Value::Null;
    }
    if t.eq_ignore_ascii_case("TRUE") {
        return Value::Bool(true);
    }
    if t.eq_ignore_ascii_case("FALSE") {
        return Value::Bool(false);
    }
    if (t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2)
        || (t.starts_with('"') && t.ends_with('"') && t.len() >= 2)
    {
        return Value::String(t[1..t.len() - 1].replace("''", "'"));
    }
    if let Ok(i) = t.parse::<i64>() {
        return serde_json::json!(i);
    }
    if let Ok(f) = t.parse::<f64>() {
        return serde_json::json!(f);
    }
    Value::String(t.to_owned())
}

fn split_csv_literals(raw: &str) -> Vec<Value> {
    split_csv_respecting_quotes(raw)
        .into_iter()
        .map(|s| parse_literal(&s))
        .collect()
}

fn split_csv_assignments(raw: &str) -> Vec<String> {
    split_csv_respecting_quotes(raw)
}

fn split_csv_respecting_quotes(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    for ch in raw.chars() {
        if ch == '\'' {
            in_single = !in_single;
            cur.push(ch);
        } else if ch == ',' && !in_single {
            out.push(cur.trim().to_owned());
            cur.clear();
        } else {
            cur.push(ch);
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_owned());
    }
    out
}
