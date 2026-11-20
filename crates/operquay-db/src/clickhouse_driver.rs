use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::columnar_engine::EmbeddedColumnarEngine;
use crate::driver::{
    compact_byte_size, is_write_sql, read_only_block_error, rows_to_objects, validate_ident_quoted,
    DatabaseEngineDriver, DbColumnDef, DbConnectRequest, DbConnectionSpec, DbMutateResult,
    DbOperationError, DbQueryResult, DbRowUpdate, DbTableDef, MAX_QUERY_ROWS, PREVIEW_ROW_LIMIT,
};

#[derive(Debug, Deserialize)]
pub struct ClickHouseJsonMeta {
    pub name: String,
    #[serde(rename = "type")]
    pub col_type: String,
}

#[derive(Debug, Deserialize)]
pub struct ClickHouseJsonResp {
    #[serde(default)]
    pub meta: Vec<ClickHouseJsonMeta>,
    #[serde(default)]
    pub data: Vec<Map<String, Value>>,
}

/// `ClickHouse` driver speaking `ClickHouse` HTTP JSON (`:8123` / `:8443` TLS) with optional
/// embedded analytical catalog mode when `host` is `embedded` or `memory`.
#[derive(Debug)]
pub struct ClickHouseDriver {
    http: reqwest::Client,
    embedded: EmbeddedColumnarEngine,
}

impl Default for ClickHouseDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl ClickHouseDriver {
    #[must_use]
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            http,
            embedded: EmbeddedColumnarEngine::new_clickhouse_embedded(),
        }
    }

    fn is_embedded(spec: &DbConnectionSpec) -> bool {
        let h = spec.host.trim();
        h.eq_ignore_ascii_case("embedded") || h.eq_ignore_ascii_case("memory")
    }

    fn endpoint_url(spec: &DbConnectionSpec, read_only: bool) -> String {
        let raw_host = spec.host.trim();
        let scheme = if raw_host.starts_with("https://")
            || (!raw_host.starts_with("http://")
                && (spec.ssl_mode == "require"
                    || spec.ssl_mode == "verify-ca"
                    || spec.ssl_mode == "verify-full"
                    || spec.port == 8443))
        {
            "https"
        } else {
            "http"
        };
        let host = raw_host
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        let port = if spec.port == 0 { 8123 } else { spec.port };
        let db = if spec.database.is_empty() {
            "default"
        } else {
            spec.database.as_str()
        };
        let ro_q = if read_only { "&readonly=1" } else { "" };
        format!("{scheme}://{host}:{port}/?database={db}{ro_q}")
    }

    pub async fn exec_http_json(
        &self,
        spec: &DbConnectionSpec,
        sql: &str,
        read_only: bool,
    ) -> Result<ClickHouseJsonResp, String> {
        let stmt = sql.trim().trim_end_matches(';');
        let body = if stmt.to_ascii_uppercase().contains("FORMAT ") {
            stmt.to_owned()
        } else {
            format!("{stmt} FORMAT JSON")
        };
        let url = Self::endpoint_url(spec, read_only);
        let mut req = self.http.post(&url).body(body);
        if !spec.username.is_empty() {
            req = req.header("X-ClickHouse-User", &spec.username);
        }
        if !spec.password.is_empty() {
            req = req.header("X-ClickHouse-Key", &spec.password);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("ClickHouse HTTP request failed: {e}"))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("ClickHouse response read error: {e}"))?;
        if !status.is_success() {
            return Err(format!("ClickHouse HTTP {status}: {}", text.trim()));
        }
        if text.trim().is_empty() {
            return Ok(ClickHouseJsonResp {
                meta: Vec::new(),
                data: Vec::new(),
            });
        }
        serde_json::from_str(&text)
            .map_err(|e| format!("ClickHouse JSON decode failed ({e}): {text}"))
    }

    pub async fn exec_http_plain(&self, spec: &DbConnectionSpec, sql: &str) -> Result<(), String> {
        let url = Self::endpoint_url(spec, false);
        let mut req = self.http.post(&url).body(sql.to_owned());
        if !spec.username.is_empty() {
            req = req.header("X-ClickHouse-User", &spec.username);
        }
        if !spec.password.is_empty() {
            req = req.header("X-ClickHouse-Key", &spec.password);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("ClickHouse HTTP execute failed: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("ClickHouse HTTP {status}: {}", text.trim()));
        }
        Ok(())
    }
}

#[async_trait]
impl DatabaseEngineDriver for ClickHouseDriver {
    fn engine(&self) -> &'static str {
        "clickhouse"
    }

    fn default_port(&self) -> u16 {
        8123
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
            out.database = "default".into();
        }
        if out.username.trim().is_empty() {
            out.username = "default".into();
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

        let db_resp = self
            .exec_http_json(
                spec,
                "SELECT name FROM system.databases ORDER BY name",
                true,
            )
            .await?;
        let databases: Vec<String> = db_resp
            .data
            .into_iter()
            .filter_map(|m| m.get("name").and_then(Value::as_str).map(ToOwned::to_owned))
            .collect();

        let target_db = spec.database.replace('\'', "''");
        let tbl_sql = format!(
            "SELECT database, name, COALESCE(total_rows, 0) AS total_rows, COALESCE(total_bytes, 0) AS total_bytes \
             FROM system.tables WHERE database = '{target_db}' ORDER BY name"
        );
        let tbl_resp = self.exec_http_json(spec, &tbl_sql, true).await?;

        let col_sql = format!(
            "SELECT table, name, type, is_in_primary_key \
             FROM system.columns WHERE database = '{target_db}' ORDER BY table, position"
        );
        let col_resp =
            self.exec_http_json(spec, &col_sql, true)
                .await
                .unwrap_or(ClickHouseJsonResp {
                    meta: Vec::new(),
                    data: Vec::new(),
                });

        let mut cols_by_table: HashMap<String, Vec<DbColumnDef>> = HashMap::new();
        for c in col_resp.data {
            let tbl = c
                .get("table")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let col_type = c
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("String")
                .to_owned();
            let nullable = col_type.starts_with("Nullable(");
            let is_pk = c
                .get("is_in_primary_key")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                != 0;
            cols_by_table.entry(tbl).or_default().push(DbColumnDef {
                name: c
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                data_type: col_type,
                nullable,
                is_primary_key: is_pk,
                default_value: None,
            });
        }

        let mut tables = Vec::with_capacity(tbl_resp.data.len());
        for t in tbl_resp.data {
            let schema = t
                .get("database")
                .and_then(Value::as_str)
                .unwrap_or(&spec.database)
                .to_owned();
            let name = t
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let rows_est = parse_json_i64(t.get("total_rows"));
            let bytes = parse_json_i64(t.get("total_bytes"));
            let columns = cols_by_table.remove(&name).unwrap_or_default();

            let preview = if let (Ok(dq), Ok(tq)) = (
                validate_ident_quoted(&schema, "database", '`'),
                validate_ident_quoted(&name, "table", '`'),
            ) {
                let p_sql = format!("SELECT * FROM {dq}.{tq} LIMIT {PREVIEW_ROW_LIMIT}");
                self.exec_http_json(spec, &p_sql, true)
                    .await
                    .map_or_default(|r| r.data)
            } else {
                Vec::new()
            };

            tables.push(DbTableDef {
                schema,
                name,
                row_count: rows_est,
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
        let resp = self
            .exec_http_json(spec, sql, read_only)
            .await
            .map_err(DbOperationError::err)?;
        let columns: Vec<String> = resp.meta.into_iter().map(|m| m.name).collect();
        let truncated = resp.data.len() > MAX_QUERY_ROWS;
        let rows: Vec<Map<String, Value>> = resp.data.into_iter().take(MAX_QUERY_ROWS).collect();
        let matrix_rows: Vec<Vec<Value>> = rows
            .iter()
            .map(|r| {
                columns
                    .iter()
                    .map(|c| r.get(c).cloned().unwrap_or(Value::Null))
                    .collect()
            })
            .collect();
        Ok(DbQueryResult {
            row_count: rows.len(),
            columns,
            rows,
            matrix_rows,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
            truncated,
            dlp_summary: None,
        })
    }

    async fn mutate_sql(&self, spec: &DbConnectionSpec, sql: &str) -> Result<u64, String> {
        if Self::is_embedded(spec) {
            return self.embedded.mutate_sql(&spec.database, None, sql);
        }
        self.exec_http_plain(spec, sql).await?;
        Ok(1)
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
        let dq = validate_ident_quoted(db, "database", '`')?;
        let tq = validate_ident_quoted(table, "table", '`')?;
        let fq = format!("{dq}.{tq}");

        let mut ins_cnt = 0u64;
        if !inserts.is_empty() {
            let mut body = String::new();
            for row in inserts {
                if row.is_empty() {
                    continue;
                }
                if let Ok(line) = serde_json::to_string(row) {
                    body.push_str(&line);
                    body.push('\n');
                    ins_cnt += 1;
                }
            }
            if !body.is_empty() {
                let sql = format!("INSERT INTO {fq} FORMAT JSONEachRow\n{body}");
                self.exec_http_plain(spec, &sql).await?;
            }
        }

        let mut upd_cnt = 0u64;
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
                        format_ch_literal(v)
                    ))
                })
                .collect::<Result<_, String>>()?;
            let wheres: Vec<String> = keys_map
                .iter()
                .map(|(k, v)| {
                    Ok(format!(
                        "{} = {}",
                        validate_ident_quoted(k, "key", '`')?,
                        format_ch_literal(v)
                    ))
                })
                .collect::<Result<_, String>>()?;
            let sql = format!(
                "ALTER TABLE {fq} UPDATE {} WHERE {}",
                sets.join(", "),
                wheres.join(" AND ")
            );
            self.exec_http_plain(spec, &sql).await?;
            upd_cnt += 1;
        }

        let mut del_cnt = 0u64;
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
                        format_ch_literal(v)
                    ))
                })
                .collect::<Result<_, String>>()?;
            let sql = format!("ALTER TABLE {fq} DELETE WHERE {}", wheres.join(" AND "));
            self.exec_http_plain(spec, &sql).await?;
            del_cnt += 1;
        }

        let _ = rows_to_objects(&[], &[]);
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

fn parse_json_i64(val: Option<&Value>) -> i64 {
    match val {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(Value::String(s)) => s.parse::<i64>().unwrap_or(0),
        _ => 0,
    }
}

fn format_ch_literal(v: &Value) -> String {
    match v {
        Value::Null => "NULL".to_owned(),
        Value::Bool(b) => if *b { "1" } else { "0" }.to_owned(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
        other => format!("'{}'", other.to_string().replace('\'', "\\'")),
    }
}
