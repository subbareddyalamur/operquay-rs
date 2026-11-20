use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{Map, Value};
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, NoTls};

use crate::driver::{
    compact_byte_size, is_write_sql, read_only_block_error, rows_to_objects, validate_ident_quoted,
    DatabaseEngineDriver, DbColumnDef, DbConnectRequest, DbConnectionSpec, DbMutateResult,
    DbOperationError, DbQueryResult, DbRowUpdate, DbTableDef, MAX_QUERY_ROWS, PREVIEW_ROW_LIMIT,
};
use crate::tls::PgRustlsMakeTls;

const QUERY_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Default)]
pub struct PostgresDriver;

impl PostgresDriver {
    #[must_use]
    pub fn build_dsn(spec: &DbConnectionSpec) -> String {
        let host = if spec.host.is_empty() {
            "localhost"
        } else {
            spec.host.as_str()
        };
        let port = if spec.port == 0 { 5432 } else { spec.port };
        let user = if spec.username.is_empty() {
            "postgres"
        } else {
            spec.username.as_str()
        };
        let db = if spec.database.is_empty() {
            "postgres"
        } else {
            spec.database.as_str()
        };
        let mut dsn = format!(
            "host={} port={} user={} dbname={}",
            escape_dsn_val(host),
            port,
            escape_dsn_val(user),
            escape_dsn_val(db)
        );
        if !spec.password.is_empty() {
            dsn.push_str(" password=");
            dsn.push_str(&escape_dsn_val(&spec.password));
        }
        dsn.push_str(" sslmode=");
        dsn.push_str(escape_dsn_val(&spec.ssl_mode).as_str());
        dsn.push_str(" connect_timeout=10");
        dsn
    }

    async fn connect_with_docker_fallback(spec: &DbConnectionSpec) -> Result<Client, String> {
        let _ = crate::tls::should_use_tls(&spec.ssl_mode)?;
        let primary_dsn = Self::build_dsn(spec);
        match connect_pg(&primary_dsn, &spec.ssl_mode).await {
            Ok(c) => Ok(c),
            Err(primary_err) => {
                let alt_host = match spec.host.as_str() {
                    "host.docker.internal" => Some("127.0.0.1"),
                    "postgres" => Some("localhost"),
                    _ => None,
                };
                if let Some(alt) = alt_host {
                    let mut fallback = spec.clone();
                    alt.clone_into(&mut fallback.host);
                    let fb_dsn = Self::build_dsn(&fallback);
                    if let Ok(c) = connect_pg(&fb_dsn, &fallback.ssl_mode).await {
                        return Ok(c);
                    }
                }
                Err(primary_err)
            }
        }
    }
}

#[async_trait]
impl DatabaseEngineDriver for PostgresDriver {
    fn engine(&self) -> &'static str {
        "postgres"
    }

    fn default_port(&self) -> u16 {
        5432
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
            out.database = "postgres".into();
        }
        if out.username.trim().is_empty() {
            out.username = "postgres".into();
        }
        out
    }

    async fn connect_and_inspect(
        &self,
        spec: &DbConnectionSpec,
    ) -> Result<(Vec<String>, Vec<DbTableDef>), String> {
        let client = Self::connect_with_docker_fallback(spec).await?;
        let databases = query_databases(&client).await.unwrap_or_default();
        let tables = inspect_tables(&client).await?;
        Ok((databases, tables))
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
        let mut client = Self::connect_with_docker_fallback(spec).await?;
        let started = Instant::now();

        let rows = tokio::time::timeout(QUERY_TIMEOUT, async {
            if read_only {
                let tx = client
                    .build_transaction()
                    .read_only(true)
                    .start()
                    .await
                    .map_err(|e| format!("failed to start read-only transaction: {e}"))?;
                let rows = tx
                    .query(sql, &[])
                    .await
                    .map_err(|e| format!("query error: {e}"))?;
                let _ = tx.rollback().await;
                Ok::<_, String>(rows)
            } else {
                client
                    .query(sql, &[])
                    .await
                    .map_err(|e| format!("query error: {e}"))
            }
        })
        .await
        .map_err(|_| DbOperationError::err("query timed out after 15s"))??;

        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let columns: Vec<String> = rows
            .first()
            .map_or_default(|r| r.columns().iter().map(|c| c.name().to_owned()).collect());

        let truncated = rows.len() > MAX_QUERY_ROWS;
        let matrix_rows: Vec<Vec<Value>> = rows
            .into_iter()
            .take(MAX_QUERY_ROWS)
            .map(|row| {
                (0..row.len())
                    .map(|idx| pg_val_to_json(&row, idx))
                    .collect()
            })
            .collect();
        let object_rows = rows_to_objects(&columns, &matrix_rows);

        Ok(DbQueryResult {
            row_count: object_rows.len(),
            columns,
            rows: object_rows,
            matrix_rows,
            duration_ms,
            truncated,
            dlp_summary: None,
        })
    }

    async fn mutate_sql(&self, spec: &DbConnectionSpec, sql: &str) -> Result<u64, String> {
        let client = Self::connect_with_docker_fallback(spec).await?;
        tokio::time::timeout(QUERY_TIMEOUT, async {
            client
                .execute(sql, &[])
                .await
                .map_err(|e| format!("mutation failed: {e}"))
        })
        .await
        .map_err(|_| "mutation timed out after 15s".to_owned())?
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
        let schema_q = validate_ident_quoted(
            if schema.is_empty() { "public" } else { schema },
            "schema",
            '"',
        )?;
        let table_q = validate_ident_quoted(table, "table", '"')?;
        let fq = format!("{schema_q}.{table_q}");

        let mut client = Self::connect_with_docker_fallback(spec).await?;
        let started = Instant::now();

        let (upd_cnt, ins_cnt, del_cnt) = tokio::time::timeout(QUERY_TIMEOUT, async {
            let tx = client
                .transaction()
                .await
                .map_err(|e| format!("failed to begin mutation tx: {e}"))?;
            let mut upd_total = 0u64;
            let mut ins_total = 0u64;
            let mut del_total = 0u64;

            for upd in updates {
                let (keys_map, vals_map) = upd.resolve_keys_and_changes(primary_keys);
                if vals_map.is_empty() || keys_map.is_empty() {
                    continue;
                }
                let mut set_parts = Vec::with_capacity(vals_map.len());
                let mut where_parts = Vec::with_capacity(keys_map.len());
                let mut params: Vec<Option<String>> =
                    Vec::with_capacity(vals_map.len() + keys_map.len());

                let mut val_entries: Vec<_> = vals_map.iter().collect();
                val_entries.sort_by(|a, b| a.0.cmp(b.0));
                for (col, val) in val_entries {
                    let col_q = validate_ident_quoted(col, "column", '"')?;
                    params.push(json_to_pg_text(val));
                    set_parts.push(format!("{col_q} = ${}", params.len()));
                }

                let mut key_entries: Vec<_> = keys_map.iter().collect();
                key_entries.sort_by(|a, b| a.0.cmp(b.0));
                for (col, val) in key_entries {
                    let col_q = validate_ident_quoted(col, "key column", '"')?;
                    if val.is_null() {
                        where_parts.push(format!("{col_q} IS NULL"));
                    } else {
                        params.push(json_to_pg_text(val));
                        where_parts.push(format!("{col_q}::text = ${}", params.len()));
                    }
                }

                let sql = format!(
                    "UPDATE {fq} SET {} WHERE {}",
                    set_parts.join(", "),
                    where_parts.join(" AND ")
                );
                let refs: Vec<&(dyn ToSql + Sync)> =
                    params.iter().map(|p| p as &(dyn ToSql + Sync)).collect();
                upd_total += tx
                    .execute(sql.as_str(), &refs)
                    .await
                    .map_err(|e| format!("structured update failed: {e}"))?;
            }

            for ins in inserts {
                if ins.is_empty() {
                    continue;
                }
                let mut entries: Vec<_> = ins.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                let mut cols = Vec::with_capacity(entries.len());
                let mut placeholders = Vec::with_capacity(entries.len());
                let mut params: Vec<Option<String>> = Vec::with_capacity(entries.len());
                for (col, val) in entries {
                    cols.push(validate_ident_quoted(col, "insert column", '"')?);
                    params.push(json_to_pg_text(val));
                    placeholders.push(format!("${}", params.len()));
                }
                let sql = format!(
                    "INSERT INTO {fq} ({}) VALUES ({})",
                    cols.join(", "),
                    placeholders.join(", ")
                );
                let refs: Vec<&(dyn ToSql + Sync)> =
                    params.iter().map(|p| p as &(dyn ToSql + Sync)).collect();
                ins_total += tx
                    .execute(sql.as_str(), &refs)
                    .await
                    .map_err(|e| format!("structured insert failed: {e}"))?;
            }

            for del in deletes {
                if del.is_empty() {
                    continue;
                }
                let mut entries: Vec<_> = del.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                let mut where_parts = Vec::with_capacity(entries.len());
                let mut params: Vec<Option<String>> = Vec::with_capacity(entries.len());
                for (col, val) in entries {
                    let col_q = validate_ident_quoted(col, "delete key", '"')?;
                    if val.is_null() {
                        where_parts.push(format!("{col_q} IS NULL"));
                    } else {
                        params.push(json_to_pg_text(val));
                        where_parts.push(format!("{col_q}::text = ${}", params.len()));
                    }
                }
                let sql = format!("DELETE FROM {fq} WHERE {}", where_parts.join(" AND "));
                let refs: Vec<&(dyn ToSql + Sync)> =
                    params.iter().map(|p| p as &(dyn ToSql + Sync)).collect();
                del_total += tx
                    .execute(sql.as_str(), &refs)
                    .await
                    .map_err(|e| format!("structured delete failed: {e}"))?;
            }

            tx.commit()
                .await
                .map_err(|e| format!("mutation commit failed: {e}"))?;
            Ok::<_, String>((upd_total, ins_total, del_total))
        })
        .await
        .map_err(|_| "structured mutation timed out".to_owned())??;

        let affected_rows = upd_cnt + ins_cnt + del_cnt;
        Ok(DbMutateResult {
            committed: true,
            updated: upd_cnt,
            inserted: ins_cnt,
            deleted: del_cnt,
            affected_rows,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

pub(crate) async fn connect_pg(dsn: &str, ssl_mode: &str) -> Result<Client, String> {
    if ssl_mode == "disable" {
        let (client, connection) = tokio_postgres::connect(dsn, NoTls)
            .await
            .map_err(|e| format!("PostgreSQL connection failed: {e}"))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(client)
    } else {
        let tls = PgRustlsMakeTls::new();
        let (client, connection) = tokio_postgres::connect(dsn, tls)
            .await
            .map_err(|e| format!("PostgreSQL TLS connection failed: {e}"))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(client)
    }
}

async fn query_databases(client: &Client) -> Result<Vec<String>, String> {
    let rows = client
        .query(
            "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname",
            &[],
        )
        .await
        .map_err(|e| format!("failed to list databases: {e}"))?;
    Ok(rows
        .into_iter()
        .filter_map(|r| r.try_get::<_, String>(0).ok())
        .collect())
}

async fn inspect_tables(client: &Client) -> Result<Vec<DbTableDef>, String> {
    let rows = client
        .query(
            "SELECT t.table_schema, t.table_name,
                    COALESCE(c.reltuples::bigint, 0) AS row_est,
                    COALESCE(pg_total_relation_size(c.oid), 0) AS bytes
             FROM information_schema.tables t
             LEFT JOIN pg_namespace n ON n.nspname = t.table_schema
             LEFT JOIN pg_class c ON c.relname = t.table_name AND c.relnamespace = n.oid
             WHERE t.table_type = 'BASE TABLE'
               AND t.table_schema NOT IN ('pg_catalog', 'information_schema')
             ORDER BY t.table_schema, t.table_name",
            &[],
        )
        .await
        .map_err(|e| format!("failed to inspect tables: {e}"))?;

    let col_rows = client
        .query(
            "SELECT c.table_schema, c.table_name, c.column_name, c.data_type,
                    (c.is_nullable = 'YES') AS nullable, c.column_default,
                    EXISTS (
                        SELECT 1
                        FROM information_schema.table_constraints tc
                        JOIN information_schema.key_column_usage kcu
                          ON tc.constraint_name = kcu.constraint_name
                         AND tc.table_schema = kcu.table_schema
                        WHERE tc.constraint_type = 'PRIMARY KEY'
                          AND tc.table_schema = c.table_schema
                          AND tc.table_name = c.table_name
                          AND kcu.column_name = c.column_name
                    ) AS is_pk
             FROM information_schema.columns c
             WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema')
             ORDER BY c.table_schema, c.table_name, c.ordinal_position",
            &[],
        )
        .await
        .map_err(|e| format!("failed to inspect columns: {e}"))?;

    let mut cols_by_tbl: HashMap<(String, String), Vec<DbColumnDef>> = HashMap::new();
    for r in col_rows {
        let schema: String = r.get(0);
        let table: String = r.get(1);
        let col = DbColumnDef {
            name: r.get(2),
            data_type: r.get(3),
            nullable: r.get(4),
            default_value: r.get(5),
            is_primary_key: r.get(6),
        };
        cols_by_tbl.entry((schema, table)).or_default().push(col);
    }

    let mut tables = Vec::with_capacity(rows.len());
    for r in rows {
        let schema: String = r.get(0);
        let name: String = r.get(1);
        let row_count: i64 = r.get(2);
        let size_bytes: i64 = r.get(3);
        let columns = cols_by_tbl
            .remove(&(schema.clone(), name.clone()))
            .unwrap_or_default();

        // Populate initial 25-row table preview (matching Go Workspace behavior)
        let preview_rows = if let (Ok(sq), Ok(tq)) = (
            validate_ident_quoted(&schema, "schema", '"'),
            validate_ident_quoted(&name, "table", '"'),
        ) {
            let sql = format!("SELECT * FROM {sq}.{tq} LIMIT {PREVIEW_ROW_LIMIT}");
            match client.query(sql.as_str(), &[]).await {
                Ok(p_rows) => {
                    let p_cols: Vec<String> = p_rows.first().map_or_default(|fr| {
                        fr.columns().iter().map(|c| c.name().to_owned()).collect()
                    });
                    let matrix: Vec<Vec<Value>> = p_rows
                        .into_iter()
                        .map(|pr| (0..pr.len()).map(|i| pg_val_to_json(&pr, i)).collect())
                        .collect();
                    rows_to_objects(&p_cols, &matrix)
                }
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };

        tables.push(DbTableDef {
            schema,
            name,
            row_count: row_count.max(0),
            size_bytes: size_bytes.max(0),
            size: compact_byte_size(size_bytes.max(0)),
            columns,
            rows: preview_rows,
        });
    }
    Ok(tables)
}

fn json_to_pg_text(val: &Value) -> Option<String> {
    match val {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        other => Some(other.to_string()),
    }
}

fn pg_val_to_json(row: &tokio_postgres::Row, idx: usize) -> Value {
    if let Ok(v) = row.try_get::<_, Option<String>>(idx) {
        return v.map_or(Value::Null, Value::String);
    }
    if let Ok(v) = row.try_get::<_, Option<i64>>(idx) {
        return v.map_or(Value::Null, |n| serde_json::json!(n));
    }
    if let Ok(v) = row.try_get::<_, Option<i32>>(idx) {
        return v.map_or(Value::Null, |n| serde_json::json!(n));
    }
    if let Ok(v) = row.try_get::<_, Option<f64>>(idx) {
        return v.map_or(Value::Null, |n| serde_json::json!(n));
    }
    if let Ok(v) = row.try_get::<_, Option<bool>>(idx) {
        return v.map_or(Value::Null, Value::Bool);
    }
    if let Ok(v) = row.try_get::<_, Option<uuid::Uuid>>(idx) {
        return v.map_or(Value::Null, |u| Value::String(u.to_string()));
    }
    let _ = Map::<String, Value>::new();
    Value::String("<unsupported>".into())
}

fn escape_dsn_val(val: &str) -> String {
    if val
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !val.is_empty()
    {
        return val.to_owned();
    }
    let escaped = val.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{escaped}'")
}
