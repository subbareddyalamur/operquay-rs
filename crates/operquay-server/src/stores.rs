use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use operquay_auth::pg::{PgAuditRow, PgAuthPool};
use operquay_core::{RemoteDesktopSettings, SecretString, SettingsStore, SettingsStoreError};
use operquay_db::DatabaseEngineDriver as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

pub const MIGRATION_SQL: &str =
    include_str!("../../../migrations/0001_remote_desktop_settings.sql");
pub const MIGRATION_FULL_SQL: &str =
    include_str!("../../../migrations/0002_full_platform_schema.sql");
pub const MIGRATION_M9_SQL: &str =
    include_str!("../../../migrations/0003_m9_security_hardening.sql");
pub const MIGRATION_M10_SQL: &str =
    include_str!("../../../migrations/0004_m10_audit_worm_persistence.sql");
pub const MIGRATION_M11_SQL: &str =
    include_str!("../../../migrations/0005_m11_governance_dlp_compliance.sql");
pub const MIGRATION_M12_SQL: &str =
    include_str!("../../../migrations/0006_m12_mcp_agent_multicloud_device_trust.sql");
pub const GENESIS_AUDIT_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
pub const TICKET_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LaunchMode {
    #[default]
    Demo,
    DirectTcp,
    SsmTunnel,
}

#[derive(Debug, Clone)]
pub struct TicketLaunchPayload {
    pub session_id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub auth_session_id: String,
    pub protocol: String,
    pub launch_mode: LaunchMode,
    pub target_host: String,
    pub target_port: u16,
    pub username: String,
    pub password: SecretString,
    pub width: u32,
    pub height: u32,
    pub keyboard_layout: Option<String>,
    pub transport_mode: Option<String>,
    pub expected_cert_sha256: Option<[u8; 32]>,
    pub simulate_recording_fault: bool,
    pub aws_profile: Option<String>,
    pub aws_region: Option<String>,
    pub rdp_security_mode: Option<operquay_core::RdpSecurityMode>,
}

#[derive(Debug)]
struct StoredTicket {
    payload: TicketLaunchPayload,
    expires_at: Instant,
}

/// Thread-safe, atomic single-use WebSocket launch ticket store (`RULES.md` §3.2).
/// Passwords never appear in WebSocket URLs or logs and are atomically removed on first use.
#[derive(Debug, Default)]
pub struct TicketStore {
    tickets: RwLock<HashMap<Uuid, StoredTicket>>,
}

impl TicketStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn issue(&self, payload: TicketLaunchPayload, ttl: Duration) -> Uuid {
        let now = Instant::now();
        let id = Uuid::new_v4();
        let mut map = self.tickets.write().await;
        map.retain(|_, v| v.expires_at > now);
        map.insert(
            id,
            StoredTicket {
                payload,
                expires_at: now + ttl,
            },
        );
        id
    }

    /// Atomically consume a single-use launch ticket (`None` if missing, expired, or replayed).
    pub async fn redeem(&self, id: Uuid) -> Option<TicketLaunchPayload> {
        let now = Instant::now();
        let mut map = self.tickets.write().await;
        map.retain(|_, v| v.expires_at > now);
        map.remove(&id).map(|entry| entry.payload)
    }
}

/// TOFU (`Trust On First Use`) certificate pin registry keyed by `(tenant_id, target_key, protocol)`.
#[derive(Debug, Default)]
pub struct CertPinStore {
    pins: RwLock<HashMap<(String, String, String), [u8; 32]>>,
}

impl CertPinStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get_pin(
        &self,
        tenant_id: &str,
        target_host: &str,
        target_port: u16,
        protocol: &str,
    ) -> Option<[u8; 32]> {
        let key = (
            tenant_id.to_owned(),
            format!("{target_host}:{target_port}"),
            protocol.to_owned(),
        );
        self.pins.read().await.get(&key).copied()
    }

    pub async fn pin_if_absent(
        &self,
        tenant_id: &str,
        target_host: &str,
        target_port: u16,
        protocol: &str,
        sha256: [u8; 32],
    ) {
        let key = (
            tenant_id.to_owned(),
            format!("{target_host}:{target_port}"),
            protocol.to_owned(),
        );
        self.pins.write().await.entry(key).or_insert(sha256);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub ts_ms: u64,
    pub timestamp: String,
    pub tenant_id: String,
    pub trace_id: String,
    pub session_id: String,
    pub action: String,
    pub protocol: String,
    pub target_host: String,
    pub detail: String,
    pub details: String,
    pub user_id: String,
    pub user_email: String,
    pub role: String,
    pub ip: String,
    pub outcome: String,
    pub method: String,
    pub status_code: u16,
    pub user_agent: String,
    pub client: String,
    pub instance_id: String,
    pub instance_name: String,
    pub profile: String,
    pub region: String,
    pub recording_id: Option<String>,
    pub recording: Option<String>,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub prev_hash: String,
    #[serde(default)]
    pub entry_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditVerifyResult {
    pub valid: bool,
    pub source: String,
    pub tenant_id: String,
    pub checked_events: usize,
    pub first_seq: u64,
    pub last_seq: u64,
    pub head_hash: String,
    pub broken_at_seq: Option<u64>,
    pub error: Option<String>,
}

/// Canonical deterministic SHA-256 hash linking `seq`, `prev_hash`, identity, actor, target, and outcome.
#[must_use]
pub fn compute_audit_entry_hash(ev: &AuditEvent) -> String {
    let mut hasher = Sha256::new();
    let rec = ev.recording_id.as_deref().unwrap_or("");
    let canonical = serde_json::json!([
        ev.seq,
        ev.prev_hash,
        ev.id,
        ev.ts_ms,
        ev.tenant_id,
        ev.trace_id,
        ev.session_id,
        ev.action,
        ev.protocol,
        ev.target_host,
        ev.detail,
        ev.user_id,
        ev.user_email,
        ev.role,
        ev.ip,
        ev.outcome,
        ev.method,
        ev.status_code,
        ev.instance_id,
        rec,
    ])
    .to_string();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    let mut hex_out = String::with_capacity(64);
    for b in digest {
        let _ = write!(hex_out, "{b:02x}");
    }
    hex_out
}

/// Parameters for [`AuditLogStore::record_full`].
#[derive(Debug, Clone, Default)]
pub struct AuditRecordInput {
    pub tenant_id: String,
    pub trace_id: String,
    pub session_id: String,
    pub action: String,
    pub protocol: String,
    pub target_host: String,
    pub detail: String,
    pub user_id: String,
    pub user_email: String,
    pub role: String,
    pub ip: String,
    pub outcome: String,
    pub method: String,
    pub status_code: u16,
    pub user_agent: String,
    pub client: String,
    pub instance_id: String,
    pub instance_name: String,
    pub profile: String,
    pub region: String,
    pub recording_id: Option<String>,
}

/// Bounded in-memory + tamper-evident hash-chained PostgreSQL/SIEM enterprise audit log (`M10.1`).
#[derive(Default)]
pub struct AuditLogStore {
    events: RwLock<Vec<AuditEvent>>,
    chain_heads: Mutex<HashMap<String, (u64, String)>>,
    pg: RwLock<Option<PgAuthPool>>,
    siem: RwLock<Option<Arc<crate::siem::SiemDispatcher>>>,
}

impl std::fmt::Debug for AuditLogStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLogStore").finish_non_exhaustive()
    }
}

impl AuditLogStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn attach_pg(&self, pg: PgAuthPool) -> Result<(), String> {
        let heads = pg.latest_audit_heads().await?;
        {
            let mut chain_guard = self.chain_heads.lock().await;
            for (tid, seq, entry_hash) in heads {
                if !entry_hash.is_empty() {
                    chain_guard.insert(tid, (seq, entry_hash));
                }
            }
        }
        if let Ok(rows) = pg.list_audit_events_for_tenant("default", 500).await {
            let mut parsed = Vec::new();
            for row in rows {
                if let Ok(ev) = serde_json::from_str::<AuditEvent>(&row.event_json) {
                    parsed.push(ev);
                }
            }
            if !parsed.is_empty() {
                let mut ev_guard = self.events.write().await;
                if ev_guard.is_empty() {
                    *ev_guard = parsed;
                }
            }
        }
        *self.pg.write().await = Some(pg);
        Ok(())
    }

    pub async fn attach_siem(&self, siem: Arc<crate::siem::SiemDispatcher>) {
        *self.siem.write().await = Some(siem);
    }

    pub async fn siem_stats(&self) -> crate::siem::SiemStats {
        if let Some(dispatcher) = self.siem.read().await.as_ref() {
            dispatcher.stats()
        } else {
            crate::siem::SiemStats::default()
        }
    }

    pub async fn record_full(&self, input: AuditRecordInput) {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        let timestamp = operquay_recording::format_epoch_ms_iso8601(ts_ms);
        let details = input.detail.clone();
        let recording = input.recording_id.clone();
        let outcome = if input.outcome.is_empty() {
            "success".to_owned()
        } else {
            input.outcome
        };
        let pg_opt = self.pg.read().await.clone();

        let mut head_guard = self.chain_heads.lock().await;
        let (last_seq, prev_hash) = head_guard
            .get(&input.tenant_id)
            .cloned()
            .unwrap_or_else(|| (0, GENESIS_AUDIT_HASH.to_owned()));
        let seq = last_seq.saturating_add(1);
        let mut ev = AuditEvent {
            id: Uuid::new_v4().to_string(),
            ts_ms,
            timestamp,
            tenant_id: input.tenant_id.clone(),
            trace_id: input.trace_id,
            session_id: input.session_id,
            action: input.action,
            protocol: input.protocol,
            target_host: input.target_host,
            detail: input.detail,
            details,
            user_id: input.user_id,
            user_email: input.user_email,
            role: input.role,
            ip: input.ip,
            outcome,
            method: input.method,
            status_code: input.status_code,
            user_agent: input.user_agent,
            client: input.client,
            instance_id: input.instance_id,
            instance_name: input.instance_name,
            profile: input.profile,
            region: input.region,
            recording_id: input.recording_id,
            recording,
            seq,
            prev_hash,
            entry_hash: String::new(),
        };
        ev.entry_hash = compute_audit_entry_hash(&ev);
        head_guard.insert(input.tenant_id, (ev.seq, ev.entry_hash.clone()));

        if let Some(pg) = pg_opt {
            let target = if ev.target_host.is_empty() {
                ev.instance_id.clone()
            } else {
                ev.target_host.clone()
            };
            let row = PgAuditRow {
                tenant_id: ev.tenant_id.clone(),
                user_id: ev.user_id.clone(),
                action: ev.action.clone(),
                target,
                event_json: serde_json::to_string(&ev).unwrap_or_else(|_| "{}".to_owned()),
                seq: i64::try_from(ev.seq).unwrap_or(i64::MAX),
                prev_hash: ev.prev_hash.clone(),
                entry_hash: ev.entry_hash.clone(),
            };
            if let Err(err) = pg.insert_audit_event(&row).await {
                tracing::warn!(seq = ev.seq, tenant = %ev.tenant_id, error = %err, "failed persisting immutable audit event");
            }
        }
        drop(head_guard);

        {
            let mut guard = self.events.write().await;
            guard.push(ev.clone());
            if guard.len() > 500 {
                let excess = guard.len() - 500;
                guard.drain(..excess);
            }
        }

        if let Some(dispatcher) = self.siem.read().await.as_ref() {
            let _ = dispatcher.try_emit(ev);
        }
    }

    pub async fn verify_chain(&self, tenant_id: &str) -> AuditVerifyResult {
        if let Some(pg) = self.pg.read().await.clone() {
            match pg.list_audit_events_for_tenant(tenant_id, 50_000).await {
                Ok(rows) => return verify_pg_rows(tenant_id, &rows),
                Err(err) => {
                    return AuditVerifyResult {
                        valid: false,
                        source: "postgres".to_owned(),
                        tenant_id: tenant_id.to_owned(),
                        checked_events: 0,
                        first_seq: 0,
                        last_seq: 0,
                        head_hash: String::new(),
                        broken_at_seq: None,
                        error: Some(err),
                    };
                }
            }
        }
        let snapshot: Vec<AuditEvent> = self
            .events
            .read()
            .await
            .iter()
            .filter(|e| e.tenant_id == tenant_id)
            .cloned()
            .collect();
        verify_memory_events(tenant_id, &snapshot)
    }

    #[cfg(test)]
    pub async fn tamper_event_for_test(&self, tenant_id: &str, index: usize, new_detail: &str) {
        let mut guard = self.events.write().await;
        if let Some(ev) = guard
            .iter_mut()
            .filter(|e| e.tenant_id == tenant_id)
            .nth(index)
        {
            new_detail.clone_into(&mut ev.detail);
        }
    }

    pub async fn record(
        &self,
        tenant_id: &str,
        trace_id: &str,
        session_id: &str,
        action: &str,
        protocol: &str,
        target_host: &str,
        detail: impl Into<String>,
        recording_id: Option<String>,
    ) {
        self.record_full(AuditRecordInput {
            tenant_id: tenant_id.to_owned(),
            trace_id: trace_id.to_owned(),
            session_id: session_id.to_owned(),
            action: action.to_owned(),
            protocol: protocol.to_owned(),
            target_host: target_host.to_owned(),
            detail: detail.into(),
            outcome: "success".to_owned(),
            recording_id,
            ..AuditRecordInput::default()
        })
        .await;
    }

    pub async fn list(&self, tenant_id: &str) -> Vec<AuditEvent> {
        self.events
            .read()
            .await
            .iter()
            .filter(|e| e.tenant_id == tenant_id)
            .rev()
            .cloned()
            .collect()
    }

    pub async fn list_paginated(
        &self,
        tenant_id: &str,
        limit: usize,
        offset: usize,
    ) -> Vec<AuditEvent> {
        let clamped = if limit == 0 { 100 } else { limit.min(500) };
        self.events
            .read()
            .await
            .iter()
            .filter(|e| e.tenant_id == tenant_id)
            .rev()
            .skip(offset)
            .take(clamped)
            .cloned()
            .collect()
    }
}

fn verify_event_sequence(
    tenant_id: &str,
    source: &str,
    events: &[AuditEvent],
    allow_evicted_head: bool,
) -> AuditVerifyResult {
    if events.is_empty() {
        return AuditVerifyResult {
            valid: true,
            source: source.to_owned(),
            tenant_id: tenant_id.to_owned(),
            checked_events: 0,
            first_seq: 0,
            last_seq: 0,
            head_hash: GENESIS_AUDIT_HASH.to_owned(),
            broken_at_seq: None,
            error: None,
        };
    }
    let first_seq = events[0].seq;
    let mut expected_seq = if allow_evicted_head && first_seq > 1 {
        first_seq
    } else {
        1
    };
    let mut expected_prev = if expected_seq == 1 {
        GENESIS_AUDIT_HASH.to_owned()
    } else {
        events[0].prev_hash.clone()
    };
    if expected_prev.len() != 64 || !expected_prev.chars().all(|c| c.is_ascii_hexdigit()) {
        return AuditVerifyResult {
            valid: false,
            source: source.to_owned(),
            tenant_id: tenant_id.to_owned(),
            checked_events: 0,
            first_seq,
            last_seq: events.last().map_or(0, |e| e.seq),
            head_hash: String::new(),
            broken_at_seq: Some(events[0].seq),
            error: Some("invalid prev_hash format at chain head".to_owned()),
        };
    }

    let mut head_hash = expected_prev.clone();
    for (idx, ev) in events.iter().enumerate() {
        if ev.seq != expected_seq || ev.prev_hash != expected_prev {
            return AuditVerifyResult {
                valid: false,
                source: source.to_owned(),
                tenant_id: tenant_id.to_owned(),
                checked_events: idx,
                first_seq,
                last_seq: head_hash_seq(events, idx),
                head_hash,
                broken_at_seq: Some(ev.seq),
                error: Some(format!(
                    "hash chain continuity break at seq {} (expected seq {expected_seq})",
                    ev.seq
                )),
            };
        }
        let recomputed = compute_audit_entry_hash(ev);
        if ev.entry_hash != recomputed {
            return AuditVerifyResult {
                valid: false,
                source: source.to_owned(),
                tenant_id: tenant_id.to_owned(),
                checked_events: idx,
                first_seq,
                last_seq: head_hash_seq(events, idx),
                head_hash,
                broken_at_seq: Some(ev.seq),
                error: Some(format!(
                    "entry_hash mismatch (tampering detected) at seq {}",
                    ev.seq
                )),
            };
        }
        head_hash.clone_from(&ev.entry_hash);
        expected_prev.clone_from(&ev.entry_hash);
        expected_seq = expected_seq.saturating_add(1);
    }

    AuditVerifyResult {
        valid: true,
        source: source.to_owned(),
        tenant_id: tenant_id.to_owned(),
        checked_events: events.len(),
        first_seq,
        last_seq: events.last().map_or(0, |e| e.seq),
        head_hash,
        broken_at_seq: None,
        error: None,
    }
}

fn head_hash_seq(events: &[AuditEvent], idx: usize) -> u64 {
    if idx == 0 {
        0
    } else {
        events[idx - 1].seq
    }
}

fn verify_memory_events(tenant_id: &str, events: &[AuditEvent]) -> AuditVerifyResult {
    verify_event_sequence(tenant_id, "memory", events, true)
}

fn verify_pg_rows(tenant_id: &str, rows: &[PgAuditRow]) -> AuditVerifyResult {
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let row_seq = u64::try_from(row.seq).unwrap_or(0);
        match serde_json::from_str::<AuditEvent>(&row.event_json) {
            Ok(ev)
                if ev.seq == row_seq
                    && ev.prev_hash == row.prev_hash
                    && ev.entry_hash == row.entry_hash =>
            {
                parsed.push(ev);
            }
            Ok(ev) => {
                return AuditVerifyResult {
                    valid: false,
                    source: "postgres".to_owned(),
                    tenant_id: tenant_id.to_owned(),
                    checked_events: parsed.len(),
                    first_seq: parsed.first().map_or(row_seq, |e| e.seq),
                    last_seq: parsed.last().map_or(0, |e| e.seq),
                    head_hash: parsed
                        .last()
                        .map_or_else(String::new, |e| e.entry_hash.clone()),
                    broken_at_seq: Some(row_seq),
                    error: Some(format!(
                        "PostgreSQL column/JSON mismatch at seq {} (ev.seq={})",
                        row_seq, ev.seq
                    )),
                };
            }
            Err(e) => {
                return AuditVerifyResult {
                    valid: false,
                    source: "postgres".to_owned(),
                    tenant_id: tenant_id.to_owned(),
                    checked_events: parsed.len(),
                    first_seq: parsed.first().map_or(row_seq, |x| x.seq),
                    last_seq: parsed.last().map_or(0, |x| x.seq),
                    head_hash: parsed
                        .last()
                        .map_or_else(String::new, |x| x.entry_hash.clone()),
                    broken_at_seq: Some(row_seq),
                    error: Some(format!("corrupt audit JSON at seq {row_seq}: {e}")),
                };
            }
        }
    }
    verify_event_sequence(tenant_id, "postgres", &parsed, false)
}

/// Pure-Rust PostgreSQL Row-Level Security (`app.tenant_id`) persistent `SettingsStore`.
pub struct PostgresSettingsStore {
    client: Arc<tokio::sync::Mutex<Client>>,
}

impl PostgresSettingsStore {
    pub async fn connect_and_migrate(dsn: &str) -> Result<Self, SettingsStoreError> {
        let (client, connection) = tokio_postgres::connect(dsn, NoTls)
            .await
            .map_err(|e| SettingsStoreError::Backend(format!("postgres connect failed: {e}")))?;

        tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::error!(error = %err, "postgres connection loop terminated");
            }
        });

        client
            .batch_execute(MIGRATION_SQL)
            .await
            .map_err(|e| SettingsStoreError::Backend(format!("postgres migration failed: {e}")))?;

        client
            .batch_execute(MIGRATION_FULL_SQL)
            .await
            .map_err(|e| {
                SettingsStoreError::Backend(format!("postgres full schema migration failed: {e}"))
            })?;

        client.batch_execute(MIGRATION_M9_SQL).await.map_err(|e| {
            SettingsStoreError::Backend(format!(
                "postgres m9 security hardening migration failed: {e}"
            ))
        })?;

        client.batch_execute(MIGRATION_M10_SQL).await.map_err(|e| {
            SettingsStoreError::Backend(format!(
                "postgres m10 audit/worm persistence migration failed: {e}"
            ))
        })?;

        client.batch_execute(MIGRATION_M11_SQL).await.map_err(|e| {
            SettingsStoreError::Backend(format!(
                "postgres m11 governance/dlp/compliance migration failed: {e}"
            ))
        })?;

        client.batch_execute(MIGRATION_M12_SQL).await.map_err(|e| {
            SettingsStoreError::Backend(format!(
                "postgres m12 mcp/agents/multicloud/device-trust migration failed: {e}"
            ))
        })?;

        Ok(Self {
            client: Arc::new(tokio::sync::Mutex::new(client)),
        })
    }
}

fn enum_to_pg<T: Serialize>(value: &T) -> Result<String, SettingsStoreError> {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => Ok(s),
        Ok(other) => Err(SettingsStoreError::Backend(format!(
            "unexpected enum JSON shape: {other}"
        ))),
        Err(e) => Err(SettingsStoreError::Backend(e.to_string())),
    }
}

fn pg_to_enum<T: for<'de> Deserialize<'de>>(raw: &str) -> Result<T, SettingsStoreError> {
    serde_json::from_value(serde_json::Value::String(raw.to_owned()))
        .map_err(|e| SettingsStoreError::Backend(format!("invalid enum value '{raw}': {e}")))
}

#[async_trait]
impl SettingsStore for PostgresSettingsStore {
    async fn get(&self, tenant_id: &str) -> Result<RemoteDesktopSettings, SettingsStoreError> {
        let mut client = self.client.lock().await;
        let tx = client
            .transaction()
            .await
            .map_err(|e| SettingsStoreError::Backend(e.to_string()))?;

        tx.execute(
            "SELECT set_config('app.tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await
        .map_err(|e| SettingsStoreError::Backend(e.to_string()))?;

        let row = tx
            .query_opt(
                "SELECT network_preset, protocol_preference, transport_mode, codec_mode,
                        target_fps, jpeg_quality_floor, enable_copy_rect, enable_dynamic_resize,
                        enable_local_cursor_prediction, enable_mouse_coalescing, keyboard_layout,
                        unicode_fallback, rdp_security_mode, vnc_security_mode, cert_policy,
                        clipboard_normalization, fail_closed_recording, enable_drive_redirection,
                        otel_sample_ratio, show_live_telemetry_hud, allow_legacy_crypto_over_ssm
                 FROM remote_desktop_settings
                 WHERE tenant_id = $1 AND scope_key = 'default'",
                &[&tenant_id],
            )
            .await
            .map_err(|e| SettingsStoreError::Backend(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| SettingsStoreError::Backend(e.to_string()))?;

        let Some(r) = row else {
            return Ok(RemoteDesktopSettings::default());
        };

        let target_fps: i32 = r.get(4);
        let quality: i32 = r.get(5);
        Ok(RemoteDesktopSettings {
            network_preset: pg_to_enum(r.get(0))?,
            protocol_preference: pg_to_enum(r.get(1))?,
            transport_mode: pg_to_enum(r.get(2))?,
            codec_mode: pg_to_enum(r.get(3))?,
            target_fps: u8::try_from(target_fps).unwrap_or(30),
            jpeg_quality_floor: u8::try_from(quality).unwrap_or(55),
            enable_copy_rect: r.get(6),
            enable_dynamic_resize: r.get(7),
            enable_local_cursor_prediction: r.get(8),
            enable_mouse_coalescing: r.get(9),
            keyboard_layout: r.get(10),
            unicode_fallback: r.get(11),
            rdp_security_mode: pg_to_enum(r.get(12))?,
            vnc_security_mode: pg_to_enum(r.get(13))?,
            cert_policy: pg_to_enum(r.get(14))?,
            clipboard_normalization: pg_to_enum(r.get(15))?,
            fail_closed_recording: r.get(16),
            enable_drive_redirection: r.get(17),
            otel_sample_ratio: r.get(18),
            show_live_telemetry_hud: r.get(19),
            allow_legacy_crypto_over_ssm: r.get(20),
        })
    }

    async fn put(
        &self,
        tenant_id: &str,
        settings: RemoteDesktopSettings,
    ) -> Result<RemoteDesktopSettings, SettingsStoreError> {
        settings.validate()?;
        let mut client = self.client.lock().await;
        let tx = client
            .transaction()
            .await
            .map_err(|e| SettingsStoreError::Backend(e.to_string()))?;

        tx.execute(
            "SELECT set_config('app.tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await
        .map_err(|e| SettingsStoreError::Backend(e.to_string()))?;

        let preset = enum_to_pg(&settings.network_preset)?;
        let proto = enum_to_pg(&settings.protocol_preference)?;
        let transport = enum_to_pg(&settings.transport_mode)?;
        let codec = enum_to_pg(&settings.codec_mode)?;
        let rdp_sec = enum_to_pg(&settings.rdp_security_mode)?;
        let vnc_sec = enum_to_pg(&settings.vnc_security_mode)?;
        let cert = enum_to_pg(&settings.cert_policy)?;
        let clip = enum_to_pg(&settings.clipboard_normalization)?;
        let fps = i32::from(settings.target_fps);
        let quality = i32::from(settings.jpeg_quality_floor);

        tx.execute(
            "INSERT INTO remote_desktop_settings (
                tenant_id, scope_key, network_preset, protocol_preference, transport_mode,
                codec_mode, target_fps, jpeg_quality_floor, enable_copy_rect, enable_dynamic_resize,
                enable_local_cursor_prediction, enable_mouse_coalescing, keyboard_layout,
                unicode_fallback, rdp_security_mode, vnc_security_mode, cert_policy,
                clipboard_normalization, fail_closed_recording, enable_drive_redirection,
                otel_sample_ratio, show_live_telemetry_hud, allow_legacy_crypto_over_ssm,
                updated_by, updated_at
             ) VALUES (
                $1, 'default', $2, $3, $4, $5, $6, $7, $8, $9,
                $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
                $20, $21, $22, 'api', NOW()
             )
             ON CONFLICT (tenant_id, scope_key) DO UPDATE SET
                network_preset = EXCLUDED.network_preset,
                protocol_preference = EXCLUDED.protocol_preference,
                transport_mode = EXCLUDED.transport_mode,
                codec_mode = EXCLUDED.codec_mode,
                target_fps = EXCLUDED.target_fps,
                jpeg_quality_floor = EXCLUDED.jpeg_quality_floor,
                enable_copy_rect = EXCLUDED.enable_copy_rect,
                enable_dynamic_resize = EXCLUDED.enable_dynamic_resize,
                enable_local_cursor_prediction = EXCLUDED.enable_local_cursor_prediction,
                enable_mouse_coalescing = EXCLUDED.enable_mouse_coalescing,
                keyboard_layout = EXCLUDED.keyboard_layout,
                unicode_fallback = EXCLUDED.unicode_fallback,
                rdp_security_mode = EXCLUDED.rdp_security_mode,
                vnc_security_mode = EXCLUDED.vnc_security_mode,
                cert_policy = EXCLUDED.cert_policy,
                clipboard_normalization = EXCLUDED.clipboard_normalization,
                fail_closed_recording = EXCLUDED.fail_closed_recording,
                enable_drive_redirection = EXCLUDED.enable_drive_redirection,
                otel_sample_ratio = EXCLUDED.otel_sample_ratio,
                show_live_telemetry_hud = EXCLUDED.show_live_telemetry_hud,
                allow_legacy_crypto_over_ssm = EXCLUDED.allow_legacy_crypto_over_ssm,
                updated_at = NOW()",
            &[
                &tenant_id,
                &preset,
                &proto,
                &transport,
                &codec,
                &fps,
                &quality,
                &settings.enable_copy_rect,
                &settings.enable_dynamic_resize,
                &settings.enable_local_cursor_prediction,
                &settings.enable_mouse_coalescing,
                &settings.keyboard_layout,
                &settings.unicode_fallback,
                &rdp_sec,
                &vnc_sec,
                &cert,
                &clip,
                &settings.fail_closed_recording,
                &settings.enable_drive_redirection,
                &settings.otel_sample_ratio,
                &settings.show_live_telemetry_hud,
                &settings.allow_legacy_crypto_over_ssm,
            ],
        )
        .await
        .map_err(|e| SettingsStoreError::Backend(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| SettingsStoreError::Backend(e.to_string()))?;

        Ok(settings)
    }

    async fn reset(&self, tenant_id: &str) -> Result<RemoteDesktopSettings, SettingsStoreError> {
        let mut client = self.client.lock().await;
        let tx = client
            .transaction()
            .await
            .map_err(|e| SettingsStoreError::Backend(e.to_string()))?;
        tx.execute(
            "SELECT set_config('app.tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await
        .map_err(|e| SettingsStoreError::Backend(e.to_string()))?;
        tx.execute(
            "DELETE FROM remote_desktop_settings WHERE tenant_id = $1 AND scope_key = 'default'",
            &[&tenant_id],
        )
        .await
        .map_err(|e| SettingsStoreError::Backend(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| SettingsStoreError::Backend(e.to_string()))?;
        Ok(RemoteDesktopSettings::default())
    }
}

/// Embedded pure-Rust `DuckDB` analytical & control-plane [`SettingsStore`] backed by [`operquay_db::DuckDbDriver`].
/// Supports `duckdb://memory` and `duckdb:///path/to/controlplane.duckdb`.
pub struct DuckDbSettingsStore {
    driver: operquay_db::DuckDbDriver,
    spec: operquay_db::DbConnectionSpec,
}

impl DuckDbSettingsStore {
    pub async fn connect_and_migrate(dsn: &str) -> Result<Self, SettingsStoreError> {
        let target = dsn
            .trim()
            .strip_prefix("duckdb://")
            .unwrap_or(dsn.trim())
            .trim();
        let host = if target.is_empty() || target == ":memory:" || target == "memory" {
            "memory".to_owned()
        } else {
            target.to_owned()
        };
        let spec = operquay_db::DbConnectionSpec {
            tenant: "system".into(),
            engine: "duckdb".into(),
            host,
            port: 1294,
            database: "operquay_control_plane".into(),
            username: String::new(),
            password: String::new(),
            ssl_mode: "disable".into(),
            cache_key: "duckdb_control_plane".into(),
        };
        let driver = operquay_db::DuckDbDriver::new();
        driver
            .mutate_sql(
                &spec,
                "CREATE TABLE IF NOT EXISTS control_plane_settings (tenant_id VARCHAR PRIMARY KEY, settings_json VARCHAR NOT NULL)",
            )
            .await
            .map_err(SettingsStoreError::Backend)?;
        Ok(Self { driver, spec })
    }
}

#[async_trait]
impl SettingsStore for DuckDbSettingsStore {
    async fn get(&self, tenant_id: &str) -> Result<RemoteDesktopSettings, SettingsStoreError> {
        use operquay_db::DatabaseEngineDriver as _;
        let escaped = tenant_id.replace('\'', "''");
        let sql = format!(
            "SELECT settings_json FROM control_plane_settings WHERE tenant_id = '{escaped}' LIMIT 1"
        );
        let res = self
            .driver
            .query(&self.spec, &sql, true)
            .await
            .map_err(|e| SettingsStoreError::Backend(e.message))?;
        let Some(raw) = res
            .rows
            .first()
            .and_then(|r| r.get("settings_json"))
            .and_then(|v| v.as_str())
        else {
            return Ok(RemoteDesktopSettings::default());
        };
        let settings: RemoteDesktopSettings =
            serde_json::from_str(raw).map_err(|e| SettingsStoreError::Backend(e.to_string()))?;
        settings.validate()?;
        Ok(settings)
    }

    async fn put(
        &self,
        tenant_id: &str,
        settings: RemoteDesktopSettings,
    ) -> Result<RemoteDesktopSettings, SettingsStoreError> {
        use operquay_db::DatabaseEngineDriver as _;
        settings.validate()?;
        let json = serde_json::to_string(&settings)
            .map_err(|e| SettingsStoreError::Backend(e.to_string()))?;
        let mut updates = Vec::new();
        let mut inserts = Vec::new();
        let existing = self
            .driver
            .query(
                &self.spec,
                &format!(
                    "SELECT tenant_id FROM control_plane_settings WHERE tenant_id = '{}' LIMIT 1",
                    tenant_id.replace('\'', "''")
                ),
                true,
            )
            .await
            .map_err(|e| SettingsStoreError::Backend(e.message))?;
        if existing.rows.is_empty() {
            let mut m = HashMap::new();
            m.insert(
                "tenant_id".into(),
                serde_json::Value::String(tenant_id.to_owned()),
            );
            m.insert("settings_json".into(), serde_json::Value::String(json));
            inserts.push(m);
        } else {
            let mut keys = HashMap::new();
            keys.insert(
                "tenant_id".into(),
                serde_json::Value::String(tenant_id.to_owned()),
            );
            let mut values = HashMap::new();
            values.insert("settings_json".into(), serde_json::Value::String(json));
            updates.push(operquay_db::DbRowUpdate {
                keys,
                values,
                original: HashMap::new(),
                changes: HashMap::new(),
            });
        }
        self.driver
            .mutate_structured(
                &self.spec,
                "main",
                "control_plane_settings",
                &["tenant_id".to_owned()],
                &updates,
                &inserts,
                &[],
            )
            .await
            .map_err(SettingsStoreError::Backend)?;
        Ok(settings)
    }

    async fn reset(&self, tenant_id: &str) -> Result<RemoteDesktopSettings, SettingsStoreError> {
        use operquay_db::DatabaseEngineDriver as _;
        let mut del = HashMap::new();
        del.insert(
            "tenant_id".into(),
            serde_json::Value::String(tenant_id.to_owned()),
        );
        self.driver
            .mutate_structured(
                &self.spec,
                "main",
                "control_plane_settings",
                &["tenant_id".to_owned()],
                &[],
                &[],
                &[del],
            )
            .await
            .map_err(SettingsStoreError::Backend)?;
        Ok(RemoteDesktopSettings::default())
    }
}

/// `ClickHouse` HTTP-JSON analytical control-plane [`SettingsStore`] backed by [`operquay_db::ClickHouseDriver`].
/// Supports `clickhouse://user:pass@host:8123/db` and `clickhouse://embedded`.
pub struct ClickHouseSettingsStore {
    driver: operquay_db::ClickHouseDriver,
    spec: operquay_db::DbConnectionSpec,
}

impl ClickHouseSettingsStore {
    pub async fn connect_and_migrate(dsn: &str) -> Result<Self, SettingsStoreError> {
        let spec = parse_clickhouse_dsn(dsn);
        let driver = operquay_db::ClickHouseDriver::new();
        let ddl = if spec.host.eq_ignore_ascii_case("embedded")
            || spec.host.eq_ignore_ascii_case("memory")
        {
            "CREATE TABLE IF NOT EXISTS control_plane_settings (tenant_id VARCHAR PRIMARY KEY, settings_json VARCHAR NOT NULL)"
        } else {
            "CREATE TABLE IF NOT EXISTS control_plane_settings (tenant_id String, settings_json String, updated_at DateTime DEFAULT now()) ENGINE = ReplacingMergeTree(updated_at) ORDER BY tenant_id"
        };
        driver
            .mutate_sql(&spec, ddl)
            .await
            .map_err(SettingsStoreError::Backend)?;
        Ok(Self { driver, spec })
    }
}

fn parse_clickhouse_dsn(dsn: &str) -> operquay_db::DbConnectionSpec {
    let trimmed = dsn
        .trim()
        .strip_prefix("clickhouse://")
        .unwrap_or(dsn.trim());
    let (auth_part, rest) = trimmed.rsplit_once('@').unwrap_or(("", trimmed));
    let (username, password) = auth_part.split_once(':').unwrap_or((auth_part, ""));
    let (host_port, db_part) = rest.split_once('/').unwrap_or((rest, "default"));
    let (host, port_str) = host_port.split_once(':').unwrap_or((host_port, "8123"));
    let port = port_str.parse::<u16>().unwrap_or(8123);
    operquay_db::DbConnectionSpec {
        tenant: "system".into(),
        engine: "clickhouse".into(),
        host: if host.is_empty() {
            "localhost".into()
        } else {
            host.to_owned()
        },
        port,
        database: if db_part.is_empty() {
            "default".into()
        } else {
            db_part.to_owned()
        },
        username: username.to_owned(),
        password: password.to_owned(),
        ssl_mode: if port == 8443 {
            "require".into()
        } else {
            "disable".into()
        },
        cache_key: "clickhouse_control_plane".into(),
    }
}

#[async_trait]
impl SettingsStore for ClickHouseSettingsStore {
    async fn get(&self, tenant_id: &str) -> Result<RemoteDesktopSettings, SettingsStoreError> {
        use operquay_db::DatabaseEngineDriver as _;
        let escaped = tenant_id.replace('\'', "''");
        let sql = format!(
            "SELECT settings_json FROM control_plane_settings WHERE tenant_id = '{escaped}' LIMIT 1"
        );
        let res = self
            .driver
            .query(&self.spec, &sql, true)
            .await
            .map_err(|e| SettingsStoreError::Backend(e.message))?;
        let Some(raw) = res
            .rows
            .last()
            .and_then(|r| r.get("settings_json"))
            .and_then(|v| v.as_str())
        else {
            return Ok(RemoteDesktopSettings::default());
        };
        let settings: RemoteDesktopSettings =
            serde_json::from_str(raw).map_err(|e| SettingsStoreError::Backend(e.to_string()))?;
        settings.validate()?;
        Ok(settings)
    }

    async fn put(
        &self,
        tenant_id: &str,
        settings: RemoteDesktopSettings,
    ) -> Result<RemoteDesktopSettings, SettingsStoreError> {
        use operquay_db::DatabaseEngineDriver as _;
        settings.validate()?;
        let json = serde_json::to_string(&settings)
            .map_err(|e| SettingsStoreError::Backend(e.to_string()))?;
        let mut ins = HashMap::new();
        ins.insert(
            "tenant_id".into(),
            serde_json::Value::String(tenant_id.to_owned()),
        );
        ins.insert("settings_json".into(), serde_json::Value::String(json));
        self.driver
            .mutate_structured(
                &self.spec,
                &self.spec.database,
                "control_plane_settings",
                &["tenant_id".to_owned()],
                &[],
                &[ins],
                &[],
            )
            .await
            .map_err(SettingsStoreError::Backend)?;
        Ok(settings)
    }

    async fn reset(&self, tenant_id: &str) -> Result<RemoteDesktopSettings, SettingsStoreError> {
        use operquay_db::DatabaseEngineDriver as _;
        let mut del = HashMap::new();
        del.insert(
            "tenant_id".into(),
            serde_json::Value::String(tenant_id.to_owned()),
        );
        let _ = self
            .driver
            .mutate_structured(
                &self.spec,
                &self.spec.database,
                "control_plane_settings",
                &["tenant_id".to_owned()],
                &[],
                &[],
                &[del],
            )
            .await;
        Ok(RemoteDesktopSettings::default())
    }
}

/// Construct the control-plane [`SettingsStore`] dynamically from `--database-url` / `OPERQUAY_DATABASE_URL`:
/// supports `postgres://`, `postgresql://`, `clickhouse://`, `duckdb://`, or `None` (in-memory).
pub async fn build_settings_store_from_dsn(
    dsn: Option<&str>,
) -> Result<Arc<dyn operquay_core::SettingsStore>, SettingsStoreError> {
    let Some(raw) = dsn.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(Arc::new(operquay_core::InMemorySettingsStore::new()));
    };
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("duckdb://") {
        tracing::info!("connecting to embedded/file DuckDB control-plane settings store");
        return Ok(Arc::new(
            DuckDbSettingsStore::connect_and_migrate(raw).await?,
        ));
    }
    if lower.starts_with("clickhouse://") {
        tracing::info!("connecting to ClickHouse analytical control-plane settings store");
        return Ok(Arc::new(
            ClickHouseSettingsStore::connect_and_migrate(raw).await?,
        ));
    }
    tracing::info!("connecting to PostgreSQL RLS settings store");
    Ok(Arc::new(
        PostgresSettingsStore::connect_and_migrate(raw).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ticket_is_strictly_single_use_and_expires() {
        let store = TicketStore::new();
        let id = store
            .issue(
                TicketLaunchPayload {
                    session_id: "s-1".into(),
                    tenant_id: "acme".into(),
                    user_id: String::new(),
                    auth_session_id: String::new(),
                    protocol: "rdp".into(),
                    launch_mode: LaunchMode::DirectTcp,
                    target_host: "10.0.0.5".into(),
                    target_port: 3389,
                    username: "admin".into(),
                    password: SecretString::new("SuperSecret!1"),
                    width: 1280,
                    height: 720,
                    keyboard_layout: None,
                    transport_mode: None,
                    expected_cert_sha256: None,
                    simulate_recording_fault: false,
                    aws_profile: None,
                    aws_region: None,
                    rdp_security_mode: None,
                },
                Duration::from_secs(30),
            )
            .await;

        assert!(store.redeem(id).await.is_some());
        assert!(store.redeem(id).await.is_none());

        let expired_id = store
            .issue(
                TicketLaunchPayload {
                    session_id: "s-exp".into(),
                    tenant_id: "acme".into(),
                    user_id: String::new(),
                    auth_session_id: String::new(),
                    protocol: "rdp".into(),
                    launch_mode: LaunchMode::Demo,
                    target_host: "demo".into(),
                    target_port: 3389,
                    username: "demo".into(),
                    password: SecretString::new(""),
                    width: 1280,
                    height: 720,
                    keyboard_layout: None,
                    transport_mode: None,
                    expected_cert_sha256: None,
                    simulate_recording_fault: false,
                    aws_profile: None,
                    aws_region: None,
                    rdp_security_mode: None,
                },
                Duration::from_millis(1),
            )
            .await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(store.redeem(expired_id).await.is_none());
    }

    #[test]
    fn postgres_enum_roundtrip_and_migration_sql_are_valid() {
        let defaults = RemoteDesktopSettings::default();
        assert_eq!(
            enum_to_pg(&defaults.network_preset).unwrap(),
            "auto_adaptive"
        );
        assert_eq!(enum_to_pg(&defaults.cert_policy).unwrap(), "tofu_pinned");
        assert_eq!(enum_to_pg(&defaults.rdp_security_mode).unwrap(), "any");
        assert!(MIGRATION_SQL.contains("CREATE TABLE IF NOT EXISTS remote_desktop_settings"));
        assert!(MIGRATION_SQL.contains("FORCE ROW LEVEL SECURITY"));
        assert!(MIGRATION_SQL.contains("NULLIF(current_setting('app.tenant_id', true), '')"));
        assert!(!MIGRATION_SQL.contains("IS NULL OR"));
        assert!(MIGRATION_FULL_SQL.contains("FORCE ROW LEVEL SECURITY"));
        assert!(
            MIGRATION_FULL_SQL.contains("NULLIF(current_setting(''app.tenant_id'', true), '''')")
        );
        assert!(!MIGRATION_FULL_SQL.contains("IS NULL OR"));
        assert!(MIGRATION_M9_SQL.contains("FORCE ROW LEVEL SECURITY"));
        assert!(MIGRATION_M9_SQL.contains("NULLIF(current_setting(''app.tenant_id'', true), '''')"));
        assert!(MIGRATION_M9_SQL.contains("operquay_app"));
        assert!(MIGRATION_M9_SQL.contains("NOBYPASSRLS"));
        assert!(!MIGRATION_M9_SQL.contains("IS NULL OR"));
        assert!(MIGRATION_M10_SQL.contains("prevent_audit_events_mutation"));
        assert!(MIGRATION_M10_SQL.contains("REVOKE UPDATE, DELETE, TRUNCATE ON audit_events"));
        assert!(MIGRATION_M10_SQL.contains("FORCE ROW LEVEL SECURITY"));
        assert!(MIGRATION_M10_SQL.contains("tenant_encryption_keys"));
        assert!(MIGRATION_M10_SQL.contains("recording_metadata"));
        assert!(MIGRATION_M10_SQL.contains("aws_sso_sessions"));
        assert!(MIGRATION_M10_SQL.contains("aws_role_leases"));
        assert!(MIGRATION_M11_SQL.contains("jit_access_requests"));
        assert!(MIGRATION_M11_SQL.contains("governance_webhooks"));
        assert!(MIGRATION_M11_SQL.contains("dlp_firewall_policies"));
        assert!(MIGRATION_M11_SQL.contains("session_risk_bookmarks"));
        assert!(MIGRATION_M11_SQL.contains("access_review_campaigns"));
        assert!(MIGRATION_M11_SQL.contains("FORCE ROW LEVEL SECURITY"));
        assert!(!MIGRATION_M11_SQL.contains("IS NULL OR"));
        assert!(MIGRATION_M12_SQL.contains("mcp_agents"));
        assert!(MIGRATION_M12_SQL.contains("mcp_tool_invocations"));
        assert!(MIGRATION_M12_SQL.contains("hybrid_agents"));
        assert!(MIGRATION_M12_SQL.contains("cloud_connectors"));
        assert!(MIGRATION_M12_SQL.contains("device_trust_policies"));
        assert!(MIGRATION_M12_SQL.contains("device_posture_attestations"));
        assert!(MIGRATION_M12_SQL.contains("FORCE ROW LEVEL SECURITY"));
        assert!(!MIGRATION_M12_SQL.contains("IS NULL OR"));
    }

    #[tokio::test]
    async fn audit_hash_chain_links_events_and_detects_tampering() {
        let audit = AuditLogStore::new();
        audit
            .record(
                "acme",
                "t1",
                "s1",
                "login",
                "http",
                "control-plane",
                "first",
                None,
            )
            .await;
        audit
            .record(
                "acme",
                "t2",
                "s2",
                "session_launch",
                "rdp",
                "10.0.0.5",
                "second",
                Some("rec-1".to_owned()),
            )
            .await;

        let ok = audit.verify_chain("acme").await;
        assert!(ok.valid);
        assert_eq!(ok.source, "memory");
        assert_eq!(ok.checked_events, 2);
        assert_eq!(ok.first_seq, 1);
        assert_eq!(ok.last_seq, 2);
        assert_eq!(ok.broken_at_seq, None);

        audit
            .tamper_event_for_test("acme", 0, "tampered detail")
            .await;
        let bad = audit.verify_chain("acme").await;
        assert!(!bad.valid);
        assert_eq!(bad.broken_at_seq, Some(1));
    }

    #[tokio::test]
    async fn multi_db_settings_store_supports_duckdb_and_clickhouse_embedded() {
        for dsn in ["duckdb://memory", "clickhouse://embedded"] {
            let store = build_settings_store_from_dsn(Some(dsn)).await.unwrap();
            let s = RemoteDesktopSettings {
                target_fps: 45,
                ..RemoteDesktopSettings::default()
            };
            store.put("tenant-a", s.clone()).await.unwrap();
            let loaded = store.get("tenant-a").await.unwrap();
            assert_eq!(loaded.target_fps, 45);
            let reset = store.reset("tenant-a").await.unwrap();
            assert_eq!(
                reset.target_fps,
                RemoteDesktopSettings::default().target_fps
            );
        }
    }
}
