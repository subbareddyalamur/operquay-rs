#![forbid(unsafe_code)]

//! Single-binary Axum control plane, REST settings/protocol/ticket/recording API,
//! OpenTelemetry HTTP/WS instrumentation, and dual `OQR2` / Guacamole WebSocket bridge.

pub mod agent_hub;
pub mod auth_routes;
pub mod aws_routes;
pub mod compliance;
pub mod device_trust;
pub mod dlp;
pub mod governance_routes;
pub mod jit;
pub mod m12_routes;
pub mod mcp;
pub mod moderation;
pub mod multicloud;
pub mod platform_routes;
pub mod session_fence;
pub mod siem;
pub mod stores;
pub mod ws;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, Extension, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use operquay_auth::crypto::{
    extract_tenant_id_checked, resolve_client_ip, TenantKeyManager, TrustedProxies,
};
use operquay_auth::AuthService;
use operquay_core::{
    EngineCapability, EngineRegistry, KeyboardLayoutDescriptor, NetworkSimulationCondition,
    NetworkSimulationResult, RemoteDesktopSettings, SecretString, SettingsStore, KEYBOARD_LAYOUTS,
};
use operquay_rdp::RdpEngineFactory;
use operquay_recording::{build_iso_bmff_mp4, RecordingCatalog, RecordingEntry};
use operquay_telemetry::{TelemetryHub, TelemetrySummary};
use operquay_vnc::VncEngineFactory;
use rust_embed::Embed;
use serde::{Deserialize, Serialize};
use tower_http::services::{ServeDir, ServeFile};
use tracing::Instrument;
use uuid::Uuid;

use crate::stores::{
    AuditEvent, AuditLogStore, CertPinStore, LaunchMode, TicketLaunchPayload, TicketStore,
    TICKET_TTL,
};

#[derive(Embed)]
#[folder = "../../frontend/dist"]
struct EmbeddedFrontend;

#[derive(Debug, Clone, Copy)]
pub struct ListenerScheme(pub bool);

#[derive(Debug, Clone)]
pub struct ResolvedRequestContext {
    pub client_ip: String,
    pub tenant_id: String,
    pub is_https: bool,
}

impl ResolvedRequestContext {
    #[must_use]
    pub fn from_headers(headers: &HeaderMap, trusted: &TrustedProxies) -> Self {
        Self {
            client_ip: resolve_client_ip(None, headers, trusted),
            tenant_id: extract_tenant_id_checked(None, headers, trusted),
            is_https: false,
        }
    }
}

fn normalize_origin(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "*" {
        return None;
    }
    let rest = if let Some(r) = trimmed.strip_prefix("https://") {
        ("https://", r)
    } else {
        let r = trimmed.strip_prefix("http://")?;
        ("http://", r)
    };
    let authority = rest
        .1
        .split(['/', '?', '#'])
        .next()
        .map(str::trim)
        .filter(|a| !a.is_empty())?;
    Some(format!("{}{}", rest.0, authority.to_ascii_lowercase()))
}

fn parse_allowed_origins_env() -> Vec<String> {
    std::env::var("OPERQUAY_ALLOWED_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .filter_map(normalize_origin)
        .collect()
}

fn public_url_origin() -> Option<String> {
    std::env::var("PUBLIC_URL")
        .or_else(|_| std::env::var("OPERQUAY_PUBLIC_URL"))
        .ok()
        .and_then(|v| normalize_origin(&v))
}

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<dyn SettingsStore>,
    pub engines: Arc<EngineRegistry>,
    pub telemetry: Arc<TelemetryHub>,
    pub tickets: Arc<TicketStore>,
    pub recordings: Arc<RecordingCatalog>,
    pub audit: Arc<AuditLogStore>,
    pub cert_pins: Arc<CertPinStore>,
    pub auth: Arc<AuthService>,
    pub aws: Arc<aws_routes::AwsHubState>,
    pub platform: Arc<platform_routes::PlatformState>,
    pub static_dir: Option<PathBuf>,
    pub pg_pool: Arc<tokio::sync::RwLock<Option<operquay_auth::pg::PgAuthPool>>>,
    pub trusted_proxies: Arc<TrustedProxies>,
    pub allowed_origins: Arc<Vec<String>>,
    pub session_fence: Arc<session_fence::ActiveSessionFence>,
    pub tenant_keys: Arc<TenantKeyManager>,
    pub governance: Arc<jit::GovernanceStore>,
    pub moderation: Arc<moderation::SessionModerationHub>,
    pub mcp: Arc<mcp::McpRegistry>,
    pub agent_hub: Arc<agent_hub::AgentHub>,
    pub multicloud: Arc<multicloud::MultiCloudStore>,
    pub device_trust: Arc<device_trust::DeviceTrustStore>,
}

impl AppState {
    pub async fn set_pg_pool(&self, pool: operquay_auth::pg::PgAuthPool) {
        *self.pg_pool.write().await = Some(pool);
    }

    pub async fn pg_pool(&self) -> Option<operquay_auth::pg::PgAuthPool> {
        self.pg_pool.read().await.clone()
    }

    /// Ensure the tenant's data-encryption key (DEK) is persisted in PostgreSQL if attached
    /// and loaded into the shared in-memory `TenantKeyManager` before starting an encrypted recording.
    pub async fn ensure_tenant_dek_persisted(&self, tenant_id: &str) {
        let Some(pg) = self.pg_pool().await else {
            return;
        };
        if let Ok(Some(dek)) = pg.get_or_create_tenant_dek(tenant_id).await {
            self.tenant_keys
                .hydrate_key(tenant_id, Some(dek), false)
                .await;
        }
    }

    /// Persist recording metadata to PostgreSQL (`recording_metadata`) and spawn async S3 WORM
    /// Object Lock archival when configured and the recording has completed.
    pub async fn persist_recording_metadata(&self, entry: &RecordingEntry) {
        if let Some(pg) = self.pg_pool().await {
            let row = operquay_auth::pg::PgRecordingMetaRow {
                id: entry.id.clone(),
                tenant_id: entry.tenant_id.clone(),
                protocol: entry.protocol.clone(),
                target_host: entry.target_host.clone(),
                format: entry.format.clone(),
                started_at_ms: i64::try_from(entry.started_at_ms).unwrap_or(i64::MAX),
                bytes_written: i64::try_from(entry.bytes_written).unwrap_or(i64::MAX),
                frame_count: i64::try_from(entry.frame_count).unwrap_or(i64::MAX),
                sha256_hex: entry.sha256_hex.clone(),
                fail_closed: entry.fail_closed,
                status: entry.status.clone(),
                encrypted: entry.encrypted,
                legal_hold: entry.legal_hold,
                legal_hold_reason: entry.legal_hold_reason.clone(),
                retention_until_ms: entry
                    .retention_until_ms
                    .map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
                archived_s3_uri: entry.archived_s3_uri.clone(),
                archived_at_ms: entry
                    .archived_at_ms
                    .map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
            };
            if let Err(err) = pg.upsert_recording_metadata(&row).await {
                tracing::warn!(recording_id = %entry.id, error = %err, "failed persisting recording metadata");
            }
        }
        if entry.status == "completed" && entry.format == "cast" {
            let state_bm = self.clone();
            let entry_bm = entry.clone();
            tokio::spawn(async move {
                let Some(raw) = state_bm.recordings.get_guac_bytes(&entry_bm.id).await else {
                    return;
                };
                let transcript = String::from_utf8_lossy(&raw);
                let analysis = state_bm
                    .platform
                    .llm
                    .safety()
                    .extract_session_risk_bookmarks(&transcript);
                if analysis.bookmarks.is_empty() {
                    return;
                }
                let now = jit::now_unix_secs();
                let items: Vec<jit::SessionRiskBookmark> = analysis
                    .bookmarks
                    .into_iter()
                    .map(|b| jit::SessionRiskBookmark {
                        id: format!("bmk-{}", Uuid::new_v4()),
                        tenant_id: entry_bm.tenant_id.clone(),
                        recording_id: entry_bm.id.clone(),
                        session_id: entry_bm.id.clone(),
                        offset_secs: b.offset_secs,
                        severity: b.severity,
                        category: b.category,
                        title: b.title,
                        detail: b.detail,
                        source: b.source,
                        created_at: now,
                    })
                    .collect();
                state_bm
                    .governance
                    .replace_bookmarks(&entry_bm.tenant_id, &entry_bm.id, items.clone())
                    .await;
                governance_routes::persist_risk_bookmarks(&state_bm, &items).await;
            });
        }
        if entry.status == "completed" && entry.archived_s3_uri.is_none() {
            if let Some(archiver) = operquay_recording::worm::S3WormArchiver::from_env() {
                let state = self.clone();
                let entry_c = entry.clone();
                tokio::spawn(async move {
                    if let Some(enc_bytes) = state.recordings.get_encrypted_bytes(&entry_c.id).await
                    {
                        let ext = if entry_c.format == "cast" {
                            "cast"
                        } else {
                            "guac"
                        };
                        match archiver
                            .archive_object(
                                &entry_c.tenant_id,
                                &entry_c.id,
                                ext,
                                &enc_bytes,
                                entry_c.legal_hold,
                            )
                            .await
                        {
                            Ok(res) => {
                                if let Some(updated) = state
                                    .recordings
                                    .mark_archived(
                                        &entry_c.tenant_id,
                                        &entry_c.id,
                                        res.s3_uri,
                                        res.retain_until_ms,
                                        res.archived_at_ms,
                                    )
                                    .await
                                {
                                    if let Some(pg) = state.pg_pool().await {
                                        let row = operquay_auth::pg::PgRecordingMetaRow {
                                            id: updated.id.clone(),
                                            tenant_id: updated.tenant_id.clone(),
                                            protocol: updated.protocol.clone(),
                                            target_host: updated.target_host.clone(),
                                            format: updated.format.clone(),
                                            started_at_ms: i64::try_from(updated.started_at_ms)
                                                .unwrap_or(i64::MAX),
                                            bytes_written: i64::try_from(updated.bytes_written)
                                                .unwrap_or(i64::MAX),
                                            frame_count: i64::try_from(updated.frame_count)
                                                .unwrap_or(i64::MAX),
                                            sha256_hex: updated.sha256_hex.clone(),
                                            fail_closed: updated.fail_closed,
                                            status: updated.status.clone(),
                                            encrypted: updated.encrypted,
                                            legal_hold: updated.legal_hold,
                                            legal_hold_reason: updated.legal_hold_reason.clone(),
                                            retention_until_ms: updated
                                                .retention_until_ms
                                                .map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
                                            archived_s3_uri: updated.archived_s3_uri.clone(),
                                            archived_at_ms: updated
                                                .archived_at_ms
                                                .map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
                                        };
                                        let _ = pg.upsert_recording_metadata(&row).await;
                                    }
                                }
                            }
                            Err(err) => {
                                tracing::warn!(recording_id = %entry_c.id, error = %err, "background WORM S3 archival failed");
                            }
                        }
                    }
                });
            }
        }
    }
}

impl AppState {
    #[must_use]
    pub fn with_defaults(
        settings: Arc<dyn SettingsStore>,
        telemetry: Arc<TelemetryHub>,
        static_dir: Option<PathBuf>,
    ) -> Self {
        let mut registry = EngineRegistry::new();
        registry.register(Arc::new(RdpEngineFactory));
        registry.register(Arc::new(VncEngineFactory));
        let admin_pw = std::env::var("OPERQUAY_ADMIN_PASSWORD")
            .ok()
            .filter(|v| !v.is_empty());
        let require_auth = std::env::var("OPERQUAY_REQUIRE_AUTH")
            .or_else(|_| std::env::var("REQUIRE_AUTH"))
            .map_or_else(
                |_| admin_pw.is_some(),
                |v| v == "1" || v.eq_ignore_ascii_case("true"),
            );
        let tenant_keys = Arc::new(TenantKeyManager::new());
        Self {
            settings,
            engines: Arc::new(registry),
            telemetry,
            tickets: Arc::new(TicketStore::new()),
            recordings: {
                #[cfg(not(test))]
                {
                    let dir_env = std::env::var("OPERQUAY_RECORDINGS_DIR").unwrap_or_default();
                    let trimmed = dir_env.trim();
                    if trimmed.is_empty() {
                        Arc::new(
                            RecordingCatalog::new()
                                .with_shared_tenant_keys(Arc::clone(&tenant_keys)),
                        )
                    } else {
                        match RecordingCatalog::with_dir(PathBuf::from(trimmed)) {
                            Ok(cat) => {
                                Arc::new(cat.with_shared_tenant_keys(Arc::clone(&tenant_keys)))
                            }
                            Err(err) => {
                                eprintln!(
                                    "Warning: failed to initialize OPERQUAY_RECORDINGS_DIR={trimmed}: {err}; using in-memory catalog"
                                );
                                Arc::new(
                                    RecordingCatalog::new()
                                        .with_shared_tenant_keys(Arc::clone(&tenant_keys)),
                                )
                            }
                        }
                    }
                }
                #[cfg(test)]
                {
                    Arc::new(
                        RecordingCatalog::new().with_shared_tenant_keys(Arc::clone(&tenant_keys)),
                    )
                }
            },
            audit: Arc::new(AuditLogStore::new()),
            cert_pins: Arc::new(CertPinStore::new()),
            auth: Arc::new(AuthService::new(require_auth, admin_pw)),
            aws: Arc::new(aws_routes::AwsHubState::default()),
            platform: Arc::new(platform_routes::PlatformState::default()),
            static_dir,
            pg_pool: Arc::new(tokio::sync::RwLock::new(None)),
            trusted_proxies: Arc::new(TrustedProxies::from_env()),
            allowed_origins: Arc::new(parse_allowed_origins_env()),
            session_fence: Arc::new(session_fence::ActiveSessionFence::new()),
            tenant_keys,
            governance: Arc::new(jit::GovernanceStore::new()),
            moderation: Arc::new(moderation::SessionModerationHub::new()),
            mcp: Arc::new(mcp::McpRegistry::new()),
            agent_hub: Arc::new(agent_hub::AgentHub::new()),
            multicloud: Arc::new(multicloud::MultiCloudStore::new()),
            device_trust: Arc::new(device_trust::DeviceTrustStore::new()),
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    let api = Router::new()
        .route("/api/v1/healthz", get(healthz))
        .route("/api/v1/protocols", get(list_protocols))
        .route(
            "/api/v1/settings/remote-desktop",
            get(get_remote_desktop_settings).put(put_remote_desktop_settings),
        )
        .route(
            "/api/v1/settings/remote-desktop/reset",
            post(reset_remote_desktop_settings),
        )
        .route(
            "/api/v1/settings/remote-desktop/preview",
            post(preview_network_simulation),
        )
        .route("/api/v1/sessions/launch", post(launch_session_ticket))
        .route("/api/v1/recordings", get(list_recordings))
        .route("/api/v1/recordings/purge", post(purge_expired_recordings))
        .route("/api/v1/recordings/{id}/guac", get(download_recording_guac))
        .route(
            "/api/v1/recordings/{id}/export-mp4",
            get(export_recording_mp4),
        )
        .route(
            "/api/v1/recordings/{id}/legal-hold",
            put(update_recording_legal_hold),
        )
        .route(
            "/api/v1/recordings/{id}/archive",
            post(archive_recording_worm),
        )
        .route("/api/v1/audit", get(list_audit_events))
        .route("/api/v1/audit/verify", get(verify_audit_chain))
        .route("/api/v1/audit/siem/status", get(get_audit_siem_status))
        .route(
            "/api/v1/tenants/{id}/crypto-shred",
            post(crypto_shred_tenant),
        )
        .route("/api/v1/telemetry/summary", get(telemetry_summary))
        .route("/api/v1/ws/rdp", get(ws::ws_desktop_handler))
        .route("/metrics", get(metrics_prometheus))
        .merge(auth_routes::auth_router())
        .merge(aws_routes::aws_router())
        .merge(platform_routes::platform_router())
        .merge(governance_routes::governance_router())
        .merge(m12_routes::m12_router());

    let static_fallback = if let Some(dir) = &state.static_dir {
        let index_file = dir.join("index.html");
        Router::new().fallback_service(ServeDir::new(dir).fallback(ServeFile::new(index_file)))
    } else {
        Router::new().fallback(get(serve_embedded_frontend))
    };

    let state_for_mw = state.clone();
    api.merge(static_fallback)
        .layer(middleware::from_fn(move |req, next| {
            otel_trace_middleware(state_for_mw.clone(), req, next)
        }))
        .with_state(state)
}

fn is_pw_rotation_exempt(path: &str) -> bool {
    matches!(
        path,
        "/api/v1/healthz"
            | "/api/auth/me"
            | "/api/auth/config"
            | "/api/auth/logout"
            | "/api/auth/password"
            | "/api/auth/admin-password"
            | "/api/auth/login"
            | "/api/auth/login/mfa"
            | "/api/clouds/gcp/sso/callback"
    ) || path.starts_with("/api/auth/mfa/")
}

fn csrf_origin_allowed(
    headers: &HeaderMap,
    is_https: bool,
    allowed_origins: &[String],
) -> Result<(), &'static str> {
    let sec_fetch = headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    let origin_hdr = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    let referer_hdr = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim);

    let matches_expected = |candidate: &str| -> bool {
        if allowed_origins.iter().any(|o| o == candidate) {
            return true;
        }
        if let Some(pub_orig) = public_url_origin() {
            if candidate == pub_orig {
                return true;
            }
        }
        if let Some(host) = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|h| !h.is_empty())
        {
            let scheme = if is_https { "https" } else { "http" };
            let expected = format!("{scheme}://{}", host.to_ascii_lowercase());
            if candidate == expected {
                return true;
            }
        }
        false
    };

    if let Some(orig_raw) = origin_hdr {
        let Some(norm) = normalize_origin(orig_raw) else {
            return Err("cross-site request rejected by CSRF protection");
        };
        if !matches_expected(&norm) {
            return Err("cross-site request rejected by CSRF protection");
        }
        if sec_fetch.is_some_and(|s| s.eq_ignore_ascii_case("cross-site"))
            && !allowed_origins.iter().any(|o| o == &norm)
        {
            return Err("cross-site request rejected by CSRF protection");
        }
        return Ok(());
    }

    if sec_fetch.is_some_and(|s| s.eq_ignore_ascii_case("cross-site")) {
        return Err("cross-site request rejected by CSRF protection");
    }
    if let Some(ref_raw) = referer_hdr {
        let Some(norm) = normalize_origin(ref_raw) else {
            return Err("cross-site request rejected by CSRF protection");
        };
        if !matches_expected(&norm) {
            return Err("cross-site request rejected by CSRF protection");
        }
    }
    Ok(())
}

fn apply_security_headers(
    headers: &mut HeaderMap,
    path: &str,
    is_https: bool,
    matched_cors_origin: Option<&str>,
) {
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("SAMEORIGIN"),
    );
    headers.insert(
        header::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' ws: wss:; worker-src 'self' blob:; frame-ancestors 'self'; base-uri 'self'; form-action 'self'; object-src 'none'",
        ),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    if is_https {
        headers.insert(
            header::HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    if (path.starts_with("/api/") || path.starts_with("/ws/") || path.starts_with("/scim/"))
        && !headers.contains_key(header::CACHE_CONTROL)
    {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    if let Some(orig) = matched_cors_origin {
        if let Ok(hv) = HeaderValue::from_str(orig) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, hv);
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
    }
}

async fn otel_trace_middleware(state: AppState, mut req: Request, next: Next) -> Response {
    let method_val = req.method().clone();
    let method = method_val.as_str().to_owned();
    let path = req.uri().path().to_owned();

    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let trusted = state.trusted_proxies.contains_peer(peer);
    let listener_https = req
        .extensions()
        .get::<ListenerScheme>()
        .is_some_and(|s| s.0);
    let is_https = listener_https
        || (trusted
            && req
                .headers()
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("https")));
    let client_ip = resolve_client_ip(peer, req.headers(), &state.trusted_proxies);
    let tenant_id = extract_tenant_id_checked(peer, req.headers(), &state.trusted_proxies);

    if !trusted {
        let h = req.headers_mut();
        h.remove("x-operquay-tenant");
        h.remove("x-forwarded-for");
        h.remove("x-forwarded-host");
        h.remove("x-forwarded-proto");
        h.remove("x-real-ip");
    }

    req.extensions_mut().insert(ResolvedRequestContext {
        client_ip: client_ip.clone(),
        tenant_id: tenant_id.clone(),
        is_https,
    });

    let matched_cors_origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .and_then(normalize_origin)
        .filter(|orig| state.allowed_origins.iter().any(|a| a == orig));

    if method_val == Method::OPTIONS {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        resp.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE, OPTIONS"),
        );
        resp.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, Authorization"),
        );
        resp.headers_mut().insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("600"),
        );
        apply_security_headers(
            resp.headers_mut(),
            &path,
            is_https,
            matched_cors_origin.as_deref(),
        );
        return resp;
    }

    let req_headers = req.headers().clone();
    let has_session_cookie = req_headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|c| c.contains("operquay_session=") || c.contains("__Host-operquay_session="));
    let is_state_changing = matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
    let is_ws_upgrade = req_headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|u| u.eq_ignore_ascii_case("websocket"));
    let csrf_exempt = path.starts_with("/api/auth/saml/")
        || path.starts_with("/scim/v2/")
        || path.starts_with("/api/access-requests/webhooks/")
        || path == "/api/mcp/rpc"
        || path == "/api/agents/tunnel";

    let should_audit = (is_state_changing
        || path.starts_with("/api/k8s/")
        || path.starts_with("/api/aws/")
        || path.starts_with("/recordings"))
        && !matches!(
            path.as_str(),
            "/api/auth/login" | "/api/license" | "/health" | "/metrics" | "/audit-log"
        )
        && !path.starts_with("/assets/");
    let claims = if should_audit || (has_session_cookie && path.starts_with("/api/")) {
        state.auth.verify_cookie(&req_headers).await
    } else {
        None
    };

    let start = Instant::now();
    let span = tracing::info_span!(
        "operquay.http.request",
        http.method = %method,
        http.route = %path
    );
    async move {
        let mut response = if has_session_cookie
            && (is_state_changing || is_ws_upgrade)
            && !csrf_exempt
            && csrf_origin_allowed(&req_headers, is_https, &state.allowed_origins).is_err()
        {
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "cross-site request rejected by CSRF protection"
                })),
            )
                .into_response()
        } else if path.starts_with("/api/") && !is_pw_rotation_exempt(&path) {
            if let Some(ref c) = claims {
                if state.auth.user_must_change_password(&c.user_id).await {
                    (
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({
                            "error": "password rotation required before accessing this endpoint",
                            "code": "must_change_password"
                        })),
                    )
                        .into_response()
                } else {
                    next.run(req).await
                }
            } else {
                next.run(req).await
            }
        } else {
            next.run(req).await
        };

        let trace_id = TelemetryHub::current_trace_id_hex();
        if let Ok(val) = HeaderValue::from_str(&trace_id) {
            response.headers_mut().insert("x-trace-id", val);
        }
        apply_security_headers(
            response.headers_mut(),
            &path,
            is_https,
            matched_cors_origin.as_deref(),
        );
        let status_u16 = response.status().as_u16();
        if should_audit {
            let tenant = tenant_id;
            let outcome = if status_u16 == 401 || status_u16 == 403 {
                "denied"
            } else if status_u16 >= 400 {
                "error"
            } else {
                "success"
            };
            let action = if status_u16 == 401 || status_u16 == 403 {
                "access_denied"
            } else if path.starts_with("/api/k8s/") {
                if method == "GET" {
                    "kubernetes_read"
                } else {
                    "kubernetes_write"
                }
            } else if path.contains("login") {
                "login_password"
            } else if path.contains("logout") {
                "logout"
            } else if path.contains("upload") {
                "upload"
            } else if path.contains("download") {
                "download"
            } else if path.contains("forward") {
                if path.contains("stop") {
                    "port_forward_stop"
                } else {
                    "port_forward_start"
                }
            } else if path.contains("clone") {
                "clone"
            } else {
                "request"
            };
            let ua = auth_routes::user_agent_from_headers(&req_headers);
            let ip = client_ip;
            let (uid, email, role, sid) = if let Some(ref c) = claims {
                (
                    c.user_id.clone(),
                    c.email.clone(),
                    c.role.clone(),
                    c.session_id.clone(),
                )
            } else {
                (String::new(), String::new(), String::new(), String::new())
            };
            state
                .audit
                .record_full(stores::AuditRecordInput {
                    tenant_id: tenant,
                    trace_id: trace_id.clone(),
                    session_id: sid,
                    action: action.to_owned(),
                    protocol: "http".to_owned(),
                    target_host: path.clone(),
                    detail: format!("{method} {path} {status_u16}"),
                    user_id: uid,
                    user_email: email,
                    role,
                    ip,
                    outcome: outcome.to_owned(),
                    method: method.clone(),
                    status_code: status_u16,
                    user_agent: ua.clone(),
                    client: ua,
                    ..stores::AuditRecordInput::default()
                })
                .await;
        }
        tracing::info!(
            status = status_u16,
            elapsed_ms = start.elapsed().as_secs_f64() * 1000.0,
            trace_id = %trace_id,
            "http request completed"
        );
        response
    }
    .instrument(span)
    .await
}

fn tenant_id_from_headers(headers: &HeaderMap) -> String {
    extract_tenant_id_checked(None, headers, &TrustedProxies::default())
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    clean_room_rdp: bool,
    ironrdp_present: bool,
    version: &'static str,
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "operquay-rust",
        clean_room_rdp: false,
        ironrdp_present: true,
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Serialize)]
struct ProtocolsResponse {
    capabilities: Vec<EngineCapability>,
    keyboard_layouts: &'static [KeyboardLayoutDescriptor],
}

async fn list_protocols(State(state): State<AppState>) -> Json<ProtocolsResponse> {
    Json(ProtocolsResponse {
        capabilities: state.engines.capabilities(),
        keyboard_layouts: KEYBOARD_LAYOUTS,
    })
}

#[derive(Serialize)]
struct SettingsResponse {
    tenant_id: String,
    settings: RemoteDesktopSettings,
    trace_id: String,
    simulations: Vec<NetworkSimulationResult>,
}

fn canonical_simulations(s: &RemoteDesktopSettings) -> Vec<NetworkSimulationResult> {
    [
        NetworkSimulationCondition {
            rtt_ms: 15,
            packet_loss_pct: 0.0,
        },
        NetworkSimulationCondition {
            rtt_ms: 120,
            packet_loss_pct: 0.2,
        },
        NetworkSimulationCondition {
            rtt_ms: 280,
            packet_loss_pct: 2.0,
        },
    ]
    .into_iter()
    .map(|c| s.simulate_network(c))
    .collect()
}

async fn get_remote_desktop_settings(
    State(state): State<AppState>,
    ctx: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
) -> Result<Json<SettingsResponse>, (StatusCode, String)> {
    let tenant = ctx.map_or_else(|| tenant_id_from_headers(&headers), |c| c.0.tenant_id);
    let settings = state
        .settings
        .get(&tenant)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let simulations = canonical_simulations(&settings);
    Ok(Json(SettingsResponse {
        tenant_id: tenant,
        settings,
        trace_id: TelemetryHub::current_trace_id_hex(),
        simulations,
    }))
}

async fn put_remote_desktop_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RemoteDesktopSettings>,
) -> Response {
    let (tenant, _) = match auth_routes::require_any_perm(
        &state,
        &headers,
        &[operquay_auth::policy::perm::SESSION_RDP],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let saved = match state.settings.put(&tenant, payload).await {
        Ok(s) => s,
        Err(err) => {
            let code = match err {
                operquay_core::SettingsStoreError::Validation(_) => {
                    StatusCode::UNPROCESSABLE_ENTITY
                }
                operquay_core::SettingsStoreError::Backend(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return (code, Json(serde_json::json!({ "error": err.to_string() }))).into_response();
        }
    };

    state
        .telemetry
        .record_settings_update(saved.network_preset.as_str());
    tracing::info!(
        tenant_id = %tenant,
        preset = saved.network_preset.as_str(),
        transport = ?saved.transport_mode,
        "remote desktop settings updated"
    );

    let simulations = canonical_simulations(&saved);
    Json(SettingsResponse {
        tenant_id: tenant,
        settings: saved,
        trace_id: TelemetryHub::current_trace_id_hex(),
        simulations,
    })
    .into_response()
}

async fn reset_remote_desktop_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let (tenant, _) = match auth_routes::require_any_perm(
        &state,
        &headers,
        &[operquay_auth::policy::perm::SESSION_RDP],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let defaults = match state.settings.reset(&tenant).await {
        Ok(d) => d,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    state
        .telemetry
        .record_settings_update(defaults.network_preset.as_str());
    let simulations = canonical_simulations(&defaults);
    Json(SettingsResponse {
        tenant_id: tenant,
        settings: defaults,
        trace_id: TelemetryHub::current_trace_id_hex(),
        simulations,
    })
    .into_response()
}

#[derive(Deserialize)]
struct PreviewRequest {
    settings: RemoteDesktopSettings,
    conditions: Option<Vec<NetworkSimulationCondition>>,
}

#[derive(Serialize)]
struct PreviewResponse {
    simulations: Vec<NetworkSimulationResult>,
    trace_id: String,
}

async fn preview_network_simulation(
    Json(req): Json<PreviewRequest>,
) -> Result<Json<PreviewResponse>, (StatusCode, Json<serde_json::Value>)> {
    req.settings.validate().map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
    })?;
    let simulations = match req.conditions {
        Some(list) if !list.is_empty() => list
            .into_iter()
            .map(|c| req.settings.simulate_network(c))
            .collect(),
        _ => canonical_simulations(&req.settings),
    };
    Ok(Json(PreviewResponse {
        simulations,
        trace_id: TelemetryHub::current_trace_id_hex(),
    }))
}

#[derive(Serialize)]
struct TelemetrySummaryEnvelope {
    summary: TelemetrySummary,
    trace_id: String,
}

async fn telemetry_summary(State(state): State<AppState>) -> Json<TelemetrySummaryEnvelope> {
    Json(TelemetrySummaryEnvelope {
        summary: state.telemetry.summary(),
        trace_id: TelemetryHub::current_trace_id_hex(),
    })
}

async fn metrics_prometheus(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.telemetry.render_prometheus(),
    )
}

#[derive(Deserialize)]
struct LaunchSessionRequest {
    protocol: String,
    #[serde(default)]
    launch_mode: LaunchMode,
    target_host: Option<String>,
    target_port: Option<u16>,
    username: Option<String>,
    #[serde(default)]
    password: String,
    width: Option<u32>,
    height: Option<u32>,
    keyboard_layout: Option<String>,
    transport_mode: Option<String>,
    expected_cert_sha256_hex: Option<String>,
    #[serde(default)]
    simulate_recording_fault: bool,
    aws_profile: Option<String>,
    aws_region: Option<String>,
}

#[derive(Serialize)]
struct LaunchSessionResponse {
    ticket: String,
    session_id: String,
    ws_url: String,
    protocol: String,
    launch_mode: LaunchMode,
    expires_in_secs: u64,
    trace_id: String,
}

fn parse_sha256_hex(raw: &str) -> Result<[u8; 32], (StatusCode, Json<serde_json::Value>)> {
    let cleaned: String = raw
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect();
    if cleaned.len() != 64 {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "expected_cert_sha256_hex must be 64 hex chars" })),
        ));
    }
    let mut out = [0u8; 32];
    for (idx, chunk) in cleaned.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let s = std::str::from_utf8(chunk).unwrap_or("00");
        out[idx] = u8::from_str_radix(s, 16).map_err(|_| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(
                    serde_json::json!({ "error": "invalid hex byte in expected_cert_sha256_hex" }),
                ),
            )
        })?;
    }
    Ok(out)
}

async fn launch_session_ticket(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LaunchSessionRequest>,
) -> Response {
    let (tenant, claims) = match auth_routes::require_any_perm(
        &state,
        &headers,
        &[operquay_auth::policy::perm::SESSION_RDP],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if let Err(reasons) = state
        .device_trust
        .check_desktop_launch(&tenant, &claims.user_id)
        .await
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": format!("Device posture policy check failed: {}", reasons.join("; ")),
                "device_trust_required": true,
                "reasons": reasons,
            })),
        )
            .into_response();
    }
    let proto = req.protocol.trim().to_ascii_lowercase();
    if proto != "rdp" && proto != "vnc" {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": format!("unsupported protocol '{proto}'") })),
        )
            .into_response();
    }
    #[cfg(not(test))]
    if req.launch_mode == LaunchMode::Demo {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "mock desktop sessions are disabled; connect a real direct_tcp host or ssm_tunnel instance" })),
        )
            .into_response();
    }
    let session_id = Uuid::new_v4().to_string();
    let target_host = req
        .target_host
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(match req.launch_mode {
            LaunchMode::SsmTunnel => "ssm-loopback",
            _ => "win2025-demo.internal",
        })
        .to_owned();
    let default_port = if proto == "vnc" { 5900 } else { 3389 };
    let target_port = req.target_port.unwrap_or(default_port);

    if req.launch_mode == LaunchMode::DirectTcp && (target_host.is_empty() || target_port == 0) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                serde_json::json!({ "error": "direct_tcp requires valid target_host and target_port" }),
            ),
        )
            .into_response();
    }

    let expected_cert_sha256 = match &req.expected_cert_sha256_hex {
        Some(hex) if !hex.trim().is_empty() => match parse_sha256_hex(hex.trim()) {
            Ok(v) => Some(v),
            Err(e) => return e.into_response(),
        },
        _ => None,
    };

    let username = req
        .username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("operator")
        .to_owned();

    let payload = TicketLaunchPayload {
        session_id: session_id.clone(),
        tenant_id: tenant.clone(),
        user_id: claims.user_id,
        auth_session_id: claims.session_id,
        protocol: proto.clone(),
        launch_mode: req.launch_mode,
        target_host: target_host.clone(),
        target_port,
        username,
        password: SecretString::new(req.password),
        width: req.width.unwrap_or(1280).clamp(200, 4096),
        height: req.height.unwrap_or(720).clamp(200, 4096),
        keyboard_layout: req.keyboard_layout,
        transport_mode: req.transport_mode,
        expected_cert_sha256,
        simulate_recording_fault: req.simulate_recording_fault,
        aws_profile: req.aws_profile,
        aws_region: req.aws_region,
        rdp_security_mode: None,
    };

    let ticket_id = state.tickets.issue(payload, TICKET_TTL).await;
    let trace_id = TelemetryHub::current_trace_id_hex();
    state
        .audit
        .record(
            &tenant,
            &trace_id,
            &session_id,
            "session_ticket_issued",
            &proto,
            &target_host,
            format!("mode={:?} port={target_port} ttl=60s", req.launch_mode),
            Some(session_id.clone()),
        )
        .await;

    Json(LaunchSessionResponse {
        ticket: ticket_id.to_string(),
        session_id,
        ws_url: format!("/api/v1/ws/rdp?ticket={ticket_id}"),
        protocol: proto,
        launch_mode: req.launch_mode,
        expires_in_secs: TICKET_TTL.as_secs(),
        trace_id,
    })
    .into_response()
}

#[derive(Serialize)]
struct RecordingsListResponse {
    tenant_id: String,
    recordings: Vec<RecordingEntry>,
    trace_id: String,
}

async fn list_recordings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match auth_routes::require_any_perm(
        &state,
        &headers,
        &[operquay_auth::policy::perm::RECORDINGS_READ],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let recordings = state.recordings.list(&tenant).await;
    Json(RecordingsListResponse {
        tenant_id: tenant,
        recordings,
        trace_id: TelemetryHub::current_trace_id_hex(),
    })
    .into_response()
}

async fn download_recording_guac(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let bytes = state
        .recordings
        .get_guac_bytes(&id)
        .await
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"operquay-{id}.guac\""),
            ),
        ],
        bytes,
    ))
}

async fn export_recording_mp4(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let guac = state
        .recordings
        .get_guac_bytes(&id)
        .await
        .ok_or(StatusCode::NOT_FOUND)?;
    let mp4 = build_iso_bmff_mp4(&guac, 1280, 720);
    Ok((
        [
            (header::CONTENT_TYPE, "video/mp4".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"operquay-{id}.mp4\""),
            ),
        ],
        mp4,
    ))
}

#[derive(Serialize)]
struct AuditListResponse {
    tenant_id: String,
    events: Vec<AuditEvent>,
    trace_id: String,
}

async fn list_audit_events(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match auth_routes::require_any_perm(
        &state,
        &headers,
        &[operquay_auth::policy::perm::AUDIT_READ],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let events = state.audit.list(&tenant).await;
    Json(AuditListResponse {
        tenant_id: tenant,
        events,
        trace_id: TelemetryHub::current_trace_id_hex(),
    })
    .into_response()
}

async fn verify_audit_chain(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match auth_routes::require_any_perm(
        &state,
        &headers,
        &[operquay_auth::policy::perm::AUDIT_READ],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let report = state.audit.verify_chain(&tenant).await;
    Json(report).into_response()
}

async fn get_audit_siem_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) =
        auth_routes::require_any_perm(&state, &headers, &[operquay_auth::policy::perm::AUDIT_READ])
            .await
    {
        return *r;
    }
    Json(state.audit.siem_stats().await).into_response()
}

#[derive(Deserialize)]
struct LegalHoldBody {
    hold: bool,
    #[serde(default)]
    reason: String,
}

async fn update_recording_legal_hold(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<LegalHoldBody>,
) -> Response {
    let (tenant, claims) = match auth_routes::require_any_perm(
        &state,
        &headers,
        &[operquay_auth::policy::perm::RECORDING_POLICY_MANAGE],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .recordings
        .set_legal_hold(&tenant, &id, body.hold, &body.reason)
        .await
    {
        Ok(updated) => {
            state.persist_recording_metadata(&updated).await;
            state
                .audit
                .record_full(crate::stores::AuditRecordInput {
                    tenant_id: tenant,
                    trace_id: TelemetryHub::current_trace_id_hex(),
                    session_id: updated.id.clone(),
                    action: "recording_legal_hold_updated".to_owned(),
                    protocol: "control-plane".to_owned(),
                    target_host: updated.target_host.clone(),
                    detail: format!(
                        "legal_hold={} reason={}",
                        updated.legal_hold, updated.legal_hold_reason
                    ),
                    user_id: claims.user_id,
                    user_email: claims.email,
                    role: claims.role,
                    outcome: "success".to_owned(),
                    recording_id: Some(updated.id.clone()),
                    ..crate::stores::AuditRecordInput::default()
                })
                .await;
            Json(updated).into_response()
        }
        Err(msg) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response(),
    }
}

async fn archive_recording_worm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, claims) = match auth_routes::require_any_perm(
        &state,
        &headers,
        &[operquay_auth::policy::perm::RECORDING_POLICY_MANAGE],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(archiver) = operquay_recording::worm::S3WormArchiver::from_env() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "S3 Object Lock WORM archival is not configured (OPERQUAY_WORM_S3_BUCKET + AWS credentials required)"
            })),
        )
            .into_response();
    };
    let Some(entry) = state
        .recordings
        .get_entry(&id)
        .await
        .filter(|e| e.tenant_id == tenant)
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "recording not found" })),
        )
            .into_response();
    };
    let Some(enc_bytes) = state.recordings.get_encrypted_bytes(&entry.id).await else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "encrypted recording payload not found" })),
        )
            .into_response();
    };
    let ext = if entry.format == "cast" {
        "cast"
    } else {
        "guac"
    };
    match archiver
        .archive_object(&tenant, &entry.id, ext, &enc_bytes, entry.legal_hold)
        .await
    {
        Ok(res) => {
            if let Some(updated) = state
                .recordings
                .mark_archived(
                    &tenant,
                    &entry.id,
                    res.s3_uri.clone(),
                    res.retain_until_ms,
                    res.archived_at_ms,
                )
                .await
            {
                state.persist_recording_metadata(&updated).await;
            }
            state
                .audit
                .record_full(crate::stores::AuditRecordInput {
                    tenant_id: tenant,
                    trace_id: TelemetryHub::current_trace_id_hex(),
                    session_id: entry.id.clone(),
                    action: "recording_worm_archived".to_owned(),
                    protocol: "control-plane".to_owned(),
                    target_host: entry.target_host,
                    detail: format!("archived_s3_uri={} mode={}", res.s3_uri, res.mode),
                    user_id: claims.user_id,
                    user_email: claims.email,
                    role: claims.role,
                    outcome: "success".to_owned(),
                    recording_id: Some(entry.id),
                    ..crate::stores::AuditRecordInput::default()
                })
                .await;
            Json(serde_json::json!({
                "s3_uri": res.s3_uri,
                "retain_until_ms": res.retain_until_ms,
                "archived_at_ms": res.archived_at_ms,
                "mode": res.mode,
            }))
            .into_response()
        }
        Err(msg) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response(),
    }
}

async fn purge_expired_recordings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, claims) = match auth_routes::require_any_perm(
        &state,
        &headers,
        &[operquay_auth::policy::perm::RECORDING_POLICY_MANAGE],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let retention_days = state
        .platform
        .rec_policies
        .read()
        .await
        .get(&tenant)
        .map_or(90, |p| p.retention_days);
    let report = state
        .recordings
        .purge_expired(&tenant, retention_days, operquay_recording::now_unix_ms())
        .await;
    if let Some(pg) = state.pg_pool().await {
        for pid in &report.purged_ids {
            let _ = pg.delete_recording_metadata(&tenant, pid).await;
        }
    }
    state
        .audit
        .record_full(crate::stores::AuditRecordInput {
            tenant_id: tenant,
            trace_id: TelemetryHub::current_trace_id_hex(),
            action: "recording_retention_purge".to_owned(),
            protocol: "control-plane".to_owned(),
            detail: format!(
                "checked={} purged={} skipped_legal_hold={}",
                report.checked,
                report.purged_ids.len(),
                report.skipped_legal_hold
            ),
            user_id: claims.user_id,
            user_email: claims.email,
            role: claims.role,
            outcome: "success".to_owned(),
            ..crate::stores::AuditRecordInput::default()
        })
        .await;
    Json(report).into_response()
}

#[derive(Deserialize, Default)]
struct CryptoShredBody {
    #[serde(default)]
    confirm: bool,
}

async fn crypto_shred_tenant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<CryptoShredBody>>,
) -> Response {
    let (caller_tenant, claims) =
        match auth_routes::require_any_perm(&state, &headers, &[operquay_auth::policy::perm::ALL])
            .await
        {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let target_tenant = id.trim();
    if target_tenant.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "tenant id is required" })),
        )
            .into_response();
    }
    if caller_tenant != "default" && target_tenant != caller_tenant {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "cannot crypto-shred a different tenant" })),
        )
            .into_response();
    }
    let confirmed = body.is_some_and(|b| b.0.confirm);
    if !confirmed {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "confirmation flag confirm=true is required" })),
        )
            .into_response();
    }

    let terminated = state
        .session_fence
        .terminate_tenant(target_tenant, "tenant_crypto_shredded");
    if let Some(pg) = state.pg_pool().await {
        if let Err(err) = pg.shred_tenant_dek(target_tenant).await {
            tracing::warn!(tenant = %target_tenant, error = %err, "failed persisting tenant DEK shred tombstone");
        }
    }
    let _ = state.tenant_keys.shred_tenant(target_tenant).await;
    state.recordings.evict_tenant_cache(target_tenant).await;
    state
        .audit
        .record_full(crate::stores::AuditRecordInput {
            tenant_id: caller_tenant,
            trace_id: TelemetryHub::current_trace_id_hex(),
            action: "tenant_crypto_shredded".to_owned(),
            protocol: "control-plane".to_owned(),
            target_host: target_tenant.to_owned(),
            detail: format!(
                "shredded tenant DEK for {target_tenant}; terminated_sessions={terminated}"
            ),
            user_id: claims.user_id,
            user_email: claims.email,
            role: claims.role,
            outcome: "success".to_owned(),
            ..crate::stores::AuditRecordInput::default()
        })
        .await;
    Json(serde_json::json!({
        "tenant_id": target_tenant,
        "shredded": true,
        "terminated_sessions": terminated,
    }))
    .into_response()
}

/// Wait for a graceful shutdown trigger, fence all active sessions immediately, and drain until
/// `active_count == 0` or `drain_timeout` elapses (`M10.5`).
pub async fn wait_for_shutdown_and_drain(
    fence: Arc<session_fence::ActiveSessionFence>,
    mut trigger: tokio::sync::watch::Receiver<bool>,
    drain_timeout: std::time::Duration,
) {
    while !*trigger.borrow() {
        if trigger.changed().await.is_err() {
            break;
        }
    }
    let terminated = fence.terminate_all("server_shutdown");
    let start = Instant::now();
    while fence.active_count() > 0 && start.elapsed() < drain_timeout {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    tracing::info!(
        terminated_sessions = terminated,
        remaining_sessions = fence.active_count(),
        "graceful shutdown session drain finished"
    );
}

async fn serve_embedded_frontend(uri: Uri) -> impl IntoResponse {
    let raw = uri.path().trim_start_matches('/');
    let rel = if raw.is_empty() { "index.html" } else { raw };
    if let Some(asset) = EmbeddedFrontend::get(rel) {
        let mime = mime_guess::from_path(rel).first_or_octet_stream();
        return (
            [(header::CONTENT_TYPE, mime.as_ref().to_owned())],
            asset.data.into_owned(),
        )
            .into_response();
    }
    if let Some(index) = EmbeddedFrontend::get("index.html") {
        return Html(String::from_utf8_lossy(&index.data).into_owned()).into_response();
    }
    Html(
        "<!doctype html><html><head><title>Operquay-Rust</title></head><body><h1>Operquay-Rust Control Plane Active</h1><p>Build frontend assets or pass --static-dir frontend/dist.</p></body></html>",
    )
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use futures_util::{SinkExt, StreamExt};
    use http::Request as HttpRequest;
    use operquay_core::InMemorySettingsStore;
    use operquay_display::Oqr2Message;
    use tokio::net::TcpListener;
    use tokio_tungstenite::{connect_async, tungstenite::Message as WsMsg};
    use tower::ServiceExt;

    fn test_state() -> AppState {
        let store = Arc::new(InMemorySettingsStore::new());
        let hub = TelemetryHub::build("operquay-test-srv", None, 1.0, false);
        AppState::with_defaults(store, hub, None)
    }

    #[tokio::test]
    async fn validates_and_persists_settings_and_increments_prometheus_metrics() {
        let app = build_router(test_state());

        let invalid_body = serde_json::json!({
            "network_preset": "custom",
            "protocol_preference": "auto",
            "transport_mode": "oqr2_binary",
            "codec_mode": "adaptive_hybrid",
            "target_fps": 5,
            "jpeg_quality_floor": 55,
            "enable_copy_rect": true,
            "enable_dynamic_resize": true,
            "enable_local_cursor_prediction": true,
            "enable_mouse_coalescing": true,
            "keyboard_layout": "en-us-qwerty",
            "unicode_fallback": true,
            "rdp_security_mode": "any",
            "vnc_security_mode": "auto",
            "cert_policy": "tofu_pinned",
            "clipboard_normalization": "preserve",
            "fail_closed_recording": true,
            "enable_drive_redirection": false,
            "otel_sample_ratio": 1.0,
            "show_live_telemetry_hud": true
        });
        let resp_err = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("PUT")
                    .uri("/api/v1/settings/remote-desktop")
                    .header("content-type", "application/json")
                    .body(Body::from(invalid_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_err.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let mut valid = RemoteDesktopSettings::default();
        valid.apply_preset(operquay_core::NetworkPreset::UltraLowLatency);
        valid.keyboard_layout = "de-de-qwertz".into();

        let resp_ok = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("PUT")
                    .uri("/api/v1/settings/remote-desktop")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&valid).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_ok.status(), StatusCode::OK);
        assert!(resp_ok.headers().contains_key("x-trace-id"));

        let metrics_resp = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let metrics_bytes = axum::body::to_bytes(metrics_resp.into_body(), 1_000_000)
            .await
            .unwrap();
        let metrics_text = String::from_utf8(metrics_bytes.to_vec()).unwrap();
        assert!(metrics_text.contains("operquay_settings_updates"));
    }

    #[tokio::test]
    async fn live_websocket_streams_oqr2_frames_and_cleans_up_session_metrics() {
        let state = test_state();
        let telemetry = state.telemetry.clone();
        let app = build_router(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("ws://{addr}/api/v1/ws/rdp?protocol=rdp&mode=oqr2&width=800&height=600");
        let (mut ws, _) = connect_async(url).await.unwrap();

        // Expect HelloAck binary OQR2 message first
        let first = ws.next().await.unwrap().unwrap();
        let WsMsg::Binary(bytes) = first else {
            panic!("expected binary OQR2 message");
        };
        let (_, msg) = Oqr2Message::decode(&bytes).unwrap();
        assert!(matches!(
            msg,
            Oqr2Message::HelloAck {
                width: 800,
                height: 600,
                ..
            }
        ));

        // Drain initial SolidFill / TilePng / StatsSync messages until StatsSync arrives
        let mut saw_tile = false;
        for _ in 0..256 {
            let next = tokio::time::timeout(std::time::Duration::from_secs(3), ws.next())
                .await
                .expect("timed out waiting for initial OQR2 frame")
                .unwrap()
                .unwrap();
            if let WsMsg::Binary(b) = next {
                let (_, m) = Oqr2Message::decode(&b).unwrap();
                match m {
                    Oqr2Message::SolidFill { .. }
                    | Oqr2Message::TilePng { .. }
                    | Oqr2Message::TileJpeg { .. } => {
                        saw_tile = true;
                    }
                    Oqr2Message::StatsSync { .. } => break,
                    _ => {}
                }
            }
        }
        assert!(saw_tile);
        assert_eq!(telemetry.summary().active_sessions, 1);

        // Send dynamic resize (odd width 1025 should snap to 1024 in RDP!)
        ws.send(WsMsg::Text(
            serde_json::json!({ "type": "resize", "width": 1025, "height": 700 })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();

        let mut saw_resized = false;
        for _ in 0..256 {
            let next = tokio::time::timeout(std::time::Duration::from_secs(3), ws.next())
                .await
                .expect("timed out waiting for ResizeSurface")
                .unwrap()
                .unwrap();
            if let WsMsg::Binary(b) = next {
                if let Ok((_, Oqr2Message::ResizeSurface { w, h, .. })) = Oqr2Message::decode(&b) {
                    assert_eq!((w, h), (1024, 700));
                    saw_resized = true;
                    break;
                }
            }
        }
        assert!(saw_resized);

        ws.close(None).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(telemetry.summary().active_sessions, 0);
        assert_eq!(telemetry.summary().sessions_started_total, 1);
    }

    #[tokio::test]
    async fn enforces_single_use_tickets_rejects_replay_and_exports_guac_and_mp4() {
        let state = test_state();
        state.platform.rec_policies.write().await.insert(
            "default".to_owned(),
            operquay_recording::RecordingPolicy {
                mode: "all".to_owned(),
                ..operquay_recording::RecordingPolicy::default()
            },
        );
        let app = build_router(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = test_client_router_or_tcp_post(
            addr,
            serde_json::json!({
                "protocol": "rdp",
                "launch_mode": "demo",
                "target_host": "win-prod-01.internal",
                "username": "alice",
                "password": "TopSecretPassword!99",
                "width": 640,
                "height": 480
            }),
        )
        .await;

        let ticket = client["ticket"].as_str().unwrap().to_owned();
        let session_id = client["session_id"].as_str().unwrap().to_owned();
        let ws_path = client["ws_url"].as_str().unwrap().to_owned();
        assert!(ws_path.contains(&ticket));
        assert!(!ws_path.contains("TopSecretPassword"));

        // First redeem succeeds
        let ws_url = format!("ws://{addr}{ws_path}");
        let (mut ws, _) = connect_async(&ws_url).await.unwrap();
        let mut saw_stats = false;
        for _ in 0..64 {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(3), ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if let WsMsg::Binary(b) = msg {
                if let Ok((_, Oqr2Message::StatsSync { .. })) = Oqr2Message::decode(&b) {
                    saw_stats = true;
                    break;
                }
            }
        }
        assert!(saw_stats);

        // Replay of SAME single-use ticket MUST return HTTP 401 before WS upgrade
        let replay = connect_async(&ws_url).await;
        match replay {
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            }
            other => panic!("expected 401 HTTP rejection on ticket replay, got {other:?}"),
        }

        ws.close(None).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        // Recording catalog has session .guac and exports valid ISO-BMFF MP4 boxes
        let recs_json = http_get_json(addr, "/api/v1/recordings").await;
        let recs = recs_json["recordings"].as_array().unwrap();
        assert!(recs.iter().any(|r| {
            r["id"].as_str() == Some(session_id.as_str())
                && r["status"].as_str() == Some("completed")
                && !r["sha256_hex"].as_str().unwrap().is_empty()
        }));

        let guac_bytes =
            http_get_bytes(addr, &format!("/api/v1/recordings/{session_id}/guac")).await;
        assert!(String::from_utf8_lossy(&guac_bytes).contains("4.size,"));

        let mp4_bytes =
            http_get_bytes(addr, &format!("/api/v1/recordings/{session_id}/export-mp4")).await;
        assert!(mp4_bytes.windows(4).any(|w| w == b"ftyp"));
        assert!(mp4_bytes.windows(4).any(|w| w == b"moov"));
        assert!(mp4_bytes.windows(4).any(|w| w == b"mdat"));

        let audit_json = http_get_json(addr, "/api/v1/audit").await;
        let events = audit_json["events"].as_array().unwrap();
        assert!(events
            .iter()
            .any(|e| e["action"].as_str() == Some("session_ticket_issued")));
        assert!(events
            .iter()
            .any(|e| e["action"].as_str() == Some("session_closed")));
    }

    #[tokio::test]
    async fn aborts_websocket_when_fail_closed_recording_encounters_sink_fault() {
        let state = test_state();
        let app = build_router(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let launched = test_client_router_or_tcp_post(
            addr,
            serde_json::json!({
                "protocol": "rdp",
                "launch_mode": "demo",
                "simulate_recording_fault": true
            }),
        )
        .await;
        let ws_url = format!("ws://{addr}{}", launched["ws_url"].as_str().unwrap());
        let (mut ws, _) = connect_async(&ws_url).await.unwrap();

        let mut saw_recording_abort = false;
        for _ in 0..32 {
            match tokio::time::timeout(std::time::Duration::from_secs(3), ws.next()).await {
                Ok(Some(Ok(WsMsg::Text(txt)))) => {
                    let parsed: serde_json::Value = serde_json::from_str(&txt).unwrap();
                    if parsed["code"].as_str() == Some("recording_required") {
                        saw_recording_abort = true;
                        break;
                    }
                }
                Ok(Some(Ok(_))) => {}
                _ => break,
            }
        }
        assert!(saw_recording_abort);
    }

    #[tokio::test]
    async fn bridges_websocket_ssm_loopback_vnc_end_to_end() {
        let state = test_state();
        let app = build_router(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let launched = test_client_router_or_tcp_post(
            addr,
            serde_json::json!({
                "protocol": "vnc",
                "launch_mode": "ssm_tunnel",
                "target_host": "ssm-loopback",
                "target_port": 0,
                "width": 640,
                "height": 480
            }),
        )
        .await;
        let ws_url = format!("ws://{addr}{}", launched["ws_url"].as_str().unwrap());
        let (mut ws, _) = connect_async(&ws_url).await.unwrap();

        let mut saw_tile = false;
        let mut last_text = String::new();
        for _ in 0..128 {
            let next = tokio::time::timeout(std::time::Duration::from_secs(4), ws.next())
                .await
                .expect("timed out waiting for SSM VNC frame");
            let Some(msg_res) = next else {
                panic!("ws stream ended cleanly before tile; last_text={last_text}");
            };
            match msg_res.unwrap() {
                WsMsg::Binary(b) => {
                    if let Ok((
                        _,
                        Oqr2Message::TilePng { .. }
                        | Oqr2Message::SolidFill { .. }
                        | Oqr2Message::TileJpeg { .. },
                    )) = Oqr2Message::decode(&b)
                    {
                        saw_tile = true;
                        break;
                    }
                }
                WsMsg::Text(t) => {
                    last_text = t.to_string();
                }
                _ => {}
            }
        }
        assert!(saw_tile);
        ws.close(None).await.unwrap();
    }

    #[tokio::test]
    async fn bridges_websocket_live_to_real_tls_mcs_rdp_loopback_target() {
        use operquay_rdp::live_client::{
            accept_ironrdp_tls_handshake_for_test, decode_fastpath_input_events_len_for_test,
            encode_fastpath_solid_bitmap_for_test,
        };
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use sha2::{Digest, Sha256};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::TlsAcceptor;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        let expected_fp: [u8; 32] = Sha256::digest(&cert_der).into();
        let mut fp_hex = String::with_capacity(64);
        for b in expected_fp {
            use std::fmt::Write as _;
            let _ = write!(fp_hex, "{b:02x}");
        }

        let srv_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(srv_cfg));
        let rdp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rdp_addr = rdp_listener.local_addr().unwrap();

        let rdp_srv = tokio::spawn(async move {
            let (sock, _) = rdp_listener.accept().await.unwrap();
            let mut tls = accept_ironrdp_tls_handshake_for_test(sock, acceptor, 800, 600)
                .await
                .unwrap();

            // Send real 32-bpp Fast-Path Bitmap Update
            let fp_pdu = encode_fastpath_solid_bitmap_for_test(8, 2).unwrap();
            tls.write_all(&fp_pdu).await.unwrap();
            tls.flush().await.unwrap();

            // Expect Fast-Path Scancode input ('a' = 0x1E) forwarded from WebSocket browser client!
            let mut fp_in = vec![0u8; 128];
            let got = tls.read(&mut fp_in).await.unwrap();
            assert!(
                decode_fastpath_input_events_len_for_test(&fp_in[..got]).unwrap() >= 1,
                "expected valid FastPathInput PDU"
            );
        });

        let state = test_state();
        let app = build_router(state);
        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(http_listener, app).await.unwrap();
        });

        let launched = test_client_router_or_tcp_post(
            http_addr,
            serde_json::json!({
                "protocol": "rdp",
                "launch_mode": "direct_tcp",
                "target_host": "127.0.0.1",
                "target_port": rdp_addr.port(),
                "username": "CORP\\admin",
                "password": "Password123!",
                "width": 800,
                "height": 600,
                "expected_cert_sha256_hex": fp_hex
            }),
        )
        .await;

        let ws_url = format!("ws://{http_addr}{}", launched["ws_url"].as_str().unwrap());
        let (mut ws, _) = connect_async(&ws_url).await.unwrap();

        let mut saw_live_tile = false;
        for _ in 0..128 {
            let next = tokio::time::timeout(std::time::Duration::from_secs(4), ws.next())
                .await
                .expect("timed out waiting for live RDP tile over WebSocket")
                .unwrap()
                .unwrap();
            if let WsMsg::Binary(b) = next {
                if let Ok((
                    _,
                    Oqr2Message::TilePng { .. }
                    | Oqr2Message::SolidFill { .. }
                    | Oqr2Message::TileJpeg { .. },
                )) = Oqr2Message::decode(&b)
                {
                    saw_live_tile = true;
                    break;
                }
            }
        }
        assert!(saw_live_tile);

        ws.send(WsMsg::Text(
            serde_json::json!({ "type": "key", "keysym": 0x0061, "pressed": true })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();

        rdp_srv.await.unwrap();
        ws.close(None).await.unwrap();
    }

    async fn test_client_router_or_tcp_post(
        addr: std::net::SocketAddr,
        payload: serde_json::Value,
    ) -> serde_json::Value {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let body = payload.to_string();
        let req = format!(
            "POST /api/v1/sessions/launch HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).await.unwrap();
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        serde_json::from_slice(&raw[split + 4..]).unwrap()
    }

    async fn http_get_bytes(addr: std::net::SocketAddr, path: &str) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).await.unwrap();
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        raw[split + 4..].to_vec()
    }

    async fn http_get_json(addr: std::net::SocketAddr, path: &str) -> serde_json::Value {
        let bytes = http_get_bytes(addr, path).await;
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn enforces_auth_rbac_tenant_isolation_security_headers_and_scim_v2() {
        let store = Arc::new(operquay_core::InMemorySettingsStore::new());
        let hub = TelemetryHub::build("test", None, 1.0, false);
        let mut state = AppState::with_defaults(store, hub, None);
        state.auth = Arc::new(AuthService::with_bcrypt_cost(
            true,
            Some("SuperSecret#99".into()),
            4,
        ));
        let app = build_router(state.clone());

        // 1. Fail-closed 401 on protected routes when require_auth = true + verify security headers
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/recordings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            res.headers()
                .get("x-content-type-options")
                .unwrap()
                .to_str()
                .unwrap(),
            "nosniff"
        );
        assert_eq!(
            res.headers()
                .get("x-frame-options")
                .unwrap()
                .to_str()
                .unwrap(),
            "SAMEORIGIN"
        );
        assert_eq!(
            res.headers()
                .get("referrer-policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "same-origin"
        );

        // 2. Host subdomain tenant extraction + reserved www fallback
        let res_tenant = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/auth/config")
                    .header("host", "acme-corp.operquay.io")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes_t = axum::body::to_bytes(res_tenant.into_body(), usize::MAX)
            .await
            .unwrap();
        let cfg_t: serde_json::Value = serde_json::from_slice(&bytes_t).unwrap();
        assert_eq!(cfg_t["tenant_id"], "acme-corp");
        assert_eq!(cfg_t["required"], true);

        let res_www = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/auth/config")
                    .header("host", "www.operquay.io")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes_w = axum::body::to_bytes(res_www.into_body(), usize::MAX)
            .await
            .unwrap();
        let cfg_w: serde_json::Value = serde_json::from_slice(&bytes_w).unwrap();
        assert_eq!(cfg_w["tenant_id"], "default");

        // 3. Sign in as default admin -> HTTP-only HMAC cookie -> /api/auth/me -> create user/group/SCIM token
        let login_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "email": "admin@local",
                            "password": "SuperSecret#99"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_res.status(), StatusCode::OK);
        let set_cookie = login_res
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(set_cookie.contains("HttpOnly"));
        let cookie_pair = set_cookie.split(';').next().unwrap().to_owned();

        let me_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/auth/me")
                    .header(header::COOKIE, &cookie_pair)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(me_res.status(), StatusCode::OK);
        let me_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(me_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(me_json["role"], "admin");

        // 4. Create SCIM bearer token & verify SCIM v2 /Users & /Groups provisioning + unauthorized rejection
        let scim_tok_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scim/tokens")
                    .header(header::COOKIE, &cookie_pair)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"okta-scim"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(scim_tok_res.status(), StatusCode::CREATED);
        let tok_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(scim_tok_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let bearer = format!("Bearer {}", tok_json["secret"].as_str().unwrap());

        let scim_unauth = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/scim/v2/Users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(scim_unauth.status(), StatusCode::UNAUTHORIZED);

        let scim_user = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/scim/v2/Users")
                    .header(header::AUTHORIZATION, &bearer)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "userName": "alice.scim@acme.test",
                            "displayName": "Alice SCIM",
                            "active": true
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(scim_user.status(), StatusCode::CREATED);

        // 5. Viewer cannot access /api/users (RBAC 403)
        let _viewer = state
            .auth
            .create_user("default", "bob@local", "Bob", "viewer", "BobPass#12345")
            .await
            .unwrap();
        let bob_login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"email":"bob@local","password":"BobPass#12345"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bob_cookie = bob_login
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let forbidden = app
            .oneshot(
                Request::builder()
                    .uri("/api/users")
                    .header(header::COOKIE, &bob_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn serves_aws_accounts_bindings_clone_topology_and_live_ssm_shell_ws() {
        let store = Arc::new(operquay_core::InMemorySettingsStore::new());
        let hub = TelemetryHub::build("test", None, 1.0, false);
        let state = AppState::with_defaults(store, hub, None);

        state
            .aws
            .discovery
            .seed_instances(
                "default",
                vec![operquay_aws::discovery::Ec2Instance {
                    instance_id: "i-0web1".into(),
                    name: "web-01".into(),
                    state: "running".into(),
                    instance_type: "t3.medium".into(),
                    platform: "linux".into(),
                    private_ip: "10.0.1.10".into(),
                    public_ip: "54.1.2.3".into(),
                    region: "us-east-1".into(),
                    availability_zone: "us-east-1a".into(),
                    vpc_id: "vpc-main".into(),
                    subnet_id: "sub-pub".into(),
                    account_id: "123456789012".into(),
                    profile: "hub".into(),
                    ssm_online: true,
                    tags: std::collections::HashMap::new(),
                    security_groups: vec!["sg-1".into()],
                    launch_time: "2026-11-16T00:00:00Z".into(),
                }],
            )
            .await;
        state
            .aws
            .topology
            .put_topology(
                "default",
                operquay_aws::topology::VpcTopology {
                    vpc: operquay_aws::topology::VpcInfo {
                        id: "vpc-main".into(),
                        cidr: "10.0.0.0/16".into(),
                        name: "main".into(),
                        is_default: true,
                    },
                    instances: vec![operquay_aws::topology::TopologyInstance {
                        id: "i-0web1".into(),
                        name: "web-01".into(),
                        private_ip: "10.0.1.10".into(),
                        public_ip: "54.1.2.3".into(),
                        subnet_id: "sub-pub".into(),
                        security_groups: vec!["sg-1".into()],
                        ..Default::default()
                    }],
                    route_tables: vec![operquay_aws::topology::RouteTableInfo {
                        id: "rtb-1".into(),
                        name: "main".into(),
                        routes: vec![operquay_aws::topology::RouteEntry {
                            destination_cidr: "10.0.0.0/16".into(),
                            target: "local".into(),
                            state: "active".into(),
                        }],
                        subnets: vec!["sub-1".into()],
                    }],
                    ..Default::default()
                },
            )
            .await;

        let app = build_router(state.clone());

        // Fleet stats + preferences + clone + topology deep-analyze
        let stats_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/fleet-stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stats_res.status(), StatusCode::OK);
        let fleet: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(stats_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(fleet["running"], 1);

        let clone_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/clone/start")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"instance_id":"i-0web1","clone_name":"web-02"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(clone_res.status(), StatusCode::CREATED);

        let topo_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/aws/topology/deep-analyze")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"vpc_id":"vpc-main"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(topo_res.status(), StatusCode::OK);

        // /ws without configured AWS credentials must return an explicit error (no mock sandbox shell)
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(ln, app).await;
        });

        let (mut ws, _) = connect_async(format!(
            "ws://{addr}/ws?instance_id=i-0web1&region=us-east-1"
        ))
        .await
        .unwrap();
        let first_msg = ws.next().await.unwrap().unwrap().into_text().unwrap();
        let lower = first_msg.to_lowercase();
        assert!(
            !first_msg.contains("[operquay-ssm]")
                && (lower.contains("error")
                    || lower.contains("credential")
                    || lower.contains("aws")),
            "expected explicit error without AWS credentials, got: {first_msg}"
        );
        let _ = ws.close(None).await;
    }

    #[tokio::test]
    async fn serves_suggest_ai_k8s_teleport_db_forward_mux_audit_csv_and_license() {
        let store = Arc::new(operquay_core::InMemorySettingsStore::new());
        let hub = TelemetryHub::build("test", None, 1.0, false);
        let state = AppState::with_defaults(store, hub, None);
        let app = build_router(state.clone());

        // 1. Suggest + DB Viewer
        let sug_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/suggest")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"prefix":"kubectl","dir":"/opt","learn":"kubectl get svc -A","exit_code":0}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sug_res.status(), StatusCode::OK);
        let dbv_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/db-viewer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dbv_res.status(), StatusCode::OK);

        // 2. AI Safety + Catalog
        let safe_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/ai/check-safety")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"command":"sudo rm -rf /var"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let safe_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(safe_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(safe_json["blocked"], true);

        // 3. K8s Teleport + Recording Policy + DB SQL Guard
        let cert = rcgen::generate_simple_self_signed(vec!["teleport.local".to_owned()]).unwrap();
        let pem = cert.cert.pem();
        let tp_mock = Router::new()
            .route(
                "/webapi/ping",
                axum::routing::get(|| async {
                    Json(serde_json::json!({
                        "cluster_name": "tp-root",
                        "auth": { "type": "local", "second_factor": "on" },
                        "proxy": { "tls_routing_enabled": true, "kube": { "enabled": true } }
                    }))
                }),
            )
            .route(
                "/v1/webapi/mfa/login/begin",
                axum::routing::post(|| async {
                    Json(serde_json::json!({ "totp_challenge": true }))
                }),
            )
            .route(
                "/v1/webapi/mfa/login/finish",
                axum::routing::post({
                    let pem = pem.clone();
                    move || {
                        let pem = pem.clone();
                        async move {
                            let enc = base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                pem.as_bytes(),
                            );
                            Json(serde_json::json!({
                                "username": "ops",
                                "tls_cert": enc,
                                "host_signers": [{ "domain_name": "tp-root", "tls_certs": [enc] }]
                            }))
                        }
                    }
                }),
            );
        let tp_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tp_addr = tp_ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(tp_ln, tp_mock).await;
        });

        let tp_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/teleport/local-login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "proxy_url": format!("http://{tp_addr}"),
                            "username": "ops",
                            "password": "secret",
                            "otp": "123456",
                            "cluster_name": "prod-eks"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(tp_res.status(), StatusCode::OK);

        // 4. Port forward + REAL TCP upstream 5-byte WS multiplexer + /health + /vault + /v1/public-key
        let tcp_echo_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_echo_addr = tcp_echo_ln.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            if let Ok((mut s, _)) = tcp_echo_ln.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                }
            }
        });

        let fwd_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/aws/forward/start")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "instance_id": "i-demo-tcp",
                            "remote_host": "127.0.0.1",
                            "remote_port": tcp_echo_addr.port(),
                            "local_port": 15432
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fwd_res.status(), StatusCode::CREATED);
        let tun: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(fwd_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let pairing_code = tun["pairing_code"].as_str().unwrap().to_owned();

        // 5. License Ed25519 redemption & Audit CSV export + Legacy Convert MP4
        let (sk, pk) = operquay_license::generate_keypair_b64();
        let tok = operquay_license::issue_license_token(
            &operquay_license::EntitlementClaims {
                license_id: "lic-e9".into(),
                customer: "SteadVerge".into(),
                plan: operquay_license::PlanTier::Enterprise,
                max_seats: 250,
                issued_at: 0,
                expires_at: 0,
                capabilities: operquay_license::all_enterprise_capabilities(),
            },
            &sk,
        )
        .unwrap();
        let lic_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/license/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "token": tok, "public_key": pk }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(lic_res.status(), StatusCode::OK);

        let csv_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/audit/export?format=csv")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(csv_res.status(), StatusCode::OK);

        let conv_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/convert-recording")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"id":"rec-e9","format":"mp4"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(conv_res.status(), StatusCode::OK);

        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(ln, app).await;
        });

        let (mut ws, _) = connect_async(format!("ws://{addr}/api/aws/forward/connect"))
            .await
            .unwrap();
        ws.send(WsMsg::Text(
            serde_json::json!({ "pairing_code": pairing_code })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        let ready = ws.next().await.unwrap().unwrap().into_text().unwrap();
        assert!(ready.contains("ready"));
        ws.send(WsMsg::Binary(
            operquay_forward::encode_mux_frame(operquay_forward::MuxFrameKind::Open, 7, &[]).into(),
        ))
        .await
        .unwrap();
        let mux_in = operquay_forward::encode_mux_frame(
            operquay_forward::MuxFrameKind::Data,
            7,
            b"ping-mux",
        );
        ws.send(WsMsg::Binary(mux_in.into())).await.unwrap();
        let echoed = ws.next().await.unwrap().unwrap().into_data();
        let (_, sid, payload) = operquay_forward::decode_mux_frame(&echoed).unwrap();
        assert_eq!(sid, 7);
        assert_eq!(payload, b"ping-mux");
        ws.close(None).await.unwrap();

        let h_bytes = http_get_bytes(addr, "/health").await;
        let h_json: serde_json::Value = serde_json::from_slice(&h_bytes).unwrap();
        assert_eq!(h_json["ironrdp_present"], true);
        let pk_json = http_get_json(addr, "/v1/public-key").await;
        assert_eq!(pk_json["algorithm"], "Ed25519");
    }

    #[tokio::test]
    async fn serves_legacy_recordings_list_conversion_and_mp4_download() {
        let store: Arc<dyn SettingsStore> = Arc::new(InMemorySettingsStore::default());
        let hub = TelemetryHub::build("test", None, 1.0, false);
        let state = AppState::with_defaults(store, hub, None);
        let app = build_router(state.clone());

        let mut tee = state
            .recordings
            .start_session(
                "rec-ui-1".to_owned(),
                "default".to_owned(),
                "rdp".to_owned(),
                "win-host".to_owned(),
                false,
            )
            .await
            .unwrap();
        tee.record_guac_line("4.size,1.0,4.1280,3.720;").unwrap();
        state.recordings.finalize(tee).await;

        let list_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/recordings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list_res.status(), StatusCode::OK);
        let list_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(list_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let rec_name = list_json[0]["name"].as_str().unwrap().to_owned();
        assert!(
            std::path::Path::new(&rec_name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("guac")),
            "expected .guac name: {rec_name}"
        );
        assert_eq!(list_json[0]["type"], "rdp");
        assert_eq!(list_json[0]["has_mp4"], false);
        assert!(list_json[0]["mod_time"].as_str().unwrap().ends_with('Z'));

        let conv_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/convert-recording")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "filename": rec_name }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(conv_res.status(), StatusCode::OK);
        let conv_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(conv_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(conv_json["status"], "done");
        assert_ne!(conv_json["job_id"].as_str().unwrap(), "");

        let mp4_name = rec_name.strip_suffix(".guac").unwrap().to_owned() + ".mp4";
        let mp4_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/recordings/{mp4_name}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mp4_res.status(), StatusCode::OK);
        let mp4_bytes = axum::body::to_bytes(mp4_res.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(mp4_bytes.len() > 24);
    }

    #[tokio::test]
    async fn verifies_all_fixed_frontend_api_and_k8s_ai_aws_contracts() {
        use axum::routing::get as ax_get;
        use axum::routing::post as ax_post;

        // Mock STS AssumeRole + GetCallerIdentity server
        let sts_app = Router::new().route(
            "/",
            ax_post(|| async {
                "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIATEMP123</AccessKeyId><SecretAccessKey>TempSecret123</SecretAccessKey><SessionToken>TempTok123</SessionToken></Credentials><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/Ops/test</Arn></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>"
            }),
        );
        let sts_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sts_addr = sts_ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(sts_ln, sts_app).await;
        });

        // Mock K8s API server
        let k8s_app = Router::new()
            .route(
                "/api/v1/namespaces",
                ax_get(|| async {
                    axum::Json(serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "NamespaceList",
                        "items": [
                            { "metadata": { "name": "default" } },
                            { "metadata": { "name": "kube-system" } }
                        ]
                    }))
                }),
            )
            .route(
                "/api/v1/namespaces/default/pods",
                ax_get(|| async {
                    axum::Json(serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "PodList",
                        "items": [{ "metadata": { "name": "web-0", "namespace": "default" } }]
                    }))
                }),
            )
            .route(
                "/api/v1/namespaces/default/pods/web-0/log",
                ax_get(|| async { "line1\nline2\n" }),
            );
        let k8s_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let k8s_addr = k8s_ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(k8s_ln, k8s_app).await;
        });

        let store = Arc::new(operquay_core::InMemorySettingsStore::new());
        let hub = TelemetryHub::build("test", None, 1.0, false);
        let mut state = AppState::with_defaults(store, hub, None);
        state.auth = Arc::new(AuthService::with_bcrypt_cost(
            true,
            Some("SuperSecret#99".into()),
            4,
        ));
        state.aws = Arc::new(aws_routes::AwsHubState {
            accounts: Arc::new(operquay_aws::accounts::AwsAccountStore::new(
                operquay_aws::accounts::AwsAccessMode::User,
                Some(format!("http://{sts_addr}/")),
            )),
            ..Default::default()
        });
        state
            .aws
            .topology
            .put_topology(
                "default",
                operquay_aws::topology::VpcTopology {
                    vpc: operquay_aws::topology::VpcInfo {
                        id: "vpc-test".into(),
                        cidr: "10.0.0.0/16".into(),
                        name: "test-vpc".into(),
                        is_default: false,
                    },
                    instances: vec![
                        operquay_aws::topology::TopologyInstance {
                            id: "i-src".into(),
                            name: "src".into(),
                            private_ip: "10.0.1.10".into(),
                            public_ip: String::new(),
                            state: "running".into(),
                            platform: "linux".into(),
                            instance_type: "t3.micro".into(),
                            subnet_id: "sub-1".into(),
                            security_groups: vec!["sg-all".into()],
                        },
                        operquay_aws::topology::TopologyInstance {
                            id: "i-dst".into(),
                            name: "dst".into(),
                            private_ip: "10.0.1.20".into(),
                            public_ip: String::new(),
                            state: "running".into(),
                            platform: "linux".into(),
                            instance_type: "t3.micro".into(),
                            subnet_id: "sub-1".into(),
                            security_groups: vec!["sg-all".into()],
                        },
                    ],
                    subnets: vec![operquay_aws::topology::SubnetInfo {
                        id: "sub-1".into(),
                        cidr: "10.0.1.0/24".into(),
                        name: "sub-1".into(),
                        az: "us-east-1a".into(),
                        ..Default::default()
                    }],
                    security_groups: vec![operquay_aws::topology::SecurityGroupInfo {
                        id: "sg-all".into(),
                        name: "sg-all".into(),
                        description: String::new(),
                        rules: vec![
                            operquay_aws::topology::SgRuleInfo {
                                direction: "egress".into(),
                                protocol: "-1".into(),
                                from_port: 0,
                                to_port: 0,
                                cidr_or_sg: "0.0.0.0/0".into(),
                            },
                            operquay_aws::topology::SgRuleInfo {
                                direction: "ingress".into(),
                                protocol: "tcp".into(),
                                from_port: 443,
                                to_port: 443,
                                cidr_or_sg: "0.0.0.0/0".into(),
                            },
                        ],
                    }],
                    route_tables: vec![operquay_aws::topology::RouteTableInfo {
                        id: "rtb-1".into(),
                        name: "main".into(),
                        routes: vec![operquay_aws::topology::RouteEntry {
                            destination_cidr: "10.0.0.0/16".into(),
                            target: "local".into(),
                            state: "active".into(),
                        }],
                        subnets: vec!["sub-1".into()],
                    }],
                    ..Default::default()
                },
            )
            .await;

        let app = build_router(state.clone());

        // Login as seeded admin
        let login_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", "203.0.113.10")
                    .header("user-agent", "OperquayTest/1.0")
                    .body(Body::from(
                        r#"{"email":"admin@local","password":"SuperSecret#99"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_res.status(), StatusCode::OK);
        let cookie = login_res
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        // Auth /me, permissions, users, groups, SSO partial PUT, license
        let me_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/auth/me")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let me_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(me_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(me_json["method"], "password");
        assert!(me_json["grants"].is_array());

        let perms_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/permissions")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let perms_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(perms_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(perms_json["permissions"].is_array());
        assert!(perms_json["scope_types"].is_array());

        let usr_create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"email":"ops@example.com","display_name":"Ops User","role":"operator"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(usr_create.status(), StatusCode::CREATED);
        let usr_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(usr_create.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let uid = usr_json["user"]["id"].as_str().unwrap().to_owned();
        assert_eq!(usr_json["email"], "ops@example.com");

        let reset_pw = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/users/{uid}/password"))
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"new_password":"NewPassword@456"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reset_pw.status(), StatusCode::OK);

        let grp_create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/groups")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"ops-team"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(grp_create.status(), StatusCode::CREATED);

        let groups_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/groups")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let groups_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(groups_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(groups_json[0]["idp_mappings"].is_array());

        let lic_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/license")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let lic_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(lic_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(lic_json["status"], "unconfigured");
        assert!(lic_json["deployment_id"].is_string());

        // SSO provider create + partial PUT
        let sso_add = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/providers")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"name":"Okta","provider_type":"oidc","issuer":"https://idp.example.com","client_id":"cid","client_secret":"csec","domains":["example.com"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sso_add.status(), StatusCode::CREATED);
        let sso_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(sso_add.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let sso_id = sso_json["id"].as_str().unwrap();
        let sso_put = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/auth/providers/{sso_id}"))
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"Okta Prod","enabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sso_put.status(), StatusCode::OK);

        // Preferences flat round-trip
        let pref_patch = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/preferences")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"default_region":"us-west-2","extra":{"sidebar_compact":true},"custom_flag":"yes"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pref_patch.status(), StatusCode::OK);
        let pref_get = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/preferences")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let pref_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(pref_get.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(pref_json["sidebar_compact"], true);
        assert_eq!(pref_json["custom_flag"], "yes");

        // Enriched Audit Log + Pagination + 19-col CSV
        let audit_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/audit-log?limit=10&offset=0")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let audit_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(audit_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(audit_json.as_array().is_some_and(|a| !a.is_empty()));
        assert!(audit_json[0]["timestamp"].is_string());

        let csv_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/audit/export")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(csv_res.status(), StatusCode::OK);
        let csv_txt = String::from_utf8(
            axum::body::to_bytes(csv_res.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(csv_txt.starts_with("timestamp,action,outcome,user_email,role,ip,"));

        // Multipart transfer upload parses multipart body cleanly (returns 401 when binding_id not connected, not 422/415)
        let boundary = "----OperquayBoundary7MA4YWxkTrZu0gW";
        let mp_body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"binding_id\"\r\n\r\nmissing-bind\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"instance_id\"\r\n\r\ni-src\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"remote_path\"\r\n\r\n/tmp/a.txt\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--{boundary}--\r\n"
        );
        let upload_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/aws/transfer/upload")
                    .header(header::COOKIE, &cookie)
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(mp_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(upload_resp.status(), StatusCode::UNAUTHORIZED);

        // AWS Onboarding + empty name add_account + binding_id 401 enforcement + STS role-login + recoverable + deep-analyze JSON
        let onb_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/aws/onboarding")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let onb_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(onb_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(onb_json["mode"], "user");
        assert_eq!(onb_json["role_name"], "OperquayAccess");

        let add_acc_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/aws-accounts")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"role_arn":"arn:aws:iam::123456789012:role/OperquayAccess"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(add_acc_res.status(), StatusCode::CREATED);

        let missing_lease = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/aws/instance-details?id=i-abc&binding_id=missing-bind")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_lease.status(), StatusCode::UNAUTHORIZED);

        let role_login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/aws/role-login")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"role_arn":"arn:aws:iam::123456789012:role/Ops","access_key_id":"AKIA1","secret_access_key":"SEC1"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(role_login.status(), StatusCode::OK);
        let role_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(role_login.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(role_json["id"].as_str().unwrap().starts_with("iam-"));

        let rec_clones = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/aws/clones/recoverable")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let rec_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(rec_clones.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(rec_json["operations"].is_array());
        assert_eq!(rec_json["incomplete"], false);

        let deep_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/aws/topology/deep-analyze")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"vpc_id":"vpc-test","sourceInstanceId":"i-src","destInstanceId":"i-dst","protocol":"tcp","port":443}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deep_res.status(), StatusCode::OK);
        let deep_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(deep_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(deep_json["reachable"], true);
        assert!(deep_json["hops"].is_array());
        assert!(deep_json["explanations"].is_array());

        // Port forward port -> forward_id & forward_id stop
        let fwd_start = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/aws/forward/start")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"instance_id":"i-src","region":"us-east-1","port":5432,"binding_id":"b-1"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fwd_start.status(), StatusCode::CREATED);
        let fwd_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(fwd_start.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let fwd_id = fwd_json["forward_id"].as_str().unwrap().to_owned();
        let fwd_stop = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/aws/forward/stop")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "forward_id": fwd_id }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fwd_stop.status(), StatusCode::OK);

        // AI catalog update (both endpoint_url + base_url, omitted enabled, explicit enabled:false) + Oi chat SSE without provider (no 422)
        let ai_put_dual = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/ai/catalog")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"provider":"openai","account_id":"acc-1","account_label":"Prod Account","binding_id":"bind-1","endpoint_url":"https://llm.example.com","base_url":"https://llm.example.com","api_key":"sk-test","models":[{"id":"m-1","name":"Model 1"}]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ai_put_dual.status(), StatusCode::OK);
        let ai_dual_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(ai_put_dual.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ai_dual_json["configured"], true);
        assert_eq!(ai_dual_json["key_configured"], true);
        assert_eq!(ai_dual_json["account_label"], "Prod Account");
        assert_eq!(ai_dual_json["binding_id"], "bind-1");
        assert_eq!(ai_dual_json["base_url"], "https://llm.example.com");

        let ai_put_disabled = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/ai/catalog")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"enabled":false,"provider":"openai","model":"m-1","endpoint_url":"https://llm.example.com","base_url":"https://llm.example.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ai_put_disabled.status(), StatusCode::OK);
        let ai_disabled_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(ai_put_disabled.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ai_disabled_json["configured"], false);

        let ai_put = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/ai/catalog")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"enabled":true,"provider":"bedrock","account_id":"acc-1","models":[{"id":"m-1","name":"Model 1"}]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ai_put.status(), StatusCode::OK);
        let ai_chat_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ai-agent/chat")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"messages":[{"role":"user","content":"hi"}]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ai_chat_res.status(), StatusCode::OK);
        assert!(ai_chat_res
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/event-stream"));

        // K8s configured clusters separation, recording policy, kubeconfig upload, namespaces/categories/resources/logs, /api/teleport/connect
        let cfg_create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/k8s/configured-clusters")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"label":"Prod","proxy":"tp.example.com","cluster_name":"eks-prod","method":"sso","connector":"okta"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cfg_create.status(), StatusCode::CREATED);
        let cfg_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(cfg_create.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let cfg_id = cfg_json["id"].as_str().unwrap().to_owned();

        let rec_put = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/k8s/configured-clusters/{cfg_id}/recording"))
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"mode":"selected","namespaces":["payments"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rec_put.status(), StatusCode::OK);

        let kc_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/k8s/kubeconfig/upload")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "kubeconfig": format!("clusters:\n  - name: mock-k8s\n    cluster:\n      server: http://{k8s_addr}\nusers:\n  - name: admin\n    user:\n      token: tok\n"),
                            "connect": true
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(kc_res.status(), StatusCode::CREATED);

        let ns_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/k8s/namespaces?cluster=mock-k8s")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let ns_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(ns_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ns_json, serde_json::json!(["default", "kube-system"]));

        let cats_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/k8s/categories")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let cats_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(cats_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(cats_json[0]["name"].is_string());
        assert!(cats_json[0]["resources"].is_array());

        let pods_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/k8s/resources/pods?cluster=mock-k8s&namespace=default")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let pods_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(pods_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(pods_json[0]["metadata"]["name"], "web-0");

        let pod_logs = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/k8s/pods/default/web-0/logs?cluster=mock-k8s&tail=10")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pod_logs.status(), StatusCode::OK);
        let logs_txt = String::from_utf8(
            axum::body::to_bytes(pod_logs.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(logs_txt.contains("line1"));

        let cert2 = rcgen::generate_simple_self_signed(vec!["teleport.local".to_owned()]).unwrap();
        let pem2 = cert2.cert.pem();
        let tp_mock2 = Router::new()
            .route(
                "/webapi/ping",
                axum::routing::get(|| async {
                    Json(serde_json::json!({
                        "cluster_name": "tp-root",
                        "auth": { "type": "local", "second_factor": "on" },
                        "proxy": { "tls_routing_enabled": true, "kube": { "enabled": true } }
                    }))
                }),
            )
            .route(
                "/v1/webapi/mfa/login/begin",
                axum::routing::post(|| async {
                    Json(serde_json::json!({ "totp_challenge": true }))
                }),
            )
            .route(
                "/v1/webapi/mfa/login/finish",
                axum::routing::post({
                    let pem2 = pem2.clone();
                    move || {
                        let pem2 = pem2.clone();
                        async move {
                            let enc = base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                pem2.as_bytes(),
                            );
                            Json(serde_json::json!({
                                "username": "ops",
                                "tls_cert": enc,
                                "host_signers": [{ "domain_name": "tp-root", "tls_certs": [enc] }]
                            }))
                        }
                    }
                }),
            );
        let tp_ln2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tp_addr2 = tp_ln2.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(tp_ln2, tp_mock2).await;
        });

        let tp_login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/teleport/local-login")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "proxy_url": format!("http://{tp_addr2}"),
                            "username": "ops",
                            "password": "secret",
                            "otp": "123456",
                            "cluster_name": "eks-prod"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(tp_login.status(), StatusCode::OK);
        let tp_login_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(tp_login.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let cb_id = tp_login_json["callback_id"].as_str().unwrap();

        let tp_conn = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/teleport/connect")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "callback_id": cb_id,
                            "cluster_name": "eks-prod"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(tp_conn.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn m9_security_headers_host_cookie_csrf_mfa_lockout_and_live_fence() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let state = test_state();
        state.auth.set_require_auth(true).await;
        state
            .auth
            .set_admin_password("AdminStrong#2026")
            .await
            .unwrap();
        let tls_app = build_router(state.clone()).layer(Extension(ListenerScheme(true)));

        // 1. HTTPS security headers + __Host- Secure cookie
        let health_res = tls_app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health_res.status(), StatusCode::OK);
        assert!(health_res
            .headers()
            .get("strict-transport-security")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("max-age=31536000")));
        assert!(health_res
            .headers()
            .get("content-security-policy")
            .is_some());
        assert!(health_res.headers().get("permissions-policy").is_some());
        assert_eq!(
            health_res
                .headers()
                .get("x-frame-options")
                .and_then(|v| v.to_str().ok()),
            Some("SAMEORIGIN")
        );
        assert_eq!(
            health_res
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );

        let login_res = tls_app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .header("host", "localhost:5444")
                    .body(Body::from(
                        r#"{"email":"admin@local","password":"AdminStrong#2026"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_res.status(), StatusCode::OK);
        let set_cookie = login_res
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(set_cookie.starts_with("__Host-operquay_session="));
        assert!(set_cookie.contains("; Secure;"));
        assert!(set_cookie.contains("; HttpOnly;"));
        let host_cookie = set_cookie.split(';').next().unwrap().to_owned();

        // 2. Anti-CSRF blocks cross-site Origin / Sec-Fetch-Site when cookie-authenticated
        let csrf_origin_res = tls_app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/auth/logout")
                    .header("host", "localhost:5444")
                    .header("origin", "https://evil.example")
                    .header(header::COOKIE, &host_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(csrf_origin_res.status(), StatusCode::FORBIDDEN);

        let csrf_sfs_res = tls_app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/auth/logout")
                    .header("host", "localhost:5444")
                    .header("sec-fetch-site", "cross-site")
                    .header(header::COOKIE, &host_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(csrf_sfs_res.status(), StatusCode::FORBIDDEN);

        // 3. Untrusted peer cannot spoof x-operquay-tenant
        let spoof_res = tls_app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/auth/me")
                    .header("x-operquay-tenant", "victim-tenant")
                    .header(header::COOKIE, &host_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(spoof_res.status(), StatusCode::OK);

        // 4. TOTP setup -> verify -> login challenge -> recovery completion -> disable
        let setup_res = tls_app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/totp/setup")
                    .header(header::COOKIE, &host_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(setup_res.status(), StatusCode::OK);
        let setup_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(setup_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let totp_secret = setup_json["secret"].as_str().unwrap().to_owned();
        let now_step = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                / 30,
        )
        .unwrap();
        let totp_code = operquay_auth::mfa::compute_totp_code(&totp_secret, now_step).unwrap();

        let verify_res = tls_app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/totp/verify")
                    .header(header::COOKIE, &host_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "code": totp_code }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify_res.status(), StatusCode::OK);
        let verify_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(verify_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(verify_json["enabled"], true);
        let rec_code_0 = verify_json["recovery_codes"][0]
            .as_str()
            .unwrap()
            .to_owned();
        let rec_code_1 = verify_json["recovery_codes"][1]
            .as_str()
            .unwrap()
            .to_owned();

        let chal_res = tls_app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"email":"admin@local","password":"AdminStrong#2026"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(chal_res.status(), StatusCode::OK);
        assert!(chal_res.headers().get(header::SET_COOKIE).is_none());
        let chal_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(chal_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(chal_json["mfa_required"], true);
        let challenge_token = chal_json["challenge_token"].as_str().unwrap().to_owned();

        let mfa_login_res = tls_app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/auth/login/mfa")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "challenge_token": challenge_token,
                            "recovery_code": rec_code_0
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mfa_login_res.status(), StatusCode::OK);
        let mfa_cookie = mfa_login_res
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        // Check active session fence triggers immediately upon logout
        let me_headers = {
            let mut h = HeaderMap::new();
            h.insert(header::COOKIE, HeaderValue::from_str(&mfa_cookie).unwrap());
            h
        };
        let claims = state.auth.verify_cookie(&me_headers).await.unwrap();
        let mut fence = state.session_fence.register(
            &claims.tenant_id,
            &claims.user_id,
            &claims.session_id,
            None,
        );
        let logout_res = tls_app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/auth/logout")
                    .header("host", "localhost:5444")
                    .header("origin", "https://localhost:5444")
                    .header(header::COOKIE, &mfa_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout_res.status(), StatusCode::OK);
        let reason = tokio::time::timeout(std::time::Duration::from_secs(1), fence.revoked())
            .await
            .expect("session fence did not fire immediately on logout");
        assert_eq!(reason, "signed_out");

        // Disable TOTP cleanly with remaining recovery code
        let disable_res = tls_app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/totp/disable")
                    .header(header::COOKIE, &host_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "current_password": "AdminStrong#2026",
                            "code": rec_code_1
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disable_res.status(), StatusCode::OK);

        // 5. Failed login lockout returns 429 + Retry-After
        let _ = state
            .auth
            .create_user(
                "default",
                "lockout@local",
                "Lockout User",
                "viewer",
                "LockoutStrong#12",
            )
            .await
            .unwrap();
        let mut saw_429 = false;
        for _ in 0..8 {
            let bad = tls_app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .method("POST")
                        .uri("/api/auth/login")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            r#"{"email":"lockout@local","password":"WrongPassword#99"}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            if bad.status() == StatusCode::TOO_MANY_REQUESTS {
                assert!(bad.headers().get(header::RETRY_AFTER).is_some());
                saw_429 = true;
                break;
            }
        }
        assert!(
            saw_429,
            "expected 429 Too Many Requests on repeated bad logins"
        );
    }

    #[tokio::test]
    async fn audit_verify_endpoint_validates_hash_chain_and_detects_tampering() {
        let state = test_state();
        state.auth.set_require_auth(false).await;
        state
            .audit
            .record(
                "default",
                "tr-1",
                "s-1",
                "settings_updated",
                "http",
                "control-plane",
                "initial",
                None,
            )
            .await;
        state
            .audit
            .record(
                "default",
                "tr-2",
                "s-2",
                "session_launch",
                "rdp",
                "10.0.0.10",
                "launched",
                Some("rec-1".to_owned()),
            )
            .await;

        let app = build_router(state.clone());
        let ok_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/audit/verify")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok_res.status(), StatusCode::OK);
        let ok_bytes = axum::body::to_bytes(ok_res.into_body(), 1024 * 64)
            .await
            .unwrap();
        let ok_json: serde_json::Value = serde_json::from_slice(&ok_bytes).unwrap();
        assert_eq!(ok_json["valid"], true);
        assert_eq!(ok_json["source"], "memory");
        assert!(ok_json["checked_events"].as_u64().unwrap_or(0) >= 2);

        state
            .audit
            .tamper_event_for_test("default", 0, "tampered-detail")
            .await;
        let bad_res = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/audit/verify")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_res.status(), StatusCode::OK);
        let bad_bytes = axum::body::to_bytes(bad_res.into_body(), 1024 * 64)
            .await
            .unwrap();
        let bad_json: serde_json::Value = serde_json::from_slice(&bad_bytes).unwrap();
        assert_eq!(bad_json["valid"], false);
        assert_eq!(bad_json["broken_at_seq"], 1);
    }

    #[tokio::test]
    async fn k8s_exec_ws_loopback_proxies_io_and_writes_encrypted_cast_recording() {
        use axum::extract::ws::WebSocketUpgrade;

        let mock_k8s = Router::new().route(
            "/api/v1/namespaces/prod/pods/web-1/exec",
            get(|ws: WebSocketUpgrade| async move {
                ws.protocols(["v5.channel.k8s.io"])
                    .on_upgrade(|mut sock| async move {
                        while let Some(Ok(msg)) = sock.next().await {
                            if let axum::extract::ws::Message::Binary(b) = msg {
                                if b.first() == Some(&0) && &b[1..] == b"whoami\n" {
                                    let mut out = vec![1u8];
                                    out.extend_from_slice(b"root\r\n");
                                    let _ = sock
                                        .send(axum::extract::ws::Message::Binary(out.into()))
                                        .await;
                                    let _ = sock
                                        .send(axum::extract::ws::Message::Binary(
                                            vec![255u8].into(),
                                        ))
                                        .await;
                                    break;
                                }
                            }
                        }
                    })
            }),
        );
        let k8s_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let k8s_addr = k8s_ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(k8s_ln, mock_k8s).await;
        });

        let state = test_state();
        state.auth.set_require_auth(false).await;
        state
            .platform
            .k8s
            .upsert_cluster(operquay_k8s::K8sClusterRecord {
                id: "loop-k8s".to_owned(),
                tenant_id: "default".to_owned(),
                name: "loop-k8s".to_owned(),
                source: "kubeconfig".to_owned(),
                api_server: format!("http://{k8s_addr}"),
                bearer_token: "tok".to_owned(),
                connected: true,
                recording_enabled: true,
                ..operquay_k8s::K8sClusterRecord::default()
            })
            .await;
        state
            .platform
            .k8s
            .set_policy(
                "default",
                operquay_k8s::K8sRecordingPolicy {
                    mode: "all".to_owned(),
                    record_exec: true,
                    fail_closed: true,
                    ..operquay_k8s::K8sRecordingPolicy::default()
                },
            )
            .await;

        let srv_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = srv_ln.local_addr().unwrap();
        let app = build_router(state.clone());
        tokio::spawn(async move {
            let _ = axum::serve(srv_ln, app).await;
        });

        let (mut ws, _) = connect_async(format!(
            "ws://{srv_addr}/ws/k8s/exec?cluster=loop-k8s&namespace=prod&pod=web-1"
        ))
        .await
        .expect("connect k8s exec ws");
        ws.send(WsMsg::Text("whoami\n".into())).await.unwrap();
        let reply = tokio::time::timeout(std::time::Duration::from_secs(3), ws.next())
            .await
            .expect("stdout timeout")
            .expect("ws item")
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(reply, "root\r\n");

        // Wait briefly for channel 255 CLOSE handling and recording finalize
        for _ in 0..30 {
            let recs = state.recordings.list("default").await;
            if recs
                .iter()
                .any(|r| r.status == "completed" && r.protocol == "k8s")
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let recs = state.recordings.list("default").await;
        let rec = recs
            .iter()
            .find(|r| r.protocol == "k8s")
            .expect("k8s recording entry");
        assert_eq!(rec.status, "completed");
        assert!(rec.encrypted);
        let plain = state
            .recordings
            .get_guac_bytes(&rec.id)
            .await
            .expect("decrypt .cast recording");
        let text = String::from_utf8(plain).unwrap();
        assert!(text.contains("root"));
    }

    #[tokio::test]
    async fn tenant_crypto_shred_destroys_dek_and_renders_recordings_undecryptable() {
        let temp_dir = std::env::temp_dir().join(format!("oq-shred-test-{}", Uuid::new_v4()));
        let tenant_keys = Arc::new(TenantKeyManager::new());
        let cat = Arc::new(
            RecordingCatalog::with_dir(temp_dir.clone())
                .unwrap()
                .with_shared_tenant_keys(Arc::clone(&tenant_keys)),
        );
        let mut state = test_state();
        state.auth.set_require_auth(false).await;
        state.recordings = cat;
        state.tenant_keys = tenant_keys;

        let mut tee = state
            .recordings
            .start_session(
                "rec-shred-1".to_owned(),
                "acme-shred".to_owned(),
                "rdp".to_owned(),
                "10.1.2.3".to_owned(),
                true,
            )
            .await
            .unwrap();
        tee.record_guac_line("4.sync,1.1;").unwrap();
        let _ = state.recordings.finalize(tee).await;
        assert!(state
            .recordings
            .get_guac_bytes("rec-shred-1")
            .await
            .is_some());

        let app = build_router(state.clone());
        let res = app
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/v1/tenants/acme-shred/crypto-shred")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"confirm":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 1024 * 64)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["shredded"], true);
        assert!(state.tenant_keys.is_shredded("acme-shred").await);
        assert!(state
            .recordings
            .get_guac_bytes("rec-shred-1")
            .await
            .is_none());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn graceful_shutdown_drains_fenced_sessions_within_timeout() {
        let fence = Arc::new(session_fence::ActiveSessionFence::new());
        let mut guard = fence.register("default", "u1", "s1", None);
        assert_eq!(fence.active_count(), 1);
        tokio::spawn(async move {
            let reason = guard.revoked().await;
            assert_eq!(reason, "server_shutdown");
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            drop(guard);
        });

        let (tx, rx) = tokio::sync::watch::channel(false);
        let fence_c = Arc::clone(&fence);
        let drain_task = tokio::spawn(async move {
            wait_for_shutdown_and_drain(fence_c, rx, std::time::Duration::from_secs(2)).await;
        });
        tx.send(true).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), drain_task)
            .await
            .expect("drain timed out")
            .unwrap();
        assert_eq!(fence.active_count(), 0);
    }

    async fn read_json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn jit_access_request_enforces_four_eyes_webhooks_and_revocation_fence() {
        let mut state = test_state();
        state.auth = Arc::new(AuthService::new(true, Some("SuperSecret#99".into())));
        let alice = state
            .auth
            .create_user(
                "default",
                "alice@local",
                "Alice",
                "admin",
                "AlicePass#12345",
            )
            .await
            .unwrap();
        let app = build_router(state.clone());

        let login_cookie = |email: String, password: String, app_c: Router| async move {
            let res = app_c
                .oneshot(
                    HttpRequest::builder()
                        .method("POST")
                        .uri("/api/auth/login")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({ "email": email, "password": password }).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            res.headers()
                .get(header::SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        };

        let alice_cookie =
            login_cookie("alice@local".into(), "AlicePass#12345".into(), app.clone()).await;
        let admin_cookie =
            login_cookie("admin@local".into(), "SuperSecret#99".into(), app.clone()).await;

        // Alice submits JIT request
        let create_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/access-requests")
                    .header(header::COOKIE, &alice_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "target_type": "aws_role",
                            "target_id": "arn:aws:iam::123456789012:role/ProdAdmin",
                            "requested_role": "ProdAdmin",
                            "duration_secs": 900,
                            "reason": "Incident response INC-42",
                            "ticket_id": "INC-42",
                            "ticket_provider": "jira"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_res.status(), StatusCode::CREATED);
        let req_json = read_json_body(create_res).await;
        let req_id = req_json["id"].as_str().unwrap().to_owned();

        // Four-eyes separation prevents Alice (even as admin) from approving her own request
        let self_approve = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri(format!("/api/access-requests/{req_id}/approve"))
                    .header(header::COOKIE, &alice_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(self_approve.status(), StatusCode::FORBIDDEN);

        // Configure webhook with signing secret
        let wh_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/governance/webhooks")
                    .header(header::COOKIE, &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "provider": "generic",
                            "name": "secops-chatops",
                            "url": "https://hooks.invalid/operquay",
                            "secret": "wh-secret-99"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wh_res.status(), StatusCode::CREATED);

        // Callback with invalid HMAC is rejected with 401
        let cb_body = serde_json::json!({
            "request_id": req_id,
            "action": "approve",
            "approver_id": "slack:U999",
            "approver_email": "secops@local",
            "note": "approved in slack"
        })
        .to_string();
        let bad_cb = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/access-requests/webhooks/generic/callback")
                    .header("x-operquay-signature", "sha256=0000")
                    .header("content-type", "application/json")
                    .body(Body::from(cb_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_cb.status(), StatusCode::UNAUTHORIZED);

        // Valid HMAC signature approves the JIT request
        let sig_hex = jit::sign_hmac_sha256_hex("wh-secret-99", cb_body.as_bytes());
        let good_cb = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/access-requests/webhooks/generic/callback")
                    .header("x-operquay-signature", format!("sha256={sig_hex}"))
                    .header("content-type", "application/json")
                    .body(Body::from(cb_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(good_cb.status(), StatusCode::OK);
        let good_json = read_json_body(good_cb).await;
        assert_eq!(good_json["request"]["status"], "approved");

        // Bind a live fenced session to the JIT grant and verify revoke terminates it immediately
        let mut fence_guard = state.session_fence.register_with_session(
            "default",
            &alice.id,
            "auth-s1",
            None,
            "ssm-jit-session",
            Some(&req_id),
        );
        let revoke_res = app
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri(format!("/api/access-requests/{req_id}/revoke"))
                    .header(header::COOKIE, &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"note":"incident mitigated"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoke_res.status(), StatusCode::OK);
        let revoked_body = read_json_body(revoke_res).await;
        assert_eq!(revoked_body["terminated_sessions"], 1);
        let reason = fence_guard.revoked().await;
        assert_eq!(reason, "jit_grant_revoked");
    }

    #[tokio::test]
    async fn live_session_moderation_ws_shadow_freeze_and_kill_and_k8s_command_firewall() {
        let state = test_state();
        state.auth.set_require_auth(false).await;

        let mod_handle = state.moderation.register_session(
            "default",
            "live-k8s-99",
            "k8s",
            "eks-prod/default/api-0",
            "usr-1",
            "alice@local",
            None,
        );
        let mut fence_guard = state.session_fence.register_with_session(
            "default",
            "usr-1",
            "anonymous-lab",
            None,
            "live-k8s-99",
            None,
        );
        let mut observer = state
            .moderation
            .subscribe(
                "default",
                "live-k8s-99",
                moderation::ModerationRole::Observer,
            )
            .expect("observer sub");
        mod_handle.publish_output("root@api-0:/# ");

        let app = build_router(state.clone());

        // Live sessions list shows registered session
        let live_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/sessions/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(live_res.status(), StatusCode::OK);
        let live_json = read_json_body(live_res).await;
        assert_eq!(live_json["sessions"][0]["session_id"], "live-k8s-99");

        // Moderator freeze toggles LiveSessionHandle and notifies shadow observers
        let freeze_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/sessions/live-k8s-99/freeze")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"frozen":true,"reason":"review dangerous cmd"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(freeze_res.status(), StatusCode::OK);
        assert!(mod_handle.is_frozen());
        let ev1 = observer.rx.recv().await.unwrap();
        assert!(matches!(ev1, moderation::LiveSessionEvent::Output { .. }));
        let ev2 = observer.rx.recv().await.unwrap();
        assert!(matches!(
            ev2,
            moderation::LiveSessionEvent::FrozenState { frozen: true, .. }
        ));

        // Command firewall dry-run checks
        let fw_block = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/governance/dlp-policy/test")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"protocol":"ssh","command":"rm -rf /var/log"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fw_block.status(), StatusCode::OK);
        assert_eq!(read_json_body(fw_block).await["verdict"]["action"], "block");

        let fw_pause = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/governance/dlp-policy/test")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"protocol":"k8s","command":"kubectl delete ns prod"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fw_pause.status(), StatusCode::OK);
        assert_eq!(
            read_json_body(fw_pause).await["verdict"]["action"],
            "pause_approval"
        );

        // Force kill terminates fenced session immediately
        let kill_res = app
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/sessions/live-k8s-99/kill")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"reason":"policy violation"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(kill_res.status(), StatusCode::OK);
        assert_eq!(read_json_body(kill_res).await["killed"], 1);
        assert_eq!(fence_guard.revoked().await, "policy violation");
    }

    #[tokio::test]
    async fn db_query_applies_inline_dlp_masking_and_compliance_portal_exports_signed_evidence() {
        let state = test_state();
        state.auth.set_require_auth(false).await;

        let mut tee = state
            .recordings
            .start_cast_session(
                "rec-m11-risk".to_owned(),
                "default".to_owned(),
                "ssh".to_owned(),
                "i-0123456789".to_owned(),
                true,
                120,
                32,
            )
            .await
            .unwrap();
        tee.record_cast_output(0.5, "sudo su -\r\ncat /etc/shadow\r\n")
            .unwrap();
        tee.record_cast_output(1.2, "export AWS=AKIAIOSFODNN7EXAMPLE alice@corp.test\r\n")
            .unwrap();
        let entry = state.recordings.finalize(tee).await;
        assert_eq!(entry.status, "completed");

        let app = build_router(state);

        // 1. DB DLP dry-run redaction masks email, SSN, password, and AWS key
        let dlp_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/governance/dlp-policy/test")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "protocol": "db",
                            "sample_columns": ["id", "email", "ssn", "secret_token"],
                            "sample_rows": [["1", "alice@corp.test", "123-45-6789", "AKIAIOSFODNN7EXAMPLE"]]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dlp_res.status(), StatusCode::OK);
        let dlp_json = read_json_body(dlp_res).await;
        assert!(dlp_json["dlp_summary"]["masked_cells"].as_u64().unwrap() >= 3);
        let dumped = dlp_json["redacted_sample"].to_string();
        assert!(!dumped.contains("123-45-6789"));
        assert!(!dumped.contains("AKIAIOSFODNN7EXAMPLE"));

        // 2. Analyze session risk bookmarks (PII-sanitized)
        let analyze_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/recordings/rec-m11-risk/analyze")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(analyze_res.status(), StatusCode::OK);
        let analyze_json = read_json_body(analyze_res).await;
        assert_ne!(analyze_json["bookmarks"].as_array().unwrap().len(), 0);
        assert!(!analyze_json.to_string().contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!analyze_json.to_string().contains("alice@corp.test"));

        // 3. Quarterly access review creation & certification
        let ar_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/compliance/access-reviews")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"title":"Q4 Review","quarter":"2026-Q4"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ar_res.status(), StatusCode::CREATED);
        let ar_json = read_json_body(ar_res).await;
        let campaign_id = ar_json["id"].as_str().unwrap().to_owned();
        if let Some(item_id) = ar_json["items"][0]["item_id"].as_str() {
            let dec_res = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .method("POST")
                        .uri(format!(
                            "/api/compliance/access-reviews/{campaign_id}/items/{item_id}"
                        ))
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{"decision":"certified","note":"Verified"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(dec_res.status(), StatusCode::OK);
        }

        // 4. Posture report & Ed25519 signed evidence bundle export + verification
        let posture_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/compliance/posture")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(posture_res.status(), StatusCode::OK);
        let posture = read_json_body(posture_res).await;
        assert_eq!(posture["audit_chain_valid"], true);
        assert_eq!(posture["controls"].as_array().unwrap().len(), 7);

        let bundle_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/compliance/evidence-bundle")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bundle_res.status(), StatusCode::OK);
        let mut signed = read_json_body(bundle_res).await;
        assert_eq!(signed["integrity"]["algorithm"], "Ed25519-SHA256");

        let verify_ok = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/compliance/evidence-bundle/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(signed.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify_ok.status(), StatusCode::OK);
        assert_eq!(read_json_body(verify_ok).await["valid"], true);

        signed["bundle"]["tenant_id"] = serde_json::json!("tampered");
        let verify_bad = app
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/compliance/evidence-bundle/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(signed.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify_bad.status(), StatusCode::OK);
        assert_eq!(read_json_body(verify_bad).await["valid"], false);
    }

    #[tokio::test]
    async fn m12_mcp_proxy_enforces_token_rbac_jit_and_dlp_redaction() {
        let mut state = test_state();
        state.auth = Arc::new(AuthService::new(true, Some("SuperSecret#99".into())));
        let alice = state
            .auth
            .create_user(
                "default",
                "alice@local",
                "Alice",
                "admin",
                "AlicePass#12345",
            )
            .await
            .unwrap();

        let conn = state
            .platform
            .db
            .connect_and_inspect(
                "default",
                &operquay_db::DbConnectRequest {
                    engine: "duckdb".into(),
                    name: "analytics".into(),
                    host: "memory".into(),
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
        state
            .platform
            .db
            .query(
                "default",
                &conn.connection_id,
                "CREATE TABLE customers (id INT, email VARCHAR, ssn VARCHAR)",
                false,
            )
            .await
            .unwrap();
        state
            .platform
            .db
            .query(
                "default",
                &conn.connection_id,
                "INSERT INTO customers VALUES (1, 'alice.pii@secret.test', '123-45-6789')",
                false,
            )
            .await
            .unwrap();

        let app = build_router(state.clone());
        let login_cookie = |email: String, password: String, app_c: Router| async move {
            let res = app_c
                .oneshot(
                    HttpRequest::builder()
                        .method("POST")
                        .uri("/api/auth/login")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({ "email": email, "password": password }).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            res.headers()
                .get(header::SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        };

        let alice_cookie =
            login_cookie("alice@local".into(), "AlicePass#12345".into(), app.clone()).await;
        let admin_cookie =
            login_cookie("admin@local".into(), "SuperSecret#99".into(), app.clone()).await;

        let create_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/mcp/agents")
                    .header("content-type", "application/json")
                    .header(header::COOKIE, &alice_cookie)
                    .body(Body::from(
                        serde_json::json!({
                            "name": "claude-ops",
                            "allowed_tools": ["operquay.db.query"],
                            "require_jit_tools": ["operquay.db.mutate"],
                            "rate_limit_per_min": 20,
                            "ttl_secs": 3600
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_res.status(), StatusCode::CREATED);
        let created = read_json_body(create_res).await;
        let agent_id = created["agent"]["id"].as_str().unwrap().to_owned();
        let token = created["token"].as_str().unwrap().to_owned();
        assert!(token.starts_with("oqmcp_"));
        assert_eq!(created["agent"]["sponsor_user_id"], alice.id);

        // Unauthorized tool denied by RBAC
        let deny_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/mcp/rpc")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": { "name": "operquay.k8s.pods", "arguments": { "cluster": "prod" } }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deny_res.status(), StatusCode::FORBIDDEN);

        // Allowed DB read tool masks PII/SSN automatically
        let query_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/mcp/rpc")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "tools/call",
                            "params": {
                                "name": "operquay.db.query",
                                "arguments": {
                                    "connection_id": conn.connection_id,
                                    "sql": "SELECT id, email, ssn FROM customers"
                                }
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(query_res.status(), StatusCode::OK);
        let q_json = read_json_body(query_res).await;
        let q_text = q_json["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!q_text.contains("alice.pii@secret.test"));
        assert!(!q_text.contains("123-45-6789"));

        // JIT tool initially blocked and opens a JIT request for peer approval
        let jit_block = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/mcp/rpc")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "tools/call",
                            "params": {
                                "name": "operquay.db.mutate",
                                "arguments": {
                                    "connection_id": conn.connection_id,
                                    "sql": "INSERT INTO customers VALUES (2, 'bob@test.io', '000-00-0000')"
                                }
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(jit_block.status(), StatusCode::FORBIDDEN);
        let jit_body = read_json_body(jit_block).await;
        let jit_req_id = jit_body["error"]["data"]["jit_request_id"]
            .as_str()
            .unwrap()
            .to_owned();

        // Admin peer approves JIT grant -> retry succeeds
        let approve_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri(format!("/api/access-requests/{jit_req_id}/approve"))
                    .header("content-type", "application/json")
                    .header(header::COOKIE, &admin_cookie)
                    .body(Body::from(r#"{"note":"approved for MCP write"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(approve_res.status(), StatusCode::OK);

        let jit_ok = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/mcp/rpc")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": 4,
                            "method": "tools/call",
                            "params": {
                                "name": "operquay.db.mutate",
                                "arguments": {
                                    "connection_id": conn.connection_id,
                                    "sql": "INSERT INTO customers VALUES (2, 'bob@test.io', '000-00-0000')"
                                }
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(jit_ok.status(), StatusCode::OK);

        // Revoking agent immediately rejects bearer token
        let rev = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("DELETE")
                    .uri(format!("/api/mcp/agents/{agent_id}"))
                    .header(header::COOKIE, &alice_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rev.status(), StatusCode::OK);

        let post_rev = app
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/mcp/rpc")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(post_rev.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn m12_hybrid_agent_reverse_tunnel_proxies_loopback_tcp_traffic() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut buf).await {
                        if n > 0 {
                            let mut out = b"ECHO:".to_vec();
                            out.extend_from_slice(&buf[..n]);
                            let _ = stream.write_all(&out).await;
                        }
                    }
                });
            }
        });

        let state = test_state();
        state.auth.set_require_auth(false).await;
        let app = build_router(state.clone());

        let srv_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = srv_listener.local_addr().unwrap();
        let srv_task = tokio::spawn(async move {
            let _ = axum::serve(srv_listener, app).await;
        });

        let enroll_res = build_router(state.clone())
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/agents/enroll")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "name": "onprem-dc-01",
                            "targets": [{ "protocol": "tcp", "host": "127.0.0.1", "port": echo_port }]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enroll_res.status(), StatusCode::CREATED);
        let enroll_json = read_json_body(enroll_res).await;
        let agent_id = enroll_json["agent"]["id"].as_str().unwrap().to_owned();
        let raw_tok = enroll_json["enrollment_token"].as_str().unwrap().to_owned();
        assert!(raw_tok.starts_with("oqag_"));

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let agent_cfg = operquay_agent::AgentConfig {
            server_url: format!("ws://{srv_addr}/api/agents/tunnel"),
            enrollment_token: raw_tok,
            name: "onprem-dc-01".into(),
            hostname: "dc01.internal".into(),
            labels: std::collections::HashMap::new(),
            targets: vec![operquay_agent::AgentTargetConfig {
                protocol: "tcp".into(),
                host: "127.0.0.1".into(),
                port: echo_port,
            }],
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
        };
        let agent_task = tokio::spawn(async move {
            let _ = operquay_agent::run_agent_tunnel_once(&agent_cfg, shutdown_rx).await;
        });

        // Wait up to 3s for agent registration over WebSocket
        let mut online = false;
        for _ in 0..30 {
            if state
                .agent_hub
                .list_agents("default")
                .await
                .iter()
                .any(|a| a.id == agent_id && a.online)
            {
                online = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(online, "hybrid agent never came online");

        let dial_res = build_router(state.clone())
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri(format!("/api/agents/{agent_id}/dial-check"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "target": format!("127.0.0.1:{echo_port}"),
                            "payload": "ping-m12"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dial_res.status(), StatusCode::OK);
        let dial_json = read_json_body(dial_res).await;
        assert_eq!(dial_json["ok"], true);
        assert_eq!(dial_json["response"], "ECHO:ping-m12");

        // Non-allowlisted target is blocked by agent
        let denied_dial = build_router(state)
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri(format!("/api/agents/{agent_id}/dial-check"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"target":"127.0.0.1:9"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied_dial.status(), StatusCode::BAD_GATEWAY);

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), agent_task).await;
        srv_task.abort();
        echo_task.abort();
    }

    #[tokio::test]
    async fn m12_multicloud_azure_gcp_connectors_and_access_graph_detect_shadow_admin_and_loops() {
        let mock_cloud = Router::new()
            .route(
                "/sub-az-1/providers/Microsoft.Compute/virtualMachines",
                get(|| async {
                    Json(serde_json::json!({
                        "value": [{ "id": "az-vm-prod-1", "name": "az-prod-bastion", "location": "eastus", "properties": { "provisioningState": "Succeeded" } }]
                    }))
                }),
            )
            .route(
                "/subscriptions/sub-az-1/providers/Microsoft.Compute/virtualMachines",
                get(|| async {
                    Json(serde_json::json!({
                        "value": [{ "id": "az-vm-prod-1", "name": "az-prod-bastion", "location": "eastus", "properties": { "provisioningState": "Succeeded" } }]
                    }))
                }),
            )
            .route(
                "/subscriptions/sub-az-1/providers/Microsoft.ContainerService/managedClusters",
                get(|| async { Json(serde_json::json!({ "value": [] })) }),
            )
            .route(
                "/subscriptions/sub-az-1/providers/Microsoft.Authorization/roleDefinitions",
                get(|| async {
                    Json(serde_json::json!({
                        "value": [{ "id": "az-owner-role", "properties": { "roleName": "Owner", "type": "BuiltInRole" } }]
                    }))
                }),
            )
            .route(
                "/compute/v1/projects/gcp-prod-99/aggregated/instances",
                get(|| async {
                    Json(serde_json::json!({
                        "items": {
                            "zones/us-central1-a": {
                                "instances": [{ "id": "101", "name": "gce-prod-app", "status": "RUNNING" }]
                            }
                        }
                    }))
                }),
            )
            .route(
                "/v1/projects/gcp-prod-99/locations/-/clusters",
                get(|| async { Json(serde_json::json!({ "clusters": [] })) }),
            )
            .route(
                "/v1/projects/gcp-prod-99:getIamPolicy",
                post(|| async {
                    Json(serde_json::json!({
                        "bindings": [{ "role": "roles/owner", "members": ["user:bob@corp.test"] }]
                    }))
                }),
            );

        let cloud_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cloud_addr = cloud_listener.local_addr().unwrap();
        let cloud_task = tokio::spawn(async move {
            let _ = axum::serve(cloud_listener, mock_cloud).await;
        });
        let cloud_base = format!("http://{cloud_addr}");

        let state = test_state();
        state.auth.set_require_auth(false).await;
        let bob = state
            .auth
            .create_user(
                "default",
                "bob@corp.test",
                "Bob",
                "readonly",
                "BobPass#12345",
            )
            .await
            .unwrap();
        // Bind non-admin Bob transitively to a privileged AWS Admin role AND circular cross-account roles
        state
            .aws
            .accounts
            .create_user_binding(
                "default",
                &bob.id,
                "ProdAdmin",
                "arn:aws:iam::111122223333:role/ProdAdmin",
                "",
                "us-east-1",
            )
            .await
            .unwrap();

        let app = build_router(state.clone());

        let az_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/clouds/connectors")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "provider": "azure",
                            "name": "Azure Prod",
                            "account_or_project_id": "sub-az-1",
                            "tenant_or_org_id": "entra-tenant-1",
                            "region": "eastus",
                            "credentials": { "access_token": "tok-az" },
                            "config": {
                                "arm_base_url": cloud_base,
                                "trust_edges": [
                                    { "from": "arn:aws:iam::1111:role/A", "to": "arn:aws:iam::2222:role/B" },
                                    { "from": "arn:aws:iam::2222:role/B", "to": "arn:aws:iam::1111:role/A" }
                                ]
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(az_res.status(), StatusCode::CREATED);
        let az_id = read_json_body(az_res).await["connector"]["id"]
            .as_str()
            .unwrap()
            .to_owned();

        let az_sync = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri(format!("/api/clouds/connectors/{az_id}/sync"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(az_sync.status(), StatusCode::OK);
        assert!(
            read_json_body(az_sync).await["resources_count"]
                .as_u64()
                .unwrap()
                >= 2
        );

        let gcp_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/clouds/connectors")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "provider": "gcp",
                            "name": "GCP Prod",
                            "account_or_project_id": "gcp-prod-99",
                            "region": "us-central1",
                            "credentials": { "access_token": "tok-gcp" },
                            "config": {
                                "compute_base_url": cloud_base,
                                "gke_base_url": cloud_base,
                                "crm_base_url": cloud_base
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(gcp_res.status(), StatusCode::CREATED);
        let gcp_id = read_json_body(gcp_res).await["connector"]["id"]
            .as_str()
            .unwrap()
            .to_owned();

        let gcp_sync = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri(format!("/api/clouds/connectors/{gcp_id}/sync"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(gcp_sync.status(), StatusCode::OK);

        let res_list = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/clouds/resources")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res_list.status(), StatusCode::OK);
        let res_json = read_json_body(res_list).await;
        assert!(res_json["resources"].as_array().unwrap().len() >= 4);

        let graph_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/access-graph")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(graph_res.status(), StatusCode::OK);
        let graph = read_json_body(graph_res).await;
        assert!(graph["summary"]["shadow_admins"].as_u64().unwrap() >= 1);
        assert!(graph["summary"]["trust_loops"].as_u64().unwrap() >= 1);

        let br_res = app
            .oneshot(
                HttpRequest::builder()
                    .uri(format!("/api/access-graph/blast-radius/{}", bob.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(br_res.status(), StatusCode::OK);

        cloud_task.abort();
    }

    #[tokio::test]
    async fn m12_device_trust_policy_blocks_non_compliant_desktop_ticket_until_attested() {
        let state = test_state();
        state.auth.set_require_auth(false).await;
        let app = build_router(state);

        // Enable MDM/EDR policy gating desktop launches
        let put_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("PUT")
                    .uri("/api/device-trust/policy")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "enabled": true,
                            "enforce_on_desktop_launch": true,
                            "require_disk_encryption": true,
                            "require_edr_running": true,
                            "max_os_patch_age_days": 30,
                            "allowed_providers": ["jamf", "crowdstrike"]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_res.status(), StatusCode::OK);

        // Blocked before attestation
        let blocked1 = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/v1/sessions/launch")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"protocol":"rdp","target_host":"win-1.internal"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked1.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            read_json_body(blocked1).await["device_trust_required"],
            true
        );

        // Non-compliant attestation still blocked
        let bad_att = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/device-trust/attest")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "device_id": "macbook-42",
                            "provider": "jamf",
                            "hostname": "eng-mbp",
                            "os_version": "macOS 15.3",
                            "disk_encrypted": false,
                            "edr_running": true,
                            "edr_agent": "CrowdStrike Falcon",
                            "os_patch_age_days": 4
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_att.status(), StatusCode::CREATED);
        assert_eq!(
            read_json_body(bad_att).await["attestation"]["compliant"],
            false
        );

        let blocked2 = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/v1/sessions/launch")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"protocol":"rdp","target_host":"win-1.internal"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked2.status(), StatusCode::FORBIDDEN);

        // Compliant attestation unlocks desktop ticket issuance
        let good_att = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/device-trust/attest")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "device_id": "macbook-42",
                            "provider": "jamf",
                            "hostname": "eng-mbp",
                            "os_version": "macOS 15.3",
                            "disk_encrypted": true,
                            "edr_running": true,
                            "edr_agent": "CrowdStrike Falcon",
                            "os_patch_age_days": 4
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(good_att.status(), StatusCode::CREATED);
        assert_eq!(
            read_json_body(good_att).await["attestation"]["compliant"],
            true
        );

        let ok_launch = app
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/v1/sessions/launch")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"protocol":"rdp","target_host":"win-1.internal"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok_launch.status(), StatusCode::OK);
        assert!(read_json_body(ok_launch).await["ticket"].as_str().is_some());
    }

    #[tokio::test]
    async fn m12_multicloud_secretless_sso_azure_device_code_and_gcp_pkce_roundtrip() {
        let mock_oauth = Router::new()
            .route(
                "/organizations/oauth2/v2.0/devicecode",
                post(|| async {
                    Json(serde_json::json!({
                        "device_code": "dc-live-1",
                        "user_code": "SSO-9988",
                        "verification_uri": "https://microsoft.com/devicelogin",
                        "interval": 1,
                        "expires_in": 600,
                        "message": "Enter SSO-9988"
                    }))
                }),
            )
            .route(
                "/organizations/oauth2/v2.0/token",
                post(|| async {
                    Json(serde_json::json!({
                        "access_token": "az-bearer-tok",
                        "refresh_token": "az-ref-tok",
                        "expires_in": 3600
                    }))
                }),
            )
            .route(
                "/subscriptions",
                get(|| async {
                    Json(serde_json::json!({
                        "value": [{
                            "subscriptionId": "sub-sso-live",
                            "displayName": "Enterprise Dev",
                            "state": "Enabled",
                            "tenantId": "entra-tid-1"
                        }]
                    }))
                }),
            )
            .route(
                "/subscriptions/sub-sso-live/providers/Microsoft.Compute/virtualMachines",
                get(|| async {
                    Json(serde_json::json!({
                        "value": [{
                            "id": "vm-sso-1",
                            "name": "win-sso-host",
                            "location": "eastus",
                            "properties": { "provisioningState": "Succeeded" }
                        }]
                    }))
                }),
            )
            .route(
                "/subscriptions/sub-sso-live/providers/Microsoft.ContainerService/managedClusters",
                get(|| async { Json(serde_json::json!({ "value": [] })) }),
            )
            .route(
                "/subscriptions/sub-sso-live/providers/Microsoft.Authorization/roleDefinitions",
                get(|| async { Json(serde_json::json!({ "value": [] })) }),
            )
            .route(
                "/google/token",
                post(|| async {
                    Json(serde_json::json!({
                        "access_token": "gcp-oauth-tok",
                        "refresh_token": "gcp-oauth-ref",
                        "expires_in": 3600
                    }))
                }),
            )
            .route(
                "/v1/projects",
                get(|| async {
                    Json(serde_json::json!({
                        "projects": [{
                            "projectId": "gcp-sso-live",
                            "name": "GCP Shared Prod",
                            "projectNumber": "777",
                            "lifecycleState": "ACTIVE"
                        }]
                    }))
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock_task = tokio::spawn(async move {
            let _ = axum::serve(listener, mock_oauth).await;
        });
        let base = format!("http://{addr}");

        let state = test_state();
        state.auth.set_require_auth(false).await;
        let app = build_router(state.clone());

        // 1. Azure Entra Device Code SSO HTTP flow (zero client_secret)
        let az_start = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/clouds/azure/sso/start")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "entra_tenant": "organizations",
                            "auth_base_url": base,
                            "arm_base_url": base
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(az_start.status(), StatusCode::OK);
        let az_start_json = read_json_body(az_start).await;
        assert_eq!(az_start_json["user_code"], "SSO-9988");
        let az_flow = az_start_json["flow_id"].as_str().unwrap().to_owned();

        let az_poll = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/clouds/azure/sso/poll")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "flow_id": az_flow }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(az_poll.status(), StatusCode::OK);
        let az_poll_json = read_json_body(az_poll).await;
        assert_eq!(az_poll_json["status"], "authorized");
        assert_eq!(
            az_poll_json["subscriptions"][0]["subscription_id"],
            "sub-sso-live"
        );

        let az_connect = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/clouds/azure/sso/connect")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "flow_id": az_flow,
                            "subscription_id": "sub-sso-live"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(az_connect.status(), StatusCode::OK);
        let az_conn_json = read_json_body(az_connect).await;
        assert_eq!(az_conn_json["connector"]["auth_mode"], "entra_sso");
        assert_eq!(az_conn_json["resources_count"], 1);

        // 2. GCP OAuth2 PKCE HTTP flow (zero Service Account JSON)
        let gcp_start = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/clouds/gcp/sso/start")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "client_id": "gcp-web-cid",
                            "token_url": format!("{base}/google/token"),
                            "crm_base_url": base
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(gcp_start.status(), StatusCode::OK);
        let gcp_start_json = read_json_body(gcp_start).await;
        let gcp_flow = gcp_start_json["flow_id"].as_str().unwrap().to_owned();
        let auth_url = gcp_start_json["authorization_url"].as_str().unwrap();
        let state_param = auth_url
            .split("state=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_owned();

        let cb_res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri(format!(
                        "/api/clouds/gcp/sso/callback?state={state_param}&code=auth-42"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cb_res.status(), StatusCode::OK);

        let gcp_status = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri(format!("/api/clouds/gcp/sso/status?flow_id={gcp_flow}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(gcp_status.status(), StatusCode::OK);
        let gcp_st_json = read_json_body(gcp_status).await;
        assert_eq!(gcp_st_json["status"], "authorized");
        assert_eq!(gcp_st_json["projects"][0]["project_id"], "gcp-sso-live");

        let gcp_connect = app
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/clouds/gcp/sso/connect")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "flow_id": gcp_flow,
                            "project_id": "gcp-sso-live"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(gcp_connect.status(), StatusCode::OK);
        assert_eq!(
            read_json_body(gcp_connect).await["connector"]["auth_mode"],
            "google_sso"
        );

        mock_task.abort();
    }
}
