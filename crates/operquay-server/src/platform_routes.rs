#![forbid(unsafe_code)]

//! Unified Platform Routes (`crates/operquay-server`):
//! Suggest + AEAD DB Viewer, Multi-LLM AI Agent + Safety Guardrails + Catalog,
//! Kubernetes Multi-Cluster + Helm + Cost + CRDs + Recorded WS Exec/Logs + Teleport,
//! PostgreSQL Database Explorer, Port Forwarder + 5-byte WS Multiplexer,
//! CSV/JSON Audit Export, Ed25519 License Entitlements, Recording Policies/Conversion,
//! and Legacy Guacamole/RDP Compat Routes.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message as WsMsg, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, FromRequest, Multipart, Path, Query, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use operquay_auth::policy::perm;
use operquay_aws::accounts::{ambient_aws_credentials, AwsAccessMode};
use operquay_aws::profiles::{load_local_profiles, resolve_profile_credentials};
use operquay_aws::sigv4::AwsCredentials;
use operquay_db::{DbConnectRequest, DbExplorer, DbRowUpdate};
use operquay_forward::{
    decode_mux_frame, encode_mux_frame, ForwardManager, ForwardTunnel, MuxFrameKind,
};
use operquay_k8s::{ConfiguredKubeCluster, K8sClusterRecord, K8sManager, K8sRecordingPolicy};
use operquay_license::LicenseManager;
use operquay_llm::{
    parse_provider_kind, ChatMessage, ChatRequest, LlmGateway, LlmProviderKind, SharedAiConfig,
};
use operquay_recording::{
    canonical_recording_filename, format_epoch_ms_iso8601, transcode_cast_to_mp4,
    transcode_guac_to_mp4, ConversionStatus, RecordingPolicy,
};
use operquay_suggest::SuggestEngine;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify, RwLock};
use tokio_tungstenite::tungstenite::Message as UpstreamWsMsg;
use uuid::Uuid;

use crate::auth_routes::{require_actor, require_any_perm};
use crate::stores::{LaunchMode, TicketLaunchPayload, TICKET_TTL};
use crate::ws::ws_desktop_handler;
use crate::AppState;

/// Unified state holder for E9 subsystems.
pub struct PlatformState {
    pub suggest: Arc<SuggestEngine>,
    pub llm: Arc<LlmGateway>,
    pub k8s: Arc<K8sManager>,
    pub db: Arc<DbExplorer>,
    pub forward: Arc<ForwardManager>,
    pub license: Arc<LicenseManager>,
    pub rec_policies: RwLock<HashMap<String, RecordingPolicy>>,
    pub conversions: RwLock<HashMap<String, ConversionStatus>>,
    pub recording_active: RwLock<HashMap<String, bool>>,
}

impl Default for PlatformState {
    fn default() -> Self {
        let license = match std::env::var("OPERQUAY_LICENSE_PUBLIC_KEY") {
            Ok(pk) if !pk.trim().is_empty() => LicenseManager::new(pk.trim().to_owned()),
            _ => LicenseManager::default(),
        };
        Self {
            suggest: Arc::new(SuggestEngine::new()),
            llm: Arc::new(LlmGateway::new()),
            k8s: Arc::new(K8sManager::new()),
            db: Arc::new(DbExplorer::new()),
            forward: Arc::new(ForwardManager::new()),
            license: Arc::new(license),
            rec_policies: RwLock::new(HashMap::new()),
            conversions: RwLock::new(HashMap::new()),
            recording_active: RwLock::new(HashMap::new()),
        }
    }
}

pub fn platform_router() -> Router<AppState> {
    Router::new()
        .route("/suggest-status", get(suggest_status))
        .route("/api/suggest", post(suggest_query))
        .route(
            "/db-viewer",
            get(db_viewer_get)
                .put(db_viewer_put)
                .delete(db_viewer_delete),
        )
        .route("/ai-agent/context", get(ai_context))
        .route("/ai-agent/models", get(ai_models).post(ai_models))
        .route("/ai-agent/chat", post(ai_chat))
        .route("/api/aws/ai/models", get(ai_models).post(ai_models))
        .route("/api/aws/ai/chat", post(ai_chat))
        .route("/api/ai/catalog", get(get_ai_catalog).put(put_ai_catalog))
        .route("/api/ai/check-safety", post(ai_check_safety))
        .route("/api/k8s/clusters", get(k8s_list_clusters))
        .route("/api/k8s/connect", post(k8s_connect))
        .route("/api/k8s/disconnect/{*cluster}", post(k8s_disconnect))
        .route("/api/k8s/namespaces", get(k8s_namespaces))
        .route("/api/k8s/categories", get(k8s_categories))
        .route("/api/k8s/discover", get(k8s_discover))
        .route("/api/k8s/metrics/pods", get(k8s_pod_metrics))
        .route("/api/k8s/helm/releases", get(k8s_helm_releases))
        .route("/api/k8s/workload-pods", get(k8s_workload_pods))
        .route("/api/k8s/cost", get(k8s_cost))
        .route("/api/k8s/cost/sources", get(k8s_cost_sources))
        .route(
            "/api/k8s/resources/{resource_type}",
            get(k8s_list_resources),
        )
        .route(
            "/api/k8s/resource/{resource_type}/{name}",
            get(k8s_get_resource),
        )
        .route("/api/k8s/actions/{action}", post(k8s_action))
        .route("/api/k8s/crds", get(k8s_list_crds))
        .route("/api/k8s/crds/{name}/resources", get(k8s_crd_resources))
        .route(
            "/api/k8s/kubeconfig/upload",
            post(k8s_kubeconfig_upload).layer(DefaultBodyLimit::max(10 * 1024 * 1024)),
        )
        .route("/api/k8s/kubeconfig/connect", post(k8s_kubeconfig_connect))
        .route(
            "/api/k8s/configured-clusters",
            get(k8s_configured_list).post(k8s_configured_create),
        )
        .route(
            "/api/k8s/configured-clusters/{id}",
            put(k8s_configured_update).delete(k8s_configured_delete),
        )
        .route(
            "/api/k8s/configured-clusters/{id}/recording",
            get(k8s_configured_rec_get).put(k8s_configured_rec_put),
        )
        .route(
            "/api/k8s/clusters/{id}/recording",
            get(k8s_configured_rec_get).put(k8s_configured_rec_put),
        )
        .route(
            "/api/k8s/recording-policy",
            get(k8s_rec_policy_get).put(k8s_rec_policy_put),
        )
        .route(
            "/api/k8s/pods/{namespace}/{name}/logs",
            get(k8s_pod_logs_text),
        )
        .route("/api/k8s/logs", get(k8s_logs_http))
        .route("/ws/k8s/logs", get(ws_k8s_logs))
        .route("/ws/k8s/exec", get(ws_k8s_exec))
        .route("/ws/k8s/attach", get(ws_k8s_attach))
        .route("/api/k8s/teleport/clusters", get(teleport_clusters))
        .route("/api/k8s/teleport/connect", post(teleport_connect))
        .route("/api/teleport/connect", post(teleport_connect))
        .route(
            "/api/teleport/request-credentials",
            post(teleport_request_credentials_handler),
        )
        .route(
            "/api/teleport/local-login",
            post(teleport_local_login_handler),
        )
        .route("/api/teleport/status", get(teleport_status))
        .route("/api/teleport/cancel", post(teleport_cancel))
        .route(
            "/api/teleport/proxy/{*rest}",
            get(teleport_status).post(teleport_connect),
        )
        .route("/callback", get(teleport_status).post(teleport_connect))
        .route("/api/db/connect", post(db_connect))
        .route("/api/db/query", post(db_query))
        .route("/api/db/mutate", post(db_mutate))
        .route("/start-port-forward", post(start_port_forward))
        .route("/stop-port-forward", post(stop_port_forward))
        .route("/active-tunnels", get(active_tunnels))
        .route("/api/aws/forward/start", post(start_port_forward))
        .route("/api/aws/forward/stop", post(stop_port_forward))
        .route("/api/aws/forward/connect", get(ws_forward_connect))
        .route("/audit-log", get(audit_log_list))
        .route("/api/audit/export", get(audit_export))
        .route("/api/license", get(license_status))
        .route("/api/license/redeem", post(license_redeem))
        .route("/v1/public-key", get(license_public_key))
        .route("/health", get(compat_health))
        .route(
            "/vault/{*key}",
            get(vault_get).post(vault_put).delete(vault_delete),
        )
        .route("/legacy", get(legacy_rdp_mode))
        .route("/rdp-client", get(legacy_detect_rdp_clients))
        .route("/recordings", get(legacy_recordings_list))
        .route(
            "/recordings/{id}",
            get(legacy_recording_get).delete(legacy_recording_delete),
        )
        .route("/toggle-recording", post(legacy_toggle_recording))
        .route("/convert-recording", post(legacy_convert_recording))
        .route("/convert-status/{id}", get(legacy_convert_status))
        .route(
            "/api/recording-policy",
            get(rec_policy_get).put(rec_policy_put),
        )
        .route("/api/recording-storage", get(rec_storage_status))
        .route("/rdp-mode", get(legacy_rdp_mode))
        .route("/detect-rdp-clients", get(legacy_detect_rdp_clients))
        .route("/guacamole-sessions", get(legacy_guac_sessions))
        .route("/start-rdp-session", post(legacy_start_rdp))
        .route("/launch-rdp-client", post(legacy_start_rdp))
        .route("/stop-rdp-session", post(legacy_stop_rdp))
        .route("/start-guacamole-rdp", post(legacy_start_rdp))
        .route("/stop-guacamole-rdp", post(legacy_stop_rdp))
        .route("/api/aws/rdp/start", post(legacy_start_rdp))
        .route("/api/aws/rdp/stop", post(legacy_stop_rdp))
        .route("/guac-ws/{*rest}", get(ws_desktop_handler))
        .route("/api/aws/rdp/ws", get(ws_desktop_handler))
}

fn json_err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

// ---------------------------------------------------------------------------
// Suggest & DB Viewer
// ---------------------------------------------------------------------------

async fn suggest_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_actor(&state, &headers).await {
        return *r;
    }
    Json(state.platform.suggest.status().await).into_response()
}

#[derive(Deserialize)]
struct SuggestQueryBody {
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    dir: String,
    #[serde(default = "default_suggest_limit")]
    limit: usize,
    #[serde(default)]
    learn: String,
    #[serde(default)]
    exit_code: i32,
    #[serde(default)]
    output: String,
}

const fn default_suggest_limit() -> usize {
    5
}

async fn suggest_query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SuggestQueryBody>,
) -> Response {
    let (tenant, _) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if !body.learn.trim().is_empty() {
        state
            .platform
            .suggest
            .learn_command(&tenant, &body.learn, body.exit_code, &body.dir)
            .await;
    }
    let suggestions = state
        .platform
        .suggest
        .suggest(&body.prefix, &body.dir, body.limit)
        .await;
    let insights = if body.output.is_empty() {
        Vec::new()
    } else {
        state.platform.suggest.analyze_output(&body.output).await
    };
    Json(serde_json::json!({
        "suggestions": suggestions,
        "insights": insights,
    }))
    .into_response()
}

async fn db_viewer_get(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_any_perm(&state, &headers, &[perm::DB_VIEWER]).await {
        return *r;
    }
    Json(serde_json::json!({
        "db": "suggest",
        "buckets": state.platform.suggest.browse_buckets().await,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct DbViewerPutBody {
    bucket: String,
    key: String,
    value: String,
}

async fn db_viewer_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DbViewerPutBody>,
) -> Response {
    if let Err(r) = require_any_perm(&state, &headers, &[perm::DB_VIEWER]).await {
        return *r;
    }
    match state
        .platform
        .suggest
        .put_bucket_key(&body.bucket, &body.key, &body.value)
        .await
    {
        Ok(()) => Json(serde_json::json!({ "status": "updated" })).into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

#[derive(Deserialize)]
struct DbViewerDelQuery {
    bucket: String,
    #[serde(default)]
    key: String,
}

async fn db_viewer_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DbViewerDelQuery>,
) -> Response {
    if let Err(r) = require_any_perm(&state, &headers, &[perm::DB_VIEWER]).await {
        return *r;
    }
    let ok = if q.key.is_empty() {
        state.platform.suggest.delete_bucket(&q.bucket).await
    } else {
        state
            .platform
            .suggest
            .delete_bucket_key(&q.bucket, &q.key)
            .await
    };
    Json(serde_json::json!({ "deleted": ok })).into_response()
}

// ---------------------------------------------------------------------------
// AI Agent, Catalog & Safety
// ---------------------------------------------------------------------------

async fn ai_context(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::AI_USE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let fleet = state.aws.discovery.fleet_stats(&tenant).await;
    let clusters = state.platform.k8s.list_clusters(&tenant).await.len();
    Json(serde_json::json!({
        "tenant_id": tenant,
        "fleet": fleet,
        "k8s_clusters": clusters,
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
struct AiModelsParams {
    #[serde(default)]
    provider: String,
    #[serde(default)]
    api_key: String,
    #[serde(default)]
    endpoint_url: String,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    binding_id: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    profile: String,
    #[serde(default)]
    access_key_id: String,
    #[serde(default)]
    secret_key: String,
    #[serde(default)]
    secret_access_key: String,
    #[serde(default)]
    session_token: String,
    #[serde(default)]
    auth_mode: String,
}

async fn ai_models(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AiModelsParams>,
    body: axum::body::Bytes,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::AI_USE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let mut p = q;
    if p.endpoint_url.trim().is_empty() && !p.base_url.trim().is_empty() {
        p.endpoint_url = p.base_url.clone();
    }
    if p.secret_key.trim().is_empty() && !p.secret_access_key.trim().is_empty() {
        p.secret_key = p.secret_access_key.clone();
    }
    if !body.is_empty() {
        if let Ok(parsed) = serde_json::from_slice::<AiModelsParams>(&body) {
            if !parsed.provider.is_empty() {
                p.provider = parsed.provider;
            }
            if !parsed.api_key.is_empty() {
                p.api_key = parsed.api_key;
            }
            let parsed_endpoint = if parsed.endpoint_url.is_empty() {
                parsed.base_url
            } else {
                parsed.endpoint_url
            };
            if !parsed_endpoint.is_empty() {
                p.endpoint_url = parsed_endpoint;
            }
            if !parsed.region.is_empty() {
                p.region = parsed.region;
            }
            if !parsed.binding_id.is_empty() {
                p.binding_id = parsed.binding_id;
            }
            if !parsed.account_id.is_empty() {
                p.account_id = parsed.account_id;
            }
            if !parsed.profile.is_empty() {
                p.profile = parsed.profile;
            }
            if !parsed.access_key_id.is_empty() {
                p.access_key_id = parsed.access_key_id;
            }
            let parsed_secret = if parsed.secret_key.is_empty() {
                parsed.secret_access_key
            } else {
                parsed.secret_key
            };
            if !parsed_secret.is_empty() {
                p.secret_key = parsed_secret;
            }
            if !parsed.session_token.is_empty() {
                p.session_token = parsed.session_token;
            }
            if !parsed.auth_mode.is_empty() {
                p.auth_mode = parsed.auth_mode;
            }
        }
    }

    let has_discovery_request = !p.provider.trim().is_empty()
        || !p.api_key.trim().is_empty()
        || !p.binding_id.trim().is_empty()
        || !p.access_key_id.trim().is_empty();

    if !has_discovery_request {
        return Json(serde_json::json!({
            "models": state.platform.llm.get_catalog(&tenant).await,
            "incomplete": false,
        }))
        .into_response();
    }

    let shared = state.platform.llm.get_shared_config(&tenant).await;
    let region = if !p.region.trim().is_empty() {
        p.region.trim().to_owned()
    } else if !shared.region.is_empty() {
        shared.region.clone()
    } else {
        "us-east-1".to_owned()
    };
    let endpoint = if p.endpoint_url.trim().is_empty() {
        shared.endpoint_url.clone()
    } else {
        p.endpoint_url.trim().to_owned()
    };
    let api_key = if p.api_key.trim().is_empty() {
        shared.api_key.clone()
    } else {
        p.api_key.trim().to_owned()
    };

    let mut aws_creds: Option<AwsCredentials> = None;
    let prov_norm = p.provider.trim().to_ascii_lowercase();
    if prov_norm == "bedrock" || prov_norm.is_empty() {
        if !p.binding_id.trim().is_empty() {
            match state
                .aws
                .accounts
                .find_connected_role_lease_for_user(&tenant, &claims.user_id, &p.binding_id)
                .await
            {
                Some(lease) => aws_creds = Some(lease.credentials),
                None => {
                    return json_err(
                        StatusCode::UNAUTHORIZED,
                        "AWS role session expired or not connected; connect an AWS role first",
                    );
                }
            }
        } else if !p.access_key_id.trim().is_empty() && !p.secret_key.trim().is_empty() {
            aws_creds = Some(AwsCredentials {
                access_key_id: p.access_key_id.trim().to_owned(),
                secret_access_key: p.secret_key.trim().to_owned(),
                session_token: (!p.session_token.trim().is_empty())
                    .then(|| p.session_token.trim().to_owned()),
            });
        } else if !p.account_id.trim().is_empty() {
            aws_creds = state
                .aws
                .accounts
                .resolve_account_credentials(&tenant, p.account_id.trim())
                .await
                .ok();
        } else if !p.profile.trim().is_empty()
            && state.aws.accounts.mode().await != AwsAccessMode::User
        {
            let local = load_local_profiles();
            if let Some(prof) = local.into_iter().find(|lp| lp.name == p.profile.trim()) {
                let http = state.aws.discovery.http_client().clone();
                aws_creds = resolve_profile_credentials(&prof, &http).await;
            }
        } else if !shared.binding_id.trim().is_empty() {
            aws_creds = state
                .aws
                .accounts
                .find_connected_role_lease_for_user(&tenant, &claims.user_id, &shared.binding_id)
                .await
                .map(|l| l.credentials);
        } else if !shared.account_id.is_empty() {
            aws_creds = state
                .aws
                .accounts
                .resolve_account_credentials(&tenant, &shared.account_id)
                .await
                .ok();
        } else if state.aws.accounts.mode().await != AwsAccessMode::User {
            aws_creds = ambient_aws_credentials();
        }
    }

    match state
        .platform
        .llm
        .discover_models(
            &p.provider,
            &api_key,
            &endpoint,
            &region,
            aws_creds.as_ref(),
        )
        .await
    {
        Ok((models, incomplete)) => Json(serde_json::json!({
            "models": models,
            "incomplete": incomplete,
        }))
        .into_response(),
        Err(e) => {
            if aws_creds.is_none() && api_key.is_empty() && prov_norm == "bedrock" {
                return Json(serde_json::json!({
                    "models": state.platform.llm.get_catalog(&tenant).await,
                    "incomplete": true,
                    "warning": e,
                }))
                .into_response();
            }
            json_err(StatusCode::BAD_GATEWAY, e)
        }
    }
}

async fn get_ai_catalog(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::AI_USE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(
        state
            .platform
            .llm
            .get_shared_config(&tenant)
            .await
            .to_public_json(),
    )
    .into_response()
}

#[derive(Deserialize, Default)]
struct PutAiCatalogBody {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    account_label: String,
    #[serde(default)]
    binding_id: String,
    #[serde(default)]
    endpoint_url: String,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    api_key: String,
    #[serde(default)]
    models: Vec<operquay_llm::AiCatalogModel>,
}

async fn put_ai_catalog(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PutAiCatalogBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::AI_CATALOG_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let endpoint_url = if body.endpoint_url.trim().is_empty() {
        body.base_url.trim().to_owned()
    } else {
        body.endpoint_url.trim().to_owned()
    };
    let enabled = body
        .enabled
        .unwrap_or_else(|| !body.models.is_empty() || !body.model.trim().is_empty());
    let cfg = SharedAiConfig {
        enabled,
        provider: body.provider,
        model: body.model,
        region: body.region,
        account_id: body.account_id,
        account_label: body.account_label,
        binding_id: body.binding_id,
        endpoint_url,
        base_url: String::new(),
        api_key: body.api_key,
        models: body.models,
    };
    let saved = state.platform.llm.set_shared_config(&tenant, cfg).await;
    Json(saved.to_public_json()).into_response()
}

#[derive(Deserialize, Default)]
struct FlexibleAiChatBody {
    #[serde(default)]
    provider: Option<LlmProviderKind>,
    #[serde(default)]
    model: String,
    #[serde(default)]
    endpoint_url: String,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    api_key: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    system: String,
    #[serde(default)]
    messages: Vec<ChatMessage>,
    #[serde(default)]
    message: String,
    #[serde(default)]
    prompt: String,
    #[serde(default)]
    max_tokens: Option<u32>,
    #[serde(default)]
    binding_id: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    instance_id: String,
    #[serde(default)]
    instance_name: String,
    #[serde(default)]
    access_key_id: String,
    #[serde(default)]
    secret_key: String,
    #[serde(default)]
    secret_access_key: String,
    #[serde(default)]
    session_token: String,
    #[serde(default)]
    profile: String,
    #[serde(default)]
    stream: Option<bool>,
}

fn sse_ai_event(payload: &serde_json::Value) -> Event {
    Event::default().data(payload.to_string())
}

async fn ai_chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<FlexibleAiChatBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::AI_USE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };

    let explicit_provider = body.provider;
    let wants_sse = explicit_provider.is_none()
        || body.stream == Some(true)
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|a| a.contains("text/event-stream"));

    let prefs = state
        .aws
        .accounts
        .get_preferences(&tenant, &claims.user_id)
        .await;
    let shared = state.platform.llm.get_shared_config(&tenant).await;

    let pref_str = |k: &str| -> String {
        prefs
            .extra
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_owned()
    };

    let catalog_match = shared
        .models
        .iter()
        .find(|m| !body.model.is_empty() && (m.id == body.model || m.model_id == body.model))
        .cloned();

    let resolved_provider = explicit_provider
        .or_else(|| catalog_match.as_ref().map(|m| m.provider))
        .or_else(|| parse_provider_kind(&pref_str("ai_provider")))
        .or_else(|| parse_provider_kind(&shared.provider))
        .unwrap_or_else(|| {
            if std::env::var("OPENAI_API_KEY").is_ok_and(|v| !v.trim().is_empty()) {
                LlmProviderKind::Openai
            } else if std::env::var("ANTHROPIC_API_KEY").is_ok_and(|v| !v.trim().is_empty()) {
                LlmProviderKind::Anthropic
            } else if std::env::var("GEMINI_API_KEY").is_ok_and(|v| !v.trim().is_empty()) {
                LlmProviderKind::Gemini
            } else {
                LlmProviderKind::Bedrock
            }
        });

    let model = if !body.model.trim().is_empty() {
        catalog_match
            .as_ref()
            .map(|m| m.model_id.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| body.model.trim().to_owned())
    } else if !shared.model.trim().is_empty() {
        shared.model.clone()
    } else {
        pref_str("ai_model")
    };

    let region = if !body.region.trim().is_empty() {
        body.region.trim().to_owned()
    } else if !shared.region.trim().is_empty() {
        shared.region.clone()
    } else {
        let pr = pref_str("ai_region");
        if pr.is_empty() {
            "us-east-1".to_owned()
        } else {
            pr
        }
    };

    let endpoint_url = if !body.endpoint_url.trim().is_empty() {
        body.endpoint_url.trim().to_owned()
    } else if !body.base_url.trim().is_empty() {
        body.base_url.trim().to_owned()
    } else if !shared.endpoint_url.trim().is_empty() {
        shared.endpoint_url.clone()
    } else {
        pref_str("ai_base_url")
    };

    let api_key = if !body.api_key.trim().is_empty() {
        body.api_key.trim().to_owned()
    } else if !shared.api_key.trim().is_empty() {
        shared.api_key.clone()
    } else {
        let pk = pref_str("ai_api_key");
        if pk.is_empty() {
            match resolved_provider {
                LlmProviderKind::Openai => std::env::var("OPENAI_API_KEY").unwrap_or_default(),
                LlmProviderKind::Anthropic => {
                    std::env::var("ANTHROPIC_API_KEY").unwrap_or_default()
                }
                LlmProviderKind::Gemini => std::env::var("GEMINI_API_KEY").unwrap_or_default(),
                _ => String::new(),
            }
        } else {
            pk
        }
    };

    let mut messages = body.messages;
    if messages.is_empty() {
        let txt = if body.message.trim().is_empty() {
            body.prompt.trim()
        } else {
            body.message.trim()
        };
        if !txt.is_empty() {
            messages.push(ChatMessage {
                role: "user".to_owned(),
                content: txt.to_owned(),
            });
        }
    }

    let system = if body.system.trim().is_empty() {
        let ctx_inst = if !body.instance_name.is_empty() {
            format!(
                " Target host: {} ({}).",
                body.instance_name, body.instance_id
            )
        } else if !body.instance_id.is_empty() {
            format!(" Target instance: {}.", body.instance_id)
        } else {
            let _ = &body.session_id;
            String::new()
        };
        format!(
            "You are Oi, the AI infrastructure assistant inside Operquay. Be concise and provide safe, read-only or explicitly confirmed commands in fenced code blocks.{ctx_inst}"
        )
    } else {
        body.system
    };

    let body_secret_key = if body.secret_key.trim().is_empty() {
        body.secret_access_key.trim()
    } else {
        body.secret_key.trim()
    };
    let mut aws_creds: Option<AwsCredentials> = None;
    if resolved_provider == LlmProviderKind::Bedrock {
        if !body.access_key_id.trim().is_empty() && !body_secret_key.is_empty() {
            aws_creds = Some(AwsCredentials {
                access_key_id: body.access_key_id.trim().to_owned(),
                secret_access_key: body_secret_key.to_owned(),
                session_token: (!body.session_token.trim().is_empty())
                    .then(|| body.session_token.trim().to_owned()),
            });
        } else if !body.binding_id.trim().is_empty() {
            aws_creds = state
                .aws
                .accounts
                .find_connected_role_lease_for_user(&tenant, &claims.user_id, &body.binding_id)
                .await
                .map(|l| l.credentials);
        } else if !body.account_id.trim().is_empty() {
            aws_creds = state
                .aws
                .accounts
                .resolve_account_credentials(&tenant, body.account_id.trim())
                .await
                .ok();
        } else if !shared.binding_id.trim().is_empty() {
            aws_creds = state
                .aws
                .accounts
                .find_connected_role_lease_for_user(&tenant, &claims.user_id, &shared.binding_id)
                .await
                .map(|l| l.credentials);
        } else if !shared.account_id.trim().is_empty() {
            aws_creds = state
                .aws
                .accounts
                .resolve_account_credentials(&tenant, shared.account_id.trim())
                .await
                .ok();
        } else if !body.profile.trim().is_empty()
            && state.aws.accounts.mode().await != AwsAccessMode::User
        {
            let local = load_local_profiles();
            if let Some(prof) = local.into_iter().find(|lp| lp.name == body.profile.trim()) {
                let http = state.aws.discovery.http_client().clone();
                aws_creds = resolve_profile_credentials(&prof, &http).await;
            }
        } else if state.aws.accounts.mode().await != AwsAccessMode::User {
            aws_creds = ambient_aws_credentials();
        }
    }

    let req = ChatRequest {
        provider: resolved_provider,
        model,
        endpoint_url,
        api_key,
        region,
        system,
        messages,
        max_tokens: body.max_tokens.unwrap_or(1024),
    };

    if !wants_sse {
        return match state.platform.llm.chat(&req, aws_creds.as_ref()).await {
            Ok(resp) => {
                state.telemetry.record_ai_request("default", "ok");
                Json(resp).into_response()
            }
            Err(e) => {
                state.telemetry.record_ai_request("default", "error");
                json_err(StatusCode::BAD_GATEWAY, e)
            }
        };
    }

    let events = match state.platform.llm.chat(&req, aws_creds.as_ref()).await {
        Ok(resp) => {
            state.telemetry.record_ai_request("default", "ok");
            let mut evs = vec![Ok::<Event, std::convert::Infallible>(sse_ai_event(
                &serde_json::json!({
                    "type": "assistant_text",
                    "text": resp.reply,
                    "content": resp.reply,
                }),
            ))];
            for cmd in resp.proposed_commands {
                evs.push(Ok(sse_ai_event(&serde_json::json!({
                    "type": "command_proposal",
                    "command": cmd.command,
                    "blocked": cmd.blocked,
                    "reason": cmd.reason,
                    "explanation": cmd.reason,
                }))));
            }
            evs.push(Ok(sse_ai_event(&serde_json::json!({ "type": "done" }))));
            evs
        }
        Err(e) => {
            state.telemetry.record_ai_request("default", "error");
            vec![
                Ok(sse_ai_event(&serde_json::json!({
                    "type": "error",
                    "error": e,
                    "message": e,
                }))),
                Ok(sse_ai_event(&serde_json::json!({ "type": "done" }))),
            ]
        }
    };

    Sse::new(futures_util::stream::iter(events))
        .keep_alive(KeepAlive::default())
        .into_response()
}

#[derive(Deserialize)]
struct SafetyBody {
    command: String,
}

async fn ai_check_safety(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SafetyBody>,
) -> Response {
    if let Err(r) = require_any_perm(&state, &headers, &[perm::AI_USE]).await {
        return *r;
    }
    let v = state.platform.llm.safety().check_command(&body.command);
    Json(serde_json::json!({
        "blocked": v.blocked,
        "reason": v.reason,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Kubernetes, Helm, Cost, CRDs, Kubeconfig & Teleport
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct K8sClustersQuery {
    #[serde(default, alias = "accountId")]
    account_id: String,
    #[serde(default)]
    binding_id: String,
    #[serde(default = "default_region")]
    region: String,
}

async fn resolve_k8s_aws_creds(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    binding_id: &str,
    account_id: &str,
) -> Result<Option<AwsCredentials>, Box<Response>> {
    if !binding_id.trim().is_empty() {
        return match state
            .aws
            .accounts
            .find_connected_role_lease_for_user(tenant, user_id, binding_id.trim())
            .await
        {
            Some(lease) => Ok(Some(lease.credentials)),
            None => Err(Box::new(json_err(
                StatusCode::UNAUTHORIZED,
                "AWS role session expired or not connected",
            ))),
        };
    }
    if !account_id.trim().is_empty() {
        return match state
            .aws
            .accounts
            .resolve_account_credentials(tenant, account_id.trim())
            .await
        {
            Ok(c) => Ok(Some(c)),
            Err(e) => Err(Box::new(json_err(StatusCode::BAD_REQUEST, e.to_string()))),
        };
    }
    Ok(None)
}

async fn k8s_list_clusters(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<K8sClustersQuery>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::K8S_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let creds = match resolve_k8s_aws_creds(
        &state,
        &tenant,
        &claims.user_id,
        &q.binding_id,
        &q.account_id,
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Some(c) = creds {
        match state
            .platform
            .k8s
            .discover_eks_clusters(&tenant, &q.region, &c)
            .await
        {
            Ok(list) => {
                let enriched: Vec<serde_json::Value> = list
                    .into_iter()
                    .map(|rec| {
                        serde_json::json!({
                            "id": rec.id,
                            "name": rec.name,
                            "source": rec.source,
                            "api_server": rec.api_server,
                            "endpoint": rec.api_server,
                            "connected": rec.connected,
                            "recording_enabled": rec.recording_enabled,
                            "region": rec.region,
                        })
                    })
                    .collect();
                return Json(enriched).into_response();
            }
            Err(e) => return json_err(StatusCode::BAD_GATEWAY, e),
        }
    }
    Json(state.platform.k8s.list_clusters(&tenant).await).into_response()
}

#[derive(Deserialize)]
struct K8sClusterTarget {
    #[serde(default, alias = "name", alias = "cluster_name")]
    cluster: String,
    #[serde(default, alias = "accountId")]
    account_id: String,
    #[serde(default)]
    binding_id: String,
    #[serde(default = "default_region")]
    region: String,
}

async fn k8s_connect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<K8sClusterTarget>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::K8S_CONNECT]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let creds = match resolve_k8s_aws_creds(
        &state,
        &tenant,
        &claims.user_id,
        &body.binding_id,
        &body.account_id,
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return *r,
    };

    if let Some(ref c) = creds {
        if let Ok(list) = state
            .platform
            .k8s
            .discover_eks_clusters(&tenant, &body.region, c)
            .await
        {
            if let Some(found) = list
                .into_iter()
                .find(|r| r.id == body.cluster || r.name == body.cluster)
            {
                let token =
                    operquay_aws::sigv4::presign_eks_token(&found.name, &found.region, c, None)
                        .unwrap_or_default();
                if let Some(updated) = state
                    .platform
                    .k8s
                    .refresh_cluster_token(&tenant, &found.id, token)
                    .await
                {
                    state.telemetry.record_k8s_request("connect", "ok");
                    return Json(serde_json::json!({
                        "cluster_id": updated.id,
                        "id": updated.id,
                        "name": updated.name,
                        "region": updated.region,
                        "source": updated.source,
                        "api_server": updated.api_server,
                        "status": "connected",
                        "connected": true,
                    }))
                    .into_response();
                }
            }
        }
    }

    if let Some(c) = state
        .platform
        .k8s
        .set_connected(&tenant, &body.cluster, true)
        .await
    {
        state.telemetry.record_k8s_request("connect", "ok");
        Json(serde_json::json!({
            "cluster_id": c.id,
            "id": c.id,
            "name": c.name,
            "region": c.region,
            "source": c.source,
            "api_server": c.api_server,
            "status": "connected",
            "connected": true,
        }))
        .into_response()
    } else {
        state.telemetry.record_k8s_request("connect", "not_found");
        json_err(StatusCode::NOT_FOUND, "cluster not found")
    }
}

async fn k8s_disconnect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(cluster): Path<String>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_CONNECT]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .platform
        .k8s
        .set_connected(&tenant, &cluster, false)
        .await
    {
        Some(c) => Json(c).into_response(),
        None => json_err(StatusCode::NOT_FOUND, "cluster not found"),
    }
}

#[derive(Deserialize)]
struct K8sQuery {
    #[serde(default)]
    cluster: String,
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    pod: String,
    #[serde(default)]
    container: String,
    #[serde(default)]
    command: String,
    #[serde(default, alias = "tailLines", alias = "tail")]
    tail_lines: Option<u32>,
    #[serde(default)]
    previous: bool,
    #[serde(default)]
    follow: Option<bool>,
    #[serde(default)]
    uid: String,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    kind: String,
}

fn parse_k8s_namespaces(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "*")
        .map(ToOwned::to_owned)
        .collect()
}

async fn k8s_namespaces(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<K8sQuery>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .platform
        .k8s
        .kube_get_json(&tenant, &q.cluster, "api/v1/namespaces")
        .await
    {
        Ok(val) => {
            let names: Vec<String> = val["items"].as_array().map_or_default(|arr| {
                arr.iter()
                    .filter_map(|item| item["metadata"]["name"].as_str().map(ToOwned::to_owned))
                    .collect()
            });
            Json(names).into_response()
        }
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

fn k8s_cat_res(
    name: &str,
    kind: &str,
    group: &str,
    version: &str,
    namespaced: bool,
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "kind": kind,
        "group": group,
        "version": version,
        "namespaced": namespaced,
    })
}

async fn k8s_categories(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_any_perm(&state, &headers, &[perm::K8S_READ]).await {
        return *r;
    }
    Json(serde_json::json!([
        {
            "name": "Workloads",
            "resources": [
                k8s_cat_res("pods", "Pod", "", "v1", true),
                k8s_cat_res("deployments", "Deployment", "apps", "v1", true),
                k8s_cat_res("daemonsets", "DaemonSet", "apps", "v1", true),
                k8s_cat_res("statefulsets", "StatefulSet", "apps", "v1", true),
                k8s_cat_res("replicasets", "ReplicaSet", "apps", "v1", true),
                k8s_cat_res("replicationcontrollers", "ReplicationController", "", "v1", true),
                k8s_cat_res("jobs", "Job", "batch", "v1", true),
                k8s_cat_res("cronjobs", "CronJob", "batch", "v1", true),
            ]
        },
        {
            "name": "Config",
            "resources": [
                k8s_cat_res("configmaps", "ConfigMap", "", "v1", true),
                k8s_cat_res("secrets", "Secret", "", "v1", true),
                k8s_cat_res("resourcequotas", "ResourceQuota", "", "v1", true),
                k8s_cat_res("limitranges", "LimitRange", "", "v1", true),
                k8s_cat_res("horizontalpodautoscalers", "HorizontalPodAutoscaler", "autoscaling", "v2", true),
                k8s_cat_res("poddisruptionbudgets", "PodDisruptionBudget", "policy", "v1", true),
                k8s_cat_res("priorityclasses", "PriorityClass", "scheduling.k8s.io", "v1", false),
                k8s_cat_res("runtimeclasses", "RuntimeClass", "node.k8s.io", "v1", false),
                k8s_cat_res("leases", "Lease", "coordination.k8s.io", "v1", true),
                k8s_cat_res("mutatingwebhookconfigurations", "MutatingWebhookConfiguration", "admissionregistration.k8s.io", "v1", false),
                k8s_cat_res("validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "admissionregistration.k8s.io", "v1", false),
            ]
        },
        {
            "name": "Network",
            "resources": [
                k8s_cat_res("services", "Service", "", "v1", true),
                k8s_cat_res("endpoints", "Endpoints", "", "v1", true),
                k8s_cat_res("endpointslices", "EndpointSlice", "discovery.k8s.io", "v1", true),
                k8s_cat_res("ingresses", "Ingress", "networking.k8s.io", "v1", true),
                k8s_cat_res("ingressclasses", "IngressClass", "networking.k8s.io", "v1", false),
                k8s_cat_res("networkpolicies", "NetworkPolicy", "networking.k8s.io", "v1", true),
            ]
        },
        {
            "name": "Storage",
            "resources": [
                k8s_cat_res("persistentvolumeclaims", "PersistentVolumeClaim", "", "v1", true),
                k8s_cat_res("persistentvolumes", "PersistentVolume", "", "v1", false),
                k8s_cat_res("storageclasses", "StorageClass", "storage.k8s.io", "v1", false),
            ]
        },
        {
            "name": "Cluster",
            "resources": [
                k8s_cat_res("nodes", "Node", "", "v1", false),
                k8s_cat_res("namespaces", "Namespace", "", "v1", false),
                k8s_cat_res("events", "Event", "", "v1", true),
            ]
        },
        {
            "name": "Access Control",
            "resources": [
                k8s_cat_res("serviceaccounts", "ServiceAccount", "", "v1", true),
                k8s_cat_res("roles", "Role", "rbac.authorization.k8s.io", "v1", true),
                k8s_cat_res("rolebindings", "RoleBinding", "rbac.authorization.k8s.io", "v1", true),
                k8s_cat_res("clusterroles", "ClusterRole", "rbac.authorization.k8s.io", "v1", false),
                k8s_cat_res("clusterrolebindings", "ClusterRoleBinding", "rbac.authorization.k8s.io", "v1", false),
            ]
        }
    ]))
    .into_response()
}

async fn k8s_discover(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<K8sQuery>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let group = q.group.trim().trim_start_matches('/');
    if group.is_empty() {
        return match state
            .platform
            .k8s
            .kube_get_json(&tenant, &q.cluster, "api/v1")
            .await
        {
            Ok(val) => Json(val).into_response(),
            Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
        };
    }

    let group_path = format!("apis/{group}");
    let group_meta = match state
        .platform
        .k8s
        .kube_get_json(&tenant, &q.cluster, &group_path)
        .await
    {
        Ok(v) => v,
        Err(e) if e.contains("404") => return Json(serde_json::json!([])).into_response(),
        Err(e) => return json_err(StatusCode::BAD_GATEWAY, e),
    };
    let ver = group_meta["preferredVersion"]["version"]
        .as_str()
        .or_else(|| group_meta["versions"][0]["version"].as_str())
        .unwrap_or("v1");
    let ver_path = format!("apis/{group}/{ver}");
    match state
        .platform
        .k8s
        .kube_get_json(&tenant, &q.cluster, &ver_path)
        .await
    {
        Ok(val) => {
            let list: Vec<serde_json::Value> = val["resources"].as_array().map_or_default(|arr| {
                arr.iter()
                    .filter_map(|r| {
                        let name = r["name"].as_str()?;
                        if name.contains('/') {
                            return None;
                        }
                        let kind = r["kind"].as_str().unwrap_or(name);
                        let namespaced = r["namespaced"].as_bool().unwrap_or(true);
                        Some(serde_json::json!({
                            "name": name,
                            "kind": kind,
                            "group": group,
                            "version": ver,
                            "namespaced": namespaced,
                        }))
                    })
                    .collect()
            });
            Json(list).into_response()
        }
        Err(e) if e.contains("404") => Json(serde_json::json!([])).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

async fn k8s_pod_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<K8sQuery>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let namespaces = parse_k8s_namespaces(&q.namespace);
    if namespaces.len() <= 1 {
        let path = if namespaces.is_empty() {
            "apis/metrics.k8s.io/v1beta1/pods".to_owned()
        } else {
            format!(
                "apis/metrics.k8s.io/v1beta1/namespaces/{}/pods",
                operquay_aws::sigv4::uri_encode(&namespaces[0], true)
            )
        };
        return match state
            .platform
            .k8s
            .kube_get_json(&tenant, &q.cluster, &path)
            .await
        {
            Ok(val) => {
                let items = val["items"].as_array().map_or(&[][..], Vec::as_slice);
                Json(operquay_k8s::normalize_pod_metrics_items(items)).into_response()
            }
            Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
        };
    }

    let mut all_items = Vec::new();
    let mut last_err = None;
    let mut any_ok = false;
    for ns in namespaces {
        let path = format!(
            "apis/metrics.k8s.io/v1beta1/namespaces/{}/pods",
            operquay_aws::sigv4::uri_encode(&ns, true)
        );
        match state
            .platform
            .k8s
            .kube_get_json(&tenant, &q.cluster, &path)
            .await
        {
            Ok(val) => {
                any_ok = true;
                if let Some(items) = val["items"].as_array() {
                    all_items.extend(items.iter().cloned());
                }
            }
            Err(e) => last_err = Some(e),
        }
    }
    if !any_ok {
        return json_err(
            StatusCode::BAD_GATEWAY,
            last_err.unwrap_or_else(|| "pod metrics unavailable".to_owned()),
        );
    }
    Json(operquay_k8s::normalize_pod_metrics_items(&all_items)).into_response()
}

async fn k8s_helm_releases(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<K8sQuery>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .platform
        .k8s
        .helm_releases(&tenant, &q.cluster, &q.namespace)
        .await
    {
        Ok(releases) => Json(releases).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

fn json_item_owned_by(
    item: &serde_json::Value,
    owner_kind: &str,
    owner_name: &str,
    owner_uid: &str,
) -> bool {
    let Some(refs) = item["metadata"]["ownerReferences"].as_array() else {
        return false;
    };
    refs.iter().any(|r| {
        if !owner_uid.is_empty() && r["uid"].as_str() == Some(owner_uid) {
            return true;
        }
        r["kind"].as_str() == Some(owner_kind) && r["name"].as_str() == Some(owner_name)
    })
}

async fn k8s_workload_pods(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<K8sQuery>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let ns = if q.namespace.trim().is_empty() {
        "default"
    } else {
        q.namespace.trim()
    };
    let pods_path = format!(
        "api/v1/namespaces/{}/pods",
        operquay_aws::sigv4::uri_encode(ns, true)
    );
    let pods_val = match state
        .platform
        .k8s
        .kube_get_json(&tenant, &q.cluster, &pods_path)
        .await
    {
        Ok(v) => v,
        Err(e) => return json_err(StatusCode::BAD_GATEWAY, e),
    };
    let all_pods = pods_val["items"].as_array().cloned().unwrap_or_default();
    if q.name.trim().is_empty() {
        return Json(all_pods).into_response();
    }

    let kind = q.kind.trim();
    let owner_name = q.name.trim();
    let owner_uid = q.uid.trim();

    let filtered: Vec<serde_json::Value> = if kind.eq_ignore_ascii_case("Deployment") {
        let rs_path = format!(
            "apis/apps/v1/namespaces/{}/replicasets",
            operquay_aws::sigv4::uri_encode(ns, true)
        );
        let rs_ids: Vec<(String, String)> = state
            .platform
            .k8s
            .kube_get_json(&tenant, &q.cluster, &rs_path)
            .await
            .ok()
            .and_then(|v| v["items"].as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter(|rs| json_item_owned_by(rs, "Deployment", owner_name, owner_uid))
            .map(|rs| {
                (
                    rs["metadata"]["name"].as_str().unwrap_or("").to_owned(),
                    rs["metadata"]["uid"].as_str().unwrap_or("").to_owned(),
                )
            })
            .collect();
        all_pods
            .into_iter()
            .filter(|pod| {
                rs_ids
                    .iter()
                    .any(|(rs_name, rs_uid)| json_item_owned_by(pod, "ReplicaSet", rs_name, rs_uid))
            })
            .collect()
    } else if kind.eq_ignore_ascii_case("CronJob") {
        let jobs_path = format!(
            "apis/batch/v1/namespaces/{}/jobs",
            operquay_aws::sigv4::uri_encode(ns, true)
        );
        let job_ids: Vec<(String, String)> = state
            .platform
            .k8s
            .kube_get_json(&tenant, &q.cluster, &jobs_path)
            .await
            .ok()
            .and_then(|v| v["items"].as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter(|job| json_item_owned_by(job, "CronJob", owner_name, owner_uid))
            .map(|job| {
                (
                    job["metadata"]["name"].as_str().unwrap_or("").to_owned(),
                    job["metadata"]["uid"].as_str().unwrap_or("").to_owned(),
                )
            })
            .collect();
        all_pods
            .into_iter()
            .filter(|pod| {
                job_ids
                    .iter()
                    .any(|(j_name, j_uid)| json_item_owned_by(pod, "Job", j_name, j_uid))
            })
            .collect()
    } else {
        all_pods
            .into_iter()
            .filter(|pod| json_item_owned_by(pod, kind, owner_name, owner_uid))
            .collect()
    };

    Json(filtered).into_response()
}

async fn k8s_cost(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<K8sQuery>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let pods = state
        .platform
        .k8s
        .kube_get_json(&tenant, &q.cluster, "api/v1/pods")
        .await
        .unwrap_or_else(|_| serde_json::json!({ "items": [] }));
    let count = pods["items"].as_array().map_or(0, Vec::len);
    Json(serde_json::json!({
        "cluster": q.cluster,
        "pod_count": count,
        "estimated_monthly_usd": (count as f64) * 18.5,
        "currency": "USD",
    }))
    .into_response()
}

async fn k8s_cost_sources(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_any_perm(&state, &headers, &[perm::K8S_READ]).await {
        return *r;
    }
    Json(serde_json::json!({
        "sources": ["eks-resource-requests", "metrics-server"],
    }))
    .into_response()
}

fn resource_api_path_with_gv(
    res_type: &str,
    group: &str,
    version: &str,
    namespace: &str,
    name: Option<&str>,
) -> String {
    let base = if !group.trim().is_empty() {
        let ver = if version.trim().is_empty() {
            "v1"
        } else {
            version.trim()
        };
        format!("apis/{}/{ver}", group.trim().trim_matches('/'))
    } else if !version.trim().is_empty() && version.trim() == "v1" {
        match res_type {
            "deployments" | "statefulsets" | "daemonsets" | "replicasets" => {
                "apis/apps/v1".to_owned()
            }
            "jobs" | "cronjobs" => "apis/batch/v1".to_owned(),
            "ingresses" | "ingressclasses" | "networkpolicies" => {
                "apis/networking.k8s.io/v1".to_owned()
            }
            "roles" | "rolebindings" | "clusterroles" | "clusterrolebindings" => {
                "apis/rbac.authorization.k8s.io/v1".to_owned()
            }
            "storageclasses" => "apis/storage.k8s.io/v1".to_owned(),
            "horizontalpodautoscalers" => "apis/autoscaling/v2".to_owned(),
            "poddisruptionbudgets" => "apis/policy/v1".to_owned(),
            "priorityclasses" => "apis/scheduling.k8s.io/v1".to_owned(),
            "runtimeclasses" => "apis/node.k8s.io/v1".to_owned(),
            "leases" => "apis/coordination.k8s.io/v1".to_owned(),
            "endpointslices" => "apis/discovery.k8s.io/v1".to_owned(),
            "mutatingwebhookconfigurations"
            | "validatingwebhookconfigurations"
            | "validatingadmissionpolicies"
            | "validatingadmissionpolicybindings" => {
                "apis/admissionregistration.k8s.io/v1".to_owned()
            }
            "customresourcedefinitions" => "apis/apiextensions.k8s.io/v1".to_owned(),
            _ => "api/v1".to_owned(),
        }
    } else {
        match res_type {
            "deployments" | "statefulsets" | "daemonsets" | "replicasets" => "apis/apps/v1",
            "jobs" | "cronjobs" => "apis/batch/v1",
            "ingresses" | "ingressclasses" | "networkpolicies" => "apis/networking.k8s.io/v1",
            "roles" | "rolebindings" | "clusterroles" | "clusterrolebindings" => {
                "apis/rbac.authorization.k8s.io/v1"
            }
            "storageclasses" => "apis/storage.k8s.io/v1",
            "horizontalpodautoscalers" => "apis/autoscaling/v2",
            "poddisruptionbudgets" => "apis/policy/v1",
            "priorityclasses" => "apis/scheduling.k8s.io/v1",
            "runtimeclasses" => "apis/node.k8s.io/v1",
            "leases" => "apis/coordination.k8s.io/v1",
            "endpointslices" => "apis/discovery.k8s.io/v1",
            "mutatingwebhookconfigurations"
            | "validatingwebhookconfigurations"
            | "validatingadmissionpolicies"
            | "validatingadmissionpolicybindings" => "apis/admissionregistration.k8s.io/v1",
            "deviceclasses" | "resourceclaims" | "resourceclaimtemplates" | "resourceslices" => {
                "apis/resource.k8s.io/v1beta1"
            }
            "customresourcedefinitions" => "apis/apiextensions.k8s.io/v1",
            _ => "api/v1",
        }
        .to_owned()
    };
    let cluster_scoped = matches!(
        res_type,
        "namespaces"
            | "nodes"
            | "persistentvolumes"
            | "storageclasses"
            | "clusterroles"
            | "clusterrolebindings"
            | "ingressclasses"
            | "priorityclasses"
            | "runtimeclasses"
            | "customresourcedefinitions"
            | "mutatingwebhookconfigurations"
            | "validatingwebhookconfigurations"
    );
    match (namespace.is_empty() || cluster_scoped, name) {
        (true, None) => format!("{base}/{res_type}"),
        (false, None) => format!("{base}/namespaces/{namespace}/{res_type}"),
        (true, Some(n)) => format!("{base}/{res_type}/{n}"),
        (false, Some(n)) => format!("{base}/namespaces/{namespace}/{res_type}/{n}"),
    }
}

async fn k8s_list_resources(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(resource_type): Path<String>,
    Query(q): Query<K8sQuery>,
) -> Response {
    let required = if resource_type == "secrets" {
        perm::K8S_SECRETS_READ
    } else {
        perm::K8S_READ
    };
    let (tenant, _) = match require_any_perm(&state, &headers, &[required]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let namespaces = parse_k8s_namespaces(&q.namespace);
    if namespaces.len() <= 1 {
        let ns = namespaces.first().map_or("", String::as_str);
        let path = resource_api_path_with_gv(&resource_type, &q.group, &q.version, ns, None);
        return match state
            .platform
            .k8s
            .kube_get_json(&tenant, &q.cluster, &path)
            .await
        {
            Ok(v) => {
                state.telemetry.record_k8s_request("list", "ok");
                let items = v["items"].as_array().cloned().unwrap_or_default();
                Json(items).into_response()
            }
            Err(e) => {
                state.telemetry.record_k8s_request("list", "error");
                json_err(StatusCode::BAD_GATEWAY, e)
            }
        };
    }

    let mut all_items = Vec::new();
    let mut last_err = None;
    let mut any_ok = false;
    for ns in namespaces {
        let path = resource_api_path_with_gv(&resource_type, &q.group, &q.version, &ns, None);
        match state
            .platform
            .k8s
            .kube_get_json(&tenant, &q.cluster, &path)
            .await
        {
            Ok(v) => {
                any_ok = true;
                if let Some(items) = v["items"].as_array() {
                    all_items.extend(items.iter().cloned());
                }
            }
            Err(e) => last_err = Some(e),
        }
    }
    if !any_ok {
        state.telemetry.record_k8s_request("list", "error");
        return json_err(
            StatusCode::BAD_GATEWAY,
            last_err.unwrap_or_else(|| "K8s list failed".to_owned()),
        );
    }
    state.telemetry.record_k8s_request("list", "ok");
    Json(all_items).into_response()
}

async fn k8s_get_resource(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((resource_type, name)): Path<(String, String)>,
    Query(q): Query<K8sQuery>,
) -> Response {
    let required = if resource_type == "secrets" {
        perm::K8S_SECRETS_READ
    } else {
        perm::K8S_READ
    };
    let (tenant, _) = match require_any_perm(&state, &headers, &[required]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let path = resource_api_path_with_gv(
        &resource_type,
        &q.group,
        &q.version,
        &q.namespace,
        Some(&name),
    );
    match state
        .platform
        .k8s
        .kube_get_json(&tenant, &q.cluster, &path)
        .await
    {
        Ok(v) => {
            state.telemetry.record_k8s_request("list", "ok");
            Json(v).into_response()
        }
        Err(e) => {
            state.telemetry.record_k8s_request("list", "error");
            json_err(StatusCode::BAD_GATEWAY, e)
        }
    }
}

#[derive(Deserialize)]
struct K8sActionBody {
    cluster: String,
    #[serde(default = "default_ns")]
    namespace: String,
    #[serde(default, alias = "resource")]
    resource_type: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    version: String,
    name: String,
    #[serde(default)]
    replicas: Option<i64>,
    #[serde(default, alias = "object")]
    manifest: Option<serde_json::Value>,
}

fn default_ns() -> String {
    "default".to_owned()
}

async fn k8s_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(action): Path<String>,
    Json(body): Json<K8sActionBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_WRITE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let rtype = if body.resource_type.is_empty() {
        "deployments"
    } else {
        &body.resource_type
    };
    let base_path = resource_api_path_with_gv(
        rtype,
        &body.group,
        &body.version,
        &body.namespace,
        Some(&body.name),
    );
    let (method, path, payload) = match action.as_str() {
        "delete" => (Method::DELETE, base_path, serde_json::json!({})),
        "scale" => (
            Method::PATCH,
            format!("{base_path}/scale"),
            serde_json::json!({ "spec": { "replicas": body.replicas.unwrap_or(1) } }),
        ),
        "edit" => (
            Method::PUT,
            base_path,
            body.manifest.unwrap_or_else(|| serde_json::json!({})),
        ),
        "patch" | "apply" => (
            Method::PATCH,
            base_path,
            body.manifest.unwrap_or_else(|| serde_json::json!({})),
        ),
        _ => {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(0));
            let iso = format_epoch_ms_iso8601(now_ms);
            (
                Method::PATCH,
                base_path,
                serde_json::json!({
                    "spec": { "template": { "metadata": { "annotations": {
                        "kubectl.kubernetes.io/restartedAt": iso
                    } } } }
                }),
            )
        }
    };
    match state
        .platform
        .k8s
        .kube_post_json(&tenant, &body.cluster, method, &path, payload)
        .await
    {
        Ok(v) => Json(v).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

async fn k8s_list_crds(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<K8sQuery>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .platform
        .k8s
        .kube_get_json(
            &tenant,
            &q.cluster,
            "apis/apiextensions.k8s.io/v1/customresourcedefinitions",
        )
        .await
    {
        Ok(v) => {
            let items = v["items"].as_array().cloned().unwrap_or_default();
            Json(items).into_response()
        }
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

async fn k8s_crd_resources(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<K8sQuery>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let crd = match state
        .platform
        .k8s
        .kube_get_json(
            &tenant,
            &q.cluster,
            &format!("apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name}"),
        )
        .await
    {
        Ok(c) => c,
        Err(e) => return json_err(StatusCode::BAD_GATEWAY, e),
    };
    let group = crd["spec"]["group"].as_str().unwrap_or("example.com");
    let plural = crd["spec"]["names"]["plural"].as_str().unwrap_or(&name);
    let version = crd["spec"]["versions"][0]["name"].as_str().unwrap_or("v1");
    let path = if q.namespace.is_empty() {
        format!("apis/{group}/{version}/{plural}")
    } else {
        format!("apis/{group}/{version}/namespaces/{}/{plural}", q.namespace)
    };
    match state
        .platform
        .k8s
        .kube_get_json(&tenant, &q.cluster, &path)
        .await
    {
        Ok(v) => {
            state.telemetry.record_k8s_request("list", "ok");
            Json(v).into_response()
        }
        Err(e) => {
            state.telemetry.record_k8s_request("list", "error");
            json_err(StatusCode::BAD_GATEWAY, e)
        }
    }
}

#[derive(Deserialize)]
struct KubeconfigBody {
    #[serde(default, alias = "content")]
    kubeconfig: String,
    #[serde(default = "default_true")]
    connect: bool,
}

const fn default_true() -> bool {
    true
}

fn format_uploaded_cluster(rec: &K8sClusterRecord) -> serde_json::Value {
    serde_json::json!({
        "id": rec.id,
        "name": rec.name,
        "server": rec.api_server,
        "api_server": rec.api_server,
        "certificateAuthority": rec.ca_data_b64,
        "ca_data_b64": rec.ca_data_b64,
        "exec_cmd": rec.exec_command,
        "exec_args": [],
        "source": rec.source,
        "connected": rec.connected,
        "region": rec.region,
    })
}

async fn k8s_kubeconfig_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: axum::extract::Request,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_CLUSTERS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };

    let is_multipart = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.to_ascii_lowercase().starts_with("multipart/form-data"));

    let (raw_kubeconfig, connect) = if is_multipart {
        let mut mp = match Multipart::from_request(req, &state).await {
            Ok(m) => m,
            Err(e) => {
                return json_err(
                    StatusCode::BAD_REQUEST,
                    format!("invalid multipart kubeconfig: {e}"),
                )
            }
        };
        let mut content = String::new();
        let mut do_connect = false;
        while let Ok(Some(field)) = mp.next_field().await {
            let name = field.name().unwrap_or("").to_owned();
            if name == "kubeconfig" || name == "file" {
                let bytes = field.bytes().await.unwrap_or_default();
                content = String::from_utf8_lossy(&bytes).into_owned();
            } else if name == "connect" {
                let val = field.text().await.unwrap_or_default();
                do_connect = val.trim().eq_ignore_ascii_case("true") || val.trim() == "1";
            }
        }
        (content, do_connect)
    } else {
        let Ok(bytes) = axum::body::to_bytes(req.into_body(), 8 * 1024 * 1024).await else {
            return json_err(StatusCode::BAD_REQUEST, "failed reading kubeconfig payload");
        };
        let Ok(body) = serde_json::from_slice::<KubeconfigBody>(&bytes) else {
            return json_err(StatusCode::BAD_REQUEST, "invalid kubeconfig JSON body");
        };
        (body.kubeconfig, body.connect)
    };

    match state
        .platform
        .k8s
        .upload_kubeconfig(&tenant, &raw_kubeconfig, connect)
        .await
    {
        Ok(list) => {
            let clusters: Vec<serde_json::Value> =
                list.iter().map(format_uploaded_cluster).collect();
            let contexts: Vec<String> = list.iter().map(|c| c.name.clone()).collect();
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "clusters": clusters,
                    "contexts": contexts,
                })),
            )
                .into_response()
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e),
    }
}

#[derive(Deserialize, Default)]
struct KubeconfigConnectBody {
    #[serde(default)]
    cluster: String,
    #[serde(default)]
    context: String,
    #[serde(default)]
    cluster_name: String,
    #[serde(default)]
    server: String,
    #[serde(default, alias = "ca_data_b64")]
    ca_data: String,
    #[serde(default, alias = "bearer_token")]
    token: String,
    #[serde(default)]
    exec_cmd: String,
    #[serde(default)]
    insecure_skip_tls_verify: bool,
}

async fn k8s_kubeconfig_connect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<KubeconfigConnectBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_CONNECT]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let target = if !body.cluster.trim().is_empty() {
        body.cluster.trim()
    } else if !body.context.trim().is_empty() {
        body.context.trim()
    } else {
        body.cluster_name.trim()
    };

    if !body.server.trim().is_empty() {
        let name = if target.is_empty() {
            "kubeconfig-cluster"
        } else {
            target
        };
        let rec = state
            .platform
            .k8s
            .upsert_cluster(K8sClusterRecord {
                id: String::new(),
                tenant_id: tenant,
                name: name.to_owned(),
                source: "kubeconfig".to_owned(),
                api_server: body.server.trim().to_owned(),
                bearer_token: body.token.trim().to_owned(),
                ca_data_b64: body.ca_data.trim().to_owned(),
                insecure_skip_tls_verify: body.insecure_skip_tls_verify,
                connected: true,
                recording_enabled: true,
                region: "custom".to_owned(),
                exec_command: body.exec_cmd.trim().to_owned(),
                ..K8sClusterRecord::default()
            })
            .await;
        state.telemetry.record_k8s_request("connect", "ok");
        return Json(serde_json::json!({
            "cluster_id": rec.id,
            "id": rec.id,
            "name": rec.name,
            "source": rec.source,
            "status": "connected",
            "connected": true,
        }))
        .into_response();
    }

    match state
        .platform
        .k8s
        .set_connected(&tenant, target, true)
        .await
    {
        Some(c) => {
            state.telemetry.record_k8s_request("connect", "ok");
            Json(serde_json::json!({
                "cluster_id": c.id,
                "id": c.id,
                "name": c.name,
                "source": c.source,
                "status": "connected",
                "connected": true,
            }))
            .into_response()
        }
        None => json_err(StatusCode::NOT_FOUND, "cluster not found"),
    }
}

async fn k8s_configured_list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.platform.k8s.list_configured(&tenant).await).into_response()
}

#[derive(Deserialize, Default)]
struct ConfiguredClusterBody {
    #[serde(default)]
    label: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    proxy: String,
    #[serde(default)]
    cluster_name: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    connector: String,
    #[serde(default)]
    recording_mode: String,
    #[serde(default)]
    api_server: String,
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    region: String,
}

impl ConfiguredClusterBody {
    fn into_record(self, id: String, tenant_id: String) -> ConfiguredKubeCluster {
        let label = if self.label.is_empty() {
            self.name
        } else {
            self.label
        };
        let api_server = if self.api_server.is_empty() {
            self.endpoint
        } else {
            self.api_server
        };
        ConfiguredKubeCluster {
            id,
            tenant_id,
            label,
            proxy: self.proxy,
            cluster_name: self.cluster_name,
            method: self.method,
            connector: self.connector,
            recording_mode: self.recording_mode,
            api_server,
            region: self.region,
        }
    }
}

async fn k8s_configured_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ConfiguredClusterBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_CLUSTERS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let rec = state
        .platform
        .k8s
        .upsert_configured(body.into_record(String::new(), tenant))
        .await;
    (StatusCode::CREATED, Json(rec)).into_response()
}

async fn k8s_configured_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ConfiguredClusterBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_CLUSTERS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let rec = state
        .platform
        .k8s
        .upsert_configured(body.into_record(id, tenant))
        .await;
    Json(rec).into_response()
}

async fn k8s_configured_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_CLUSTERS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if state.platform.k8s.delete_configured(&tenant, &id).await {
        Json(serde_json::json!({ "status": "deleted" })).into_response()
    } else {
        json_err(StatusCode::NOT_FOUND, "cluster not found")
    }
}

async fn k8s_configured_rec_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, _) =
        match require_any_perm(&state, &headers, &[perm::RECORDING_POLICY_MANAGE]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let (pol, inherited) = state
        .platform
        .k8s
        .get_cluster_recording_policy(&tenant, &id)
        .await;
    Json(serde_json::json!({
        "id": id,
        "mode": pol.mode,
        "namespaces": pol.namespaces,
        "inherited": inherited,
        "recording_enabled": pol.mode != "off",
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
struct ToggleClusterRecBody {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    namespaces: Vec<String>,
    #[serde(default)]
    recording_enabled: Option<bool>,
}

async fn k8s_configured_rec_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ToggleClusterRecBody>,
) -> Response {
    let (tenant, _) =
        match require_any_perm(&state, &headers, &[perm::RECORDING_POLICY_MANAGE]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let mut base = state.platform.k8s.get_policy(&tenant).await;
    if !body.mode.trim().is_empty() {
        base.mode = body.mode.trim().to_owned();
    } else if let Some(en) = body.recording_enabled {
        if en { "all" } else { "off" }.clone_into(&mut base.mode);
    }
    base.namespaces = body.namespaces;
    let saved = state
        .platform
        .k8s
        .set_cluster_recording_policy(&tenant, &id, base)
        .await;
    Json(serde_json::json!({
        "id": id,
        "mode": saved.mode,
        "namespaces": saved.namespaces,
        "inherited": false,
        "recording_enabled": saved.mode != "off",
    }))
    .into_response()
}

async fn k8s_rec_policy_get(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.platform.k8s.get_policy(&tenant).await).into_response()
}

async fn k8s_rec_policy_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(pol): Json<K8sRecordingPolicy>,
) -> Response {
    let (tenant, _) =
        match require_any_perm(&state, &headers, &[perm::RECORDING_POLICY_MANAGE]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    Json(state.platform.k8s.set_policy(&tenant, pol).await).into_response()
}

async fn fetch_pod_logs_string(
    state: &AppState,
    tenant: &str,
    cluster: &str,
    namespace: &str,
    pod: &str,
    container: &str,
    tail_lines: u32,
    previous: bool,
) -> Result<String, String> {
    let ns = if namespace.trim().is_empty() {
        "default"
    } else {
        namespace.trim()
    };
    let tail = tail_lines.clamp(1, 50_000);
    let mut path = format!(
        "api/v1/namespaces/{}/pods/{}/log?follow=false&timestamps=true&tailLines={tail}",
        operquay_aws::sigv4::uri_encode(ns, true),
        operquay_aws::sigv4::uri_encode(pod.trim(), true),
    );
    if !container.trim().is_empty() {
        use std::fmt::Write as _;
        let _ = write!(
            path,
            "&container={}",
            operquay_aws::sigv4::uri_encode(container.trim(), true)
        );
    }
    if previous {
        path.push_str("&previous=true");
    }
    state
        .platform
        .k8s
        .kube_get_text(tenant, cluster, &path)
        .await
}

async fn k8s_pod_logs_text(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((namespace, name)): Path<(String, String)>,
    Query(q): Query<K8sQuery>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let tail = q.tail_lines.unwrap_or(50);
    match fetch_pod_logs_string(
        &state,
        &tenant,
        &q.cluster,
        &namespace,
        &name,
        &q.container,
        tail,
        q.previous,
    )
    .await
    {
        Ok(txt) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            txt,
        )
            .into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

async fn k8s_logs_http(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<K8sQuery>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let tail = q.tail_lines.unwrap_or(200);
    match fetch_pod_logs_string(
        &state,
        &tenant,
        &q.cluster,
        &q.namespace,
        &q.pod,
        &q.container,
        tail,
        q.previous,
    )
    .await
    {
        Ok(txt) => {
            let lines: Vec<&str> = txt.lines().collect();
            Json(lines).into_response()
        }
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

async fn drain_log_lines(socket: &mut WebSocket, buf: &mut Vec<u8>) -> bool {
    while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
        let mut line_bytes: Vec<u8> = buf.drain(..=pos).collect();
        if line_bytes.last() == Some(&b'\n') {
            line_bytes.pop();
        }
        if line_bytes.last() == Some(&b'\r') {
            line_bytes.pop();
        }
        let line = String::from_utf8_lossy(&line_bytes).into_owned();
        let frame = serde_json::json!({ "log": line }).to_string();
        if socket.send(WsMsg::Text(frame.into())).await.is_err() {
            return false;
        }
    }
    true
}

async fn ws_k8s_logs(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<K8sQuery>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    ws.on_upgrade(move |mut socket| async move {
        let ns = if q.namespace.trim().is_empty() {
            "default".to_owned()
        } else {
            q.namespace.trim().to_owned()
        };
        if q.cluster.trim().is_empty() || q.pod.trim().is_empty() {
            let err = serde_json::json!({ "error": "cluster and pod query parameters are required" })
                .to_string();
            let _ = socket.send(WsMsg::Text(err.into())).await;
            let _ = socket.close().await;
            return;
        }
        let cont = (!q.container.trim().is_empty()).then_some(q.container.trim());
        let follow = q.follow.unwrap_or(true);
        let tail_lines = q.tail_lines.unwrap_or(100).clamp(1, 50_000);
        match state
            .platform
            .k8s
            .kube_get_stream_logs(&tenant, &q.cluster, &ns, q.pod.trim(), cont, follow, tail_lines, true)
            .await
        {
            Ok(resp) => {
                let mut stream = resp.bytes_stream();
                let mut buf = Vec::<u8>::with_capacity(8192);
                loop {
                    tokio::select! {
                        biased;
                        cli_msg = socket.next() => {
                            match cli_msg {
                                Some(Ok(WsMsg::Close(_)) | Err(_)) | None => return,
                                _ => {}
                            }
                        }
                        chunk = stream.next() => {
                            match chunk {
                                Some(Ok(bytes)) => {
                                    buf.extend_from_slice(&bytes);
                                    if !drain_log_lines(&mut socket, &mut buf).await {
                                        return;
                                    }
                                }
                                Some(Err(e)) => {
                                    let err = serde_json::json!({ "error": format!("Log stream interrupted: {e}") }).to_string();
                                    let _ = socket.send(WsMsg::Text(err.into())).await;
                                    break;
                                }
                                None => {
                                    if !buf.is_empty() {
                                        if buf.last() == Some(&b'\r') {
                                            buf.pop();
                                        }
                                        let tail = String::from_utf8_lossy(&buf).into_owned();
                                        let frame = serde_json::json!({ "log": tail }).to_string();
                                        let _ = socket.send(WsMsg::Text(frame.into())).await;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            Err(err) => {
                let frame = serde_json::json!({ "error": err }).to_string();
                let _ = socket.send(WsMsg::Text(frame.into())).await;
            }
        }
        let _ = socket.close().await;
    })
}

async fn ws_k8s_exec(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<K8sQuery>,
) -> Response {
    ws_k8s_terminal(ws, state, headers, q, false).await
}

async fn ws_k8s_attach(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<K8sQuery>,
) -> Response {
    ws_k8s_terminal(ws, state, headers, q, true).await
}

async fn ws_k8s_terminal(
    ws: WebSocketUpgrade,
    state: AppState,
    headers: HeaderMap,
    q: K8sQuery,
    is_attach: bool,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::K8S_EXEC]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let user_id = claims.user_id;
    let user_email = claims.email;
    let auth_session_id = claims.session_id;
    ws.on_upgrade(move |mut socket| async move {
        let ns = if q.namespace.trim().is_empty() {
            "default".to_owned()
        } else {
            q.namespace.trim().to_owned()
        };
        if q.cluster.trim().is_empty() || q.pod.trim().is_empty() {
            let _ = socket
                .send(WsMsg::Text(
                    "[k8s] cluster and pod are required for interactive exec/attach\r\n".into(),
                ))
                .await;
            let _ = socket.close().await;
            return;
        }
        let (policy, _) = state
            .platform
            .k8s
            .get_cluster_recording_policy(&tenant, &q.cluster)
            .await;
        let effective_fail_closed =
            policy.fail_closed || operquay_core::compliance_mode_enabled();
        let record_active = policy.should_record_namespace(&ns, is_attach);
        let rec_id = format!("k8s-{}", Uuid::new_v4());
        let k8s_sid = rec_id.clone();
        let target_label = format!("{}/{}/{}", q.cluster, ns, q.pod);
        let rec_start = std::time::Instant::now();
        let mut tee = if record_active {
            state.ensure_tenant_dek_persisted(&tenant).await;
            match state
                .recordings
                .start_cast_session(
                    rec_id.clone(),
                    tenant.clone(),
                    "k8s".to_owned(),
                    target_label.clone(),
                    effective_fail_closed,
                    120,
                    32,
                )
                .await
            {
                Ok(t) => Some(t),
                Err(err) if effective_fail_closed => {
                    let _ = socket
                        .send(WsMsg::Text(
                            format!("[recording fail-closed abort] {err}\r\n").into(),
                        ))
                        .await;
                    let _ = socket.close().await;
                    return;
                }
                Err(_) => None,
            }
        } else {
            None
        };
        let auth_check_active = !user_id.is_empty()
            && !auth_session_id.is_empty()
            && auth_session_id != "anonymous-lab";
        let mut fence_guard = state.session_fence.register_with_session(
            &tenant,
            &user_id,
            &auth_session_id,
            None,
            &k8s_sid,
            None,
        );
        let mod_handle = state.moderation.register_session(
            &tenant,
            &k8s_sid,
            "k8s",
            &target_label,
            &user_id,
            &user_email,
            record_active.then_some(rec_id),
        );
        let mut fw_buf = crate::dlp::ShellCommandFirewallBuffer::new();
        let mut fence_tick = tokio::time::interval(std::time::Duration::from_secs(5));
        fence_tick.tick().await;

        let cmd = if q.command.trim().is_empty() {
            "/bin/sh"
        } else {
            q.command.trim()
        };
        let op = if is_attach { "attach" } else { "exec" };
        // Kubernetes rejects `tty=true` paired with `stderr=true`.
        let mut api_path = format!(
            "api/v1/namespaces/{}/pods/{}/{op}?stdin=true&stdout=true&stderr=false&tty=true",
            operquay_aws::sigv4::uri_encode(&ns, true),
            operquay_aws::sigv4::uri_encode(q.pod.trim(), true),
        );
        if !is_attach {
            use std::fmt::Write as _;
            for part in cmd.split_whitespace() {
                let _ = write!(
                    api_path,
                    "&command={}",
                    operquay_aws::sigv4::uri_encode(part, true)
                );
            }
        }
        if !q.container.trim().is_empty() {
            use std::fmt::Write as _;
            let _ = write!(
                api_path,
                "&container={}",
                operquay_aws::sigv4::uri_encode(q.container.trim(), true)
            );
        }
        match state
            .platform
            .k8s
            .connect_spdy_channel_ws_with_proto(&tenant, &q.cluster, &api_path)
            .await
        {
            Ok((upstream, up_proto)) => {
                let is_base64 = up_proto == "base64.channel.k8s.io";
                let (mut up_sink, mut up_src) = upstream.split();
                let resize_v1 = q.protocol == "resize-v1";
                loop {
                    tokio::select! {
                        biased;
                        reason = fence_guard.revoked() => {
                            let _ = socket
                                .send(WsMsg::Text(
                                    format!("\r\n[k8s] session terminated: {reason}\r\n").into(),
                                ))
                                .await;
                            let _ = socket.close().await;
                            break;
                        }
                        _ = fence_tick.tick(), if auth_check_active => {
                            if !state
                                .auth
                                .is_session_active(&tenant, &auth_session_id, &user_id)
                                .await
                            {
                                let _ = socket
                                    .send(WsMsg::Text(
                                        "\r\n[k8s] session terminated: revoked or expired\r\n"
                                            .into(),
                                    ))
                                    .await;
                                let _ = socket.close().await;
                                break;
                            }
                        }
                        up_msg = up_src.next() => {
                            let Some(Ok(msg)) = up_msg else { break; };
                            let decoded_frame: Option<(u8, Vec<u8>)> = match msg {
                                UpstreamWsMsg::Binary(bytes) if !is_base64 && !bytes.is_empty() => {
                                    Some((bytes[0], bytes[1..].to_vec()))
                                }
                                UpstreamWsMsg::Text(txt) if is_base64 && !txt.is_empty() => {
                                    let b = txt.as_bytes();
                                    let ch = match b[0] {
                                        b'0'..=b'9' => b[0] - b'0',
                                        other => other,
                                    };
                                    STANDARD.decode(&b[1..]).ok().map(|payload| (ch, payload))
                                }
                                UpstreamWsMsg::Close(_) => break,
                                _ => None,
                            };
                            if let Some((ch, payload)) = decoded_frame {
                                if ch == 255 && up_proto == "v5.channel.k8s.io" {
                                    // K8s v5 remote CLOSE channel
                                    break;
                                }
                                if (ch == 1 || ch == 2) && !payload.is_empty() {
                                    let text = String::from_utf8_lossy(&payload).into_owned();
                                    mod_handle.publish_output(&text);
                                    if let Some(ref mut t) = tee {
                                        if let Err(err) = t.record_cast_output(rec_start.elapsed().as_secs_f64(), &text) {
                                            let _ = socket.send(WsMsg::Text(format!("\r\n[recording fail-closed abort] {err}\r\n").into())).await;
                                            break;
                                        }
                                    }
                                    if socket.send(WsMsg::Text(text.into())).await.is_err() {
                                        break;
                                    }
                                } else if ch == 3 && !payload.is_empty() {
                                    if let Ok(st) = serde_json::from_slice::<serde_json::Value>(&payload) {
                                        if st["status"].as_str() != Some("Success") {
                                            let msg = st["message"].as_str().unwrap_or("command terminated with error");
                                            let _ = socket.send(WsMsg::Text(format!("\r\n[k8s] {msg}\r\n").into())).await;
                                        }
                                    }
                                }
                            }
                        }
                        cli_msg = socket.next() => {
                            let Some(Ok(msg)) = cli_msg else { break; };
                            let input_bytes: Option<Vec<u8>> = match msg {
                                WsMsg::Text(txt) => {
                                    if let Ok(ctrl) = serde_json::from_str::<serde_json::Value>(&txt) {
                                        if ctrl["type"].as_str() == Some("resize") {
                                            let cols = ctrl["cols"].as_u64().unwrap_or(120);
                                            let rows = ctrl["rows"].as_u64().unwrap_or(32);
                                            let rsz = format!("{{\"Width\":{cols},\"Height\":{rows}}}");
                                            let _ = send_k8s_channel_frame(&mut up_sink, is_base64, 4, rsz.as_bytes()).await;
                                            None
                                        } else if ctrl["type"].as_str() == Some("input") {
                                            Some(ctrl["data"].as_str().unwrap_or("").as_bytes().to_vec())
                                        } else if resize_v1 {
                                            None
                                        } else {
                                            Some(txt.as_bytes().to_vec())
                                        }
                                    } else {
                                        Some(txt.as_bytes().to_vec())
                                    }
                                }
                                WsMsg::Binary(b) => Some(b.to_vec()),
                                WsMsg::Close(_) => break,
                                _ => None,
                            };
                            if let Some(raw_bytes) = input_bytes {
                                let decision = crate::governance_routes::execute_shell_input_firewall(
                                    &state,
                                    &tenant,
                                    &k8s_sid,
                                    "k8s",
                                    &target_label,
                                    &user_id,
                                    &user_email,
                                    &mod_handle,
                                    &mut fw_buf,
                                    &raw_bytes,
                                )
                                .await;
                                if let Some(banner) = decision.user_banner {
                                    let _ = socket.send(WsMsg::Text(banner.into())).await;
                                }
                                if !decision.send_upstream.is_empty()
                                    && send_k8s_channel_frame(&mut up_sink, is_base64, 0, &decision.send_upstream)
                                        .await
                                        .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            Err(err) => {
                tracing::warn!(cluster = %q.cluster, ns = %ns, pod = %q.pod, error = %err, "K8s exec/attach WS failed");
                let err_msg = format!(
                    "[k8s] unable to connect upstream WebSocket stream for pod={} ({ns}) in cluster={}: {err}\r\n",
                    q.pod, q.cluster
                );
                let _ = socket.send(WsMsg::Text(err_msg.into())).await;
                let _ = socket.close().await;
            }
        }
        if let Some(t) = tee {
            let entry = state.recordings.finalize(t).await;
            state.persist_recording_metadata(&entry).await;
        }
    })
}

async fn send_k8s_channel_frame<S>(
    sink: &mut S,
    is_base64: bool,
    channel: u8,
    payload: &[u8],
) -> Result<(), ()>
where
    S: futures_util::Sink<UpstreamWsMsg> + Unpin,
{
    let msg = if is_base64 {
        let ch_char = char::from(b'0'.saturating_add(channel));
        UpstreamWsMsg::Text(format!("{ch_char}{}", STANDARD.encode(payload)).into())
    } else {
        let mut frame = Vec::with_capacity(1 + payload.len());
        frame.push(channel);
        frame.extend_from_slice(payload);
        UpstreamWsMsg::Binary(frame.into())
    };
    sink.send(msg).await.map_err(|_| ())
}

#[derive(Deserialize, Default)]
struct TeleportLocalLoginBody {
    #[serde(default, alias = "proxy")]
    proxy_url: String,
    #[serde(default, alias = "username")]
    user: String,
    #[serde(default)]
    password: String,
    #[serde(default, alias = "totp_code")]
    otp: String,
    #[serde(default)]
    cluster_name: String,
}

#[derive(Deserialize, Default)]
struct TeleportRequestCredentialsBody {
    #[serde(default, alias = "proxy")]
    proxy_url: String,
    #[serde(default, alias = "connector")]
    auth_type: String,
}

#[derive(Deserialize, Default)]
struct TeleportConnectBody {
    #[serde(default, alias = "proxy")]
    proxy_url: String,
    #[serde(default)]
    cluster_name: String,
    #[serde(default)]
    callback_id: String,
}

#[derive(Deserialize, Default)]
struct TeleportQuery {
    #[serde(default)]
    callback_id: String,
}

async fn teleport_local_login_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TeleportLocalLoginBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_CONNECT]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let proxy = body.proxy_url.trim();
    match operquay_k8s::teleport::teleport_local_login(
        proxy,
        &body.user,
        &body.password,
        &body.otp,
        &body.cluster_name,
    )
    .await
    {
        Ok(outcome) => {
            let sess = state
                .platform
                .k8s
                .store_teleport_callback(&tenant, proxy, outcome)
                .await;
            Json(serde_json::to_value(&sess).unwrap_or_default()).into_response()
        }
        Err(err) => {
            let status = if err.to_ascii_lowercase().contains("invalid credentials")
                || err.to_ascii_lowercase().contains("unauthorized")
                || err.to_ascii_lowercase().contains("denied")
                || err.to_ascii_lowercase().contains("mfa")
                || err.to_ascii_lowercase().contains("totp")
            {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::BAD_REQUEST
            };
            json_err(status, err)
        }
    }
}

async fn teleport_request_credentials_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TeleportRequestCredentialsBody>,
) -> Response {
    if let Err(r) = require_any_perm(&state, &headers, &[perm::K8S_CONNECT]).await {
        return *r;
    }
    let proxy = body.proxy_url.trim();
    match state.platform.k8s.ping_teleport_proxy(proxy).await {
        Ok(ping) => {
            if ping.auth_type.eq_ignore_ascii_case("local") {
                json_err(
                    StatusCode::BAD_REQUEST,
                    "This Teleport proxy uses local username, password, and MFA authentication. Select 'Local (Username / Password / OTP)' as the Sign-in Method.",
                )
            } else {
                let kind = if body.auth_type.trim().is_empty() {
                    ping.auth_type
                } else {
                    body.auth_type
                };
                json_err(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "Teleport SSO connector '{kind}' requires browser OIDC/SAML redirect flow not supported in headless backend mode. Switch to Local authentication or upload a Teleport kubeconfig."
                    ),
                )
            }
        }
        Err(err) => json_err(StatusCode::BAD_GATEWAY, err),
    }
}

async fn teleport_connect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TeleportConnectBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::K8S_CONNECT]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let cname = body.cluster_name.trim();
    if cname.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "cluster_name is required");
    }
    let Some(cb) = state
        .platform
        .k8s
        .teleport_callback(&tenant, &body.callback_id)
        .await
    else {
        return json_err(
            StatusCode::UNAUTHORIZED,
            "Teleport sign-in session expired or not found. Please sign in again.",
        );
    };
    if cb.client_cert_pem.trim().is_empty() || cb.client_key_pem.trim().is_empty() {
        return json_err(
            StatusCode::BAD_REQUEST,
            format!(
                "Select cluster '{cname}' directly and sign in with a fresh 6-digit MFA code so cluster-scoped Teleport Kubernetes certificates can be issued."
            ),
        );
    }
    let api_server = if !cb.kube_api_base.is_empty() {
        cb.kube_api_base.clone()
    } else if !cb.proxy_url.trim().is_empty() {
        format!(
            "https://{}",
            cb.proxy_url.trim().trim_start_matches("https://")
        )
    } else if !body.proxy_url.trim().is_empty() {
        format!(
            "https://{}",
            body.proxy_url.trim().trim_start_matches("https://")
        )
    } else {
        String::new()
    };
    let rec = state
        .platform
        .k8s
        .upsert_cluster(K8sClusterRecord {
            id: format!("tp:{cname}"),
            tenant_id: tenant.clone(),
            name: cname.to_owned(),
            source: "teleport".to_owned(),
            api_server,
            client_cert_pem: cb.client_cert_pem.clone(),
            client_key_pem: cb.client_key_pem.clone(),
            ca_data_b64: cb.ca_data_b64.clone(),
            connected: true,
            recording_enabled: true,
            ..K8sClusterRecord::default()
        })
        .await;
    let sess = state
        .platform
        .k8s
        .teleport_status_for_callback(&tenant, &cb.callback_id)
        .await;
    let mut val = serde_json::to_value(&sess).unwrap_or_default();
    if let Some(obj) = val.as_object_mut() {
        obj.insert("cluster_id".to_owned(), serde_json::json!(rec.id));
        obj.insert("name".to_owned(), serde_json::json!(rec.name));
    }
    Json(val).into_response()
}

async fn teleport_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TeleportQuery>,
) -> Response {
    let (tenant, _) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(
        state
            .platform
            .k8s
            .teleport_status_for_callback(&tenant, &query.callback_id)
            .await,
    )
    .into_response()
}

async fn teleport_clusters(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TeleportQuery>,
) -> Response {
    let (tenant, _) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let st = state
        .platform
        .k8s
        .teleport_status_for_callback(&tenant, &query.callback_id)
        .await;
    Json(serde_json::json!({ "clusters": st.clusters })).into_response()
}

async fn teleport_cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let (tenant, _) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let parsed = serde_json::from_slice::<TeleportQuery>(&body).unwrap_or_default();
    state
        .platform
        .k8s
        .cancel_teleport_callback(&tenant, &parsed.callback_id)
        .await;
    Json(serde_json::json!({ "status": "cancelled" })).into_response()
}

// ---------------------------------------------------------------------------
// PostgreSQL Database Explorer
// ---------------------------------------------------------------------------

async fn db_connect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DbConnectRequest>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::DB_VIEWER]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state.platform.db.connect_and_inspect(&tenant, &req).await {
        Ok(res) => Json(res).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct DbQueryBody {
    #[serde(default)]
    connection_id: String,
    #[serde(default)]
    connection: Option<DbConnectRequest>,
    sql: String,
    #[serde(default)]
    read_only: Option<bool>,
}

async fn db_query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DbQueryBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::DB_VIEWER]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let conn_id = if !body.connection_id.is_empty() {
        body.connection_id
    } else if let Some(ref conn) = body.connection {
        match state.platform.db.connect_or_reuse(&tenant, conn).await {
            Ok(id) => id,
            Err(e) => return json_err(StatusCode::BAD_GATEWAY, e),
        }
    } else {
        return json_err(
            StatusCode::BAD_REQUEST,
            "connection_id or connection required",
        );
    };
    let engine_label = body
        .connection
        .as_ref()
        .map_or("cached", |c| c.engine.as_str())
        .to_owned();
    let read_only = body.read_only.unwrap_or(true);
    match state
        .platform
        .db
        .query(&tenant, &conn_id, &body.sql, read_only)
        .await
    {
        Ok(mut res) => {
            let dlp_pol = state.governance.get_dlp_policy(&tenant).await;
            let summary =
                operquay_db::dlp::redact_query_result(&mut res, &dlp_pol.db_dlp, &claims.role);
            if summary.masked_cells > 0 {
                crate::governance_routes::record_gov_audit(
                    &state,
                    &tenant,
                    &claims.user_id,
                    &claims.email,
                    &claims.role,
                    "",
                    &conn_id,
                    "db_query_dlp_masked",
                    "db",
                    &conn_id,
                    format!(
                        "masked_cells={} columns={}",
                        summary.masked_cells,
                        summary.masked_columns.join(",")
                    ),
                    "success",
                    None,
                )
                .await;
            }
            state
                .telemetry
                .record_db_query(&engine_label, "ok", res.duration_ms as f64);
            Json(res).into_response()
        }
        Err(err) => {
            let status_lbl = if err.blocked_by_guard {
                "blocked"
            } else {
                "error"
            };
            state
                .telemetry
                .record_db_query(&engine_label, status_lbl, 0.0);
            let status = if err.blocked_by_guard {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::BAD_REQUEST
            };
            (
                status,
                Json(serde_json::json!({
                    "error": err.message,
                    "blocked_by_guard": err.blocked_by_guard,
                })),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct DbMutateBody {
    #[serde(default)]
    connection_id: String,
    #[serde(default)]
    connection: Option<DbConnectRequest>,
    #[serde(default)]
    sql: Option<String>,
    #[serde(default)]
    schema: String,
    #[serde(default)]
    table: String,
    #[serde(default)]
    primary_keys: Vec<String>,
    #[serde(default)]
    updates: Vec<DbRowUpdate>,
    #[serde(default)]
    inserts: Vec<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    deletes: Vec<HashMap<String, serde_json::Value>>,
}

async fn db_mutate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DbMutateBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::DB_VIEWER]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let conn_id = if !body.connection_id.is_empty() {
        body.connection_id
    } else if let Some(ref conn) = body.connection {
        match state.platform.db.connect_or_reuse(&tenant, conn).await {
            Ok(id) => id,
            Err(e) => return json_err(StatusCode::BAD_GATEWAY, e),
        }
    } else {
        return json_err(
            StatusCode::BAD_REQUEST,
            "connection_id or connection required",
        );
    };

    let dlp_pol = state.governance.get_dlp_policy(&tenant).await;
    if dlp_pol.require_jit_for_db_write
        && state
            .governance
            .find_active_grant(
                &tenant,
                &claims.user_id,
                crate::jit::JitTargetType::DbWrite,
                &conn_id,
            )
            .await
            .is_none()
    {
        crate::governance_routes::record_gov_audit(
            &state,
            &tenant,
            &claims.user_id,
            &claims.email,
            &claims.role,
            "",
            &conn_id,
            "db_mutate_jit_blocked",
            "db",
            &conn_id,
            "database mutation rejected pending approved JIT db_write grant",
            "denied",
            None,
        )
        .await;
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "JIT approval required for database mutations",
                "jit_required": true,
                "target_type": "db_write",
                "target_id": conn_id,
            })),
        )
            .into_response();
    }

    if let Some(ref sql) = body.sql {
        return match state.platform.db.mutate(&tenant, &conn_id, sql).await {
            Ok(affected_rows) => Json(serde_json::json!({
                "committed": true,
                "updated": affected_rows,
                "inserted": 0,
                "deleted": 0,
                "affected_rows": affected_rows,
                "duration_ms": 1
            }))
            .into_response(),
            Err(e) => json_err(StatusCode::BAD_REQUEST, e),
        };
    }

    match state
        .platform
        .db
        .mutate_structured(
            &tenant,
            &conn_id,
            &body.schema,
            &body.table,
            &body.primary_keys,
            &body.updates,
            &body.inserts,
            &body.deletes,
        )
        .await
    {
        Ok(res) => Json(res).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e),
    }
}

// ---------------------------------------------------------------------------
// Port Forwarder & 5-Byte Stream Multiplexer
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct StartForwardBody {
    instance_id: String,
    #[serde(default)]
    instance_name: String,
    #[serde(default)]
    binding_id: String,
    #[serde(default = "default_region")]
    region: String,
    #[serde(default = "default_loopback")]
    remote_host: String,
    #[serde(alias = "port")]
    remote_port: u16,
    #[serde(default)]
    local_port: u16,
}

fn default_region() -> String {
    "us-east-1".to_owned()
}

fn default_loopback() -> String {
    "127.0.0.1".to_owned()
}

async fn start_port_forward(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<StartForwardBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::NETWORK_FORWARD]).await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let tun = state
        .platform
        .forward
        .start_tunnel_with_binding(
            &tenant,
            &claims.user_id,
            &body.instance_id,
            &body.instance_name,
            &body.binding_id,
            &body.region,
            &body.remote_host,
            body.remote_port,
            body.local_port,
        )
        .await;
    state.telemetry.record_ssm_tunnel("port_forward", "started");
    let mut val = serde_json::to_value(&tun).unwrap_or_default();
    if let Some(obj) = val.as_object_mut() {
        obj.insert("forward_id".to_owned(), serde_json::json!(tun.id));
    }
    (StatusCode::CREATED, Json(val)).into_response()
}

#[derive(Deserialize)]
struct StopForwardBody {
    #[serde(alias = "forward_id")]
    id: String,
}

async fn stop_port_forward(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<StopForwardBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::NETWORK_FORWARD]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let ok = state.platform.forward.stop_tunnel(&tenant, &body.id).await;
    Json(serde_json::json!({ "stopped": ok })).into_response()
}

async fn active_tunnels(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::NETWORK_FORWARD]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.platform.forward.list_active(&tenant).await).into_response()
}

async fn ws_forward_connect(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| handle_ws_forward_mux(socket, state))
}

async fn handle_ws_forward_mux(mut socket: WebSocket, state: AppState) {
    let Some(Ok(WsMsg::Text(hs))) = socket.next().await else {
        return;
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(&hs) else {
        return;
    };
    let code = val["pairing_code"].as_str().unwrap_or("");
    let Some(tunnel) = state.platform.forward.take_pairing(code).await else {
        return;
    };
    let _ = socket
        .send(WsMsg::Text(r#"{"status":"ready"}"#.into()))
        .await;

    let (ws_out_tx, mut ws_out_rx) = mpsc::channel::<Vec<u8>>(128);
    let mut streams: HashMap<u32, mpsc::Sender<Vec<u8>>> = HashMap::new();

    loop {
        tokio::select! {
            biased;

            out_bin = ws_out_rx.recv() => {
                let Some(frame) = out_bin else { break; };
                if socket.send(WsMsg::Binary(frame.into())).await.is_err() {
                    break;
                }
            }

            inbound = socket.next() => {
                let Some(Ok(msg)) = inbound else { break; };
                let WsMsg::Binary(b) = msg else {
                    if matches!(msg, WsMsg::Close(_)) {
                        break;
                    }
                    continue;
                };
                let Some((kind, sid, payload)) = decode_mux_frame(&b) else {
                    continue;
                };
                match kind {
                    MuxFrameKind::Open => {
                        if tunnel.remote_host == "mux-echo" || tunnel.remote_port == 0 {
                            if !payload.is_empty() {
                                let _ = ws_out_tx.try_send(encode_mux_frame(MuxFrameKind::Data, sid, payload));
                            }
                            continue;
                        }
                        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
                        streams.insert(sid, in_tx);
                        spawn_mux_upstream(
                            sid,
                            tunnel.clone(),
                            state.clone(),
                            in_rx,
                            ws_out_tx.clone(),
                        );
                    }
                    MuxFrameKind::Data => {
                        if tunnel.remote_host == "mux-echo" || tunnel.remote_port == 0 {
                            let _ = ws_out_tx.try_send(encode_mux_frame(MuxFrameKind::Data, sid, payload));
                        } else if let Some(tx) = streams.get(&sid) {
                            let _ = tx.send(payload.to_vec()).await;
                        }
                    }
                    MuxFrameKind::Heartbeat => {
                        let _ = ws_out_tx.try_send(encode_mux_frame(MuxFrameKind::Heartbeat, sid, &[]));
                    }
                    MuxFrameKind::Close => {
                        streams.remove(&sid);
                        if tunnel.remote_host == "mux-echo" || tunnel.remote_port == 0 {
                            break;
                        }
                    }
                }
            }
        }
    }
}

async fn bridge_async_rw_to_mux<S>(
    sid: u32,
    stream: S,
    mut in_rx: mpsc::Receiver<Vec<u8>>,
    ws_out_tx: mpsc::Sender<Vec<u8>>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut r_io, mut w_io) = tokio::io::split(stream);
    let pump_up = tokio::spawn(async move {
        while let Some(data) = in_rx.recv().await {
            if w_io.write_all(&data).await.is_err() {
                break;
            }
        }
    });
    let mut buf = vec![0u8; 16_384];
    while let Ok(n) = r_io.read(&mut buf).await {
        if n == 0 {
            break;
        }
        if ws_out_tx
            .send(encode_mux_frame(MuxFrameKind::Data, sid, &buf[..n]))
            .await
            .is_err()
        {
            break;
        }
    }
    pump_up.abort();
}

fn spawn_mux_upstream(
    sid: u32,
    tunnel: ForwardTunnel,
    state: AppState,
    in_rx: mpsc::Receiver<Vec<u8>>,
    ws_out_tx: mpsc::Sender<Vec<u8>>,
) {
    tokio::spawn(async move {
        let is_ssm = tunnel.instance_id.starts_with("i-") || tunnel.instance_id.starts_with("mi-");
        let creds = if is_ssm {
            if tunnel.binding_id.trim().is_empty() {
                crate::ws::resolve_tenant_aws_creds(&state.aws.accounts, &tunnel.tenant_id).await
            } else {
                state
                    .aws
                    .accounts
                    .find_connected_role_lease_for_user(
                        &tunnel.tenant_id,
                        &tunnel.owner_user_id,
                        &tunnel.binding_id,
                    )
                    .await
                    .map(|l| l.credentials)
            }
        } else {
            None
        };
        if let Some(c) = creds {
            let shut = std::sync::Arc::new(Notify::new());
            if let Ok((started, ssm_stream)) = state
                .aws
                .shells
                .connect_port_forward_tunnel(
                    &tunnel.region,
                    &tunnel.instance_id,
                    tunnel.remote_port,
                    &c,
                    shut.clone(),
                )
                .await
            {
                bridge_async_rw_to_mux(sid, ssm_stream, in_rx, ws_out_tx.clone()).await;
                shut.notify_waiters();
                let _ = state
                    .aws
                    .shells
                    .terminate_session(&tunnel.region, &started.session_id, &c)
                    .await;
                let _ = ws_out_tx
                    .send(encode_mux_frame(MuxFrameKind::Close, sid, &[]))
                    .await;
                return;
            }
        }

        let addr = format!("{}:{}", tunnel.remote_host, tunnel.remote_port);
        if let Ok(tcp) = TcpStream::connect(&addr).await {
            let _ = tcp.set_nodelay(true);
            bridge_async_rw_to_mux(sid, tcp, in_rx, ws_out_tx.clone()).await;
        }
        let _ = ws_out_tx
            .send(encode_mux_frame(MuxFrameKind::Close, sid, &[]))
            .await;
    });
}

// ---------------------------------------------------------------------------
// Audit CSV/JSON Export + Ed25519 License Management
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AuditListQuery {
    #[serde(default = "default_audit_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

const fn default_audit_limit() -> usize {
    100
}

fn csv_escape(val: &str) -> String {
    let clean = val.replace('"', "\"\"");
    format!("\"{clean}\"")
}

async fn audit_log_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AuditListQuery>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::AUDIT_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.audit.list_paginated(&tenant, q.limit, q.offset).await).into_response()
}

#[derive(Deserialize)]
struct AuditExportQuery {
    #[serde(default = "default_csv")]
    format: String,
}

fn default_csv() -> String {
    "csv".to_owned()
}

async fn audit_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AuditExportQuery>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::AUDIT_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let events = state.audit.list(&tenant).await;
    if q.format.eq_ignore_ascii_case("json") {
        let body = serde_json::to_string_pretty(&events).unwrap_or_else(|_| "[]".into());
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"operquay-audit.json\"",
                ),
            ],
            body,
        )
            .into_response();
    }
    let mut csv = String::from(
        "timestamp,action,outcome,user_email,role,ip,method,status_code,instance_id,target_host,details,session_id,recording,id,ts_ms,tenant_id,trace_id,protocol,detail,seq,prev_hash,entry_hash\n",
    );
    for ev in &events {
        use std::fmt::Write as _;
        let _ = writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&ev.timestamp),
            csv_escape(&ev.action),
            csv_escape(&ev.outcome),
            csv_escape(&ev.user_email),
            csv_escape(&ev.role),
            csv_escape(&ev.ip),
            csv_escape(&ev.method),
            ev.status_code,
            csv_escape(&ev.instance_id),
            csv_escape(&ev.target_host),
            csv_escape(&ev.details),
            csv_escape(&ev.session_id),
            csv_escape(ev.recording.as_deref().unwrap_or("")),
            csv_escape(&ev.id),
            ev.ts_ms,
            csv_escape(&ev.tenant_id),
            csv_escape(&ev.trace_id),
            csv_escape(&ev.protocol),
            csv_escape(&ev.detail),
            ev.seq,
            csv_escape(&ev.prev_hash),
            csv_escape(&ev.entry_hash),
        );
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"operquay-audit.csv\"",
            ),
        ],
        csv,
    )
        .into_response()
}

fn enrich_license_status(st: &operquay_license::LicenseStatus) -> serde_json::Value {
    let status_str = if st.valid && !matches!(st.plan, operquay_license::PlanTier::Unconfigured) {
        "active"
    } else {
        "unconfigured"
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0_i64, |d| d.as_secs() as i64);
    let days_remaining = if st.expires_at > now_secs {
        (st.expires_at - now_secs) / 86_400
    } else {
        0
    };
    let mut val = serde_json::to_value(st).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = val.as_object_mut() {
        obj.insert("status".to_owned(), serde_json::json!(status_str));
        obj.insert("controller".to_owned(), serde_json::json!(false));
        obj.insert(
            "days_remaining".to_owned(),
            serde_json::json!(days_remaining),
        );
        obj.insert("deployment_id".to_owned(), serde_json::json!(st.tenant_id));
        obj.insert("notice".to_owned(), serde_json::json!(""));
    }
    val
}

async fn license_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(enrich_license_status(
        &state.platform.license.status(&tenant).await,
    ))
    .into_response()
}

#[derive(Deserialize)]
struct RedeemLicenseBody {
    #[serde(alias = "code")]
    token: String,
    #[serde(default)]
    public_key: Option<String>,
}

async fn license_redeem(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RedeemLicenseBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::LICENSE_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .platform
        .license
        .redeem(&tenant, &body.token, body.public_key.as_deref())
        .await
    {
        Ok(st) => Json(enrich_license_status(&st)).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e),
    }
}

// ---------------------------------------------------------------------------
// Legacy Recording Policy/Conversions + Legacy Guacamole/RDP Compat Routes
// ---------------------------------------------------------------------------

async fn legacy_recordings_list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::RECORDINGS_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let entries = state.recordings.list(&tenant).await;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = canonical_recording_filename(&entry);
        let rec_type = if matches!(entry.protocol.as_str(), "rdp" | "vnc") {
            "rdp"
        } else {
            "ssh"
        };
        let has_mp4 = state.recordings.has_mp4(&entry.id).await;
        out.push(serde_json::json!({
            "id": entry.id,
            "name": name,
            "type": rec_type,
            "size": entry.bytes_written,
            "mod_time": format_epoch_ms_iso8601(entry.started_at_ms),
            "has_mp4": has_mp4,
            "tenant_id": entry.tenant_id,
            "protocol": entry.protocol,
            "target_host": entry.target_host,
            "format": entry.format,
            "started_at_ms": entry.started_at_ms,
            "bytes_written": entry.bytes_written,
            "frame_count": entry.frame_count,
            "sha256_hex": entry.sha256_hex,
            "fail_closed": entry.fail_closed,
            "status": entry.status,
            "encrypted": entry.encrypted,
            "legal_hold": entry.legal_hold,
            "legal_hold_reason": entry.legal_hold_reason,
            "retention_until_ms": entry.retention_until_ms,
            "archived_s3_uri": entry.archived_s3_uri,
            "archived_at_ms": entry.archived_at_ms,
        }));
    }
    Json(out).into_response()
}

async fn legacy_recording_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = require_any_perm(&state, &headers, &[perm::RECORDINGS_READ]).await {
        return *r;
    }
    if std::path::Path::new(&id)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("mp4"))
    {
        let Some(bytes) = state.recordings.get_mp4_bytes(&id).await else {
            return json_err(StatusCode::NOT_FOUND, "mp4 recording not found");
        };
        return (StatusCode::OK, [(header::CONTENT_TYPE, "video/mp4")], bytes).into_response();
    }
    let Some(bytes) = state.recordings.get_guac_bytes(&id).await else {
        return json_err(StatusCode::NOT_FOUND, "recording not found");
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        bytes,
    )
        .into_response()
}

async fn legacy_recording_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, _) =
        match require_any_perm(&state, &headers, &[perm::RECORDING_POLICY_MANAGE]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let resolved_id = state
        .recordings
        .resolve_id(&id)
        .await
        .unwrap_or_else(|| operquay_recording::strip_recording_extension(&id).to_owned());
    match state.recordings.delete_recording_checked(&id).await {
        Ok(removed) => {
            if removed {
                if let Some(pg) = state.pg_pool().await {
                    let _ = pg.delete_recording_metadata(&tenant, &resolved_id).await;
                }
            }
            Json(serde_json::json!({ "deleted": removed })).into_response()
        }
        Err(msg) => json_err(StatusCode::CONFLICT, msg),
    }
}

#[derive(Deserialize)]
struct ToggleRecBody {
    session_id: String,
    enabled: bool,
}

async fn legacy_toggle_recording(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ToggleRecBody>,
) -> Response {
    if let Err(r) = require_actor(&state, &headers).await {
        return *r;
    }
    state
        .platform
        .recording_active
        .write()
        .await
        .insert(body.session_id.clone(), body.enabled);
    Json(serde_json::json!({ "session_id": body.session_id, "recording": body.enabled }))
        .into_response()
}

#[derive(Deserialize)]
struct ConvertRecBody {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default = "default_mp4")]
    format: String,
    #[serde(default)]
    cast_data: String,
}

fn default_mp4() -> String {
    "mp4".to_owned()
}

async fn legacy_convert_recording(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ConvertRecBody>,
) -> Response {
    if let Err(r) = require_any_perm(&state, &headers, &[perm::RECORDINGS_READ]).await {
        return *r;
    }
    let Some(target) = body
        .id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| body.filename.clone().filter(|s| !s.trim().is_empty()))
    else {
        return json_err(StatusCode::BAD_REQUEST, "recording id or filename required");
    };
    let stored_bytes = state.recordings.get_guac_bytes(&target).await;
    let is_guac = target.to_ascii_lowercase().ends_with(".guac")
        || stored_bytes.as_ref().is_some_and(|raw| {
            raw.starts_with(b"4.size,") || raw.windows(6).any(|w| w == b".cfill" || w == b"4.copy")
        });
    let mp4 = if is_guac {
        if let Some(raw) = &stored_bytes {
            transcode_guac_to_mp4(raw)
        } else if !body.cast_data.is_empty() {
            transcode_guac_to_mp4(body.cast_data.as_bytes())
        } else {
            transcode_guac_to_mp4(b"4.size,1.0,3.960,3.600;")
        }
    } else {
        let cast_input = if !body.cast_data.is_empty() {
            body.cast_data
        } else if let Some(raw) = &stored_bytes {
            String::from_utf8_lossy(raw).into_owned()
        } else {
            "{\"version\":2,\"width\":80,\"height\":24}\n[0.1,\"o\",\"operquay session\\r\\n\"]\n"
                .to_owned()
        };
        transcode_cast_to_mp4(&cast_input)
    };
    let output_bytes = mp4.len();
    state.recordings.set_mp4_bytes(&target, mp4).await;
    let job_id = body.id.unwrap_or_else(|| format!("job-{}", Uuid::new_v4()));
    let st = ConversionStatus {
        id: job_id.clone(),
        job_id: job_id.clone(),
        status: "done".to_owned(),
        format: body.format,
        output_bytes,
        error: None,
    };
    state
        .platform
        .conversions
        .write()
        .await
        .insert(job_id, st.clone());
    Json(st).into_response()
}

async fn legacy_convert_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = require_any_perm(&state, &headers, &[perm::RECORDINGS_READ]).await {
        return *r;
    }
    match state.platform.conversions.read().await.get(&id).cloned() {
        Some(st) => Json(st).into_response(),
        None => json_err(StatusCode::NOT_FOUND, "conversion job not found"),
    }
}

async fn rec_policy_get(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let pol = state
        .platform
        .rec_policies
        .read()
        .await
        .get(&tenant)
        .cloned()
        .unwrap_or_default();
    Json(pol).into_response()
}

async fn rec_policy_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(pol): Json<RecordingPolicy>,
) -> Response {
    let (tenant, _) =
        match require_any_perm(&state, &headers, &[perm::RECORDING_POLICY_MANAGE]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    state
        .platform
        .rec_policies
        .write()
        .await
        .insert(tenant.clone(), pol.clone());
    if let Some(pg) = state.pg_pool().await {
        if let Ok(val) = serde_json::to_value(&pol) {
            if let Err(err) = pg.upsert_recording_policy(&tenant, &val).await {
                eprintln!("Warning: failed persisting recording policy for {tenant}: {err}");
            }
        }
    }
    Json(pol).into_response()
}

async fn rec_storage_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::RECORDINGS_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let list = state.recordings.list(&tenant).await;
    let total_bytes: usize = list.iter().map(|r| r.bytes_written).sum();
    Json(serde_json::json!({
        "configured": true,
        "required_production": false,
        "backend": "embedded+postgres",
        "count": list.len(),
        "total_bytes": total_bytes,
    }))
    .into_response()
}

async fn legacy_rdp_mode() -> impl IntoResponse {
    Json(serde_json::json!({
        "mode": "native-rust-ironrdp",
        "ironrdp": true,
        "guacd_required": false,
        "protocols": ["oqr2", "guacamole"],
    }))
}

async fn legacy_detect_rdp_clients() -> impl IntoResponse {
    Json(serde_json::json!({
        "browser_native": true,
        "clients": ["operquay-web-canvas", "operquay-guac-compat"],
    }))
}

async fn legacy_guac_sessions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(serde_json::json!({ "tenant_id": tenant, "sessions": [] })).into_response()
}

#[derive(Deserialize)]
struct LegacyRdpStartBody {
    #[serde(default = "default_rdp")]
    protocol: String,
    #[serde(default)]
    instance_id: String,
    #[serde(default)]
    aws_profile: String,
    #[serde(default)]
    aws_region: String,
    #[serde(default)]
    target_host: String,
    #[serde(default)]
    target_port: Option<u16>,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    width: Option<u32>,
    #[serde(default)]
    height: Option<u32>,
    #[serde(default)]
    security: String,
}

fn default_rdp() -> String {
    "rdp".to_owned()
}

fn parse_rdp_security(s: &str) -> Option<operquay_core::RdpSecurityMode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "" => None,
        "nla" => Some(operquay_core::RdpSecurityMode::Nla),
        "nla_ext" | "nla-ext" => Some(operquay_core::RdpSecurityMode::NlaExt),
        "tls" => Some(operquay_core::RdpSecurityMode::Tls),
        "rdp" | "classic" | "classic_rdp" => Some(operquay_core::RdpSecurityMode::ClassicRdp),
        _ => Some(operquay_core::RdpSecurityMode::Any),
    }
}

async fn legacy_start_rdp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LegacyRdpStartBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::SESSION_RDP]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let settings = state.settings.get(&tenant).await.unwrap_or_default();
    let aws_profile = (!body.aws_profile.trim().is_empty()).then_some(body.aws_profile);
    let aws_region = (!body.aws_region.trim().is_empty()).then_some(body.aws_region);
    let (mode, target_host) = if !body.target_host.trim().is_empty() {
        (LaunchMode::DirectTcp, body.target_host.trim().to_owned())
    } else if !body.instance_id.trim().is_empty() {
        (LaunchMode::SsmTunnel, body.instance_id.trim().to_owned())
    } else {
        return json_err(
            StatusCode::BAD_REQUEST,
            "target_host or valid EC2 instance_id is required",
        );
    };
    if mode == LaunchMode::SsmTunnel {
        if let Some(prof) = aws_profile.as_deref() {
            let trimmed = prof.trim();
            if trimmed.starts_with("user:")
                && state
                    .aws
                    .accounts
                    .find_connected_role_lease_for_user(&tenant, &claims.user_id, trimmed)
                    .await
                    .is_none()
            {
                return json_err(
                    StatusCode::UNAUTHORIZED,
                    "AWS role session expired or not connected. Reconnect the AWS role and try again.",
                );
            }
        }
    }
    let session_id = Uuid::new_v4().to_string();
    let rec_policy = state
        .platform
        .rec_policies
        .read()
        .await
        .get(&tenant)
        .cloned()
        .unwrap_or_default();
    let should_record = rec_policy.should_record_instance(&body.protocol, &target_host, "");
    let ticket = state
        .tickets
        .issue(
            TicketLaunchPayload {
                session_id: session_id.clone(),
                tenant_id: tenant,
                user_id: claims.user_id,
                auth_session_id: claims.session_id,
                protocol: body.protocol,
                launch_mode: mode,
                target_host,
                target_port: body.target_port.unwrap_or(3389),
                username: if body.username.is_empty() {
                    "operator".to_owned()
                } else {
                    body.username
                },
                password: operquay_core::SecretString::new(&body.password),
                width: body.width.unwrap_or(1280).clamp(320, 4096),
                height: body.height.unwrap_or(720).clamp(240, 4096),
                keyboard_layout: Some(settings.keyboard_layout),
                transport_mode: Some("oqr2".to_owned()),
                expected_cert_sha256: None,
                simulate_recording_fault: false,
                aws_profile,
                aws_region,
                rdp_security_mode: parse_rdp_security(&body.security),
            },
            TICKET_TTL,
        )
        .await;
    let rec_name = if should_record {
        format!("{session_id}.guac")
    } else {
        String::new()
    };
    Json(serde_json::json!({
        "session_id": session_id,
        "forward_id": session_id,
        "recording": should_record,
        "recording_name": rec_name,
        "token": ticket.to_string(),
        "ticket": ticket.to_string(),
        "ws_url": format!("/api/v1/ws/rdp?ticket={ticket}&transport=oqr2"),
        "guac_ws_url": format!("/guac-ws/{ticket}?ticket={ticket}"),
    }))
    .into_response()
}

async fn legacy_stop_rdp() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "stopped" }))
}

async fn license_public_key(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "algorithm": "Ed25519",
        "public_key": state.platform.license.public_key_b64(),
    }))
}

async fn compat_health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "operquay-rust",
        "clean_room_rdp": false,
        "ironrdp_present": true,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[derive(Deserialize)]
struct VaultPutBody {
    value: serde_json::Value,
}

async fn vault_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::DB_VIEWER]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let scoped = format!("vault/{tenant}/{key}");
    let buckets = state.platform.suggest.browse_buckets().await;
    match buckets.get("vault").and_then(|b| b.get(&scoped)) {
        Some(v) => Json(serde_json::json!({ "key": key, "value": v })).into_response(),
        None => json_err(StatusCode::NOT_FOUND, "vault key not found"),
    }
}

async fn vault_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(body): Json<VaultPutBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::DB_VIEWER]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let scoped = format!("vault/{tenant}/{key}");
    let serialized = match body.value {
        serde_json::Value::String(s) => s,
        other => other.to_string(),
    };
    match state
        .platform
        .suggest
        .put_bucket_key("vault", &scoped, &serialized)
        .await
    {
        Ok(()) => Json(serde_json::json!({ "status": "stored", "key": key })).into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

async fn vault_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::DB_VIEWER]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let scoped = format!("vault/{tenant}/{key}");
    let deleted = state
        .platform
        .suggest
        .delete_bucket_key("vault", &scoped)
        .await;
    Json(serde_json::json!({ "deleted": deleted })).into_response()
}
