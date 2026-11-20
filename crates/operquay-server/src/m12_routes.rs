#![forbid(unsafe_code)]

//! Milestone 12 REST & WebSocket Control-Plane Routes:
//! - M12.1: AI Agent / Model Context Protocol (MCP) Governance Proxy (`POST /api/mcp/rpc`)
//! - M12.2: Zero-Inbound Hybrid Reverse-Tunnel Agent Mux (`GET /api/agents/tunnel`)
//! - M12.3: Multi-Cloud Connectors for Microsoft Azure & Google Cloud Platform (`/api/clouds/*`)
//! - M12.4: Unified Identity & Resource Blast-Radius Access Graph (`/api/access-graph/*`)
//! - M12.5: Hardware Device Trust & MDM Posture Attestation (`/api/device-trust/*`)

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message as WsMsg, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use operquay_auth::crypto::extract_tenant_id_checked;
use operquay_auth::pg::{
    PgCloudConnectorRow, PgDevicePostureRow, PgDeviceTrustPolicyRow, PgHybridAgentRow,
    PgMcpAgentRow, PgMcpInvocationRow,
};
use operquay_auth::policy::perm;
use operquay_aws::access_graph::{
    analyze_access_graph, AccessEdge, AccessEdgeKind, AccessGraphInput, AccessGraphReport,
    AccessNode, AccessNodeKind,
};
use operquay_db::dlp::{redact_query_result, DbDlpPolicy};
use operquay_forward::{decode_mux_frame, encode_mux_frame, MuxFrameKind};
use regex::Regex;
use serde::Deserialize;
use uuid::Uuid;

use crate::agent_hub::{AgentOutboundFrame, AgentTargetSpec, HybridAgentRecord, PublicHybridAgent};
use crate::auth_routes::{require_actor, require_any_perm};
use crate::device_trust::{DevicePostureAttestation, DevicePostureInput, DeviceTrustPolicy};
use crate::governance_routes::{persist_jit_request, record_gov_audit};
use crate::jit::{now_unix_secs, CreateJitRequestInput, JitTargetType};
use crate::mcp::{
    mcp_tools_catalog, CreateMcpAgentInput, McpAgent, McpToolInvocation, PublicMcpAgent,
};
use crate::multicloud::{
    sync_azure_connector, sync_gcp_connector, AzureSsoStartInput, CloudConnectorRecord,
    CloudResourceItem, CreateCloudConnectorInput, GcpSsoStartInput, PublicCloudConnector,
};
use crate::AppState;

pub fn m12_router() -> Router<AppState> {
    Router::new()
        // M12.1 MCP Governance Proxy
        .route(
            "/api/mcp/agents",
            get(list_mcp_agents).post(create_mcp_agent),
        )
        .route("/api/mcp/agents/{id}", delete(revoke_mcp_agent))
        .route("/api/mcp/invocations", get(list_mcp_invocations))
        .route("/api/mcp/rpc", post(mcp_json_rpc))
        // M12.2 Zero-Inbound Hybrid Reverse-Tunnel Agent
        .route("/api/agents", get(list_hybrid_agents))
        .route("/api/agents/enroll", post(enroll_hybrid_agent))
        .route("/api/agents/{id}", delete(delete_hybrid_agent))
        .route("/api/agents/{id}/dial-check", post(dial_check_hybrid_agent))
        .route("/api/agents/tunnel", get(ws_hybrid_agent_tunnel))
        // M12.3 Multi-Cloud Azure & GCP Connectors & Secretless SSO
        .route(
            "/api/clouds/connectors",
            get(list_cloud_connectors).post(create_cloud_connector),
        )
        .route(
            "/api/clouds/connectors/{id}",
            delete(delete_cloud_connector),
        )
        .route(
            "/api/clouds/connectors/{id}/sync",
            post(sync_cloud_connector),
        )
        .route("/api/clouds/resources", get(list_cloud_resources))
        .route("/api/clouds/azure/sso/start", post(azure_sso_start))
        .route("/api/clouds/azure/sso/poll", post(azure_sso_poll))
        .route("/api/clouds/azure/sso/connect", post(azure_sso_connect))
        .route("/api/clouds/gcp/sso/start", post(gcp_sso_start))
        .route("/api/clouds/gcp/sso/callback", get(gcp_sso_callback))
        .route("/api/clouds/gcp/sso/status", get(gcp_sso_status))
        .route("/api/clouds/gcp/sso/connect", post(gcp_sso_connect))
        // M12.4 Unified Access Graph & Blast Radius
        .route("/api/access-graph", get(get_access_graph))
        .route(
            "/api/access-graph/blast-radius/{principal_id}",
            get(get_principal_blast_radius),
        )
        // M12.5 Hardware Device Trust & MDM Posture
        .route(
            "/api/device-trust/policy",
            get(get_device_trust_policy).put(put_device_trust_policy),
        )
        .route("/api/device-trust/attest", post(post_device_attestation))
        .route("/api/device-trust/devices", get(list_device_postures))
}

fn json_err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// PG persistence helpers
// ---------------------------------------------------------------------------

async fn persist_mcp_agent(state: &AppState, agent: &McpAgent) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let row = PgMcpAgentRow {
        id: agent.id.clone(),
        tenant_id: agent.tenant_id.clone(),
        name: agent.name.clone(),
        sponsor_user_id: agent.sponsor_user_id.clone(),
        sponsor_email: agent.sponsor_email.clone(),
        token_hash: agent.token_hash.clone(),
        allowed_tools_json: serde_json::to_string(&agent.allowed_tools)
            .unwrap_or_else(|_| "[]".to_owned()),
        require_jit_tools_json: serde_json::to_string(&agent.require_jit_tools)
            .unwrap_or_else(|_| "[]".to_owned()),
        rate_limit_per_min: i32::try_from(agent.rate_limit_per_min).unwrap_or(60),
        status: agent.status.clone(),
        expires_at: agent.expires_at,
        created_at: agent.created_at,
        revoked_at: agent.revoked_at,
        payload_json: serde_json::to_string(agent).unwrap_or_else(|_| "{}".to_owned()),
    };
    if let Err(err) = pg.upsert_mcp_agent(&row).await {
        tracing::warn!(error = %err, "failed persisting mcp_agent");
    }
}

async fn persist_mcp_invocation(state: &AppState, inv: &McpToolInvocation) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let row = PgMcpInvocationRow {
        id: inv.id.clone(),
        tenant_id: inv.tenant_id.clone(),
        agent_id: inv.agent_id.clone(),
        sponsor_user_id: inv.sponsor_user_id.clone(),
        tool_name: inv.tool_name.clone(),
        sanitized_args: inv.sanitized_args.clone(),
        decision: inv.decision.clone(),
        jit_request_id: inv.jit_request_id.clone(),
        masked_result_preview: inv.masked_result_preview.clone(),
        duration_ms: inv.duration_ms,
        created_at: inv.created_at,
    };
    if let Err(err) = pg.insert_mcp_invocation(&row).await {
        tracing::warn!(error = %err, "failed persisting mcp_tool_invocation");
    }
}

async fn persist_hybrid_agent(state: &AppState, rec: &HybridAgentRecord) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let row = PgHybridAgentRow {
        id: rec.id.clone(),
        tenant_id: rec.tenant_id.clone(),
        name: rec.name.clone(),
        enrollment_token_hash: rec.enrollment_token_hash.clone(),
        cert_fingerprint_sha256: rec.cert_fingerprint_sha256.clone(),
        hostname: rec.hostname.clone(),
        os: rec.os.clone(),
        arch: rec.arch.clone(),
        labels_json: serde_json::to_string(&rec.labels).unwrap_or_else(|_| "{}".to_owned()),
        targets_json: serde_json::to_string(&rec.targets).unwrap_or_else(|_| "[]".to_owned()),
        status: rec.status.clone(),
        last_heartbeat_at: rec.last_heartbeat_at,
        created_at: rec.created_at,
        payload_json: serde_json::to_string(rec).unwrap_or_else(|_| "{}".to_owned()),
    };
    if let Err(err) = pg.upsert_hybrid_agent(&row).await {
        tracing::warn!(error = %err, "failed persisting hybrid_agent");
    }
}

async fn persist_cloud_connector(state: &AppState, rec: &CloudConnectorRecord) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let row = PgCloudConnectorRow {
        id: rec.id.clone(),
        tenant_id: rec.tenant_id.clone(),
        provider: rec.provider.clone(),
        name: rec.name.clone(),
        account_or_project_id: rec.account_or_project_id.clone(),
        tenant_or_org_id: rec.tenant_or_org_id.clone(),
        region: rec.region.clone(),
        credentials_json: rec.credentials_json.clone(),
        config_json: rec.config.to_string(),
        status: rec.status.clone(),
        last_synced_at: rec.last_synced_at,
        created_at: rec.created_at,
    };
    if let Err(err) = pg.upsert_cloud_connector(&row).await {
        tracing::warn!(error = %err, "failed persisting cloud_connector");
    }
}

async fn persist_device_trust_policy(state: &AppState, tenant: &str, policy: &DeviceTrustPolicy) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let row = PgDeviceTrustPolicyRow {
        tenant_id: tenant.to_owned(),
        policy_json: serde_json::to_string(policy).unwrap_or_else(|_| "{}".to_owned()),
    };
    if let Err(err) = pg.upsert_device_trust_policy(&row).await {
        tracing::warn!(error = %err, "failed persisting device_trust_policy");
    }
}

async fn persist_device_posture(state: &AppState, att: &DevicePostureAttestation) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let row = PgDevicePostureRow {
        id: att.id.clone(),
        tenant_id: att.tenant_id.clone(),
        user_id: att.user_id.clone(),
        device_id: att.device_id.clone(),
        provider: att.provider.clone(),
        hostname: att.hostname.clone(),
        os_version: att.os_version.clone(),
        disk_encrypted: att.disk_encrypted,
        edr_running: att.edr_running,
        edr_agent: att.edr_agent.clone(),
        os_patch_age_days: i32::try_from(att.os_patch_age_days).unwrap_or(i32::MAX),
        compliant: att.compliant,
        reasons_json: serde_json::to_string(&att.reasons).unwrap_or_else(|_| "[]".to_owned()),
        attested_at: att.attested_at,
        expires_at: att.expires_at,
    };
    if let Err(err) = pg.upsert_device_posture(&row).await {
        tracing::warn!(error = %err, "failed persisting device_posture_attestation");
    }
}

// ---------------------------------------------------------------------------
// M12.1: AI Agent / MCP Proxy Handlers
// ---------------------------------------------------------------------------

async fn list_mcp_agents(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) =
        match require_any_perm(&state, &headers, &[perm::MCP_MANAGE, perm::AUDIT_READ]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let agents = state.mcp.list_agents(&tenant).await;
    Json(serde_json::json!({ "agents": agents })).into_response()
}

async fn create_mcp_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateMcpAgentInput>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::MCP_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .mcp
        .create_agent(&tenant, &claims.user_id, &claims.email, input)
        .await
    {
        Ok((agent, raw_token)) => {
            persist_mcp_agent(&state, &agent).await;
            record_gov_audit(
                &state,
                &tenant,
                &claims.user_id,
                &claims.email,
                &claims.role,
                "",
                &agent.id,
                "mcp_agent_created",
                "mcp_agent",
                &agent.id,
                format!(
                    "name={} rate_limit={}/min",
                    agent.name, agent.rate_limit_per_min
                ),
                "success",
                None,
            )
            .await;
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "agent": PublicMcpAgent::from(&agent),
                    "token": raw_token,
                })),
            )
                .into_response()
        }
        Err(err) => json_err(StatusCode::UNPROCESSABLE_ENTITY, err),
    }
}

async fn revoke_mcp_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::MCP_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(agent) = state.mcp.revoke_agent(&tenant, &id).await else {
        return json_err(StatusCode::NOT_FOUND, "MCP agent not found");
    };
    persist_mcp_agent(&state, &agent).await;
    record_gov_audit(
        &state,
        &tenant,
        &claims.user_id,
        &claims.email,
        &claims.role,
        "",
        &agent.id,
        "mcp_agent_revoked",
        "mcp_agent",
        &agent.id,
        format!("revoked MCP agent '{}'", agent.name),
        "success",
        None,
    )
    .await;
    Json(serde_json::json!({
        "revoked": true,
        "agent": PublicMcpAgent::from(&agent),
    }))
    .into_response()
}

async fn list_mcp_invocations(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) =
        match require_any_perm(&state, &headers, &[perm::MCP_MANAGE, perm::AUDIT_READ]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let invocations = state.mcp.list_invocations(&tenant).await;
    Json(serde_json::json!({ "invocations": invocations })).into_response()
}

#[derive(Debug, Deserialize)]
struct JsonRpcReq {
    #[serde(default = "default_rpc_ver")]
    jsonrpc: String,
    #[serde(default)]
    id: serde_json::Value,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

fn default_rpc_ver() -> String {
    "2.0".to_owned()
}

fn rpc_ok(id: &serde_json::Value, result: &serde_json::Value) -> Response {
    Json(serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    }))
    .into_response()
}

fn rpc_err(
    status: StatusCode,
    id: &serde_json::Value,
    code: i64,
    message: impl Into<String>,
    data: Option<serde_json::Value>,
) -> Response {
    let mut err_obj = serde_json::json!({
        "code": code,
        "message": message.into(),
    });
    if let Some(d) = data {
        err_obj["data"] = d;
    }
    (
        status,
        Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": err_obj,
        })),
    )
        .into_response()
}

fn redact_pii_text_for_mcp(raw: &str) -> String {
    struct PiiRegexes {
        ssn: Regex,
        email: Regex,
        aws_key: Regex,
    }
    static RE: OnceLock<PiiRegexes> = OnceLock::new();
    let re = RE.get_or_init(|| PiiRegexes {
        ssn: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")
            .unwrap_or_else(|_| Regex::new("a^").unwrap_or_else(|_| unreachable!())),
        email: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
            .unwrap_or_else(|_| Regex::new("a^").unwrap_or_else(|_| unreachable!())),
        aws_key: Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
            .unwrap_or_else(|_| Regex::new("a^").unwrap_or_else(|_| unreachable!())),
    });
    let step1 = crate::dlp::sanitize_command_for_audit(raw);
    let step2 = re.ssn.replace_all(&step1, "[REDACTED-SSN]");
    let step3 = re.aws_key.replace_all(&step2, "[REDACTED-AWS-KEY]");
    re.email
        .replace_all(&step3, "[REDACTED-EMAIL]")
        .into_owned()
}

async fn record_and_persist_mcp_invocation(
    state: &AppState,
    agent: &McpAgent,
    tool_name: &str,
    sanitized_args: String,
    decision: &str,
    jit_request_id: Option<String>,
    masked_result_preview: String,
    duration_ms: i64,
) {
    let inv = McpToolInvocation {
        id: format!("mcpi-{}", Uuid::new_v4()),
        tenant_id: agent.tenant_id.clone(),
        agent_id: agent.id.clone(),
        sponsor_user_id: agent.sponsor_user_id.clone(),
        tool_name: tool_name.to_owned(),
        sanitized_args,
        decision: decision.to_owned(),
        jit_request_id,
        masked_result_preview,
        duration_ms,
        created_at: now_unix_secs(),
    };
    state.mcp.record_invocation(inv.clone()).await;
    persist_mcp_invocation(state, &inv).await;
}

async fn mcp_json_rpc(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<JsonRpcReq>,
) -> Response {
    let tenant = extract_tenant_id_checked(None, &headers, &state.trusted_proxies);
    let Some(token) = extract_bearer_token(&headers) else {
        return rpc_err(
            StatusCode::UNAUTHORIZED,
            &req.id,
            -32001,
            "missing Bearer oqmcp_ token",
            None,
        );
    };
    let Some(agent) = state.mcp.authenticate_token(&tenant, token).await else {
        return rpc_err(
            StatusCode::UNAUTHORIZED,
            &req.id,
            -32001,
            "invalid, expired, or revoked MCP agent token",
            None,
        );
    };
    if !state.mcp.check_and_consume_rate_limit(&agent).await {
        return rpc_err(
            StatusCode::TOO_MANY_REQUESTS,
            &req.id,
            -32029,
            "MCP agent rate limit exceeded",
            None,
        );
    }
    if req.jsonrpc != "2.0" {
        return rpc_err(
            StatusCode::BAD_REQUEST,
            &req.id,
            -32600,
            "jsonrpc version must be '2.0'",
            None,
        );
    }

    match req.method.as_str() {
        "initialize" => rpc_ok(
            &req.id,
            &serde_json::json!({
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "operquay-mcp-proxy",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "capabilities": { "tools": {} },
                "sponsor": {
                    "user_id": agent.sponsor_user_id,
                    "email": agent.sponsor_email,
                }
            }),
        ),
        "tools/list" => rpc_ok(
            &req.id,
            &serde_json::json!({
                "tools": mcp_tools_catalog(&agent),
            }),
        ),
        "tools/call" => handle_mcp_tool_call(&state, &tenant, &agent, &req.id, &req.params).await,
        other => rpc_err(
            StatusCode::NOT_FOUND,
            &req.id,
            -32601,
            format!("method '{other}' not found"),
            None,
        ),
    }
}

async fn handle_mcp_tool_call(
    state: &AppState,
    tenant: &str,
    agent: &McpAgent,
    rpc_id: &serde_json::Value,
    params: &serde_json::Value,
) -> Response {
    let start = Instant::now();
    let tool_name = params["name"].as_str().unwrap_or("").trim();
    if tool_name.is_empty() {
        return rpc_err(
            StatusCode::BAD_REQUEST,
            rpc_id,
            -32602,
            "params.name is required",
            None,
        );
    }
    let args = &params["arguments"];
    let sanitized_args = redact_pii_text_for_mcp(&args.to_string());

    let in_allowed = agent
        .allowed_tools
        .iter()
        .any(|t| t == "*" || t == tool_name);
    let in_jit = agent.require_jit_tools.iter().any(|t| t == tool_name);
    if !in_allowed && !in_jit {
        let elapsed = i64::try_from(start.elapsed().as_millis()).unwrap_or(0);
        record_and_persist_mcp_invocation(
            state,
            agent,
            tool_name,
            sanitized_args,
            "denied",
            None,
            "RBAC denied: tool not in allowed_tools".to_owned(),
            elapsed,
        )
        .await;
        record_gov_audit(
            state,
            tenant,
            &agent.sponsor_user_id,
            &agent.sponsor_email,
            "mcp_agent",
            "",
            &agent.id,
            "mcp_tool_denied",
            "mcp_tool",
            tool_name,
            format!("agent={} denied by RBAC", agent.name),
            "denied",
            None,
        )
        .await;
        return rpc_err(
            StatusCode::FORBIDDEN,
            rpc_id,
            -32003,
            format!(
                "tool '{tool_name}' is not permitted for MCP agent '{}'",
                agent.name
            ),
            None,
        );
    }

    if in_jit {
        let target_key = format!("mcp:{}:{tool_name}", agent.id);
        let active = state
            .governance
            .find_active_grant(
                tenant,
                &agent.sponsor_user_id,
                JitTargetType::DbWrite,
                &target_key,
            )
            .await;
        if active.is_none() {
            let input = CreateJitRequestInput {
                target_type: JitTargetType::DbWrite,
                target_id: target_key,
                requested_role: "mcp-jit-tool".to_owned(),
                duration_secs: 1800,
                reason: format!(
                    "AI agent '{}' sponsored by {} requested JIT tool '{tool_name}'",
                    agent.name, agent.sponsor_email
                ),
                ticket_id: String::new(),
                ticket_provider: String::new(),
            };
            let jit_req = match state
                .governance
                .create_request(tenant, &agent.sponsor_user_id, &agent.sponsor_email, input)
                .await
            {
                Ok(r) => r,
                Err(err) => {
                    return rpc_err(StatusCode::BAD_REQUEST, rpc_id, -32000, err, None);
                }
            };
            persist_jit_request(state, &jit_req).await;
            if let Ok(payload) = serde_json::to_value(&jit_req) {
                state
                    .governance
                    .dispatch_webhook(tenant, "access_request.created", payload)
                    .await;
            }
            let elapsed = i64::try_from(start.elapsed().as_millis()).unwrap_or(0);
            record_and_persist_mcp_invocation(
                state,
                agent,
                tool_name,
                sanitized_args,
                "jit_pending",
                Some(jit_req.id.clone()),
                format!("JIT approval required: {}", jit_req.id),
                elapsed,
            )
            .await;
            return rpc_err(
                StatusCode::FORBIDDEN,
                rpc_id,
                -32010,
                format!(
                    "tool '{tool_name}' requires human-in-the-loop JIT approval (request {})",
                    jit_req.id
                ),
                Some(serde_json::json!({
                    "jit_required": true,
                    "jit_request_id": jit_req.id,
                })),
            );
        }
    }

    let exec_result = execute_mcp_tool(state, tenant, tool_name, args).await;
    let elapsed = i64::try_from(start.elapsed().as_millis()).unwrap_or(0);
    match exec_result {
        Ok(val) => {
            let text_raw = serde_json::to_string_pretty(&val).unwrap_or_else(|_| "{}".to_owned());
            let redacted_text = redact_pii_text_for_mcp(&text_raw);
            let preview: String = redacted_text.chars().take(480).collect();
            record_and_persist_mcp_invocation(
                state,
                agent,
                tool_name,
                sanitized_args,
                "allowed",
                None,
                preview,
                elapsed,
            )
            .await;
            record_gov_audit(
                state,
                tenant,
                &agent.sponsor_user_id,
                &agent.sponsor_email,
                "mcp_agent",
                "",
                &agent.id,
                "mcp_tool_invocation",
                "mcp_tool",
                tool_name,
                format!("agent={} allowed elapsed_ms={elapsed}", agent.name),
                "success",
                None,
            )
            .await;
            rpc_ok(
                rpc_id,
                &serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": redacted_text,
                    }]
                }),
            )
        }
        Err((code, msg)) => {
            record_and_persist_mcp_invocation(
                state,
                agent,
                tool_name,
                sanitized_args,
                "error",
                None,
                msg.chars().take(480).collect(),
                elapsed,
            )
            .await;
            rpc_err(StatusCode::BAD_REQUEST, rpc_id, code, msg, None)
        }
    }
}

async fn execute_mcp_tool(
    state: &AppState,
    tenant: &str,
    tool_name: &str,
    args: &serde_json::Value,
) -> Result<serde_json::Value, (i64, String)> {
    match tool_name {
        "operquay.instances.list" => {
            let ec2 = state.aws.discovery.list_instances(tenant).await;
            let multicloud = state.multicloud.list_resources(tenant, None).await;
            Ok(serde_json::json!({
                "ec2_instances": ec2,
                "multicloud_resources": multicloud,
            }))
        }
        "operquay.db.query" | "operquay.db.mutate" => {
            let conn_id = args["connection_id"]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((-32602, "arguments.connection_id is required".to_owned()))?;
            let sql = args["sql"]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((-32602, "arguments.sql is required".to_owned()))?;
            let read_only = tool_name == "operquay.db.query";
            let mut res = state
                .platform
                .db
                .query(tenant, conn_id, sql, read_only)
                .await
                .map_err(|e| (-32004, e.message))?;
            let mut policy = state.governance.get_dlp_policy(tenant).await.db_dlp;
            let _ = DbDlpPolicy::default();
            policy.enabled = true;
            policy.mask_emails = true;
            policy.mask_ssn = true;
            policy.mask_secrets = true;
            policy.unmasked_roles.clear();
            let dlp_summary = redact_query_result(&mut res, &policy, "__ai_mcp_agent__");
            Ok(serde_json::json!({
                "result": res,
                "dlp_masked_cells": dlp_summary.masked_cells,
                "dlp_categories": dlp_summary.categories,
            }))
        }
        "operquay.k8s.pods" => {
            let clusters = state.platform.k8s.list_clusters(tenant).await;
            let requested_cluster = args["cluster"].as_str().unwrap_or("");
            let requested_ns = args["namespace"].as_str().unwrap_or("default");
            Ok(serde_json::json!({
                "cluster": requested_cluster,
                "namespace": requested_ns,
                "connected_clusters": clusters,
            }))
        }
        "operquay.aws.topology_summary" => {
            let report = build_tenant_access_graph(state, tenant).await;
            Ok(serde_json::json!({
                "summary": report.summary,
                "findings": report.findings,
            }))
        }
        other => Err((-32601, format!("unknown MCP tool '{other}'"))),
    }
}

// ---------------------------------------------------------------------------
// M12.2: Zero-Inbound Hybrid Reverse-Tunnel Agent Handlers
// ---------------------------------------------------------------------------

async fn list_hybrid_agents(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) =
        match require_any_perm(&state, &headers, &[perm::AGENTS_MANAGE, perm::AUDIT_READ]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let agents = state.agent_hub.list_agents(&tenant).await;
    Json(serde_json::json!({ "agents": agents })).into_response()
}

#[derive(Debug, Deserialize)]
struct EnrollAgentBody {
    name: String,
    #[serde(default)]
    labels: HashMap<String, String>,
    #[serde(default)]
    targets: Vec<AgentTargetSpec>,
}

async fn enroll_hybrid_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EnrollAgentBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::AGENTS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .agent_hub
        .enroll_agent(&tenant, &body.name, body.labels, body.targets)
        .await
    {
        Ok((rec, raw_token)) => {
            persist_hybrid_agent(&state, &rec).await;
            record_gov_audit(
                &state,
                &tenant,
                &claims.user_id,
                &claims.email,
                &claims.role,
                "",
                &rec.id,
                "hybrid_agent_enrolled",
                "hybrid_agent",
                &rec.id,
                format!("name={} targets={}", rec.name, rec.targets.len()),
                "success",
                None,
            )
            .await;
            let host_hdr = headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("localhost:5444");
            let mut target_flags = String::new();
            for t in &rec.targets {
                let _ = write!(
                    target_flags,
                    " --target {}:{}:{}",
                    t.protocol, t.host, t.port
                );
            }
            let run_command = format!(
                "operquay-agent --server wss://{host_hdr}/api/agents/tunnel --name \"{}\" --token {raw_token}{target_flags}",
                rec.name
            );
            let pub_view = PublicHybridAgent {
                id: rec.id,
                tenant_id: rec.tenant_id,
                name: rec.name,
                cert_fingerprint_sha256: rec.cert_fingerprint_sha256,
                hostname: rec.hostname,
                os: rec.os,
                arch: rec.arch,
                labels: rec.labels,
                targets: rec.targets,
                status: rec.status,
                online: false,
                last_heartbeat_at: rec.last_heartbeat_at,
                created_at: rec.created_at,
            };
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "agent": pub_view,
                    "enrollment_token": raw_token,
                    "run_command": run_command,
                })),
            )
                .into_response()
        }
        Err(err) => json_err(StatusCode::UNPROCESSABLE_ENTITY, err),
    }
}

async fn delete_hybrid_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::AGENTS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if !state.agent_hub.delete_agent(&tenant, &id).await {
        return json_err(StatusCode::NOT_FOUND, "hybrid agent not found");
    }
    if let Some(pg) = state.pg_pool().await {
        let _ = pg.delete_hybrid_agent(&tenant, &id).await;
    }
    record_gov_audit(
        &state,
        &tenant,
        &claims.user_id,
        &claims.email,
        &claims.role,
        "",
        &id,
        "hybrid_agent_deleted",
        "hybrid_agent",
        &id,
        "deleted hybrid reverse-tunnel agent".to_owned(),
        "success",
        None,
    )
    .await;
    Json(serde_json::json!({ "deleted": true, "id": id })).into_response()
}

#[derive(Debug, Deserialize)]
struct DialCheckBody {
    target: String,
    #[serde(default)]
    payload: Option<String>,
}

async fn dial_check_hybrid_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<DialCheckBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::AGENTS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .agent_hub
        .dial_through_agent(&tenant, &id, &body.target)
        .await
    {
        Ok((stream_id, mut rx, handle)) => {
            let mut echoed = String::new();
            if let Some(ref probe) = body.payload {
                if handle
                    .send_data_to_agent(stream_id, probe.as_bytes().to_vec())
                    .is_ok()
                {
                    if let Ok(Some(bytes)) =
                        tokio::time::timeout(Duration::from_secs(3), rx.recv()).await
                    {
                        echoed = String::from_utf8_lossy(&bytes).into_owned();
                    }
                }
            }
            handle.send_close_to_agent(stream_id);
            Json(serde_json::json!({
                "ok": true,
                "stream_id": stream_id,
                "target": body.target,
                "response": echoed,
            }))
            .into_response()
        }
        Err(err) => json_err(StatusCode::BAD_GATEWAY, err),
    }
}

async fn ws_hybrid_agent_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let tenant = extract_tenant_id_checked(None, &headers, &state.trusted_proxies);
    let Some(token) = extract_bearer_token(&headers) else {
        return json_err(StatusCode::UNAUTHORIZED, "missing agent Bearer token");
    };
    let Some(rec) = state.agent_hub.authenticate_token(&tenant, token).await else {
        return json_err(StatusCode::UNAUTHORIZED, "invalid hybrid agent token");
    };
    let agent_id = rec.id.clone();
    ws.on_upgrade(move |socket| serve_agent_tunnel_ws(state, tenant, agent_id, socket))
}

#[derive(Debug, Deserialize)]
struct AgentRegisterMsg {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    arch: String,
    #[serde(default)]
    cert_fingerprint_sha256: String,
    #[serde(default)]
    labels: HashMap<String, String>,
    #[serde(default)]
    targets: Vec<AgentTargetSpec>,
}

async fn serve_agent_tunnel_ws(
    state: AppState,
    tenant: String,
    agent_id: String,
    socket: WebSocket,
) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let reg_timeout = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(Ok(msg)) = ws_rx.next().await {
            if let WsMsg::Text(txt) = msg {
                if let Ok(reg) = serde_json::from_str::<AgentRegisterMsg>(&txt) {
                    if reg.msg_type == "register" {
                        return Some(reg);
                    }
                }
            }
        }
        None
    })
    .await;

    let Ok(Some(reg)) = reg_timeout else {
        let _ = ws_tx.close().await;
        return;
    };

    let Ok((saved, handle, mut out_rx)) = state
        .agent_hub
        .mark_registered(
            &tenant,
            &agent_id,
            reg.hostname,
            reg.os,
            reg.arch,
            reg.cert_fingerprint_sha256,
            reg.labels,
            reg.targets,
        )
        .await
    else {
        let _ = ws_tx.close().await;
        return;
    };
    persist_hybrid_agent(&state, &saved).await;

    loop {
        tokio::select! {
            out_opt = out_rx.recv() => {
                let Some(frame) = out_opt else { break; };
                let ws_msg = match frame {
                    AgentOutboundFrame::ControlJson(s) => WsMsg::Text(s.into()),
                    AgentOutboundFrame::MuxData { stream_id, data } => {
                        WsMsg::Binary(encode_mux_frame(MuxFrameKind::Data, stream_id, &data).into())
                    }
                    AgentOutboundFrame::MuxClose { stream_id } => {
                        WsMsg::Binary(encode_mux_frame(MuxFrameKind::Close, stream_id, &[]).into())
                    }
                };
                if ws_tx.send(ws_msg).await.is_err() {
                    break;
                }
            }
            in_opt = ws_rx.next() => {
                let Some(Ok(msg)) = in_opt else { break; };
                match msg {
                    WsMsg::Close(_) => break,
                    WsMsg::Binary(bytes) => {
                        if let Some((kind, stream_id, payload)) = decode_mux_frame(&bytes) {
                            match kind {
                                MuxFrameKind::Data => {
                                    handle.forward_data_from_agent(stream_id, payload.to_vec()).await;
                                }
                                MuxFrameKind::Close => {
                                    handle.close_stream_from_agent(stream_id).await;
                                }
                                _ => {}
                            }
                        }
                    }
                    WsMsg::Text(txt) => {
                        let Ok(val) = serde_json::from_str::<serde_json::Value>(&txt) else { continue; };
                        match val["type"].as_str().unwrap_or("") {
                            "heartbeat" => {
                                state.agent_hub.touch_heartbeat(&tenant, &agent_id).await;
                            }
                            "dial_ok" => {
                                let sid = u32::try_from(val["stream_id"].as_u64().unwrap_or(0)).unwrap_or(0);
                                handle.notify_dial_result(sid, true, String::new()).await;
                            }
                            "dial_err" => {
                                let sid = u32::try_from(val["stream_id"].as_u64().unwrap_or(0)).unwrap_or(0);
                                let err = val["error"].as_str().unwrap_or("dial failed").to_owned();
                                handle.notify_dial_result(sid, false, err).await;
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    state.agent_hub.mark_offline(&tenant, &agent_id).await;
}

// ---------------------------------------------------------------------------
// M12.3: Multi-Cloud Azure & GCP Connector Handlers
// ---------------------------------------------------------------------------

async fn list_cloud_connectors(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let connectors = state.multicloud.list_connectors(&tenant).await;
    Json(serde_json::json!({ "connectors": connectors })).into_response()
}

async fn create_cloud_connector(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateCloudConnectorInput>,
) -> Response {
    let (tenant, claims) = match require_any_perm(
        &state,
        &headers,
        &[perm::AWS_ACCOUNTS_MANAGE, perm::INSTANCES_SCAN],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state.multicloud.add_connector(&tenant, input).await {
        Ok(rec) => {
            persist_cloud_connector(&state, &rec).await;
            record_gov_audit(
                &state,
                &tenant,
                &claims.user_id,
                &claims.email,
                &claims.role,
                "",
                &rec.id,
                "cloud_connector_created",
                "cloud_connector",
                &rec.id,
                format!("provider={} name={}", rec.provider, rec.name),
                "success",
                None,
            )
            .await;
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "connector": PublicCloudConnector::from(&rec),
                })),
            )
                .into_response()
        }
        Err(err) => json_err(StatusCode::UNPROCESSABLE_ENTITY, err),
    }
}

async fn delete_cloud_connector(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, claims) = match require_any_perm(
        &state,
        &headers,
        &[perm::AWS_ACCOUNTS_MANAGE, perm::INSTANCES_SCAN],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if !state.multicloud.delete_connector(&tenant, &id).await {
        return json_err(StatusCode::NOT_FOUND, "cloud connector not found");
    }
    if let Some(pg) = state.pg_pool().await {
        let _ = pg.delete_cloud_connector(&tenant, &id).await;
    }
    record_gov_audit(
        &state,
        &tenant,
        &claims.user_id,
        &claims.email,
        &claims.role,
        "",
        &id,
        "cloud_connector_deleted",
        "cloud_connector",
        &id,
        "deleted cloud connector".to_owned(),
        "success",
        None,
    )
    .await;
    Json(serde_json::json!({ "deleted": true, "id": id })).into_response()
}

async fn sync_cloud_connector(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, _) = match require_any_perm(
        &state,
        &headers,
        &[perm::AWS_ACCOUNTS_MANAGE, perm::INSTANCES_SCAN],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(conn) = state.multicloud.get_connector(&tenant, &id).await else {
        return json_err(StatusCode::NOT_FOUND, "cloud connector not found");
    };
    let Ok(http) = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
    else {
        return json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed initializing HTTP client",
        );
    };
    let synced = if conn.provider == "azure" {
        sync_azure_connector(&http, &conn).await
    } else {
        sync_gcp_connector(&http, &conn).await
    };
    match synced {
        Ok(items) => {
            let count = items.len();
            let updated = state
                .multicloud
                .update_synced(&tenant, &id, items.clone())
                .await;
            if let Some(ref rec) = updated {
                persist_cloud_connector(&state, rec).await;
            }
            Json(serde_json::json!({
                "connector": updated.as_ref().map(PublicCloudConnector::from),
                "resources_count": count,
                "resources": items,
            }))
            .into_response()
        }
        Err(err) => json_err(StatusCode::BAD_GATEWAY, err),
    }
}

#[derive(Debug, Deserialize)]
struct CloudResQuery {
    #[serde(default)]
    provider: Option<String>,
}

async fn list_cloud_resources(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CloudResQuery>,
) -> Response {
    let (tenant, _) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let resources = state
        .multicloud
        .list_resources(&tenant, q.provider.as_deref())
        .await;
    Json(serde_json::json!({ "resources": resources })).into_response()
}

fn build_strict_cloud_http() -> Result<reqwest::Client, Box<Response>> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|_| {
            Box::new(json_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed initializing HTTP client",
            ))
        })
}

async fn azure_sso_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<AzureSsoStartInput>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let http = match build_strict_cloud_http() {
        Ok(h) => h,
        Err(r) => return *r,
    };
    match state
        .multicloud
        .start_azure_device_sso(&http, &tenant, &claims.user_id, input)
        .await
    {
        Ok(started) => Json(started).into_response(),
        Err(err) => json_err(StatusCode::BAD_GATEWAY, err),
    }
}

#[derive(Debug, Deserialize)]
struct AzurePollBody {
    flow_id: String,
}

async fn azure_sso_poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AzurePollBody>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let http = match build_strict_cloud_http() {
        Ok(h) => h,
        Err(r) => return *r,
    };
    match state
        .multicloud
        .poll_azure_device_sso(&http, &tenant, &claims.user_id, body.flow_id.trim())
        .await
    {
        Ok(poll) => Json(poll).into_response(),
        Err(err) => json_err(StatusCode::BAD_REQUEST, err),
    }
}

#[derive(Debug, Deserialize)]
struct AzureConnectSsoBody {
    flow_id: String,
    subscription_id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    region: Option<String>,
}

async fn azure_sso_connect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AzureConnectSsoBody>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let rec = match state
        .multicloud
        .connect_azure_sso_subscription(
            &tenant,
            &claims.user_id,
            body.flow_id.trim(),
            &body.subscription_id,
            body.name.as_deref(),
            body.region.as_deref(),
        )
        .await
    {
        Ok(r) => r,
        Err(err) => return json_err(StatusCode::BAD_REQUEST, err),
    };
    persist_cloud_connector(&state, &rec).await;
    record_gov_audit(
        &state,
        &tenant,
        &claims.user_id,
        &claims.email,
        &claims.role,
        "",
        &rec.id,
        "azure_sso_connected",
        "cloud_connector",
        &rec.id,
        format!("subscription={}", rec.account_or_project_id),
        "success",
        None,
    )
    .await;

    let mut items = Vec::new();
    let mut final_rec = rec.clone();
    if let Ok(http) = build_strict_cloud_http() {
        if let Ok(synced) = sync_azure_connector(&http, &rec).await {
            items = synced.clone();
            if let Some(updated) = state
                .multicloud
                .update_synced(&tenant, &rec.id, synced)
                .await
            {
                persist_cloud_connector(&state, &updated).await;
                final_rec = updated;
            }
        }
    }
    Json(serde_json::json!({
        "connector": PublicCloudConnector::from(&final_rec),
        "resources_count": items.len(),
        "resources": items,
    }))
    .into_response()
}

fn derive_public_base(headers: &HeaderMap) -> String {
    if let Ok(pub_url) = std::env::var("PUBLIC_URL") {
        let clean = pub_url.trim().trim_end_matches('/');
        if !clean.is_empty() {
            return clean.to_owned();
        }
    }
    if let Some(orig) = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| s.starts_with("http://") || s.starts_with("https://"))
    {
        return orig.trim_end_matches('/').to_owned();
    }
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:5444");
    format!("https://{host}")
}

async fn gcp_sso_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut input): Json<GcpSsoStartInput>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if input.redirect_uri.trim().is_empty() {
        let base = derive_public_base(&headers);
        input.redirect_uri = format!("{base}/api/clouds/gcp/sso/callback");
    }
    match state
        .multicloud
        .start_gcp_pkce_sso(&tenant, &claims.user_id, input)
        .await
    {
        Ok(started) => Json(started).into_response(),
        Err(err) => json_err(StatusCode::UNPROCESSABLE_ENTITY, err),
    }
}

#[derive(Debug, Deserialize)]
struct GcpCallbackQuery {
    #[serde(default)]
    state: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    error: String,
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn gcp_sso_callback(
    State(state): State<AppState>,
    Query(q): Query<GcpCallbackQuery>,
) -> Response {
    if !q.error.trim().is_empty() {
        let msg = escape_html(&q.error);
        return (
            StatusCode::BAD_REQUEST,
            Html(format!(
                "<!doctype html><html><body><h3>Google Cloud sign-in canceled or denied</h3><p>{msg}</p><script>if(window.opener){{window.opener.postMessage({{type:'operquay:gcp-sso-complete',ok:false}},window.location.origin);}}</script></body></html>"
            )),
        )
            .into_response();
    }
    if q.state.trim().is_empty() || q.code.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Html("<!doctype html><html><body><h3>Missing state or authorization code.</h3></body></html>".to_owned()),
        )
            .into_response();
    }
    let http = match build_strict_cloud_http() {
        Ok(h) => h,
        Err(r) => return *r,
    };
    match state
        .multicloud
        .finish_gcp_pkce_callback(&http, q.state.trim(), q.code.trim())
        .await
    {
        Ok(status) => {
            let safe_flow = escape_html(&status.flow_id);
            Html(format!(
                "<!doctype html><html><body><h3>Google Cloud sign-in complete</h3><p>You can close this tab and return to Operquay (flow {safe_flow}).</p><script>if(window.opener){{window.opener.postMessage({{type:'operquay:gcp-sso-complete',ok:true,flow_id:'{safe_flow}'}},window.location.origin);window.close();}}</script></body></html>"
            ))
            .into_response()
        }
        Err(err) => {
            let safe_err = escape_html(&err);
            (
                StatusCode::BAD_REQUEST,
                Html(format!(
                    "<!doctype html><html><body><h3>Google Cloud sign-in failed</h3><p>{safe_err}</p></body></html>"
                )),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct GcpStatusQuery {
    flow_id: String,
}

async fn gcp_sso_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<GcpStatusQuery>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .multicloud
        .get_gcp_sso_status(&tenant, &claims.user_id, q.flow_id.trim())
        .await
    {
        Some(st) => Json(st).into_response(),
        None => json_err(StatusCode::NOT_FOUND, "GCP SSO flow not found"),
    }
}

#[derive(Debug, Deserialize)]
struct GcpConnectSsoBody {
    flow_id: String,
    project_id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    region: Option<String>,
}

async fn gcp_sso_connect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GcpConnectSsoBody>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let rec = match state
        .multicloud
        .connect_gcp_sso_project(
            &tenant,
            &claims.user_id,
            body.flow_id.trim(),
            &body.project_id,
            body.name.as_deref(),
            body.region.as_deref(),
        )
        .await
    {
        Ok(r) => r,
        Err(err) => return json_err(StatusCode::BAD_REQUEST, err),
    };
    persist_cloud_connector(&state, &rec).await;
    record_gov_audit(
        &state,
        &tenant,
        &claims.user_id,
        &claims.email,
        &claims.role,
        "",
        &rec.id,
        "gcp_sso_connected",
        "cloud_connector",
        &rec.id,
        format!("project={}", rec.account_or_project_id),
        "success",
        None,
    )
    .await;

    let mut items = Vec::new();
    let mut final_rec = rec.clone();
    if let Ok(http) = build_strict_cloud_http() {
        if let Ok(synced) = sync_gcp_connector(&http, &rec).await {
            items = synced.clone();
            if let Some(updated) = state
                .multicloud
                .update_synced(&tenant, &rec.id, synced)
                .await
            {
                persist_cloud_connector(&state, &updated).await;
                final_rec = updated;
            }
        }
    }
    Json(serde_json::json!({
        "connector": PublicCloudConnector::from(&final_rec),
        "resources_count": items.len(),
        "resources": items,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// M12.4: Unified Access Graph & Blast Radius Explorer
// ---------------------------------------------------------------------------

pub async fn build_tenant_access_graph(state: &AppState, tenant: &str) -> AccessGraphReport {
    let now = now_unix_secs();
    let users = state.auth.list_users(tenant).await;
    let groups = state.auth.list_groups_detailed(tenant).await;
    let roles = state.auth.list_roles(tenant).await;
    let aws_bindings = state.aws.accounts.list_all_tenant_bindings(tenant).await;
    let ec2 = state.aws.discovery.list_instances(tenant).await;
    let multicloud_res = state.multicloud.list_resources(tenant, None).await;
    let connectors = state.multicloud.list_connectors(tenant).await;
    let k8s_clusters = state.platform.k8s.list_clusters(tenant).await;
    let db_conns = state.platform.db.list_connections().await;
    let mcp_agents = state.mcp.all_agents_in_tenant(tenant).await;
    let hybrid_agents = state.agent_hub.list_agents(tenant).await;

    let mut nodes: Vec<AccessNode> = Vec::new();
    let mut edges: Vec<AccessEdge> = Vec::new();
    let mut role_perms_map: HashMap<String, Vec<String>> = HashMap::new();

    for u in &users {
        let is_admin = u.role.eq_ignore_ascii_case("admin");
        nodes.push(AccessNode {
            id: format!("user:{}", u.id),
            label: u.email.clone(),
            kind: AccessNodeKind::User,
            account_or_tenant: tenant.to_owned(),
            environment: "identity".to_owned(),
            is_admin_capability: is_admin,
            has_jit_gate: false,
            last_used_at: Some(now),
            permissions: if is_admin {
                vec!["*".to_owned()]
            } else {
                Vec::new()
            },
        });
    }

    for r in &roles {
        role_perms_map.insert(r.id.clone(), r.permissions.clone());
        let is_priv = r.permissions.iter().any(|p| {
            matches!(
                p.as_str(),
                "*" | "users:manage"
                    | "roles:manage"
                    | "sso:manage"
                    | "aws_accounts:manage"
                    | "mcp:manage"
                    | "agents:manage"
            )
        });
        nodes.push(AccessNode {
            id: format!("role:{}", r.id),
            label: r.name.clone(),
            kind: AccessNodeKind::Role,
            account_or_tenant: tenant.to_owned(),
            environment: "rbac".to_owned(),
            is_admin_capability: is_priv,
            has_jit_gate: false,
            last_used_at: Some(now),
            permissions: r.permissions.clone(),
        });
    }

    for g in &groups {
        let gid = g["id"].as_str().unwrap_or("");
        if gid.is_empty() {
            continue;
        }
        let gname = g["name"].as_str().unwrap_or(gid).to_owned();
        let gnode_id = format!("group:{gid}");
        nodes.push(AccessNode {
            id: gnode_id.clone(),
            label: gname,
            kind: AccessNodeKind::Group,
            account_or_tenant: tenant.to_owned(),
            environment: "identity".to_owned(),
            is_admin_capability: false,
            has_jit_gate: false,
            last_used_at: Some(now),
            permissions: Vec::new(),
        });
        if let Some(members) = g["members"].as_array() {
            for m in members {
                if let Some(uid) = m["user_id"].as_str() {
                    edges.push(AccessEdge {
                        from: format!("user:{uid}"),
                        to: gnode_id.clone(),
                        kind: AccessEdgeKind::MemberOf,
                        label: "member".to_owned(),
                    });
                }
            }
        }
        if let Some(bindings) = g["bindings"].as_array() {
            for b in bindings {
                if b["effect"].as_str() == Some("deny") {
                    continue;
                }
                if let Some(rid) = b["role_id"].as_str() {
                    edges.push(AccessEdge {
                        from: gnode_id.clone(),
                        to: format!("role:{rid}"),
                        kind: AccessEdgeKind::AssignedRole,
                        label: "assigned".to_owned(),
                    });
                }
            }
        }
    }

    // Target infrastructure resources
    let mut instance_ids: Vec<String> = Vec::new();
    for inst in &ec2 {
        let env = inst
            .tags
            .get("env")
            .or_else(|| inst.tags.get("Environment"))
            .cloned()
            .unwrap_or_else(|| inst.region.clone());
        let nid = format!("inst:{}", inst.instance_id);
        instance_ids.push(nid.clone());
        nodes.push(AccessNode {
            id: nid,
            label: if inst.name.is_empty() {
                inst.instance_id.clone()
            } else {
                inst.name.clone()
            },
            kind: AccessNodeKind::Instance,
            account_or_tenant: inst.account_id.clone(),
            environment: env,
            is_admin_capability: false,
            has_jit_gate: false,
            last_used_at: Some(now),
            permissions: Vec::new(),
        });
    }

    let mut k8s_ids: Vec<String> = Vec::new();
    for cl in &k8s_clusters {
        let nid = format!("k8s:{}", cl.name);
        k8s_ids.push(nid.clone());
        nodes.push(AccessNode {
            id: nid,
            label: cl.name.clone(),
            kind: AccessNodeKind::K8sCluster,
            account_or_tenant: tenant.to_owned(),
            environment: if cl.name.to_ascii_lowercase().contains("prod") {
                "prod".to_owned()
            } else {
                cl.region.clone()
            },
            is_admin_capability: false,
            has_jit_gate: false,
            last_used_at: Some(now),
            permissions: Vec::new(),
        });
    }

    let mut db_ids: Vec<String> = Vec::new();
    for db_name in &db_conns {
        let nid = format!("db:{db_name}");
        db_ids.push(nid.clone());
        nodes.push(AccessNode {
            id: nid,
            label: db_name.clone(),
            kind: AccessNodeKind::Database,
            account_or_tenant: tenant.to_owned(),
            environment: if db_name.to_ascii_lowercase().contains("prod") {
                "prod".to_owned()
            } else {
                "data".to_owned()
            },
            is_admin_capability: false,
            has_jit_gate: false,
            last_used_at: Some(now),
            permissions: Vec::new(),
        });
    }

    let mut cloud_role_ids: HashSet<String> = HashSet::new();
    let mut multicloud_res_ids: Vec<(String, CloudResourceItem)> = Vec::new();
    for res in &multicloud_res {
        match res.kind.as_str() {
            "k8s" => {
                let nid = format!("k8s:{}", res.id);
                k8s_ids.push(nid.clone());
                nodes.push(AccessNode {
                    id: nid.clone(),
                    label: res.name.clone(),
                    kind: AccessNodeKind::K8sCluster,
                    account_or_tenant: res.account_or_project.clone(),
                    environment: if res.name.to_ascii_lowercase().contains("prod") {
                        "prod".to_owned()
                    } else {
                        res.region.clone()
                    },
                    is_admin_capability: false,
                    has_jit_gate: false,
                    last_used_at: Some(now),
                    permissions: Vec::new(),
                });
                multicloud_res_ids.push((nid, res.clone()));
            }
            "iam" => {
                let is_priv = res.is_privileged
                    || res.name.to_ascii_lowercase().contains("admin")
                    || res.name.to_ascii_lowercase().contains("owner");
                cloud_role_ids.insert(res.id.clone());
                nodes.push(AccessNode {
                    id: res.id.clone(),
                    label: res.name.clone(),
                    kind: AccessNodeKind::CloudRole,
                    account_or_tenant: res.account_or_project.clone(),
                    environment: res.provider.clone(),
                    is_admin_capability: is_priv,
                    has_jit_gate: false,
                    last_used_at: Some(now),
                    permissions: if is_priv {
                        vec!["*".to_owned()]
                    } else {
                        Vec::new()
                    },
                });
            }
            _ => {
                let nid = format!("inst:{}", res.id);
                instance_ids.push(nid.clone());
                nodes.push(AccessNode {
                    id: nid.clone(),
                    label: res.name.clone(),
                    kind: AccessNodeKind::Instance,
                    account_or_tenant: res.account_or_project.clone(),
                    environment: if res.name.to_ascii_lowercase().contains("prod") {
                        "prod".to_owned()
                    } else {
                        res.region.clone()
                    },
                    is_admin_capability: false,
                    has_jit_gate: false,
                    last_used_at: Some(now),
                    permissions: Vec::new(),
                });
                multicloud_res_ids.push((nid, res.clone()));
            }
        }
    }

    // Wire RBAC roles to resources they can reach
    for r in &roles {
        let role_nid = format!("role:{}", r.id);
        let can_inst = r
            .permissions
            .iter()
            .any(|p| p == "*" || p == "session:ssh" || p == "session:rdp" || p == "instances:read");
        let can_k8s = r
            .permissions
            .iter()
            .any(|p| p == "*" || p.starts_with("k8s:"));
        let can_db = r
            .permissions
            .iter()
            .any(|p| p == "*" || p == "db_viewer:use");
        if can_inst {
            for nid in &instance_ids {
                edges.push(AccessEdge {
                    from: role_nid.clone(),
                    to: nid.clone(),
                    kind: AccessEdgeKind::CanAccess,
                    label: "ssh/rdp".to_owned(),
                });
            }
        }
        if can_k8s {
            for nid in &k8s_ids {
                edges.push(AccessEdge {
                    from: role_nid.clone(),
                    to: nid.clone(),
                    kind: AccessEdgeKind::CanAccess,
                    label: "k8s".to_owned(),
                });
            }
        }
        if can_db {
            for nid in &db_ids {
                edges.push(AccessEdge {
                    from: role_nid.clone(),
                    to: nid.clone(),
                    kind: AccessEdgeKind::CanAccess,
                    label: "db".to_owned(),
                });
            }
        }
    }

    // AWS user role bindings & cross-account role assumptions
    for b in &aws_bindings {
        let is_priv = b.role_arn.to_ascii_lowercase().contains("admin")
            || b.label.to_ascii_lowercase().contains("admin");
        if cloud_role_ids.insert(b.role_arn.clone()) {
            nodes.push(AccessNode {
                id: b.role_arn.clone(),
                label: if b.label.is_empty() {
                    b.role_arn.clone()
                } else {
                    b.label.clone()
                },
                kind: AccessNodeKind::CloudRole,
                account_or_tenant: b.account_id.clone(),
                environment: "aws".to_owned(),
                is_admin_capability: is_priv,
                has_jit_gate: false,
                last_used_at: Some(b.created_at),
                permissions: if is_priv {
                    vec!["*".to_owned()]
                } else {
                    Vec::new()
                },
            });
        }
        edges.push(AccessEdge {
            from: format!("user:{}", b.user_id),
            to: b.role_arn.clone(),
            kind: AccessEdgeKind::CanAssume,
            label: "assume-role".to_owned(),
        });
        if !b.principal_arn.trim().is_empty() {
            if cloud_role_ids.insert(b.principal_arn.clone()) {
                nodes.push(AccessNode {
                    id: b.principal_arn.clone(),
                    label: b.principal_arn.clone(),
                    kind: AccessNodeKind::CloudRole,
                    account_or_tenant: b.account_id.clone(),
                    environment: "aws".to_owned(),
                    is_admin_capability: false,
                    has_jit_gate: false,
                    last_used_at: Some(b.created_at),
                    permissions: Vec::new(),
                });
            }
            edges.push(AccessEdge {
                from: b.principal_arn.clone(),
                to: b.role_arn.clone(),
                kind: AccessEdgeKind::CanAssume,
                label: "trust".to_owned(),
            });
        }
        for inst in &ec2 {
            if inst.account_id == b.account_id || b.account_id.is_empty() {
                edges.push(AccessEdge {
                    from: b.role_arn.clone(),
                    to: format!("inst:{}", inst.instance_id),
                    kind: AccessEdgeKind::CanAccess,
                    label: "ssm".to_owned(),
                });
            }
        }
    }

    // Cloud connector optional trust_edges & standing roles metadata
    for c in &connectors {
        if let Some(trust_edges) = c.config["trust_edges"].as_array() {
            for te in trust_edges {
                let Some(from_id) = te["from"].as_str() else {
                    continue;
                };
                let Some(to_id) = te["to"].as_str() else {
                    continue;
                };
                for role_id in [from_id, to_id] {
                    if cloud_role_ids.insert(role_id.to_owned()) {
                        let priv_flag = role_id.to_ascii_lowercase().contains("admin")
                            || role_id.to_ascii_lowercase().contains("owner");
                        nodes.push(AccessNode {
                            id: role_id.to_owned(),
                            label: role_id.to_owned(),
                            kind: AccessNodeKind::CloudRole,
                            account_or_tenant: c.account_or_project_id.clone(),
                            environment: c.provider.clone(),
                            is_admin_capability: priv_flag,
                            has_jit_gate: false,
                            last_used_at: Some(now),
                            permissions: if priv_flag {
                                vec!["*".to_owned()]
                            } else {
                                Vec::new()
                            },
                        });
                    }
                }
                edges.push(AccessEdge {
                    from: from_id.to_owned(),
                    to: to_id.to_owned(),
                    kind: AccessEdgeKind::CanAssume,
                    label: te["label"].as_str().unwrap_or("trust").to_owned(),
                });
            }
        }
        if let Some(extra_roles) = c.config["standing_roles"].as_array() {
            for er in extra_roles {
                let Some(rid) = er["id"].as_str() else {
                    continue;
                };
                let is_priv = er["is_admin_capability"].as_bool().unwrap_or(true);
                let has_jit = er["has_jit_gate"].as_bool().unwrap_or(false);
                let last_used = er["last_used_at"].as_i64();
                if cloud_role_ids.insert(rid.to_owned()) {
                    nodes.push(AccessNode {
                        id: rid.to_owned(),
                        label: er["label"].as_str().unwrap_or(rid).to_owned(),
                        kind: AccessNodeKind::CloudRole,
                        account_or_tenant: c.account_or_project_id.clone(),
                        environment: c.provider.clone(),
                        is_admin_capability: is_priv,
                        has_jit_gate: has_jit,
                        last_used_at: last_used,
                        permissions: if is_priv {
                            vec!["*".to_owned()]
                        } else {
                            Vec::new()
                        },
                    });
                }
            }
        }
        for (nid, item) in &multicloud_res_ids {
            if item.account_or_project == c.account_or_project_id {
                for r in &multicloud_res {
                    if r.kind == "iam" && r.account_or_project == item.account_or_project {
                        edges.push(AccessEdge {
                            from: r.id.clone(),
                            to: nid.clone(),
                            kind: AccessEdgeKind::CanAccess,
                            label: r.provider.clone(),
                        });
                    }
                }
            }
        }
    }

    // AI MCP Agents & Hybrid Agents
    for ag in &mcp_agents {
        let ag_nid = format!("mcp:{}", ag.id);
        nodes.push(AccessNode {
            id: ag_nid.clone(),
            label: format!("AI: {}", ag.name),
            kind: AccessNodeKind::AiAgent,
            account_or_tenant: tenant.to_owned(),
            environment: "mcp".to_owned(),
            is_admin_capability: ag.allowed_tools.iter().any(|t| t == "*"),
            has_jit_gate: !ag.require_jit_tools.is_empty(),
            last_used_at: Some(ag.created_at),
            permissions: ag.allowed_tools.clone(),
        });
        edges.push(AccessEdge {
            from: format!("user:{}", ag.sponsor_user_id),
            to: ag_nid.clone(),
            kind: AccessEdgeKind::Sponsors,
            label: "sponsors".to_owned(),
        });
        if ag
            .allowed_tools
            .iter()
            .any(|t| t == "*" || t == "operquay.instances.list")
        {
            for nid in &instance_ids {
                edges.push(AccessEdge {
                    from: ag_nid.clone(),
                    to: nid.clone(),
                    kind: AccessEdgeKind::CanAccess,
                    label: "mcp-read".to_owned(),
                });
            }
        }
        if ag
            .allowed_tools
            .iter()
            .any(|t| t == "*" || t == "operquay.db.query" || t == "operquay.db.mutate")
        {
            for nid in &db_ids {
                edges.push(AccessEdge {
                    from: ag_nid.clone(),
                    to: nid.clone(),
                    kind: AccessEdgeKind::CanAccess,
                    label: "mcp-sql".to_owned(),
                });
            }
        }
    }

    for ha in &hybrid_agents {
        let nid = format!("hybrid:{}", ha.id);
        nodes.push(AccessNode {
            id: nid,
            label: format!("{} ({})", ha.name, ha.hostname),
            kind: AccessNodeKind::HybridHost,
            account_or_tenant: tenant.to_owned(),
            environment: "on-prem".to_owned(),
            is_admin_capability: false,
            has_jit_gate: false,
            last_used_at: ha.last_heartbeat_at,
            permissions: Vec::new(),
        });
    }

    let _ = role_perms_map;
    analyze_access_graph(&AccessGraphInput {
        now_secs: now,
        unused_threshold_days: 30,
        nodes,
        edges,
    })
}

async fn get_access_graph(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(
        &state,
        &headers,
        &[
            perm::AUDIT_READ,
            perm::ROLES_MANAGE,
            perm::AWS_ACCOUNTS_MANAGE,
        ],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let report = build_tenant_access_graph(&state, &tenant).await;
    Json(report).into_response()
}

async fn get_principal_blast_radius(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(principal_id): Path<String>,
) -> Response {
    let (tenant, _) = match require_any_perm(
        &state,
        &headers,
        &[
            perm::AUDIT_READ,
            perm::ROLES_MANAGE,
            perm::AWS_ACCOUNTS_MANAGE,
        ],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let report = build_tenant_access_graph(&state, &tenant).await;
    let user_prefixed = format!("user:{principal_id}");
    let mcp_prefixed = format!("mcp:{principal_id}");
    let matched = report.blast_radius.iter().find(|b| {
        b.principal_id == principal_id
            || b.principal_id == user_prefixed
            || b.principal_id == mcp_prefixed
            || b.principal_label == principal_id
    });
    match matched {
        Some(br) => Json(serde_json::json!({
            "principal": br,
            "findings": report.findings.iter().filter(|f| f.node_ids.contains(&br.principal_id)).collect::<Vec<_>>(),
        }))
        .into_response(),
        None => json_err(StatusCode::NOT_FOUND, "principal not found in access graph"),
    }
}

// ---------------------------------------------------------------------------
// M12.5: Hardware Device Trust & MDM Posture Handlers
// ---------------------------------------------------------------------------

async fn get_device_trust_policy(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(
        &state,
        &headers,
        &[perm::DEVICE_TRUST_MANAGE, perm::AUDIT_READ],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let policy = state.device_trust.get_policy(&tenant).await;
    Json(policy).into_response()
}

async fn put_device_trust_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(policy): Json<DeviceTrustPolicy>,
) -> Response {
    let (tenant, claims) =
        match require_any_perm(&state, &headers, &[perm::DEVICE_TRUST_MANAGE]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    state.device_trust.set_policy(&tenant, policy.clone()).await;
    persist_device_trust_policy(&state, &tenant, &policy).await;
    record_gov_audit(
        &state,
        &tenant,
        &claims.user_id,
        &claims.email,
        &claims.role,
        "",
        "device-trust-policy",
        "device_trust_policy_updated",
        "device_trust_policy",
        &tenant,
        format!(
            "enabled={} require_fde={} require_edr={} max_patch_age={}d",
            policy.enabled,
            policy.require_disk_encryption,
            policy.require_edr_running,
            policy.max_os_patch_age_days
        ),
        "success",
        None,
    )
    .await;
    Json(policy).into_response()
}

async fn post_device_attestation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<DevicePostureInput>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .device_trust
        .record_attestation(&tenant, &claims.user_id, input)
        .await
    {
        Ok(att) => {
            persist_device_posture(&state, &att).await;
            record_gov_audit(
                &state,
                &tenant,
                &claims.user_id,
                &claims.email,
                &claims.role,
                "",
                &att.device_id,
                "device_posture_attested",
                "device",
                &att.device_id,
                format!("provider={} compliant={}", att.provider, att.compliant),
                if att.compliant { "success" } else { "denied" },
                None,
            )
            .await;
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "attestation": att })),
            )
                .into_response()
        }
        Err(err) => json_err(StatusCode::UNPROCESSABLE_ENTITY, err),
    }
}

async fn list_device_postures(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(
        &state,
        &headers,
        &[perm::DEVICE_TRUST_MANAGE, perm::AUDIT_READ],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let devices = state.device_trust.list_attestations(&tenant).await;
    Json(serde_json::json!({ "devices": devices })).into_response()
}
