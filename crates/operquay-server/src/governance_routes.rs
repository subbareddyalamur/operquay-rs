#![forbid(unsafe_code)]

//! Governance, Just-in-Time Access Requests (M11.1), Dual-Control Live Session Moderation &
//! Risk Bookmarks (M11.2), Inline DLP & Command Firewall (M11.3), and Continuous SOC 2 / ISO
//! Compliance & Signed Evidence Portal (M11.4).

use axum::body::Bytes;
use axum::extract::ws::{Message as WsMsg, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use futures_util::{SinkExt, StreamExt};
use operquay_auth::crypto::extract_tenant_id_checked;
use operquay_auth::pg::{
    PgAccessReviewCampaignRow, PgDlpPolicyRow, PgGovernanceWebhookRow, PgJitAccessRequestRow,
    PgSessionRiskBookmarkRow,
};
use operquay_auth::policy::{perm, ScopeType};
use operquay_auth::{compliance_mode_enabled, SessionClaims};
use operquay_db::driver::DbQueryResult;
use serde::Deserialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::auth_routes::{require_actor, require_any_perm};
use crate::compliance::{
    sign_evidence_bundle, verify_signed_evidence_bundle, AccessReviewCampaign,
    AccessReviewDecision, AccessReviewItem, AccessReviewStatus, ComplianceControlStatus,
    CompliancePostureReport, SignedEvidenceBundle,
};
use crate::dlp::{
    evaluate_command, validate_policy, DlpFirewallPolicy, ShellCommandFirewallBuffer,
    ShellInputDecision,
};
use crate::jit::{
    now_unix_secs, verify_operquay_hmac, verify_slack_signature, CreateJitRequestInput,
    GovernanceWebhook, JitAccessRequest, JitStatus, SessionRiskBookmark,
};
use crate::moderation::{LiveSessionEvent, LiveSessionHandle, ModerationRole};
use crate::stores::AuditRecordInput;
use crate::{AppState, ResolvedRequestContext};

pub fn governance_router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/access-requests",
            get(list_access_requests).post(create_access_request),
        )
        .route(
            "/api/access-requests/{id}/approve",
            post(approve_access_request),
        )
        .route("/api/access-requests/{id}/deny", post(deny_access_request))
        .route(
            "/api/access-requests/{id}/revoke",
            post(revoke_access_request),
        )
        .route(
            "/api/access-requests/webhooks/{provider}/callback",
            post(webhook_action_callback),
        )
        .route(
            "/api/governance/webhooks",
            get(list_governance_webhooks).post(create_governance_webhook),
        )
        .route(
            "/api/governance/webhooks/{id}",
            delete(delete_governance_webhook),
        )
        .route(
            "/api/governance/dlp-policy",
            get(get_dlp_policy).put(put_dlp_policy),
        )
        .route("/api/governance/dlp-policy/test", post(test_dlp_policy))
        .route("/api/sessions/live", get(list_live_sessions))
        .route("/api/sessions/{id}/freeze", post(freeze_live_session))
        .route("/api/sessions/{id}/kill", post(kill_live_session))
        .route("/ws/sessions/{id}/shadow", get(ws_session_shadow))
        .route(
            "/api/recordings/{id}/bookmarks",
            get(list_recording_bookmarks),
        )
        .route("/api/recordings/{id}/analyze", post(analyze_recording_risk))
        .route("/api/compliance/posture", get(get_compliance_posture))
        .route(
            "/api/compliance/access-reviews",
            get(list_access_reviews).post(create_access_review),
        )
        .route(
            "/api/compliance/access-reviews/{id}/items/{item_id}",
            post(decide_access_review_item),
        )
        .route(
            "/api/compliance/evidence-bundle",
            post(export_signed_evidence_bundle),
        )
        .route(
            "/api/compliance/evidence-bundle/verify",
            post(verify_evidence_bundle_route),
        )
}

fn json_err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

fn req_ctx(
    state: &AppState,
    headers: &HeaderMap,
    ext: Option<&Extension<ResolvedRequestContext>>,
) -> ResolvedRequestContext {
    ext.map_or_else(
        || ResolvedRequestContext::from_headers(headers, &state.trusted_proxies),
        |e| e.0.clone(),
    )
}

async fn actor_has_any_perm(state: &AppState, claims: &SessionClaims, perms: &[&str]) -> bool {
    if !state.auth.require_auth().await && claims.method == "lab-open" {
        return true;
    }
    for p in perms {
        if state
            .auth
            .check_permission(&claims.user_id, p, ScopeType::Global, "", None)
            .await
        {
            return true;
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
pub async fn record_gov_audit(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    user_email: &str,
    role: &str,
    ip: &str,
    session_id: &str,
    action: &str,
    protocol: &str,
    target_host: &str,
    detail: impl Into<String>,
    outcome: &str,
    recording_id: Option<String>,
) {
    state
        .audit
        .record_full(AuditRecordInput {
            tenant_id: tenant_id.to_owned(),
            trace_id: crate::TelemetryHub::current_trace_id_hex(),
            session_id: session_id.to_owned(),
            action: action.to_owned(),
            protocol: protocol.to_owned(),
            target_host: target_host.to_owned(),
            detail: detail.into(),
            user_id: user_id.to_owned(),
            user_email: user_email.to_owned(),
            role: role.to_owned(),
            ip: ip.to_owned(),
            outcome: outcome.to_owned(),
            recording_id,
            ..AuditRecordInput::default()
        })
        .await;
}

pub(crate) struct ShellFirewallExecution {
    pub send_upstream: Vec<u8>,
    pub user_banner: Option<String>,
}

/// Shared inline command firewall & moderation-freeze enforcer across K8s, SSM, and multiplexed shells (`M11.2`/`M11.3`).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_shell_input_firewall(
    state: &AppState,
    tenant_id: &str,
    session_id: &str,
    protocol: &str,
    target_host: &str,
    user_id: &str,
    user_email: &str,
    mod_handle: &LiveSessionHandle,
    fw_buf: &mut ShellCommandFirewallBuffer,
    raw_bytes: &[u8],
) -> ShellFirewallExecution {
    if mod_handle.is_frozen() {
        return ShellFirewallExecution {
            send_upstream: Vec::new(),
            user_banner: Some(format!(
                "\r\n\x1b[1;33m[operquay] Session frozen by moderator: {}\x1b[0m\r\n",
                mod_handle.freeze_reason()
            )),
        };
    }
    let policy = state.governance.get_dlp_policy(tenant_id).await;
    match fw_buf.feed_input(raw_bytes, &policy, protocol) {
        ShellInputDecision::Forward(bytes) => ShellFirewallExecution {
            send_upstream: bytes,
            user_banner: None,
        },
        ShellInputDecision::WarnForward { bytes, verdict } => {
            mod_handle.publish_notice(
                "warn",
                &format!("{} ({})", verdict.rule_name, verdict.sanitized_command),
            );
            record_gov_audit(
                state,
                tenant_id,
                user_id,
                user_email,
                "operator",
                "",
                session_id,
                "command_firewall_warn",
                protocol,
                target_host,
                format!("rule={} cmd={}", verdict.rule_id, verdict.sanitized_command),
                "warn",
                None,
            )
            .await;
            ShellFirewallExecution {
                send_upstream: bytes,
                user_banner: Some(format!(
                    "\r\n\x1b[1;33m[command-firewall WARN: {}] {}\x1b[0m\r\n",
                    verdict.rule_name, verdict.message
                )),
            }
        }
        ShellInputDecision::Block {
            verdict,
            cancel_bytes,
        } => {
            mod_handle.publish_notice(
                "critical",
                &format!(
                    "BLOCKED {}: {}",
                    verdict.rule_name, verdict.sanitized_command
                ),
            );
            record_gov_audit(
                state,
                tenant_id,
                user_id,
                user_email,
                "operator",
                "",
                session_id,
                "command_firewall_blocked",
                protocol,
                target_host,
                format!("rule={} cmd={}", verdict.rule_id, verdict.sanitized_command),
                "denied",
                None,
            )
            .await;
            state
                .governance
                .dispatch_webhook(
                    tenant_id,
                    "command_firewall.blocked",
                    serde_json::json!({
                        "session_id": session_id,
                        "protocol": protocol,
                        "target_host": target_host,
                        "user_email": user_email,
                        "rule_id": verdict.rule_id,
                        "rule_name": verdict.rule_name,
                        "command": verdict.sanitized_command,
                        "summary": format!("Blocked {} in {protocol} session {session_id}", verdict.rule_name),
                    }),
                )
                .await;
            ShellFirewallExecution {
                send_upstream: cancel_bytes,
                user_banner: Some(format!(
                    "\r\n\x1b[1;31m[command-firewall BLOCKED: {}] {}\x1b[0m\r\n",
                    verdict.rule_name, verdict.message
                )),
            }
        }
        ShellInputDecision::PauseApproval {
            verdict,
            cancel_bytes,
        } => {
            let freeze_msg = format!("{}: {}", verdict.rule_name, verdict.message);
            let _ = state.moderation.set_frozen(
                tenant_id,
                session_id,
                true,
                "command-firewall",
                &freeze_msg,
            );
            mod_handle.publish_notice(
                "critical",
                &format!(
                    "PAUSED FOR APPROVAL {}: {}",
                    verdict.rule_name, verdict.sanitized_command
                ),
            );
            record_gov_audit(
                state,
                tenant_id,
                user_id,
                user_email,
                "operator",
                "",
                session_id,
                "command_firewall_paused",
                protocol,
                target_host,
                format!("rule={} cmd={}", verdict.rule_id, verdict.sanitized_command),
                "paused",
                None,
            )
            .await;
            state
                .governance
                .dispatch_webhook(
                    tenant_id,
                    "command_firewall.paused",
                    serde_json::json!({
                        "session_id": session_id,
                        "protocol": protocol,
                        "target_host": target_host,
                        "user_email": user_email,
                        "rule_id": verdict.rule_id,
                        "rule_name": verdict.rule_name,
                        "command": verdict.sanitized_command,
                        "summary": format!("Paused session {session_id} for dual-control approval: {}", verdict.rule_name),
                    }),
                )
                .await;
            ShellFirewallExecution {
                send_upstream: cancel_bytes,
                user_banner: Some(format!(
                    "\r\n\x1b[1;33m[command-firewall PAUSED FOR APPROVAL: {}] Session frozen pending moderator review.\x1b[0m\r\n",
                    verdict.rule_name
                )),
            }
        }
    }
}

pub async fn persist_jit_request(state: &AppState, req: &JitAccessRequest) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let payload_json = serde_json::to_string(req).unwrap_or_else(|_| "{}".to_owned());
    let row = PgJitAccessRequestRow {
        id: req.id.clone(),
        tenant_id: req.tenant_id.clone(),
        requester_user_id: req.requester_user_id.clone(),
        requester_email: req.requester_email.clone(),
        target_type: req.target_type.as_str().to_owned(),
        target_id: req.target_id.clone(),
        requested_role: req.requested_role.clone(),
        duration_secs: i64::try_from(req.duration_secs).unwrap_or(3600),
        reason: req.reason.clone(),
        ticket_id: req.ticket_id.clone(),
        ticket_provider: req.ticket_provider.clone(),
        status: req.status.as_str().to_owned(),
        approver_user_id: req.approver_user_id.clone(),
        approver_email: req.approver_email.clone(),
        decision_note: req.decision_note.clone(),
        created_at: req.created_at,
        decided_at: req.decided_at,
        expires_at: req.expires_at,
        revoked_at: req.revoked_at,
        payload_json,
    };
    if let Err(err) = pg.upsert_jit_access_request(&row).await {
        tracing::warn!(request_id = %req.id, error = %err, "failed persisting JIT access request");
    }
}

async fn persist_webhook(state: &AppState, hook: &GovernanceWebhook) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let row = PgGovernanceWebhookRow {
        id: hook.id.clone(),
        tenant_id: hook.tenant_id.clone(),
        provider: hook.provider.clone(),
        name: hook.name.clone(),
        url: hook.url.clone(),
        secret: hook.secret.clone(),
        events_json: serde_json::to_string(&hook.events).unwrap_or_else(|_| "[]".to_owned()),
        enabled: hook.enabled,
        created_at: hook.created_at,
    };
    if let Err(err) = pg.upsert_governance_webhook(&row).await {
        tracing::warn!(webhook_id = %hook.id, error = %err, "failed persisting governance webhook");
    }
}

async fn persist_dlp_policy(state: &AppState, tenant_id: &str, policy: &DlpFirewallPolicy) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let row = PgDlpPolicyRow {
        tenant_id: tenant_id.to_owned(),
        policy_json: serde_json::to_string(policy).unwrap_or_else(|_| "{}".to_owned()),
    };
    if let Err(err) = pg.upsert_dlp_policy(&row).await {
        tracing::warn!(tenant_id, error = %err, "failed persisting DLP firewall policy");
    }
}

pub(crate) async fn persist_risk_bookmarks(state: &AppState, bookmarks: &[SessionRiskBookmark]) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    for bm in bookmarks {
        let row = PgSessionRiskBookmarkRow {
            id: bm.id.clone(),
            tenant_id: bm.tenant_id.clone(),
            recording_id: bm.recording_id.clone(),
            session_id: bm.session_id.clone(),
            offset_secs: bm.offset_secs,
            severity: bm.severity.clone(),
            category: bm.category.clone(),
            title: bm.title.clone(),
            detail: bm.detail.clone(),
            source: bm.source.clone(),
            created_at: bm.created_at,
        };
        if let Err(err) = pg.insert_session_risk_bookmark(&row).await {
            tracing::warn!(bookmark_id = %bm.id, error = %err, "failed persisting session risk bookmark");
        }
    }
}

async fn persist_campaign(state: &AppState, campaign: &AccessReviewCampaign) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let status_str = match campaign.status {
        AccessReviewStatus::Active => "active",
        AccessReviewStatus::Completed => "completed",
    };
    let row = PgAccessReviewCampaignRow {
        id: campaign.id.clone(),
        tenant_id: campaign.tenant_id.clone(),
        title: campaign.title.clone(),
        quarter: campaign.quarter.clone(),
        status: status_str.to_owned(),
        created_by: campaign.created_by.clone(),
        created_at: campaign.created_at,
        completed_at: campaign.completed_at,
        payload_json: serde_json::to_string(campaign).unwrap_or_else(|_| "{}".to_owned()),
    };
    if let Err(err) = pg.upsert_access_review_campaign(&row).await {
        tracing::warn!(campaign_id = %campaign.id, error = %err, "failed persisting access review campaign");
    }
}

// ---------------------------------------------------------------------------
// M11.1: JIT Access Requests & Four-Eyes Approvals
// ---------------------------------------------------------------------------

async fn list_access_requests(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let can_approve =
        actor_has_any_perm(&state, &claims, &[perm::ACCESS_REQUESTS_APPROVE, perm::ALL]).await;
    let can_audit = actor_has_any_perm(&state, &claims, &[perm::AUDIT_READ, perm::ALL]).await;
    let mut items = state.governance.list_requests(&tenant).await;
    if !can_approve && !can_audit {
        items.retain(|r| r.requester_user_id == claims.user_id);
    }
    Json(serde_json::json!({
        "items": items,
        "can_approve": can_approve,
    }))
    .into_response()
}

async fn create_access_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Option<Extension<ResolvedRequestContext>>,
    Json(input): Json<CreateJitRequestInput>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let req = match state
        .governance
        .create_request(&tenant, &claims.user_id, &claims.email, input)
        .await
    {
        Ok(r) => r,
        Err(err) => return json_err(StatusCode::BAD_REQUEST, err),
    };
    persist_jit_request(&state, &req).await;
    record_gov_audit(
        &state,
        &tenant,
        &claims.user_id,
        &claims.email,
        &claims.role,
        &ctx.client_ip,
        &req.id,
        "jit_access_requested",
        req.target_type.as_str(),
        &req.target_id,
        format!(
            "requested {} for {}s (ticket={}) reason={}",
            req.requested_role, req.duration_secs, req.ticket_id, req.reason
        ),
        "success",
        None,
    )
    .await;
    if let Ok(payload) = serde_json::to_value(&req) {
        state
            .governance
            .dispatch_webhook(&tenant, "access_request.created", payload)
            .await;
    }
    (StatusCode::CREATED, Json(req)).into_response()
}

#[derive(Debug, Default, Deserialize)]
struct DecisionBody {
    #[serde(default)]
    note: String,
    #[serde(default)]
    reason: String,
}

async fn approve_access_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Option<Extension<ResolvedRequestContext>>,
    Path(id): Path<String>,
    body: Option<Json<DecisionBody>>,
) -> Response {
    let (tenant, claims) = match require_any_perm(
        &state,
        &headers,
        &[perm::ACCESS_REQUESTS_APPROVE, perm::ALL],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let note = body.map_or_else(String::new, |b| b.0.note);
    match state
        .governance
        .approve_request(&tenant, &id, &claims.user_id, &claims.email, &note)
        .await
    {
        Ok(req) => {
            persist_jit_request(&state, &req).await;
            record_gov_audit(
                &state,
                &tenant,
                &claims.user_id,
                &claims.email,
                &claims.role,
                &ctx.client_ip,
                &req.id,
                "jit_access_approved",
                req.target_type.as_str(),
                &req.target_id,
                format!(
                    "approved request for {} ({})",
                    req.requester_email, req.reason
                ),
                "success",
                None,
            )
            .await;
            if let Ok(payload) = serde_json::to_value(&req) {
                state
                    .governance
                    .dispatch_webhook(&tenant, "access_request.approved", payload)
                    .await;
            }
            Json(req).into_response()
        }
        Err(err) => {
            let status = if err.contains("four-eyes") {
                record_gov_audit(
                    &state,
                    &tenant,
                    &claims.user_id,
                    &claims.email,
                    &claims.role,
                    &ctx.client_ip,
                    &id,
                    "jit_four_eyes_violation",
                    "governance",
                    &id,
                    err.clone(),
                    "denied",
                    None,
                )
                .await;
                StatusCode::FORBIDDEN
            } else if err.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            json_err(status, err)
        }
    }
}

async fn deny_access_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Option<Extension<ResolvedRequestContext>>,
    Path(id): Path<String>,
    body: Option<Json<DecisionBody>>,
) -> Response {
    let (tenant, claims) = match require_any_perm(
        &state,
        &headers,
        &[perm::ACCESS_REQUESTS_APPROVE, perm::ALL],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let note = body.map_or_else(String::new, |b| {
        if b.0.note.is_empty() {
            b.0.reason
        } else {
            b.0.note
        }
    });
    match state
        .governance
        .deny_request(&tenant, &id, &claims.user_id, &claims.email, &note)
        .await
    {
        Ok(req) => {
            persist_jit_request(&state, &req).await;
            record_gov_audit(
                &state,
                &tenant,
                &claims.user_id,
                &claims.email,
                &claims.role,
                &ctx.client_ip,
                &req.id,
                "jit_access_denied",
                req.target_type.as_str(),
                &req.target_id,
                format!("denied request for {} ({note})", req.requester_email),
                "success",
                None,
            )
            .await;
            if let Ok(payload) = serde_json::to_value(&req) {
                state
                    .governance
                    .dispatch_webhook(&tenant, "access_request.denied", payload)
                    .await;
            }
            Json(req).into_response()
        }
        Err(err) => {
            let status = if err.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            json_err(status, err)
        }
    }
}

async fn revoke_access_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Option<Extension<ResolvedRequestContext>>,
    Path(id): Path<String>,
    body: Option<Json<DecisionBody>>,
) -> Response {
    let (tenant, claims) = match require_any_perm(
        &state,
        &headers,
        &[perm::ACCESS_REQUESTS_APPROVE, perm::ALL],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let note = body.map_or_else(String::new, |b| {
        if b.0.note.is_empty() {
            b.0.reason
        } else {
            b.0.note
        }
    });
    match state
        .governance
        .revoke_request(&tenant, &id, &claims.user_id, &note)
        .await
    {
        Ok(req) => {
            let terminated =
                state
                    .session_fence
                    .terminate_jit_grant(&tenant, &req.id, "jit_grant_revoked");
            persist_jit_request(&state, &req).await;
            record_gov_audit(
                &state,
                &tenant,
                &claims.user_id,
                &claims.email,
                &claims.role,
                &ctx.client_ip,
                &req.id,
                "jit_access_revoked",
                req.target_type.as_str(),
                &req.target_id,
                format!("revoked JIT grant (terminated_sessions={terminated})"),
                "success",
                None,
            )
            .await;
            if let Ok(payload) = serde_json::to_value(&req) {
                state
                    .governance
                    .dispatch_webhook(&tenant, "access_request.revoked", payload)
                    .await;
            }
            Json(serde_json::json!({
                "request": req,
                "terminated_sessions": terminated,
            }))
            .into_response()
        }
        Err(err) => {
            let status = if err.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            json_err(status, err)
        }
    }
}

fn percent_decode_form(raw: &str) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(u8::try_from((hi << 4) | lo).unwrap_or(b'?'));
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map_or("", str::trim)
}

async fn webhook_action_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Option<Extension<ResolvedRequestContext>>,
    Path(provider): Path<String>,
    body: Bytes,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let tenant = extract_tenant_id_checked(None, &headers, &state.trusted_proxies);
    let hooks = state
        .governance
        .raw_webhooks_for_provider(&tenant, &provider)
        .await;
    let slack_ts = header_str(&headers, "x-slack-request-timestamp");
    let slack_sig = header_str(&headers, "x-slack-signature");
    let generic_sig = header_str(&headers, "x-operquay-signature");
    let alt_sig = header_str(&headers, "x-signature-256");
    let sig_hdr = if generic_sig.is_empty() {
        alt_sig
    } else {
        generic_sig
    };

    let sig_valid = hooks.iter().filter(|h| !h.secret.is_empty()).any(|hook| {
        if provider.eq_ignore_ascii_case("slack") && !slack_sig.is_empty() {
            verify_slack_signature(&hook.secret, slack_ts, slack_sig, &body)
        } else if !sig_hdr.is_empty() {
            verify_operquay_hmac(&hook.secret, sig_hdr, &body)
        } else {
            false
        }
    });

    if !sig_valid {
        record_gov_audit(
            &state,
            &tenant,
            "",
            &format!("webhook:{provider}"),
            "webhook",
            &ctx.client_ip,
            "",
            "webhook_callback_rejected",
            "governance",
            &provider,
            "missing or invalid webhook HMAC signature",
            "denied",
            None,
        )
        .await;
        return json_err(
            StatusCode::UNAUTHORIZED,
            "invalid webhook callback signature",
        );
    }

    let raw_str = String::from_utf8_lossy(&body);
    let parsed_json: Option<Value> = if let Ok(v) = serde_json::from_slice::<Value>(&body) {
        Some(v)
    } else {
        raw_str.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k == "payload" {
                serde_json::from_str::<Value>(&percent_decode_form(v)).ok()
            } else {
                None
            }
        })
    };

    let Some(val) = parsed_json else {
        return json_err(
            StatusCode::BAD_REQUEST,
            "unrecognized webhook callback body",
        );
    };

    let (action_str, request_id, approver_id, approver_email, note) =
        if let Some(first_action) = val["actions"].as_array().and_then(|a| a.first()) {
            let act_id = first_action["action_id"].as_str().unwrap_or("");
            let act = if act_id.contains("approve") {
                "approve"
            } else {
                "deny"
            };
            let req_id = first_action["value"]
                .as_str()
                .unwrap_or("")
                .trim()
                .to_owned();
            let uid = val["user"]["id"].as_str().map_or_else(
                || format!("webhook:{provider}"),
                |u| format!("{provider}:{u}"),
            );
            let email = val["user"]["username"].as_str().unwrap_or(&uid).to_owned();
            (
                act.to_owned(),
                req_id,
                uid,
                email,
                format!("via {provider} callback"),
            )
        } else {
            let act = val["action"]
                .as_str()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let req_id = val["request_id"].as_str().unwrap_or("").trim().to_owned();
            let uid = val["approver_id"]
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .map_or_else(|| format!("webhook:{provider}"), ToOwned::to_owned);
            let email = val["approver_email"]
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(&uid)
                .to_owned();
            let note = val["note"]
                .as_str()
                .unwrap_or(&format!("via {provider} callback"))
                .to_owned();
            (act, req_id, uid, email, note)
        };

    if request_id.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "request_id is required");
    }

    let res = match action_str.as_str() {
        "approve" | "jit_approve" => {
            state
                .governance
                .approve_request(&tenant, &request_id, &approver_id, &approver_email, &note)
                .await
        }
        "deny" | "jit_deny" => {
            state
                .governance
                .deny_request(&tenant, &request_id, &approver_id, &approver_email, &note)
                .await
        }
        other => {
            return json_err(
                StatusCode::BAD_REQUEST,
                format!("unsupported callback action '{other}'"),
            );
        }
    };

    match res {
        Ok(req) => {
            persist_jit_request(&state, &req).await;
            let action_name = if req.status == JitStatus::Approved {
                "jit_access_approved_webhook"
            } else {
                "jit_access_denied_webhook"
            };
            record_gov_audit(
                &state,
                &tenant,
                &approver_id,
                &approver_email,
                "webhook",
                &ctx.client_ip,
                &req.id,
                action_name,
                req.target_type.as_str(),
                &req.target_id,
                format!(
                    "{provider} callback updated status to {}",
                    req.status.as_str()
                ),
                "success",
                None,
            )
            .await;
            Json(serde_json::json!({
                "ok": true,
                "request": req,
            }))
            .into_response()
        }
        Err(err) => {
            let status = if err.contains("four-eyes") {
                StatusCode::FORBIDDEN
            } else if err.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            json_err(status, err)
        }
    }
}

// ---------------------------------------------------------------------------
// ChatOps Governance Webhooks
// ---------------------------------------------------------------------------

async fn list_governance_webhooks(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _claims) = match require_any_perm(
        &state,
        &headers,
        &[
            perm::DLP_MANAGE,
            perm::ACCESS_REQUESTS_APPROVE,
            perm::COMPLIANCE_MANAGE,
            perm::AUDIT_READ,
            perm::ALL,
        ],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let webhooks = state.governance.list_webhooks(&tenant).await;
    let delivery_stats = state.governance.webhook_stats();
    Json(serde_json::json!({
        "webhooks": webhooks,
        "stats": delivery_stats,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct CreateWebhookBody {
    #[serde(default = "default_webhook_provider")]
    provider: String,
    #[serde(default)]
    name: String,
    url: String,
    #[serde(default)]
    secret: String,
    #[serde(default)]
    events: Vec<String>,
    #[serde(default = "default_enabled_true")]
    enabled: bool,
}

fn default_webhook_provider() -> String {
    "generic".to_owned()
}

const fn default_enabled_true() -> bool {
    true
}

async fn create_governance_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Option<Extension<ResolvedRequestContext>>,
    Json(body): Json<CreateWebhookBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(
        &state,
        &headers,
        &[perm::DLP_MANAGE, perm::COMPLIANCE_MANAGE, perm::ALL],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let hook = GovernanceWebhook {
        id: format!("whk-{}", Uuid::new_v4()),
        tenant_id: tenant.clone(),
        provider: body.provider.trim().to_ascii_lowercase(),
        name: if body.name.trim().is_empty() {
            format!("{} webhook", body.provider.trim())
        } else {
            body.name.trim().to_owned()
        },
        url: body.url.trim().to_owned(),
        secret: body.secret,
        events: body.events,
        enabled: body.enabled,
        created_at: now_unix_secs(),
    };
    match state.governance.add_webhook(hook).await {
        Ok(saved) => {
            persist_webhook(&state, &saved).await;
            record_gov_audit(
                &state,
                &tenant,
                &claims.user_id,
                &claims.email,
                &claims.role,
                &ctx.client_ip,
                &saved.id,
                "governance_webhook_created",
                "governance",
                &saved.provider,
                format!("configured webhook '{}'", saved.name),
                "success",
                None,
            )
            .await;
            (
                StatusCode::CREATED,
                Json(crate::jit::PublicGovernanceWebhook::from(&saved)),
            )
                .into_response()
        }
        Err(err) => json_err(StatusCode::BAD_REQUEST, err),
    }
}

async fn delete_governance_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Option<Extension<ResolvedRequestContext>>,
    Path(id): Path<String>,
) -> Response {
    let (tenant, claims) = match require_any_perm(
        &state,
        &headers,
        &[perm::DLP_MANAGE, perm::COMPLIANCE_MANAGE, perm::ALL],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let deleted = state.governance.delete_webhook(&tenant, &id).await;
    if let Some(pg) = state.pg_pool().await {
        if let Err(err) = pg.delete_governance_webhook(&tenant, &id).await {
            tracing::warn!(webhook_id = %id, error = %err, "failed deleting governance webhook from PG");
        }
    }
    record_gov_audit(
        &state,
        &tenant,
        &claims.user_id,
        &claims.email,
        &claims.role,
        &ctx.client_ip,
        &id,
        "governance_webhook_deleted",
        "governance",
        &id,
        format!("deleted={deleted}"),
        "success",
        None,
    )
    .await;
    Json(serde_json::json!({ "deleted": deleted })).into_response()
}

// ---------------------------------------------------------------------------
// M11.3: Inline DLP & Command Firewall
// ---------------------------------------------------------------------------

async fn get_dlp_policy(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _claims) = match require_any_perm(
        &state,
        &headers,
        &[
            perm::DLP_MANAGE,
            perm::COMPLIANCE_MANAGE,
            perm::AUDIT_READ,
            perm::ALL,
        ],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.governance.get_dlp_policy(&tenant).await).into_response()
}

async fn put_dlp_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Option<Extension<ResolvedRequestContext>>,
    Json(policy): Json<DlpFirewallPolicy>,
) -> Response {
    let (tenant, claims) =
        match require_any_perm(&state, &headers, &[perm::DLP_MANAGE, perm::ALL]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    if let Err(err) = validate_policy(&policy) {
        return json_err(StatusCode::BAD_REQUEST, err);
    }
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    state
        .governance
        .set_dlp_policy(&tenant, policy.clone())
        .await;
    persist_dlp_policy(&state, &tenant, &policy).await;
    record_gov_audit(
        &state,
        &tenant,
        &claims.user_id,
        &claims.email,
        &claims.role,
        &ctx.client_ip,
        "",
        "dlp_policy_updated",
        "dlp",
        "policy",
        format!(
            "db_dlp={} command_firewall={} rules={} jit_db_write={}",
            policy.db_dlp.enabled,
            policy.command_firewall_enabled,
            policy.rules.len(),
            policy.require_jit_for_db_write
        ),
        "success",
        None,
    )
    .await;
    Json(policy).into_response()
}

#[derive(Deserialize)]
struct TestDlpBody {
    #[serde(default = "default_ssh_proto")]
    protocol: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    sample_columns: Vec<String>,
    #[serde(default)]
    sample_rows: Vec<Vec<String>>,
    #[serde(default = "default_viewer_role")]
    role: String,
    #[serde(default)]
    policy: Option<DlpFirewallPolicy>,
}

fn default_ssh_proto() -> String {
    "ssh".to_owned()
}

fn default_viewer_role() -> String {
    "operator".to_owned()
}

async fn test_dlp_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TestDlpBody>,
) -> Response {
    let (tenant, _claims) =
        match require_any_perm(&state, &headers, &[perm::DLP_MANAGE, perm::ALL]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let policy = match body.policy {
        Some(p) => {
            if let Err(err) = validate_policy(&p) {
                return json_err(StatusCode::BAD_REQUEST, err);
            }
            p
        }
        None => state.governance.get_dlp_policy(&tenant).await,
    };
    let verdict = evaluate_command(&policy, &body.protocol, &body.command);
    let (redacted_sample, dlp_summary) = if body.sample_columns.is_empty() {
        (None, None)
    } else {
        let mut rows = Vec::with_capacity(body.sample_rows.len());
        let mut matrix_rows = Vec::with_capacity(body.sample_rows.len());
        for raw_row in &body.sample_rows {
            let mut obj = Map::new();
            let mut matrix = Vec::with_capacity(body.sample_columns.len());
            for (idx, col) in body.sample_columns.iter().enumerate() {
                let cell = raw_row.get(idx).cloned().unwrap_or_default();
                let v = Value::String(cell);
                obj.insert(col.clone(), v.clone());
                matrix.push(v);
            }
            rows.push(obj);
            matrix_rows.push(matrix);
        }
        let mut res = DbQueryResult {
            columns: body.sample_columns.clone(),
            rows,
            matrix_rows,
            row_count: body.sample_rows.len(),
            duration_ms: 0,
            truncated: false,
            dlp_summary: None,
        };
        let summary = operquay_db::dlp::redact_query_result(&mut res, &policy.db_dlp, &body.role);
        (Some(res), Some(summary))
    };

    Json(serde_json::json!({
        "verdict": verdict,
        "redacted_sample": redacted_sample,
        "dlp_summary": dlp_summary,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// M11.2: Dual-Control Session Moderation, Live Shadowing & Risk Bookmarks
// ---------------------------------------------------------------------------

async fn list_live_sessions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _claims) = match require_any_perm(
        &state,
        &headers,
        &[perm::SESSIONS_MODERATE, perm::AUDIT_READ, perm::ALL],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let sessions = state.moderation.list_sessions(&tenant);
    Json(serde_json::json!({ "sessions": sessions })).into_response()
}

#[derive(Deserialize)]
struct FreezeBody {
    frozen: bool,
    #[serde(default)]
    reason: String,
}

async fn freeze_live_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Option<Extension<ResolvedRequestContext>>,
    Path(id): Path<String>,
    Json(body): Json<FreezeBody>,
) -> Response {
    let (tenant, claims) =
        match require_any_perm(&state, &headers, &[perm::SESSIONS_MODERATE, perm::ALL]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    match state
        .moderation
        .set_frozen(&tenant, &id, body.frozen, &claims.email, &body.reason)
    {
        Ok(info) => {
            let action = if body.frozen {
                "session_frozen"
            } else {
                "session_unfrozen"
            };
            record_gov_audit(
                &state,
                &tenant,
                &claims.user_id,
                &claims.email,
                &claims.role,
                &ctx.client_ip,
                &id,
                action,
                &info.protocol,
                &info.target_host,
                info.frozen_reason.clone(),
                "success",
                info.recording_id.clone(),
            )
            .await;
            Json(info).into_response()
        }
        Err(err) => json_err(StatusCode::NOT_FOUND, err),
    }
}

async fn kill_live_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Option<Extension<ResolvedRequestContext>>,
    Path(id): Path<String>,
    body: Option<Json<DecisionBody>>,
) -> Response {
    let (tenant, claims) =
        match require_any_perm(&state, &headers, &[perm::SESSIONS_MODERATE, perm::ALL]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let reason = body.map_or_else(String::new, |b| {
        if b.0.reason.is_empty() {
            b.0.note
        } else {
            b.0.reason
        }
    });
    match state
        .moderation
        .kill_session(&state.session_fence, &tenant, &id, &claims.email, &reason)
    {
        Ok(killed) => {
            record_gov_audit(
                &state,
                &tenant,
                &claims.user_id,
                &claims.email,
                &claims.role,
                &ctx.client_ip,
                &id,
                "session_force_killed",
                "moderation",
                &id,
                format!("moderator {} killed session: {reason}", claims.email),
                "success",
                None,
            )
            .await;
            state
                .governance
                .dispatch_webhook(
                    &tenant,
                    "session.killed",
                    serde_json::json!({
                        "session_id": id,
                        "moderator": claims.email,
                        "reason": reason,
                        "summary": format!("Session {id} force-killed by {}", claims.email),
                    }),
                )
                .await;
            Json(serde_json::json!({ "killed": killed })).into_response()
        }
        Err(err) => json_err(StatusCode::NOT_FOUND, err),
    }
}

#[derive(Default, Deserialize)]
struct ShadowQuery {
    #[serde(default)]
    role: String,
}

async fn ws_session_shadow(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Option<Extension<ResolvedRequestContext>>,
    Path(session_id): Path<String>,
    Query(q): Query<ShadowQuery>,
) -> Response {
    let mod_role = if q.role.eq_ignore_ascii_case("moderator") {
        ModerationRole::Moderator
    } else {
        ModerationRole::Observer
    };
    let required: &[&str] = match mod_role {
        ModerationRole::Moderator => &[perm::SESSIONS_MODERATE, perm::ALL],
        ModerationRole::Observer => &[
            perm::SESSIONS_MODERATE,
            perm::AUDIT_READ,
            perm::RECORDINGS_READ,
            perm::ALL,
        ],
    };
    let (tenant, claims) = match require_any_perm(&state, &headers, required).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(sub) = state.moderation.subscribe(&tenant, &session_id, mod_role) else {
        return json_err(StatusCode::NOT_FOUND, "live session not found");
    };
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let role_str = match mod_role {
        ModerationRole::Moderator => "moderator",
        ModerationRole::Observer => "observer",
    };
    record_gov_audit(
        &state,
        &tenant,
        &claims.user_id,
        &claims.email,
        &claims.role,
        &ctx.client_ip,
        &session_id,
        "session_shadow_started",
        &sub.snapshot.protocol,
        &sub.snapshot.target_host,
        format!("live shadow joined as {role_str}"),
        "success",
        sub.snapshot.recording_id.clone(),
    )
    .await;

    ws.on_upgrade(move |socket| {
        handle_shadow_socket(socket, state, tenant, session_id, mod_role, claims, sub)
    })
}

async fn send_shadow_event(socket: &mut WebSocket, ev: &LiveSessionEvent) -> bool {
    let Ok(json) = serde_json::to_string(ev) else {
        return true;
    };
    socket.send(WsMsg::Text(json.into())).await.is_ok()
}

async fn handle_shadow_socket(
    mut socket: WebSocket,
    state: AppState,
    tenant_id: String,
    session_id: String,
    role: ModerationRole,
    claims: SessionClaims,
    mut sub: crate::moderation::ShadowSubscription,
) {
    let snap = LiveSessionEvent::Snapshot {
        session: sub.snapshot.clone(),
    };
    if !send_shadow_event(&mut socket, &snap).await {
        return;
    }
    if !sub.backlog.is_empty() {
        let backlog_ev = LiveSessionEvent::Output {
            data: std::mem::take(&mut sub.backlog),
        };
        if !send_shadow_event(&mut socket, &backlog_ev).await {
            return;
        }
    }

    loop {
        tokio::select! {
            ev_res = sub.rx.recv() => {
                match ev_res {
                    Ok(ev) => {
                        let is_term = matches!(ev, LiveSessionEvent::Terminated { .. });
                        if !send_shadow_event(&mut socket, &ev).await || is_term {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        let notice = LiveSessionEvent::Notice {
                            level: "warn".to_owned(),
                            message: format!("shadow stream dropped {skipped} lagged frames"),
                        };
                        if !send_shadow_event(&mut socket, &notice).await {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            cli = socket.next() => {
                let Some(Ok(msg)) = cli else { break; };
                match msg {
                    WsMsg::Close(_) => break,
                    WsMsg::Text(txt) => {
                        let Ok(cmd) = serde_json::from_str::<Value>(&txt) else { continue; };
                        let action = cmd["action"].as_str().unwrap_or("");
                        if role != ModerationRole::Moderator {
                            let notice = LiveSessionEvent::Notice {
                                level: "error".to_owned(),
                                message: "observer role is read-only; moderator permission required".to_owned(),
                            };
                            if !send_shadow_event(&mut socket, &notice).await {
                                break;
                            }
                            continue;
                        }
                        let reason = cmd["reason"].as_str().unwrap_or("");
                        match action {
                            "freeze" => {
                                let _ = state.moderation.set_frozen(&tenant_id, &session_id, true, &claims.email, reason);
                            }
                            "unfreeze" => {
                                let _ = state.moderation.set_frozen(&tenant_id, &session_id, false, &claims.email, reason);
                            }
                            "kill" => {
                                let _ = state.moderation.kill_session(&state.session_fence, &tenant_id, &session_id, &claims.email, reason);
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let _ = socket.close().await;
}

async fn list_recording_bookmarks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, _claims) = match require_any_perm(
        &state,
        &headers,
        &[perm::RECORDINGS_READ, perm::AUDIT_READ, perm::ALL],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(entry) = state.recordings.get_entry(&id).await else {
        return json_err(StatusCode::NOT_FOUND, "recording not found");
    };
    if entry.tenant_id != tenant {
        return json_err(StatusCode::FORBIDDEN, "tenant mismatch");
    }
    let bookmarks = state.governance.list_bookmarks(&tenant, &entry.id).await;
    Json(serde_json::json!({
        "recording_id": entry.id,
        "bookmarks": bookmarks,
    }))
    .into_response()
}

async fn analyze_recording_risk(
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Option<Extension<ResolvedRequestContext>>,
    Path(id): Path<String>,
) -> Response {
    let (tenant, claims) = match require_any_perm(
        &state,
        &headers,
        &[perm::RECORDINGS_READ, perm::AUDIT_READ, perm::ALL],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(entry) = state.recordings.get_entry(&id).await else {
        return json_err(StatusCode::NOT_FOUND, "recording not found");
    };
    if entry.tenant_id != tenant {
        return json_err(StatusCode::FORBIDDEN, "tenant mismatch");
    }
    let Some(raw) = state.recordings.get_guac_bytes(&entry.id).await else {
        return json_err(
            StatusCode::NOT_FOUND,
            "recording payload unavailable or crypto-shredded",
        );
    };
    let transcript = String::from_utf8_lossy(&raw).into_owned();
    let analysis = state
        .platform
        .llm
        .analyze_session_risk_bookmarks(&tenant, &transcript, None)
        .await;
    let now = now_unix_secs();
    let bookmarks: Vec<SessionRiskBookmark> = analysis
        .bookmarks
        .into_iter()
        .map(|b| SessionRiskBookmark {
            id: format!("bmk-{}", Uuid::new_v4()),
            tenant_id: tenant.clone(),
            recording_id: entry.id.clone(),
            session_id: entry.id.clone(),
            offset_secs: b.offset_secs,
            severity: b.severity,
            category: b.category,
            title: b.title,
            detail: b.detail,
            source: b.source,
            created_at: now,
        })
        .collect();
    state
        .governance
        .replace_bookmarks(&tenant, &entry.id, bookmarks.clone())
        .await;
    persist_risk_bookmarks(&state, &bookmarks).await;

    let ctx = req_ctx(&state, &headers, ext.as_ref());
    record_gov_audit(
        &state,
        &tenant,
        &claims.user_id,
        &claims.email,
        &claims.role,
        &ctx.client_ip,
        &entry.id,
        "recording_risk_analyzed",
        &entry.protocol,
        &entry.target_host,
        format!(
            "risk_score={} bookmarks={}",
            analysis.risk_score,
            bookmarks.len()
        ),
        "success",
        Some(entry.id.clone()),
    )
    .await;
    if analysis.risk_score >= 70 {
        state
            .governance
            .dispatch_webhook(
                &tenant,
                "recording.risk_analyzed",
                serde_json::json!({
                    "recording_id": entry.id,
                    "risk_score": analysis.risk_score,
                    "bookmark_count": bookmarks.len(),
                    "summary": analysis.summary,
                }),
            )
            .await;
    }

    Json(serde_json::json!({
        "recording_id": entry.id,
        "risk_score": analysis.risk_score,
        "summary": analysis.summary,
        "bookmarks": bookmarks,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// M11.4: Continuous Compliance Posture, Access Reviews & Signed Evidence
// ---------------------------------------------------------------------------

async fn build_posture_report(state: &AppState, tenant_id: &str) -> CompliancePostureReport {
    let now = now_unix_secs();
    let compliance_mode = compliance_mode_enabled();
    let audit_verify = state.audit.verify_chain(tenant_id).await;
    let recordings = state.recordings.list(tenant_id).await;
    let total_recordings = recordings.len();
    let encrypted_recordings = recordings.iter().filter(|r| r.encrypted).count();
    let legal_hold_recordings = recordings.iter().filter(|r| r.legal_hold).count();

    let requests = state.governance.list_requests(tenant_id).await;
    let jit_pending_requests = requests
        .iter()
        .filter(|r| r.status == JitStatus::Pending)
        .count();
    let jit_active_grants = requests
        .iter()
        .filter(|r| r.status == JitStatus::Approved && r.expires_at.is_some_and(|exp| exp > now))
        .count();

    let dlp_policy = state.governance.get_dlp_policy(tenant_id).await;
    let webhooks = state.governance.list_webhooks(tenant_id).await;
    let campaigns = state.governance.list_campaigns(tenant_id).await;
    let users = state.auth.list_users(tenant_id).await;
    let mfa_users = users.iter().filter(|u| u.mfa_enabled).count();

    let controls = vec![
        ComplianceControlStatus {
            control_id: "CC6.1".to_owned(),
            framework: "SOC 2 Type II".to_owned(),
            title: "Fail-Closed Session Recording & AEAD Encryption".to_owned(),
            status: if total_recordings == 0 || encrypted_recordings == total_recordings {
                "passing".to_owned()
            } else {
                "attention".to_owned()
            },
            evidence: format!(
                "{encrypted_recordings}/{total_recordings} encrypted recordings, {legal_hold_recordings} legal holds"
            ),
        },
        ComplianceControlStatus {
            control_id: "CC6.2".to_owned(),
            framework: "SOC 2 Type II".to_owned(),
            title: "Phishing-Resistant Auth & Multi-Factor Enforcement".to_owned(),
            status: if compliance_mode || mfa_users > 0 {
                "passing".to_owned()
            } else {
                "attention".to_owned()
            },
            evidence: format!(
                "compliance_mode={compliance_mode}, {mfa_users}/{} users MFA enrolled",
                users.len()
            ),
        },
        ComplianceControlStatus {
            control_id: "CC6.3".to_owned(),
            framework: "SOC 2 Type II".to_owned(),
            title: "Quarterly Access Reviews & Least-Privilege Recertification".to_owned(),
            status: if campaigns.is_empty() {
                "attention".to_owned()
            } else {
                "passing".to_owned()
            },
            evidence: format!("{} access review campaign(s) recorded", campaigns.len()),
        },
        ComplianceControlStatus {
            control_id: "CC6.6".to_owned(),
            framework: "SOC 2 Type II".to_owned(),
            title: "Inline Data Loss Prevention & Command Firewall".to_owned(),
            status: if dlp_policy.db_dlp.enabled && dlp_policy.command_firewall_enabled {
                "passing".to_owned()
            } else {
                "attention".to_owned()
            },
            evidence: format!(
                "db_dlp={} firewall={} active_rules={}",
                dlp_policy.db_dlp.enabled,
                dlp_policy.command_firewall_enabled,
                dlp_policy.rules.iter().filter(|r| r.enabled).count()
            ),
        },
        ComplianceControlStatus {
            control_id: "CC6.8".to_owned(),
            framework: "SOC 2 Type II".to_owned(),
            title: "Zero Standing Privileges (JIT) & Four-Eyes Separation".to_owned(),
            status: "passing".to_owned(),
            evidence: format!(
                "{jit_active_grants} active lease(s), {jit_pending_requests} pending approval(s), 4-eyes enforced"
            ),
        },
        ComplianceControlStatus {
            control_id: "CC7.2".to_owned(),
            framework: "SOC 2 Type II".to_owned(),
            title: "Tamper-Evident Hash-Chained Audit Ledger & Out-of-Band Alerting".to_owned(),
            status: if audit_verify.valid {
                "passing".to_owned()
            } else {
                "failing".to_owned()
            },
            evidence: format!(
                "chain_valid={} source={} checked={} webhook(s)={}",
                audit_verify.valid,
                audit_verify.source,
                audit_verify.checked_events,
                webhooks.len()
            ),
        },
        ComplianceControlStatus {
            control_id: "A.12.4".to_owned(),
            framework: "ISO/IEC 27001".to_owned(),
            title: "Dual-Control Live Session Moderation & Risk Tagging".to_owned(),
            status: "passing".to_owned(),
            evidence: format!(
                "{} live session(s) under moderation hub",
                state.moderation.list_sessions(tenant_id).len()
            ),
        },
    ];

    CompliancePostureReport {
        tenant_id: tenant_id.to_owned(),
        generated_at: now,
        compliance_mode,
        audit_chain_valid: audit_verify.valid,
        audit_source: audit_verify.source,
        audit_checked_events: audit_verify.checked_events,
        total_recordings,
        encrypted_recordings,
        legal_hold_recordings,
        jit_pending_requests,
        jit_active_grants,
        dlp_firewall_enabled: dlp_policy.command_firewall_enabled && dlp_policy.db_dlp.enabled,
        webhooks_configured: webhooks.len(),
        controls,
    }
}

async fn get_compliance_posture(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _claims) = match require_any_perm(
        &state,
        &headers,
        &[perm::COMPLIANCE_MANAGE, perm::AUDIT_READ, perm::ALL],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(build_posture_report(&state, &tenant).await).into_response()
}

async fn list_access_reviews(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _claims) = match require_any_perm(
        &state,
        &headers,
        &[perm::COMPLIANCE_MANAGE, perm::AUDIT_READ, perm::ALL],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let campaigns = state.governance.list_campaigns(&tenant).await;
    Json(serde_json::json!({ "campaigns": campaigns })).into_response()
}

#[derive(Default, Deserialize)]
struct CreateCampaignBody {
    #[serde(default)]
    title: String,
    #[serde(default)]
    quarter: String,
}

async fn create_access_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Option<Extension<ResolvedRequestContext>>,
    Json(body): Json<CreateCampaignBody>,
) -> Response {
    let (tenant, claims) =
        match require_any_perm(&state, &headers, &[perm::COMPLIANCE_MANAGE, perm::ALL]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let now = now_unix_secs();
    let users = state.auth.list_users(&tenant).await;
    let items: Vec<AccessReviewItem> = users
        .into_iter()
        .map(|u| AccessReviewItem {
            item_id: format!("ari-{}", Uuid::new_v4()),
            principal_id: u.id,
            principal_email: u.email,
            role: u.role,
            target_summary: format!("provider={} disabled={}", u.provider, u.disabled),
            mfa_enabled: u.mfa_enabled,
            last_active_at: now,
            decision: AccessReviewDecision::Pending,
            reviewer_email: None,
            note: String::new(),
            decided_at: None,
        })
        .collect();
    let quarter = if body.quarter.trim().is_empty() {
        "Current".to_owned()
    } else {
        body.quarter.trim().to_owned()
    };
    let title = if body.title.trim().is_empty() {
        format!("Quarterly Access Review ({quarter})")
    } else {
        body.title.trim().to_owned()
    };
    let campaign = AccessReviewCampaign {
        id: format!("arc-{}", Uuid::new_v4()),
        tenant_id: tenant.clone(),
        title,
        quarter,
        status: AccessReviewStatus::Active,
        created_by: claims.email.clone(),
        created_at: now,
        completed_at: None,
        items,
    };
    state.governance.save_campaign(campaign.clone()).await;
    persist_campaign(&state, &campaign).await;
    record_gov_audit(
        &state,
        &tenant,
        &claims.user_id,
        &claims.email,
        &claims.role,
        &ctx.client_ip,
        &campaign.id,
        "access_review_started",
        "compliance",
        &campaign.quarter,
        format!(
            "created review campaign with {} user(s)",
            campaign.items.len()
        ),
        "success",
        None,
    )
    .await;
    (StatusCode::CREATED, Json(campaign)).into_response()
}

#[derive(Deserialize)]
struct DecideItemBody {
    decision: AccessReviewDecision,
    #[serde(default)]
    note: String,
    #[serde(default)]
    disable_user: Option<bool>,
}

async fn decide_access_review_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Option<Extension<ResolvedRequestContext>>,
    Path((id, item_id)): Path<(String, String)>,
    Json(body): Json<DecideItemBody>,
) -> Response {
    let (tenant, claims) =
        match require_any_perm(&state, &headers, &[perm::COMPLIANCE_MANAGE, perm::ALL]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let Some(mut campaign) = state.governance.get_campaign(&tenant, &id).await else {
        return json_err(StatusCode::NOT_FOUND, "access review campaign not found");
    };
    let Some(item) = campaign.items.iter_mut().find(|i| i.item_id == item_id) else {
        return json_err(StatusCode::NOT_FOUND, "access review item not found");
    };
    let now = now_unix_secs();
    item.decision = body.decision;
    item.reviewer_email = Some(claims.email.clone());
    body.note.trim().clone_into(&mut item.note);
    item.decided_at = Some(now);
    let principal_id = item.principal_id.clone();
    let principal_email = item.principal_email.clone();

    if body.decision == AccessReviewDecision::Revoked && body.disable_user.unwrap_or(true) {
        let _ = state
            .auth
            .update_user_status(&claims.user_id, &tenant, &principal_id, true)
            .await;
    }

    if campaign
        .items
        .iter()
        .all(|i| i.decision != AccessReviewDecision::Pending)
    {
        campaign.status = AccessReviewStatus::Completed;
        campaign.completed_at = Some(now);
    }

    state.governance.save_campaign(campaign.clone()).await;
    persist_campaign(&state, &campaign).await;

    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let dec_str = match body.decision {
        AccessReviewDecision::Certified => "certified",
        AccessReviewDecision::Revoked => "revoked",
        AccessReviewDecision::Pending => "pending",
    };
    record_gov_audit(
        &state,
        &tenant,
        &claims.user_id,
        &claims.email,
        &claims.role,
        &ctx.client_ip,
        &campaign.id,
        "access_review_item_decided",
        "compliance",
        &principal_email,
        format!("decision={dec_str} note={}", body.note.trim()),
        "success",
        None,
    )
    .await;

    Json(campaign).into_response()
}

async fn export_signed_evidence_bundle(
    State(state): State<AppState>,
    headers: HeaderMap,
    ext: Option<Extension<ResolvedRequestContext>>,
) -> Response {
    let (tenant, claims) = match require_any_perm(
        &state,
        &headers,
        &[perm::COMPLIANCE_MANAGE, perm::AUDIT_READ, perm::ALL],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let now = now_unix_secs();
    let posture = build_posture_report(&state, &tenant).await;
    let audit_verify = state.audit.verify_chain(&tenant).await;
    let mut audit_events = state.audit.list(&tenant).await;
    if audit_events.len() > 500 {
        let skip = audit_events.len() - 500;
        audit_events.drain(..skip);
    }
    let recordings = state.recordings.list(&tenant).await;
    let access_requests = state.governance.list_requests(&tenant).await;
    let access_reviews = state.governance.list_campaigns(&tenant).await;
    let dlp_policy = state.governance.get_dlp_policy(&tenant).await;

    let bundle = serde_json::json!({
        "schema_version": "operquay-evidence-v1",
        "tenant_id": tenant,
        "generated_at": now,
        "generated_by": claims.email,
        "posture": posture,
        "audit_verify": audit_verify,
        "audit_events": audit_events,
        "recordings": recordings,
        "access_requests": access_requests,
        "access_review_campaigns": access_reviews,
        "dlp_policy": dlp_policy,
    });
    let seed = state.governance.evidence_signing_seed().await;
    match sign_evidence_bundle(&seed, bundle, now) {
        Ok(signed) => {
            record_gov_audit(
                &state,
                &tenant,
                &claims.user_id,
                &claims.email,
                &claims.role,
                &ctx.client_ip,
                "",
                "compliance_evidence_exported",
                "compliance",
                "evidence_bundle",
                format!("sha256={}", signed.integrity.payload_sha256),
                "success",
                None,
            )
            .await;
            Json(signed).into_response()
        }
        Err(err) => json_err(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

async fn verify_evidence_bundle_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(signed): Json<SignedEvidenceBundle>,
) -> Response {
    let (_tenant, _claims) = match require_any_perm(
        &state,
        &headers,
        &[perm::COMPLIANCE_MANAGE, perm::AUDIT_READ, perm::ALL],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match verify_signed_evidence_bundle(&signed) {
        Ok(()) => Json(serde_json::json!({
            "valid": true,
            "error": Value::Null,
            "algorithm": signed.integrity.algorithm,
            "public_key_b64": signed.integrity.public_key_b64,
            "payload_sha256": signed.integrity.payload_sha256,
            "signed_at": signed.integrity.signed_at,
        }))
        .into_response(),
        Err(err) => Json(serde_json::json!({
            "valid": false,
            "error": err,
            "algorithm": signed.integrity.algorithm,
            "public_key_b64": signed.integrity.public_key_b64,
            "payload_sha256": signed.integrity.payload_sha256,
            "signed_at": signed.integrity.signed_at,
        }))
        .into_response(),
    }
}
