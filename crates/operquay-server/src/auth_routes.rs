#![forbid(unsafe_code)]

//! Enterprise Authentication, RBAC, SSO (`OIDC` PKCE + `SAML` 2.0), Groups,
//! `IdP` Group Mappings, and `SCIM` v2 HTTP routes (`crates/operquay-server`).

use axum::extract::{Form, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use operquay_auth::crypto::extract_tenant_id_checked;
use operquay_auth::policy::{perm, BindingConditions, Effect, ScopeType, PERMISSION_CATALOG};
use operquay_auth::scim::{
    ScimGroupResource, ScimPatchRequest, ScimUserResource, SCIM_CONTENT_TYPE, SCIM_SCHEMA_ERROR,
    SCIM_SCHEMA_GROUP, SCIM_SCHEMA_META, SCIM_SCHEMA_RES_TYPE, SCIM_SCHEMA_SPC, SCIM_SCHEMA_USER,
};
use operquay_auth::sso::{SsoProviderConfig, SsoProviderPatch};
use operquay_auth::{
    compliance_mode_enabled, AuthError, SessionClaims, HOST_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
};
use serde::Deserialize;

use crate::stores::AuditRecordInput;
use crate::{AppState, ResolvedRequestContext};

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

pub(crate) fn user_agent_from_headers(headers: &HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned()
}

pub fn auth_router() -> Router<AppState> {
    Router::new()
        .route("/api/auth/config", get(auth_config))
        .route("/api/auth/login", post(login))
        .route("/api/auth/login/mfa", post(login_mfa))
        .route("/api/auth/logout", post(logout).get(logout_redirect))
        .route("/api/auth/admin-password", post(admin_password))
        .route("/api/auth/password", post(own_password))
        .route("/api/auth/me", get(me))
        .route("/api/auth/mfa/status", get(mfa_status))
        .route("/api/auth/mfa/totp/setup", post(mfa_totp_setup))
        .route("/api/auth/mfa/totp/verify", post(mfa_totp_verify))
        .route("/api/auth/mfa/totp/disable", post(mfa_totp_disable))
        .route(
            "/api/auth/mfa/webauthn/register/start",
            post(webauthn_register_start),
        )
        .route(
            "/api/auth/mfa/webauthn/register/finish",
            post(webauthn_register_finish),
        )
        .route(
            "/api/auth/mfa/webauthn/login/start",
            post(webauthn_login_start),
        )
        .route(
            "/api/auth/mfa/webauthn/login/finish",
            post(webauthn_login_finish),
        )
        .route(
            "/api/auth/mfa/webauthn/{id}",
            delete(webauthn_delete_credential),
        )
        .route(
            "/api/auth/providers",
            get(list_providers).post(add_provider),
        )
        .route(
            "/api/auth/providers/{id}",
            put(update_provider).delete(delete_provider),
        )
        .route("/api/auth/sso/{id}/start", get(sso_start_id))
        .route("/api/auth/sso/start", get(sso_start_default))
        .route("/api/auth/sso/{id}/callback", get(oidc_callback_id))
        .route("/api/auth/sso/callback", get(oidc_callback_default))
        .route("/api/auth/saml/{id}/metadata", get(saml_metadata))
        .route("/api/auth/saml/{id}/acs", post(saml_acs))
        .route("/api/auth/saml/{id}/slo", get(saml_slo).post(saml_slo))
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/{id}", put(edit_user).delete(delete_user))
        .route("/api/users/{id}/role", put(update_user_role))
        .route("/api/users/{id}/groups", put(set_user_groups))
        .route("/api/users/{id}/status", put(update_user_status))
        .route("/api/users/{id}/password", post(reset_user_password))
        .route("/api/permissions", get(list_permissions))
        .route("/api/roles", get(list_roles).post(create_role))
        .route("/api/roles/{id}", put(update_role).delete(delete_role))
        .route("/api/groups", get(list_groups).post(create_group))
        .route("/api/groups/{id}", put(update_group).delete(delete_group))
        .route("/api/groups/{id}/members", post(add_group_member))
        .route(
            "/api/groups/{id}/members/{user_id}",
            delete(remove_group_member),
        )
        .route("/api/groups/{id}/roles", post(bind_group_role))
        .route(
            "/api/groups/{id}/roles/{binding_id}",
            delete(unbind_group_role),
        )
        .route(
            "/api/idp-mappings",
            get(list_idp_mappings).post(create_idp_mapping),
        )
        .route("/api/idp-mappings/{id}", delete(delete_idp_mapping))
        .route(
            "/api/scim/tokens",
            get(list_scim_tokens).post(create_scim_token),
        )
        .route("/api/scim/tokens/{id}", delete(revoke_scim_token))
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(scim_service_provider_config),
        )
        .route("/scim/v2/ResourceTypes", get(scim_resource_types))
        .route("/scim/v2/Schemas", get(scim_schemas))
        .route(
            "/scim/v2/Users",
            get(scim_list_users).post(scim_create_user),
        )
        .route(
            "/scim/v2/Users/{id}",
            get(scim_get_user)
                .put(scim_replace_user)
                .patch(scim_patch_user)
                .delete(scim_delete_user),
        )
        .route(
            "/scim/v2/Groups",
            get(scim_list_groups).post(scim_create_group),
        )
        .route(
            "/scim/v2/Groups/{id}",
            get(scim_get_group)
                .put(scim_replace_group)
                .patch(scim_patch_group)
                .delete(scim_delete_group),
        )
}

pub(crate) async fn require_actor(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(String, SessionClaims), Box<Response>> {
    let tenant_id = extract_tenant_id_checked(None, headers, &state.trusted_proxies);
    if let Some(claims) = state.auth.verify_cookie(headers).await {
        if claims.tenant_id == tenant_id {
            return Ok((tenant_id, claims));
        }
        return Err(Box::new(json_err(StatusCode::FORBIDDEN, "tenant mismatch")));
    }
    if !state.auth.require_auth().await {
        return Ok((
            tenant_id.clone(),
            SessionClaims {
                session_id: "anonymous-lab".to_owned(),
                user_id: "usr-default-admin".to_owned(),
                email: "admin@local".to_owned(),
                name: "Platform Administrator".to_owned(),
                role: "admin".to_owned(),
                tenant_id,
                method: "lab-open".to_owned(),
                issued_at: 0,
                expires_at: i64::MAX,
                last_active_at: 0,
                groups: Vec::new(),
                permissions: Vec::new(),
            },
        ));
    }
    Err(Box::new(json_err(
        StatusCode::UNAUTHORIZED,
        "authentication required",
    )))
}

pub(crate) async fn require_any_perm(
    state: &AppState,
    headers: &HeaderMap,
    perms: &[&str],
) -> Result<(String, SessionClaims), Box<Response>> {
    let (tenant_id, claims) = require_actor(state, headers).await?;
    if !state.auth.require_auth().await && claims.method == "lab-open" {
        return Ok((tenant_id, claims));
    }
    for p in perms {
        if state
            .auth
            .check_permission(&claims.user_id, p, ScopeType::Global, "", None)
            .await
        {
            return Ok((tenant_id, claims));
        }
    }
    Err(Box::new(json_err(
        StatusCode::FORBIDDEN,
        "insufficient permissions for this operation",
    )))
}

fn json_err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

fn auth_err_to_response(err: &AuthError) -> Response {
    if let AuthError::AccountLocked { retry_after_secs } = err {
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": err.to_string(),
                "retry_after": retry_after_secs,
            })),
        )
            .into_response();
        if let Ok(hv) = HeaderValue::from_str(&retry_after_secs.to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, hv);
        }
        return resp;
    }
    if let AuthError::MfaRequired { challenge, methods } = err {
        return Json(serde_json::json!({
            "mfa_required": true,
            "challenge_token": challenge,
            "methods": methods,
        }))
        .into_response();
    }
    let status = match err {
        AuthError::InvalidCredentials | AuthError::ScimUnauthorized | AuthError::InvalidMfaCode => {
            StatusCode::UNAUTHORIZED
        }
        AuthError::AccountDisabled
        | AuthError::SelfEscalation
        | AuthError::SystemRole
        | AuthError::PasswordChangeRequired => StatusCode::FORBIDDEN,
        AuthError::UserNotFound
        | AuthError::GroupNotFound
        | AuthError::RoleNotFound
        | AuthError::ProviderNotFound => StatusCode::NOT_FOUND,
        AuthError::UserExists
        | AuthError::GroupExists
        | AuthError::RoleExists
        | AuthError::LastAdmin => StatusCode::CONFLICT,
        AuthError::InvalidPermission(_) | AuthError::Sso(_) | AuthError::WeakPassword(_) => {
            StatusCode::BAD_REQUEST
        }
        AuthError::AccountLocked { .. } | AuthError::MfaRequired { .. } => {
            StatusCode::TOO_MANY_REQUESTS
        }
    };
    json_err(status, err.to_string())
}

fn session_cookie_header(value: &str, max_age_secs: i64, is_https: bool) -> String {
    if is_https {
        format!(
            "{HOST_SESSION_COOKIE_NAME}={value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age_secs}"
        )
    } else {
        format!(
            "{SESSION_COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}"
        )
    }
}

fn append_clear_session_cookies(resp: &mut Response, is_https: bool) {
    if is_https {
        if let Ok(hv) = HeaderValue::from_str(&session_cookie_header("", 0, true)) {
            resp.headers_mut().append(header::SET_COOKIE, hv);
        }
    }
    if let Ok(hv) = HeaderValue::from_str(&session_cookie_header("", 0, false)) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
}

fn external_origin(headers: &HeaderMap, is_https: bool) -> String {
    if let Ok(pub_url) =
        std::env::var("PUBLIC_URL").or_else(|_| std::env::var("OPERQUAY_PUBLIC_URL"))
    {
        let trimmed = pub_url.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1:8080");
    let tls_port = std::env::var("OPERQUAY_TLS_LISTEN")
        .ok()
        .and_then(|v| v.rsplit(':').next().map(str::to_owned));
    let proto = if is_https
        || host.ends_with(":443")
        || host.ends_with(":5444")
        || host.ends_with(":5443")
        || tls_port
            .as_deref()
            .is_some_and(|p| host.ends_with(&format!(":{p}")))
    {
        "https"
    } else {
        "http"
    };
    format!("{proto}://{host}")
}

fn rp_id_from_origin(origin: &str) -> String {
    let without_scheme = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or(origin);
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
    if authority.starts_with('[') {
        authority
            .split(']')
            .next()
            .unwrap_or("localhost")
            .trim_start_matches('[')
            .to_owned()
    } else {
        authority
            .split(':')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("localhost")
            .to_owned()
    }
}

async fn finish_local_login_response(
    state: &AppState,
    headers: &HeaderMap,
    ctx: &ResolvedRequestContext,
    claims: SessionClaims,
    token: &str,
    action: &str,
    detail: &str,
) -> Response {
    let ua = user_agent_from_headers(headers);
    state
        .audit
        .record_full(AuditRecordInput {
            tenant_id: ctx.tenant_id.clone(),
            trace_id: crate::TelemetryHub::current_trace_id_hex(),
            session_id: claims.session_id.clone(),
            action: action.to_owned(),
            protocol: "auth".to_owned(),
            target_host: claims.email.clone(),
            detail: detail.to_owned(),
            user_id: claims.user_id.clone(),
            user_email: claims.email.clone(),
            role: claims.role.clone(),
            ip: ctx.client_ip.clone(),
            outcome: "success".to_owned(),
            method: "POST".to_owned(),
            status_code: 200,
            user_agent: ua.clone(),
            client: ua,
            ..AuditRecordInput::default()
        })
        .await;
    state.telemetry.record_auth_event("login", "ok");
    let must_change = state.auth.user_must_change_password(&claims.user_id).await;
    let mut resp = Json(serde_json::json!({
        "status": "ok",
        "user": {
            "id": claims.user_id,
            "email": claims.email,
            "name": claims.name,
            "role": claims.role,
            "tenant_id": claims.tenant_id,
            "must_change_password": must_change,
        }
    }))
    .into_response();
    if let Ok(hv) = HeaderValue::from_str(&session_cookie_header(token, 28_800, ctx.is_https)) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

async fn auth_config(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let mut cfg = state.auth.auth_config(&ctx.tenant_id).await;
    if let Some(obj) = cfg.as_object_mut() {
        obj.insert(
            "version".to_owned(),
            serde_json::json!(env!("CARGO_PKG_VERSION")),
        );
        obj.insert(
            "compliance_mode".to_owned(),
            serde_json::json!(compliance_mode_enabled()),
        );
    }
    Json(cfg)
}

#[derive(Deserialize)]
struct LoginBody {
    email: String,
    password: String,
    #[serde(default)]
    totp_code: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
}

async fn login(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    match state
        .auth
        .authenticate_local_with_context(
            &ctx.tenant_id,
            &body.email,
            &body.password,
            &ctx.client_ip,
            body.totp_code.as_deref(),
            body.recovery_code.as_deref(),
        )
        .await
    {
        Ok((claims, token)) => {
            let action = if claims.method == "break_glass" {
                "login_break_glass"
            } else {
                "login_password"
            };
            if action == "login_break_glass" {
                state
                    .governance
                    .dispatch_webhook(
                        &claims.tenant_id,
                        "break_glass.login",
                        serde_json::json!({
                            "user_id": claims.user_id,
                            "email": claims.email,
                            "ip": ctx.client_ip,
                            "summary": format!(
                                "Break-glass local login by {} from {}",
                                claims.email, ctx.client_ip
                            ),
                        }),
                    )
                    .await;
            }
            let detail = format!("local sign-in ({action})");
            finish_local_login_response(&state, &headers, &ctx, claims, &token, action, &detail)
                .await
        }
        Err(AuthError::MfaRequired { challenge, methods }) => Json(serde_json::json!({
            "mfa_required": true,
            "challenge_token": challenge,
            "methods": methods,
        }))
        .into_response(),
        Err(AuthError::AccountLocked { retry_after_secs }) => {
            let ua = user_agent_from_headers(&headers);
            state
                .audit
                .record_full(AuditRecordInput {
                    tenant_id: ctx.tenant_id.clone(),
                    trace_id: crate::TelemetryHub::current_trace_id_hex(),
                    action: "login_locked".to_owned(),
                    protocol: "auth".to_owned(),
                    target_host: body.email.clone(),
                    detail: format!("account login locked ({retry_after_secs}s)"),
                    user_email: body.email,
                    ip: ctx.client_ip,
                    outcome: "denied".to_owned(),
                    method: "POST".to_owned(),
                    status_code: 429,
                    user_agent: ua.clone(),
                    client: ua,
                    ..AuditRecordInput::default()
                })
                .await;
            state.telemetry.record_auth_event("login", "locked");
            auth_err_to_response(&AuthError::AccountLocked { retry_after_secs })
        }
        Err(e) => {
            state.telemetry.record_auth_event("login", "error");
            auth_err_to_response(&e)
        }
    }
}

#[derive(Deserialize)]
struct MfaLoginBody {
    challenge_token: String,
    #[serde(default)]
    totp_code: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
}

async fn login_mfa(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
    Json(body): Json<MfaLoginBody>,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    match state
        .auth
        .complete_mfa_challenge(
            &ctx.tenant_id,
            &body.challenge_token,
            body.totp_code.as_deref(),
            body.recovery_code.as_deref(),
        )
        .await
    {
        Ok((claims, token)) => {
            finish_local_login_response(
                &state,
                &headers,
                &ctx,
                claims,
                &token,
                "login_mfa",
                "MFA verification completed",
            )
            .await
        }
        Err(e) => {
            state.telemetry.record_auth_event("login_mfa", "error");
            auth_err_to_response(&e)
        }
    }
}

async fn mfa_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state.auth.mfa_status(&tenant, &claims.user_id).await {
        Ok(val) => Json(val).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

async fn mfa_totp_setup(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state.auth.begin_totp_setup(&tenant, &claims.user_id).await {
        Ok((secret, otpauth_url)) => {
            Json(serde_json::json!({ "secret": secret, "otpauth_url": otpauth_url }))
                .into_response()
        }
        Err(e) => auth_err_to_response(&e),
    }
}

#[derive(Deserialize)]
struct TotpVerifyBody {
    code: String,
}

async fn mfa_totp_verify(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
    Json(body): Json<TotpVerifyBody>,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .confirm_totp_setup(&tenant, &claims.user_id, &body.code)
        .await
    {
        Ok(recovery_codes) => {
            state
                .audit
                .record_full(AuditRecordInput {
                    tenant_id: tenant,
                    trace_id: crate::TelemetryHub::current_trace_id_hex(),
                    session_id: claims.session_id,
                    action: "mfa_totp_enabled".to_owned(),
                    protocol: "auth".to_owned(),
                    target_host: claims.email.clone(),
                    detail: "enrolled TOTP MFA and issued recovery codes".to_owned(),
                    user_id: claims.user_id,
                    user_email: claims.email,
                    role: claims.role,
                    ip: ctx.client_ip,
                    outcome: "success".to_owned(),
                    method: "POST".to_owned(),
                    status_code: 200,
                    ..AuditRecordInput::default()
                })
                .await;
            Json(serde_json::json!({
                "enabled": true,
                "recovery_codes": recovery_codes,
            }))
            .into_response()
        }
        Err(e) => auth_err_to_response(&e),
    }
}

#[derive(Deserialize)]
struct TotpDisableBody {
    #[serde(default)]
    current_password: String,
    code: String,
}

async fn mfa_totp_disable(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
    Json(body): Json<TotpDisableBody>,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .disable_totp(&tenant, &claims.user_id, &body.current_password, &body.code)
        .await
    {
        Ok(()) => {
            state
                .audit
                .record_full(AuditRecordInput {
                    tenant_id: tenant,
                    trace_id: crate::TelemetryHub::current_trace_id_hex(),
                    session_id: claims.session_id,
                    action: "mfa_totp_disabled".to_owned(),
                    protocol: "auth".to_owned(),
                    target_host: claims.email.clone(),
                    detail: "disabled TOTP MFA".to_owned(),
                    user_id: claims.user_id,
                    user_email: claims.email,
                    role: claims.role,
                    ip: ctx.client_ip,
                    outcome: "success".to_owned(),
                    method: "POST".to_owned(),
                    status_code: 200,
                    ..AuditRecordInput::default()
                })
                .await;
            Json(serde_json::json!({ "enabled": false })).into_response()
        }
        Err(e) => auth_err_to_response(&e),
    }
}

async fn webauthn_register_start(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let origin = external_origin(&headers, ctx.is_https);
    let rp_id = rp_id_from_origin(&origin);
    match state
        .auth
        .begin_webauthn_register(&tenant, &claims.user_id, &rp_id, &origin)
        .await
    {
        Ok(options) => Json(options).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

#[derive(Deserialize)]
struct WebAuthnRegisterFinishBody {
    credential_id: String,
    #[serde(default)]
    label: String,
    public_key_spki_b64: String,
    alg: i32,
    client_data_b64: String,
}

async fn webauthn_register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<WebAuthnRegisterFinishBody>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .finish_webauthn_register(
            &tenant,
            &claims.user_id,
            &body.credential_id,
            &body.label,
            &body.public_key_spki_b64,
            body.alg,
            &body.client_data_b64,
        )
        .await
    {
        Ok(()) => Json(serde_json::json!({ "registered": true })).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

#[derive(Deserialize)]
struct WebAuthnLoginStartBody {
    challenge_token: String,
}

async fn webauthn_login_start(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
    Json(body): Json<WebAuthnLoginStartBody>,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let origin = external_origin(&headers, ctx.is_https);
    let rp_id = rp_id_from_origin(&origin);
    match state
        .auth
        .begin_webauthn_login(&ctx.tenant_id, &body.challenge_token, &rp_id, &origin)
        .await
    {
        Ok(options) => Json(options).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

#[derive(Deserialize)]
struct WebAuthnLoginFinishBody {
    challenge_token: String,
    credential_id: String,
    client_data_b64: String,
    authenticator_data_b64: String,
    signature_b64: String,
}

async fn webauthn_login_finish(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
    Json(body): Json<WebAuthnLoginFinishBody>,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    match state
        .auth
        .finish_webauthn_login(
            &ctx.tenant_id,
            &body.challenge_token,
            &body.credential_id,
            &body.client_data_b64,
            &body.authenticator_data_b64,
            &body.signature_b64,
        )
        .await
    {
        Ok((claims, token)) => {
            finish_local_login_response(
                &state,
                &headers,
                &ctx,
                claims,
                &token,
                "login_webauthn",
                "WebAuthn passkey verification completed",
            )
            .await
        }
        Err(e) => auth_err_to_response(&e),
    }
}

async fn webauthn_delete_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .delete_webauthn_credential(&tenant, &claims.user_id, &id)
        .await
    {
        Ok(()) => Json(serde_json::json!({ "deleted": true })).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

async fn logout(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    if let Some(claims) = state.auth.verify_cookie(&headers).await {
        state.session_fence.terminate_auth_session(
            &claims.tenant_id,
            &claims.session_id,
            "signed_out",
        );
    }
    state.auth.revoke_session(&headers).await;
    let mut resp = Json(serde_json::json!({ "status": "signed_out" })).into_response();
    append_clear_session_cookies(&mut resp, ctx.is_https);
    resp
}

async fn logout_redirect(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    if let Some(claims) = state.auth.verify_cookie(&headers).await {
        state.session_fence.terminate_auth_session(
            &claims.tenant_id,
            &claims.session_id,
            "signed_out",
        );
    }
    state.auth.revoke_session(&headers).await;
    let mut resp = Redirect::temporary("/").into_response();
    append_clear_session_cookies(&mut resp, ctx.is_https);
    resp
}

#[derive(Deserialize)]
struct PasswordChangeBody {
    #[serde(default)]
    current_password: String,
    new_password: String,
}

async fn admin_password(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
    Json(body): Json<PasswordChangeBody>,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if claims.role != "admin" {
        return json_err(StatusCode::FORBIDDEN, "administrator sign-in required");
    }
    if let Err(e) = state
        .auth
        .change_password(
            &tenant,
            &claims.user_id,
            Some(&body.current_password),
            &body.new_password,
        )
        .await
    {
        return auth_err_to_response(&e);
    }
    state
        .auth
        .revoke_all_user_sessions(&tenant, &claims.user_id)
        .await;
    state
        .session_fence
        .terminate_user(&tenant, &claims.user_id, "password_changed");
    let mut resp = Json(serde_json::json!({ "status": "password changed" })).into_response();
    append_clear_session_cookies(&mut resp, ctx.is_https);
    resp
}

async fn own_password(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
    Json(body): Json<PasswordChangeBody>,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if let Err(e) = state
        .auth
        .change_password(
            &tenant,
            &claims.user_id,
            Some(&body.current_password),
            &body.new_password,
        )
        .await
    {
        return auth_err_to_response(&e);
    }
    state
        .auth
        .revoke_all_user_sessions(&tenant, &claims.user_id)
        .await;
    state
        .session_fence
        .terminate_user(&tenant, &claims.user_id, "password_changed");
    let mut resp = Json(serde_json::json!({ "status": "password changed" })).into_response();
    append_clear_session_cookies(&mut resp, ctx.is_https);
    resp
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if state.auth.require_auth().await {
        match state.auth.verify_cookie(&headers).await {
            Some(c) => Json(state.auth.me_payload(&c).await).into_response(),
            None => json_err(StatusCode::UNAUTHORIZED, "not signed in"),
        }
    } else {
        match require_actor(&state, &headers).await {
            Ok((_, c)) => Json(state.auth.me_payload(&c).await).into_response(),
            Err(r) => *r,
        }
    }
}

async fn list_providers(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::SSO_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let providers = state.auth.list_sso_providers(&tenant).await;
    let saml_base_url = external_origin(&headers, ctx.is_https);
    let local = std::env::var("LOCAL_LOGIN").unwrap_or_else(|_| "admin".to_owned());
    Json(serde_json::json!({
        "providers": providers,
        "local": local,
        "can_manage": true,
        "saml_base_url": saml_base_url,
    }))
    .into_response()
}

async fn add_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut cfg): Json<SsoProviderConfig>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::SSO_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    cfg.tenant_id = tenant;
    let pub_view = state.auth.upsert_sso_provider(cfg).await;
    (StatusCode::CREATED, Json(pub_view)).into_response()
}

async fn update_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(patch): Json<SsoProviderPatch>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::SSO_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .update_sso_provider_patch(&tenant, &id, patch)
        .await
    {
        Ok(v) => Json(v).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

async fn delete_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::SSO_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    state.auth.delete_sso_provider(&tenant, &id).await;
    Json(serde_json::json!({ "status": "deleted" })).into_response()
}

async fn sso_start_id(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    sso_start_inner(state, ext, headers, Some(id)).await
}

async fn sso_start_default(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
) -> Response {
    sso_start_inner(state, ext, headers, None).await
}

async fn sso_start_inner(
    state: AppState,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
    id: Option<String>,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let tenant = ctx.tenant_id;
    let provider_id = if let Some(i) = id {
        i
    } else {
        let list = state.auth.list_sso_providers(&tenant).await;
        let Some(first) = list.first() else {
            return json_err(StatusCode::NOT_FOUND, "no SSO provider configured");
        };
        first.id.clone()
    };
    let origin = external_origin(&headers, ctx.is_https);
    match state
        .auth
        .start_sso_login(&tenant, &provider_id, &origin)
        .await
    {
        Ok(url) => Redirect::temporary(&url).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

#[derive(Deserialize)]
struct OidcCallbackQuery {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
}

async fn oidc_callback_id(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
    Path(_id): Path<String>,
    Query(q): Query<OidcCallbackQuery>,
) -> Response {
    oidc_callback_inner(state, ext, headers, q).await
}

async fn oidc_callback_default(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
    Query(q): Query<OidcCallbackQuery>,
) -> Response {
    oidc_callback_inner(state, ext, headers, q).await
}

async fn oidc_callback_inner(
    state: AppState,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
    q: OidcCallbackQuery,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    match state
        .auth
        .finish_oidc_callback(&ctx.tenant_id, &q.code, &q.state)
        .await
    {
        Ok((_claims, token)) => {
            let mut resp = Redirect::temporary("/").into_response();
            if let Ok(hv) =
                HeaderValue::from_str(&session_cookie_header(&token, 28_800, ctx.is_https))
            {
                resp.headers_mut().insert(header::SET_COOKIE, hv);
            }
            resp
        }
        Err(e) => auth_err_to_response(&e),
    }
}

async fn saml_metadata(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let origin = external_origin(&headers, ctx.is_https);
    match state.auth.saml_metadata(&ctx.tenant_id, &id, &origin).await {
        Ok(xml) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
            xml,
        )
            .into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

#[derive(Deserialize)]
struct SamlAcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
}

async fn saml_acs(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<SamlAcsForm>,
) -> Response {
    let ctx = req_ctx(&state, &headers, ext.as_ref());
    let expected_acs_url = format!(
        "{}/api/auth/saml/{id}/acs",
        external_origin(&headers, ctx.is_https)
    );
    match state
        .auth
        .finish_saml_acs(&ctx.tenant_id, &id, &form.saml_response, &expected_acs_url)
        .await
    {
        Ok((_claims, token)) => {
            let mut resp = Redirect::temporary("/").into_response();
            if let Ok(hv) =
                HeaderValue::from_str(&session_cookie_header(&token, 28_800, ctx.is_https))
            {
                resp.headers_mut().insert(header::SET_COOKIE, hv);
            }
            resp
        }
        Err(e) => auth_err_to_response(&e),
    }
}

async fn saml_slo(
    State(state): State<AppState>,
    ext: Option<Extension<ResolvedRequestContext>>,
    headers: HeaderMap,
) -> Response {
    logout_redirect(State(state), ext, headers).await
}

async fn list_users(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::USERS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.auth.list_users_with_groups(&tenant).await).into_response()
}

#[derive(Deserialize)]
struct CreateUserBody {
    email: String,
    #[serde(default)]
    name: String,
    #[serde(default = "default_viewer_role")]
    role: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    local_signin_enabled: Option<bool>,
}

fn default_viewer_role() -> String {
    "viewer".to_owned()
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateUserBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::USERS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .create_user(&tenant, &body.email, &body.name, &body.role, &body.password)
        .await
    {
        Ok(mut u) => {
            if let Some(enabled) = body.local_signin_enabled {
                if let Ok(updated) = state
                    .auth
                    .set_user_local_signin(&tenant, &u.id, enabled)
                    .await
                {
                    u = updated;
                }
            }
            let mut val = serde_json::to_value(&u).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(obj) = val.as_object_mut() {
                obj.insert(
                    "user".to_owned(),
                    serde_json::to_value(&u).unwrap_or_else(|_| serde_json::json!({})),
                );
                obj.insert("groups".to_owned(), serde_json::json!([]));
            }
            (StatusCode::CREATED, Json(val)).into_response()
        }
        Err(e) => auth_err_to_response(&e),
    }
}

#[derive(Deserialize)]
struct EditUserBody {
    name: Option<String>,
    email: Option<String>,
}

async fn edit_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<EditUserBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::USERS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .edit_user(&tenant, &id, body.name.as_deref(), body.email.as_deref())
        .await
    {
        Ok(u) => Json(u).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::USERS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state.auth.delete_user(&claims.user_id, &tenant, &id).await {
        Ok(()) => {
            state.auth.revoke_all_user_sessions(&tenant, &id).await;
            state
                .session_fence
                .terminate_user(&tenant, &id, "user_deleted");
            Json(serde_json::json!({ "status": "deleted" })).into_response()
        }
        Err(e) => auth_err_to_response(&e),
    }
}

#[derive(Deserialize)]
struct UpdateRoleBody {
    role: String,
}

async fn update_user_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateRoleBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::USERS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .update_user_role(&claims.user_id, &tenant, &id, &body.role)
        .await
    {
        Ok(u) => {
            state.auth.revoke_all_user_sessions(&tenant, &id).await;
            state
                .session_fence
                .terminate_user(&tenant, &id, "role_changed");
            Json(u).into_response()
        }
        Err(e) => auth_err_to_response(&e),
    }
}

#[derive(Deserialize)]
struct SetGroupsBody {
    group_ids: Vec<String>,
}

async fn set_user_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<SetGroupsBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(
        &state,
        &headers,
        &[perm::USERS_MANAGE, perm::GROUPS_MANAGE],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .set_user_groups(&claims.user_id, &tenant, &id, &body.group_ids)
        .await
    {
        Ok(()) => Json(serde_json::json!({ "status": "updated" })).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

#[derive(Deserialize)]
struct UserStatusBody {
    disabled: bool,
}

async fn update_user_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UserStatusBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::USERS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .update_user_status(&claims.user_id, &tenant, &id, body.disabled)
        .await
    {
        Ok(u) => {
            if body.disabled {
                state.auth.revoke_all_user_sessions(&tenant, &id).await;
                state
                    .session_fence
                    .terminate_user(&tenant, &id, "account_disabled");
            }
            Json(u).into_response()
        }
        Err(e) => auth_err_to_response(&e),
    }
}

#[derive(Deserialize)]
struct ResetPasswordBody {
    #[serde(alias = "new_password")]
    password: String,
}

async fn reset_user_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ResetPasswordBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::USERS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .change_password(&tenant, &id, None, &body.password)
        .await
    {
        Ok(()) => {
            state.auth.revoke_all_user_sessions(&tenant, &id).await;
            state
                .session_fence
                .terminate_user(&tenant, &id, "password_reset");
            Json(serde_json::json!({ "status": "reset" })).into_response()
        }
        Err(e) => auth_err_to_response(&e),
    }
}

async fn list_permissions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_actor(&state, &headers).await {
        return *r;
    }
    Json(serde_json::json!({
        "permissions": PERMISSION_CATALOG,
        "scope_types": ["global", "env", "aws_account", "k8s_cluster"],
    }))
    .into_response()
}

async fn list_roles(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.auth.list_roles(&tenant).await).into_response()
}

#[derive(Deserialize)]
struct RoleBody {
    name: String,
    #[serde(default)]
    description: String,
    permissions: Vec<String>,
}

async fn create_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RoleBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::ROLES_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .create_role(&tenant, &body.name, &body.description, body.permissions)
        .await
    {
        Ok(r) => (StatusCode::CREATED, Json(r)).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

async fn update_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<RoleBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::ROLES_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .update_role(
            &tenant,
            &id,
            &body.name,
            &body.description,
            body.permissions,
        )
        .await
    {
        Ok(r) => Json(r).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

async fn delete_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::ROLES_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state.auth.delete_role(&tenant, &id).await {
        Ok(()) => Json(serde_json::json!({ "status": "deleted" })).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

async fn list_groups(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.auth.list_groups_detailed(&tenant).await).into_response()
}

#[derive(Deserialize)]
struct GroupBody {
    name: String,
    #[serde(default)]
    description: String,
}

async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GroupBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::GROUPS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .create_group(&tenant, &body.name, &body.description)
        .await
    {
        Ok(g) => (StatusCode::CREATED, Json(g)).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

async fn update_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<GroupBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::GROUPS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .update_group(&tenant, &id, &body.name, &body.description)
        .await
    {
        Ok(g) => Json(g).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

async fn delete_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::GROUPS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state.auth.delete_group(&tenant, &id).await {
        Ok(()) => Json(serde_json::json!({ "status": "deleted" })).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

#[derive(Deserialize)]
struct AddMemberBody {
    user_id: String,
}

async fn add_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<AddMemberBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::GROUPS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .add_group_member(&tenant, &id, &body.user_id)
        .await
    {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "status": "added" })),
        )
            .into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

async fn remove_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, user_id)): Path<(String, String)>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::GROUPS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    state.auth.remove_group_member(&tenant, &id, &user_id).await;
    state
        .session_fence
        .terminate_user(&tenant, &user_id, "group_membership_removed");
    Json(serde_json::json!({ "status": "removed" })).into_response()
}

#[derive(Deserialize)]
struct BindRoleBody {
    role_id: String,
    #[serde(default)]
    scope_type: ScopeType,
    #[serde(default)]
    scope_id: String,
    #[serde(default)]
    effect: Effect,
    #[serde(default)]
    conditions: BindingConditions,
}

async fn bind_group_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<BindRoleBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(
        &state,
        &headers,
        &[perm::GROUPS_MANAGE, perm::ROLES_MANAGE],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .auth
        .bind_group_role(
            &tenant,
            &id,
            &body.role_id,
            body.scope_type,
            &body.scope_id,
            body.effect,
            body.conditions,
        )
        .await
    {
        Ok(b) => (StatusCode::CREATED, Json(b)).into_response(),
        Err(e) => auth_err_to_response(&e),
    }
}

async fn unbind_group_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((_id, binding_id)): Path<(String, String)>,
) -> Response {
    let (tenant, _) = match require_any_perm(
        &state,
        &headers,
        &[perm::GROUPS_MANAGE, perm::ROLES_MANAGE],
    )
    .await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    state.auth.unbind_group_role(&tenant, &binding_id).await;
    Json(serde_json::json!({ "status": "unbound" })).into_response()
}

async fn list_idp_mappings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) =
        match require_any_perm(&state, &headers, &[perm::GROUPS_MANAGE, perm::SSO_MANAGE]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    Json(state.auth.list_idp_mappings(&tenant).await).into_response()
}

#[derive(Deserialize)]
struct CreateIdpMappingBody {
    provider_id: String,
    external_group: String,
    group_id: String,
}

async fn create_idp_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateIdpMappingBody>,
) -> Response {
    let (tenant, _) =
        match require_any_perm(&state, &headers, &[perm::GROUPS_MANAGE, perm::SSO_MANAGE]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let mapping = state
        .auth
        .create_idp_mapping(
            &tenant,
            &body.provider_id,
            &body.external_group,
            &body.group_id,
        )
        .await;
    (StatusCode::CREATED, Json(mapping)).into_response()
}

async fn delete_idp_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, _) =
        match require_any_perm(&state, &headers, &[perm::GROUPS_MANAGE, perm::SSO_MANAGE]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    state.auth.delete_idp_mapping(&tenant, &id).await;
    Json(serde_json::json!({ "status": "deleted" })).into_response()
}

async fn list_scim_tokens(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) =
        match require_any_perm(&state, &headers, &[perm::GROUPS_MANAGE, perm::SSO_MANAGE]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    Json(state.auth.scim_list_tokens(&tenant).await).into_response()
}

#[derive(Deserialize)]
struct CreateScimTokenBody {
    name: String,
}

async fn create_scim_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateScimTokenBody>,
) -> Response {
    let (tenant, claims) =
        match require_any_perm(&state, &headers, &[perm::GROUPS_MANAGE, perm::SSO_MANAGE]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let created = state
        .auth
        .create_scim_token(&tenant, &claims.user_id, &body.name)
        .await;
    (StatusCode::CREATED, Json(created)).into_response()
}

async fn revoke_scim_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, _) =
        match require_any_perm(&state, &headers, &[perm::GROUPS_MANAGE, perm::SSO_MANAGE]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    state.auth.scim_revoke_token(&tenant, &id).await;
    Json(serde_json::json!({ "status": "revoked" })).into_response()
}

fn scim_response(status: StatusCode, body: impl serde::Serialize) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, SCIM_CONTENT_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Json(body),
    )
        .into_response()
}

fn scim_error(status: StatusCode, detail: &str) -> Response {
    scim_response(
        status,
        serde_json::json!({
            "schemas": [SCIM_SCHEMA_ERROR],
            "status": status.as_u16().to_string(),
            "detail": detail,
        }),
    )
}

async fn require_scim(state: &AppState, headers: &HeaderMap) -> Result<String, Box<Response>> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    state
        .auth
        .authenticate_scim_bearer(auth_header)
        .await
        .map_err(|_| {
            Box::new(scim_error(
                StatusCode::UNAUTHORIZED,
                "valid SCIM bearer token required",
            ))
        })
}

async fn scim_service_provider_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_scim(&state, &headers).await {
        return *r;
    }
    scim_response(
        StatusCode::OK,
        serde_json::json!({
            "schemas": [SCIM_SCHEMA_SPC],
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": 200 },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Bearer SCIM provisioning token",
                "primary": true
            }]
        }),
    )
}

async fn scim_resource_types(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_scim(&state, &headers).await {
        return *r;
    }
    scim_response(
        StatusCode::OK,
        serde_json::json!([
            { "schemas": [SCIM_SCHEMA_RES_TYPE], "id": "User", "name": "User", "endpoint": "/scim/v2/Users", "schema": SCIM_SCHEMA_USER },
            { "schemas": [SCIM_SCHEMA_RES_TYPE], "id": "Group", "name": "Group", "endpoint": "/scim/v2/Groups", "schema": SCIM_SCHEMA_GROUP }
        ]),
    )
}

async fn scim_schemas(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_scim(&state, &headers).await {
        return *r;
    }
    scim_response(
        StatusCode::OK,
        serde_json::json!([
            { "schemas": [SCIM_SCHEMA_META], "id": SCIM_SCHEMA_USER, "name": "User" },
            { "schemas": [SCIM_SCHEMA_META], "id": SCIM_SCHEMA_GROUP, "name": "Group" }
        ]),
    )
}

async fn scim_list_users(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let tenant = match require_scim(&state, &headers).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    scim_response(StatusCode::OK, state.auth.scim_list_users(&tenant).await)
}

async fn scim_create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ScimUserResource>,
) -> Response {
    let tenant = match require_scim(&state, &headers).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    match state.auth.scim_create_user(&tenant, body).await {
        Ok(u) => scim_response(StatusCode::CREATED, u),
        Err(e) => scim_error(StatusCode::CONFLICT, &e.to_string()),
    }
}

async fn scim_get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let tenant = match require_scim(&state, &headers).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    match state.auth.scim_get_user(&tenant, &id).await {
        Ok(u) => scim_response(StatusCode::OK, u),
        Err(e) => scim_error(StatusCode::NOT_FOUND, &e.to_string()),
    }
}

async fn scim_replace_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ScimUserResource>,
) -> Response {
    let tenant = match require_scim(&state, &headers).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    match state.auth.scim_replace_user(&tenant, &id, &body).await {
        Ok(u) => {
            if !u.active {
                state
                    .session_fence
                    .terminate_user(&tenant, &id, "scim_deprovisioned");
            }
            scim_response(StatusCode::OK, u)
        }
        Err(e) => scim_error(StatusCode::NOT_FOUND, &e.to_string()),
    }
}

async fn scim_patch_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ScimPatchRequest>,
) -> Response {
    let tenant = match require_scim(&state, &headers).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    match state.auth.scim_patch_user(&tenant, &id, &body).await {
        Ok(u) => {
            if !u.active {
                state
                    .session_fence
                    .terminate_user(&tenant, &id, "scim_deprovisioned");
            }
            scim_response(StatusCode::OK, u)
        }
        Err(e) => scim_error(StatusCode::NOT_FOUND, &e.to_string()),
    }
}

async fn scim_delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let tenant = match require_scim(&state, &headers).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    match state.auth.scim_delete_user(&tenant, &id).await {
        Ok(()) => {
            state
                .session_fence
                .terminate_user(&tenant, &id, "scim_deleted");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => scim_error(StatusCode::NOT_FOUND, &e.to_string()),
    }
}

async fn scim_list_groups(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let tenant = match require_scim(&state, &headers).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    scim_response(StatusCode::OK, state.auth.scim_list_groups(&tenant).await)
}

async fn scim_create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ScimGroupResource>,
) -> Response {
    let tenant = match require_scim(&state, &headers).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    match state.auth.scim_create_group(&tenant, body).await {
        Ok(g) => scim_response(StatusCode::CREATED, g),
        Err(e) => scim_error(StatusCode::CONFLICT, &e.to_string()),
    }
}

async fn scim_get_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let tenant = match require_scim(&state, &headers).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    match state.auth.scim_get_group(&tenant, &id).await {
        Ok(g) => scim_response(StatusCode::OK, g),
        Err(e) => scim_error(StatusCode::NOT_FOUND, &e.to_string()),
    }
}

async fn scim_replace_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ScimGroupResource>,
) -> Response {
    let tenant = match require_scim(&state, &headers).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    match state.auth.scim_replace_group(&tenant, &id, &body).await {
        Ok(g) => scim_response(StatusCode::OK, g),
        Err(e) => scim_error(StatusCode::NOT_FOUND, &e.to_string()),
    }
}

async fn scim_patch_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ScimPatchRequest>,
) -> Response {
    let tenant = match require_scim(&state, &headers).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    match state.auth.scim_patch_group(&tenant, &id, &body).await {
        Ok(g) => scim_response(StatusCode::OK, g),
        Err(e) => scim_error(StatusCode::NOT_FOUND, &e.to_string()),
    }
}

async fn scim_delete_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let tenant = match require_scim(&state, &headers).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    match state.auth.scim_delete_group(&tenant, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => scim_error(StatusCode::NOT_FOUND, &e.to_string()),
    }
}
