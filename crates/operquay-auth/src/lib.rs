#![forbid(unsafe_code)]

//! Clean-room multi-tenant IAM, RBAC, OIDC PKCE, SAML 2.0 XML SP, Groups,
//! `IdP` Mappings, HTTP-only HMAC sessions, and SCIM v2 provisioning (`crates/operquay-auth`).

pub mod crypto;
pub mod mfa;
pub mod pg;
pub mod policy;
pub mod scim;
pub mod sso;
pub mod xmldsig;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crypto::{
    extract_cookie, random_token_b64, sha256_hex, sign_session_token, verify_session_token,
};
use policy::{
    base_role_permissions, is_valid_permission, normalize_role, perm, BindingConditions, Effect,
    ScopeType,
};
use scim::{
    CreatedScimToken, ScimGroupResource, ScimMemberRef, ScimPatchRequest, ScimToken,
    ScimUserResource, SCIM_SCHEMA_LIST,
};
use serde::{Deserialize, Serialize};
use sso::{
    build_oidc_authorize_url, claims_from_oidc_json, discover_oidc, exchange_oidc_code,
    fetch_oidc_jwks, format_iso8601_utc, render_saml_sp_metadata,
    verify_and_parse_saml_response_b64, verify_oidc_id_token, JwkSet, OidcPendingState,
    OidcValidationParams, SamlPendingTracker, SamlValidationParams, SsoIdentityClaims,
    SsoProviderConfig, SsoProviderPatch, SsoProviderPublic,
};
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

pub const SESSION_COOKIE_NAME: &str = "operquay_session";
pub const HOST_SESSION_COOKIE_NAME: &str = "__Host-operquay_session";
pub const DEFAULT_BCRYPT_COST: u32 = 12;
const DUMMY_BCRYPT_HASH: &str = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW";

#[must_use]
pub fn compliance_mode_enabled() -> bool {
    std::env::var("OPERQUAY_COMPLIANCE_MODE")
        .or_else(|_| std::env::var("COMPLIANCE_MODE"))
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("account disabled")]
    AccountDisabled,
    #[error("too many failed login attempts; retry in {retry_after_secs}s")]
    AccountLocked { retry_after_secs: u64 },
    #[error("multi-factor verification required")]
    MfaRequired {
        challenge: String,
        methods: Vec<String>,
    },
    #[error("invalid MFA verification code")]
    InvalidMfaCode,
    #[error("password rotation required before continuing")]
    PasswordChangeRequired,
    #[error("{0}")]
    WeakPassword(String),
    #[error("cannot remove the last active administrator")]
    LastAdmin,
    #[error("cannot alter your own administrative group or role")]
    SelfEscalation,
    #[error("user not found")]
    UserNotFound,
    #[error("user already exists")]
    UserExists,
    #[error("group not found")]
    GroupNotFound,
    #[error("group already exists")]
    GroupExists,
    #[error("role not found")]
    RoleNotFound,
    #[error("role already exists")]
    RoleExists,
    #[error("system role cannot be modified")]
    SystemRole,
    #[error("invalid permission '{0}'")]
    InvalidPermission(String),
    #[error("provider not found")]
    ProviderNotFound,
    #[error("SSO error: {0}")]
    Sso(String),
    #[error("SCIM unauthorized")]
    ScimUnauthorized,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub provider: String,
    #[serde(default)]
    pub subject: String,
    pub disabled: bool,
    #[serde(skip_serializing)]
    pub password_hash: String,
    #[serde(default)]
    pub local_signin_enabled: bool,
    #[serde(default)]
    pub must_change_password: bool,
    #[serde(default, skip_serializing)]
    pub password_history: Vec<String>,
    #[serde(default)]
    pub mfa_enabled: bool,
    #[serde(default, skip_serializing)]
    pub mfa_totp_secret: String,
    #[serde(default, skip_serializing)]
    pub mfa_pending_totp_secret: String,
    #[serde(default, skip_serializing)]
    pub mfa_recovery_hashes: Vec<String>,
    #[serde(default, skip_serializing)]
    pub mfa_last_totp_step: i64,
    #[serde(default, skip_serializing)]
    pub webauthn_credentials: Vec<mfa::WebAuthnCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicUser {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub provider: String,
    pub disabled: bool,
    pub local_signin_enabled: bool,
    pub must_change_password: bool,
    pub mfa_enabled: bool,
}

impl User {
    #[must_use]
    pub fn to_public(&self) -> PublicUser {
        PublicUser {
            id: self.id.clone(),
            tenant_id: self.tenant_id.clone(),
            email: self.email.clone(),
            name: self.name.clone(),
            role: self.role.clone(),
            provider: self.provider.clone(),
            disabled: self.disabled,
            local_signin_enabled: self.local_signin_enabled,
            must_change_password: self.must_change_password,
            mfa_enabled: self.mfa_enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: String,
    pub source: String,
    #[serde(default)]
    pub external_id: String,
    pub is_system: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDef {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: String,
    pub base_role: String,
    pub is_system: bool,
    pub permissions: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembership {
    pub tenant_id: String,
    pub group_id: String,
    pub user_id: String,
    pub source: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRoleBinding {
    pub id: String,
    pub tenant_id: String,
    pub group_id: String,
    pub role_id: String,
    pub scope_type: ScopeType,
    #[serde(default)]
    pub scope_id: String,
    #[serde(default)]
    pub effect: Effect,
    #[serde(default)]
    pub conditions: BindingConditions,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdPGroupMapping {
    pub id: String,
    pub tenant_id: String,
    pub provider_id: String,
    pub external_group: String,
    pub group_id: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    pub session_id: String,
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub tenant_id: String,
    pub method: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub last_active_at: i64,
    pub groups: Vec<String>,
    pub permissions: Vec<String>,
}

struct ScimTokenRecord {
    meta: ScimToken,
    token_hash: String,
}

#[derive(Debug, Default, Clone)]
struct FailureBucket {
    count: u32,
    locked_until: i64,
    last_attempt: i64,
}

#[derive(Debug, Clone)]
struct MfaChallengeRecord {
    user_id: String,
    tenant_id: String,
    expires_at: i64,
    failures: u32,
}

#[derive(Debug, Clone)]
struct WebAuthnChallengeRecord {
    user_id: String,
    tenant_id: String,
    challenge: String,
    rp_id: String,
    origin: String,
    expires_at: i64,
}

#[derive(Default)]
struct LoginRateLimiter {
    acct_failures: HashMap<(String, String), FailureBucket>,
    ip_failures: HashMap<String, Vec<i64>>,
}

impl LoginRateLimiter {
    fn check_locked(&mut self, tenant_id: &str, email: &str, ip: &str, now: i64) -> Option<u64> {
        let acct_key = (tenant_id.to_owned(), email.to_ascii_lowercase());
        if let Some(bucket) = self.acct_failures.get(&acct_key) {
            if now < bucket.locked_until {
                return Some(u64::try_from(bucket.locked_until - now).unwrap_or(60));
            }
        }
        if let Some(ts_list) = self.ip_failures.get_mut(ip) {
            ts_list.retain(|&t| now - t < 900);
            if ts_list.len() >= 20 {
                let oldest = ts_list.first().copied().unwrap_or(now);
                return Some(u64::try_from((oldest + 900 - now).max(1)).unwrap_or(300));
            }
        }
        None
    }

    fn record_failure(&mut self, tenant_id: &str, email: &str, ip: &str, now: i64) -> Option<u64> {
        let ip_list = self.ip_failures.entry(ip.to_owned()).or_default();
        ip_list.retain(|&t| now - t < 900);
        ip_list.push(now);

        let acct_key = (tenant_id.to_owned(), email.to_ascii_lowercase());
        let bucket = self.acct_failures.entry(acct_key).or_default();
        if now - bucket.last_attempt > 900 && now >= bucket.locked_until {
            bucket.count = 0;
        }
        bucket.last_attempt = now;
        bucket.count = bucket.count.saturating_add(1);
        if bucket.count >= 5 {
            let lock_secs = if bucket.count == 5 {
                60
            } else if bucket.count <= 7 {
                300
            } else {
                900
            };
            bucket.locked_until = now + lock_secs;
            return Some(lock_secs as u64);
        }
        if ip_list.len() >= 20 {
            return Some(300);
        }
        None
    }

    fn clear_account(&mut self, tenant_id: &str, email: &str) {
        self.acct_failures
            .remove(&(tenant_id.to_owned(), email.to_ascii_lowercase()));
    }
}

#[derive(Default)]
struct AuthState {
    users: HashMap<String, User>,
    groups: HashMap<String, Group>,
    roles: HashMap<String, RoleDef>,
    memberships: Vec<GroupMembership>,
    bindings: Vec<GroupRoleBinding>,
    idp_mappings: Vec<IdPGroupMapping>,
    sessions: HashMap<String, SessionClaims>,
    providers: HashMap<String, SsoProviderConfig>,
    oidc_pending: HashMap<String, OidcPendingState>,
    jwks_cache: HashMap<String, (Instant, JwkSet)>,
    saml_trackers: HashMap<String, SamlPendingTracker>,
    scim_tokens: HashMap<String, ScimTokenRecord>,
    rate_limiter: LoginRateLimiter,
    mfa_challenges: HashMap<String, MfaChallengeRecord>,
    webauthn_challenges: HashMap<String, WebAuthnChallengeRecord>,
    require_auth: bool,
    initial_admin_password: Option<String>,
    master_secret: Vec<u8>,
}

/// Complete multi-tenant IAM, RBAC, SSO, MFA & SCIM v2 service preserving all Go `operquay` contracts.
pub struct AuthService {
    inner: RwLock<AuthState>,
    pg: RwLock<Option<pg::PgAuthPool>>,
    bcrypt_cost: u32,
}

impl Default for AuthService {
    fn default() -> Self {
        Self::new(false, None)
    }
}

fn warn_pg_err(op: &str, res: Result<(), String>) {
    if let Err(err) = res {
        tracing::warn!(op, error = %err, "auth postgres persistence failed");
    }
}

pub fn validate_password_policy(password: &str) -> Result<(), AuthError> {
    if password.chars().count() < 12 {
        return Err(AuthError::WeakPassword(
            "Password must be at least 12 characters long.".into(),
        ));
    }
    let lower = password.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "password1234"
            | "password12345"
            | "123456789012"
            | "qwerty123456"
            | "admin1234567"
            | "operquay1234"
            | "letmein12345"
            | "welcome12345"
    ) {
        return Err(AuthError::WeakPassword(
            "Password is too common; choose a stronger unique passphrase.".into(),
        ));
    }
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());
    let classes =
        u8::from(has_upper) + u8::from(has_lower) + u8::from(has_digit) + u8::from(has_symbol);
    if classes < 3 {
        return Err(AuthError::WeakPassword(
            "Password must include at least 3 of: uppercase, lowercase, number, and symbol.".into(),
        ));
    }
    Ok(())
}

impl AuthService {
    async fn pg_pool(&self) -> Option<pg::PgAuthPool> {
        self.pg.read().await.clone()
    }

    #[must_use]
    pub fn session_hours(&self) -> i64 {
        std::env::var("OPERQUAY_SESSION_HOURS")
            .ok()
            .and_then(|v| v.trim().parse::<i64>().ok())
            .unwrap_or(8)
            .clamp(1, 24)
    }

    #[must_use]
    pub fn idle_minutes(&self) -> i64 {
        std::env::var("OPERQUAY_SESSION_IDLE_MINUTES")
            .ok()
            .and_then(|v| v.trim().parse::<i64>().ok())
            .unwrap_or(30)
            .clamp(5, 480)
    }

    #[must_use]
    pub fn new(require_auth: bool, initial_admin_password: Option<String>) -> Self {
        Self::with_bcrypt_cost(require_auth, initial_admin_password, DEFAULT_BCRYPT_COST)
    }

    #[must_use]
    pub fn with_bcrypt_cost(
        require_auth: bool,
        initial_admin_password: Option<String>,
        bcrypt_cost: u32,
    ) -> Self {
        let mut master = vec![0u8; 32];
        if crypto::fill_csprng(&mut master).is_err() {
            let u1 = Uuid::new_v4();
            let u2 = Uuid::new_v4();
            master[..16].copy_from_slice(u1.as_bytes());
            master[16..].copy_from_slice(u2.as_bytes());
        }
        let mut state = AuthState {
            require_auth,
            master_secret: master,
            ..Default::default()
        };

        let now = now_unix();
        seed_system_roles(&mut state.roles, "default", now);
        seed_system_groups(&mut state.groups, "default", now);

        let admin_pass = initial_admin_password
            .filter(|p| !p.is_empty())
            .unwrap_or_else(random_token_b64);
        let hash =
            bcrypt::hash(&admin_pass, bcrypt_cost).unwrap_or_else(|_| DUMMY_BCRYPT_HASH.to_owned());
        let force_rot = require_auth
            && (std::env::var("OPERQUAY_FORCE_ADMIN_PASSWORD_CHANGE")
                .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                || compliance_mode_enabled());
        state.initial_admin_password = Some(admin_pass);
        state.users.insert(
            "admin-default".to_owned(),
            User {
                id: "admin-default".to_owned(),
                tenant_id: "default".to_owned(),
                email: "admin@local".to_owned(),
                name: "Break-glass admin".to_owned(),
                role: "admin".to_owned(),
                provider: "local".to_owned(),
                subject: String::new(),
                disabled: false,
                password_hash: hash.clone(),
                local_signin_enabled: true,
                must_change_password: force_rot,
                password_history: vec![hash],
                mfa_enabled: false,
                mfa_totp_secret: String::new(),
                mfa_pending_totp_secret: String::new(),
                mfa_recovery_hashes: Vec::new(),
                mfa_last_totp_step: 0,
                webauthn_credentials: Vec::new(),
            },
        );

        Self {
            inner: RwLock::new(state),
            pg: RwLock::new(None),
            bcrypt_cost,
        }
    }

    /// Attach a live PostgreSQL RLS pool, hydrate any existing rows so state
    /// persists across server restarts, and seed missing bootstrap records.
    ///
    /// # Errors
    /// Returns an error if initial hydration or bootstrap SQL writes fail.
    pub async fn attach_pg(&self, pool: pg::PgAuthPool) -> Result<(), String> {
        let fallback_secret = self.inner.read().await.master_secret.clone();
        pool.ensure_tenant("default", "Default Tenant").await?;
        let snap = pool.load_snapshot(&fallback_secret).await?;

        let mut roles_to_seed = Vec::new();
        let mut groups_to_seed = Vec::new();
        let mut users_to_seed = Vec::new();
        let mut memberships_to_seed = Vec::new();

        let master_secret = {
            let mut guard = self.inner.write().await;
            guard.master_secret = snap.master_secret;

            let had_db_admin = snap.users.iter().any(|u| u.id == "admin-default");
            for role in snap.roles {
                guard.roles.insert(role.id.clone(), role);
            }
            for grp in snap.groups {
                guard.groups.insert(grp.id.clone(), grp);
            }
            for u in snap.users {
                guard.users.insert(u.id.clone(), u);
            }
            if had_db_admin {
                // Keep rotated/persisted DB hash authoritative rather than surfacing stale boot secret.
                guard.initial_admin_password = None;
            } else if let Some(admin) = guard.users.get("admin-default").cloned() {
                users_to_seed.push(admin);
            }

            if snap.memberships.is_empty() {
                memberships_to_seed.extend(guard.memberships.iter().cloned());
            } else {
                guard.memberships = snap.memberships;
            }
            if !snap.bindings.is_empty() {
                guard.bindings = snap.bindings;
            }
            if !snap.idp_mappings.is_empty() {
                guard.idp_mappings = snap.idp_mappings;
            }
            for (tok, hash) in snap.scim_tokens {
                guard.scim_tokens.insert(
                    tok.id.clone(),
                    ScimTokenRecord {
                        meta: tok,
                        token_hash: hash,
                    },
                );
            }
            for cfg in snap.sso_providers {
                guard.providers.insert(cfg.id.clone(), cfg);
            }
            for sess in snap.sessions {
                guard.sessions.insert(sess.session_id.clone(), sess);
            }
            if !had_db_admin {
                roles_to_seed.extend(guard.roles.values().cloned());
                groups_to_seed.extend(guard.groups.values().cloned());
            }
            guard.master_secret.clone()
        };

        for r in roles_to_seed {
            pool.upsert_role(&r).await?;
        }
        for g in groups_to_seed {
            pool.upsert_group(&g).await?;
        }
        for u in users_to_seed {
            pool.upsert_user(&u, &master_secret).await?;
        }
        for m in memberships_to_seed {
            pool.upsert_membership(&m).await?;
        }
        *self.pg.write().await = Some(pool);
        Ok(())
    }

    pub async fn initial_admin_password(&self) -> Option<String> {
        self.inner.read().await.initial_admin_password.clone()
    }

    pub async fn auth_config(&self, tenant_id: &str) -> serde_json::Value {
        let guard = self.inner.read().await;
        let providers: Vec<SsoProviderPublic> = guard
            .providers
            .values()
            .filter(|p| p.tenant_id == tenant_id)
            .map(SsoProviderConfig::to_public)
            .collect();
        let has_sso = !providers.is_empty();
        let aws_mode = std::env::var("OPERQUAY_AWS_ACCESS_MODE")
            .or_else(|_| std::env::var("AWS_ACCESS_MODE"))
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| {
                if guard.require_auth {
                    "user".into()
                } else {
                    let home = std::env::var("HOME").unwrap_or_default();
                    if !home.is_empty() && std::path::Path::new(&home).join(".aws").exists() {
                        "profiles".into()
                    } else {
                        "hub".into()
                    }
                }
            });
        let local_policy = std::env::var("OPERQUAY_LOCAL_LOGIN")
            .or_else(|_| std::env::var("LOCAL_LOGIN"))
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| v == "admin" || v == "all" || v == "off")
            .unwrap_or_else(|| {
                if has_sso {
                    "admin".into()
                } else {
                    "all".into()
                }
            });
        let session_hours = self.session_hours();
        let idle_minutes = self.idle_minutes();
        serde_json::json!({
            "tenant_id": tenant_id,
            "required": guard.require_auth,
            "local_enabled": local_policy != "off",
            "local": local_policy,
            "local_user_opt_in_allowed": false,
            "compliance_mode": compliance_mode_enabled(),
            "providers": providers,
            "sso": { "enabled": has_sso, "providers": providers },
            "aws_access_mode": aws_mode,
            "session_hours": session_hours,
            "idle_minutes": idle_minutes,
            "version": env!("CARGO_PKG_VERSION"),
        })
    }

    pub async fn set_require_auth(&self, required: bool) {
        self.inner.write().await.require_auth = required;
    }

    pub async fn set_admin_password(&self, password: &str) -> Result<(), AuthError> {
        let hash =
            bcrypt::hash(password, self.bcrypt_cost).map_err(|_| AuthError::InvalidCredentials)?;
        let (updated, master) = {
            let mut guard = self.inner.write().await;
            let master = guard.master_secret.clone();
            let u = if let Some(u) = guard.users.get_mut("admin-default") {
                hash.clone_into(&mut u.password_hash);
                if u.password_history.is_empty() {
                    u.password_history.push(hash);
                }
                u.local_signin_enabled = true;
                u.disabled = false;
                Some(u.clone())
            } else {
                None
            };
            (u, master)
        };
        if let (Some(u), Some(pg)) = (updated, self.pg_pool().await) {
            warn_pg_err("upsert_user", pg.upsert_user(&u, &master).await);
        }
        Ok(())
    }

    pub async fn require_auth(&self) -> bool {
        self.inner.read().await.require_auth
    }

    pub async fn authenticate_local(
        &self,
        tenant_id: &str,
        email: &str,
        password: &str,
    ) -> Result<(SessionClaims, String), AuthError> {
        self.authenticate_local_with_context(tenant_id, email, password, "127.0.0.1", None, None)
            .await
    }

    pub async fn authenticate_local_with_context(
        &self,
        tenant_id: &str,
        email: &str,
        password: &str,
        client_ip: &str,
        totp_code: Option<&str>,
        recovery_code: Option<&str>,
    ) -> Result<(SessionClaims, String), AuthError> {
        let norm_email = email.trim().to_ascii_lowercase();
        let now = now_unix();
        {
            let mut guard = self.inner.write().await;
            if let Some(secs) =
                guard
                    .rate_limiter
                    .check_locked(tenant_id, &norm_email, client_ip, now)
            {
                return Err(AuthError::AccountLocked {
                    retry_after_secs: secs,
                });
            }
        }
        let (found_id, found_hash, disabled) = {
            let guard = self.inner.read().await;
            if let Some(u) = guard
                .users
                .values()
                .find(|u| u.tenant_id == tenant_id && u.email.eq_ignore_ascii_case(&norm_email))
            {
                (Some(u.id.clone()), u.password_hash.clone(), u.disabled)
            } else {
                (None, DUMMY_BCRYPT_HASH.to_owned(), false)
            }
        };

        // Constant-time timing parity: ALWAYS invoke bcrypt::verify even on missing user!
        let verified = bcrypt::verify(password, &found_hash).unwrap_or(false);
        let Some(user_id) = found_id else {
            let mut guard = self.inner.write().await;
            if let Some(secs) =
                guard
                    .rate_limiter
                    .record_failure(tenant_id, &norm_email, client_ip, now)
            {
                return Err(AuthError::AccountLocked {
                    retry_after_secs: secs,
                });
            }
            return Err(AuthError::InvalidCredentials);
        };
        if disabled {
            return Err(AuthError::AccountDisabled);
        }
        if !verified {
            let mut guard = self.inner.write().await;
            if let Some(secs) =
                guard
                    .rate_limiter
                    .record_failure(tenant_id, &norm_email, client_ip, now)
            {
                return Err(AuthError::AccountLocked {
                    retry_after_secs: secs,
                });
            }
            return Err(AuthError::InvalidCredentials);
        }

        let session_ttl = self.session_hours() * 3600;
        let (claims, signed, updated_user, master) = {
            let mut guard = self.inner.write().await;
            guard.rate_limiter.clear_account(tenant_id, &norm_email);
            let master = guard.master_secret.clone();
            let user = guard
                .users
                .get_mut(&user_id)
                .ok_or(AuthError::UserNotFound)?;

            let mut used_mfa = false;
            let mut persisted_user: Option<User> = None;
            if user.mfa_enabled {
                if let Some(code) = totp_code.filter(|c| !c.trim().is_empty()) {
                    let step = mfa::verify_totp_code(
                        &user.mfa_totp_secret,
                        code,
                        now,
                        user.mfa_last_totp_step,
                    )
                    .map_err(|_| AuthError::InvalidMfaCode)?;
                    user.mfa_last_totp_step = step;
                    used_mfa = true;
                    persisted_user = Some(user.clone());
                } else if let Some(rc) = recovery_code.filter(|c| !c.trim().is_empty()) {
                    if !mfa::consume_recovery_code(&mut user.mfa_recovery_hashes, rc) {
                        return Err(AuthError::InvalidMfaCode);
                    }
                    used_mfa = true;
                    persisted_user = Some(user.clone());
                } else {
                    let mut methods = Vec::new();
                    if !user.mfa_totp_secret.is_empty() {
                        methods.push("totp".to_owned());
                    }
                    if !user.webauthn_credentials.is_empty() {
                        methods.push("webauthn".to_owned());
                    }
                    if !user.mfa_recovery_hashes.is_empty() {
                        methods.push("recovery".to_owned());
                    }
                    let challenge_user_id = user.id.clone();
                    let challenge_tenant_id = user.tenant_id.clone();
                    let challenge_id = random_token_b64();
                    let signed_chal = sign_session_token(&master, &challenge_id);
                    guard.mfa_challenges.retain(|_, v| v.expires_at > now);
                    guard.mfa_challenges.insert(
                        challenge_id,
                        MfaChallengeRecord {
                            user_id: challenge_user_id,
                            tenant_id: challenge_tenant_id,
                            expires_at: now + 300,
                            failures: 0,
                        },
                    );
                    return Err(AuthError::MfaRequired {
                        challenge: signed_chal,
                        methods,
                    });
                }
            }

            let user_snapshot = user.clone();
            let method = if used_mfa { "password+mfa" } else { "password" };
            let claims = create_session_claims(&mut guard, &user_snapshot, method, session_ttl);
            let signed = sign_session_token(&master, &claims.session_id);
            (claims, signed, persisted_user, master)
        };
        if let Some(pg) = self.pg_pool().await {
            if let Some(ref u) = updated_user {
                warn_pg_err("upsert_user", pg.upsert_user(u, &master).await);
            }
            warn_pg_err("upsert_session", pg.upsert_session(&claims).await);
        }
        Ok((claims, signed))
    }

    pub async fn complete_mfa_challenge(
        &self,
        tenant_id: &str,
        challenge_token: &str,
        totp_code: Option<&str>,
        recovery_code: Option<&str>,
    ) -> Result<(SessionClaims, String), AuthError> {
        let now = now_unix();
        let session_ttl = self.session_hours() * 3600;
        let (claims, signed, updated_user, master) = {
            let mut guard = self.inner.write().await;
            let master = guard.master_secret.clone();
            let cid =
                verify_session_token(&master, challenge_token).ok_or(AuthError::InvalidMfaCode)?;
            let Some(rec) = guard.mfa_challenges.get(&cid).cloned() else {
                return Err(AuthError::InvalidMfaCode);
            };
            if now > rec.expires_at || rec.tenant_id != tenant_id {
                guard.mfa_challenges.remove(&cid);
                return Err(AuthError::InvalidMfaCode);
            }
            if rec.failures >= 5 {
                guard.mfa_challenges.remove(&cid);
                return Err(AuthError::AccountLocked {
                    retry_after_secs: 60,
                });
            }

            let res = {
                let user = guard
                    .users
                    .get_mut(&rec.user_id)
                    .ok_or(AuthError::UserNotFound)?;
                if user.disabled {
                    return Err(AuthError::AccountDisabled);
                }
                if let Some(code) = totp_code.filter(|c| !c.trim().is_empty()) {
                    match mfa::verify_totp_code(
                        &user.mfa_totp_secret,
                        code,
                        now,
                        user.mfa_last_totp_step,
                    ) {
                        Ok(step) => {
                            user.mfa_last_totp_step = step;
                            Ok(user.clone())
                        }
                        Err(_) => Err(AuthError::InvalidMfaCode),
                    }
                } else if let Some(rc) = recovery_code.filter(|c| !c.trim().is_empty()) {
                    if mfa::consume_recovery_code(&mut user.mfa_recovery_hashes, rc) {
                        Ok(user.clone())
                    } else {
                        Err(AuthError::InvalidMfaCode)
                    }
                } else {
                    Err(AuthError::InvalidMfaCode)
                }
            };

            let updated_user = match res {
                Ok(u) => {
                    guard.mfa_challenges.remove(&cid);
                    u
                }
                Err(err) => {
                    if let Some(entry) = guard.mfa_challenges.get_mut(&cid) {
                        entry.failures += 1;
                    }
                    return Err(err);
                }
            };

            let claims =
                create_session_claims(&mut guard, &updated_user, "password+mfa", session_ttl);
            let signed = sign_session_token(&master, &claims.session_id);
            (claims, signed, updated_user, master)
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_user", pg.upsert_user(&updated_user, &master).await);
            warn_pg_err("upsert_session", pg.upsert_session(&claims).await);
        }
        Ok((claims, signed))
    }

    pub async fn mfa_status(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<serde_json::Value, AuthError> {
        let guard = self.inner.read().await;
        let user = guard
            .users
            .get(user_id)
            .filter(|u| u.tenant_id == tenant_id)
            .ok_or(AuthError::UserNotFound)?;
        let passkeys: Vec<serde_json::Value> = user
            .webauthn_credentials
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.id,
                    "label": c.label,
                    "alg": c.alg,
                    "created_at": c.created_at,
                })
            })
            .collect();
        Ok(serde_json::json!({
            "mfa_enabled": user.mfa_enabled,
            "totp_enabled": !user.mfa_totp_secret.is_empty(),
            "recovery_codes_remaining": user.mfa_recovery_hashes.len(),
            "passkeys": passkeys,
        }))
    }

    pub async fn begin_totp_setup(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<(String, String), AuthError> {
        let secret = mfa::generate_totp_secret().map_err(AuthError::Sso)?;
        let mut guard = self.inner.write().await;
        let user = guard
            .users
            .get_mut(user_id)
            .filter(|u| u.tenant_id == tenant_id)
            .ok_or(AuthError::UserNotFound)?;
        let uri = mfa::totp_otpauth_uri("Operquay", &user.email, &secret);
        user.mfa_pending_totp_secret.clone_from(&secret);
        Ok((secret, uri))
    }

    pub async fn confirm_totp_setup(
        &self,
        tenant_id: &str,
        user_id: &str,
        code: &str,
    ) -> Result<Vec<String>, AuthError> {
        let now = now_unix();
        let recovery_codes = mfa::generate_recovery_codes(8).map_err(AuthError::Sso)?;
        let recovery_hashes: Vec<String> = recovery_codes
            .iter()
            .map(|c| mfa::hash_recovery_code(c))
            .collect();
        let (updated, master) = {
            let mut guard = self.inner.write().await;
            let master = guard.master_secret.clone();
            let user = guard
                .users
                .get_mut(user_id)
                .filter(|u| u.tenant_id == tenant_id)
                .ok_or(AuthError::UserNotFound)?;
            if user.mfa_pending_totp_secret.is_empty() {
                return Err(AuthError::Sso("no pending TOTP enrollment".into()));
            }
            let step = mfa::verify_totp_code(&user.mfa_pending_totp_secret, code, now, 0)
                .map_err(|_| AuthError::InvalidMfaCode)?;
            user.mfa_totp_secret = std::mem::take(&mut user.mfa_pending_totp_secret);
            user.mfa_last_totp_step = step;
            user.mfa_recovery_hashes = recovery_hashes;
            user.mfa_enabled = true;
            (user.clone(), master)
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_user", pg.upsert_user(&updated, &master).await);
        }
        Ok(recovery_codes)
    }

    pub async fn disable_totp(
        &self,
        tenant_id: &str,
        user_id: &str,
        current_password: &str,
        code: &str,
    ) -> Result<(), AuthError> {
        let now = now_unix();
        let hash = {
            let guard = self.inner.read().await;
            let user = guard
                .users
                .get(user_id)
                .filter(|u| u.tenant_id == tenant_id)
                .ok_or(AuthError::UserNotFound)?;
            user.password_hash.clone()
        };
        if !hash.is_empty() && !bcrypt::verify(current_password, &hash).unwrap_or(false) {
            return Err(AuthError::InvalidCredentials);
        }
        let (updated, master) = {
            let mut guard = self.inner.write().await;
            let master = guard.master_secret.clone();
            let user = guard
                .users
                .get_mut(user_id)
                .filter(|u| u.tenant_id == tenant_id)
                .ok_or(AuthError::UserNotFound)?;
            let code_ok = (!user.mfa_totp_secret.is_empty()
                && mfa::verify_totp_code(
                    &user.mfa_totp_secret,
                    code,
                    now,
                    user.mfa_last_totp_step,
                )
                .is_ok())
                || mfa::consume_recovery_code(&mut user.mfa_recovery_hashes, code);
            if !code_ok {
                return Err(AuthError::InvalidMfaCode);
            }
            user.mfa_totp_secret.clear();
            user.mfa_pending_totp_secret.clear();
            user.mfa_recovery_hashes.clear();
            user.mfa_last_totp_step = 0;
            user.mfa_enabled = !user.webauthn_credentials.is_empty();
            (user.clone(), master)
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_user", pg.upsert_user(&updated, &master).await);
        }
        Ok(())
    }

    pub async fn begin_webauthn_register(
        &self,
        tenant_id: &str,
        user_id: &str,
        rp_id: &str,
        origin: &str,
    ) -> Result<serde_json::Value, AuthError> {
        let now = now_unix();
        let challenge = random_token_b64();
        let mut guard = self.inner.write().await;
        let user = guard
            .users
            .get(user_id)
            .filter(|u| u.tenant_id == tenant_id)
            .ok_or(AuthError::UserNotFound)?
            .clone();
        guard.webauthn_challenges.retain(|_, c| c.expires_at > now);
        guard.webauthn_challenges.insert(
            format!("reg:{user_id}"),
            WebAuthnChallengeRecord {
                user_id: user.id.clone(),
                tenant_id: user.tenant_id.clone(),
                challenge: challenge.clone(),
                rp_id: rp_id.to_owned(),
                origin: origin.to_owned(),
                expires_at: now + 300,
            },
        );
        Ok(serde_json::json!({
            "challenge": challenge,
            "rp": { "id": rp_id, "name": "Operquay" },
            "user": {
                "id": crypto::b64url_encode(user.id.as_bytes()),
                "name": user.email,
                "displayName": user.name,
            },
            "pubKeyCredParams": [
                { "type": "public-key", "alg": -7 },
                { "type": "public-key", "alg": -8 },
                { "type": "public-key", "alg": -257 }
            ],
            "timeout": 60000,
            "authenticatorSelection": {
                "residentKey": "preferred",
                "userVerification": "preferred"
            }
        }))
    }

    pub async fn finish_webauthn_register(
        &self,
        tenant_id: &str,
        user_id: &str,
        credential_id: &str,
        label: &str,
        public_key_spki_b64: &str,
        alg: i32,
        client_data_b64: &str,
    ) -> Result<(), AuthError> {
        let now = now_unix();
        let (updated, master) = {
            let mut guard = self.inner.write().await;
            let rec = guard
                .webauthn_challenges
                .remove(&format!("reg:{user_id}"))
                .ok_or_else(|| AuthError::Sso("missing WebAuthn registration challenge".into()))?;
            if now > rec.expires_at || rec.tenant_id != tenant_id {
                return Err(AuthError::Sso(
                    "expired WebAuthn registration challenge".into(),
                ));
            }
            mfa::validate_webauthn_registration(
                public_key_spki_b64,
                alg,
                client_data_b64,
                &rec.challenge,
                Some(&rec.origin),
            )
            .map_err(AuthError::Sso)?;
            let master = guard.master_secret.clone();
            let user = guard
                .users
                .get_mut(user_id)
                .filter(|u| u.tenant_id == tenant_id)
                .ok_or(AuthError::UserNotFound)?;
            user.webauthn_credentials.retain(|c| c.id != credential_id);
            user.webauthn_credentials.push(mfa::WebAuthnCredential {
                id: credential_id.to_owned(),
                label: if label.trim().is_empty() {
                    "Passkey".to_owned()
                } else {
                    label.trim().to_owned()
                },
                public_key_spki_b64: public_key_spki_b64.to_owned(),
                alg,
                sign_count: 0,
                created_at: now,
            });
            user.mfa_enabled = true;
            (user.clone(), master)
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_user", pg.upsert_user(&updated, &master).await);
        }
        Ok(())
    }

    pub async fn begin_webauthn_login(
        &self,
        tenant_id: &str,
        challenge_token: &str,
        rp_id: &str,
        origin: &str,
    ) -> Result<serde_json::Value, AuthError> {
        let now = now_unix();
        let mut guard = self.inner.write().await;
        let master = guard.master_secret.clone();
        let cid =
            verify_session_token(&master, challenge_token).ok_or(AuthError::InvalidMfaCode)?;
        let rec = guard
            .mfa_challenges
            .get(&cid)
            .filter(|r| r.tenant_id == tenant_id && r.expires_at >= now)
            .cloned()
            .ok_or(AuthError::InvalidMfaCode)?;
        let user = guard
            .users
            .get(&rec.user_id)
            .ok_or(AuthError::UserNotFound)?
            .clone();
        let challenge = random_token_b64();
        guard.webauthn_challenges.insert(
            format!("auth:{cid}"),
            WebAuthnChallengeRecord {
                user_id: user.id.clone(),
                tenant_id: user.tenant_id.clone(),
                challenge: challenge.clone(),
                rp_id: rp_id.to_owned(),
                origin: origin.to_owned(),
                expires_at: now + 300,
            },
        );
        let allow: Vec<serde_json::Value> = user
            .webauthn_credentials
            .iter()
            .map(|c| serde_json::json!({ "type": "public-key", "id": c.id }))
            .collect();
        Ok(serde_json::json!({
            "challenge": challenge,
            "rpId": rp_id,
            "allowCredentials": allow,
            "timeout": 60000,
            "userVerification": "preferred"
        }))
    }

    pub async fn finish_webauthn_login(
        &self,
        tenant_id: &str,
        challenge_token: &str,
        credential_id: &str,
        client_data_b64: &str,
        authenticator_data_b64: &str,
        signature_b64: &str,
    ) -> Result<(SessionClaims, String), AuthError> {
        let now = now_unix();
        let session_ttl = self.session_hours() * 3600;
        let (claims, signed, updated, master) = {
            let mut guard = self.inner.write().await;
            let master = guard.master_secret.clone();
            let cid =
                verify_session_token(&master, challenge_token).ok_or(AuthError::InvalidMfaCode)?;
            let wrec = guard
                .webauthn_challenges
                .remove(&format!("auth:{cid}"))
                .ok_or(AuthError::InvalidMfaCode)?;
            if now > wrec.expires_at || wrec.tenant_id != tenant_id {
                return Err(AuthError::InvalidMfaCode);
            }
            guard.mfa_challenges.remove(&cid);
            let user = guard
                .users
                .get_mut(&wrec.user_id)
                .ok_or(AuthError::UserNotFound)?;
            let cred = user
                .webauthn_credentials
                .iter_mut()
                .find(|c| c.id == credential_id)
                .ok_or(AuthError::InvalidMfaCode)?;
            let next_cnt = mfa::verify_webauthn_assertion(
                cred,
                &wrec.challenge,
                Some(&wrec.origin),
                &wrec.rp_id,
                client_data_b64,
                authenticator_data_b64,
                signature_b64,
            )
            .map_err(|_| AuthError::InvalidMfaCode)?;
            cred.sign_count = next_cnt;
            let snapshot = user.clone();
            let claims = create_session_claims(&mut guard, &snapshot, "password+mfa", session_ttl);
            let signed = sign_session_token(&master, &claims.session_id);
            (claims, signed, snapshot, master)
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_user", pg.upsert_user(&updated, &master).await);
            warn_pg_err("upsert_session", pg.upsert_session(&claims).await);
        }
        Ok((claims, signed))
    }

    pub async fn delete_webauthn_credential(
        &self,
        tenant_id: &str,
        user_id: &str,
        cred_id: &str,
    ) -> Result<(), AuthError> {
        let (updated, master) = {
            let mut guard = self.inner.write().await;
            let master = guard.master_secret.clone();
            let user = guard
                .users
                .get_mut(user_id)
                .filter(|u| u.tenant_id == tenant_id)
                .ok_or(AuthError::UserNotFound)?;
            let before = user.webauthn_credentials.len();
            user.webauthn_credentials.retain(|c| c.id != cred_id);
            if user.webauthn_credentials.len() == before {
                return Err(AuthError::UserNotFound);
            }
            if user.mfa_totp_secret.is_empty() && user.webauthn_credentials.is_empty() {
                user.mfa_enabled = false;
            }
            (user.clone(), master)
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_user", pg.upsert_user(&updated, &master).await);
        }
        Ok(())
    }

    pub async fn verify_cookie(&self, headers: &http::HeaderMap) -> Option<SessionClaims> {
        let raw_cookie = extract_cookie(headers, HOST_SESSION_COOKIE_NAME)
            .or_else(|| extract_cookie(headers, SESSION_COOKIE_NAME))?;
        let idle_limit = self.idle_minutes() * 60;
        let now = now_unix();
        let (result, expired_info) = {
            let mut guard = self.inner.write().await;
            let session_id = verify_session_token(&guard.master_secret, &raw_cookie)?;
            let (expires, last_active, tenant_id, user_id) = {
                let s = guard.sessions.get(&session_id)?;
                (
                    s.expires_at,
                    s.last_active_at,
                    s.tenant_id.clone(),
                    s.user_id.clone(),
                )
            };
            if now > expires || now.saturating_sub(last_active) > idle_limit {
                guard.sessions.remove(&session_id);
                (None, Some((tenant_id, session_id)))
            } else {
                if let Some(sess) = guard.sessions.get_mut(&session_id) {
                    sess.last_active_at = now;
                }
                let user = guard.users.get(&user_id).cloned();
                match user {
                    Some(u) if !u.disabled => {
                        let (groups, perms) =
                            compute_effective_rbac(&guard, &u, None, current_hour_utc());
                        let sess = guard.sessions.get_mut(&session_id)?;
                        sess.role = u.role;
                        sess.groups = groups;
                        sess.permissions = perms;
                        (Some(sess.clone()), None)
                    }
                    _ => {
                        guard.sessions.remove(&session_id);
                        (None, Some((tenant_id, session_id)))
                    }
                }
            }
        };
        if let (Some((tid, sid)), Some(pg)) = (expired_info, self.pg_pool().await) {
            warn_pg_err("delete_session", pg.delete_session(&tid, &sid).await);
        }
        result
    }

    pub async fn is_session_active(
        &self,
        tenant_id: &str,
        session_id: &str,
        user_id: &str,
    ) -> bool {
        let now = now_unix();
        let idle_limit = self.idle_minutes() * 60;
        let mem_ok = {
            let guard = self.inner.read().await;
            if let Some(user) = guard.users.get(user_id) {
                if user.disabled || user.tenant_id != tenant_id {
                    return false;
                }
            }
            if session_id == "anonymous-lab" && !guard.require_auth {
                return true;
            }
            guard.sessions.get(session_id).is_some_and(|s| {
                s.tenant_id == tenant_id
                    && s.user_id == user_id
                    && now <= s.expires_at
                    && now.saturating_sub(s.last_active_at) <= idle_limit
            })
        };
        if !mem_ok {
            return false;
        }
        if let Some(pg) = self.pg_pool().await {
            if let Ok(valid) = pg.is_session_valid(tenant_id, session_id, user_id).await {
                return valid;
            }
        }
        true
    }

    pub async fn revoke_all_user_sessions(&self, tenant_id: &str, user_id: &str) -> Vec<String> {
        let removed_ids: Vec<String> = {
            let mut guard = self.inner.write().await;
            let ids: Vec<String> = guard
                .sessions
                .iter()
                .filter(|(_, s)| s.tenant_id == tenant_id && s.user_id == user_id)
                .map(|(k, _)| k.clone())
                .collect();
            for id in &ids {
                guard.sessions.remove(id);
            }
            ids
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err(
                "delete_user_sessions",
                pg.delete_user_sessions(tenant_id, user_id).await,
            );
        }
        removed_ids
    }

    pub async fn revoke_session(&self, headers: &http::HeaderMap) {
        let Some(raw) = extract_cookie(headers, HOST_SESSION_COOKIE_NAME)
            .or_else(|| extract_cookie(headers, SESSION_COOKIE_NAME))
        else {
            return;
        };
        let removed = {
            let mut guard = self.inner.write().await;
            verify_session_token(&guard.master_secret, &raw)
                .and_then(|sid| guard.sessions.remove(&sid))
        };
        if let (Some(sess), Some(pg)) = (removed, self.pg_pool().await) {
            warn_pg_err(
                "delete_session",
                pg.delete_session(&sess.tenant_id, &sess.session_id).await,
            );
        }
    }

    pub async fn check_permission(
        &self,
        user_id: &str,
        permission: &str,
        scope_type: ScopeType,
        scope_id: &str,
        client_ip: Option<IpAddr>,
    ) -> bool {
        let guard = self.inner.read().await;
        let Some(user) = guard.users.get(user_id) else {
            return false;
        };
        evaluate_scoped_permission(
            &guard,
            user,
            permission,
            scope_type,
            scope_id,
            client_ip,
            current_hour_utc(),
        )
    }

    pub async fn list_users(&self, tenant_id: &str) -> Vec<PublicUser> {
        let guard = self.inner.read().await;
        let mut list: Vec<PublicUser> = guard
            .users
            .values()
            .filter(|u| u.tenant_id == tenant_id)
            .map(User::to_public)
            .collect();
        list.sort_by(|a, b| a.email.cmp(&b.email));
        list
    }

    pub async fn list_users_with_groups(&self, tenant_id: &str) -> Vec<serde_json::Value> {
        let guard = self.inner.read().await;
        let mut users: Vec<&User> = guard
            .users
            .values()
            .filter(|u| u.tenant_id == tenant_id)
            .collect();
        users.sort_by(|a, b| a.email.cmp(&b.email));
        users
            .into_iter()
            .map(|u| {
                let groups: Vec<serde_json::Value> = guard
                    .memberships
                    .iter()
                    .filter(|m| m.tenant_id == tenant_id && m.user_id == u.id)
                    .filter_map(|m| {
                        guard.groups.get(&m.group_id).map(|g| {
                            serde_json::json!({
                                "id": g.id,
                                "name": g.name,
                                "source": m.source,
                            })
                        })
                    })
                    .collect();
                let mut val =
                    serde_json::to_value(u.to_public()).unwrap_or_else(|_| serde_json::json!({}));
                if let Some(obj) = val.as_object_mut() {
                    obj.insert("groups".to_owned(), serde_json::Value::Array(groups));
                }
                val
            })
            .collect()
    }

    pub async fn set_user_local_signin(
        &self,
        tenant_id: &str,
        user_id: &str,
        enabled: bool,
    ) -> Result<PublicUser, AuthError> {
        let (pub_user, updated, master) = {
            let mut guard = self.inner.write().await;
            let master = guard.master_secret.clone();
            let user = guard
                .users
                .get_mut(user_id)
                .filter(|u| u.tenant_id == tenant_id)
                .ok_or(AuthError::UserNotFound)?;
            user.local_signin_enabled = enabled;
            (user.to_public(), user.clone(), master)
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_user", pg.upsert_user(&updated, &master).await);
        }
        Ok(pub_user)
    }

    pub async fn create_user(
        &self,
        tenant_id: &str,
        email: &str,
        name: &str,
        role: &str,
        password: &str,
    ) -> Result<PublicUser, AuthError> {
        let clean_email = email.trim().to_ascii_lowercase();
        let norm_role = normalize_role(role);
        if !password.is_empty() {
            validate_password_policy(password)?;
        }
        let hash = if password.is_empty() {
            String::new()
        } else {
            bcrypt::hash(password, self.bcrypt_cost).map_err(|_| AuthError::InvalidCredentials)?
        };
        let (pub_user, stored_user, default_membership, seeded_roles, seeded_groups, master) = {
            let mut guard = self.inner.write().await;
            let master = guard.master_secret.clone();
            let now = now_unix();
            let before_roles = guard.roles.len();
            let before_groups = guard.groups.len();
            seed_system_roles(&mut guard.roles, tenant_id, now);
            seed_system_groups(&mut guard.groups, tenant_id, now);
            let seeded_roles = if guard.roles.len() > before_roles {
                guard
                    .roles
                    .values()
                    .filter(|r| r.tenant_id == tenant_id && r.is_system)
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };
            let seeded_groups = if guard.groups.len() > before_groups {
                guard
                    .groups
                    .values()
                    .filter(|g| g.tenant_id == tenant_id && g.is_system)
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };
            if guard
                .users
                .values()
                .any(|u| u.tenant_id == tenant_id && u.email.eq_ignore_ascii_case(&clean_email))
            {
                return Err(AuthError::UserExists);
            }
            let id = format!("usr-{}", Uuid::new_v4());
            let history = if hash.is_empty() {
                Vec::new()
            } else {
                vec![hash.clone()]
            };
            let user = User {
                id: id.clone(),
                tenant_id: tenant_id.to_owned(),
                email: clean_email,
                name: if name.trim().is_empty() {
                    email.trim().to_owned()
                } else {
                    name.trim().to_owned()
                },
                role: norm_role.clone(),
                provider: "local".to_owned(),
                subject: String::new(),
                disabled: false,
                password_hash: hash,
                local_signin_enabled: !password.is_empty(),
                must_change_password: false,
                password_history: history,
                mfa_enabled: false,
                mfa_totp_secret: String::new(),
                mfa_pending_totp_secret: String::new(),
                mfa_recovery_hashes: Vec::new(),
                mfa_last_totp_step: 0,
                webauthn_credentials: Vec::new(),
            };
            let pub_user = user.to_public();
            guard.users.insert(id.clone(), user.clone());
            let m = bind_default_group(&mut guard, tenant_id, &id, &norm_role, now);
            (pub_user, user, m, seeded_roles, seeded_groups, master)
        };
        if let Some(pg) = self.pg_pool().await {
            for r in seeded_roles {
                warn_pg_err("upsert_role", pg.upsert_role(&r).await);
            }
            for g in seeded_groups {
                warn_pg_err("upsert_group", pg.upsert_group(&g).await);
            }
            warn_pg_err("upsert_user", pg.upsert_user(&stored_user, &master).await);
            if let Some(m) = default_membership {
                warn_pg_err("upsert_membership", pg.upsert_membership(&m).await);
            }
        }
        Ok(pub_user)
    }

    pub async fn update_user_role(
        &self,
        actor_id: &str,
        tenant_id: &str,
        target_id: &str,
        role: &str,
    ) -> Result<PublicUser, AuthError> {
        if actor_id == target_id {
            return Err(AuthError::SelfEscalation);
        }
        let norm_role = normalize_role(role);
        let (pub_user, updated, role_downgraded, master) = {
            let mut guard = self.inner.write().await;
            let master = guard.master_secret.clone();
            let active_admins = guard
                .users
                .values()
                .filter(|u| u.tenant_id == tenant_id && u.role == "admin" && !u.disabled)
                .count();
            let target = guard
                .users
                .get_mut(target_id)
                .filter(|u| u.tenant_id == tenant_id)
                .ok_or(AuthError::UserNotFound)?;
            if target.role == "admin" && norm_role != "admin" && active_admins <= 1 {
                return Err(AuthError::LastAdmin);
            }
            let downgraded = target.role != norm_role && norm_role != "admin";
            target.role = norm_role;
            (target.to_public(), target.clone(), downgraded, master)
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_user", pg.upsert_user(&updated, &master).await);
        }
        if role_downgraded {
            let _ = self.revoke_all_user_sessions(tenant_id, target_id).await;
        }
        Ok(pub_user)
    }

    pub async fn update_user_status(
        &self,
        actor_id: &str,
        tenant_id: &str,
        target_id: &str,
        disabled: bool,
    ) -> Result<PublicUser, AuthError> {
        if actor_id == target_id && disabled {
            return Err(AuthError::SelfEscalation);
        }
        let (pub_user, updated, master) = {
            let mut guard = self.inner.write().await;
            let master = guard.master_secret.clone();
            let active_admins = guard
                .users
                .values()
                .filter(|u| u.tenant_id == tenant_id && u.role == "admin" && !u.disabled)
                .count();
            let target = guard
                .users
                .get_mut(target_id)
                .filter(|u| u.tenant_id == tenant_id)
                .ok_or(AuthError::UserNotFound)?;
            if disabled && target.role == "admin" && !target.disabled && active_admins <= 1 {
                return Err(AuthError::LastAdmin);
            }
            target.disabled = disabled;
            (target.to_public(), target.clone(), master)
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_user", pg.upsert_user(&updated, &master).await);
        }
        if disabled {
            let _ = self.revoke_all_user_sessions(tenant_id, target_id).await;
        }
        Ok(pub_user)
    }

    pub async fn edit_user(
        &self,
        tenant_id: &str,
        target_id: &str,
        name: Option<&str>,
        email: Option<&str>,
    ) -> Result<PublicUser, AuthError> {
        let (pub_user, updated, master) = {
            let mut guard = self.inner.write().await;
            let master = guard.master_secret.clone();
            let user = guard
                .users
                .get_mut(target_id)
                .filter(|u| u.tenant_id == tenant_id)
                .ok_or(AuthError::UserNotFound)?;
            if let Some(n) = name {
                n.trim().clone_into(&mut user.name);
            }
            if let Some(e) = email {
                user.email = e.trim().to_ascii_lowercase();
            }
            (user.to_public(), user.clone(), master)
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_user", pg.upsert_user(&updated, &master).await);
        }
        Ok(pub_user)
    }

    pub async fn delete_user(
        &self,
        actor_id: &str,
        tenant_id: &str,
        target_id: &str,
    ) -> Result<(), AuthError> {
        if actor_id == target_id {
            return Err(AuthError::SelfEscalation);
        }
        let _ = self.revoke_all_user_sessions(tenant_id, target_id).await;
        {
            let mut guard = self.inner.write().await;
            let active_admins = guard
                .users
                .values()
                .filter(|u| u.tenant_id == tenant_id && u.role == "admin" && !u.disabled)
                .count();
            let target = guard
                .users
                .get(target_id)
                .filter(|u| u.tenant_id == tenant_id)
                .ok_or(AuthError::UserNotFound)?;
            if target.role == "admin" && !target.disabled && active_admins <= 1 {
                return Err(AuthError::LastAdmin);
            }
            guard.users.remove(target_id);
            guard
                .memberships
                .retain(|m| !(m.tenant_id == tenant_id && m.user_id == target_id));
        }
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("delete_user", pg.delete_user(tenant_id, target_id).await);
        }
        Ok(())
    }

    pub async fn change_password(
        &self,
        tenant_id: &str,
        target_id: &str,
        current_pw: Option<&str>,
        new_pw: &str,
    ) -> Result<(), AuthError> {
        validate_password_policy(new_pw)?;
        let (existing_hash, history) = {
            let guard = self.inner.read().await;
            let user = guard
                .users
                .get(target_id)
                .filter(|u| u.tenant_id == tenant_id)
                .ok_or(AuthError::UserNotFound)?;
            (user.password_hash.clone(), user.password_history.clone())
        };
        if let Some(cur) = current_pw {
            if !bcrypt::verify(cur, &existing_hash).unwrap_or(false) {
                return Err(AuthError::InvalidCredentials);
            }
        }
        for old_hash in history
            .iter()
            .chain((!existing_hash.is_empty()).then_some(&existing_hash))
        {
            if bcrypt::verify(new_pw, old_hash).unwrap_or(false) {
                return Err(AuthError::WeakPassword(
                    "New password cannot reuse any of your last 5 passwords.".into(),
                ));
            }
        }
        let new_hash =
            bcrypt::hash(new_pw, self.bcrypt_cost).map_err(|_| AuthError::InvalidCredentials)?;
        let (updated, master) = {
            let mut guard = self.inner.write().await;
            let master = guard.master_secret.clone();
            let u = guard.users.get_mut(target_id).map(|u| {
                if !u.password_hash.is_empty()
                    && u.password_history.last() != Some(&u.password_hash)
                {
                    u.password_history.push(u.password_hash.clone());
                }
                u.password_history.push(new_hash.clone());
                if u.password_history.len() > 5 {
                    let drop_n = u.password_history.len() - 5;
                    u.password_history.drain(..drop_n);
                }
                u.password_hash = new_hash;
                u.local_signin_enabled = true;
                u.must_change_password = false;
                u.clone()
            });
            (u, master)
        };
        if let (Some(u), Some(pg)) = (updated, self.pg_pool().await) {
            warn_pg_err("upsert_user", pg.upsert_user(&u, &master).await);
        }
        let _ = self.revoke_all_user_sessions(tenant_id, target_id).await;
        Ok(())
    }

    pub async fn list_roles(&self, tenant_id: &str) -> Vec<RoleDef> {
        let mut guard = self.inner.write().await;
        seed_system_roles(&mut guard.roles, tenant_id, now_unix());
        let mut list: Vec<_> = guard
            .roles
            .values()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        list
    }

    pub async fn create_role(
        &self,
        tenant_id: &str,
        name: &str,
        description: &str,
        permissions: Vec<String>,
    ) -> Result<RoleDef, AuthError> {
        for p in &permissions {
            if !is_valid_permission(p) {
                return Err(AuthError::InvalidPermission(p.clone()));
            }
        }
        let role = {
            let mut guard = self.inner.write().await;
            if guard
                .roles
                .values()
                .any(|r| r.tenant_id == tenant_id && r.name.eq_ignore_ascii_case(name.trim()))
            {
                return Err(AuthError::RoleExists);
            }
            let now = now_unix();
            let role = RoleDef {
                id: format!("role-{}", Uuid::new_v4()),
                tenant_id: tenant_id.to_owned(),
                name: name.trim().to_owned(),
                description: description.to_owned(),
                base_role: String::new(),
                is_system: false,
                permissions,
                created_at: now,
                updated_at: now,
            };
            guard.roles.insert(role.id.clone(), role.clone());
            role
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_role", pg.upsert_role(&role).await);
        }
        Ok(role)
    }

    pub async fn update_role(
        &self,
        tenant_id: &str,
        role_id: &str,
        name: &str,
        description: &str,
        permissions: Vec<String>,
    ) -> Result<RoleDef, AuthError> {
        for p in &permissions {
            if !is_valid_permission(p) {
                return Err(AuthError::InvalidPermission(p.clone()));
            }
        }
        let updated = {
            let mut guard = self.inner.write().await;
            let role = guard
                .roles
                .get_mut(role_id)
                .filter(|r| r.tenant_id == tenant_id)
                .ok_or(AuthError::RoleNotFound)?;
            if role.is_system {
                return Err(AuthError::SystemRole);
            }
            name.trim().clone_into(&mut role.name);
            description.clone_into(&mut role.description);
            role.permissions = permissions;
            role.updated_at = now_unix();
            role.clone()
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_role", pg.upsert_role(&updated).await);
        }
        Ok(updated)
    }

    pub async fn delete_role(&self, tenant_id: &str, role_id: &str) -> Result<(), AuthError> {
        {
            let mut guard = self.inner.write().await;
            let role = guard
                .roles
                .get(role_id)
                .filter(|r| r.tenant_id == tenant_id)
                .ok_or(AuthError::RoleNotFound)?;
            if role.is_system {
                return Err(AuthError::SystemRole);
            }
            guard.roles.remove(role_id);
            guard
                .bindings
                .retain(|b| !(b.tenant_id == tenant_id && b.role_id == role_id));
        }
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("delete_role", pg.delete_role(tenant_id, role_id).await);
        }
        Ok(())
    }

    pub async fn list_groups(&self, tenant_id: &str) -> Vec<Group> {
        let mut guard = self.inner.write().await;
        seed_system_groups(&mut guard.groups, tenant_id, now_unix());
        let mut list: Vec<_> = guard
            .groups
            .values()
            .filter(|g| g.tenant_id == tenant_id)
            .cloned()
            .collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        list
    }

    pub async fn create_group(
        &self,
        tenant_id: &str,
        name: &str,
        description: &str,
    ) -> Result<Group, AuthError> {
        let grp = {
            let mut guard = self.inner.write().await;
            if guard
                .groups
                .values()
                .any(|g| g.tenant_id == tenant_id && g.name.eq_ignore_ascii_case(name.trim()))
            {
                return Err(AuthError::GroupExists);
            }
            let now = now_unix();
            let grp = Group {
                id: format!("grp-{}", Uuid::new_v4()),
                tenant_id: tenant_id.to_owned(),
                name: name.trim().to_owned(),
                description: description.to_owned(),
                source: "local".to_owned(),
                external_id: String::new(),
                is_system: false,
                created_at: now,
                updated_at: now,
            };
            guard.groups.insert(grp.id.clone(), grp.clone());
            grp
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_group", pg.upsert_group(&grp).await);
        }
        Ok(grp)
    }

    pub async fn add_group_member(
        &self,
        tenant_id: &str,
        group_id: &str,
        user_id: &str,
    ) -> Result<(), AuthError> {
        let added =
            {
                let mut guard = self.inner.write().await;
                if !guard.groups.contains_key(group_id) {
                    return Err(AuthError::GroupNotFound);
                }
                if !guard.users.contains_key(user_id) {
                    return Err(AuthError::UserNotFound);
                }
                if guard.memberships.iter().any(|m| {
                    m.tenant_id == tenant_id && m.group_id == group_id && m.user_id == user_id
                }) {
                    None
                } else {
                    let m = GroupMembership {
                        tenant_id: tenant_id.to_owned(),
                        group_id: group_id.to_owned(),
                        user_id: user_id.to_owned(),
                        source: "manual".to_owned(),
                        created_at: now_unix(),
                    };
                    guard.memberships.push(m.clone());
                    Some(m)
                }
            };
        if let (Some(m), Some(pg)) = (added, self.pg_pool().await) {
            warn_pg_err("upsert_membership", pg.upsert_membership(&m).await);
        }
        Ok(())
    }

    pub async fn remove_group_member(&self, tenant_id: &str, group_id: &str, user_id: &str) {
        self.inner.write().await.memberships.retain(|m| {
            !(m.tenant_id == tenant_id && m.group_id == group_id && m.user_id == user_id)
        });
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err(
                "delete_group_member",
                pg.delete_group_member(tenant_id, group_id, user_id).await,
            );
        }
    }

    pub async fn set_user_groups(
        &self,
        actor_id: &str,
        tenant_id: &str,
        target_id: &str,
        group_ids: &[String],
    ) -> Result<(), AuthError> {
        let inserted = {
            let mut guard = self.inner.write().await;
            if guard
                .users
                .get(target_id)
                .is_none_or(|u| u.tenant_id != tenant_id)
            {
                return Err(AuthError::UserNotFound);
            }
            if actor_id == target_id {
                return Err(AuthError::SelfEscalation);
            }
            let valid_groups: Vec<String> = group_ids
                .iter()
                .filter(|gid| {
                    guard
                        .groups
                        .get(gid.as_str())
                        .is_some_and(|g| g.tenant_id == tenant_id)
                })
                .cloned()
                .collect();
            guard
                .memberships
                .retain(|m| !(m.tenant_id == tenant_id && m.user_id == target_id));
            let now = now_unix();
            let mut inserted = Vec::with_capacity(valid_groups.len());
            for gid in valid_groups {
                let m = GroupMembership {
                    tenant_id: tenant_id.to_owned(),
                    group_id: gid,
                    user_id: target_id.to_owned(),
                    source: "manual".to_owned(),
                    created_at: now,
                };
                guard.memberships.push(m.clone());
                inserted.push(m);
            }
            inserted
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err(
                "replace_user_memberships",
                pg.replace_user_memberships(tenant_id, target_id, None, &inserted)
                    .await,
            );
        }
        Ok(())
    }

    pub async fn me_payload(&self, claims: &SessionClaims) -> serde_json::Value {
        let guard = self.inner.read().await;
        let groups: Vec<serde_json::Value> = guard
            .memberships
            .iter()
            .filter(|m| m.tenant_id == claims.tenant_id && m.user_id == claims.user_id)
            .filter_map(|m| {
                guard.groups.get(&m.group_id).map(|g| {
                    serde_json::json!({
                        "id": g.id,
                        "name": g.name,
                        "source": m.source,
                    })
                })
            })
            .collect();
        let effective_perms: Vec<String> = if claims.permissions.is_empty() {
            if let Some(user) = guard.users.get(&claims.user_id) {
                let hour = current_hour_utc();
                policy::PERMISSION_CATALOG
                    .iter()
                    .map(|p| p.id)
                    .filter(|perm_id| {
                        evaluate_scoped_permission(
                            &guard,
                            user,
                            perm_id,
                            ScopeType::Global,
                            "",
                            None,
                            hour,
                        )
                    })
                    .map(str::to_owned)
                    .collect()
            } else {
                base_role_permissions(&claims.role)
            }
        } else {
            claims.permissions.clone()
        };
        let user_group_ids: Vec<String> = guard
            .memberships
            .iter()
            .filter(|m| m.tenant_id == claims.tenant_id && m.user_id == claims.user_id)
            .map(|m| m.group_id.clone())
            .collect();
        let mut grants: Vec<serde_json::Value> = guard
            .bindings
            .iter()
            .filter(|b| b.tenant_id == claims.tenant_id && user_group_ids.contains(&b.group_id))
            .map(|b| {
                let role = guard.roles.get(&b.role_id);
                serde_json::json!({
                    "role_id": b.role_id,
                    "role_name": role.map_or(b.role_id.as_str(), |r| r.name.as_str()),
                    "base_role": role.map_or("", |r| r.base_role.as_str()),
                    "permissions": role.map_or_default(|r| r.permissions.clone()),
                    "scope_type": b.scope_type,
                    "scope_id": b.scope_id,
                    "effect": b.effect,
                    "conditions": b.conditions,
                })
            })
            .collect();
        if grants.is_empty() && !effective_perms.is_empty() {
            grants.push(serde_json::json!({
                "role_id": claims.role,
                "role_name": claims.role,
                "base_role": claims.role,
                "permissions": effective_perms,
                "scope_type": "global",
                "scope_id": "",
                "effect": "allow",
                "conditions": {},
            }));
        }
        let (mfa_enabled, must_change_password) = guard
            .users
            .get(&claims.user_id)
            .map_or((false, false), |u| (u.mfa_enabled, u.must_change_password));
        let method = if claims.method == "local" && claims.email == "admin@local" {
            "break_glass"
        } else if claims.method == "local"
            || claims.method == "password"
            || claims.method == "password+mfa"
        {
            "password"
        } else if claims.method == "oidc" || claims.method == "saml" || claims.method == "sso" {
            "sso"
        } else {
            claims.method.as_str()
        };
        serde_json::json!({
            "id": claims.user_id,
            "user_id": claims.user_id,
            "username": claims.email,
            "tenant_id": claims.tenant_id,
            "email": claims.email,
            "name": claims.name,
            "role": claims.role,
            "method": method,
            "provider": claims.method,
            "expires_at": claims.expires_at,
            "mfa_enabled": mfa_enabled,
            "must_change_password": must_change_password,
            "compliance_mode": compliance_mode_enabled(),
            "groups": groups,
            "grants": grants,
            "permissions": effective_perms,
        })
    }

    pub async fn user_must_change_password(&self, user_id: &str) -> bool {
        self.inner
            .read()
            .await
            .users
            .get(user_id)
            .is_some_and(|u| u.must_change_password)
    }

    pub async fn update_group(
        &self,
        tenant_id: &str,
        group_id: &str,
        name: &str,
        description: &str,
    ) -> Result<Group, AuthError> {
        let updated = {
            let mut guard = self.inner.write().await;
            let grp = guard
                .groups
                .get_mut(group_id)
                .filter(|g| g.tenant_id == tenant_id)
                .ok_or(AuthError::GroupNotFound)?;
            name.trim().clone_into(&mut grp.name);
            description.clone_into(&mut grp.description);
            grp.updated_at = now_unix();
            grp.clone()
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_group", pg.upsert_group(&updated).await);
        }
        Ok(updated)
    }

    pub async fn delete_group(&self, tenant_id: &str, group_id: &str) -> Result<(), AuthError> {
        {
            let mut guard = self.inner.write().await;
            let grp = guard
                .groups
                .get(group_id)
                .filter(|g| g.tenant_id == tenant_id)
                .ok_or(AuthError::GroupNotFound)?;
            if grp.is_system {
                return Err(AuthError::SystemRole);
            }
            guard.groups.remove(group_id);
            guard
                .memberships
                .retain(|m| !(m.tenant_id == tenant_id && m.group_id == group_id));
            guard
                .bindings
                .retain(|b| !(b.tenant_id == tenant_id && b.group_id == group_id));
        }
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("delete_group", pg.delete_group(tenant_id, group_id).await);
        }
        Ok(())
    }

    pub async fn list_groups_detailed(&self, tenant_id: &str) -> Vec<serde_json::Value> {
        let guard = self.inner.read().await;
        let mut groups: Vec<&Group> = guard
            .groups
            .values()
            .filter(|g| g.tenant_id == tenant_id)
            .collect();
        groups.sort_by(|a, b| a.name.cmp(&b.name));
        groups
            .into_iter()
            .map(|g| {
                let members: Vec<serde_json::Value> = guard
                    .memberships
                    .iter()
                    .filter(|m| m.tenant_id == tenant_id && m.group_id == g.id)
                    .filter_map(|m| {
                        guard.users.get(&m.user_id).map(|u| {
                            serde_json::json!({
                                "user_id": u.id,
                                "email": u.email,
                                "name": u.name,
                                "source": m.source,
                            })
                        })
                    })
                    .collect();
                let mut bindings: Vec<serde_json::Value> = guard
                    .bindings
                    .iter()
                    .filter(|b| b.tenant_id == tenant_id && b.group_id == g.id)
                    .map(|b| {
                        let role = guard.roles.get(&b.role_id);
                        serde_json::json!({
                            "id": b.id,
                            "group_id": b.group_id,
                            "role_id": b.role_id,
                            "role_name": role.map_or(b.role_id.as_str(), |r| r.name.as_str()),
                            "base_role": role.map(|r| r.base_role.as_str()),
                            "permissions": role.map_or_default(|r| r.permissions.clone()),
                            "scope_type": b.scope_type,
                            "scope_id": b.scope_id,
                            "effect": b.effect,
                            "conditions": b.conditions,
                        })
                    })
                    .collect();
                if bindings.is_empty() && g.is_system {
                    let default_role_id = if g.id.starts_with("grp-admins-") {
                        Some(format!("role-admin-{tenant_id}"))
                    } else if g.id.starts_with("grp-operators-") {
                        Some(format!("role-user-{tenant_id}"))
                    } else if g.id.starts_with("grp-viewers-") {
                        Some(format!("role-readonly-{tenant_id}"))
                    } else {
                        None
                    };
                    if let Some(rid) = default_role_id {
                        if let Some(role) = guard.roles.get(&rid) {
                            bindings.push(serde_json::json!({
                                "id": format!("default-{}", g.id),
                                "group_id": g.id,
                                "role_id": role.id,
                                "role_name": role.name,
                                "base_role": role.base_role,
                                "permissions": role.permissions,
                                "scope_type": "global",
                                "scope_id": "",
                                "effect": "allow",
                            }));
                        }
                    }
                }
                let idp_mappings: Vec<&IdPGroupMapping> = guard
                    .idp_mappings
                    .iter()
                    .filter(|m| m.tenant_id == tenant_id && m.group_id == g.id)
                    .collect();
                serde_json::json!({
                    "id": g.id,
                    "tenant_id": g.tenant_id,
                    "name": g.name,
                    "description": g.description,
                    "source": g.source,
                    "is_system": g.is_system,
                    "created_at": g.created_at,
                    "updated_at": g.updated_at,
                    "member_count": members.len(),
                    "members": members,
                    "bindings": bindings,
                    "idp_mappings": idp_mappings,
                })
            })
            .collect()
    }

    pub async fn bind_group_role(
        &self,
        tenant_id: &str,
        group_id: &str,
        role_id: &str,
        scope_type: ScopeType,
        scope_id: &str,
        effect: Effect,
        conditions: BindingConditions,
    ) -> Result<GroupRoleBinding, AuthError> {
        let binding = {
            let mut guard = self.inner.write().await;
            if !guard.groups.contains_key(group_id) {
                return Err(AuthError::GroupNotFound);
            }
            if !guard.roles.contains_key(role_id) {
                return Err(AuthError::RoleNotFound);
            }
            let binding = GroupRoleBinding {
                id: format!("bnd-{}", Uuid::new_v4()),
                tenant_id: tenant_id.to_owned(),
                group_id: group_id.to_owned(),
                role_id: role_id.to_owned(),
                scope_type,
                scope_id: scope_id.to_owned(),
                effect,
                conditions,
                created_at: now_unix(),
            };
            guard.bindings.push(binding.clone());
            binding
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_binding", pg.upsert_binding(&binding).await);
        }
        Ok(binding)
    }

    pub async fn unbind_group_role(&self, tenant_id: &str, binding_id: &str) {
        self.inner
            .write()
            .await
            .bindings
            .retain(|b| !(b.tenant_id == tenant_id && b.id == binding_id));
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err(
                "delete_binding",
                pg.delete_binding(tenant_id, binding_id).await,
            );
        }
    }

    pub async fn list_idp_mappings(&self, tenant_id: &str) -> Vec<IdPGroupMapping> {
        self.inner
            .read()
            .await
            .idp_mappings
            .iter()
            .filter(|m| m.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    pub async fn create_idp_mapping(
        &self,
        tenant_id: &str,
        provider_id: &str,
        external_group: &str,
        group_id: &str,
    ) -> IdPGroupMapping {
        let m = IdPGroupMapping {
            id: format!("map-{}", Uuid::new_v4()),
            tenant_id: tenant_id.to_owned(),
            provider_id: provider_id.to_owned(),
            external_group: external_group.to_owned(),
            group_id: group_id.to_owned(),
            created_at: now_unix(),
        };
        self.inner.write().await.idp_mappings.push(m.clone());
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_idp_mapping", pg.upsert_idp_mapping(&m).await);
        }
        m
    }

    pub async fn delete_idp_mapping(&self, tenant_id: &str, id: &str) {
        self.inner
            .write()
            .await
            .idp_mappings
            .retain(|m| !(m.tenant_id == tenant_id && m.id == id));
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err(
                "delete_idp_mapping",
                pg.delete_idp_mapping(tenant_id, id).await,
            );
        }
    }

    pub async fn upsert_sso_provider(&self, mut cfg: SsoProviderConfig) -> SsoProviderPublic {
        if cfg.id.is_empty() {
            cfg.id = format!("sso-{}", Uuid::new_v4());
        }
        if cfg.tenant_id.is_empty() {
            "default".clone_into(&mut cfg.tenant_id);
        }
        let pub_view = cfg.to_public();
        let master = {
            let mut guard = self.inner.write().await;
            guard.providers.insert(cfg.id.clone(), cfg.clone());
            guard.master_secret.clone()
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err(
                "upsert_sso_provider",
                pg.upsert_sso_provider(&cfg, &master).await,
            );
        }
        pub_view
    }

    pub async fn update_sso_provider(
        &self,
        tenant_id: &str,
        id: &str,
        mut cfg: SsoProviderConfig,
    ) -> Result<SsoProviderPublic, AuthError> {
        let (pub_view, saved, master) = {
            let mut guard = self.inner.write().await;
            let existing = guard
                .providers
                .get(id)
                .filter(|p| p.tenant_id == tenant_id)
                .ok_or(AuthError::ProviderNotFound)?
                .clone();
            cfg.id = existing.id;
            cfg.tenant_id = existing.tenant_id;
            if cfg.provider_type.is_empty() {
                cfg.provider_type = existing.provider_type;
            }
            if cfg.client_secret.is_empty() {
                cfg.client_secret = existing.client_secret;
            }
            let pub_view = cfg.to_public();
            guard.providers.insert(cfg.id.clone(), cfg.clone());
            (pub_view, cfg, guard.master_secret.clone())
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err(
                "upsert_sso_provider",
                pg.upsert_sso_provider(&saved, &master).await,
            );
        }
        Ok(pub_view)
    }

    pub async fn update_sso_provider_patch(
        &self,
        tenant_id: &str,
        id: &str,
        patch: SsoProviderPatch,
    ) -> Result<SsoProviderPublic, AuthError> {
        let (pub_view, saved, master) = {
            let mut guard = self.inner.write().await;
            let mut cfg = guard
                .providers
                .get(id)
                .filter(|p| p.tenant_id == tenant_id)
                .ok_or(AuthError::ProviderNotFound)?
                .clone();
            if let Some(v) = patch.label {
                cfg.label = v;
            }
            if let Some(v) = patch.provider_type {
                if !v.is_empty() {
                    cfg.provider_type = v;
                }
            }
            if let Some(v) = patch.issuer {
                cfg.issuer = v;
            }
            if let Some(v) = patch.client_id {
                cfg.client_id = v;
            }
            if let Some(v) = patch.client_secret {
                if !v.is_empty() {
                    cfg.client_secret = v;
                }
            }
            if let Some(v) = patch.redirect_url {
                cfg.redirect_url = v;
            }
            if let Some(v) = patch.metadata_url {
                cfg.metadata_url = v;
            }
            if let Some(v) = patch.metadata_xml {
                cfg.metadata_xml = v;
            }
            if let Some(v) = patch.entity_id {
                cfg.entity_id = v;
            }
            if let Some(v) = patch.sso_url {
                cfg.sso_url = v;
            }
            if let Some(v) = patch.slo_url {
                cfg.slo_url = v;
            }
            if let Some(v) = patch.certificate_pem {
                cfg.certificate_pem = v;
            }
            if let Some(v) = patch.groups_attribute {
                cfg.groups_attribute = v;
            }
            if let Some(v) = patch.default_role {
                cfg.default_role = v;
            }
            if let Some(v) = patch.allowed_domains {
                cfg.allowed_domains = v;
            }
            if let Some(v) = patch.viewer_groups {
                cfg.viewer_groups = v;
            }
            if let Some(v) = patch.admin_groups {
                cfg.admin_groups = v;
            }
            if let Some(v) = patch.operator_groups {
                cfg.operator_groups = v;
            }
            if let Some(v) = patch.require_email_verified {
                cfg.require_email_verified = Some(v);
            }
            let pub_view = cfg.to_public();
            guard.providers.insert(cfg.id.clone(), cfg.clone());
            (pub_view, cfg, guard.master_secret.clone())
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err(
                "upsert_sso_provider",
                pg.upsert_sso_provider(&saved, &master).await,
            );
        }
        Ok(pub_view)
    }

    pub async fn list_sso_providers(&self, tenant_id: &str) -> Vec<SsoProviderPublic> {
        self.inner
            .read()
            .await
            .providers
            .values()
            .filter(|p| p.tenant_id == tenant_id)
            .map(SsoProviderConfig::to_public)
            .collect()
    }

    pub async fn delete_sso_provider(&self, tenant_id: &str, id: &str) {
        let removed = {
            let mut guard = self.inner.write().await;
            if guard
                .providers
                .get(id)
                .is_some_and(|p| p.tenant_id == tenant_id)
            {
                guard.providers.remove(id).is_some()
            } else {
                false
            }
        };
        if removed {
            if let Some(pg) = self.pg_pool().await {
                warn_pg_err(
                    "delete_sso_provider",
                    pg.delete_sso_provider(tenant_id, id).await,
                );
            }
        }
    }

    pub async fn start_sso_login(
        &self,
        tenant_id: &str,
        provider_id: &str,
        public_base_url: &str,
    ) -> Result<String, AuthError> {
        let cfg = {
            let guard = self.inner.read().await;
            guard
                .providers
                .get(provider_id)
                .filter(|p| p.tenant_id == tenant_id)
                .cloned()
                .ok_or(AuthError::ProviderNotFound)?
        };
        if cfg.provider_type == "saml" {
            let acs = format!("{public_base_url}/api/auth/saml/{}/acs", cfg.id);
            let now_ts = format_iso8601_utc(now_unix());
            let mut guard = self.inner.write().await;
            let tracker = guard.saml_trackers.entry(cfg.id.clone()).or_default();
            let (url, _) = tracker.build_redirect_request(&cfg, &acs, &now_ts);
            return Ok(url);
        }
        let disc = discover_oidc(&cfg.issuer).await.map_err(AuthError::Sso)?;
        let (auth_url, pending) = build_oidc_authorize_url(&cfg, &disc.authorization_endpoint);
        self.inner
            .write()
            .await
            .oidc_pending
            .insert(pending.state.clone(), pending);
        Ok(auth_url)
    }

    pub async fn finish_oidc_callback(
        &self,
        tenant_id: &str,
        code: &str,
        state_tok: &str,
    ) -> Result<(SessionClaims, String), AuthError> {
        let (pending, cfg) = {
            let mut guard = self.inner.write().await;
            let pending = guard
                .oidc_pending
                .remove(state_tok)
                .ok_or_else(|| AuthError::Sso("invalid or expired OIDC state".into()))?;
            let cfg = guard
                .providers
                .get(&pending.provider_id)
                .filter(|p| p.tenant_id == tenant_id)
                .cloned()
                .ok_or(AuthError::ProviderNotFound)?;
            (pending, cfg)
        };
        let disc = discover_oidc(&cfg.issuer).await.map_err(AuthError::Sso)?;
        let tok_res = exchange_oidc_code(&cfg, &disc.token_endpoint, code, &pending.code_verifier)
            .await
            .map_err(AuthError::Sso)?;
        let id_tok = tok_res
            .id_token
            .ok_or_else(|| AuthError::Sso("missing id_token in OIDC response".into()))?;

        let expected_issuer = if disc.issuer.trim().is_empty() {
            cfg.issuer.as_str()
        } else {
            disc.issuer.as_str()
        };
        let params = OidcValidationParams {
            issuer: expected_issuer,
            client_id: &cfg.client_id,
            nonce: Some(&pending.nonce),
            now_unix: now_unix(),
            require_email_verified: cfg.require_email_verified.unwrap_or(true),
        };

        let cached_jwks = {
            let guard = self.inner.read().await;
            guard
                .jwks_cache
                .get(&disc.jwks_uri)
                .filter(|(fetched_at, _)| fetched_at.elapsed() < Duration::from_secs(300))
                .map(|(_, set)| set.clone())
        };

        let payload = if let Some(ref jwks) = cached_jwks {
            if let Ok(claims) = verify_oidc_id_token(&id_tok, jwks, &params) {
                claims
            } else {
                let fresh = fetch_oidc_jwks(&disc.jwks_uri)
                    .await
                    .map_err(AuthError::Sso)?;
                self.inner
                    .write()
                    .await
                    .jwks_cache
                    .insert(disc.jwks_uri.clone(), (Instant::now(), fresh.clone()));
                verify_oidc_id_token(&id_tok, &fresh, &params).map_err(AuthError::Sso)?
            }
        } else {
            let fresh = fetch_oidc_jwks(&disc.jwks_uri)
                .await
                .map_err(AuthError::Sso)?;
            self.inner
                .write()
                .await
                .jwks_cache
                .insert(disc.jwks_uri.clone(), (Instant::now(), fresh.clone()));
            verify_oidc_id_token(&id_tok, &fresh, &params).map_err(AuthError::Sso)?
        };

        let claims =
            claims_from_oidc_json(&payload, &cfg.groups_attribute).map_err(AuthError::Sso)?;
        self.complete_sso_signin(tenant_id, &cfg, claims).await
    }

    pub async fn saml_metadata(
        &self,
        tenant_id: &str,
        provider_id: &str,
        public_base: &str,
    ) -> Result<String, AuthError> {
        let cfg = self
            .inner
            .read()
            .await
            .providers
            .get(provider_id)
            .filter(|p| p.tenant_id == tenant_id)
            .cloned()
            .ok_or(AuthError::ProviderNotFound)?;
        let acs = format!("{public_base}/api/auth/saml/{}/acs", cfg.id);
        let slo = format!("{public_base}/api/auth/saml/{}/slo", cfg.id);
        let entity = if cfg.entity_id.is_empty() {
            acs.clone()
        } else {
            cfg.entity_id
        };
        Ok(render_saml_sp_metadata(&entity, &acs, &slo))
    }

    pub async fn finish_saml_acs(
        &self,
        tenant_id: &str,
        provider_id: &str,
        saml_response_b64: &str,
        expected_acs_url: &str,
    ) -> Result<(SessionClaims, String), AuthError> {
        let (cfg, in_resp_to, assertion_id, claims) = {
            let guard = self.inner.read().await;
            let cfg = guard
                .providers
                .get(provider_id)
                .filter(|p| p.tenant_id == tenant_id)
                .cloned()
                .ok_or(AuthError::ProviderNotFound)?;
            let expected_aud = if cfg.entity_id.trim().is_empty() {
                expected_acs_url
            } else {
                cfg.entity_id.as_str()
            };
            let params = SamlValidationParams {
                cfg: &cfg,
                expected_audience: expected_aud,
                expected_recipient: expected_acs_url,
                now_unix: now_unix(),
                compliance_mode: compliance_mode_enabled(),
            };
            let (in_resp, aid, parsed) =
                verify_and_parse_saml_response_b64(saml_response_b64, &params)
                    .map_err(AuthError::Sso)?;
            (cfg, in_resp, aid, parsed)
        };
        {
            let mut guard = self.inner.write().await;
            let tracker = guard
                .saml_trackers
                .entry(provider_id.to_owned())
                .or_default();
            tracker
                .consume_response_id(&in_resp_to, &assertion_id)
                .map_err(AuthError::Sso)?;
        }
        self.complete_sso_signin(tenant_id, &cfg, claims).await
    }

    async fn complete_sso_signin(
        &self,
        tenant_id: &str,
        cfg: &SsoProviderConfig,
        claims: SsoIdentityClaims,
    ) -> Result<(SessionClaims, String), AuthError> {
        if !cfg.allowed_domains.is_empty() {
            let domain = claims.email.rsplit_once('@').map_or("", |(_, d)| d);
            if !cfg
                .allowed_domains
                .iter()
                .any(|d| d.eq_ignore_ascii_case(domain))
            {
                return Err(AuthError::Sso(
                    "email domain not in provider allowlist".into(),
                ));
            }
        }
        let session_ttl = self.session_hours() * 3600;
        let (uid, synced_memberships, user, session, signed, master) = {
            let mut guard = self.inner.write().await;
            let master = guard.master_secret.clone();
            let now = now_unix();
            seed_system_roles(&mut guard.roles, tenant_id, now);
            seed_system_groups(&mut guard.groups, tenant_id, now);
            let existing_id = guard
                .users
                .values()
                .find(|u| u.tenant_id == tenant_id && u.email.eq_ignore_ascii_case(&claims.email))
                .map(|u| u.id.clone());
            let uid = if let Some(id) = existing_id {
                if let Some(u) = guard.users.get_mut(&id) {
                    if u.disabled {
                        return Err(AuthError::AccountDisabled);
                    }
                    u.name.clone_from(&claims.name);
                }
                id
            } else {
                let id = format!("usr-{}", Uuid::new_v4());
                let role = if cfg.default_role.is_empty() {
                    "readonly".to_owned()
                } else {
                    normalize_role(&cfg.default_role)
                };
                guard.users.insert(
                    id.clone(),
                    User {
                        id: id.clone(),
                        tenant_id: tenant_id.to_owned(),
                        email: claims.email.clone(),
                        name: claims.name.clone(),
                        role,
                        provider: format!("sso:{}", cfg.id),
                        subject: claims.subject.clone(),
                        disabled: false,
                        password_hash: String::new(),
                        local_signin_enabled: false,
                        must_change_password: false,
                        password_history: Vec::new(),
                        mfa_enabled: false,
                        mfa_totp_secret: String::new(),
                        mfa_pending_totp_secret: String::new(),
                        mfa_recovery_hashes: Vec::new(),
                        mfa_last_totp_step: 0,
                        webauthn_credentials: Vec::new(),
                    },
                );
                id
            };

            // Sync mapped IdP group memberships automatically on SSO sign-in
            guard.memberships.retain(|m| {
                !(m.tenant_id == tenant_id && m.user_id == uid && m.source == "sso_sync")
            });
            let mapped_groups: Vec<String> = guard
                .idp_mappings
                .iter()
                .filter(|m| {
                    m.tenant_id == tenant_id
                        && m.provider_id == cfg.id
                        && claims
                            .groups
                            .iter()
                            .any(|ext| ext.eq_ignore_ascii_case(&m.external_group))
                })
                .map(|m| m.group_id.clone())
                .collect();
            let mut synced_memberships = Vec::with_capacity(mapped_groups.len());
            for gid in mapped_groups {
                let m = GroupMembership {
                    tenant_id: tenant_id.to_owned(),
                    group_id: gid,
                    user_id: uid.clone(),
                    source: "sso_sync".to_owned(),
                    created_at: now,
                };
                guard.memberships.push(m.clone());
                synced_memberships.push(m);
            }

            let user = guard
                .users
                .get(&uid)
                .cloned()
                .ok_or(AuthError::UserNotFound)?;
            let session = create_session_claims(&mut guard, &user, "sso", session_ttl);
            let signed = sign_session_token(&master, &session.session_id);
            (uid, synced_memberships, user, session, signed, master)
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err("upsert_user", pg.upsert_user(&user, &master).await);
            warn_pg_err(
                "replace_user_memberships",
                pg.replace_user_memberships(tenant_id, &uid, Some("sso_sync"), &synced_memberships)
                    .await,
            );
            warn_pg_err("upsert_session", pg.upsert_session(&session).await);
        }
        Ok((session, signed))
    }

    pub async fn create_scim_token(
        &self,
        tenant_id: &str,
        created_by: &str,
        name: &str,
    ) -> CreatedScimToken {
        let secret = format!("oqscim_{}", random_token_b64());
        let prefix = secret.chars().take(14).collect();
        let token = ScimToken {
            id: format!("scim-{}", Uuid::new_v4()),
            tenant_id: tenant_id.to_owned(),
            name: name.to_owned(),
            prefix,
            created_by: created_by.to_owned(),
            created_at: now_unix(),
            last_used_at: 0,
            revoked_at: 0,
        };
        let token_hash = sha256_hex(secret.as_bytes());
        let rec = ScimTokenRecord {
            meta: token.clone(),
            token_hash: token_hash.clone(),
        };
        self.inner
            .write()
            .await
            .scim_tokens
            .insert(token.id.clone(), rec);
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err(
                "upsert_scim_token",
                pg.upsert_scim_token(&token, &token_hash).await,
            );
        }
        CreatedScimToken { token, secret }
    }

    pub async fn authenticate_scim_bearer(&self, auth_header: &str) -> Result<String, AuthError> {
        let bearer = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .map(str::trim)
            .ok_or(AuthError::ScimUnauthorized)?;
        let hash = sha256_hex(bearer.as_bytes());
        let (tenant_id, meta, token_hash) = {
            let mut guard = self.inner.write().await;
            let rec = guard
                .scim_tokens
                .values_mut()
                .find(|r| r.token_hash == hash && r.meta.revoked_at == 0)
                .ok_or(AuthError::ScimUnauthorized)?;
            rec.meta.last_used_at = now_unix();
            (
                rec.meta.tenant_id.clone(),
                rec.meta.clone(),
                rec.token_hash.clone(),
            )
        };
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err(
                "upsert_scim_token",
                pg.upsert_scim_token(&meta, &token_hash).await,
            );
        }
        Ok(tenant_id)
    }

    pub async fn scim_list_tokens(&self, tenant_id: &str) -> Vec<ScimToken> {
        self.inner
            .read()
            .await
            .scim_tokens
            .values()
            .filter(|r| r.meta.tenant_id == tenant_id)
            .map(|r| r.meta.clone())
            .collect()
    }

    pub async fn scim_revoke_token(&self, tenant_id: &str, id: &str) {
        let updated = {
            let mut guard = self.inner.write().await;
            if let Some(rec) = guard.scim_tokens.get_mut(id) {
                if rec.meta.tenant_id == tenant_id {
                    rec.meta.revoked_at = now_unix();
                    Some((rec.meta.clone(), rec.token_hash.clone()))
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let (Some((meta, hash)), Some(pg)) = (updated, self.pg_pool().await) {
            warn_pg_err(
                "upsert_scim_token",
                pg.upsert_scim_token(&meta, &hash).await,
            );
        }
    }

    pub async fn scim_list_users(&self, tenant_id: &str) -> serde_json::Value {
        let guard = self.inner.read().await;
        let resources: Vec<ScimUserResource> = guard
            .users
            .values()
            .filter(|u| u.tenant_id == tenant_id)
            .map(user_to_scim)
            .collect();
        serde_json::json!({
            "schemas": [SCIM_SCHEMA_LIST],
            "totalResults": resources.len(),
            "startIndex": 1,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        })
    }

    pub async fn scim_create_user(
        &self,
        tenant_id: &str,
        res: ScimUserResource,
    ) -> Result<ScimUserResource, AuthError> {
        let email = res
            .emails
            .iter()
            .find(|e| e.primary)
            .or_else(|| res.emails.first())
            .map_or_else(|| res.user_name.clone(), |e| e.value.clone());
        let display = if res.display_name.is_empty() {
            res.name
                .as_ref()
                .map_or_else(|| email.clone(), |n| n.formatted.clone())
        } else {
            res.display_name
        };
        let created = self
            .create_user(tenant_id, &email, &display, "user", "")
            .await?;
        if !res.active {
            let _ = self
                .update_user_status("scim", tenant_id, &created.id, true)
                .await;
        }
        let guard = self.inner.read().await;
        Ok(guard.users.get(&created.id).map_or_else(
            || {
                user_to_scim(&User {
                    id: created.id,
                    tenant_id: created.tenant_id,
                    email: created.email,
                    name: created.name,
                    role: created.role,
                    provider: created.provider,
                    subject: String::new(),
                    disabled: !res.active,
                    password_hash: String::new(),
                    local_signin_enabled: false,
                    must_change_password: false,
                    password_history: Vec::new(),
                    mfa_enabled: false,
                    mfa_totp_secret: String::new(),
                    mfa_pending_totp_secret: String::new(),
                    mfa_recovery_hashes: Vec::new(),
                    mfa_last_totp_step: 0,
                    webauthn_credentials: Vec::new(),
                })
            },
            user_to_scim,
        ))
    }

    pub async fn scim_patch_user(
        &self,
        tenant_id: &str,
        id: &str,
        patch: &ScimPatchRequest,
    ) -> Result<ScimUserResource, AuthError> {
        for op in patch.ops() {
            let action = op.op.to_ascii_lowercase();
            let op_path = op.path.to_ascii_lowercase();
            if action == "replace" || action == "add" {
                if op_path == "active" {
                    if let Some(active) = op.value.as_bool() {
                        let _ = self
                            .update_user_status("scim", tenant_id, id, !active)
                            .await?;
                    }
                } else if op_path.is_empty() {
                    if let Some(active) =
                        op.value.get("active").and_then(serde_json::Value::as_bool)
                    {
                        let _ = self
                            .update_user_status("scim", tenant_id, id, !active)
                            .await?;
                    }
                }
            }
        }
        let guard = self.inner.read().await;
        guard
            .users
            .get(id)
            .filter(|u| u.tenant_id == tenant_id)
            .map(user_to_scim)
            .ok_or(AuthError::UserNotFound)
    }

    pub async fn scim_list_groups(&self, tenant_id: &str) -> serde_json::Value {
        let guard = self.inner.read().await;
        let resources: Vec<ScimGroupResource> = guard
            .groups
            .values()
            .filter(|g| g.tenant_id == tenant_id)
            .map(|g| group_to_scim(&guard, g))
            .collect();
        serde_json::json!({
            "schemas": [SCIM_SCHEMA_LIST],
            "totalResults": resources.len(),
            "startIndex": 1,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        })
    }

    pub async fn scim_create_group(
        &self,
        tenant_id: &str,
        res: ScimGroupResource,
    ) -> Result<ScimGroupResource, AuthError> {
        let grp = self
            .create_group(tenant_id, &res.display_name, "SCIM 2.0")
            .await?;
        for m in &res.members {
            let _ = self.add_group_member(tenant_id, &grp.id, &m.value).await;
        }
        let guard = self.inner.read().await;
        Ok(group_to_scim(&guard, &grp))
    }

    pub async fn scim_patch_group(
        &self,
        tenant_id: &str,
        group_id: &str,
        patch: &ScimPatchRequest,
    ) -> Result<ScimGroupResource, AuthError> {
        for op in patch.ops() {
            let action = op.op.to_ascii_lowercase();
            let op_path = op.path.to_ascii_lowercase();
            if op_path.starts_with("members") {
                if action == "add" || action == "replace" {
                    if let Some(arr) = op.value.as_array() {
                        for item in arr {
                            if let Some(uid) = item.get("value").and_then(|v| v.as_str()) {
                                let _ = self.add_group_member(tenant_id, group_id, uid).await;
                            }
                        }
                    }
                } else if action == "remove" {
                    if let Some(arr) = op.value.as_array() {
                        for item in arr {
                            if let Some(uid) = item.get("value").and_then(|v| v.as_str()) {
                                self.remove_group_member(tenant_id, group_id, uid).await;
                            }
                        }
                    }
                }
            }
        }
        let guard = self.inner.read().await;
        guard
            .groups
            .get(group_id)
            .filter(|g| g.tenant_id == tenant_id)
            .map(|g| group_to_scim(&guard, g))
            .ok_or(AuthError::GroupNotFound)
    }

    pub async fn scim_get_user(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<ScimUserResource, AuthError> {
        let guard = self.inner.read().await;
        guard
            .users
            .get(id)
            .filter(|u| u.tenant_id == tenant_id)
            .map(user_to_scim)
            .ok_or(AuthError::UserNotFound)
    }

    pub async fn scim_replace_user(
        &self,
        tenant_id: &str,
        id: &str,
        res: &ScimUserResource,
    ) -> Result<ScimUserResource, AuthError> {
        let name = if res.display_name.is_empty() {
            res.name
                .as_ref()
                .map(|n| n.formatted.clone())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| res.user_name.clone())
        } else {
            res.display_name.clone()
        };
        let email = res
            .emails
            .iter()
            .find(|e| e.primary)
            .or_else(|| res.emails.first())
            .map_or_else(|| res.user_name.clone(), |e| e.value.clone());
        let _ = self
            .edit_user(tenant_id, id, Some(&name), Some(&email))
            .await?;
        let _ = self
            .update_user_status("scim", tenant_id, id, !res.active)
            .await?;
        self.scim_get_user(tenant_id, id).await
    }

    pub async fn scim_delete_user(&self, tenant_id: &str, id: &str) -> Result<(), AuthError> {
        self.delete_user("scim", tenant_id, id).await
    }

    pub async fn scim_get_group(
        &self,
        tenant_id: &str,
        group_id: &str,
    ) -> Result<ScimGroupResource, AuthError> {
        let guard = self.inner.read().await;
        guard
            .groups
            .get(group_id)
            .filter(|g| g.tenant_id == tenant_id)
            .map(|g| group_to_scim(&guard, g))
            .ok_or(AuthError::GroupNotFound)
    }

    pub async fn scim_replace_group(
        &self,
        tenant_id: &str,
        group_id: &str,
        res: &ScimGroupResource,
    ) -> Result<ScimGroupResource, AuthError> {
        let _ = self
            .update_group(tenant_id, group_id, &res.display_name, "SCIM 2.0")
            .await?;
        {
            let mut guard = self.inner.write().await;
            guard
                .memberships
                .retain(|m| !(m.tenant_id == tenant_id && m.group_id == group_id));
        }
        if let Some(pg) = self.pg_pool().await {
            warn_pg_err(
                "replace_group_memberships",
                pg.replace_group_memberships(tenant_id, group_id, &[]).await,
            );
        }
        for m in &res.members {
            let _ = self.add_group_member(tenant_id, group_id, &m.value).await;
        }
        self.scim_get_group(tenant_id, group_id).await
    }

    pub async fn scim_delete_group(
        &self,
        tenant_id: &str,
        group_id: &str,
    ) -> Result<(), AuthError> {
        self.delete_group(tenant_id, group_id).await
    }
}

fn user_to_scim(u: &User) -> ScimUserResource {
    ScimUserResource {
        schemas: vec![scim::SCIM_SCHEMA_USER.to_owned()],
        id: u.id.clone(),
        external_id: u.subject.clone(),
        user_name: u.email.clone(),
        display_name: u.name.clone(),
        name: Some(scim::ScimName {
            formatted: u.name.clone(),
        }),
        emails: vec![scim::ScimEmail {
            value: u.email.clone(),
            primary: true,
        }],
        active: !u.disabled,
    }
}

fn group_to_scim(guard: &AuthState, g: &Group) -> ScimGroupResource {
    let members = guard
        .memberships
        .iter()
        .filter(|m| m.tenant_id == g.tenant_id && m.group_id == g.id)
        .filter_map(|m| {
            guard.users.get(&m.user_id).map(|u| ScimMemberRef {
                value: u.id.clone(),
                display: u.email.clone(),
            })
        })
        .collect();
    ScimGroupResource {
        schemas: vec![scim::SCIM_SCHEMA_GROUP.to_owned()],
        id: g.id.clone(),
        external_id: g.external_id.clone(),
        display_name: g.name.clone(),
        members,
    }
}

fn create_session_claims(
    guard: &mut AuthState,
    user: &User,
    method: &str,
    session_ttl_secs: i64,
) -> SessionClaims {
    let now = now_unix();
    let sid = Uuid::new_v4().to_string();
    let (groups, permissions) = compute_effective_rbac(guard, user, None, current_hour_utc());
    let claims = SessionClaims {
        session_id: sid.clone(),
        user_id: user.id.clone(),
        email: user.email.clone(),
        name: user.name.clone(),
        role: user.role.clone(),
        tenant_id: user.tenant_id.clone(),
        method: method.to_owned(),
        issued_at: now,
        expires_at: now + session_ttl_secs,
        last_active_at: now,
        groups,
        permissions,
    };
    guard.sessions.insert(sid, claims.clone());
    claims
}

fn compute_effective_rbac(
    guard: &AuthState,
    user: &User,
    client_ip: Option<IpAddr>,
    hour_utc: u8,
) -> (Vec<String>, Vec<String>) {
    let user_groups: Vec<String> = guard
        .memberships
        .iter()
        .filter(|m| m.tenant_id == user.tenant_id && m.user_id == user.id)
        .map(|m| m.group_id.clone())
        .collect();

    let mut allowed: HashSet<String> = base_role_permissions(&user.role).into_iter().collect();
    let mut denied: HashSet<String> = HashSet::new();

    for binding in guard
        .bindings
        .iter()
        .filter(|b| b.tenant_id == user.tenant_id && user_groups.contains(&b.group_id))
    {
        if !binding.conditions.matches(client_ip, hour_utc) {
            continue;
        }
        if let Some(role) = guard.roles.get(&binding.role_id) {
            for p in &role.permissions {
                match binding.effect {
                    Effect::Allow => {
                        allowed.insert(p.clone());
                    }
                    Effect::Deny => {
                        denied.insert(p.clone());
                    }
                }
            }
        }
    }

    for d in &denied {
        allowed.remove(d);
    }
    let mut perms: Vec<String> = allowed.into_iter().collect();
    perms.sort();
    (user_groups, perms)
}

fn evaluate_scoped_permission(
    guard: &AuthState,
    user: &User,
    permission: &str,
    scope_type: ScopeType,
    scope_id: &str,
    client_ip: Option<IpAddr>,
    hour_utc: u8,
) -> bool {
    if user.disabled {
        return false;
    }
    let user_groups: Vec<String> = guard
        .memberships
        .iter()
        .filter(|m| m.tenant_id == user.tenant_id && m.user_id == user.id)
        .map(|m| m.group_id.clone())
        .collect();

    let base = base_role_permissions(&user.role);
    let mut allowed = base.iter().any(|p| p == perm::ALL || p == permission);
    let mut denied = false;

    for b in guard
        .bindings
        .iter()
        .filter(|b| b.tenant_id == user.tenant_id && user_groups.contains(&b.group_id))
    {
        let scope_matches = b.scope_type == ScopeType::Global
            || (b.scope_type == scope_type
                && (b.scope_id.is_empty() || b.scope_id.eq_ignore_ascii_case(scope_id)));
        if !scope_matches || !b.conditions.matches(client_ip, hour_utc) {
            continue;
        }
        if let Some(role) = guard.roles.get(&b.role_id) {
            let hits = role
                .permissions
                .iter()
                .any(|p| p == perm::ALL || p == permission);
            if hits {
                match b.effect {
                    Effect::Allow => allowed = true,
                    Effect::Deny => denied = true,
                }
            }
        }
    }

    allowed && !denied
}

fn seed_system_roles(roles: &mut HashMap<String, RoleDef>, tenant_id: &str, now: i64) {
    for (id, name, base, desc) in [
        (
            "role-admin",
            "Admin",
            "admin",
            "Full tenant administrative control",
        ),
        (
            "role-user",
            "Operator",
            "user",
            "Standard interactive cloud & desktop session operator",
        ),
        (
            "role-readonly",
            "Viewer",
            "readonly",
            "Read-only fleet & recordings inspector",
        ),
    ] {
        let key = format!("{id}-{tenant_id}");
        roles.entry(key.clone()).or_insert_with(|| RoleDef {
            id: key,
            tenant_id: tenant_id.to_owned(),
            name: name.to_owned(),
            description: desc.to_owned(),
            base_role: base.to_owned(),
            is_system: true,
            permissions: base_role_permissions(base),
            created_at: now,
            updated_at: now,
        });
    }
}

fn seed_system_groups(groups: &mut HashMap<String, Group>, tenant_id: &str, now: i64) {
    for (id, name, desc) in [
        (
            "grp-admins",
            "Administrators",
            "Default tenant administrators group",
        ),
        ("grp-operators", "Operators", "Default operators group"),
        ("grp-viewers", "Viewers", "Default read-only viewers group"),
    ] {
        let key = format!("{id}-{tenant_id}");
        groups.entry(key.clone()).or_insert_with(|| Group {
            id: key,
            tenant_id: tenant_id.to_owned(),
            name: name.to_owned(),
            description: desc.to_owned(),
            source: "local".to_owned(),
            external_id: String::new(),
            is_system: true,
            created_at: now,
            updated_at: now,
        });
    }
}

fn bind_default_group(
    guard: &mut AuthState,
    tenant_id: &str,
    user_id: &str,
    role: &str,
    now: i64,
) -> Option<GroupMembership> {
    let gid = match role {
        "admin" => format!("grp-admins-{tenant_id}"),
        "user" => format!("grp-operators-{tenant_id}"),
        _ => format!("grp-viewers-{tenant_id}"),
    };
    if guard
        .memberships
        .iter()
        .any(|m| m.tenant_id == tenant_id && m.group_id == gid && m.user_id == user_id)
    {
        return None;
    }
    let m = GroupMembership {
        tenant_id: tenant_id.to_owned(),
        group_id: gid,
        user_id: user_id.to_owned(),
        source: "manual".to_owned(),
        created_at: now,
    };
    guard.memberships.push(m.clone());
    Some(m)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn current_hour_utc() -> u8 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    ((secs / 3600) % 24) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign_test_saml_response(
        assertion_id: &str,
        name_id: &str,
        audience: &str,
        recipient: &str,
        not_on_or_after: &str,
        cert: &rcgen::CertifiedKey,
    ) -> String {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
        use sha2::{Digest, Sha256};
        use std::collections::BTreeSet;

        let rng = SystemRandom::new();
        let kp = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &cert.key_pair.serialize_der(),
            &rng,
        )
        .unwrap();

        let unsigned_resp = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Destination="{recipient}"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="{assertion_id}"><saml:Subject><saml:NameID>{name_id}</saml:NameID><saml:SubjectConfirmation><saml:SubjectConfirmationData Recipient="{recipient}" NotOnOrAfter="{not_on_or_after}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="{not_on_or_after}"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="displayName"><saml:AttributeValue>Bob SRE</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups"><saml:AttributeValue>Cloud-SRE</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"#
        );

        let root_dom = xmldsig::parse_xml_dom(&unsigned_resp).unwrap();
        let assertion_dom = root_dom
            .child_elems()
            .into_iter()
            .find(|c| c.local_name() == "Assertion")
            .unwrap();
        let canon_assn = xmldsig::exclusive_canonicalize(
            assertion_dom,
            &[&root_dom],
            None,
            false,
            &BTreeSet::new(),
        );
        let digest_b64 = STANDARD.encode(Sha256::digest(canon_assn.as_bytes()));

        let signed_info_fragment = format!(
            r##"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/><ds:Reference URI="#{assertion_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
        );
        let wrapper_xml = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion ID="{assertion_id}"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info_fragment}</ds:Signature></saml:Assertion></samlp:Response>"#
        );
        let wdom = xmldsig::parse_xml_dom(&wrapper_xml).unwrap();
        let wa = wdom.child_elems()[0];
        let ws = wa.child_elems()[0];
        let wsi = ws.child_elems()[0];
        let canon_si =
            xmldsig::exclusive_canonicalize(wsi, &[&wdom, wa, ws], None, false, &BTreeSet::new());
        let sig_b64 = STANDARD.encode(kp.sign(&rng, canon_si.as_bytes()).unwrap().as_ref());

        let full_sig = format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info_fragment}<ds:SignatureValue>{sig_b64}</ds:SignatureValue></ds:Signature>"#
        );
        unsigned_resp.replacen(
            &format!(r#"<saml:Assertion ID="{assertion_id}">"#),
            &format!(r#"<saml:Assertion ID="{assertion_id}">{full_sig}"#),
            1,
        )
    }

    #[tokio::test]
    async fn enforces_bcrypt_login_last_admin_protection_and_deny_overrides() {
        let auth = AuthService::with_bcrypt_cost(true, Some("BreakGlass!99".into()), 4);
        assert!(auth
            .authenticate_local("default", "admin@local", "wrong")
            .await
            .is_err());

        let (admin_claims, token) = auth
            .authenticate_local("default", "admin@local", "BreakGlass!99")
            .await
            .unwrap();
        assert_eq!(admin_claims.role, "admin");

        let mut hdrs = http::HeaderMap::new();
        hdrs.insert(
            http::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={token}").parse().unwrap(),
        );
        assert!(auth.verify_cookie(&hdrs).await.is_some());

        // Cannot demote or delete last active admin
        assert!(matches!(
            auth.update_user_role("other", "default", &admin_claims.user_id, "user")
                .await,
            Err(AuthError::LastAdmin)
        ));

        // Weak password rejected
        assert!(matches!(
            auth.create_user("default", "weak@corp.io", "Weak", "user", "short1!")
                .await,
            Err(AuthError::WeakPassword(_))
        ));

        // Scoped RBAC deny-overrides + CIDR conditions
        let op = auth
            .create_user("default", "alice@corp.io", "Alice", "user", "AlicePass!12")
            .await
            .unwrap();
        let prod_grp = auth
            .create_group("default", "prod-deny", "Deny prod SSH from off-VPN")
            .await
            .unwrap();
        auth.add_group_member("default", &prod_grp.id, &op.id)
            .await
            .unwrap();
        let ssh_role = auth
            .create_role(
                "default",
                "ssh-role",
                "SSH permission",
                vec![perm::SESSION_SSH.into()],
            )
            .await
            .unwrap();
        auth.bind_group_role(
            "default",
            &prod_grp.id,
            &ssh_role.id,
            ScopeType::Environment,
            "prod",
            Effect::Deny,
            BindingConditions::default(),
        )
        .await
        .unwrap();

        assert!(
            auth.check_permission(
                &op.id,
                perm::SESSION_SSH,
                ScopeType::Environment,
                "dev",
                None
            )
            .await
        );
        assert!(
            !auth
                .check_permission(
                    &op.id,
                    perm::SESSION_SSH,
                    ScopeType::Environment,
                    "prod",
                    None
                )
                .await
        );
    }

    #[tokio::test]
    async fn handles_saml_xml_dsig_anti_xsw_replay_and_scim_v2_revocation() {
        let cert = rcgen::generate_simple_self_signed(vec!["idp.corp.io".into()]).unwrap();
        let other_cert = rcgen::generate_simple_self_signed(vec!["evil.corp.io".into()]).unwrap();
        let cert_pem = cert.cert.pem();

        let auth = AuthService::with_bcrypt_cost(true, Some("AdminPass!12".into()), 4);
        let prod_grp = auth
            .create_group("default", "SRE", "SRE Team")
            .await
            .unwrap();
        let acs_url = "https://operquay.local/api/auth/saml/okta-saml/acs";
        let saml_cfg = SsoProviderConfig {
            id: "okta-saml".into(),
            tenant_id: "default".into(),
            provider_type: "saml".into(),
            label: "Okta SAML".into(),
            entity_id: "https://operquay.local/sp".into(),
            sso_url: "https://okta.example.com/app/sso".into(),
            certificate_pem: cert_pem,
            groups_attribute: "groups".into(),
            default_role: "user".into(),
            allowed_domains: vec!["corp.io".into()],
            ..Default::default()
        };
        auth.upsert_sso_provider(saml_cfg).await;
        auth.create_idp_mapping("default", "okta-saml", "Cloud-SRE", &prod_grp.id)
            .await;

        let redirect = auth
            .start_sso_login("default", "okta-saml", "https://operquay.local")
            .await
            .unwrap();
        assert!(redirect.contains("SAMLRequest="));

        let signed_xml = sign_test_saml_response(
            "_assert_123",
            "bob@corp.io",
            "https://operquay.local/sp",
            acs_url,
            "2099-01-01T00:00:00Z",
            &cert,
        );
        let b64 = crypto::b64_encode(signed_xml.as_bytes());
        let (claims, _) = auth
            .finish_saml_acs("default", "okta-saml", &b64, acs_url)
            .await
            .unwrap();
        assert_eq!(claims.email, "bob@corp.io");
        assert!(claims.groups.contains(&prod_grp.id));

        // Replaying same Assertion ID is rejected
        assert!(auth
            .finish_saml_acs("default", "okta-saml", &b64, acs_url)
            .await
            .is_err());

        // Unsigned SAMLResponse rejected
        let unsigned_xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_unsigned"><saml:Subject><saml:NameID>bob@corp.io</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"#;
        assert!(auth
            .finish_saml_acs(
                "default",
                "okta-saml",
                &crypto::b64_encode(unsigned_xml.as_bytes()),
                acs_url
            )
            .await
            .is_err());

        // Tampered payload rejected (DigestValue mismatch)
        let tampered = signed_xml.replace("bob@corp.io", "evil@corp.io");
        assert!(auth
            .finish_saml_acs(
                "default",
                "okta-saml",
                &crypto::b64_encode(tampered.as_bytes()),
                acs_url
            )
            .await
            .is_err());

        // Wrong signing key rejected
        let wrong_key_xml = sign_test_saml_response(
            "_assert_wrong",
            "bob@corp.io",
            "https://operquay.local/sp",
            acs_url,
            "2099-01-01T00:00:00Z",
            &other_cert,
        );
        assert!(auth
            .finish_saml_acs(
                "default",
                "okta-saml",
                &crypto::b64_encode(wrong_key_xml.as_bytes()),
                acs_url
            )
            .await
            .is_err());

        // Anti-XSW: extra sibling unsigned Assertion rejected
        let xsw_xml = signed_xml.replace(
            "</samlp:Response>",
            r#"<saml:Assertion ID="_evil"><saml:Subject><saml:NameID>admin@corp.io</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"#,
        );
        assert!(auth
            .finish_saml_acs(
                "default",
                "okta-saml",
                &crypto::b64_encode(xsw_xml.as_bytes()),
                acs_url
            )
            .await
            .is_err());

        // Expired NotOnOrAfter rejected
        let expired_xml = sign_test_saml_response(
            "_assert_exp",
            "bob@corp.io",
            "https://operquay.local/sp",
            acs_url,
            "2020-01-02T00:00:00Z",
            &cert,
        );
        assert!(auth
            .finish_saml_acs(
                "default",
                "okta-saml",
                &crypto::b64_encode(expired_xml.as_bytes()),
                acs_url
            )
            .await
            .is_err());

        // Wrong Audience rejected
        let wrong_aud_xml = sign_test_saml_response(
            "_assert_aud",
            "bob@corp.io",
            "https://other-sp.local/sp",
            acs_url,
            "2099-01-01T00:00:00Z",
            &cert,
        );
        assert!(auth
            .finish_saml_acs(
                "default",
                "okta-saml",
                &crypto::b64_encode(wrong_aud_xml.as_bytes()),
                acs_url
            )
            .await
            .is_err());

        // SCIM v2 Token + Provisioning
        let created_tok = auth
            .create_scim_token("default", "admin", "Okta SCIM")
            .await;
        let tid = auth
            .authenticate_scim_bearer(&format!("Bearer {}", created_tok.secret))
            .await
            .unwrap();
        assert_eq!(tid, "default");

        let provisioned = auth
            .scim_create_user(
                "default",
                serde_json::from_value(serde_json::json!({
                    "userName": "carol@corp.io",
                    "displayName": "Carol Ops",
                    "active": true
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(provisioned.user_name, "carol@corp.io");
    }

    #[test]
    fn verifies_oidc_jwks_signatures_and_rejects_alg_none_and_hs_confusion() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let jwks = JwkSet {
            keys: vec![sso::JwkKey {
                kty: "OKP".into(),
                kid: Some("k1".into()),
                key_use: Some("sig".into()),
                alg: Some("EdDSA".into()),
                crv: Some("Ed25519".into()),
                x: Some(URL_SAFE_NO_PAD.encode(kp.public_key().as_ref())),
                n: None,
                e: None,
                y: None,
            }],
        };

        let now = 1_700_000_000i64;
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::json!({ "alg": "EdDSA", "kid": "k1", "typ": "JWT" })
                .to_string()
                .as_bytes(),
        );
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": "https://idp.example.com",
                "sub": "u123",
                "aud": "client-1",
                "nonce": "nonce-xyz",
                "exp": now + 600,
                "nbf": now - 10,
                "email": "eng@corp.io",
                "email_verified": true
            })
            .to_string()
            .as_bytes(),
        );
        let input = format!("{header}.{payload}");
        let sig = URL_SAFE_NO_PAD.encode(kp.sign(input.as_bytes()).as_ref());
        let jwt = format!("{input}.{sig}");

        let params = OidcValidationParams {
            issuer: "https://idp.example.com",
            client_id: "client-1",
            nonce: Some("nonce-xyz"),
            now_unix: now,
            require_email_verified: true,
        };
        let verified = verify_oidc_id_token(&jwt, &jwks, &params).unwrap();
        assert_eq!(verified["email"], "eng@corp.io");

        let none_hdr = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        assert!(
            verify_oidc_id_token(&format!("{none_hdr}.{payload}.{sig}"), &jwks, &params).is_err()
        );

        let hs_hdr = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","kid":"k1"}"#);
        assert!(
            verify_oidc_id_token(&format!("{hs_hdr}.{payload}.{sig}"), &jwks, &params).is_err()
        );

        assert!(verify_oidc_id_token(
            &jwt,
            &jwks,
            &OidcValidationParams {
                issuer: "https://other.example.com",
                ..params
            }
        )
        .is_err());
        assert!(verify_oidc_id_token(
            &jwt,
            &jwks,
            &OidcValidationParams {
                nonce: Some("wrong-nonce"),
                ..params
            }
        )
        .is_err());
        assert!(verify_oidc_id_token(
            &jwt,
            &jwks,
            &OidcValidationParams {
                now_unix: now + 5000,
                ..params
            }
        )
        .is_err());
    }

    #[tokio::test]
    async fn enforces_lockout_password_history_totp_mfa_and_instant_revocation() {
        let auth = AuthService::with_bcrypt_cost(true, Some("BreakGlass!99".into()), 4);
        let user = auth
            .create_user("default", "sec@corp.io", "Sec", "user", "StrongPass#2026")
            .await
            .unwrap();

        assert!(matches!(
            auth.change_password(
                "default",
                &user.id,
                Some("StrongPass#2026"),
                "StrongPass#2026"
            )
            .await,
            Err(AuthError::WeakPassword(_))
        ));

        for _ in 0..4 {
            assert!(matches!(
                auth.authenticate_local_with_context(
                    "default",
                    "sec@corp.io",
                    "bad",
                    "10.1.2.3",
                    None,
                    None
                )
                .await,
                Err(AuthError::InvalidCredentials)
            ));
        }
        assert!(matches!(
            auth.authenticate_local_with_context(
                "default",
                "sec@corp.io",
                "bad",
                "10.1.2.3",
                None,
                None
            )
            .await,
            Err(AuthError::AccountLocked { .. })
        ));

        let u2 = auth
            .create_user(
                "default",
                "mfa@corp.io",
                "MfaUser",
                "user",
                "MfaStrongPass#2026",
            )
            .await
            .unwrap();
        let (s2, uri) = auth.begin_totp_setup("default", &u2.id).await.unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        let otp_enroll = mfa::compute_totp_code(&s2, (now_unix() / 30) - 1).unwrap();
        let rec2 = auth
            .confirm_totp_setup("default", &u2.id, &otp_enroll)
            .await
            .unwrap();
        assert_eq!(rec2.len(), 8);

        let chal = match auth
            .authenticate_local("default", "mfa@corp.io", "MfaStrongPass#2026")
            .await
        {
            Err(AuthError::MfaRequired { challenge, .. }) => challenge,
            other => panic!("expected MfaRequired, got {other:?}"),
        };
        let (sess, tok) = auth
            .complete_mfa_challenge("default", &chal, None, Some(&rec2[0]))
            .await
            .unwrap();
        assert!(
            auth.is_session_active("default", &sess.session_id, &u2.id)
                .await
        );

        let mut hdrs = http::HeaderMap::new();
        hdrs.insert(
            http::header::COOKIE,
            format!("{HOST_SESSION_COOKIE_NAME}={tok}").parse().unwrap(),
        );
        assert!(auth.verify_cookie(&hdrs).await.is_some());

        auth.update_user_status("admin", "default", &u2.id, true)
            .await
            .unwrap();
        assert!(
            !auth
                .is_session_active("default", &sess.session_id, &u2.id)
                .await
        );
        assert!(auth.verify_cookie(&hdrs).await.is_none());
    }

    #[test]
    fn extract_tenant_ignores_raw_ip_addresses() {
        for (host, expected) in [
            ("127.0.0.1:8080", "default"),
            ("10.0.1.5", "default"),
            ("[::1]:8080", "default"),
            ("localhost:8080", "default"),
            ("acme.operquay.io:8080", "acme"),
        ] {
            let mut h = http::HeaderMap::new();
            h.insert(
                http::header::HOST,
                http::HeaderValue::from_str(host).unwrap(),
            );
            assert_eq!(crypto::extract_tenant_id(&h), expected, "host={host}");
        }
    }
}
