#![forbid(unsafe_code)]

//! PostgreSQL multi-tenant RLS (`app.tenant_id`) repository helpers for auth,
//! sessions, MFA, groups, custom roles, role bindings, `IdP` mappings, SSO providers,
//! and SCIM tokens (`migrations/0002_full_platform_schema.sql` & `0003_m9_security_hardening.sql`).

use std::sync::Arc;

use tokio::sync::Mutex;
use tokio_postgres::{Client, NoTls, Transaction};

use crate::crypto::{fill_csprng, open_aead_versioned, seal_aead_versioned, KeyRing};
use crate::mfa::WebAuthnCredential;
use crate::policy::{BindingConditions, Effect, ScopeType};
use crate::scim::ScimToken;
use crate::sso::SsoProviderConfig;
use crate::{
    Group, GroupMembership, GroupRoleBinding, IdPGroupMapping, RoleDef, SessionClaims, User,
};

#[derive(Debug, Clone)]
pub struct PgAwsSsoProviderRow {
    pub id: String,
    pub tenant_id: String,
    pub label: String,
    pub start_url: String,
    pub region: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct PgAuditRow {
    pub tenant_id: String,
    pub user_id: String,
    pub action: String,
    pub target: String,
    pub event_json: String,
    pub seq: i64,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone)]
pub struct PgRecordingMetaRow {
    pub id: String,
    pub tenant_id: String,
    pub protocol: String,
    pub target_host: String,
    pub format: String,
    pub started_at_ms: i64,
    pub bytes_written: i64,
    pub frame_count: i64,
    pub sha256_hex: String,
    pub fail_closed: bool,
    pub status: String,
    pub encrypted: bool,
    pub legal_hold: bool,
    pub legal_hold_reason: String,
    pub retention_until_ms: Option<i64>,
    pub archived_s3_uri: Option<String>,
    pub archived_at_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct PgAwsSsoSessionRow {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub region: String,
    pub start_url: String,
    pub token_state_json: String,
    pub expires_at: i64,
    pub cancelled: bool,
}

#[derive(Debug, Clone)]
pub struct PgAwsRoleLeaseRow {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub binding_id: String,
    pub label: String,
    pub account_id: String,
    pub role_arn: String,
    pub role_name: String,
    pub start_url: String,
    pub region: String,
    pub status: String,
    pub credential_revision: String,
    pub connected_at: i64,
    pub expires_at: i64,
    pub credentials_json: String,
}

#[derive(Debug, Clone)]
pub struct PgAwsRoleBindingRow {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub role_arn: String,
    pub label: String,
    pub payload_json: String,
}

#[derive(Debug, Clone)]
pub struct PgAwsDiscoveryRow {
    pub tenant_id: String,
    pub instances_json: String,
    pub status_json: String,
}

#[derive(Debug, Clone)]
pub struct PgAwsSavedInventoryRow {
    pub tenant_id: String,
    pub user_id: String,
    pub items_json: String,
}

#[derive(Debug, Clone)]
pub struct PgAwsCloneRow {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub source_instance_id: String,
    pub status: String,
    pub payload_json: String,
}

#[derive(Debug, Clone)]
pub struct PgUserPrefsRow {
    pub tenant_id: String,
    pub user_id: String,
    pub prefs_json: String,
}

#[derive(Debug, Clone)]
pub struct PgTenantKeyRow {
    pub tenant_id: String,
    pub dek: Option<[u8; 32]>,
    pub shredded: bool,
}

#[derive(Debug, Clone)]
pub struct PgJitAccessRequestRow {
    pub id: String,
    pub tenant_id: String,
    pub requester_user_id: String,
    pub requester_email: String,
    pub target_type: String,
    pub target_id: String,
    pub requested_role: String,
    pub duration_secs: i64,
    pub reason: String,
    pub ticket_id: String,
    pub ticket_provider: String,
    pub status: String,
    pub approver_user_id: Option<String>,
    pub approver_email: Option<String>,
    pub decision_note: String,
    pub created_at: i64,
    pub decided_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub payload_json: String,
}

#[derive(Debug, Clone)]
pub struct PgGovernanceWebhookRow {
    pub id: String,
    pub tenant_id: String,
    pub provider: String,
    pub name: String,
    pub url: String,
    pub secret: String,
    pub events_json: String,
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct PgDlpPolicyRow {
    pub tenant_id: String,
    pub policy_json: String,
}

#[derive(Debug, Clone)]
pub struct PgSessionRiskBookmarkRow {
    pub id: String,
    pub tenant_id: String,
    pub recording_id: String,
    pub session_id: String,
    pub offset_secs: f64,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub detail: String,
    pub source: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct PgAccessReviewCampaignRow {
    pub id: String,
    pub tenant_id: String,
    pub title: String,
    pub quarter: String,
    pub status: String,
    pub created_by: String,
    pub created_at: i64,
    pub completed_at: Option<i64>,
    pub payload_json: String,
}

#[derive(Debug, Clone)]
pub struct PgMcpAgentRow {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub sponsor_user_id: String,
    pub sponsor_email: String,
    pub token_hash: String,
    pub allowed_tools_json: String,
    pub require_jit_tools_json: String,
    pub rate_limit_per_min: i32,
    pub status: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub payload_json: String,
}

#[derive(Debug, Clone)]
pub struct PgMcpInvocationRow {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub sponsor_user_id: String,
    pub tool_name: String,
    pub sanitized_args: String,
    pub decision: String,
    pub jit_request_id: Option<String>,
    pub masked_result_preview: String,
    pub duration_ms: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct PgHybridAgentRow {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub enrollment_token_hash: String,
    pub cert_fingerprint_sha256: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub labels_json: String,
    pub targets_json: String,
    pub status: String,
    pub last_heartbeat_at: Option<i64>,
    pub created_at: i64,
    pub payload_json: String,
}

#[derive(Debug, Clone)]
pub struct PgCloudConnectorRow {
    pub id: String,
    pub tenant_id: String,
    pub provider: String,
    pub name: String,
    pub account_or_project_id: String,
    pub tenant_or_org_id: String,
    pub region: String,
    pub credentials_json: String,
    pub config_json: String,
    pub status: String,
    pub last_synced_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct PgDeviceTrustPolicyRow {
    pub tenant_id: String,
    pub policy_json: String,
}

#[derive(Debug, Clone)]
pub struct PgDevicePostureRow {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub device_id: String,
    pub provider: String,
    pub hostname: String,
    pub os_version: String,
    pub disk_encrypted: bool,
    pub edr_running: bool,
    pub edr_agent: String,
    pub os_patch_age_days: i32,
    pub compliant: bool,
    pub reasons_json: String,
    pub attested_at: i64,
    pub expires_at: i64,
}

/// Full hydrated snapshot loaded from PostgreSQL at server startup.
#[derive(Debug, Default)]
pub struct PgAuthSnapshot {
    pub master_secret: Vec<u8>,
    pub users: Vec<User>,
    pub roles: Vec<RoleDef>,
    pub groups: Vec<Group>,
    pub memberships: Vec<GroupMembership>,
    pub bindings: Vec<GroupRoleBinding>,
    pub idp_mappings: Vec<IdPGroupMapping>,
    pub scim_tokens: Vec<(ScimToken, String)>,
    pub sso_providers: Vec<SsoProviderConfig>,
    pub sessions: Vec<SessionClaims>,
}

/// Thread-safe handle to an optional PostgreSQL connection configured for fail-closed RLS.
#[derive(Clone)]
pub struct PgAuthPool {
    client: Arc<Mutex<Client>>,
    master_secret: Arc<tokio::sync::RwLock<Vec<u8>>>,
}

impl PgAuthPool {
    /// Connect to a PostgreSQL DSN (`host=... dbname=...`) and spawn the I/O task.
    pub async fn connect(dsn: &str) -> Result<Self, String> {
        let (client, connection) = tokio_postgres::connect(dsn, NoTls)
            .await
            .map_err(|e| format!("postgres connect error: {e}"))?;
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::error!(error = %err, "postgres auth connection terminated");
            }
        });
        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            master_secret: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        })
    }

    /// Return the cluster master secret cached from `auth_cluster_state` (available after `load_snapshot`).
    pub async fn master_secret(&self) -> Vec<u8> {
        self.master_secret.read().await.clone()
    }

    async fn begin_tenant_tx<'a>(
        client: &'a mut Client,
        tenant_id: &str,
    ) -> Result<Transaction<'a>, String> {
        let tx = client
            .transaction()
            .await
            .map_err(|e| format!("begin tx: {e}"))?;
        tx.execute(
            "INSERT INTO tenants (id, name) VALUES ($1, $1) ON CONFLICT (id) DO NOTHING",
            &[&tenant_id],
        )
        .await
        .map_err(|e| format!("ensure tenant in tx: {e}"))?;
        tx.execute(
            "SELECT set_config('app.tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await
        .map_err(|e| format!("set app.tenant_id: {e}"))?;
        Ok(tx)
    }

    /// Ensure tenant row exists before writing child records under RLS.
    pub async fn ensure_tenant(&self, tenant_id: &str, name: &str) -> Result<(), String> {
        let guard = self.client.lock().await;
        guard
            .execute(
                "INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING",
                &[&tenant_id, &name],
            )
            .await
            .map_err(|e| format!("ensure_tenant: {e}"))?;
        Ok(())
    }

    /// Persist or update a user record (including encrypted TOTP secret & passkeys) inside a tenant-scoped RLS transaction.
    pub async fn upsert_user(&self, user: &User, master_secret: &[u8]) -> Result<(), String> {
        let pw_history_text = serde_json::to_string(&user.password_history)
            .map_err(|e| format!("pw history: {e}"))?;
        let rec_hashes_text = serde_json::to_string(&user.mfa_recovery_hashes)
            .map_err(|e| format!("rec hashes: {e}"))?;
        let webauthn_text = serde_json::to_string(&user.webauthn_credentials)
            .map_err(|e| format!("webauthn json: {e}"))?;
        let totp_enc = if user.mfa_totp_secret.is_empty() {
            Vec::new()
        } else {
            let ring = KeyRing::from_master_and_env(master_secret, b"operquay/mfa-totp/v1");
            seal_aead_versioned(&ring, user.id.as_bytes(), user.mfa_totp_secret.as_bytes())?
        };

        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &user.tenant_id).await?;
        let status = if user.disabled { "disabled" } else { "active" };
        tx.execute(
            "INSERT INTO users (id, tenant_id, email, name, role, password_hash, status, mfa_enabled, provider, subject, local_signin_enabled, must_change_password, password_history, mfa_totp_secret_enc, mfa_recovery_hashes, mfa_webauthn_creds, mfa_last_totp_step) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::text::jsonb, $14, $15::text::jsonb, $16::text::jsonb, $17) \
             ON CONFLICT (id) DO UPDATE SET \
             email = EXCLUDED.email, name = EXCLUDED.name, role = EXCLUDED.role, \
             password_hash = EXCLUDED.password_hash, status = EXCLUDED.status, \
             mfa_enabled = EXCLUDED.mfa_enabled, provider = EXCLUDED.provider, \
             subject = EXCLUDED.subject, local_signin_enabled = EXCLUDED.local_signin_enabled, \
             must_change_password = EXCLUDED.must_change_password, \
             password_history = EXCLUDED.password_history, \
             mfa_totp_secret_enc = EXCLUDED.mfa_totp_secret_enc, \
             mfa_recovery_hashes = EXCLUDED.mfa_recovery_hashes, \
             mfa_webauthn_creds = EXCLUDED.mfa_webauthn_creds, \
             mfa_last_totp_step = EXCLUDED.mfa_last_totp_step",
            &[
                &user.id,
                &user.tenant_id,
                &user.email,
                &user.name,
                &user.role,
                &user.password_hash,
                &status,
                &user.mfa_enabled,
                &user.provider,
                &user.subject,
                &user.local_signin_enabled,
                &user.must_change_password,
                &pw_history_text,
                &totp_enc,
                &rec_hashes_text,
                &webauthn_text,
                &user.mfa_last_totp_step,
            ],
        )
        .await
        .map_err(|e| format!("upsert_user: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    async fn delete_in_tenant_by_id(
        &self,
        tenant_id: &str,
        queries: &[&str],
        id: &str,
    ) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, tenant_id).await?;
        for sql in queries {
            tx.execute(*sql, &[&tenant_id, &id])
                .await
                .map_err(|e| format!("delete_in_tenant: {e}"))?;
        }
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn delete_user(&self, tenant_id: &str, user_id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &[
                "DELETE FROM group_memberships WHERE tenant_id = $1 AND user_id = $2",
                "DELETE FROM auth_sessions WHERE tenant_id = $1 AND user_id = $2",
                "DELETE FROM users WHERE tenant_id = $1 AND id = $2",
            ],
            user_id,
        )
        .await
    }

    pub async fn delete_user_sessions(&self, tenant_id: &str, user_id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &["DELETE FROM auth_sessions WHERE tenant_id = $1 AND user_id = $2"],
            user_id,
        )
        .await
    }

    pub async fn is_session_valid(
        &self,
        tenant_id: &str,
        session_id: &str,
        user_id: &str,
    ) -> Result<bool, String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, tenant_id).await?;
        let user_row = tx
            .query_opt(
                "SELECT status FROM users WHERE tenant_id = $1 AND id = $2",
                &[&tenant_id, &user_id],
            )
            .await
            .map_err(|e| format!("is_session_valid user: {e}"))?;
        let user_active = user_row.is_some_and(|r| {
            let st: String = r.get(0);
            st != "disabled"
        });
        if !user_active {
            let _ = tx.commit().await;
            return Ok(false);
        }
        let sess_row = tx
            .query_opt(
                "SELECT 1 FROM auth_sessions WHERE tenant_id = $1 AND session_id = $2 AND user_id = $3 AND expires_at > NOW()",
                &[&tenant_id, &session_id, &user_id],
            )
            .await
            .map_err(|e| format!("is_session_valid sess: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
        Ok(sess_row.is_some())
    }

    pub async fn upsert_role(&self, role: &RoleDef) -> Result<(), String> {
        let perms_text =
            serde_json::to_string(&role.permissions).map_err(|e| format!("perms json: {e}"))?;
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &role.tenant_id).await?;
        tx.execute(
            "INSERT INTO roles (tenant_id, id, name, description, base_role, is_system, permissions, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7::text::jsonb, $8, $9) \
             ON CONFLICT (tenant_id, id) DO UPDATE SET \
             name = EXCLUDED.name, description = EXCLUDED.description, permissions = EXCLUDED.permissions, updated_at = EXCLUDED.updated_at",
            &[
                &role.tenant_id,
                &role.id,
                &role.name,
                &role.description,
                &role.base_role,
                &role.is_system,
                &perms_text,
                &role.created_at,
                &role.updated_at,
            ],
        )
        .await
        .map_err(|e| format!("upsert_role: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn upsert_group(&self, group: &Group) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &group.tenant_id).await?;
        tx.execute(
            "INSERT INTO groups (id, tenant_id, name, description, source, is_system, external_id, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, updated_at = EXCLUDED.updated_at",
            &[
                &group.id,
                &group.tenant_id,
                &group.name,
                &group.description,
                &group.source,
                &group.is_system,
                &group.external_id,
                &group.created_at,
                &group.updated_at,
            ],
        )
        .await
        .map_err(|e| format!("upsert_group: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn upsert_binding(&self, b: &GroupRoleBinding) -> Result<(), String> {
        let cond_text =
            serde_json::to_string(&b.conditions).map_err(|e| format!("cond json: {e}"))?;
        let scope_str = match b.scope_type {
            ScopeType::Global => "global",
            ScopeType::Environment => "environment",
            ScopeType::Instance => "instance",
            ScopeType::Cluster => "cluster",
        };
        let effect_str = match b.effect {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
        };
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &b.tenant_id).await?;
        tx.execute(
            "INSERT INTO group_role_bindings (id, tenant_id, group_id, role_id, scope_type, scope_id, effect, conditions, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text::jsonb, $9) \
             ON CONFLICT (id) DO UPDATE SET effect = EXCLUDED.effect, conditions = EXCLUDED.conditions",
            &[
                &b.id,
                &b.tenant_id,
                &b.group_id,
                &b.role_id,
                &scope_str,
                &b.scope_id,
                &effect_str,
                &cond_text,
                &b.created_at,
            ],
        )
        .await
        .map_err(|e| format!("upsert_binding: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn upsert_idp_mapping(&self, m: &IdPGroupMapping) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &m.tenant_id).await?;
        tx.execute(
            "INSERT INTO idp_group_mappings (id, tenant_id, provider_id, external_group, group_id, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (id) DO UPDATE SET external_group = EXCLUDED.external_group, group_id = EXCLUDED.group_id",
            &[
                &m.id,
                &m.tenant_id,
                &m.provider_id,
                &m.external_group,
                &m.group_id,
                &m.created_at,
            ],
        )
        .await
        .map_err(|e| format!("upsert_idp_mapping: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn upsert_scim_token(&self, t: &ScimToken, token_hash: &str) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &t.tenant_id).await?;
        tx.execute(
            "INSERT INTO scim_tokens (id, tenant_id, name, token_hash, prefix, created_by, created_at, last_used_at, revoked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (id) DO UPDATE SET last_used_at = EXCLUDED.last_used_at, revoked_at = EXCLUDED.revoked_at",
            &[
                &t.id,
                &t.tenant_id,
                &t.name,
                &token_hash,
                &t.prefix,
                &t.created_by,
                &t.created_at,
                &t.last_used_at,
                &t.revoked_at,
            ],
        )
        .await
        .map_err(|e| format!("upsert_scim_token: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    #[must_use]
    pub fn parse_binding_fields(
        scope: &str,
        effect: &str,
        cond_json: &serde_json::Value,
    ) -> (ScopeType, Effect, BindingConditions) {
        let s = match scope {
            "environment" => ScopeType::Environment,
            "instance" => ScopeType::Instance,
            "cluster" => ScopeType::Cluster,
            _ => ScopeType::Global,
        };
        let eff = if effect.eq_ignore_ascii_case("deny") {
            Effect::Deny
        } else {
            Effect::Allow
        };
        let cond = serde_json::from_value(cond_json.clone()).unwrap_or_default();
        (s, eff, cond)
    }

    pub async fn delete_role(&self, tenant_id: &str, role_id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &[
                "DELETE FROM group_role_bindings WHERE tenant_id = $1 AND role_id = $2",
                "DELETE FROM roles WHERE tenant_id = $1 AND id = $2",
            ],
            role_id,
        )
        .await
    }

    pub async fn delete_group(&self, tenant_id: &str, group_id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &[
                "DELETE FROM group_memberships WHERE tenant_id = $1 AND group_id = $2",
                "DELETE FROM group_role_bindings WHERE tenant_id = $1 AND group_id = $2",
                "DELETE FROM groups WHERE tenant_id = $1 AND id = $2",
            ],
            group_id,
        )
        .await
    }

    pub async fn upsert_membership(&self, m: &GroupMembership) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &m.tenant_id).await?;
        Self::insert_membership_tx(&tx, m).await?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    async fn insert_membership_tx(tx: &Transaction<'_>, m: &GroupMembership) -> Result<(), String> {
        tx.execute(
            "INSERT INTO group_memberships (tenant_id, group_id, user_id, source, created_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (tenant_id, group_id, user_id) DO UPDATE SET source = EXCLUDED.source",
            &[
                &m.tenant_id,
                &m.group_id,
                &m.user_id,
                &m.source,
                &m.created_at,
            ],
        )
        .await
        .map(|_| ())
        .map_err(|e| format!("upsert_membership: {e}"))
    }

    pub async fn delete_group_member(
        &self,
        tenant_id: &str,
        group_id: &str,
        user_id: &str,
    ) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, tenant_id).await?;
        tx.execute(
            "DELETE FROM group_memberships WHERE tenant_id = $1 AND group_id = $2 AND user_id = $3",
            &[&tenant_id, &group_id, &user_id],
        )
        .await
        .map_err(|e| format!("delete_group_member: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn replace_user_memberships(
        &self,
        tenant_id: &str,
        user_id: &str,
        source_filter: Option<&str>,
        items: &[GroupMembership],
    ) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, tenant_id).await?;
        match source_filter {
            Some(src) => {
                tx.execute(
                    "DELETE FROM group_memberships WHERE tenant_id = $1 AND user_id = $2 AND source = $3",
                    &[&tenant_id, &user_id, &src],
                )
                .await
            }
            None => {
                tx.execute(
                    "DELETE FROM group_memberships WHERE tenant_id = $1 AND user_id = $2",
                    &[&tenant_id, &user_id],
                )
                .await
            }
        }
        .map_err(|e| format!("clear user memberships: {e}"))?;
        for m in items {
            Self::insert_membership_tx(&tx, m).await?;
        }
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn replace_group_memberships(
        &self,
        tenant_id: &str,
        group_id: &str,
        items: &[GroupMembership],
    ) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, tenant_id).await?;
        tx.execute(
            "DELETE FROM group_memberships WHERE tenant_id = $1 AND group_id = $2",
            &[&tenant_id, &group_id],
        )
        .await
        .map_err(|e| format!("clear group memberships: {e}"))?;
        for m in items {
            Self::insert_membership_tx(&tx, m).await?;
        }
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn delete_binding(&self, tenant_id: &str, binding_id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &["DELETE FROM group_role_bindings WHERE tenant_id = $1 AND id = $2"],
            binding_id,
        )
        .await
    }

    pub async fn delete_idp_mapping(&self, tenant_id: &str, id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &["DELETE FROM idp_group_mappings WHERE tenant_id = $1 AND id = $2"],
            id,
        )
        .await
    }

    pub async fn upsert_sso_provider(
        &self,
        cfg: &SsoProviderConfig,
        master_secret: &[u8],
    ) -> Result<(), String> {
        let sealed = cfg.seal(master_secret)?;
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &cfg.tenant_id).await?;
        tx.execute(
            "INSERT INTO sso_providers (id, tenant_id, provider_type, label, encrypted_config) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (id) DO UPDATE SET provider_type = EXCLUDED.provider_type, \
             label = EXCLUDED.label, encrypted_config = EXCLUDED.encrypted_config",
            &[
                &cfg.id,
                &cfg.tenant_id,
                &cfg.provider_type,
                &cfg.label,
                &sealed,
            ],
        )
        .await
        .map_err(|e| format!("upsert_sso_provider: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn delete_sso_provider(&self, tenant_id: &str, id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &["DELETE FROM sso_providers WHERE tenant_id = $1 AND id = $2"],
            id,
        )
        .await
    }

    pub async fn upsert_session(&self, s: &SessionClaims) -> Result<(), String> {
        let payload_text = serde_json::to_string(s).map_err(|e| format!("session json: {e}"))?;
        #[allow(clippy::cast_precision_loss)]
        let expires_f64 = s.expires_at as f64;
        #[allow(clippy::cast_precision_loss)]
        let last_active_f64 = s.last_active_at as f64;
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &s.tenant_id).await?;
        tx.execute(
            "INSERT INTO auth_sessions (session_id, tenant_id, user_id, expires_at, last_active_at, payload) \
             VALUES ($1, $2, $3, TO_TIMESTAMP($4), TO_TIMESTAMP($5), $6::text::jsonb) \
             ON CONFLICT (session_id) DO UPDATE SET last_active_at = EXCLUDED.last_active_at, \
             expires_at = EXCLUDED.expires_at, payload = EXCLUDED.payload",
            &[
                &s.session_id,
                &s.tenant_id,
                &s.user_id,
                &expires_f64,
                &last_active_f64,
                &payload_text,
            ],
        )
        .await
        .map_err(|e| format!("upsert_session: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn delete_session(&self, tenant_id: &str, session_id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &["DELETE FROM auth_sessions WHERE tenant_id = $1 AND session_id = $2"],
            session_id,
        )
        .await
    }

    async fn ensure_master_secret(client: &Client, candidate: &[u8]) -> Result<Vec<u8>, String> {
        client
            .execute(
                "INSERT INTO auth_cluster_state (id, master_secret) VALUES (TRUE, $1) ON CONFLICT (id) DO NOTHING",
                &[&candidate],
            )
            .await
            .map_err(|e| format!("seed auth_cluster_state: {e}"))?;
        let row = client
            .query_one(
                "SELECT master_secret FROM auth_cluster_state WHERE id = TRUE",
                &[],
            )
            .await
            .map_err(|e| format!("load auth_cluster_state: {e}"))?;
        Ok(row.get(0))
    }

    async fn list_tenant_ids(client: &Client) -> Result<Vec<String>, String> {
        let rows = client
            .query("SELECT id FROM tenants ORDER BY id", &[])
            .await
            .map_err(|e| format!("list tenants: {e}"))?;
        Ok(rows.into_iter().map(|r| r.get(0)).collect())
    }

    async fn load_users_and_roles(
        tx: &Transaction<'_>,
        master_secret: &[u8],
    ) -> Result<(Vec<User>, Vec<RoleDef>), String> {
        let totp_ring = KeyRing::from_master_and_env(master_secret, b"operquay/mfa-totp/v1");
        let u_rows = tx
            .query(
                "SELECT id, tenant_id, email, name, role, password_hash, status, mfa_enabled, provider, subject, local_signin_enabled, must_change_password, password_history::text, mfa_totp_secret_enc, mfa_recovery_hashes::text, mfa_webauthn_creds::text, mfa_last_totp_step FROM users",
                &[],
            )
            .await
            .map_err(|e| format!("load users: {e}"))?;
        let users = u_rows
            .into_iter()
            .map(|r| {
                let id: String = r.get(0);
                let status: String = r.get(6);
                let pw_hist_raw: String = r.get(12);
                let totp_enc: Vec<u8> = r.get(13);
                let rec_raw: String = r.get(14);
                let wa_raw: String = r.get(15);
                let mfa_totp_secret = if totp_enc.is_empty() {
                    String::new()
                } else {
                    open_aead_versioned(&totp_ring, id.as_bytes(), &totp_enc)
                        .ok()
                        .and_then(|b| String::from_utf8(b).ok())
                        .unwrap_or_default()
                };
                User {
                    id,
                    tenant_id: r.get(1),
                    email: r.get(2),
                    name: r.get(3),
                    role: r.get(4),
                    password_hash: r.get(5),
                    disabled: status == "disabled",
                    mfa_enabled: r.get(7),
                    provider: r.get(8),
                    subject: r.get(9),
                    local_signin_enabled: r.get(10),
                    must_change_password: r.get(11),
                    password_history: serde_json::from_str(&pw_hist_raw).unwrap_or_default(),
                    mfa_totp_secret,
                    mfa_pending_totp_secret: String::new(),
                    mfa_recovery_hashes: serde_json::from_str(&rec_raw).unwrap_or_default(),
                    webauthn_credentials: serde_json::from_str::<Vec<WebAuthnCredential>>(&wa_raw)
                        .unwrap_or_default(),
                    mfa_last_totp_step: r.get(16),
                }
            })
            .collect();

        let r_rows = tx
            .query(
                "SELECT tenant_id, id, name, description, base_role, is_system, permissions::text, created_at, updated_at FROM roles",
                &[],
            )
            .await
            .map_err(|e| format!("load roles: {e}"))?;
        let roles = r_rows
            .into_iter()
            .map(|r| {
                let perms_raw: String = r.get(6);
                let permissions = serde_json::from_str(&perms_raw).unwrap_or_default();
                RoleDef {
                    tenant_id: r.get(0),
                    id: r.get(1),
                    name: r.get(2),
                    description: r.get(3),
                    base_role: r.get(4),
                    is_system: r.get(5),
                    permissions,
                    created_at: r.get(7),
                    updated_at: r.get(8),
                }
            })
            .collect();
        Ok((users, roles))
    }

    async fn load_groups_and_bindings(
        tx: &Transaction<'_>,
    ) -> Result<(Vec<Group>, Vec<GroupMembership>, Vec<GroupRoleBinding>), String> {
        let g_rows = tx
            .query(
                "SELECT id, tenant_id, name, description, source, is_system, external_id, created_at, updated_at FROM groups",
                &[],
            )
            .await
            .map_err(|e| format!("load groups: {e}"))?;
        let groups = g_rows
            .into_iter()
            .map(|r| Group {
                id: r.get(0),
                tenant_id: r.get(1),
                name: r.get(2),
                description: r.get(3),
                source: r.get(4),
                is_system: r.get(5),
                external_id: r.get(6),
                created_at: r.get(7),
                updated_at: r.get(8),
            })
            .collect();

        let m_rows = tx
            .query(
                "SELECT tenant_id, group_id, user_id, source, created_at FROM group_memberships",
                &[],
            )
            .await
            .map_err(|e| format!("load memberships: {e}"))?;
        let memberships = m_rows
            .into_iter()
            .map(|r| GroupMembership {
                tenant_id: r.get(0),
                group_id: r.get(1),
                user_id: r.get(2),
                source: r.get(3),
                created_at: r.get(4),
            })
            .collect();

        let b_rows = tx
            .query(
                "SELECT id, tenant_id, group_id, role_id, scope_type, scope_id, effect, conditions::text, created_at FROM group_role_bindings",
                &[],
            )
            .await
            .map_err(|e| format!("load bindings: {e}"))?;
        let bindings = b_rows
            .into_iter()
            .map(|r| {
                let scope_raw: String = r.get(4);
                let effect_raw: String = r.get(6);
                let cond_raw: String = r.get(7);
                let cond_val: serde_json::Value =
                    serde_json::from_str(&cond_raw).unwrap_or(serde_json::Value::Null);
                let (scope_type, effect, conditions) =
                    Self::parse_binding_fields(&scope_raw, &effect_raw, &cond_val);
                GroupRoleBinding {
                    id: r.get(0),
                    tenant_id: r.get(1),
                    group_id: r.get(2),
                    role_id: r.get(3),
                    scope_type,
                    scope_id: r.get(5),
                    effect,
                    conditions,
                    created_at: r.get(8),
                }
            })
            .collect();

        Ok((groups, memberships, bindings))
    }

    async fn load_sso_scim_sessions(
        tx: &Transaction<'_>,
        master_secret: &[u8],
    ) -> Result<
        (
            Vec<IdPGroupMapping>,
            Vec<(ScimToken, String)>,
            Vec<SsoProviderConfig>,
            Vec<SessionClaims>,
        ),
        String,
    > {
        let map_rows = tx
            .query(
                "SELECT id, tenant_id, provider_id, external_group, group_id, created_at FROM idp_group_mappings",
                &[],
            )
            .await
            .map_err(|e| format!("load idp_mappings: {e}"))?;
        let idp_mappings = map_rows
            .into_iter()
            .map(|r| IdPGroupMapping {
                id: r.get(0),
                tenant_id: r.get(1),
                provider_id: r.get(2),
                external_group: r.get(3),
                group_id: r.get(4),
                created_at: r.get(5),
            })
            .collect();

        let tok_rows = tx
            .query(
                "SELECT id, tenant_id, name, prefix, token_hash, created_by, created_at, last_used_at, revoked_at FROM scim_tokens",
                &[],
            )
            .await
            .map_err(|e| format!("load scim_tokens: {e}"))?;
        let scim_tokens = tok_rows
            .into_iter()
            .map(|r| {
                (
                    ScimToken {
                        id: r.get(0),
                        tenant_id: r.get(1),
                        name: r.get(2),
                        prefix: r.get(3),
                        created_by: r.get(5),
                        created_at: r.get(6),
                        last_used_at: r.get(7),
                        revoked_at: r.get(8),
                    },
                    r.get(4),
                )
            })
            .collect();

        let sso_rows = tx
            .query("SELECT id, encrypted_config FROM sso_providers", &[])
            .await
            .map_err(|e| format!("load sso_providers: {e}"))?;
        let mut sso_providers = Vec::new();
        for r in sso_rows {
            let id: String = r.get(0);
            let sealed: Vec<u8> = r.get(1);
            match SsoProviderConfig::open(master_secret, &id, &sealed) {
                Ok(cfg) => sso_providers.push(cfg),
                Err(err) => {
                    tracing::warn!(id = %id, error = %err, "failed to unseal SSO provider row");
                }
            }
        }

        let sess_rows = tx
            .query(
                "SELECT payload::text FROM auth_sessions WHERE expires_at > NOW()",
                &[],
            )
            .await
            .map_err(|e| format!("load auth_sessions: {e}"))?;
        let mut sessions = Vec::new();
        for r in sess_rows {
            let raw: String = r.get(0);
            if let Ok(claims) = serde_json::from_str::<SessionClaims>(&raw) {
                sessions.push(claims);
            }
        }

        Ok((idp_mappings, scim_tokens, sso_providers, sessions))
    }

    /// Load the complete multi-tenant auth snapshot on startup strictly inside per-tenant RLS transactions.
    pub async fn load_snapshot(&self, fallback_secret: &[u8]) -> Result<PgAuthSnapshot, String> {
        let mut guard = self.client.lock().await;
        let master_secret = Self::ensure_master_secret(&guard, fallback_secret).await?;
        *self.master_secret.write().await = master_secret.clone();
        let tenant_ids = Self::list_tenant_ids(&guard).await?;

        let mut snap = PgAuthSnapshot {
            master_secret: master_secret.clone(),
            ..Default::default()
        };

        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let (u, r) = Self::load_users_and_roles(&tx, &master_secret).await?;
            let (g, m, b) = Self::load_groups_and_bindings(&tx).await?;
            let (idp, scim, sso, sess) = Self::load_sso_scim_sessions(&tx, &master_secret).await?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;

            snap.users.extend(u);
            snap.roles.extend(r);
            snap.groups.extend(g);
            snap.memberships.extend(m);
            snap.bindings.extend(b);
            snap.idp_mappings.extend(idp);
            snap.scim_tokens.extend(scim);
            snap.sso_providers.extend(sso);
            snap.sessions.extend(sess);
        }

        Ok(snap)
    }

    async fn secret_ring(&self, purpose: &[u8]) -> Result<KeyRing, String> {
        let secret = {
            let cur = self.master_secret.read().await;
            if cur.is_empty() {
                drop(cur);
                let guard = self.client.lock().await;
                let row = guard
                    .query_opt(
                        "SELECT master_secret FROM auth_cluster_state WHERE id = TRUE",
                        &[],
                    )
                    .await
                    .map_err(|e| format!("load master_secret: {e}"))?;
                let loaded = row.map_or_else(|| vec![0u8; 32], |r| r.get::<_, Vec<u8>>(0));
                *self.master_secret.write().await = loaded.clone();
                loaded
            } else {
                cur.clone()
            }
        };
        Ok(KeyRing::from_master_and_env(&secret, purpose))
    }

    pub async fn ensure_runtime_tables(&self) -> Result<(), String> {
        let guard = self.client.lock().await;
        guard
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS aws_user_sso_providers (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    label TEXT NOT NULL DEFAULT '',
                    start_url TEXT NOT NULL,
                    region TEXT NOT NULL DEFAULT 'us-east-1',
                    created_at BIGINT NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS recording_policies (
                    tenant_id TEXT PRIMARY KEY,
                    policy JSONB NOT NULL DEFAULT '{}'::jsonb
                );",
            )
            .await
            .map_err(|e| format!("ensure_runtime_tables: {e}"))?;
        Ok(())
    }

    pub async fn list_aws_sso_providers(&self) -> Result<Vec<PgAwsSsoProviderRow>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT id, tenant_id, label, start_url, region, created_at FROM aws_user_sso_providers",
                    &[],
                )
                .await
                .map_err(|e| format!("list_aws_sso_providers: {e}"))?;
            for r in rows {
                out.push(PgAwsSsoProviderRow {
                    id: r.get(0),
                    tenant_id: r.get(1),
                    label: r.get(2),
                    start_url: r.get(3),
                    region: r.get(4),
                    created_at: r.get(5),
                });
            }
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
        }
        Ok(out)
    }

    pub async fn upsert_aws_sso_provider(&self, row: &PgAwsSsoProviderRow) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO aws_user_sso_providers (id, tenant_id, label, start_url, region, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (id) DO UPDATE SET \
             label = EXCLUDED.label, start_url = EXCLUDED.start_url, region = EXCLUDED.region",
            &[
                &row.id,
                &row.tenant_id,
                &row.label,
                &row.start_url,
                &row.region,
                &row.created_at,
            ],
        )
        .await
        .map_err(|e| format!("upsert_aws_sso_provider: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn delete_aws_sso_provider(&self, tenant_id: &str, id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &["DELETE FROM aws_user_sso_providers WHERE tenant_id = $1 AND id = $2"],
            id,
        )
        .await
    }

    pub async fn list_recording_policies(
        &self,
    ) -> Result<Vec<(String, serde_json::Value)>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT tenant_id, policy::text FROM recording_policies",
                    &[],
                )
                .await
                .map_err(|e| format!("list_recording_policies: {e}"))?;
            for r in rows {
                let row_tid: String = r.get(0);
                let raw: String = r.get(1);
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                    out.push((row_tid, val));
                }
            }
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
        }
        Ok(out)
    }

    pub async fn upsert_recording_policy(
        &self,
        tenant_id: &str,
        policy: &serde_json::Value,
    ) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, tenant_id).await?;
        let json_str = policy.to_string();
        tx.execute(
            "INSERT INTO recording_policies (tenant_id, policy) VALUES ($1, $2::text::jsonb) \
             ON CONFLICT (tenant_id) DO UPDATE SET policy = EXCLUDED.policy",
            &[&tenant_id, &json_str],
        )
        .await
        .map_err(|e| format!("upsert_recording_policy: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    // -----------------------------------------------------------------------
    // M10.1: Immutable Hash-Chained Audit Log Persistence
    // -----------------------------------------------------------------------

    pub async fn insert_audit_event(&self, row: &PgAuditRow) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO audit_events (tenant_id, user_id, action, target, event, seq, prev_hash, entry_hash) \
             VALUES ($1, $2, $3, $4, $5::text::jsonb, $6, $7, $8)",
            &[
                &row.tenant_id,
                &row.user_id,
                &row.action,
                &row.target,
                &row.event_json,
                &row.seq,
                &row.prev_hash,
                &row.entry_hash,
            ],
        )
        .await
        .map_err(|e| format!("insert_audit_event: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_audit_events_for_tenant(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<PgAuditRow>, String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, tenant_id).await?;
        let lim = i64::try_from(limit.clamp(1, 50_000)).unwrap_or(10_000);
        let rows = tx
            .query(
                "SELECT tenant_id, COALESCE(user_id, ''), action, COALESCE(target, ''), \
                        event::text, seq, prev_hash, entry_hash \
                 FROM audit_events WHERE seq > 0 ORDER BY seq ASC, id ASC LIMIT $1",
                &[&lim],
            )
            .await
            .map_err(|e| format!("list_audit_events_for_tenant: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
        Ok(rows
            .into_iter()
            .map(|r| PgAuditRow {
                tenant_id: r.get(0),
                user_id: r.get(1),
                action: r.get(2),
                target: r.get(3),
                event_json: r.get(4),
                seq: r.get(5),
                prev_hash: r.get(6),
                entry_hash: r.get(7),
            })
            .collect())
    }

    pub async fn latest_audit_heads(&self) -> Result<Vec<(String, u64, String)>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut heads = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let row = tx
                .query_opt(
                    "SELECT seq, entry_hash FROM audit_events WHERE seq > 0 ORDER BY seq DESC LIMIT 1",
                    &[],
                )
                .await
                .map_err(|e| format!("latest_audit_heads: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            if let Some(r) = row {
                let seq_i64: i64 = r.get(0);
                let seq = u64::try_from(seq_i64).unwrap_or(0);
                let entry_hash: String = r.get(1);
                heads.push((tid, seq, entry_hash));
            }
        }
        Ok(heads)
    }

    // -----------------------------------------------------------------------
    // M10.2: Recording Metadata & Legal-Hold / WORM Archival Persistence
    // -----------------------------------------------------------------------

    pub async fn upsert_recording_metadata(&self, row: &PgRecordingMetaRow) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO recording_metadata (
                id, tenant_id, protocol, target_host, format, started_at_ms, bytes_written,
                frame_count, sha256_hex, fail_closed, status, encrypted, legal_hold,
                legal_hold_reason, retention_until_ms, archived_s3_uri, archived_at_ms, updated_at
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, NOW()
             ) ON CONFLICT (id) DO UPDATE SET
                bytes_written = EXCLUDED.bytes_written,
                frame_count = EXCLUDED.frame_count,
                sha256_hex = EXCLUDED.sha256_hex,
                status = EXCLUDED.status,
                encrypted = EXCLUDED.encrypted,
                legal_hold = EXCLUDED.legal_hold,
                legal_hold_reason = EXCLUDED.legal_hold_reason,
                retention_until_ms = EXCLUDED.retention_until_ms,
                archived_s3_uri = EXCLUDED.archived_s3_uri,
                archived_at_ms = EXCLUDED.archived_at_ms,
                updated_at = NOW()",
            &[
                &row.id,
                &row.tenant_id,
                &row.protocol,
                &row.target_host,
                &row.format,
                &row.started_at_ms,
                &row.bytes_written,
                &row.frame_count,
                &row.sha256_hex,
                &row.fail_closed,
                &row.status,
                &row.encrypted,
                &row.legal_hold,
                &row.legal_hold_reason,
                &row.retention_until_ms,
                &row.archived_s3_uri,
                &row.archived_at_ms,
            ],
        )
        .await
        .map_err(|e| format!("upsert_recording_metadata: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_recording_metadata(&self) -> Result<Vec<PgRecordingMetaRow>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT id, tenant_id, protocol, target_host, format, started_at_ms, \
                            bytes_written, frame_count, sha256_hex, fail_closed, status, encrypted, \
                            legal_hold, legal_hold_reason, retention_until_ms, archived_s3_uri, \
                            archived_at_ms FROM recording_metadata",
                    &[],
                )
                .await
                .map_err(|e| format!("list_recording_metadata: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                out.push(PgRecordingMetaRow {
                    id: r.get(0),
                    tenant_id: r.get(1),
                    protocol: r.get(2),
                    target_host: r.get(3),
                    format: r.get(4),
                    started_at_ms: r.get(5),
                    bytes_written: r.get(6),
                    frame_count: r.get(7),
                    sha256_hex: r.get(8),
                    fail_closed: r.get(9),
                    status: r.get(10),
                    encrypted: r.get(11),
                    legal_hold: r.get(12),
                    legal_hold_reason: r.get(13),
                    retention_until_ms: r.get(14),
                    archived_s3_uri: r.get(15),
                    archived_at_ms: r.get(16),
                });
            }
        }
        Ok(out)
    }

    pub async fn delete_recording_metadata(&self, tenant_id: &str, id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &["DELETE FROM recording_metadata WHERE tenant_id = $1 AND id = $2"],
            id,
        )
        .await
    }

    // -----------------------------------------------------------------------
    // M10.3: Encrypted AWS SSO Sessions, Role Leases, Bindings, Discovery, Clones & Preferences
    // -----------------------------------------------------------------------

    pub async fn upsert_aws_sso_session(&self, row: &PgAwsSsoSessionRow) -> Result<(), String> {
        let ring = self.secret_ring(b"operquay/aws-sso-session/v1").await?;
        let aad = format!("{}:{}", row.tenant_id, row.id);
        let sealed = seal_aead_versioned(&ring, aad.as_bytes(), row.token_state_json.as_bytes())?;
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO aws_sso_sessions (
                id, tenant_id, user_id, region, start_url, encrypted_token_state,
                expires_at, cancelled, updated_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
             ON CONFLICT (id) DO UPDATE SET
                encrypted_token_state = EXCLUDED.encrypted_token_state,
                expires_at = EXCLUDED.expires_at,
                cancelled = EXCLUDED.cancelled,
                updated_at = NOW()",
            &[
                &row.id,
                &row.tenant_id,
                &row.user_id,
                &row.region,
                &row.start_url,
                &sealed,
                &row.expires_at,
                &row.cancelled,
            ],
        )
        .await
        .map_err(|e| format!("upsert_aws_sso_session: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_aws_sso_sessions(&self) -> Result<Vec<PgAwsSsoSessionRow>, String> {
        let ring = self.secret_ring(b"operquay/aws-sso-session/v1").await?;
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT id, tenant_id, user_id, region, start_url, encrypted_token_state, \
                            expires_at, cancelled FROM aws_sso_sessions WHERE cancelled = FALSE",
                    &[],
                )
                .await
                .map_err(|e| format!("list_aws_sso_sessions: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                let id: String = r.get(0);
                let tenant_id: String = r.get(1);
                let sealed: Vec<u8> = r.get(5);
                let aad = format!("{tenant_id}:{id}");
                if let Ok(plain) = open_aead_versioned(&ring, aad.as_bytes(), &sealed) {
                    if let Ok(token_state_json) = String::from_utf8(plain) {
                        out.push(PgAwsSsoSessionRow {
                            id,
                            tenant_id,
                            user_id: r.get(2),
                            region: r.get(3),
                            start_url: r.get(4),
                            token_state_json,
                            expires_at: r.get(6),
                            cancelled: r.get(7),
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    pub async fn delete_aws_sso_session(&self, tenant_id: &str, id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &["DELETE FROM aws_sso_sessions WHERE tenant_id = $1 AND id = $2"],
            id,
        )
        .await
    }

    pub async fn upsert_aws_role_lease(&self, row: &PgAwsRoleLeaseRow) -> Result<(), String> {
        let ring = self.secret_ring(b"operquay/aws-role-lease/v1").await?;
        let aad = format!("{}:{}", row.tenant_id, row.id);
        let sealed = seal_aead_versioned(&ring, aad.as_bytes(), row.credentials_json.as_bytes())?;
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO aws_role_leases (
                id, tenant_id, user_id, binding_id, label, account_id, role_arn, role_name,
                start_url, region, status, credential_revision, connected_at, expires_at,
                encrypted_credentials, updated_at
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW()
             ) ON CONFLICT (id) DO UPDATE SET
                status = EXCLUDED.status,
                credential_revision = EXCLUDED.credential_revision,
                expires_at = EXCLUDED.expires_at,
                encrypted_credentials = EXCLUDED.encrypted_credentials,
                updated_at = NOW()",
            &[
                &row.id,
                &row.tenant_id,
                &row.user_id,
                &row.binding_id,
                &row.label,
                &row.account_id,
                &row.role_arn,
                &row.role_name,
                &row.start_url,
                &row.region,
                &row.status,
                &row.credential_revision,
                &row.connected_at,
                &row.expires_at,
                &sealed,
            ],
        )
        .await
        .map_err(|e| format!("upsert_aws_role_lease: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_aws_role_leases(&self) -> Result<Vec<PgAwsRoleLeaseRow>, String> {
        let ring = self.secret_ring(b"operquay/aws-role-lease/v1").await?;
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT id, tenant_id, user_id, binding_id, label, account_id, role_arn, \
                            role_name, start_url, region, status, credential_revision, \
                            connected_at, expires_at, encrypted_credentials \
                     FROM aws_role_leases",
                    &[],
                )
                .await
                .map_err(|e| format!("list_aws_role_leases: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                let id: String = r.get(0);
                let tenant_id: String = r.get(1);
                let sealed: Vec<u8> = r.get(14);
                let aad = format!("{tenant_id}:{id}");
                if let Ok(plain) = open_aead_versioned(&ring, aad.as_bytes(), &sealed) {
                    if let Ok(credentials_json) = String::from_utf8(plain) {
                        out.push(PgAwsRoleLeaseRow {
                            id,
                            tenant_id,
                            user_id: r.get(2),
                            binding_id: r.get(3),
                            label: r.get(4),
                            account_id: r.get(5),
                            role_arn: r.get(6),
                            role_name: r.get(7),
                            start_url: r.get(8),
                            region: r.get(9),
                            status: r.get(10),
                            credential_revision: r.get(11),
                            connected_at: r.get(12),
                            expires_at: r.get(13),
                            credentials_json,
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    pub async fn delete_aws_role_lease(&self, tenant_id: &str, id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &["DELETE FROM aws_role_leases WHERE tenant_id = $1 AND (id = $2 OR binding_id = $2)"],
            id,
        )
        .await
    }

    pub async fn delete_user_role_leases(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &["DELETE FROM aws_role_leases WHERE tenant_id = $1 AND user_id = $2"],
            user_id,
        )
        .await
    }

    pub async fn upsert_aws_role_binding(&self, row: &PgAwsRoleBindingRow) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO aws_user_role_bindings (id, tenant_id, user_id, role_arn, label, payload) \
             VALUES ($1, $2, $3, $4, $5, $6::text::jsonb) \
             ON CONFLICT (id) DO UPDATE SET role_arn = EXCLUDED.role_arn, label = EXCLUDED.label, payload = EXCLUDED.payload",
            &[
                &row.id,
                &row.tenant_id,
                &row.user_id,
                &row.role_arn,
                &row.label,
                &row.payload_json,
            ],
        )
        .await
        .map_err(|e| format!("upsert_aws_role_binding: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_aws_role_bindings(&self) -> Result<Vec<PgAwsRoleBindingRow>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT id, tenant_id, user_id, role_arn, label, payload::text FROM aws_user_role_bindings",
                    &[],
                )
                .await
                .map_err(|e| format!("list_aws_role_bindings: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                out.push(PgAwsRoleBindingRow {
                    id: r.get(0),
                    tenant_id: r.get(1),
                    user_id: r.get(2),
                    role_arn: r.get(3),
                    label: r.get(4),
                    payload_json: r.get(5),
                });
            }
        }
        Ok(out)
    }

    pub async fn delete_aws_role_binding(&self, tenant_id: &str, id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &["DELETE FROM aws_user_role_bindings WHERE tenant_id = $1 AND id = $2"],
            id,
        )
        .await
    }

    pub async fn upsert_aws_discovery_inventory(
        &self,
        row: &PgAwsDiscoveryRow,
    ) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO aws_discovery_inventory (tenant_id, instances, status, updated_at) \
             VALUES ($1, $2::text::jsonb, $3::text::jsonb, NOW()) \
             ON CONFLICT (tenant_id) DO UPDATE SET \
             instances = EXCLUDED.instances, status = EXCLUDED.status, updated_at = NOW()",
            &[&row.tenant_id, &row.instances_json, &row.status_json],
        )
        .await
        .map_err(|e| format!("upsert_aws_discovery_inventory: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_aws_discovery_inventories(&self) -> Result<Vec<PgAwsDiscoveryRow>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT tenant_id, instances::text, status::text FROM aws_discovery_inventory",
                    &[],
                )
                .await
                .map_err(|e| format!("list_aws_discovery_inventories: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                out.push(PgAwsDiscoveryRow {
                    tenant_id: r.get(0),
                    instances_json: r.get(1),
                    status_json: r.get(2),
                });
            }
        }
        Ok(out)
    }

    pub async fn upsert_aws_saved_inventory(
        &self,
        row: &PgAwsSavedInventoryRow,
    ) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO aws_user_saved_inventory (tenant_id, user_id, items, updated_at) \
             VALUES ($1, $2, $3::text::jsonb, NOW()) \
             ON CONFLICT (tenant_id, user_id) DO UPDATE SET items = EXCLUDED.items, updated_at = NOW()",
            &[&row.tenant_id, &row.user_id, &row.items_json],
        )
        .await
        .map_err(|e| format!("upsert_aws_saved_inventory: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_aws_saved_inventories(&self) -> Result<Vec<PgAwsSavedInventoryRow>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT tenant_id, user_id, items::text FROM aws_user_saved_inventory",
                    &[],
                )
                .await
                .map_err(|e| format!("list_aws_saved_inventories: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                out.push(PgAwsSavedInventoryRow {
                    tenant_id: r.get(0),
                    user_id: r.get(1),
                    items_json: r.get(2),
                });
            }
        }
        Ok(out)
    }

    pub async fn delete_aws_saved_inventory(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &["DELETE FROM aws_user_saved_inventory WHERE tenant_id = $1 AND user_id = $2"],
            user_id,
        )
        .await
    }

    pub async fn upsert_aws_clone_operation(&self, row: &PgAwsCloneRow) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO aws_user_clone_operations (
                id, tenant_id, user_id, source_instance_id, status, settings, payload, updated_at
             ) VALUES ($1, $2, $3, $4, $5, $6::text::jsonb, $6::text::jsonb, NOW())
             ON CONFLICT (id) DO UPDATE SET
                status = EXCLUDED.status,
                settings = EXCLUDED.settings,
                payload = EXCLUDED.payload,
                updated_at = NOW()",
            &[
                &row.id,
                &row.tenant_id,
                &row.user_id,
                &row.source_instance_id,
                &row.status,
                &row.payload_json,
            ],
        )
        .await
        .map_err(|e| format!("upsert_aws_clone_operation: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_aws_clone_operations(&self) -> Result<Vec<PgAwsCloneRow>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT id, tenant_id, user_id, source_instance_id, status, payload::text \
                     FROM aws_user_clone_operations",
                    &[],
                )
                .await
                .map_err(|e| format!("list_aws_clone_operations: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                out.push(PgAwsCloneRow {
                    id: r.get(0),
                    tenant_id: r.get(1),
                    user_id: r.get(2),
                    source_instance_id: r.get(3),
                    status: r.get(4),
                    payload_json: r.get(5),
                });
            }
        }
        Ok(out)
    }

    pub async fn upsert_user_preferences(&self, row: &PgUserPrefsRow) -> Result<(), String> {
        let ring = self.secret_ring(b"operquay/user-preferences/v1").await?;
        let aad = format!("{}:{}", row.tenant_id, row.user_id);
        let sealed = seal_aead_versioned(&ring, aad.as_bytes(), row.prefs_json.as_bytes())?;
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO user_preferences (tenant_id, user_id, encrypted_data) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (tenant_id, user_id) DO UPDATE SET encrypted_data = EXCLUDED.encrypted_data",
            &[&row.tenant_id, &row.user_id, &sealed],
        )
        .await
        .map_err(|e| format!("upsert_user_preferences: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_user_preferences(&self) -> Result<Vec<PgUserPrefsRow>, String> {
        let ring = self.secret_ring(b"operquay/user-preferences/v1").await?;
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT tenant_id, user_id, encrypted_data FROM user_preferences",
                    &[],
                )
                .await
                .map_err(|e| format!("list_user_preferences: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                let tenant_id: String = r.get(0);
                let user_id: String = r.get(1);
                let sealed: Vec<u8> = r.get(2);
                let aad = format!("{tenant_id}:{user_id}");
                if let Ok(plain) = open_aead_versioned(&ring, aad.as_bytes(), &sealed) {
                    if let Ok(prefs_json) = String::from_utf8(plain) {
                        out.push(PgUserPrefsRow {
                            tenant_id,
                            user_id,
                            prefs_json,
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // M10.5: Tenant Crypto-Shredding Keys
    // -----------------------------------------------------------------------

    pub async fn get_or_create_tenant_dek(
        &self,
        tenant_id: &str,
    ) -> Result<Option<[u8; 32]>, String> {
        let ring = self.secret_ring(b"operquay/tenant-dek/v1").await?;
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, tenant_id).await?;
        let existing = tx
            .query_opt(
                "SELECT wrapped_dek, status FROM tenant_encryption_keys WHERE tenant_id = $1",
                &[&tenant_id],
            )
            .await
            .map_err(|e| format!("get tenant dek: {e}"))?;
        if let Some(r) = existing {
            let wrapped: Vec<u8> = r.get(0);
            let status: String = r.get(1);
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            if status == "shredded" {
                return Ok(None);
            }
            let plain = open_aead_versioned(&ring, tenant_id.as_bytes(), &wrapped)?;
            if plain.len() != 32 {
                return Err("stored tenant DEK has invalid length".into());
            }
            let mut dek = [0u8; 32];
            dek.copy_from_slice(&plain);
            return Ok(Some(dek));
        }
        let mut dek = [0u8; 32];
        fill_csprng(&mut dek)?;
        let wrapped = seal_aead_versioned(&ring, tenant_id.as_bytes(), &dek)?;
        let ver = i32::from(ring.active_version());
        tx.execute(
            "INSERT INTO tenant_encryption_keys (tenant_id, key_version, wrapped_dek, status) \
             VALUES ($1, $2, $3, 'active') ON CONFLICT (tenant_id) DO NOTHING",
            &[&tenant_id, &ver, &wrapped],
        )
        .await
        .map_err(|e| format!("insert tenant dek: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
        Ok(Some(dek))
    }

    pub async fn list_tenant_deks(&self) -> Result<Vec<PgTenantKeyRow>, String> {
        let ring = self.secret_ring(b"operquay/tenant-dek/v1").await?;
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let row = tx
                .query_opt(
                    "SELECT tenant_id, wrapped_dek, status FROM tenant_encryption_keys",
                    &[],
                )
                .await
                .map_err(|e| format!("list_tenant_deks: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            if let Some(r) = row {
                let tenant_id: String = r.get(0);
                let wrapped: Vec<u8> = r.get(1);
                let status: String = r.get(2);
                let shredded = status == "shredded";
                let dek = if shredded {
                    None
                } else {
                    open_aead_versioned(&ring, tenant_id.as_bytes(), &wrapped)
                        .ok()
                        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                };
                out.push(PgTenantKeyRow {
                    tenant_id,
                    dek,
                    shredded,
                });
            }
        }
        Ok(out)
    }

    pub async fn shred_tenant_dek(&self, tenant_id: &str) -> Result<bool, String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, tenant_id).await?;
        let empty: &[u8] = &[];
        let updated = tx
            .execute(
                "INSERT INTO tenant_encryption_keys (tenant_id, key_version, wrapped_dek, status, shredded_at) \
                 VALUES ($1, 0, $2, 'shredded', NOW()) \
                 ON CONFLICT (tenant_id) DO UPDATE SET \
                 wrapped_dek = $2, status = 'shredded', shredded_at = NOW()",
                &[&tenant_id, &empty],
            )
            .await
            .map_err(|e| format!("shred_tenant_dek: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
        Ok(updated > 0)
    }

    // -----------------------------------------------------------------------
    // M11: Zero Standing Privileges, Webhooks, DLP Firewall, Bookmarks & Compliance
    // -----------------------------------------------------------------------

    pub async fn upsert_jit_access_request(
        &self,
        row: &PgJitAccessRequestRow,
    ) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO jit_access_requests (
                id, tenant_id, requester_user_id, requester_email, target_type, target_id,
                requested_role, duration_secs, reason, ticket_id, ticket_provider, status,
                approver_user_id, approver_email, decision_note, created_at, decided_at,
                expires_at, revoked_at, payload
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                $17, $18, $19, $20::text::jsonb
             ) ON CONFLICT (id) DO UPDATE SET
                status = EXCLUDED.status,
                approver_user_id = EXCLUDED.approver_user_id,
                approver_email = EXCLUDED.approver_email,
                decision_note = EXCLUDED.decision_note,
                decided_at = EXCLUDED.decided_at,
                expires_at = EXCLUDED.expires_at,
                revoked_at = EXCLUDED.revoked_at,
                payload = EXCLUDED.payload",
            &[
                &row.id,
                &row.tenant_id,
                &row.requester_user_id,
                &row.requester_email,
                &row.target_type,
                &row.target_id,
                &row.requested_role,
                &row.duration_secs,
                &row.reason,
                &row.ticket_id,
                &row.ticket_provider,
                &row.status,
                &row.approver_user_id,
                &row.approver_email,
                &row.decision_note,
                &row.created_at,
                &row.decided_at,
                &row.expires_at,
                &row.revoked_at,
                &row.payload_json,
            ],
        )
        .await
        .map_err(|e| format!("upsert_jit_access_request: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_jit_access_requests(&self) -> Result<Vec<PgJitAccessRequestRow>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT id, tenant_id, requester_user_id, requester_email, target_type, target_id, \
                            requested_role, duration_secs, reason, ticket_id, ticket_provider, status, \
                            approver_user_id, approver_email, decision_note, created_at, decided_at, \
                            expires_at, revoked_at, payload::text \
                     FROM jit_access_requests ORDER BY created_at DESC",
                    &[],
                )
                .await
                .map_err(|e| format!("list_jit_access_requests: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                out.push(PgJitAccessRequestRow {
                    id: r.get(0),
                    tenant_id: r.get(1),
                    requester_user_id: r.get(2),
                    requester_email: r.get(3),
                    target_type: r.get(4),
                    target_id: r.get(5),
                    requested_role: r.get(6),
                    duration_secs: r.get(7),
                    reason: r.get(8),
                    ticket_id: r.get(9),
                    ticket_provider: r.get(10),
                    status: r.get(11),
                    approver_user_id: r.get(12),
                    approver_email: r.get(13),
                    decision_note: r.get(14),
                    created_at: r.get(15),
                    decided_at: r.get(16),
                    expires_at: r.get(17),
                    revoked_at: r.get(18),
                    payload_json: r.get(19),
                });
            }
        }
        Ok(out)
    }

    pub async fn upsert_governance_webhook(
        &self,
        row: &PgGovernanceWebhookRow,
    ) -> Result<(), String> {
        let ring = self.secret_ring(b"operquay/gov-webhook/v1").await?;
        let aad = format!("{}:{}", row.tenant_id, row.id);
        let sealed = seal_aead_versioned(&ring, aad.as_bytes(), row.secret.as_bytes())?;
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO governance_webhooks (
                id, tenant_id, provider, name, url, encrypted_secret, events, enabled, created_at
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7::text::jsonb, $8, $9
             ) ON CONFLICT (id) DO UPDATE SET
                provider = EXCLUDED.provider,
                name = EXCLUDED.name,
                url = EXCLUDED.url,
                encrypted_secret = EXCLUDED.encrypted_secret,
                events = EXCLUDED.events,
                enabled = EXCLUDED.enabled",
            &[
                &row.id,
                &row.tenant_id,
                &row.provider,
                &row.name,
                &row.url,
                &sealed,
                &row.events_json,
                &row.enabled,
                &row.created_at,
            ],
        )
        .await
        .map_err(|e| format!("upsert_governance_webhook: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_governance_webhooks(&self) -> Result<Vec<PgGovernanceWebhookRow>, String> {
        let ring = self.secret_ring(b"operquay/gov-webhook/v1").await?;
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT id, tenant_id, provider, name, url, encrypted_secret, events::text, \
                            enabled, created_at \
                     FROM governance_webhooks ORDER BY created_at DESC",
                    &[],
                )
                .await
                .map_err(|e| format!("list_governance_webhooks: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                let id: String = r.get(0);
                let tenant_id: String = r.get(1);
                let sealed: Vec<u8> = r.get(5);
                let aad = format!("{tenant_id}:{id}");
                let secret = open_aead_versioned(&ring, aad.as_bytes(), &sealed)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_default();
                out.push(PgGovernanceWebhookRow {
                    id,
                    tenant_id,
                    provider: r.get(2),
                    name: r.get(3),
                    url: r.get(4),
                    secret,
                    events_json: r.get(6),
                    enabled: r.get(7),
                    created_at: r.get(8),
                });
            }
        }
        Ok(out)
    }

    pub async fn delete_governance_webhook(&self, tenant_id: &str, id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &["DELETE FROM governance_webhooks WHERE tenant_id = $1 AND id = $2"],
            id,
        )
        .await
    }

    pub async fn upsert_dlp_policy(&self, row: &PgDlpPolicyRow) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO dlp_firewall_policies (tenant_id, policy, updated_at) \
             VALUES ($1, $2::text::jsonb, NOW()) \
             ON CONFLICT (tenant_id) DO UPDATE SET \
             policy = EXCLUDED.policy, updated_at = NOW()",
            &[&row.tenant_id, &row.policy_json],
        )
        .await
        .map_err(|e| format!("upsert_dlp_policy: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_dlp_policies(&self) -> Result<Vec<PgDlpPolicyRow>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT tenant_id, policy::text FROM dlp_firewall_policies",
                    &[],
                )
                .await
                .map_err(|e| format!("list_dlp_policies: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                out.push(PgDlpPolicyRow {
                    tenant_id: r.get(0),
                    policy_json: r.get(1),
                });
            }
        }
        Ok(out)
    }

    pub async fn insert_session_risk_bookmark(
        &self,
        row: &PgSessionRiskBookmarkRow,
    ) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO session_risk_bookmarks (
                id, tenant_id, recording_id, session_id, offset_secs, severity,
                category, title, detail, source, created_at
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
             ) ON CONFLICT (id) DO UPDATE SET
                severity = EXCLUDED.severity,
                title = EXCLUDED.title,
                detail = EXCLUDED.detail,
                source = EXCLUDED.source",
            &[
                &row.id,
                &row.tenant_id,
                &row.recording_id,
                &row.session_id,
                &row.offset_secs,
                &row.severity,
                &row.category,
                &row.title,
                &row.detail,
                &row.source,
                &row.created_at,
            ],
        )
        .await
        .map_err(|e| format!("insert_session_risk_bookmark: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_session_risk_bookmarks(
        &self,
    ) -> Result<Vec<PgSessionRiskBookmarkRow>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT id, tenant_id, recording_id, session_id, offset_secs, severity, \
                            category, title, detail, source, created_at \
                     FROM session_risk_bookmarks ORDER BY offset_secs ASC",
                    &[],
                )
                .await
                .map_err(|e| format!("list_session_risk_bookmarks: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                out.push(PgSessionRiskBookmarkRow {
                    id: r.get(0),
                    tenant_id: r.get(1),
                    recording_id: r.get(2),
                    session_id: r.get(3),
                    offset_secs: r.get(4),
                    severity: r.get(5),
                    category: r.get(6),
                    title: r.get(7),
                    detail: r.get(8),
                    source: r.get(9),
                    created_at: r.get(10),
                });
            }
        }
        Ok(out)
    }

    pub async fn upsert_access_review_campaign(
        &self,
        row: &PgAccessReviewCampaignRow,
    ) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO access_review_campaigns (
                id, tenant_id, title, quarter, status, created_by, created_at, completed_at, payload
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9::text::jsonb
             ) ON CONFLICT (id) DO UPDATE SET
                title = EXCLUDED.title,
                status = EXCLUDED.status,
                completed_at = EXCLUDED.completed_at,
                payload = EXCLUDED.payload",
            &[
                &row.id,
                &row.tenant_id,
                &row.title,
                &row.quarter,
                &row.status,
                &row.created_by,
                &row.created_at,
                &row.completed_at,
                &row.payload_json,
            ],
        )
        .await
        .map_err(|e| format!("upsert_access_review_campaign: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_access_review_campaigns(
        &self,
    ) -> Result<Vec<PgAccessReviewCampaignRow>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT id, tenant_id, title, quarter, status, created_by, created_at, \
                            completed_at, payload::text \
                     FROM access_review_campaigns ORDER BY created_at DESC",
                    &[],
                )
                .await
                .map_err(|e| format!("list_access_review_campaigns: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                out.push(PgAccessReviewCampaignRow {
                    id: r.get(0),
                    tenant_id: r.get(1),
                    title: r.get(2),
                    quarter: r.get(3),
                    status: r.get(4),
                    created_by: r.get(5),
                    created_at: r.get(6),
                    completed_at: r.get(7),
                    payload_json: r.get(8),
                });
            }
        }
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // M12: MCP Agents, Hybrid Reverse-Tunnel Agents, Multi-Cloud & Device Trust
    // -----------------------------------------------------------------------

    pub async fn upsert_mcp_agent(&self, row: &PgMcpAgentRow) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO mcp_agents (
                id, tenant_id, name, sponsor_user_id, sponsor_email, token_hash,
                allowed_tools, require_jit_tools, rate_limit_per_min, status,
                expires_at, created_at, revoked_at, payload
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7::text::jsonb, $8::text::jsonb,
                $9, $10, $11, $12, $13, $14::text::jsonb
             ) ON CONFLICT (id) DO UPDATE SET
                status = EXCLUDED.status,
                revoked_at = EXCLUDED.revoked_at,
                allowed_tools = EXCLUDED.allowed_tools,
                require_jit_tools = EXCLUDED.require_jit_tools,
                rate_limit_per_min = EXCLUDED.rate_limit_per_min,
                payload = EXCLUDED.payload",
            &[
                &row.id,
                &row.tenant_id,
                &row.name,
                &row.sponsor_user_id,
                &row.sponsor_email,
                &row.token_hash,
                &row.allowed_tools_json,
                &row.require_jit_tools_json,
                &row.rate_limit_per_min,
                &row.status,
                &row.expires_at,
                &row.created_at,
                &row.revoked_at,
                &row.payload_json,
            ],
        )
        .await
        .map_err(|e| format!("upsert_mcp_agent: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_mcp_agents(&self) -> Result<Vec<PgMcpAgentRow>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT id, tenant_id, name, sponsor_user_id, sponsor_email, token_hash, \
                            allowed_tools::text, require_jit_tools::text, rate_limit_per_min, status, \
                            expires_at, created_at, revoked_at, payload::text \
                     FROM mcp_agents ORDER BY created_at DESC",
                    &[],
                )
                .await
                .map_err(|e| format!("list_mcp_agents: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                out.push(PgMcpAgentRow {
                    id: r.get(0),
                    tenant_id: r.get(1),
                    name: r.get(2),
                    sponsor_user_id: r.get(3),
                    sponsor_email: r.get(4),
                    token_hash: r.get(5),
                    allowed_tools_json: r.get(6),
                    require_jit_tools_json: r.get(7),
                    rate_limit_per_min: r.get(8),
                    status: r.get(9),
                    expires_at: r.get(10),
                    created_at: r.get(11),
                    revoked_at: r.get(12),
                    payload_json: r.get(13),
                });
            }
        }
        Ok(out)
    }

    pub async fn insert_mcp_invocation(&self, row: &PgMcpInvocationRow) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO mcp_tool_invocations (
                id, tenant_id, agent_id, sponsor_user_id, tool_name, sanitized_args,
                decision, jit_request_id, masked_result_preview, duration_ms, created_at
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
             ) ON CONFLICT (id) DO NOTHING",
            &[
                &row.id,
                &row.tenant_id,
                &row.agent_id,
                &row.sponsor_user_id,
                &row.tool_name,
                &row.sanitized_args,
                &row.decision,
                &row.jit_request_id,
                &row.masked_result_preview,
                &row.duration_ms,
                &row.created_at,
            ],
        )
        .await
        .map_err(|e| format!("insert_mcp_invocation: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_mcp_invocations(&self) -> Result<Vec<PgMcpInvocationRow>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT id, tenant_id, agent_id, sponsor_user_id, tool_name, sanitized_args, \
                            decision, jit_request_id, masked_result_preview, duration_ms, created_at \
                     FROM mcp_tool_invocations ORDER BY created_at DESC LIMIT 1000",
                    &[],
                )
                .await
                .map_err(|e| format!("list_mcp_invocations: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                out.push(PgMcpInvocationRow {
                    id: r.get(0),
                    tenant_id: r.get(1),
                    agent_id: r.get(2),
                    sponsor_user_id: r.get(3),
                    tool_name: r.get(4),
                    sanitized_args: r.get(5),
                    decision: r.get(6),
                    jit_request_id: r.get(7),
                    masked_result_preview: r.get(8),
                    duration_ms: r.get(9),
                    created_at: r.get(10),
                });
            }
        }
        Ok(out)
    }

    pub async fn upsert_hybrid_agent(&self, row: &PgHybridAgentRow) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO hybrid_agents (
                id, tenant_id, name, enrollment_token_hash, cert_fingerprint_sha256,
                hostname, os, arch, labels, targets, status, last_heartbeat_at, created_at, payload
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9::text::jsonb, $10::text::jsonb,
                $11, $12, $13, $14::text::jsonb
             ) ON CONFLICT (id) DO UPDATE SET
                cert_fingerprint_sha256 = EXCLUDED.cert_fingerprint_sha256,
                hostname = EXCLUDED.hostname,
                os = EXCLUDED.os,
                arch = EXCLUDED.arch,
                labels = EXCLUDED.labels,
                targets = EXCLUDED.targets,
                status = EXCLUDED.status,
                last_heartbeat_at = EXCLUDED.last_heartbeat_at,
                payload = EXCLUDED.payload",
            &[
                &row.id,
                &row.tenant_id,
                &row.name,
                &row.enrollment_token_hash,
                &row.cert_fingerprint_sha256,
                &row.hostname,
                &row.os,
                &row.arch,
                &row.labels_json,
                &row.targets_json,
                &row.status,
                &row.last_heartbeat_at,
                &row.created_at,
                &row.payload_json,
            ],
        )
        .await
        .map_err(|e| format!("upsert_hybrid_agent: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_hybrid_agents(&self) -> Result<Vec<PgHybridAgentRow>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT id, tenant_id, name, enrollment_token_hash, cert_fingerprint_sha256, \
                            hostname, os, arch, labels::text, targets::text, status, \
                            last_heartbeat_at, created_at, payload::text \
                     FROM hybrid_agents ORDER BY created_at DESC",
                    &[],
                )
                .await
                .map_err(|e| format!("list_hybrid_agents: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                out.push(PgHybridAgentRow {
                    id: r.get(0),
                    tenant_id: r.get(1),
                    name: r.get(2),
                    enrollment_token_hash: r.get(3),
                    cert_fingerprint_sha256: r.get(4),
                    hostname: r.get(5),
                    os: r.get(6),
                    arch: r.get(7),
                    labels_json: r.get(8),
                    targets_json: r.get(9),
                    status: r.get(10),
                    last_heartbeat_at: r.get(11),
                    created_at: r.get(12),
                    payload_json: r.get(13),
                });
            }
        }
        Ok(out)
    }

    pub async fn delete_hybrid_agent(&self, tenant_id: &str, id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &["DELETE FROM hybrid_agents WHERE tenant_id = $1 AND id = $2"],
            id,
        )
        .await
    }

    pub async fn upsert_cloud_connector(&self, row: &PgCloudConnectorRow) -> Result<(), String> {
        let ring = self.secret_ring(b"operquay/cloud-connector/v1").await?;
        let aad = format!("{}:{}", row.tenant_id, row.id);
        let sealed = seal_aead_versioned(&ring, aad.as_bytes(), row.credentials_json.as_bytes())?;
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO cloud_connectors (
                id, tenant_id, provider, name, account_or_project_id, tenant_or_org_id,
                region, encrypted_credentials, config, status, last_synced_at, created_at
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9::text::jsonb, $10, $11, $12
             ) ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                account_or_project_id = EXCLUDED.account_or_project_id,
                tenant_or_org_id = EXCLUDED.tenant_or_org_id,
                region = EXCLUDED.region,
                encrypted_credentials = EXCLUDED.encrypted_credentials,
                config = EXCLUDED.config,
                status = EXCLUDED.status,
                last_synced_at = EXCLUDED.last_synced_at",
            &[
                &row.id,
                &row.tenant_id,
                &row.provider,
                &row.name,
                &row.account_or_project_id,
                &row.tenant_or_org_id,
                &row.region,
                &sealed,
                &row.config_json,
                &row.status,
                &row.last_synced_at,
                &row.created_at,
            ],
        )
        .await
        .map_err(|e| format!("upsert_cloud_connector: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_cloud_connectors(&self) -> Result<Vec<PgCloudConnectorRow>, String> {
        let ring = self.secret_ring(b"operquay/cloud-connector/v1").await?;
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT id, tenant_id, provider, name, account_or_project_id, \
                            tenant_or_org_id, region, encrypted_credentials, config::text, \
                            status, last_synced_at, created_at \
                     FROM cloud_connectors ORDER BY created_at DESC",
                    &[],
                )
                .await
                .map_err(|e| format!("list_cloud_connectors: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                let id: String = r.get(0);
                let tenant_id: String = r.get(1);
                let sealed: Vec<u8> = r.get(7);
                let aad = format!("{tenant_id}:{id}");
                let credentials_json = open_aead_versioned(&ring, aad.as_bytes(), &sealed)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_else(|| "{}".to_owned());
                out.push(PgCloudConnectorRow {
                    id,
                    tenant_id,
                    provider: r.get(2),
                    name: r.get(3),
                    account_or_project_id: r.get(4),
                    tenant_or_org_id: r.get(5),
                    region: r.get(6),
                    credentials_json,
                    config_json: r.get(8),
                    status: r.get(9),
                    last_synced_at: r.get(10),
                    created_at: r.get(11),
                });
            }
        }
        Ok(out)
    }

    pub async fn delete_cloud_connector(&self, tenant_id: &str, id: &str) -> Result<(), String> {
        self.delete_in_tenant_by_id(
            tenant_id,
            &["DELETE FROM cloud_connectors WHERE tenant_id = $1 AND id = $2"],
            id,
        )
        .await
    }

    pub async fn upsert_device_trust_policy(
        &self,
        row: &PgDeviceTrustPolicyRow,
    ) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO device_trust_policies (tenant_id, policy, updated_at) \
             VALUES ($1, $2::text::jsonb, NOW()) \
             ON CONFLICT (tenant_id) DO UPDATE SET \
             policy = EXCLUDED.policy, updated_at = NOW()",
            &[&row.tenant_id, &row.policy_json],
        )
        .await
        .map_err(|e| format!("upsert_device_trust_policy: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_device_trust_policies(&self) -> Result<Vec<PgDeviceTrustPolicyRow>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT tenant_id, policy::text FROM device_trust_policies",
                    &[],
                )
                .await
                .map_err(|e| format!("list_device_trust_policies: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                out.push(PgDeviceTrustPolicyRow {
                    tenant_id: r.get(0),
                    policy_json: r.get(1),
                });
            }
        }
        Ok(out)
    }

    pub async fn upsert_device_posture(&self, row: &PgDevicePostureRow) -> Result<(), String> {
        let mut guard = self.client.lock().await;
        let tx = Self::begin_tenant_tx(&mut guard, &row.tenant_id).await?;
        tx.execute(
            "INSERT INTO device_posture_attestations (
                id, tenant_id, user_id, device_id, provider, hostname, os_version,
                disk_encrypted, edr_running, edr_agent, os_patch_age_days, compliant,
                reasons, attested_at, expires_at
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::text::jsonb, $14, $15
             ) ON CONFLICT (id) DO UPDATE SET
                disk_encrypted = EXCLUDED.disk_encrypted,
                edr_running = EXCLUDED.edr_running,
                edr_agent = EXCLUDED.edr_agent,
                os_patch_age_days = EXCLUDED.os_patch_age_days,
                compliant = EXCLUDED.compliant,
                reasons = EXCLUDED.reasons,
                attested_at = EXCLUDED.attested_at,
                expires_at = EXCLUDED.expires_at",
            &[
                &row.id,
                &row.tenant_id,
                &row.user_id,
                &row.device_id,
                &row.provider,
                &row.hostname,
                &row.os_version,
                &row.disk_encrypted,
                &row.edr_running,
                &row.edr_agent,
                &row.os_patch_age_days,
                &row.compliant,
                &row.reasons_json,
                &row.attested_at,
                &row.expires_at,
            ],
        )
        .await
        .map_err(|e| format!("upsert_device_posture: {e}"))?;
        tx.commit().await.map_err(|e| format!("commit tx: {e}"))
    }

    pub async fn list_device_postures(&self) -> Result<Vec<PgDevicePostureRow>, String> {
        let mut guard = self.client.lock().await;
        let tenant_ids = Self::list_tenant_ids(&guard).await?;
        let mut out = Vec::new();
        for tid in tenant_ids {
            let tx = Self::begin_tenant_tx(&mut guard, &tid).await?;
            let rows = tx
                .query(
                    "SELECT id, tenant_id, user_id, device_id, provider, hostname, os_version, \
                            disk_encrypted, edr_running, edr_agent, os_patch_age_days, compliant, \
                            reasons::text, attested_at, expires_at \
                     FROM device_posture_attestations ORDER BY attested_at DESC",
                    &[],
                )
                .await
                .map_err(|e| format!("list_device_postures: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
            for r in rows {
                out.push(PgDevicePostureRow {
                    id: r.get(0),
                    tenant_id: r.get(1),
                    user_id: r.get(2),
                    device_id: r.get(3),
                    provider: r.get(4),
                    hostname: r.get(5),
                    os_version: r.get(6),
                    disk_encrypted: r.get(7),
                    edr_running: r.get(8),
                    edr_agent: r.get(9),
                    os_patch_age_days: r.get(10),
                    compliant: r.get(11),
                    reasons_json: r.get(12),
                    attested_at: r.get(13),
                    expires_at: r.get(14),
                });
            }
        }
        Ok(out)
    }
}
