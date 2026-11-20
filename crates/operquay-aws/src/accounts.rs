#![forbid(unsafe_code)]

//! AWS Access Modes (`hub`/`profiles`/`user`), `AES-256-GCM` encrypted manual accounts,
//! explicit user role bindings, `STS` 5-second lease fences, onboarding hints, preferences,
//! and saved inventory snapshots.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use operquay_auth::crypto::{derive_key32, open_aead, random_token_b64, seal_aead};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::sigv4::{now_unix_secs, sign_request, AwsCredentials};

pub const USER_SESSION_FENCE_SECS: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AwsAccessMode {
    #[default]
    Hub,
    Profiles,
    User,
}

#[derive(Debug, Error)]
pub enum AwsAccountError {
    #[error("account not found")]
    AccountNotFound,
    #[error("role binding not found")]
    BindingNotFound,
    #[error("invalid ARN or account input: {0}")]
    Validation(String),
    #[error("AWS STS/API request failed: {0}")]
    Upstream(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualAwsAccount {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    #[serde(default)]
    pub access_key_id: String,
    #[serde(skip_serializing, default)]
    pub sealed_secret_access_key: Vec<u8>,
    #[serde(skip_serializing, default)]
    pub sealed_session_token: Vec<u8>,
    #[serde(default)]
    pub role_arn: String,
    #[serde(default)]
    pub external_id: String,
    #[serde(default)]
    pub aws_account_id: String,
    #[serde(default)]
    pub default_region: String,
    pub added_at: i64,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub verified_arn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddAwsAccountRequest {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub access_key_id: String,
    #[serde(default)]
    pub secret_access_key: String,
    #[serde(default)]
    pub session_token: String,
    #[serde(default)]
    pub role_arn: String,
    #[serde(default)]
    pub external_id: String,
    #[serde(default = "default_region")]
    pub default_region: String,
}

fn default_region() -> String {
    "us-east-1".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRoleBinding {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub label: String,
    pub account_id: String,
    pub role_arn: String,
    #[serde(default)]
    pub external_id: String,
    #[serde(default)]
    pub principal_arn: String,
    #[serde(default)]
    pub principal_id: String,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default)]
    pub auth_source: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedRoleLease {
    pub id: String,
    pub binding_id: String,
    pub label: String,
    pub account_id: String,
    pub role_arn: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub role_name: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub start_url: String,
    pub region: String,
    pub status: String,
    pub credential_revision: String,
    pub connected_at: i64,
    pub expires_at: i64,
    #[serde(skip)]
    pub credentials: AwsCredentials,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserPreferences {
    #[serde(default)]
    pub default_region: String,
    #[serde(default)]
    pub favorite_instances: Vec<String>,
    #[serde(default)]
    pub default_account_id: String,
    #[serde(default)]
    pub theme: String,
    #[serde(flatten, default)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardingSummary {
    pub tenant_id: String,
    pub aws_access_mode: AwsAccessMode,
    pub mode: AwsAccessMode,
    pub access_keys: bool,
    pub role_name: String,
    pub template: String,
    pub external_id: String,
    pub recommended_policy_arn: String,
    pub trust_principal_arn: String,
}

#[derive(Default)]
struct AccountsInner {
    mode: AwsAccessMode,
    enc_key: [u8; 32],
    accounts: HashMap<String, ManualAwsAccount>,
    bindings: HashMap<String, UserRoleBinding>,
    leases: HashMap<(String, String, String), ConnectedRoleLease>,
    fences: HashMap<(String, String), Instant>,
    preferences: HashMap<(String, String), UserPreferences>,
    saved_inventory: HashMap<(String, String), Vec<serde_json::Value>>,
    sts_endpoint: Option<String>,
}

pub struct AwsAccountStore {
    inner: RwLock<AccountsInner>,
    http: reqwest::Client,
}

impl Default for AwsAccountStore {
    fn default() -> Self {
        Self::new(AwsAccessMode::Hub, None)
    }
}

impl AwsAccountStore {
    #[must_use]
    pub fn new(mode: AwsAccessMode, sts_endpoint: Option<String>) -> Self {
        let secret = random_token_b64();
        let enc_key = derive_key32(secret.as_bytes(), b"operquay-aws-account-aead-v1");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self {
            inner: RwLock::new(AccountsInner {
                mode,
                enc_key,
                sts_endpoint,
                ..AccountsInner::default()
            }),
            http,
        }
    }

    pub async fn mode(&self) -> AwsAccessMode {
        self.inner.read().await.mode
    }

    pub async fn set_mode(&self, mode: AwsAccessMode) {
        self.inner.write().await.mode = mode;
    }

    pub async fn list_accounts(&self, tenant_id: &str) -> Vec<ManualAwsAccount> {
        let mut items: Vec<_> = self
            .inner
            .read()
            .await
            .accounts
            .values()
            .filter(|a| a.tenant_id == tenant_id)
            .cloned()
            .collect();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        items
    }

    pub async fn add_account(
        &self,
        tenant_id: &str,
        req: AddAwsAccountRequest,
    ) -> Result<ManualAwsAccount, AwsAccountError> {
        let role_arn = req.role_arn.trim().to_owned();
        let access_key_id = req.access_key_id.trim().to_owned();
        let aws_acc = extract_account_id_from_arn(&role_arn);
        let derived_name = if !req.name.trim().is_empty() {
            req.name.trim().to_owned()
        } else if !role_arn.is_empty() {
            role_arn
                .rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
                .map_or_else(
                    || {
                        if aws_acc.is_empty() {
                            role_arn.clone()
                        } else {
                            aws_acc.clone()
                        }
                    },
                    |r| {
                        if aws_acc.is_empty() {
                            r.to_owned()
                        } else {
                            format!("{aws_acc}-{r}")
                        }
                    },
                )
        } else if !access_key_id.is_empty() {
            let prefix: String = access_key_id.chars().take(8).collect();
            format!("aws-{prefix}")
        } else {
            return Err(AwsAccountError::Validation(
                "account name, role_arn, or access_key_id required".into(),
            ));
        };
        let guard_key = self.inner.read().await.enc_key;
        let id = format!("aws-{}", Uuid::new_v4());
        let aad = format!("{tenant_id}:{id}");
        let sealed_secret = if req.secret_access_key.is_empty() {
            Vec::new()
        } else {
            seal_aead(&guard_key, aad.as_bytes(), req.secret_access_key.as_bytes())
                .map_err(AwsAccountError::Upstream)?
        };
        let sealed_tok = if req.session_token.is_empty() {
            Vec::new()
        } else {
            seal_aead(&guard_key, aad.as_bytes(), req.session_token.as_bytes())
                .map_err(AwsAccountError::Upstream)?
        };
        let acc = ManualAwsAccount {
            id: id.clone(),
            tenant_id: tenant_id.to_owned(),
            name: derived_name,
            access_key_id,
            sealed_secret_access_key: sealed_secret,
            sealed_session_token: sealed_tok,
            role_arn,
            external_id: req.external_id.trim().to_owned(),
            aws_account_id: aws_acc,
            default_region: if req.default_region.trim().is_empty() {
                "us-east-1".to_owned()
            } else {
                req.default_region.trim().to_owned()
            },
            added_at: now_unix_secs(),
            verified: false,
            verified_arn: String::new(),
        };
        self.inner.write().await.accounts.insert(id, acc.clone());
        Ok(acc)
    }

    pub async fn delete_account(&self, tenant_id: &str, id: &str) -> Result<(), AwsAccountError> {
        let mut guard = self.inner.write().await;
        if guard
            .accounts
            .get(id)
            .is_some_and(|a| a.tenant_id == tenant_id)
        {
            guard.accounts.remove(id);
            Ok(())
        } else {
            Err(AwsAccountError::AccountNotFound)
        }
    }

    pub async fn credentials_for_account(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<AwsCredentials, AwsAccountError> {
        let guard = self.inner.read().await;
        let acc = guard
            .accounts
            .get(id)
            .filter(|a| a.tenant_id == tenant_id)
            .ok_or(AwsAccountError::AccountNotFound)?;
        let aad = format!("{tenant_id}:{}", acc.id);
        let secret = if acc.sealed_secret_access_key.is_empty() {
            String::new()
        } else {
            let pt = open_aead(
                &guard.enc_key,
                aad.as_bytes(),
                &acc.sealed_secret_access_key,
            )
            .map_err(|_| AwsAccountError::Upstream("failed decrypting secret key".into()))?;
            String::from_utf8_lossy(&pt).into_owned()
        };
        let session_token = if acc.sealed_session_token.is_empty() {
            None
        } else {
            let pt = open_aead(&guard.enc_key, aad.as_bytes(), &acc.sealed_session_token)
                .map_err(|_| AwsAccountError::Upstream("failed decrypting session token".into()))?;
            Some(String::from_utf8_lossy(&pt).into_owned())
        };
        Ok(AwsCredentials {
            access_key_id: acc.access_key_id.clone(),
            secret_access_key: secret,
            session_token,
        })
    }

    /// Call AWS STS `AssumeRole` using `caller_creds` (or configured `sts_endpoint`),
    /// returning temporary credentials along with assumed ARN and account ID.
    pub async fn assume_role_with_sts(
        &self,
        region: &str,
        role_arn: &str,
        external_id: Option<&str>,
        role_session_name: &str,
        caller_creds: &AwsCredentials,
    ) -> Result<(AwsCredentials, String, String), AwsAccountError> {
        let reg = if region.trim().is_empty() {
            "us-east-1"
        } else {
            region.trim()
        };
        let arn = role_arn.trim();
        if !arn.starts_with("arn:aws") {
            return Err(AwsAccountError::Validation(
                "role_arn must start with arn:aws".into(),
            ));
        }
        if caller_creds.access_key_id.trim().is_empty()
            || caller_creds.secret_access_key.trim().is_empty()
        {
            return Err(AwsAccountError::Validation(
                "caller AWS credentials are required for sts:AssumeRole".into(),
            ));
        }
        let base = self
            .inner
            .read()
            .await
            .sts_endpoint
            .clone()
            .unwrap_or_else(|| format!("https://sts.{reg}.amazonaws.com/"));
        let sep = if base.contains('?') { '&' } else { '?' };
        let session = if role_session_name.trim().is_empty() {
            "operquay-session"
        } else {
            role_session_name.trim()
        };
        let mut url = format!(
            "{base}{sep}Action=AssumeRole&Version=2011-06-15&RoleArn={}&RoleSessionName={}",
            pct_encode(arn),
            pct_encode(session)
        );
        if let Some(ext) = external_id.map(str::trim).filter(|s| !s.is_empty()) {
            url.push_str("&ExternalId=");
            url.push_str(&pct_encode(ext));
        }
        let mut headers = http::HeaderMap::new();
        sign_request(
            "POST",
            &url,
            &mut headers,
            b"",
            caller_creds,
            reg,
            "sts",
            None,
        )
        .map_err(AwsAccountError::Upstream)?;
        let resp = self
            .http
            .post(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| AwsAccountError::Upstream(e.to_string()))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| AwsAccountError::Upstream(e.to_string()))?;
        if !status.is_success() {
            return Err(AwsAccountError::Upstream(format!(
                "STS AssumeRole returned {status}: {body}"
            )));
        }
        let ak = xml_tag_text(&body, "AccessKeyId").ok_or_else(|| {
            AwsAccountError::Upstream("STS AssumeRole missing AccessKeyId".into())
        })?;
        let sk = xml_tag_text(&body, "SecretAccessKey").ok_or_else(|| {
            AwsAccountError::Upstream("STS AssumeRole missing SecretAccessKey".into())
        })?;
        let st = xml_tag_text(&body, "SessionToken");
        let assumed_arn = xml_tag_text(&body, "AssumedRoleUser")
            .and_then(|block| xml_tag_text(&block, "Arn"))
            .or_else(|| xml_tag_text(&body, "Arn"))
            .unwrap_or_else(|| arn.to_owned());
        let account_id = extract_account_id_from_arn(&assumed_arn)
            .chars()
            .collect::<String>();
        let account_id = if account_id.is_empty() {
            extract_account_id_from_arn(arn)
        } else {
            account_id
        };
        Ok((
            AwsCredentials {
                access_key_id: ak,
                secret_access_key: sk,
                session_token: st.filter(|s| !s.is_empty()),
            },
            assumed_arn,
            account_id,
        ))
    }

    /// Resolve effective credentials for a stored manual account: decrypt static keys and,
    /// if `role_arn` is set, exchange them via `sts:AssumeRole` (using ambient creds as caller
    /// if static keys are omitted in hub mode).
    pub async fn resolve_account_credentials(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<AwsCredentials, AwsAccountError> {
        let base_creds = self.credentials_for_account(tenant_id, id).await?;
        let (role_arn, external_id, region) = {
            let guard = self.inner.read().await;
            let acc = guard
                .accounts
                .get(id)
                .filter(|a| a.tenant_id == tenant_id)
                .ok_or(AwsAccountError::AccountNotFound)?;
            (
                acc.role_arn.clone(),
                acc.external_id.clone(),
                acc.default_region.clone(),
            )
        };
        if !base_creds.access_key_id.is_empty() && !base_creds.secret_access_key.is_empty() {
            return Ok(base_creds);
        }
        if role_arn.is_empty() {
            return Ok(base_creds);
        }
        let caller = ambient_aws_credentials().ok_or_else(|| {
            AwsAccountError::Validation(
                "role_arn configured without static keys and no ambient AWS credentials found"
                    .into(),
            )
        })?;
        let ext = if external_id.is_empty() {
            None
        } else {
            Some(external_id.as_str())
        };
        let (assumed, _, _) = self
            .assume_role_with_sts(&region, &role_arn, ext, "operquay-hub", &caller)
            .await?;
        Ok(assumed)
    }

    /// Verify credentials with `sts:GetCallerIdentity` against AWS STS or configured endpoint.
    pub async fn verify_account(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<ManualAwsAccount, AwsAccountError> {
        let creds = self.resolve_account_credentials(tenant_id, id).await?;
        let (region, endpoint_override) = {
            let guard = self.inner.read().await;
            let acc = guard
                .accounts
                .get(id)
                .filter(|a| a.tenant_id == tenant_id)
                .ok_or(AwsAccountError::AccountNotFound)?;
            (acc.default_region.clone(), guard.sts_endpoint.clone())
        };
        let url = endpoint_override
            .unwrap_or_else(|| format!("https://sts.{region}.amazonaws.com/"))
            + "?Action=GetCallerIdentity&Version=2011-06-15";
        let mut headers = http::HeaderMap::new();
        sign_request(
            "POST",
            &url,
            &mut headers,
            b"",
            &creds,
            &region,
            "sts",
            None,
        )
        .map_err(AwsAccountError::Upstream)?;
        let resp = self
            .http
            .post(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| AwsAccountError::Upstream(e.to_string()))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| AwsAccountError::Upstream(e.to_string()))?;
        if !status.is_success() {
            return Err(AwsAccountError::Upstream(format!(
                "STS returned {status}: {body}"
            )));
        }
        let account = xml_tag_text(&body, "Account").unwrap_or_default();
        let arn = xml_tag_text(&body, "Arn").unwrap_or_default();
        let mut guard = self.inner.write().await;
        let acc = guard
            .accounts
            .get_mut(id)
            .ok_or(AwsAccountError::AccountNotFound)?;
        acc.verified = true;
        if !account.is_empty() {
            acc.aws_account_id = account;
        }
        acc.verified_arn = arn;
        Ok(acc.clone())
    }

    pub async fn onboarding(&self, tenant_id: &str) -> OnboardingSummary {
        let mode = self.inner.read().await.mode;
        let access_keys = !std::env::var("OPERQUAY_DISABLE_ACCESS_KEYS")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        let trust_principal_arn = std::env::var("OPERQUAY_TRUST_PRINCIPAL_ARN")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "arn:aws:iam::000000000000:root".to_owned());
        OnboardingSummary {
            tenant_id: tenant_id.to_owned(),
            aws_access_mode: mode,
            mode,
            access_keys,
            role_name: "OperquayAccess".to_owned(),
            template: "deploy/cloudformation/operquay-access.yaml".to_owned(),
            external_id: format!("operquay-{tenant_id}"),
            recommended_policy_arn: "arn:aws:iam::aws:policy/ReadOnlyAccess".to_owned(),
            trust_principal_arn,
        }
    }

    pub async fn list_user_bindings(&self, tenant_id: &str, user_id: &str) -> Vec<UserRoleBinding> {
        let mut list: Vec<_> = self
            .inner
            .read()
            .await
            .bindings
            .values()
            .filter(|b| b.tenant_id == tenant_id && b.user_id == user_id)
            .cloned()
            .collect();
        list.sort_by(|a, b| a.label.cmp(&b.label));
        list
    }

    pub async fn list_all_tenant_bindings(&self, tenant_id: &str) -> Vec<UserRoleBinding> {
        let mut list: Vec<_> = self
            .inner
            .read()
            .await
            .bindings
            .values()
            .filter(|b| b.tenant_id == tenant_id)
            .cloned()
            .collect();
        list.sort_by(|a, b| a.label.cmp(&b.label));
        list
    }

    pub async fn get_user_binding(
        &self,
        tenant_id: &str,
        user_id: &str,
        id: &str,
    ) -> Option<UserRoleBinding> {
        self.inner
            .read()
            .await
            .bindings
            .get(id)
            .filter(|b| b.tenant_id == tenant_id && b.user_id == user_id)
            .cloned()
    }

    pub async fn create_user_binding(
        &self,
        tenant_id: &str,
        user_id: &str,
        label: &str,
        role_arn: &str,
        external_id: &str,
        region: &str,
    ) -> Result<UserRoleBinding, AwsAccountError> {
        self.create_user_binding_with_principal(
            tenant_id,
            user_id,
            label,
            role_arn,
            external_id,
            region,
            "",
            "",
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_user_binding_with_principal(
        &self,
        tenant_id: &str,
        user_id: &str,
        label: &str,
        role_arn: &str,
        external_id: &str,
        region: &str,
        principal_arn: &str,
        principal_id: &str,
    ) -> Result<UserRoleBinding, AwsAccountError> {
        if !role_arn.trim().starts_with("arn:aws") {
            return Err(AwsAccountError::Validation(
                "role_arn must start with arn:aws".into(),
            ));
        }
        let binding = UserRoleBinding {
            id: format!("bind-{}", Uuid::new_v4()),
            tenant_id: tenant_id.to_owned(),
            user_id: user_id.to_owned(),
            label: if label.trim().is_empty() {
                role_arn.trim().to_owned()
            } else {
                label.trim().to_owned()
            },
            account_id: extract_account_id_from_arn(role_arn.trim()),
            role_arn: role_arn.trim().to_owned(),
            external_id: external_id.trim().to_owned(),
            principal_arn: principal_arn.trim().to_owned(),
            principal_id: principal_id.trim().to_owned(),
            region: if region.trim().is_empty() {
                "us-east-1".to_owned()
            } else {
                region.trim().to_owned()
            },
            auth_source: "sts".to_owned(),
            created_at: now_unix_secs(),
        };
        self.inner
            .write()
            .await
            .bindings
            .insert(binding.id.clone(), binding.clone());
        Ok(binding)
    }

    pub async fn delete_user_binding(
        &self,
        tenant_id: &str,
        user_id: &str,
        id: &str,
    ) -> Result<(), AwsAccountError> {
        let mut guard = self.inner.write().await;
        if guard
            .bindings
            .get(id)
            .is_some_and(|b| b.tenant_id == tenant_id && b.user_id == user_id)
        {
            guard.bindings.remove(id);
            guard
                .leases
                .remove(&(tenant_id.to_owned(), user_id.to_owned(), id.to_owned()));
            Ok(())
        } else {
            Err(AwsAccountError::BindingNotFound)
        }
    }

    pub async fn delete_binding_any_user(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<(), AwsAccountError> {
        let mut guard = self.inner.write().await;
        if let Some(binding) = guard.bindings.get(id).cloned() {
            if binding.tenant_id == tenant_id {
                guard.bindings.remove(id);
                guard
                    .leases
                    .remove(&(tenant_id.to_owned(), binding.user_id, id.to_owned()));
                return Ok(());
            }
        }
        Err(AwsAccountError::BindingNotFound)
    }

    /// Connect a user role binding, clearing any disconnect fence, or assume via STS endpoint if creds available.
    pub async fn connect_role_lease(
        &self,
        tenant_id: &str,
        user_id: &str,
        binding_id: &str,
        creds: AwsCredentials,
    ) -> Result<ConnectedRoleLease, AwsAccountError> {
        let mut guard = self.inner.write().await;
        let binding = guard
            .bindings
            .get(binding_id)
            .filter(|b| b.tenant_id == tenant_id && b.user_id == user_id)
            .ok_or(AwsAccountError::BindingNotFound)?
            .clone();
        if let Some(fence_until) = guard
            .fences
            .get(&(tenant_id.to_owned(), user_id.to_owned()))
        {
            if Instant::now() < *fence_until {
                guard
                    .fences
                    .remove(&(tenant_id.to_owned(), user_id.to_owned()));
            }
        }
        let now = now_unix_secs();
        let rev = format!("rev-{}", Uuid::new_v4());
        let lease = ConnectedRoleLease {
            id: binding.id.clone(),
            binding_id: binding.id.clone(),
            label: binding.label,
            account_id: binding.account_id,
            role_arn: binding.role_arn,
            role_name: String::new(),
            start_url: String::new(),
            region: binding.region,
            status: "connected".to_owned(),
            credential_revision: rev,
            connected_at: now,
            expires_at: now + 3600,
            credentials: creds,
        };
        guard.leases.insert(
            (
                tenant_id.to_owned(),
                user_id.to_owned(),
                binding_id.to_owned(),
            ),
            lease.clone(),
        );
        Ok(lease)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect_sso_role_lease(
        &self,
        tenant_id: &str,
        user_id: &str,
        account_id: &str,
        role_name: &str,
        start_url: &str,
        region: &str,
        label: &str,
        creds: AwsCredentials,
    ) -> ConnectedRoleLease {
        let mut guard = self.inner.write().await;
        guard
            .fences
            .remove(&(tenant_id.to_owned(), user_id.to_owned()));
        let now = now_unix_secs();
        let id = format!("sso-{}", Uuid::new_v4());
        let rev = format!("rev-{}", Uuid::new_v4());
        let lease = ConnectedRoleLease {
            id: id.clone(),
            binding_id: id.clone(),
            label: label.to_owned(),
            account_id: account_id.to_owned(),
            role_arn: format!("arn:aws:iam::{account_id}:role/{role_name}"),
            role_name: role_name.to_owned(),
            start_url: start_url.to_owned(),
            region: region.to_owned(),
            status: "connected".to_owned(),
            credential_revision: rev,
            connected_at: now,
            expires_at: now + 3600,
            credentials: creds,
        };
        guard.leases.insert(
            (tenant_id.to_owned(), user_id.to_owned(), id),
            lease.clone(),
        );
        lease
    }

    pub async fn list_connected_roles(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Vec<ConnectedRoleLease> {
        let now = now_unix_secs();
        self.inner
            .read()
            .await
            .leases
            .iter()
            .filter(|((t, u, _), l)| t == tenant_id && u == user_id && l.expires_at > now)
            .map(|(_, l)| l.clone())
            .collect()
    }

    pub async fn find_connected_role_lease(
        &self,
        tenant_id: &str,
        role_id_or_profile: &str,
    ) -> Option<ConnectedRoleLease> {
        let needle = role_id_or_profile
            .trim()
            .strip_prefix("user:")
            .unwrap_or(role_id_or_profile.trim());
        let now = now_unix_secs();
        let guard = self.inner.read().await;
        if !needle.is_empty() {
            if let Some(hit) = guard
                .leases
                .iter()
                .find(|((t, _, bid), l)| {
                    t == tenant_id && (bid == needle || l.id == needle) && l.expires_at > now
                })
                .map(|(_, l)| l.clone())
            {
                return Some(hit);
            }
        }
        None
    }

    pub async fn find_connected_role_lease_for_user(
        &self,
        tenant_id: &str,
        user_id: &str,
        role_id_or_profile: &str,
    ) -> Option<ConnectedRoleLease> {
        let needle = role_id_or_profile
            .trim()
            .strip_prefix("user:")
            .unwrap_or(role_id_or_profile.trim());
        let now = now_unix_secs();
        let guard = self.inner.read().await;
        if needle.is_empty() {
            return None;
        }
        guard
            .leases
            .iter()
            .find(|((t, u, bid), l)| {
                t == tenant_id
                    && u == user_id
                    && (bid == needle || l.id == needle || l.binding_id == needle)
                    && l.expires_at > now
            })
            .map(|(_, l)| l.clone())
    }

    /// Connect an ad-hoc user role lease (when logging in directly with `role_arn` + credentials
    /// without a pre-created saved binding).
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_adhoc_role_lease(
        &self,
        tenant_id: &str,
        user_id: &str,
        binding_id: Option<&str>,
        label: &str,
        account_id: &str,
        role_arn: &str,
        region: &str,
        creds: AwsCredentials,
    ) -> ConnectedRoleLease {
        let mut guard = self.inner.write().await;
        guard
            .fences
            .remove(&(tenant_id.to_owned(), user_id.to_owned()));
        let now = now_unix_secs();
        let id = binding_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map_or_else(|| format!("iam-{}", Uuid::new_v4()), ToOwned::to_owned);
        let rev = format!("rev-{}", Uuid::new_v4());
        let role_name = role_arn
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("")
            .to_owned();
        let lease = ConnectedRoleLease {
            id: id.clone(),
            binding_id: id.clone(),
            label: if label.trim().is_empty() {
                role_arn.to_owned()
            } else {
                label.trim().to_owned()
            },
            account_id: if account_id.is_empty() {
                extract_account_id_from_arn(role_arn)
            } else {
                account_id.to_owned()
            },
            role_arn: role_arn.to_owned(),
            role_name,
            start_url: String::new(),
            region: if region.trim().is_empty() {
                "us-east-1".to_owned()
            } else {
                region.trim().to_owned()
            },
            status: "connected".to_owned(),
            credential_revision: rev,
            connected_at: now,
            expires_at: now + 3600,
            credentials: creds,
        };
        guard.leases.insert(
            (tenant_id.to_owned(), user_id.to_owned(), id),
            lease.clone(),
        );
        lease
    }

    pub async fn disconnect_user_role(&self, tenant_id: &str, user_id: &str, binding_id: &str) {
        self.inner.write().await.leases.remove(&(
            tenant_id.to_owned(),
            user_id.to_owned(),
            binding_id.to_owned(),
        ));
    }

    /// Enforce a 5-second disconnect fence (matches Go `user_aws_fence.go`) that revokes active leases
    /// and prevents late background polls from restoring credentials right after disconnect.
    pub async fn disconnect_all_user_roles(&self, tenant_id: &str, user_id: &str) {
        let mut guard = self.inner.write().await;
        guard
            .leases
            .retain(|(t, u, _), _| !(t == tenant_id && u == user_id));
        guard.fences.insert(
            (tenant_id.to_owned(), user_id.to_owned()),
            Instant::now() + Duration::from_secs(USER_SESSION_FENCE_SECS),
        );
    }

    pub async fn is_user_fenced(&self, tenant_id: &str, user_id: &str) -> bool {
        self.inner
            .read()
            .await
            .fences
            .get(&(tenant_id.to_owned(), user_id.to_owned()))
            .is_some_and(|until| Instant::now() < *until)
    }

    pub async fn get_preferences(&self, tenant_id: &str, user_id: &str) -> UserPreferences {
        self.inner
            .read()
            .await
            .preferences
            .get(&(tenant_id.to_owned(), user_id.to_owned()))
            .cloned()
            .unwrap_or_default()
    }

    pub async fn save_preferences(
        &self,
        tenant_id: &str,
        user_id: &str,
        prefs: UserPreferences,
    ) -> UserPreferences {
        self.inner
            .write()
            .await
            .preferences
            .insert((tenant_id.to_owned(), user_id.to_owned()), prefs.clone());
        prefs
    }

    pub async fn save_inventory_snapshot(
        &self,
        tenant_id: &str,
        user_id: &str,
        items: Vec<serde_json::Value>,
    ) {
        self.inner
            .write()
            .await
            .saved_inventory
            .insert((tenant_id.to_owned(), user_id.to_owned()), items);
    }

    pub async fn get_saved_inventory(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Vec<serde_json::Value> {
        self.inner
            .read()
            .await
            .saved_inventory
            .get(&(tenant_id.to_owned(), user_id.to_owned()))
            .cloned()
            .unwrap_or_default()
    }

    pub async fn forget_saved_inventory(&self, tenant_id: &str, user_id: &str) {
        self.inner
            .write()
            .await
            .saved_inventory
            .remove(&(tenant_id.to_owned(), user_id.to_owned()));
    }

    pub async fn hydrate_bindings(&self, items: Vec<UserRoleBinding>) {
        let mut guard = self.inner.write().await;
        for b in items {
            guard.bindings.insert(b.id.clone(), b);
        }
    }

    pub async fn hydrate_leases(&self, items: Vec<(String, String, ConnectedRoleLease)>) {
        let now = now_unix_secs();
        let mut guard = self.inner.write().await;
        for (tenant_id, user_id, lease) in items {
            if lease.expires_at > now {
                guard
                    .leases
                    .insert((tenant_id, user_id, lease.id.clone()), lease);
            }
        }
    }

    pub async fn hydrate_preferences(&self, items: Vec<(String, String, UserPreferences)>) {
        let mut guard = self.inner.write().await;
        for (tenant_id, user_id, prefs) in items {
            guard.preferences.insert((tenant_id, user_id), prefs);
        }
    }

    pub async fn hydrate_saved_inventory(
        &self,
        items: Vec<(String, String, Vec<serde_json::Value>)>,
    ) {
        let mut guard = self.inner.write().await;
        for (tenant_id, user_id, vals) in items {
            guard.saved_inventory.insert((tenant_id, user_id), vals);
        }
    }
}

#[must_use]
pub fn ambient_aws_credentials() -> Option<AwsCredentials> {
    let ak = std::env::var("AWS_ACCESS_KEY_ID").ok()?;
    let sk = std::env::var("AWS_SECRET_ACCESS_KEY").ok()?;
    if ak.trim().is_empty() || sk.trim().is_empty() {
        return None;
    }
    let st = std::env::var("AWS_SESSION_TOKEN")
        .ok()
        .filter(|s| !s.trim().is_empty());
    Some(AwsCredentials {
        access_key_id: ak,
        secret_access_key: sk,
        session_token: st,
    })
}

fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

#[must_use]
pub fn extract_account_id_from_arn(arn: &str) -> String {
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() >= 5 && parts[4].len() == 12 && parts[4].bytes().all(|b| b.is_ascii_digit()) {
        parts[4].to_owned()
    } else {
        String::new()
    }
}

#[must_use]
pub fn xml_tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&close)?;
    Some(xml[start..end].trim().to_owned())
}
