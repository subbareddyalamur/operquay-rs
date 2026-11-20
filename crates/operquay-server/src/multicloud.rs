#![forbid(unsafe_code)]

//! Multi-Cloud Connectors for Microsoft Azure (Entra ID Device Code SSO, Managed Identity,
//! Workload Identity OIDC Federation, Service Principal, Compute / AKS / RBAC) &
//! Google Cloud Platform (Interactive `OAuth2` PKCE SSO, Workload Identity Federation, GCE/GKE Metadata ADC,
//! Service Account RS256 `OAuth2`, Compute Engine / GKE / IAM) (`M12.3`).

use std::collections::HashMap;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use operquay_auth::crypto::fill_csprng;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::jit::now_unix_secs;

/// Azure CLI well-known public client ID supporting secretless RFC 8628 Entra Device Code SSO.
pub const DEFAULT_AZURE_PUBLIC_CLIENT_ID: &str = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudConnectorRecord {
    pub id: String,
    pub tenant_id: String,
    pub provider: String,
    pub name: String,
    pub account_or_project_id: String,
    #[serde(default)]
    pub tenant_or_org_id: String,
    #[serde(default)]
    pub region: String,
    #[serde(skip_serializing)]
    pub credentials_json: String,
    #[serde(default)]
    pub config: serde_json::Value,
    pub status: String,
    #[serde(default)]
    pub last_synced_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicCloudConnector {
    pub id: String,
    pub tenant_id: String,
    pub provider: String,
    pub name: String,
    pub account_or_project_id: String,
    pub tenant_or_org_id: String,
    pub region: String,
    pub auth_mode: String,
    pub has_credentials: bool,
    pub config: serde_json::Value,
    pub status: String,
    pub last_synced_at: Option<i64>,
    pub created_at: i64,
}

impl From<&CloudConnectorRecord> for PublicCloudConnector {
    fn from(c: &CloudConnectorRecord) -> Self {
        let auth_mode = c.config["auth_mode"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map_or_else(
                || {
                    if c.provider == "azure" {
                        "service_principal".to_owned()
                    } else {
                        "service_account".to_owned()
                    }
                },
                ToOwned::to_owned,
            );
        Self {
            id: c.id.clone(),
            tenant_id: c.tenant_id.clone(),
            provider: c.provider.clone(),
            name: c.name.clone(),
            account_or_project_id: c.account_or_project_id.clone(),
            tenant_or_org_id: c.tenant_or_org_id.clone(),
            region: c.region.clone(),
            auth_mode,
            has_credentials: !c.credentials_json.trim().is_empty(),
            config: c.config.clone(),
            status: c.status.clone(),
            last_synced_at: c.last_synced_at,
            created_at: c.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudResourceItem {
    pub id: String,
    pub tenant_id: String,
    pub connector_id: String,
    pub provider: String,
    pub kind: String,
    pub name: String,
    pub region: String,
    pub state: String,
    pub account_or_project: String,
    pub bastion_or_iap_uri: String,
    #[serde(default)]
    pub private_ip: String,
    #[serde(default)]
    pub is_privileged: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateCloudConnectorInput {
    pub provider: String,
    pub name: String,
    pub account_or_project_id: String,
    #[serde(default)]
    pub tenant_or_org_id: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub credentials: serde_json::Value,
    #[serde(default)]
    pub config: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Azure Entra ID Device Code SSO & Keyless Auth Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct AzureSsoStartInput {
    #[serde(default)]
    pub entra_tenant: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub auth_base_url: String,
    #[serde(default)]
    pub arm_base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureSubscriptionInfo {
    pub subscription_id: String,
    pub display_name: String,
    pub state: String,
    #[serde(default)]
    pub tenant_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicAzureSsoStart {
    pub flow_id: String,
    pub entra_tenant: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    pub message: String,
    pub interval_seconds: u64,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AzureSsoPollResult {
    pub status: String,
    #[serde(default)]
    pub subscriptions: Vec<AzureSubscriptionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
struct AzureSsoFlow {
    tenant_id: String,
    user_id: String,
    entra_tenant: String,
    client_id: String,
    auth_base_url: String,
    arm_base_url: String,
    device_code: String,
    expires_at: i64,
    status: String,
    access_token: String,
    refresh_token: String,
    token_expires_at: i64,
    subscriptions: Vec<AzureSubscriptionInfo>,
}

// ---------------------------------------------------------------------------
// GCP OAuth2 PKCE SSO & Keyless Auth Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct GcpSsoStartInput {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub auth_base_url: String,
    #[serde(default)]
    pub token_url: String,
    #[serde(default)]
    pub crm_base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpProjectInfo {
    pub project_id: String,
    pub name: String,
    pub project_number: String,
    pub lifecycle_state: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicGcpSsoStart {
    pub flow_id: String,
    pub authorization_url: String,
    pub redirect_uri: String,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GcpSsoStatusResult {
    pub flow_id: String,
    pub status: String,
    pub projects: Vec<GcpProjectInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
struct GcpSsoFlow {
    id: String,
    state: String,
    tenant_id: String,
    user_id: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    code_verifier: String,
    token_url: String,
    crm_base_url: String,
    status: String,
    error_msg: Option<String>,
    access_token: String,
    refresh_token: String,
    token_expires_at: i64,
    projects: Vec<GcpProjectInfo>,
    expires_at: i64,
}

#[derive(Default)]
pub struct MultiCloudStore {
    connectors: RwLock<HashMap<String, CloudConnectorRecord>>,
    resources: RwLock<HashMap<String, Vec<CloudResourceItem>>>,
    azure_flows: RwLock<HashMap<String, AzureSsoFlow>>,
    gcp_flows: RwLock<HashMap<String, GcpSsoFlow>>,
}

impl MultiCloudStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn add_connector(
        &self,
        tenant_id: &str,
        input: CreateCloudConnectorInput,
    ) -> Result<CloudConnectorRecord, String> {
        let provider = input.provider.trim().to_ascii_lowercase();
        if provider != "azure" && provider != "gcp" {
            return Err("provider must be 'azure' or 'gcp'".to_owned());
        }
        if input.name.trim().is_empty() || input.account_or_project_id.trim().is_empty() {
            return Err("name and account_or_project_id are required".to_owned());
        }
        let rec = CloudConnectorRecord {
            id: format!("cld-{}", Uuid::new_v4()),
            tenant_id: tenant_id.to_owned(),
            provider,
            name: input.name.trim().to_owned(),
            account_or_project_id: input.account_or_project_id.trim().to_owned(),
            tenant_or_org_id: input.tenant_or_org_id.trim().to_owned(),
            region: input.region.trim().to_owned(),
            credentials_json: serde_json::to_string(&input.credentials)
                .unwrap_or_else(|_| "{}".to_owned()),
            config: input.config,
            status: "configured".to_owned(),
            last_synced_at: None,
            created_at: now_unix_secs(),
        };
        self.connectors
            .write()
            .await
            .insert(rec.id.clone(), rec.clone());
        Ok(rec)
    }

    pub async fn list_connectors(&self, tenant_id: &str) -> Vec<PublicCloudConnector> {
        let mut out: Vec<_> = self
            .connectors
            .read()
            .await
            .values()
            .filter(|c| c.tenant_id == tenant_id)
            .map(PublicCloudConnector::from)
            .collect();
        out.sort_by_key(|c| std::cmp::Reverse(c.created_at));
        out
    }

    pub async fn get_connector(&self, tenant_id: &str, id: &str) -> Option<CloudConnectorRecord> {
        self.connectors
            .read()
            .await
            .get(id)
            .filter(|c| c.tenant_id == tenant_id)
            .cloned()
    }

    pub async fn update_synced(
        &self,
        tenant_id: &str,
        connector_id: &str,
        items: Vec<CloudResourceItem>,
    ) -> Option<CloudConnectorRecord> {
        let mut guard = self.connectors.write().await;
        let rec = guard
            .get_mut(connector_id)
            .filter(|c| c.tenant_id == tenant_id)?;
        "connected".clone_into(&mut rec.status);
        rec.last_synced_at = Some(now_unix_secs());
        let saved = rec.clone();
        drop(guard);
        self.resources
            .write()
            .await
            .insert(connector_id.to_owned(), items);
        Some(saved)
    }

    pub async fn delete_connector(&self, tenant_id: &str, id: &str) -> bool {
        let mut guard = self.connectors.write().await;
        if guard.get(id).is_some_and(|c| c.tenant_id == tenant_id) {
            guard.remove(id);
            drop(guard);
            self.resources.write().await.remove(id);
            true
        } else {
            false
        }
    }

    pub async fn list_resources(
        &self,
        tenant_id: &str,
        provider_filter: Option<&str>,
    ) -> Vec<CloudResourceItem> {
        let pf = provider_filter.map(str::trim).filter(|s| !s.is_empty());
        self.resources
            .read()
            .await
            .values()
            .flatten()
            .filter(|r| r.tenant_id == tenant_id && pf.is_none_or(|p| r.provider == p))
            .cloned()
            .collect()
    }

    pub async fn hydrate_connectors(&self, items: Vec<CloudConnectorRecord>) {
        let mut guard = self.connectors.write().await;
        for c in items {
            guard.insert(c.id.clone(), c);
        }
    }

    // -----------------------------------------------------------------------
    // Azure Entra ID Device Code SSO Flow (Zero Client Secret)
    // -----------------------------------------------------------------------

    pub async fn start_azure_device_sso(
        &self,
        http: &reqwest::Client,
        tenant_id: &str,
        user_id: &str,
        input: AzureSsoStartInput,
    ) -> Result<PublicAzureSsoStart, String> {
        let entra_tenant = {
            let trimmed = input.entra_tenant.trim();
            if trimmed.is_empty() {
                "organizations".to_owned()
            } else {
                trimmed.to_owned()
            }
        };
        let env_client = std::env::var("OPERQUAY_AZURE_CLIENT_ID").unwrap_or_default();
        let client_id = first_non_empty(&[
            input.client_id.trim(),
            env_client.trim(),
            DEFAULT_AZURE_PUBLIC_CLIENT_ID,
        ]);
        let auth_base = first_non_empty(&[
            input.auth_base_url.trim().trim_end_matches('/'),
            "https://login.microsoftonline.com",
        ]);
        let arm_base = first_non_empty(&[
            input.arm_base_url.trim().trim_end_matches('/'),
            "https://management.azure.com",
        ]);

        let resp = http
            .post(format!("{auth_base}/{entra_tenant}/oauth2/v2.0/devicecode"))
            .timeout(Duration::from_secs(15))
            .form(&[
                ("client_id", client_id.as_str()),
                (
                    "scope",
                    "https://management.azure.com/.default offline_access",
                ),
            ])
            .send()
            .await
            .map_err(|e| format!("Entra device authorization request failed: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let err_txt = resp.text().await.unwrap_or_default();
            return Err(format!(
                "Entra device code initiation failed ({status}): {err_txt}"
            ));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Entra device code response parse failed: {e}"))?;

        let device_code = body["device_code"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "Entra response missing device_code".to_owned())?
            .to_owned();
        let user_code = body["user_code"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "Entra response missing user_code".to_owned())?
            .to_owned();
        let verification_uri = body["verification_uri"]
            .as_str()
            .or_else(|| body["verification_url"].as_str())
            .unwrap_or("https://microsoft.com/devicelogin")
            .to_owned();
        let verification_uri_complete = body["verification_uri_complete"]
            .as_str()
            .map(ToOwned::to_owned);
        let interval_secs = body["interval"].as_u64().unwrap_or(5).clamp(1, 30);
        let expires_in_secs = body["expires_in"].as_u64().unwrap_or(900).clamp(60, 3600);
        let message = body["message"]
            .as_str()
            .unwrap_or("Open the Microsoft verification URL and enter the user code.")
            .to_owned();

        let flow_id = format!("azsso-{}", Uuid::new_v4());
        let flow = AzureSsoFlow {
            tenant_id: tenant_id.to_owned(),
            user_id: user_id.to_owned(),
            entra_tenant: entra_tenant.clone(),
            client_id,
            auth_base_url: auth_base,
            arm_base_url: arm_base,
            device_code,
            expires_at: now_unix_secs()
                .saturating_add(i64::try_from(expires_in_secs).unwrap_or(900)),
            status: "pending".to_owned(),
            access_token: String::new(),
            refresh_token: String::new(),
            token_expires_at: 0,
            subscriptions: Vec::new(),
        };
        let mut guard = self.azure_flows.write().await;
        let now = now_unix_secs();
        guard.retain(|_, f| f.expires_at > now - 300);
        guard.insert(flow_id.clone(), flow);

        Ok(PublicAzureSsoStart {
            flow_id,
            entra_tenant,
            user_code,
            verification_uri,
            verification_uri_complete,
            message,
            interval_seconds: interval_secs,
            expires_in_seconds: expires_in_secs,
        })
    }

    pub async fn poll_azure_device_sso(
        &self,
        http: &reqwest::Client,
        tenant_id: &str,
        user_id: &str,
        flow_id: &str,
    ) -> Result<AzureSsoPollResult, String> {
        let flow = self
            .azure_flows
            .read()
            .await
            .get(flow_id)
            .filter(|f| f.tenant_id == tenant_id && f.user_id == user_id)
            .cloned()
            .ok_or_else(|| "Azure SSO flow not found".to_owned())?;

        if flow.status == "authorized" {
            return Ok(AzureSsoPollResult {
                status: "authorized".to_owned(),
                subscriptions: flow.subscriptions,
                error: None,
            });
        }
        if now_unix_secs() >= flow.expires_at {
            self.azure_flows.write().await.remove(flow_id);
            return Err("Azure device authorization expired; start again".to_owned());
        }

        let resp = http
            .post(format!(
                "{}/{}/oauth2/v2.0/token",
                flow.auth_base_url, flow.entra_tenant
            ))
            .timeout(Duration::from_secs(15))
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", flow.client_id.as_str()),
                ("device_code", flow.device_code.as_str()),
            ])
            .send()
            .await
            .map_err(|e| format!("Entra token poll failed: {e}"))?;

        let status_code = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Entra token poll JSON error: {e}"))?;

        if !status_code.is_success() {
            let err_code = body["error"].as_str().unwrap_or("unknown");
            return match err_code {
                "authorization_pending" | "slow_down" => Ok(AzureSsoPollResult {
                    status: "pending".to_owned(),
                    subscriptions: Vec::new(),
                    error: None,
                }),
                "authorization_declined" | "bad_verification_code" | "expired_token" => {
                    self.azure_flows.write().await.remove(flow_id);
                    Err(body["error_description"]
                        .as_str()
                        .unwrap_or("Azure authorization was declined or expired")
                        .to_owned())
                }
                other => Err(format!(
                    "Entra SSO poll error ({other}): {}",
                    body["error_description"].as_str().unwrap_or("")
                )),
            };
        }

        let access_token = body["access_token"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "Entra token response missing access_token".to_owned())?
            .to_owned();
        let refresh_token = body["refresh_token"].as_str().unwrap_or("").to_owned();
        let expires_in = i64::try_from(body["expires_in"].as_u64().unwrap_or(3600)).unwrap_or(3600);
        let subs = fetch_azure_subscriptions(http, &flow.arm_base_url, &access_token).await?;

        let mut guard = self.azure_flows.write().await;
        if let Some(entry) = guard.get_mut(flow_id) {
            "authorized".clone_into(&mut entry.status);
            entry.access_token = access_token;
            entry.refresh_token = refresh_token;
            entry.token_expires_at = now_unix_secs().saturating_add(expires_in);
            entry.subscriptions.clone_from(&subs);
        }
        Ok(AzureSsoPollResult {
            status: "authorized".to_owned(),
            subscriptions: subs,
            error: None,
        })
    }

    pub async fn connect_azure_sso_subscription(
        &self,
        tenant_id: &str,
        user_id: &str,
        flow_id: &str,
        subscription_id: &str,
        display_name: Option<&str>,
        region: Option<&str>,
    ) -> Result<CloudConnectorRecord, String> {
        let sub_trimmed = subscription_id.trim();
        if sub_trimmed.is_empty() {
            return Err("subscription_id is required".to_owned());
        }
        let flow = self
            .azure_flows
            .read()
            .await
            .get(flow_id)
            .filter(|f| {
                f.tenant_id == tenant_id && f.user_id == user_id && f.status == "authorized"
            })
            .cloned()
            .ok_or_else(|| "authorized Azure SSO session not found".to_owned())?;

        let matched = flow
            .subscriptions
            .iter()
            .find(|s| s.subscription_id == sub_trimmed);
        let label = display_name
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| matched.map(|s| s.display_name.as_str()))
            .filter(|s| !s.is_empty())
            .unwrap_or(sub_trimmed)
            .to_owned();
        let entra_tenant = matched
            .map(|s| s.tenant_id.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(&flow.entra_tenant)
            .to_owned();

        self.add_connector(
            tenant_id,
            CreateCloudConnectorInput {
                provider: "azure".to_owned(),
                name: label,
                account_or_project_id: sub_trimmed.to_owned(),
                tenant_or_org_id: entra_tenant,
                region: region
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("eastus")
                    .to_owned(),
                credentials: serde_json::json!({
                    "access_token": flow.access_token,
                    "refresh_token": flow.refresh_token,
                    "token_expires_at": flow.token_expires_at,
                    "client_id": flow.client_id,
                }),
                config: serde_json::json!({
                    "auth_mode": "entra_sso",
                    "client_id": flow.client_id,
                    "auth_base_url": flow.auth_base_url,
                    "arm_base_url": flow.arm_base_url,
                }),
            },
        )
        .await
    }

    // -----------------------------------------------------------------------
    // GCP OAuth2 PKCE (`S256`) Interactive SSO Flow (Zero SA JSON Key)
    // -----------------------------------------------------------------------

    pub async fn start_gcp_pkce_sso(
        &self,
        tenant_id: &str,
        user_id: &str,
        input: GcpSsoStartInput,
    ) -> Result<PublicGcpSsoStart, String> {
        let env_client_id = std::env::var("OPERQUAY_GCP_OAUTH_CLIENT_ID").unwrap_or_default();
        let env_client_sec = std::env::var("OPERQUAY_GCP_OAUTH_CLIENT_SECRET").unwrap_or_default();
        let client_id = first_non_empty(&[input.client_id.trim(), env_client_id.trim()]);
        if client_id.is_empty() {
            return Err("Google OAuth Client ID is required (pass client_id or set OPERQUAY_GCP_OAUTH_CLIENT_ID)".to_owned());
        }
        let client_secret = first_non_empty(&[input.client_secret.trim(), env_client_sec.trim()]);
        let redirect_uri = input.redirect_uri.trim().to_owned();
        if redirect_uri.is_empty() {
            return Err("redirect_uri is required for Google OAuth2 PKCE".to_owned());
        }
        let auth_base = first_non_empty(&[
            input.auth_base_url.trim().trim_end_matches('/'),
            "https://accounts.google.com/o/oauth2/v2/auth",
        ]);
        let token_url = first_non_empty(&[
            input.token_url.trim(),
            "https://oauth2.googleapis.com/token",
        ]);
        let crm_base = first_non_empty(&[
            input.crm_base_url.trim().trim_end_matches('/'),
            "https://cloudresourcemanager.googleapis.com",
        ]);

        let mut raw_state = [0u8; 24];
        fill_csprng(&mut raw_state)?;
        let state = hex::encode(raw_state);

        let mut raw_verifier = [0u8; 32];
        fill_csprng(&mut raw_verifier)?;
        let code_verifier = URL_SAFE_NO_PAD.encode(raw_verifier);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));

        let flow_id = format!("gcpsso-{}", Uuid::new_v4());
        let authorization_url = format!(
            "{auth_base}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256&access_type=offline&prompt=consent",
            percent_encode(&client_id),
            percent_encode(&redirect_uri),
            percent_encode("https://www.googleapis.com/auth/cloud-platform.read-only"),
            percent_encode(&state),
            percent_encode(&challenge),
        );

        let flow = GcpSsoFlow {
            id: flow_id.clone(),
            state,
            tenant_id: tenant_id.to_owned(),
            user_id: user_id.to_owned(),
            client_id,
            client_secret,
            redirect_uri: redirect_uri.clone(),
            code_verifier,
            token_url,
            crm_base_url: crm_base,
            status: "pending".to_owned(),
            error_msg: None,
            access_token: String::new(),
            refresh_token: String::new(),
            token_expires_at: 0,
            projects: Vec::new(),
            expires_at: now_unix_secs().saturating_add(900),
        };
        let mut guard = self.gcp_flows.write().await;
        let now = now_unix_secs();
        guard.retain(|_, f| f.expires_at > now - 300);
        guard.insert(flow_id.clone(), flow);

        Ok(PublicGcpSsoStart {
            flow_id,
            authorization_url,
            redirect_uri,
            expires_in_seconds: 900,
        })
    }

    pub async fn finish_gcp_pkce_callback(
        &self,
        http: &reqwest::Client,
        state: &str,
        code: &str,
    ) -> Result<GcpSsoStatusResult, String> {
        let matched = {
            let guard = self.gcp_flows.read().await;
            guard
                .values()
                .find(|f| f.state == state && f.status == "pending")
                .cloned()
        };
        let Some(flow) = matched else {
            return Err("invalid or expired Google OAuth state".to_owned());
        };
        if now_unix_secs() >= flow.expires_at {
            return Err("Google OAuth PKCE flow expired; start again".to_owned());
        }

        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", flow.client_id.as_str()),
            ("redirect_uri", flow.redirect_uri.as_str()),
            ("code_verifier", flow.code_verifier.as_str()),
        ];
        if !flow.client_secret.is_empty() {
            form.push(("client_secret", flow.client_secret.as_str()));
        }
        let resp = http
            .post(&flow.token_url)
            .timeout(Duration::from_secs(15))
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("Google OAuth2 token exchange failed: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let err_txt = resp.text().await.unwrap_or_default();
            let msg = format!("Google OAuth2 token exchange failed ({status}): {err_txt}");
            if let Some(entry) = self.gcp_flows.write().await.get_mut(&flow.id) {
                "error".clone_into(&mut entry.status);
                entry.error_msg = Some(msg.clone());
            }
            return Err(msg);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Google OAuth token parse failed: {e}"))?;
        let access_token = body["access_token"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "Google token response missing access_token".to_owned())?
            .to_owned();
        let refresh_token = body["refresh_token"].as_str().unwrap_or("").to_owned();
        let expires_in = i64::try_from(body["expires_in"].as_u64().unwrap_or(3600)).unwrap_or(3600);
        let projects = fetch_gcp_projects(http, &flow.crm_base_url, &access_token).await?;

        let mut guard = self.gcp_flows.write().await;
        if let Some(entry) = guard.get_mut(&flow.id) {
            "authorized".clone_into(&mut entry.status);
            entry.error_msg = None;
            entry.access_token = access_token;
            entry.refresh_token = refresh_token;
            entry.token_expires_at = now_unix_secs().saturating_add(expires_in);
            entry.projects.clone_from(&projects);
        }

        Ok(GcpSsoStatusResult {
            flow_id: flow.id,
            status: "authorized".to_owned(),
            projects,
            error: None,
        })
    }

    pub async fn get_gcp_sso_status(
        &self,
        tenant_id: &str,
        user_id: &str,
        flow_id: &str,
    ) -> Option<GcpSsoStatusResult> {
        self.gcp_flows
            .read()
            .await
            .get(flow_id)
            .filter(|f| f.tenant_id == tenant_id && f.user_id == user_id)
            .map(|f| GcpSsoStatusResult {
                flow_id: f.id.clone(),
                status: f.status.clone(),
                projects: f.projects.clone(),
                error: f.error_msg.clone(),
            })
    }

    pub async fn connect_gcp_sso_project(
        &self,
        tenant_id: &str,
        user_id: &str,
        flow_id: &str,
        project_id: &str,
        display_name: Option<&str>,
        region: Option<&str>,
    ) -> Result<CloudConnectorRecord, String> {
        let proj_trimmed = project_id.trim();
        if proj_trimmed.is_empty() {
            return Err("project_id is required".to_owned());
        }
        let flow = self
            .gcp_flows
            .read()
            .await
            .get(flow_id)
            .filter(|f| {
                f.tenant_id == tenant_id && f.user_id == user_id && f.status == "authorized"
            })
            .cloned()
            .ok_or_else(|| "authorized Google Cloud SSO session not found".to_owned())?;

        let matched = flow.projects.iter().find(|p| p.project_id == proj_trimmed);
        let label = display_name
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| matched.map(|p| p.name.as_str()))
            .filter(|s| !s.is_empty())
            .unwrap_or(proj_trimmed)
            .to_owned();

        self.add_connector(
            tenant_id,
            CreateCloudConnectorInput {
                provider: "gcp".to_owned(),
                name: label,
                account_or_project_id: proj_trimmed.to_owned(),
                tenant_or_org_id: String::new(),
                region: region
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("us-central1")
                    .to_owned(),
                credentials: serde_json::json!({
                    "access_token": flow.access_token,
                    "refresh_token": flow.refresh_token,
                    "token_expires_at": flow.token_expires_at,
                    "client_id": flow.client_id,
                    "client_secret": flow.client_secret,
                }),
                config: serde_json::json!({
                    "auth_mode": "google_sso",
                    "client_id": flow.client_id,
                    "token_url": flow.token_url,
                    "crm_base_url": flow.crm_base_url,
                }),
            },
        )
        .await
    }
}

fn first_non_empty(candidates: &[&str]) -> String {
    candidates
        .iter()
        .copied()
        .find(|s| !s.trim().is_empty())
        .unwrap_or("")
        .to_owned()
}

fn percent_encode(input: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

async fn fetch_azure_subscriptions(
    http: &reqwest::Client,
    arm_base: &str,
    access_token: &str,
) -> Result<Vec<AzureSubscriptionInfo>, String> {
    let url = format!(
        "{}/subscriptions?api-version=2022-12-01",
        arm_base.trim_end_matches('/')
    );
    let resp = http
        .get(&url)
        .bearer_auth(access_token)
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("Azure subscription discovery failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "Azure subscription discovery returned {}",
            resp.status()
        ));
    }
    let val: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Azure subscriptions JSON parse failed: {e}"))?;
    let subs = val["value"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| {
            let sid = s["subscriptionId"].as_str()?.trim().to_owned();
            if sid.is_empty() {
                return None;
            }
            Some(AzureSubscriptionInfo {
                display_name: s["displayName"].as_str().unwrap_or(&sid).to_owned(),
                state: s["state"].as_str().unwrap_or("Enabled").to_owned(),
                tenant_id: s["tenantId"].as_str().unwrap_or("").to_owned(),
                subscription_id: sid,
            })
        })
        .collect();
    Ok(subs)
}

async fn fetch_gcp_projects(
    http: &reqwest::Client,
    crm_base: &str,
    access_token: &str,
) -> Result<Vec<GcpProjectInfo>, String> {
    let url = format!(
        "{}/v1/projects?filter=lifecycleState%3AACTIVE",
        crm_base.trim_end_matches('/')
    );
    let resp = http
        .get(&url)
        .bearer_auth(access_token)
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("GCP project discovery failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GCP project discovery returned {}", resp.status()));
    }
    let val: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("GCP projects JSON parse failed: {e}"))?;
    let projs = val["projects"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| {
            let pid = p["projectId"].as_str()?.trim().to_owned();
            if pid.is_empty() {
                return None;
            }
            Some(GcpProjectInfo {
                name: p["name"].as_str().unwrap_or(&pid).to_owned(),
                project_number: p["projectNumber"].as_str().unwrap_or("").to_owned(),
                lifecycle_state: p["lifecycleState"].as_str().unwrap_or("ACTIVE").to_owned(),
                project_id: pid,
            })
        })
        .collect();
    Ok(projs)
}

async fn resolve_azure_token(
    http: &reqwest::Client,
    conn: &CloudConnectorRecord,
) -> Result<String, String> {
    let creds: serde_json::Value = serde_json::from_str(&conn.credentials_json).unwrap_or_default();
    let auth_base = conn.config["auth_base_url"]
        .as_str()
        .unwrap_or("https://login.microsoftonline.com")
        .trim_end_matches('/');
    let mode = conn.config["auth_mode"].as_str().unwrap_or("");

    if mode == "managed_identity" {
        let imds_base = conn.config["imds_base_url"]
            .as_str()
            .unwrap_or("http://169.254.169.254")
            .trim_end_matches('/');
        let mut url = format!(
            "{imds_base}/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"
        );
        if let Some(cid) = conn.config["client_id"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
        {
            url.push_str("&client_id=");
            url.push_str(&percent_encode(cid.trim()));
        }
        let resp = http
            .get(&url)
            .header("Metadata", "true")
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("Azure Managed Identity IMDS request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "Azure Managed Identity IMDS returned {}",
                resp.status()
            ));
        }
        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Azure IMDS token parse failed: {e}"))?;
        return val["access_token"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| "Azure IMDS response missing access_token".to_owned());
    }

    if mode == "workload_identity" {
        let tenant = conn.tenant_or_org_id.trim();
        let client_id = conn.config["client_id"]
            .as_str()
            .or_else(|| creds["client_id"].as_str())
            .unwrap_or("")
            .trim();
        let token_file = conn.config["federated_token_file"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| std::env::var("AZURE_FEDERATED_TOKEN_FILE").ok())
            .ok_or_else(|| "Azure Workload Identity requires federated_token_file".to_owned())?;
        let assertion = tokio::fs::read_to_string(&token_file).await.map_err(|e| {
            format!("failed reading Azure federated token file '{token_file}': {e}")
        })?;
        let resp = http
            .post(format!("{auth_base}/{tenant}/oauth2/v2.0/token"))
            .timeout(Duration::from_secs(15))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion.trim()),
                ("scope", "https://management.azure.com/.default"),
            ])
            .send()
            .await
            .map_err(|e| format!("Azure Workload Identity token exchange failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "Azure Workload Identity token exchange returned {}",
                resp.status()
            ));
        }
        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Azure WIF token parse failed: {e}"))?;
        return val["access_token"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| "Azure WIF response missing access_token".to_owned());
    }

    if mode == "entra_sso" {
        let now = now_unix_secs();
        let exp = creds["token_expires_at"].as_i64().unwrap_or(0);
        if let Some(tok) = creds["access_token"].as_str().filter(|s| !s.is_empty()) {
            if exp == 0 || exp > now + 60 {
                return Ok(tok.to_owned());
            }
        }
        if let Some(rtok) = creds["refresh_token"].as_str().filter(|s| !s.is_empty()) {
            let cid = conn.config["client_id"]
                .as_str()
                .or_else(|| creds["client_id"].as_str())
                .unwrap_or(DEFAULT_AZURE_PUBLIC_CLIENT_ID);
            let tenant = if conn.tenant_or_org_id.trim().is_empty() {
                "organizations"
            } else {
                conn.tenant_or_org_id.trim()
            };
            let resp = http
                .post(format!("{auth_base}/{tenant}/oauth2/v2.0/token"))
                .timeout(Duration::from_secs(15))
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("client_id", cid),
                    ("refresh_token", rtok),
                    (
                        "scope",
                        "https://management.azure.com/.default offline_access",
                    ),
                ])
                .send()
                .await
                .map_err(|e| format!("Entra SSO token refresh failed: {e}"))?;
            if resp.status().is_success() {
                if let Ok(val) = resp.json::<serde_json::Value>().await {
                    if let Some(new_tok) = val["access_token"].as_str().filter(|s| !s.is_empty()) {
                        return Ok(new_tok.to_owned());
                    }
                }
            }
        }
        return Err("Entra SSO token expired; sign in again via Azure SSO".to_owned());
    }

    if let Some(tok) = creds["access_token"].as_str().filter(|s| !s.is_empty()) {
        return Ok(tok.to_owned());
    }
    let tenant = conn.tenant_or_org_id.trim();
    let client_id = creds["client_id"].as_str().unwrap_or("").trim();
    let client_secret = creds["client_secret"].as_str().unwrap_or("").trim();
    if tenant.is_empty() || client_id.is_empty() || client_secret.is_empty() {
        return Err(
            "Azure connector requires Entra SSO, Managed/Workload Identity, or client_id + client_secret"
                .to_owned(),
        );
    }
    let resp = http
        .post(format!("{auth_base}/{tenant}/oauth2/v2.0/token"))
        .timeout(Duration::from_secs(15))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", "https://management.azure.com/.default"),
        ])
        .send()
        .await
        .map_err(|e| format!("Entra OAuth2 request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Entra OAuth2 failed ({})", resp.status()));
    }
    let val: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Entra token parse failed: {e}"))?;
    val["access_token"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| "Entra response missing access_token".to_owned())
}

/// Synchronize real Azure Compute VMs, AKS clusters, and RBAC definitions using Entra `OAuth2`,
/// Device Code SSO, Managed Identity IMDS, or OIDC Workload Identity Federation.
pub async fn sync_azure_connector(
    http: &reqwest::Client,
    conn: &CloudConnectorRecord,
) -> Result<Vec<CloudResourceItem>, String> {
    let sub_id = conn.account_or_project_id.trim();
    let arm_base = conn.config["arm_base_url"]
        .as_str()
        .unwrap_or("https://management.azure.com")
        .trim_end_matches('/');
    let token = resolve_azure_token(http, conn).await?;

    let mut out = Vec::new();
    let vm_url = format!(
        "{arm_base}/subscriptions/{sub_id}/providers/Microsoft.Compute/virtualMachines?api-version=2024-03-01"
    );
    if let Ok(resp) = http.get(&vm_url).bearer_auth(&token).send().await {
        if resp.status().is_success() {
            if let Ok(val) = resp.json::<serde_json::Value>().await {
                if let Some(arr) = val["value"].as_array() {
                    for vm in arr {
                        let id = vm["id"].as_str().unwrap_or("").to_owned();
                        let name = vm["name"].as_str().unwrap_or("azure-vm").to_owned();
                        let loc = vm["location"].as_str().unwrap_or(&conn.region).to_owned();
                        let st = vm["properties"]["provisioningState"]
                            .as_str()
                            .unwrap_or("running")
                            .to_owned();
                        out.push(CloudResourceItem {
                            id: if id.is_empty() {
                                format!("az-vm-{name}")
                            } else {
                                id
                            },
                            tenant_id: conn.tenant_id.clone(),
                            connector_id: conn.id.clone(),
                            provider: "azure".to_owned(),
                            kind: "vm".to_owned(),
                            name,
                            region: loc,
                            state: st,
                            account_or_project: sub_id.to_owned(),
                            bastion_or_iap_uri: String::new(),
                            private_ip: String::new(),
                            is_privileged: false,
                        });
                    }
                }
            }
        }
    }

    let aks_url = format!(
        "{arm_base}/subscriptions/{sub_id}/providers/Microsoft.ContainerService/managedClusters?api-version=2024-02-01"
    );
    if let Ok(resp) = http.get(&aks_url).bearer_auth(&token).send().await {
        if resp.status().is_success() {
            if let Ok(val) = resp.json::<serde_json::Value>().await {
                if let Some(arr) = val["value"].as_array() {
                    for aks in arr {
                        let id = aks["id"].as_str().unwrap_or("").to_owned();
                        let name = aks["name"].as_str().unwrap_or("aks-cluster").to_owned();
                        let loc = aks["location"].as_str().unwrap_or(&conn.region).to_owned();
                        let fqdn = aks["properties"]["fqdn"].as_str().unwrap_or("").to_owned();
                        out.push(CloudResourceItem {
                            id: if id.is_empty() {
                                format!("az-aks-{name}")
                            } else {
                                id
                            },
                            tenant_id: conn.tenant_id.clone(),
                            connector_id: conn.id.clone(),
                            provider: "azure".to_owned(),
                            kind: "k8s".to_owned(),
                            name,
                            region: loc,
                            state: "Succeeded".to_owned(),
                            account_or_project: sub_id.to_owned(),
                            bastion_or_iap_uri: fqdn,
                            private_ip: String::new(),
                            is_privileged: false,
                        });
                    }
                }
            }
        }
    }

    let role_url = format!(
        "{arm_base}/subscriptions/{sub_id}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
    );
    if let Ok(resp) = http.get(&role_url).bearer_auth(&token).send().await {
        if resp.status().is_success() {
            if let Ok(val) = resp.json::<serde_json::Value>().await {
                if let Some(arr) = val["value"].as_array() {
                    for rd in arr.iter().take(25) {
                        let role_name = rd["properties"]["roleName"]
                            .as_str()
                            .unwrap_or("AzureRole")
                            .to_owned();
                        let id = rd["id"].as_str().unwrap_or(&role_name).to_owned();
                        let is_priv = matches!(
                            role_name.as_str(),
                            "Owner" | "Contributor" | "User Access Administrator"
                        );
                        out.push(CloudResourceItem {
                            id,
                            tenant_id: conn.tenant_id.clone(),
                            connector_id: conn.id.clone(),
                            provider: "azure".to_owned(),
                            kind: "iam".to_owned(),
                            name: role_name,
                            region: "global".to_owned(),
                            state: "eligible".to_owned(),
                            account_or_project: sub_id.to_owned(),
                            bastion_or_iap_uri: String::new(),
                            private_ip: String::new(),
                            is_privileged: is_priv,
                        });
                    }
                }
            }
        }
    }

    Ok(out)
}

fn sign_gcp_jwt_assertion(
    client_email: &str,
    private_key_pem: &str,
    token_uri: &str,
) -> Result<String, String> {
    const BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
    const END: &str = "-----END PRIVATE KEY-----";
    let start = private_key_pem
        .find(BEGIN)
        .ok_or_else(|| "GCP service account private_key missing PKCS#8 PEM header".to_owned())?;
    let after = &private_key_pem[start + BEGIN.len()..];
    let end = after
        .find(END)
        .ok_or_else(|| "GCP service account private_key missing PEM footer".to_owned())?;
    let b64: String = after[..end]
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let pkcs8 = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| format!("invalid base64 in GCP private_key: {e}"))?;
    let rsa = RsaKeyPair::from_pkcs8(&pkcs8).map_err(|e| format!("invalid RSA PKCS#8 key: {e}"))?;

    let now = now_unix_secs();
    let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = serde_json::json!({
        "iss": client_email,
        "scope": "https://www.googleapis.com/auth/cloud-platform.read-only",
        "aud": token_uri,
        "iat": now,
        "exp": now + 3600,
    });
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let rng = SystemRandom::new();
    let mut sig = vec![0u8; rsa.public().modulus_len()];
    rsa.sign(&RSA_PKCS1_SHA256, &rng, signing_input.as_bytes(), &mut sig)
        .map_err(|e| format!("failed signing GCP JWT assertion: {e}"))?;
    Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig)))
}

async fn impersonate_gcp_sa(
    http: &reqwest::Client,
    iamcreds_base: &str,
    service_account_email: &str,
    source_token: &str,
) -> Result<String, String> {
    let sa = service_account_email.trim();
    let url = format!(
        "{}/v1/projects/-/serviceAccounts/{}:generateAccessToken",
        iamcreds_base.trim_end_matches('/'),
        percent_encode(sa),
    );
    let resp = http
        .post(&url)
        .bearer_auth(source_token)
        .timeout(Duration::from_secs(15))
        .json(&serde_json::json!({
            "scope": ["https://www.googleapis.com/auth/cloud-platform.read-only"]
        }))
        .send()
        .await
        .map_err(|e| format!("GCP service account impersonation failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GCP SA impersonation returned {}", resp.status()));
    }
    let val: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("GCP SA impersonation JSON parse error: {e}"))?;
    val["accessToken"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| "GCP SA impersonation response missing accessToken".to_owned())
}

async fn resolve_gcp_token(
    http: &reqwest::Client,
    conn: &CloudConnectorRecord,
) -> Result<String, String> {
    let creds: serde_json::Value = serde_json::from_str(&conn.credentials_json).unwrap_or_default();
    let mode = conn.config["auth_mode"].as_str().unwrap_or("");
    let iamcreds_base = conn.config["iamcredentials_base_url"]
        .as_str()
        .unwrap_or("https://iamcredentials.googleapis.com")
        .trim_end_matches('/');

    if mode == "metadata_adc" {
        let meta_base = conn.config["metadata_base_url"]
            .as_str()
            .unwrap_or("http://metadata.google.internal")
            .trim_end_matches('/');
        let resp = http
            .get(format!(
                "{meta_base}/computeMetadata/v1/instance/service-accounts/default/token"
            ))
            .header("Metadata-Flavor", "Google")
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("GCP metadata ADC request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("GCP metadata ADC returned {}", resp.status()));
        }
        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("GCP metadata ADC token parse failed: {e}"))?;
        let base_tok = val["access_token"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| "GCP metadata ADC missing access_token".to_owned())?;
        if let Some(sa) = conn.config["impersonate_service_account"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
        {
            return impersonate_gcp_sa(http, iamcreds_base, sa, &base_tok).await;
        }
        return Ok(base_tok);
    }

    if mode == "workload_identity" {
        let sts_base = conn.config["sts_base_url"]
            .as_str()
            .unwrap_or("https://sts.googleapis.com")
            .trim_end_matches('/');
        let audience = conn.config["wif_audience"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "GCP Workload Identity Federation requires config.wif_audience".to_owned()
            })?;
        let token_file = conn.config["federated_token_file"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| std::env::var("GCP_FEDERATED_TOKEN_FILE").ok())
            .ok_or_else(|| "GCP Workload Identity requires federated_token_file".to_owned())?;
        let subject_token = tokio::fs::read_to_string(&token_file)
            .await
            .map_err(|e| format!("failed reading GCP federated token file '{token_file}': {e}"))?;
        let resp = http
            .post(format!("{sts_base}/v1/token"))
            .timeout(Duration::from_secs(15))
            .json(&serde_json::json!({
                "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
                "audience": audience,
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
                "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
                "subjectToken": subject_token.trim(),
            }))
            .send()
            .await
            .map_err(|e| format!("GCP STS token exchange failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("GCP STS token exchange returned {}", resp.status()));
        }
        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("GCP STS token parse error: {e}"))?;
        let sts_tok = val["access_token"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| "GCP STS response missing access_token".to_owned())?;
        if let Some(sa) = conn.config["impersonate_service_account"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
        {
            return impersonate_gcp_sa(http, iamcreds_base, sa, &sts_tok).await;
        }
        return Ok(sts_tok);
    }

    if mode == "google_sso" {
        let now = now_unix_secs();
        let exp = creds["token_expires_at"].as_i64().unwrap_or(0);
        if let Some(tok) = creds["access_token"].as_str().filter(|s| !s.is_empty()) {
            if exp == 0 || exp > now + 60 {
                return Ok(tok.to_owned());
            }
        }
        if let Some(rtok) = creds["refresh_token"].as_str().filter(|s| !s.is_empty()) {
            let token_url = conn.config["token_url"]
                .as_str()
                .unwrap_or("https://oauth2.googleapis.com/token");
            let cid = conn.config["client_id"]
                .as_str()
                .or_else(|| creds["client_id"].as_str())
                .unwrap_or("");
            let csec = creds["client_secret"].as_str().unwrap_or("");
            let mut form = vec![
                ("grant_type", "refresh_token"),
                ("client_id", cid),
                ("refresh_token", rtok),
            ];
            if !csec.is_empty() {
                form.push(("client_secret", csec));
            }
            let resp = http
                .post(token_url)
                .timeout(Duration::from_secs(15))
                .form(&form)
                .send()
                .await
                .map_err(|e| format!("Google SSO refresh failed: {e}"))?;
            if resp.status().is_success() {
                if let Ok(val) = resp.json::<serde_json::Value>().await {
                    if let Some(new_tok) = val["access_token"].as_str().filter(|s| !s.is_empty()) {
                        return Ok(new_tok.to_owned());
                    }
                }
            }
        }
        return Err("Google Cloud SSO token expired; sign in again".to_owned());
    }

    if let Some(tok) = creds["access_token"].as_str().filter(|s| !s.is_empty()) {
        return Ok(tok.to_owned());
    }
    let sa = creds
        .get("service_account_json")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .unwrap_or_else(|| creds.clone());
    let client_email = sa["client_email"].as_str().unwrap_or("").trim();
    let private_key = sa["private_key"].as_str().unwrap_or("").trim();
    let token_uri = conn.config["token_url"]
        .as_str()
        .or_else(|| sa["token_uri"].as_str())
        .unwrap_or("https://oauth2.googleapis.com/token");
    if client_email.is_empty() || private_key.is_empty() {
        return Err(
            "GCP connector requires Google OAuth2 SSO, Workload Identity / ADC, or Service Account JSON"
                .to_owned(),
        );
    }
    let assertion = sign_gcp_jwt_assertion(client_email, private_key, token_uri)?;
    let resp = http
        .post(token_uri)
        .timeout(Duration::from_secs(15))
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ])
        .send()
        .await
        .map_err(|e| format!("GCP OAuth2 token exchange failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GCP OAuth2 failed ({})", resp.status()));
    }
    let val: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("GCP token parse error: {e}"))?;
    val["access_token"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| "GCP OAuth response missing access_token".to_owned())
}

/// Synchronize real GCP Compute Engine instances, GKE clusters, and IAM policy roles using
/// Google `OAuth2` PKCE SSO, Workload Identity Federation, Metadata ADC, or Service Account JWT.
pub async fn sync_gcp_connector(
    http: &reqwest::Client,
    conn: &CloudConnectorRecord,
) -> Result<Vec<CloudResourceItem>, String> {
    let project = conn.account_or_project_id.trim();
    let compute_base = conn.config["compute_base_url"]
        .as_str()
        .unwrap_or("https://compute.googleapis.com")
        .trim_end_matches('/');
    let gke_base = conn.config["gke_base_url"]
        .as_str()
        .unwrap_or("https://container.googleapis.com")
        .trim_end_matches('/');
    let crm_base = conn.config["crm_base_url"]
        .as_str()
        .unwrap_or("https://cloudresourcemanager.googleapis.com")
        .trim_end_matches('/');
    let token = resolve_gcp_token(http, conn).await?;

    let mut out = Vec::new();
    let gce_url = format!("{compute_base}/compute/v1/projects/{project}/aggregated/instances");
    if let Ok(resp) = http.get(&gce_url).bearer_auth(&token).send().await {
        if resp.status().is_success() {
            if let Ok(val) = resp.json::<serde_json::Value>().await {
                if let Some(map) = val["items"].as_object() {
                    for (scope_key, scope_val) in map {
                        let zone = scope_key.strip_prefix("zones/").unwrap_or(scope_key);
                        if let Some(arr) = scope_val["instances"].as_array() {
                            for inst in arr {
                                let name = inst["name"].as_str().unwrap_or("gce-vm").to_owned();
                                let id = inst["id"]
                                    .as_str()
                                    .or_else(|| inst["selfLink"].as_str())
                                    .unwrap_or(&name)
                                    .to_owned();
                                let status =
                                    inst["status"].as_str().unwrap_or("RUNNING").to_owned();
                                let ip = inst["networkInterfaces"][0]["networkIP"]
                                    .as_str()
                                    .unwrap_or("")
                                    .to_owned();
                                out.push(CloudResourceItem {
                                    id,
                                    tenant_id: conn.tenant_id.clone(),
                                    connector_id: conn.id.clone(),
                                    provider: "gcp".to_owned(),
                                    kind: "vm".to_owned(),
                                    name: name.clone(),
                                    region: zone.to_owned(),
                                    state: status,
                                    account_or_project: project.to_owned(),
                                    bastion_or_iap_uri: format!(
                                        "gcp-iap://{project}/{zone}/{name}"
                                    ),
                                    private_ip: ip,
                                    is_privileged: false,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    let clusters_url = format!("{gke_base}/v1/projects/{project}/locations/-/clusters");
    if let Ok(resp) = http.get(&clusters_url).bearer_auth(&token).send().await {
        if resp.status().is_success() {
            if let Ok(val) = resp.json::<serde_json::Value>().await {
                if let Some(arr) = val["clusters"].as_array() {
                    for c in arr {
                        let name = c["name"].as_str().unwrap_or("gke-cluster").to_owned();
                        let loc = c["location"].as_str().unwrap_or(&conn.region).to_owned();
                        let ep = c["endpoint"].as_str().unwrap_or("").to_owned();
                        out.push(CloudResourceItem {
                            id: format!("gke-{project}-{name}"),
                            tenant_id: conn.tenant_id.clone(),
                            connector_id: conn.id.clone(),
                            provider: "gcp".to_owned(),
                            kind: "k8s".to_owned(),
                            name,
                            region: loc,
                            state: c["status"].as_str().unwrap_or("RUNNING").to_owned(),
                            account_or_project: project.to_owned(),
                            bastion_or_iap_uri: ep,
                            private_ip: String::new(),
                            is_privileged: false,
                        });
                    }
                }
            }
        }
    }

    let iam_url = format!("{crm_base}/v1/projects/{project}:getIamPolicy");
    if let Ok(resp) = http
        .post(&iam_url)
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
    {
        if resp.status().is_success() {
            if let Ok(val) = resp.json::<serde_json::Value>().await {
                if let Some(bindings) = val["bindings"].as_array() {
                    for b in bindings.iter().take(25) {
                        let role = b["role"].as_str().unwrap_or("").to_owned();
                        if role.is_empty() {
                            continue;
                        }
                        let is_priv = matches!(role.as_str(), "roles/owner" | "roles/editor");
                        out.push(CloudResourceItem {
                            id: format!("gcp-role-{project}-{role}"),
                            tenant_id: conn.tenant_id.clone(),
                            connector_id: conn.id.clone(),
                            provider: "gcp".to_owned(),
                            kind: "iam".to_owned(),
                            name: role,
                            region: "global".to_owned(),
                            state: "bound".to_owned(),
                            account_or_project: project.to_owned(),
                            bastion_or_iap_uri: String::new(),
                            private_ip: String::new(),
                            is_privileged: is_priv,
                        });
                    }
                }
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::routing::{get, post};
    use axum::{Json, Router};
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn syncs_azure_and_gcp_resources_over_rest_endpoints() {
        let app = Router::new()
            .route(
                "/tenant-1/oauth2/v2.0/token",
                post(|| async { Json(serde_json::json!({ "access_token": "az-tok" })) }),
            )
            .route(
                "/subscriptions/sub-1/providers/Microsoft.Compute/virtualMachines",
                get(|| async {
                    Json(serde_json::json!({
                        "value": [{
                            "id": "/subs/sub-1/vm/win-ops",
                            "name": "win-ops",
                            "location": "eastus",
                            "properties": { "provisioningState": "Succeeded" }
                        }]
                    }))
                }),
            )
            .route(
                "/subscriptions/sub-1/providers/Microsoft.ContainerService/managedClusters",
                get(|| async {
                    Json(serde_json::json!({
                        "value": [{
                            "id": "/subs/sub-1/aks/prod-aks",
                            "name": "prod-aks",
                            "location": "eastus",
                            "properties": { "fqdn": "prod-aks.hcp.eastus.azmk8s.io" }
                        }]
                    }))
                }),
            )
            .route(
                "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions",
                get(|| async {
                    Json(serde_json::json!({
                        "value": [{ "id": "rd-owner", "properties": { "roleName": "Owner" } }]
                    }))
                }),
            )
            .route(
                "/compute/v1/projects/proj-1/aggregated/instances",
                get(|| async {
                    Json(serde_json::json!({
                        "items": {
                            "zones/us-central1-a": {
                                "instances": [{
                                    "id": "12345",
                                    "name": "gce-bastion",
                                    "status": "RUNNING",
                                    "networkInterfaces": [{ "networkIP": "10.128.0.10" }]
                                }]
                            }
                        }
                    }))
                }),
            )
            .route(
                "/v1/projects/proj-1/locations/-/clusters",
                get(|| async {
                    Json(serde_json::json!({
                        "clusters": [{ "name": "gke-prod", "location": "us-central1", "endpoint": "35.1.2.3", "status": "RUNNING" }]
                    }))
                }),
            )
            .route(
                "/v1/projects/proj-1:getIamPolicy",
                post(|| async {
                    Json(serde_json::json!({
                        "bindings": [{ "role": "roles/owner", "members": ["user:admin@acme.io"] }]
                    }))
                }),
            );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://{addr}");
        let http = reqwest::Client::new();

        let store = MultiCloudStore::new();
        let az_conn = store
            .add_connector(
                "default",
                CreateCloudConnectorInput {
                    provider: "azure".into(),
                    name: "Corp Azure".into(),
                    account_or_project_id: "sub-1".into(),
                    tenant_or_org_id: "tenant-1".into(),
                    region: "eastus".into(),
                    credentials: serde_json::json!({ "client_id": "cid", "client_secret": "sec" }),
                    config: serde_json::json!({ "auth_base_url": base, "arm_base_url": base }),
                },
            )
            .await
            .unwrap();
        let az_items = sync_azure_connector(&http, &az_conn).await.unwrap();
        assert_eq!(az_items.len(), 3);
        assert!(az_items
            .iter()
            .any(|r| r.kind == "vm" && r.name == "win-ops"));
        assert!(az_items
            .iter()
            .any(|r| r.kind == "k8s" && r.name == "prod-aks"));
        assert!(az_items.iter().any(|r| r.kind == "iam" && r.is_privileged));

        let gcp_conn = store
            .add_connector(
                "default",
                CreateCloudConnectorInput {
                    provider: "gcp".into(),
                    name: "Corp GCP".into(),
                    account_or_project_id: "proj-1".into(),
                    tenant_or_org_id: String::new(),
                    region: "us-central1".into(),
                    credentials: serde_json::json!({ "access_token": "gcp-tok" }),
                    config: serde_json::json!({
                        "compute_base_url": base,
                        "gke_base_url": base,
                        "crm_base_url": base
                    }),
                },
            )
            .await
            .unwrap();
        let gcp_items = sync_gcp_connector(&http, &gcp_conn).await.unwrap();
        assert_eq!(gcp_items.len(), 3);
        assert!(gcp_items
            .iter()
            .any(|r| r.kind == "vm" && r.name == "gce-bastion"));
        assert!(gcp_items
            .iter()
            .any(|r| r.kind == "k8s" && r.name == "gke-prod"));
    }

    #[tokio::test]
    async fn azure_device_sso_managed_identity_and_gcp_pkce_wif_work_without_static_secrets() {
        let az_polls = Arc::new(AtomicUsize::new(0));
        let az_polls_c = Arc::clone(&az_polls);
        let app = Router::new()
            .route(
                "/organizations/oauth2/v2.0/devicecode",
                post(|| async {
                    Json(serde_json::json!({
                        "device_code": "dev-123",
                        "user_code": "WXYZ-1234",
                        "verification_uri": "https://microsoft.com/devicelogin",
                        "interval": 1,
                        "expires_in": 600,
                        "message": "Enter WXYZ-1234"
                    }))
                }),
            )
            .route(
                "/organizations/oauth2/v2.0/token",
                post(move || {
                    let c = Arc::clone(&az_polls_c);
                    async move {
                        if c.fetch_add(1, Ordering::SeqCst) == 0 {
                            (
                                axum::http::StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({ "error": "authorization_pending" })),
                            )
                        } else {
                            (
                                axum::http::StatusCode::OK,
                                Json(serde_json::json!({
                                    "access_token": "az-sso-tok",
                                    "refresh_token": "az-ref-tok",
                                    "expires_in": 3600
                                })),
                            )
                        }
                    }
                }),
            )
            .route(
                "/subscriptions",
                get(|| async {
                    Json(serde_json::json!({
                        "value": [{ "subscriptionId": "sub-sso-1", "displayName": "Azure SSO Prod", "state": "Enabled", "tenantId": "entra-tid" }]
                    }))
                }),
            )
            .route(
                "/metadata/identity/oauth2/token",
                get(|| async { Json(serde_json::json!({ "access_token": "imds-az-tok" })) }),
            )
            .route(
                "/subscriptions/sub-sso-1/providers/Microsoft.Compute/virtualMachines",
                get(|| async {
                    Json(serde_json::json!({
                        "value": [{ "id": "vm-sso", "name": "az-sso-vm", "location": "eastus", "properties": { "provisioningState": "Succeeded" } }]
                    }))
                }),
            )
            .route(
                "/gcp/token",
                post(|| async {
                    Json(serde_json::json!({
                        "access_token": "gcp-sso-tok",
                        "refresh_token": "gcp-ref-tok",
                        "expires_in": 3600
                    }))
                }),
            )
            .route(
                "/v1/projects",
                get(|| async {
                    Json(serde_json::json!({
                        "projects": [{ "projectId": "gcp-sso-proj", "name": "GCP SSO Prod", "projectNumber": "99", "lifecycleState": "ACTIVE" }]
                    }))
                }),
            )
            .route(
                "/computeMetadata/v1/instance/service-accounts/default/token",
                get(|| async { Json(serde_json::json!({ "access_token": "adc-base-tok" })) }),
            )
            .route(
                "/v1/token",
                post(|| async { Json(serde_json::json!({ "access_token": "sts-wif-tok" })) }),
            )
            .route(
                "/v1/projects/-/serviceAccounts/reader%40gcp.iam:generateAccessToken",
                post(|| async { Json(serde_json::json!({ "accessToken": "impersonated-tok" })) }),
            )
            .route(
                "/compute/v1/projects/gcp-sso-proj/aggregated/instances",
                get(|| async {
                    Json(serde_json::json!({
                        "items": { "zones/us-central1-a": { "instances": [{ "id": "99", "name": "gce-sso-vm", "status": "RUNNING" }] } }
                    }))
                }),
            );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://{addr}");
        let http = reqwest::Client::new();
        let store = MultiCloudStore::new();

        // 1. Azure Device Code SSO flow
        let start = store
            .start_azure_device_sso(
                &http,
                "default",
                "u-1",
                AzureSsoStartInput {
                    entra_tenant: String::new(),
                    client_id: String::new(),
                    auth_base_url: base.clone(),
                    arm_base_url: base.clone(),
                },
            )
            .await
            .unwrap();
        assert_eq!(start.user_code, "WXYZ-1234");
        let p1 = store
            .poll_azure_device_sso(&http, "default", "u-1", &start.flow_id)
            .await
            .unwrap();
        assert_eq!(p1.status, "pending");
        let p2 = store
            .poll_azure_device_sso(&http, "default", "u-1", &start.flow_id)
            .await
            .unwrap();
        assert_eq!(p2.status, "authorized");
        assert_eq!(p2.subscriptions[0].subscription_id, "sub-sso-1");

        let az_conn = store
            .connect_azure_sso_subscription(
                "default",
                "u-1",
                &start.flow_id,
                "sub-sso-1",
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(az_conn.config["auth_mode"], "entra_sso");
        assert!(sync_azure_connector(&http, &az_conn)
            .await
            .unwrap()
            .iter()
            .any(|r| r.name == "az-sso-vm"));

        // 2. Azure Managed Identity IMDS (keyless)
        let mi_conn = store
            .add_connector(
                "default",
                CreateCloudConnectorInput {
                    provider: "azure".into(),
                    name: "Azure MI".into(),
                    account_or_project_id: "sub-sso-1".into(),
                    tenant_or_org_id: "entra-tid".into(),
                    region: "eastus".into(),
                    credentials: serde_json::json!({}),
                    config: serde_json::json!({
                        "auth_mode": "managed_identity",
                        "imds_base_url": base,
                        "arm_base_url": base,
                    }),
                },
            )
            .await
            .unwrap();
        assert!(sync_azure_connector(&http, &mi_conn)
            .await
            .unwrap()
            .iter()
            .any(|r| r.name == "az-sso-vm"));

        // 3. GCP PKCE SSO flow
        let gcp_start = store
            .start_gcp_pkce_sso(
                "default",
                "u-1",
                GcpSsoStartInput {
                    client_id: "gcp-client-id".into(),
                    client_secret: String::new(),
                    redirect_uri: "https://localhost:5444/api/clouds/gcp/sso/callback".into(),
                    auth_base_url: format!("{base}/auth"),
                    token_url: format!("{base}/gcp/token"),
                    crm_base_url: base.clone(),
                },
            )
            .await
            .unwrap();
        assert!(gcp_start
            .authorization_url
            .contains("code_challenge_method=S256"));
        let state_val = gcp_start
            .authorization_url
            .split("state=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_owned();
        let cb = store
            .finish_gcp_pkce_callback(&http, &state_val, "auth-code-99")
            .await
            .unwrap();
        assert_eq!(cb.status, "authorized");
        assert_eq!(cb.projects[0].project_id, "gcp-sso-proj");

        let gcp_conn = store
            .connect_gcp_sso_project(
                "default",
                "u-1",
                &gcp_start.flow_id,
                "gcp-sso-proj",
                None,
                None,
            )
            .await
            .unwrap();
        let mut gcp_conn_cfg = gcp_conn;
        gcp_conn_cfg.config["compute_base_url"] = serde_json::json!(base);
        assert!(sync_gcp_connector(&http, &gcp_conn_cfg)
            .await
            .unwrap()
            .iter()
            .any(|r| r.name == "gce-sso-vm"));

        // 4. GCP Metadata ADC + SA Impersonation & WIF (keyless)
        let tmp_tok = std::env::temp_dir().join(format!("oq-wif-{}.jwt", Uuid::new_v4()));
        std::fs::write(&tmp_tok, "eyJ.oidc.jwt").unwrap();
        let wif_conn = store
            .add_connector(
                "default",
                CreateCloudConnectorInput {
                    provider: "gcp".into(),
                    name: "GCP WIF".into(),
                    account_or_project_id: "gcp-sso-proj".into(),
                    tenant_or_org_id: String::new(),
                    region: "us-central1".into(),
                    credentials: serde_json::json!({}),
                    config: serde_json::json!({
                        "auth_mode": "workload_identity",
                        "wif_audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/o",
                        "federated_token_file": tmp_tok.to_string_lossy(),
                        "impersonate_service_account": "reader@gcp.iam",
                        "sts_base_url": base,
                        "iamcredentials_base_url": base,
                        "compute_base_url": base,
                    }),
                },
            )
            .await
            .unwrap();
        let res = sync_gcp_connector(&http, &wif_conn).await.unwrap();
        let _ = std::fs::remove_file(&tmp_tok);
        assert!(res.iter().any(|r| r.name == "gce-sso-vm"));
    }
}
