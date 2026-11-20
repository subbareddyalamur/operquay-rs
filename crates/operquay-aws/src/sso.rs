#![forbid(unsafe_code)]

//! AWS IAM Identity Center (`ssooidc` Device Authorization + `sso` Portal APIs)
//! and User AWS SSO Provider catalog.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;

use crate::sigv4::{now_unix_secs, AwsCredentials};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAwsSsoProvider {
    pub id: String,
    pub tenant_id: String,
    pub label: String,
    pub start_url: String,
    pub region: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsSsoStartResponse {
    pub id: String,
    pub verification_url: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub verification_url_complete: String,
    pub user_code: String,
    pub interval_seconds: u64,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsSsoAccount {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsSsoRole {
    pub account_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedSsoFlow {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub region: String,
    pub start_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub device_code: String,
    pub access_token: String,
    pub interval_secs: u64,
    pub expires_at: i64,
    pub cancelled: bool,
}

type ActiveSsoFlow = PersistedSsoFlow;

pub struct AwsSsoManager {
    flows: RwLock<HashMap<(String, String, String), ActiveSsoFlow>>,
    providers: RwLock<HashMap<String, UserAwsSsoProvider>>,
    account_names: RwLock<HashMap<String, String>>,
    portal_sem: Arc<Semaphore>,
    http: reqwest::Client,
    oidc_endpoint_override: Option<String>,
    portal_endpoint_override: Option<String>,
}

impl Default for AwsSsoManager {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl AwsSsoManager {
    #[must_use]
    pub fn new(
        oidc_endpoint_override: Option<String>,
        portal_endpoint_override: Option<String>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self {
            flows: RwLock::new(HashMap::new()),
            providers: RwLock::new(HashMap::new()),
            account_names: RwLock::new(HashMap::new()),
            portal_sem: Arc::new(Semaphore::new(2)),
            http,
            oidc_endpoint_override,
            portal_endpoint_override,
        }
    }

    pub async fn account_name(&self, account_id: &str) -> Option<String> {
        self.account_names
            .read()
            .await
            .get(account_id.trim())
            .filter(|s| !s.trim().is_empty())
            .cloned()
    }

    pub async fn hydrate_providers(&self, items: Vec<UserAwsSsoProvider>) {
        let mut guard = self.providers.write().await;
        for item in items {
            guard.insert(item.id.clone(), item);
        }
    }

    pub async fn get_persisted_flow(
        &self,
        tenant_id: &str,
        user_id: &str,
        flow_id: &str,
    ) -> Option<PersistedSsoFlow> {
        self.flows
            .read()
            .await
            .get(&(tenant_id.to_owned(), user_id.to_owned(), flow_id.to_owned()))
            .cloned()
    }

    pub async fn hydrate_flows(&self, flows: Vec<PersistedSsoFlow>) {
        let now = now_unix_secs();
        let mut guard = self.flows.write().await;
        for f in flows {
            if !f.cancelled && f.expires_at > now {
                guard.insert((f.tenant_id.clone(), f.user_id.clone(), f.id.clone()), f);
            }
        }
    }

    pub async fn list_providers(&self, tenant_id: &str) -> Vec<UserAwsSsoProvider> {
        let mut out: Vec<_> = self
            .providers
            .read()
            .await
            .values()
            .filter(|p| p.tenant_id == tenant_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.label.cmp(&b.label));
        out
    }

    pub async fn add_provider(
        &self,
        tenant_id: &str,
        label: &str,
        start_url: &str,
        region: &str,
    ) -> Result<UserAwsSsoProvider, String> {
        if !start_url.starts_with("https://") {
            return Err("start_url must be https://".to_owned());
        }
        let item = UserAwsSsoProvider {
            id: format!("awssso-{}", Uuid::new_v4()),
            tenant_id: tenant_id.to_owned(),
            label: if label.trim().is_empty() {
                start_url.to_owned()
            } else {
                label.trim().to_owned()
            },
            start_url: start_url.trim().to_owned(),
            region: if region.trim().is_empty() {
                "us-east-1".to_owned()
            } else {
                region.trim().to_owned()
            },
            created_at: now_unix_secs(),
        };
        self.providers
            .write()
            .await
            .insert(item.id.clone(), item.clone());
        Ok(item)
    }

    pub async fn delete_provider(&self, tenant_id: &str, id: &str) {
        let mut guard = self.providers.write().await;
        if guard.get(id).is_some_and(|p| p.tenant_id == tenant_id) {
            guard.remove(id);
        }
    }

    fn oidc_base(&self, region: &str) -> String {
        self.oidc_endpoint_override
            .clone()
            .unwrap_or_else(|| format!("https://oidc.{region}.amazonaws.com"))
    }

    fn portal_base(&self, region: &str) -> String {
        self.portal_endpoint_override
            .clone()
            .unwrap_or_else(|| format!("https://portal.sso.{region}.amazonaws.com"))
    }

    pub async fn start_device_auth(
        &self,
        tenant_id: &str,
        user_id: &str,
        region: &str,
        start_url: &str,
    ) -> Result<AwsSsoStartResponse, String> {
        let base = self.oidc_base(region);
        let reg: serde_json::Value = self
            .http
            .post(format!("{base}/client/register"))
            .json(&serde_json::json!({
                "clientName": "operquay",
                "clientType": "public"
            }))
            .send()
            .await
            .map_err(|e| format!("ssooidc register: {e}"))?
            .error_for_status()
            .map_err(|e| format!("ssooidc register status: {e}"))?
            .json()
            .await
            .map_err(|e| format!("ssooidc register json: {e}"))?;

        let client_id = reg["clientId"].as_str().unwrap_or_default().to_owned();
        let client_secret = reg["clientSecret"].as_str().unwrap_or_default().to_owned();

        let dev: serde_json::Value = self
            .http
            .post(format!("{base}/device_authorization"))
            .json(&serde_json::json!({
                "clientId": client_id,
                "clientSecret": client_secret,
                "startUrl": start_url,
            }))
            .send()
            .await
            .map_err(|e| format!("ssooidc device_authorization: {e}"))?
            .error_for_status()
            .map_err(|e| format!("ssooidc device status: {e}"))?
            .json()
            .await
            .map_err(|e| format!("ssooidc device json: {e}"))?;

        let expires_in = dev["expiresIn"].as_i64().unwrap_or(600);
        let interval = dev["interval"].as_u64().unwrap_or(5).max(1);
        let flow_id = Uuid::new_v4().to_string();
        let expires_at = now_unix_secs() + expires_in;

        let flow = ActiveSsoFlow {
            id: flow_id.clone(),
            tenant_id: tenant_id.to_owned(),
            user_id: user_id.to_owned(),
            region: region.to_owned(),
            start_url: start_url.to_owned(),
            client_id,
            client_secret,
            device_code: dev["deviceCode"].as_str().unwrap_or_default().to_owned(),
            access_token: String::new(),
            interval_secs: interval,
            expires_at,
            cancelled: false,
        };
        self.flows.write().await.insert(
            (tenant_id.to_owned(), user_id.to_owned(), flow_id.clone()),
            flow,
        );

        Ok(AwsSsoStartResponse {
            id: flow_id,
            verification_url: dev["verificationUri"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            verification_url_complete: dev["verificationUriComplete"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            user_code: dev["userCode"].as_str().unwrap_or_default().to_owned(),
            interval_seconds: interval,
            expires_at: unix_to_rfc3339(expires_at),
        })
    }

    pub async fn poll_token(
        &self,
        tenant_id: &str,
        user_id: &str,
        flow_id: &str,
    ) -> Result<&'static str, String> {
        let flow = self
            .flows
            .read()
            .await
            .get(&(tenant_id.to_owned(), user_id.to_owned(), flow_id.to_owned()))
            .cloned()
            .ok_or_else(|| "SSO session not found".to_owned())?;
        if flow.cancelled {
            return Err("SSO flow cancelled".to_owned());
        }
        if !flow.access_token.is_empty() {
            return Ok("authorized");
        }
        let base = self.oidc_base(&flow.region);
        let resp = self
            .http
            .post(format!("{base}/token"))
            .json(&serde_json::json!({
                "clientId": flow.client_id,
                "clientSecret": flow.client_secret,
                "grantType": "urn:ietf:params:oauth:grant-type:device_code",
                "deviceCode": flow.device_code,
            }))
            .send()
            .await
            .map_err(|e| format!("ssooidc token: {e}"))?;
        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("ssooidc token json: {e}"))?;
        if let Some(tok) = val["accessToken"].as_str().filter(|s| !s.is_empty()) {
            let exp_in = val["expiresIn"].as_i64().unwrap_or(28_800).max(60);
            if let Some(entry) = self.flows.write().await.get_mut(&(
                tenant_id.to_owned(),
                user_id.to_owned(),
                flow_id.to_owned(),
            )) {
                tok.clone_into(&mut entry.access_token);
                entry.expires_at = now_unix_secs() + exp_in;
            }
            return Ok("authorized");
        }
        let err = val["error"].as_str().unwrap_or("authorization_pending");
        if err == "authorization_pending" || err == "slow_down" {
            if self.oidc_endpoint_override.is_none() && !cfg!(test) {
                if let Some((tok, exp_unix)) =
                    find_or_refresh_local_sso_token(&self.http, &flow.region, &flow.start_url).await
                {
                    if let Some(entry) = self.flows.write().await.get_mut(&(
                        tenant_id.to_owned(),
                        user_id.to_owned(),
                        flow_id.to_owned(),
                    )) {
                        entry.access_token = tok;
                        entry.expires_at = exp_unix;
                    }
                    return Ok("authorized");
                }
            }
            Ok("pending")
        } else {
            Err(format!("SSO authorization failed: {err}"))
        }
    }

    pub async fn session_status(&self, tenant_id: &str, user_id: &str) -> serde_json::Value {
        let now = now_unix_secs();
        let active_flows: Vec<ActiveSsoFlow> = self
            .flows
            .read()
            .await
            .values()
            .filter(|f| {
                f.tenant_id == tenant_id
                    && f.user_id == user_id
                    && !f.cancelled
                    && !f.access_token.is_empty()
                    && f.expires_at > now
            })
            .cloned()
            .collect();
        let sessions: Vec<serde_json::Value> = active_flows
            .iter()
            .map(|f| {
                serde_json::json!({
                    "id": f.id,
                    "region": f.region,
                    "start_url": f.start_url,
                    "expires_at": unix_to_rfc3339(f.expires_at),
                })
            })
            .collect();
        if let Some(first) = active_flows.first() {
            serde_json::json!({
                "active": true,
                "connected": true,
                "sessions": sessions,
                "id": first.id,
                "region": first.region,
                "start_url": first.start_url,
                "expires_at": unix_to_rfc3339(first.expires_at),
                "interval_seconds": first.interval_secs,
            })
        } else {
            serde_json::json!({ "active": false, "connected": false, "sessions": [] })
        }
    }

    async fn portal_get_json(
        &self,
        url: &str,
        token: &str,
        op: &str,
    ) -> Result<serde_json::Value, String> {
        const MAX_ATTEMPTS: usize = 5;
        let mut last_err = String::new();
        for attempt in 0..MAX_ATTEMPTS {
            let resp_res = {
                let _permit = self
                    .portal_sem
                    .acquire()
                    .await
                    .map_err(|_| format!("{op}: portal semaphore closed"))?;
                self.http
                    .get(url)
                    .header("x-amz-sso_bearer_token", token)
                    .send()
                    .await
            };

            let resp = match resp_res {
                Ok(r) => r,
                Err(e) => {
                    last_err = format!("{op}: {e}");
                    if attempt + 1 < MAX_ATTEMPTS {
                        let backoff_ms = (350u64.saturating_mul(1u64 << attempt)).min(3000);
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        continue;
                    }
                    return Err(last_err);
                }
            };

            let status = resp.status();
            if status.as_u16() == 429 || matches!(status.as_u16(), 500 | 502 | 503 | 504) {
                let retry_after_ms = resp
                    .headers()
                    .get(http::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .map(|secs| (secs.saturating_mul(1000)).clamp(100, 5000));
                let body = resp.text().await.unwrap_or_default();
                last_err = format!("{op} status {status}: {body}");
                if attempt + 1 < MAX_ATTEMPTS {
                    let backoff_ms = retry_after_ms
                        .unwrap_or_else(|| (350u64.saturating_mul(1u64 << attempt)).min(3000));
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    continue;
                }
                return Err(last_err);
            }

            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(format!("{op} status {status}: {body}"));
            }

            return resp
                .json::<serde_json::Value>()
                .await
                .map_err(|e| format!("{op} json: {e}"));
        }
        Err(last_err)
    }

    pub async fn list_accounts(
        &self,
        tenant_id: &str,
        user_id: &str,
        flow_id: &str,
    ) -> Result<Vec<AwsSsoAccount>, String> {
        let flow = self.authorized_flow(tenant_id, user_id, flow_id).await?;
        let base = self.portal_base(&flow.region);
        let mut out = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let url = match next_token.as_deref() {
                Some(tok) if !tok.is_empty() => format!(
                    "{base}/assignment/accounts?max_result=100&next_token={}",
                    encode_query_component(tok)
                ),
                _ => format!("{base}/assignment/accounts?max_result=100"),
            };
            let val = self
                .portal_get_json(&url, &flow.access_token, "sso list accounts")
                .await?;
            if let Some(arr) = val["accountList"].as_array() {
                let mut names = self.account_names.write().await;
                for item in arr {
                    let id = item["accountId"].as_str().unwrap_or_default().to_owned();
                    let name = item["accountName"].as_str().unwrap_or_default().to_owned();
                    if !id.is_empty() && !name.is_empty() {
                        names.insert(id.clone(), name.clone());
                    }
                    out.push(AwsSsoAccount {
                        id,
                        name,
                        email: item["emailAddress"].as_str().unwrap_or_default().to_owned(),
                    });
                }
            }
            next_token = val["nextToken"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            if next_token.is_none() {
                break;
            }
        }
        Ok(out)
    }

    pub async fn list_account_roles(
        &self,
        tenant_id: &str,
        user_id: &str,
        flow_id: &str,
        account_id: &str,
    ) -> Result<Vec<AwsSsoRole>, String> {
        let flow = self.authorized_flow(tenant_id, user_id, flow_id).await?;
        let base = self.portal_base(&flow.region);
        let acct_q = encode_query_component(account_id);
        let mut out = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let url = match next_token.as_deref() {
                Some(tok) if !tok.is_empty() => format!(
                    "{base}/assignment/roles?account_id={acct_q}&max_result=100&next_token={}",
                    encode_query_component(tok)
                ),
                _ => format!("{base}/assignment/roles?account_id={acct_q}&max_result=100"),
            };
            let val = self
                .portal_get_json(&url, &flow.access_token, "sso list roles")
                .await?;
            if let Some(arr) = val["roleList"].as_array() {
                for item in arr {
                    out.push(AwsSsoRole {
                        account_id: account_id.to_owned(),
                        name: item["roleName"].as_str().unwrap_or_default().to_owned(),
                    });
                }
            }
            next_token = val["nextToken"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            if next_token.is_none() {
                break;
            }
        }
        Ok(out)
    }

    pub async fn get_role_credentials(
        &self,
        tenant_id: &str,
        user_id: &str,
        flow_id: &str,
        account_id: &str,
        role_name: &str,
    ) -> Result<(String, AwsCredentials), String> {
        let (region, _, creds) = self
            .get_role_credentials_with_portal(tenant_id, user_id, flow_id, account_id, role_name)
            .await?;
        Ok((region, creds))
    }

    pub async fn get_role_credentials_with_portal(
        &self,
        tenant_id: &str,
        user_id: &str,
        flow_id: &str,
        account_id: &str,
        role_name: &str,
    ) -> Result<(String, String, AwsCredentials), String> {
        let flow = self.authorized_flow(tenant_id, user_id, flow_id).await?;
        let url = format!(
            "{}/federation/credentials?account_id={}&role_name={}",
            self.portal_base(&flow.region),
            encode_query_component(account_id),
            encode_query_component(role_name),
        );
        let val = self
            .portal_get_json(&url, &flow.access_token, "sso get creds")
            .await?;
        let rc = &val["roleCredentials"];
        Ok((
            flow.region,
            flow.start_url,
            AwsCredentials {
                access_key_id: rc["accessKeyId"].as_str().unwrap_or_default().to_owned(),
                secret_access_key: rc["secretAccessKey"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                session_token: rc["sessionToken"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned),
            },
        ))
    }

    pub async fn cancel(&self, tenant_id: &str, user_id: &str, flow_id: &str) {
        if let Some(f) = self.flows.write().await.get_mut(&(
            tenant_id.to_owned(),
            user_id.to_owned(),
            flow_id.to_owned(),
        )) {
            f.cancelled = true;
            f.access_token.clear();
        }
    }

    async fn authorized_flow(
        &self,
        tenant_id: &str,
        user_id: &str,
        flow_id: &str,
    ) -> Result<ActiveSsoFlow, String> {
        let f = self
            .flows
            .read()
            .await
            .get(&(tenant_id.to_owned(), user_id.to_owned(), flow_id.to_owned()))
            .cloned()
            .ok_or_else(|| "SSO session not found".to_owned())?;
        if f.cancelled || f.access_token.is_empty() {
            return Err("SSO session not authorized".to_owned());
        }
        Ok(f)
    }
}

fn encode_query_component(raw: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn normalize_sso_portal_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    let host_part = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host = host_part
        .split('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if host.is_empty() {
        String::new()
    } else {
        format!("https://{host}/start")
    }
}

fn unix_to_rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y_base = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y_base + i64::from(m <= 2);
    let h = tod / 3600;
    let min = (tod % 3600) / 60;
    let s = tod % 60;
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{s:02}Z")
}

fn parse_rfc3339_secs(raw: &str) -> Option<i64> {
    let clean = raw.trim();
    if clean.len() < 19 {
        return None;
    }
    let y: i64 = clean.get(0..4)?.parse().ok()?;
    let m: i64 = clean.get(5..7)?.parse().ok()?;
    let d: i64 = clean.get(8..10)?.parse().ok()?;
    let h: i64 = clean.get(11..13)?.parse().ok()?;
    let min: i64 = clean.get(14..16)?.parse().ok()?;
    let s: i64 = clean.get(17..19)?.parse().ok()?;
    let y_adj = y - i64::from(m <= 2);
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = (y_adj - era * 400) as u64;
    let m_u = m as u64;
    let doy = (153 * (if m_u > 2 { m_u - 3 } else { m_u + 9 }) + 2) / 5 + (d as u64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + (doe as i64) - 719_468;
    Some(days * 86_400 + h * 3600 + min * 60 + s)
}

async fn find_or_refresh_local_sso_token(
    http: &reqwest::Client,
    region: &str,
    start_url: &str,
) -> Option<(String, i64)> {
    let home = std::env::var("HOME").ok().filter(|h| !h.is_empty())?;
    let cache_dir = std::path::Path::new(&home).join(".aws/sso/cache");
    let entries = std::fs::read_dir(cache_dir).ok()?;
    let target = normalize_sso_portal_url(start_url);
    if target.is_empty() {
        return None;
    }
    let now = now_unix_secs();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        let entry_start = val["startUrl"].as_str().unwrap_or_default();
        if normalize_sso_portal_url(entry_start) != target {
            continue;
        }
        let tok = val["accessToken"].as_str().unwrap_or_default();
        let exp = val["expiresAt"]
            .as_str()
            .and_then(parse_rfc3339_secs)
            .unwrap_or(0);
        if !tok.is_empty() && exp > now + 30 {
            return Some((tok.to_owned(), exp));
        }
        let reg = val["region"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or(region);
        let refresh = val["refreshToken"].as_str().unwrap_or_default();
        let cid = val["clientId"].as_str().unwrap_or_default();
        let csec = val["clientSecret"].as_str().unwrap_or_default();
        if !refresh.is_empty() && !cid.is_empty() && !csec.is_empty() {
            let oidc_url = format!("https://oidc.{reg}.amazonaws.com/token");
            if let Ok(resp) = http
                .post(&oidc_url)
                .json(&serde_json::json!({
                    "clientId": cid,
                    "clientSecret": csec,
                    "grantType": "refresh_token",
                    "refreshToken": refresh,
                }))
                .send()
                .await
            {
                if resp.status().is_success() {
                    if let Ok(refreshed) = resp.json::<serde_json::Value>().await {
                        if let Some(new_tok) =
                            refreshed["accessToken"].as_str().filter(|s| !s.is_empty())
                        {
                            let exp_in = refreshed["expiresIn"].as_i64().unwrap_or(28_800).max(60);
                            return Some((new_tok.to_owned(), now + exp_in));
                        }
                    }
                }
            }
        }
    }
    None
}
