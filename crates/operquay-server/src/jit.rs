#![forbid(unsafe_code)]

//! Zero Standing Privileges (ZSP) JIT Access Requests, Four-Eyes Approval, Bounded `ChatOps`
//! Interactive Webhooks (Slack / Teams / `PagerDuty` / Jira / `ServiceNow`), and Governance State
//! Store (`M11.1`–`M11.4`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use constant_time_eq::constant_time_eq;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use crate::compliance::{
    derive_evidence_key_from_master, generate_ephemeral_evidence_seed, AccessReviewCampaign,
};
use crate::dlp::DlpFirewallPolicy;

type HmacSha256 = Hmac<Sha256>;

const WEBHOOK_CHANNEL_CAPACITY: usize = 512;
const MIN_JIT_DURATION_SECS: u64 = 300;
const MAX_JIT_DURATION_SECS: u64 = 14_400;

#[must_use]
pub fn now_unix_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JitTargetType {
    #[default]
    AwsRole,
    Ssh,
    Rdp,
    K8sExec,
    DbWrite,
}

impl JitTargetType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwsRole => "aws_role",
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::K8sExec => "k8s_exec",
            Self::DbWrite => "db_write",
        }
    }

    #[must_use]
    pub fn parse_lossy(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "ssh" | "ssm" => Self::Ssh,
            "rdp" | "vnc" | "desktop" => Self::Rdp,
            "k8s" | "k8s_exec" | "kubernetes" => Self::K8sExec,
            "db" | "db_write" | "database" => Self::DbWrite,
            _ => Self::AwsRole,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JitStatus {
    #[default]
    Pending,
    Approved,
    Denied,
    Expired,
    Revoked,
}

impl JitStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitAccessRequest {
    pub id: String,
    pub tenant_id: String,
    pub requester_user_id: String,
    pub requester_email: String,
    pub target_type: JitTargetType,
    pub target_id: String,
    pub requested_role: String,
    pub duration_secs: u64,
    pub reason: String,
    #[serde(default)]
    pub ticket_id: String,
    #[serde(default)]
    pub ticket_provider: String,
    pub status: JitStatus,
    #[serde(default)]
    pub approver_user_id: Option<String>,
    #[serde(default)]
    pub approver_email: Option<String>,
    #[serde(default)]
    pub decision_note: String,
    pub created_at: i64,
    #[serde(default)]
    pub decided_at: Option<i64>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateJitRequestInput {
    pub target_type: JitTargetType,
    pub target_id: String,
    pub requested_role: String,
    pub duration_secs: u64,
    pub reason: String,
    #[serde(default)]
    pub ticket_id: String,
    #[serde(default)]
    pub ticket_provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceWebhook {
    pub id: String,
    pub tenant_id: String,
    pub provider: String,
    pub name: String,
    pub url: String,
    #[serde(skip_serializing)]
    pub secret: String,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicGovernanceWebhook {
    pub id: String,
    pub tenant_id: String,
    pub provider: String,
    pub name: String,
    pub url: String,
    pub has_secret: bool,
    pub events: Vec<String>,
    pub enabled: bool,
    pub created_at: i64,
}

impl From<&GovernanceWebhook> for PublicGovernanceWebhook {
    fn from(w: &GovernanceWebhook) -> Self {
        Self {
            id: w.id.clone(),
            tenant_id: w.tenant_id.clone(),
            provider: w.provider.clone(),
            name: w.name.clone(),
            url: w.url.clone(),
            has_secret: !w.secret.is_empty(),
            events: w.events.clone(),
            enabled: w.enabled,
            created_at: w.created_at,
        }
    }
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionRiskBookmark {
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookDeliveryStats {
    pub enqueued: u64,
    pub delivered: u64,
    pub dropped: u64,
    pub failed: u64,
}

#[derive(Debug, Default)]
struct WebhookCounters {
    enqueued: AtomicU64,
    delivered: AtomicU64,
    dropped: AtomicU64,
    failed: AtomicU64,
}

#[derive(Debug, Clone)]
struct WebhookDispatchJob {
    webhook: GovernanceWebhook,
    event_type: String,
    payload: serde_json::Value,
}

pub struct GovernanceStore {
    requests: RwLock<HashMap<String, JitAccessRequest>>,
    webhooks: RwLock<HashMap<String, GovernanceWebhook>>,
    dlp_policies: RwLock<HashMap<String, DlpFirewallPolicy>>,
    bookmarks: RwLock<HashMap<String, Vec<SessionRiskBookmark>>>,
    campaigns: RwLock<HashMap<String, AccessReviewCampaign>>,
    evidence_signing_seed: RwLock<[u8; 32]>,
    webhook_tx: mpsc::Sender<WebhookDispatchJob>,
    webhook_counters: Arc<WebhookCounters>,
}

impl Default for GovernanceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernanceStore {
    #[must_use]
    pub fn new() -> Self {
        let (webhook_tx, webhook_rx) = mpsc::channel(WEBHOOK_CHANNEL_CAPACITY);
        let counters = Arc::new(WebhookCounters::default());
        tokio::spawn(run_webhook_worker(webhook_rx, Arc::clone(&counters)));
        Self {
            requests: RwLock::new(HashMap::new()),
            webhooks: RwLock::new(HashMap::new()),
            dlp_policies: RwLock::new(HashMap::new()),
            bookmarks: RwLock::new(HashMap::new()),
            campaigns: RwLock::new(HashMap::new()),
            evidence_signing_seed: RwLock::new(generate_ephemeral_evidence_seed()),
            webhook_tx,
            webhook_counters: counters,
        }
    }

    pub async fn set_cluster_master_secret(&self, secret: &[u8]) {
        if !secret.is_empty() {
            *self.evidence_signing_seed.write().await = derive_evidence_key_from_master(secret);
        }
    }

    pub async fn evidence_signing_seed(&self) -> [u8; 32] {
        *self.evidence_signing_seed.read().await
    }

    pub async fn create_request(
        &self,
        tenant_id: &str,
        requester_user_id: &str,
        requester_email: &str,
        input: CreateJitRequestInput,
    ) -> Result<JitAccessRequest, String> {
        let target_id = input.target_id.trim();
        let reason = input.reason.trim();
        if target_id.is_empty() {
            return Err("target_id is required".to_owned());
        }
        if reason.is_empty() {
            return Err("reason is required for audit trail".to_owned());
        }
        let ticket = input.ticket_id.trim();
        if !ticket.is_empty()
            && !ticket
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '#'))
        {
            return Err("ticket_id contains invalid characters".to_owned());
        }
        let duration_secs = input
            .duration_secs
            .clamp(MIN_JIT_DURATION_SECS, MAX_JIT_DURATION_SECS);
        let req = JitAccessRequest {
            id: format!("jit-{}", Uuid::new_v4()),
            tenant_id: tenant_id.to_owned(),
            requester_user_id: requester_user_id.to_owned(),
            requester_email: requester_email.to_owned(),
            target_type: input.target_type,
            target_id: target_id.to_owned(),
            requested_role: if input.requested_role.trim().is_empty() {
                "operator".to_owned()
            } else {
                input.requested_role.trim().to_owned()
            },
            duration_secs,
            reason: reason.to_owned(),
            ticket_id: ticket.to_owned(),
            ticket_provider: input.ticket_provider.trim().to_owned(),
            status: JitStatus::Pending,
            approver_user_id: None,
            approver_email: None,
            decision_note: String::new(),
            created_at: now_unix_secs(),
            decided_at: None,
            expires_at: None,
            revoked_at: None,
        };
        self.requests
            .write()
            .await
            .insert(req.id.clone(), req.clone());
        Ok(req)
    }

    pub async fn list_requests(&self, tenant_id: &str) -> Vec<JitAccessRequest> {
        let mut items: Vec<_> = self
            .requests
            .read()
            .await
            .values()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect();
        items.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        items
    }

    pub async fn get_request(&self, tenant_id: &str, id: &str) -> Option<JitAccessRequest> {
        self.requests
            .read()
            .await
            .get(id)
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
    }

    pub async fn approve_request(
        &self,
        tenant_id: &str,
        id: &str,
        approver_user_id: &str,
        approver_email: &str,
        note: &str,
    ) -> Result<JitAccessRequest, String> {
        let mut guard = self.requests.write().await;
        let req = guard
            .get_mut(id)
            .filter(|r| r.tenant_id == tenant_id)
            .ok_or_else(|| "access request not found".to_owned())?;
        if req.status != JitStatus::Pending {
            return Err(format!(
                "cannot approve request in '{}' status",
                req.status.as_str()
            ));
        }
        if !req.requester_user_id.is_empty() && req.requester_user_id == approver_user_id {
            return Err(
                "four-eyes separation enforced: requester cannot approve their own access request"
                    .to_owned(),
            );
        }
        let now = now_unix_secs();
        req.status = JitStatus::Approved;
        req.approver_user_id = Some(approver_user_id.to_owned());
        req.approver_email = Some(approver_email.to_owned());
        note.trim().clone_into(&mut req.decision_note);
        req.decided_at = Some(now);
        req.expires_at = Some(now.saturating_add(i64::try_from(req.duration_secs).unwrap_or(3600)));
        Ok(req.clone())
    }

    pub async fn deny_request(
        &self,
        tenant_id: &str,
        id: &str,
        approver_user_id: &str,
        approver_email: &str,
        note: &str,
    ) -> Result<JitAccessRequest, String> {
        let mut guard = self.requests.write().await;
        let req = guard
            .get_mut(id)
            .filter(|r| r.tenant_id == tenant_id)
            .ok_or_else(|| "access request not found".to_owned())?;
        if req.status != JitStatus::Pending {
            return Err(format!(
                "cannot deny request in '{}' status",
                req.status.as_str()
            ));
        }
        let now = now_unix_secs();
        req.status = JitStatus::Denied;
        req.approver_user_id = Some(approver_user_id.to_owned());
        req.approver_email = Some(approver_email.to_owned());
        note.trim().clone_into(&mut req.decision_note);
        req.decided_at = Some(now);
        Ok(req.clone())
    }

    pub async fn revoke_request(
        &self,
        tenant_id: &str,
        id: &str,
        actor_user_id: &str,
        note: &str,
    ) -> Result<JitAccessRequest, String> {
        let mut guard = self.requests.write().await;
        let req = guard
            .get_mut(id)
            .filter(|r| r.tenant_id == tenant_id)
            .ok_or_else(|| "access request not found".to_owned())?;
        let now = now_unix_secs();
        req.status = JitStatus::Revoked;
        req.revoked_at = Some(now);
        if req.approver_user_id.is_none() {
            req.approver_user_id = Some(actor_user_id.to_owned());
        }
        if !note.trim().is_empty() {
            note.trim().clone_into(&mut req.decision_note);
        }
        Ok(req.clone())
    }

    /// Return the ID of an active, unexpired approved JIT grant matching `(user_id, target_type, target_id)`.
    pub async fn find_active_grant(
        &self,
        tenant_id: &str,
        user_id: &str,
        target_type: JitTargetType,
        target_id: &str,
    ) -> Option<JitAccessRequest> {
        let now = now_unix_secs();
        self.requests
            .read()
            .await
            .values()
            .find(|r| {
                r.tenant_id == tenant_id
                    && r.requester_user_id == user_id
                    && r.target_type == target_type
                    && (r.target_id == target_id || r.target_id == "*")
                    && r.status == JitStatus::Approved
                    && r.revoked_at.is_none()
                    && r.expires_at.is_some_and(|exp| exp > now)
            })
            .cloned()
    }

    /// Expire approved requests past `expires_at` and return them for session-fence revocation.
    pub async fn reap_expired_grants(&self) -> Vec<JitAccessRequest> {
        let now = now_unix_secs();
        let mut expired = Vec::new();
        let mut guard = self.requests.write().await;
        for req in guard.values_mut() {
            if req.status == JitStatus::Approved && req.expires_at.is_some_and(|exp| exp <= now) {
                req.status = JitStatus::Expired;
                expired.push(req.clone());
            }
        }
        expired
    }

    pub async fn hydrate_requests(&self, items: Vec<JitAccessRequest>) {
        let mut guard = self.requests.write().await;
        for item in items {
            guard.insert(item.id.clone(), item);
        }
    }

    pub async fn add_webhook(&self, hook: GovernanceWebhook) -> Result<GovernanceWebhook, String> {
        let url = hook.url.trim();
        if url.is_empty()
            || (!url.starts_with("https://")
                && !url.starts_with("http://127.0.0.1")
                && !url.starts_with("http://localhost"))
        {
            return Err(
                "webhook url must use https:// (or loopback http:// for local tests)".to_owned(),
            );
        }
        self.webhooks
            .write()
            .await
            .insert(hook.id.clone(), hook.clone());
        Ok(hook)
    }

    pub async fn list_webhooks(&self, tenant_id: &str) -> Vec<PublicGovernanceWebhook> {
        self.webhooks
            .read()
            .await
            .values()
            .filter(|w| w.tenant_id == tenant_id)
            .map(PublicGovernanceWebhook::from)
            .collect()
    }

    pub async fn raw_webhooks_for_provider(
        &self,
        tenant_id: &str,
        provider: &str,
    ) -> Vec<GovernanceWebhook> {
        self.webhooks
            .read()
            .await
            .values()
            .filter(|w| {
                w.tenant_id == tenant_id
                    && w.enabled
                    && w.provider.eq_ignore_ascii_case(provider.trim())
            })
            .cloned()
            .collect()
    }

    pub async fn delete_webhook(&self, tenant_id: &str, id: &str) -> bool {
        let mut guard = self.webhooks.write().await;
        if guard.get(id).is_some_and(|w| w.tenant_id == tenant_id) {
            guard.remove(id).is_some()
        } else {
            false
        }
    }

    pub async fn hydrate_webhooks(&self, items: Vec<GovernanceWebhook>) {
        let mut guard = self.webhooks.write().await;
        for w in items {
            guard.insert(w.id.clone(), w);
        }
    }

    /// Non-blocking bounded enqueue to all enabled matching webhooks for `tenant_id`.
    pub async fn dispatch_webhook(
        &self,
        tenant_id: &str,
        event_type: &str,
        payload: serde_json::Value,
    ) {
        let hooks: Vec<GovernanceWebhook> = self
            .webhooks
            .read()
            .await
            .values()
            .filter(|w| {
                w.tenant_id == tenant_id
                    && w.enabled
                    && (w.events.is_empty() || w.events.iter().any(|e| e == "*" || e == event_type))
            })
            .cloned()
            .collect();
        for webhook in hooks {
            if self
                .webhook_tx
                .try_send(WebhookDispatchJob {
                    webhook,
                    event_type: event_type.to_owned(),
                    payload: payload.clone(),
                })
                .is_ok()
            {
                self.webhook_counters
                    .enqueued
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                self.webhook_counters
                    .dropped
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[must_use]
    pub fn webhook_stats(&self) -> WebhookDeliveryStats {
        WebhookDeliveryStats {
            enqueued: self.webhook_counters.enqueued.load(Ordering::Relaxed),
            delivered: self.webhook_counters.delivered.load(Ordering::Relaxed),
            dropped: self.webhook_counters.dropped.load(Ordering::Relaxed),
            failed: self.webhook_counters.failed.load(Ordering::Relaxed),
        }
    }

    pub async fn get_dlp_policy(&self, tenant_id: &str) -> DlpFirewallPolicy {
        self.dlp_policies
            .read()
            .await
            .get(tenant_id)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn set_dlp_policy(&self, tenant_id: &str, policy: DlpFirewallPolicy) {
        self.dlp_policies
            .write()
            .await
            .insert(tenant_id.to_owned(), policy);
    }

    pub async fn hydrate_dlp_policies(&self, items: Vec<(String, DlpFirewallPolicy)>) {
        let mut guard = self.dlp_policies.write().await;
        for (tid, pol) in items {
            guard.insert(tid, pol);
        }
    }

    pub async fn replace_bookmarks(
        &self,
        tenant_id: &str,
        recording_id: &str,
        items: Vec<SessionRiskBookmark>,
    ) {
        self.bookmarks
            .write()
            .await
            .insert(format!("{tenant_id}:{recording_id}"), items);
    }

    pub async fn hydrate_bookmarks(&self, items: Vec<SessionRiskBookmark>) {
        let mut guard = self.bookmarks.write().await;
        for item in items {
            guard
                .entry(format!("{}:{}", item.tenant_id, item.recording_id))
                .or_default()
                .push(item);
        }
    }

    pub async fn list_bookmarks(
        &self,
        tenant_id: &str,
        recording_id: &str,
    ) -> Vec<SessionRiskBookmark> {
        self.bookmarks
            .read()
            .await
            .get(&format!("{tenant_id}:{recording_id}"))
            .cloned()
            .unwrap_or_default()
    }

    pub async fn save_campaign(&self, campaign: AccessReviewCampaign) {
        self.campaigns
            .write()
            .await
            .insert(campaign.id.clone(), campaign);
    }

    pub async fn get_campaign(&self, tenant_id: &str, id: &str) -> Option<AccessReviewCampaign> {
        self.campaigns
            .read()
            .await
            .get(id)
            .filter(|c| c.tenant_id == tenant_id)
            .cloned()
    }

    pub async fn list_campaigns(&self, tenant_id: &str) -> Vec<AccessReviewCampaign> {
        let mut items: Vec<_> = self
            .campaigns
            .read()
            .await
            .values()
            .filter(|c| c.tenant_id == tenant_id)
            .cloned()
            .collect();
        items.sort_by_key(|c| std::cmp::Reverse(c.created_at));
        items
    }

    pub async fn hydrate_campaigns(&self, items: Vec<AccessReviewCampaign>) {
        let mut guard = self.campaigns.write().await;
        for c in items {
            guard.insert(c.id.clone(), c);
        }
    }
}

/// Compute `sha256=<hex>` HMAC signature header for outbound `ChatOps` webhooks and verify callbacks.
#[must_use]
pub fn sign_hmac_sha256_hex(secret: &str, body: &[u8]) -> String {
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return String::new();
    };
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Verify Slack `X-Slack-Signature` (`v0=<hex>`) against `v0:{timestamp}:{raw_body}` with 300s replay bound.
#[must_use]
pub fn verify_slack_signature(
    signing_secret: &str,
    timestamp: &str,
    signature_header: &str,
    raw_body: &[u8],
) -> bool {
    let Ok(ts) = timestamp.trim().parse::<i64>() else {
        return false;
    };
    if now_unix_secs().abs_diff(ts) > 300 {
        return false;
    }
    let Some(hex_sig) = signature_header.trim().strip_prefix("v0=") else {
        return false;
    };
    let Ok(provided) = hex::decode(hex_sig) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(signing_secret.as_bytes()) else {
        return false;
    };
    mac.update(b"v0:");
    mac.update(timestamp.trim().as_bytes());
    mac.update(b":");
    mac.update(raw_body);
    let expected = mac.finalize().into_bytes();
    constant_time_eq(&expected, &provided)
}

/// Verify generic Operquay HMAC header (`sha256=<hex>` or raw `<hex>`).
#[must_use]
pub fn verify_operquay_hmac(secret: &str, signature_header: &str, raw_body: &[u8]) -> bool {
    let clean = signature_header
        .trim()
        .strip_prefix("sha256=")
        .unwrap_or(signature_header.trim());
    let Ok(provided) = hex::decode(clean) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(raw_body);
    let expected = mac.finalize().into_bytes();
    constant_time_eq(&expected, &provided)
}

#[must_use]
pub fn format_provider_webhook_body(
    provider: &str,
    event_type: &str,
    payload: &serde_json::Value,
) -> serde_json::Value {
    let summary = payload["summary"]
        .as_str()
        .or_else(|| payload["reason"].as_str())
        .unwrap_or(event_type);
    let req_id = payload["id"].as_str().unwrap_or("");
    let target = payload["target_id"].as_str().unwrap_or("");
    let requester = payload["requester_email"].as_str().unwrap_or("");

    match provider.trim().to_ascii_lowercase().as_str() {
        "slack" => {
            if event_type.starts_with("access_request.") && !req_id.is_empty() {
                serde_json::json!({
                    "text": format!("[Operquay JIT] {event_type}: {requester} -> {target}"),
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": format!("*Operquay JIT Access Request* (`{req_id}`)\n*Event:* `{event_type}`\n*Requester:* {requester}\n*Target:* `{target}`\n*Detail:* {summary}")
                            }
                        },
                        {
                            "type": "actions",
                            "block_id": format!("jit_{req_id}"),
                            "elements": [
                                {
                                    "type": "button",
                                    "text": { "type": "plain_text", "text": "Approve" },
                                    "style": "primary",
                                    "action_id": "jit_approve",
                                    "value": req_id
                                },
                                {
                                    "type": "button",
                                    "text": { "type": "plain_text", "text": "Deny" },
                                    "style": "danger",
                                    "action_id": "jit_deny",
                                    "value": req_id
                                }
                            ]
                        }
                    ],
                    "operquay": payload,
                })
            } else {
                serde_json::json!({
                    "text": format!("[Operquay Alert] `{event_type}`: {summary}"),
                    "operquay": payload,
                })
            }
        }
        "teams" => serde_json::json!({
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        { "type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": format!("Operquay Governance: {event_type}") },
                        { "type": "TextBlock", "wrap": true, "text": summary }
                    ]
                }
            }],
            "operquay": payload,
        }),
        "pagerduty" => serde_json::json!({
            "event_action": "trigger",
            "dedup_key": format!("operquay-{event_type}-{req_id}"),
            "payload": {
                "summary": format!("[Operquay] {event_type}: {summary}"),
                "source": "operquay-control-plane",
                "severity": if event_type.contains("break_glass") || event_type.contains("block") { "critical" } else { "warning" },
                "custom_details": payload,
            }
        }),
        _ => serde_json::json!({
            "event": event_type,
            "timestamp": now_unix_secs(),
            "payload": payload,
        }),
    }
}

async fn run_webhook_worker(
    mut rx: mpsc::Receiver<WebhookDispatchJob>,
    counters: Arc<WebhookCounters>,
) {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();
    while let Some(job) = rx.recv().await {
        let body_json =
            format_provider_webhook_body(&job.webhook.provider, &job.event_type, &job.payload);
        let bytes = serde_json::to_vec(&body_json).unwrap_or_else(|_| b"{}".to_vec());
        let mut req = http
            .post(&job.webhook.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("X-Operquay-Event", &job.event_type);
        if !job.webhook.secret.is_empty() {
            let sig = sign_hmac_sha256_hex(&job.webhook.secret, &bytes);
            req = req.header("X-Operquay-Signature", format!("sha256={sig}"));
        }
        match req.body(bytes).send().await {
            Ok(resp) if resp.status().is_success() => {
                counters.delivered.fetch_add(1, Ordering::Relaxed);
            }
            Ok(resp) => {
                counters.failed.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(webhook = %job.webhook.name, status = %resp.status(), "governance webhook returned non-2xx");
            }
            Err(err) => {
                counters.failed.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(webhook = %job.webhook.name, error = %err, "governance webhook delivery failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn enforces_four_eyes_reaps_expired_grants_and_dispatches_signed_webhooks() {
        let store = GovernanceStore::new();
        let req = store
            .create_request(
                "acme",
                "u-alice",
                "alice@acme.test",
                CreateJitRequestInput {
                    target_type: JitTargetType::AwsRole,
                    target_id: "arn:aws:iam::123456789012:role/ProdAdmin".into(),
                    requested_role: "ProdAdmin".into(),
                    duration_secs: 600,
                    reason: "Incident mitigation".into(),
                    ticket_id: "INC-4242".into(),
                    ticket_provider: "jira".into(),
                },
            )
            .await
            .unwrap();

        // Four-eyes enforcement: requester cannot self-approve
        let self_err = store
            .approve_request("acme", &req.id, "u-alice", "alice@acme.test", "self")
            .await
            .unwrap_err();
        assert!(self_err.contains("four-eyes"));

        // Peer approval succeeds
        let approved = store
            .approve_request("acme", &req.id, "u-bob", "bob@acme.test", "lgtm")
            .await
            .unwrap();
        assert_eq!(approved.status, JitStatus::Approved);
        assert!(store
            .find_active_grant(
                "acme",
                "u-alice",
                JitTargetType::AwsRole,
                "arn:aws:iam::123456789012:role/ProdAdmin",
            )
            .await
            .is_some());

        // Loopback signed Slack webhook delivery
        let hits = Arc::new(Mutex::new(Vec::<(String, serde_json::Value)>::new()));
        let hits_c = Arc::clone(&hits);
        let app = Router::new().route(
            "/slack",
            post(move |headers: HeaderMap, body: axum::body::Bytes| {
                let h = Arc::clone(&hits_c);
                async move {
                    let sig = headers
                        .get("x-operquay-signature")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    assert!(verify_operquay_hmac("wh-secret", &sig, &body));
                    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    h.lock().await.push((sig, json));
                    StatusCode::OK
                }
            }),
        );
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(ln, app).await;
        });

        store
            .add_webhook(GovernanceWebhook {
                id: "wh-1".into(),
                tenant_id: "acme".into(),
                provider: "slack".into(),
                name: "SecOps Slack".into(),
                url: format!("http://{addr}/slack"),
                secret: "wh-secret".into(),
                events: vec!["access_request.requested".into()],
                enabled: true,
                created_at: now_unix_secs(),
            })
            .await
            .unwrap();

        store
            .dispatch_webhook(
                "acme",
                "access_request.requested",
                serde_json::to_value(&req).unwrap(),
            )
            .await;

        for _ in 0..40 {
            if !hits.lock().await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(hits.lock().await.len(), 1);
        assert!(hits.lock().await[0].1["blocks"].is_array());

        // Expiration reaping marks expired grants
        let mut expired_req = approved;
        expired_req.id = "jit-expired-1".into();
        expired_req.expires_at = Some(now_unix_secs() - 10);
        store.hydrate_requests(vec![expired_req]).await;
        let reaped = store.reap_expired_grants().await;
        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0].id, "jit-expired-1");
        assert_eq!(reaped[0].status, JitStatus::Expired);
    }

    #[test]
    fn slack_hmac_verification_accepts_valid_and_rejects_tamper() {
        let ts = now_unix_secs().to_string();
        let body = b"payload=%7B%7D";
        let mut mac = HmacSha256::new_from_slice(b"slack-signing-sec").unwrap();
        mac.update(b"v0:");
        mac.update(ts.as_bytes());
        mac.update(b":");
        mac.update(body);
        let sig = format!("v0={}", hex::encode(mac.finalize().into_bytes()));
        assert!(verify_slack_signature("slack-signing-sec", &ts, &sig, body));
        assert!(!verify_slack_signature(
            "slack-signing-sec",
            &ts,
            &sig,
            b"tampered"
        ));
    }
}
