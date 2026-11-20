#![forbid(unsafe_code)]

//! AI Agent & Model Context Protocol (MCP) Zero-Trust Governance Broker (`M12.1`, ISO/IEC 42001).

use std::collections::{HashMap, VecDeque};

use constant_time_eq::constant_time_eq;
use operquay_auth::crypto::fill_csprng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::jit::now_unix_secs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpAgent {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub sponsor_user_id: String,
    pub sponsor_email: String,
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub allowed_tools: Vec<String>,
    pub require_jit_tools: Vec<String>,
    pub rate_limit_per_min: u32,
    pub status: String,
    pub expires_at: i64,
    pub created_at: i64,
    #[serde(default)]
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicMcpAgent {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub sponsor_user_id: String,
    pub sponsor_email: String,
    pub allowed_tools: Vec<String>,
    pub require_jit_tools: Vec<String>,
    pub rate_limit_per_min: u32,
    pub status: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

impl From<&McpAgent> for PublicMcpAgent {
    fn from(a: &McpAgent) -> Self {
        Self {
            id: a.id.clone(),
            tenant_id: a.tenant_id.clone(),
            name: a.name.clone(),
            sponsor_user_id: a.sponsor_user_id.clone(),
            sponsor_email: a.sponsor_email.clone(),
            allowed_tools: a.allowed_tools.clone(),
            require_jit_tools: a.require_jit_tools.clone(),
            rate_limit_per_min: a.rate_limit_per_min,
            status: a.status.clone(),
            expires_at: a.expires_at,
            created_at: a.created_at,
            revoked_at: a.revoked_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateMcpAgentInput {
    pub name: String,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub require_jit_tools: Vec<String>,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_min: u32,
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: i64,
}

const fn default_rate_limit() -> u32 {
    60
}

const fn default_ttl_secs() -> i64 {
    86_400
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolInvocation {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub sponsor_user_id: String,
    pub tool_name: String,
    pub sanitized_args: String,
    pub decision: String,
    #[serde(default)]
    pub jit_request_id: Option<String>,
    pub masked_result_preview: String,
    pub duration_ms: i64,
    pub created_at: i64,
}

#[must_use]
pub fn hash_mcp_token(raw: &str) -> String {
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}

#[derive(Default)]
pub struct McpRegistry {
    agents: RwLock<HashMap<String, McpAgent>>,
    invocations: RwLock<Vec<McpToolInvocation>>,
    rate_windows: RwLock<HashMap<String, VecDeque<i64>>>,
}

impl McpRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn create_agent(
        &self,
        tenant_id: &str,
        sponsor_user_id: &str,
        sponsor_email: &str,
        input: CreateMcpAgentInput,
    ) -> Result<(McpAgent, String), String> {
        let name = input.name.trim();
        if name.is_empty() {
            return Err("agent name is required".to_owned());
        }
        let mut raw_bytes = [0u8; 24];
        fill_csprng(&mut raw_bytes)?;
        let raw_token = format!("oqmcp_{}", hex::encode(raw_bytes));
        let token_hash = hash_mcp_token(&raw_token);

        let now = now_unix_secs();
        let ttl = input.ttl_secs.clamp(300, 30 * 86_400);
        let allowed_tools = if input.allowed_tools.is_empty() {
            vec![
                "operquay.instances.list".to_owned(),
                "operquay.db.query".to_owned(),
                "operquay.k8s.pods".to_owned(),
                "operquay.aws.topology_summary".to_owned(),
            ]
        } else {
            input.allowed_tools
        };

        let agent = McpAgent {
            id: format!("mcp-{}", Uuid::new_v4()),
            tenant_id: tenant_id.to_owned(),
            name: name.to_owned(),
            sponsor_user_id: sponsor_user_id.to_owned(),
            sponsor_email: sponsor_email.to_owned(),
            token_hash,
            allowed_tools,
            require_jit_tools: input.require_jit_tools,
            rate_limit_per_min: input.rate_limit_per_min.clamp(1, 600),
            status: "active".to_owned(),
            expires_at: now.saturating_add(ttl),
            created_at: now,
            revoked_at: None,
        };
        self.agents
            .write()
            .await
            .insert(agent.id.clone(), agent.clone());
        Ok((agent, raw_token))
    }

    pub async fn authenticate_token(&self, tenant_id: &str, bearer: &str) -> Option<McpAgent> {
        let candidate_hash = hash_mcp_token(bearer.trim());
        let now = now_unix_secs();
        self.agents
            .read()
            .await
            .values()
            .find(|a| {
                a.tenant_id == tenant_id
                    && a.status == "active"
                    && a.revoked_at.is_none()
                    && a.expires_at > now
                    && constant_time_eq(a.token_hash.as_bytes(), candidate_hash.as_bytes())
            })
            .cloned()
    }

    pub async fn check_and_consume_rate_limit(&self, agent: &McpAgent) -> bool {
        let now = now_unix_secs();
        let mut guard = self.rate_windows.write().await;
        let win = guard.entry(agent.id.clone()).or_default();
        while win.front().is_some_and(|ts| *ts <= now - 60) {
            win.pop_front();
        }
        if win.len() >= usize::try_from(agent.rate_limit_per_min).unwrap_or(60) {
            return false;
        }
        win.push_back(now);
        true
    }

    pub async fn revoke_agent(&self, tenant_id: &str, id: &str) -> Option<McpAgent> {
        let mut guard = self.agents.write().await;
        let agent = guard.get_mut(id).filter(|a| a.tenant_id == tenant_id)?;
        "revoked".clone_into(&mut agent.status);
        agent.revoked_at = Some(now_unix_secs());
        Some(agent.clone())
    }

    pub async fn list_agents(&self, tenant_id: &str) -> Vec<PublicMcpAgent> {
        let mut out: Vec<_> = self
            .agents
            .read()
            .await
            .values()
            .filter(|a| a.tenant_id == tenant_id)
            .map(PublicMcpAgent::from)
            .collect();
        out.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        out
    }

    pub async fn all_agents_in_tenant(&self, tenant_id: &str) -> Vec<McpAgent> {
        self.agents
            .read()
            .await
            .values()
            .filter(|a| a.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    pub async fn hydrate_agents(&self, items: Vec<McpAgent>) {
        let mut guard = self.agents.write().await;
        for a in items {
            guard.insert(a.id.clone(), a);
        }
    }

    pub async fn record_invocation(&self, inv: McpToolInvocation) {
        let mut guard = self.invocations.write().await;
        guard.push(inv);
        if guard.len() > 2000 {
            let drain = guard.len() - 2000;
            guard.drain(..drain);
        }
    }

    pub async fn list_invocations(&self, tenant_id: &str) -> Vec<McpToolInvocation> {
        let mut out: Vec<_> = self
            .invocations
            .read()
            .await
            .iter()
            .filter(|i| i.tenant_id == tenant_id)
            .cloned()
            .collect();
        out.sort_by_key(|i| std::cmp::Reverse(i.created_at));
        out
    }

    pub async fn hydrate_invocations(&self, items: Vec<McpToolInvocation>) {
        let mut guard = self.invocations.write().await;
        *guard = items;
    }
}

#[must_use]
pub fn mcp_tools_catalog(agent: &McpAgent) -> Vec<serde_json::Value> {
    let all = [
        (
            "operquay.instances.list",
            "List discovered EC2 & multi-cloud instances for the tenant.",
            serde_json::json!({ "type": "object", "properties": {} }),
        ),
        (
            "operquay.db.query",
            "Execute a read-only SQL query with automatic inline PII/secret DLP redaction.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "connection_id": { "type": "string" },
                    "sql": { "type": "string" }
                },
                "required": ["connection_id", "sql"]
            }),
        ),
        (
            "operquay.db.mutate",
            "Execute a controlled database write (subject to JIT human-in-the-loop approval).",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "connection_id": { "type": "string" },
                    "sql": { "type": "string" }
                },
                "required": ["connection_id", "sql"]
            }),
        ),
        (
            "operquay.k8s.pods",
            "List Kubernetes pods in a connected cluster namespace.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "cluster": { "type": "string" },
                    "namespace": { "type": "string" }
                },
                "required": ["cluster"]
            }),
        ),
        (
            "operquay.aws.topology_summary",
            "Return access graph blast-radius summary and findings for the tenant.",
            serde_json::json!({ "type": "object", "properties": {} }),
        ),
    ];

    all.into_iter()
        .filter(|(name, _, _)| {
            agent.allowed_tools.iter().any(|t| t == "*" || t == name)
                || agent.require_jit_tools.iter().any(|t| t == name)
        })
        .map(|(name, desc, schema)| {
            serde_json::json!({
                "name": name,
                "description": desc,
                "inputSchema": schema,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mints_tokens_enforces_rate_limits_and_revokes_agents() {
        let reg = McpRegistry::new();
        let (agent, raw_tok) = reg
            .create_agent(
                "default",
                "u-sponsor",
                "sponsor@acme.io",
                CreateMcpAgentInput {
                    name: "claude-desktop".into(),
                    allowed_tools: vec!["operquay.db.query".into()],
                    require_jit_tools: vec!["operquay.db.mutate".into()],
                    rate_limit_per_min: 2,
                    ttl_secs: 3600,
                },
            )
            .await
            .unwrap();
        assert!(raw_tok.starts_with("oqmcp_"));
        assert_eq!(mcp_tools_catalog(&agent).len(), 2);

        let authed = reg.authenticate_token("default", &raw_tok).await.unwrap();
        assert_eq!(authed.sponsor_user_id, "u-sponsor");
        assert!(reg
            .authenticate_token("other-tenant", &raw_tok)
            .await
            .is_none());

        assert!(reg.check_and_consume_rate_limit(&authed).await);
        assert!(reg.check_and_consume_rate_limit(&authed).await);
        assert!(!reg.check_and_consume_rate_limit(&authed).await);

        let _ = reg.revoke_agent("default", &agent.id).await.unwrap();
        assert!(reg.authenticate_token("default", &raw_tok).await.is_none());
    }
}
