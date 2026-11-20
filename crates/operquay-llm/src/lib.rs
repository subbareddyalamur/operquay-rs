#![forbid(unsafe_code)]

//! Multi-provider AI Gateway (`Bedrock`, `Anthropic`, `OpenAI`, `Gemini`, `Ollama`)
//! with PII redaction, destructive command guardrails, shared AI model catalog,
//! and unified streaming/non-streaming chat completion.

pub mod safety;

use std::collections::HashMap;
use std::time::Duration;

use operquay_aws::sigv4::{sign_request, AwsCredentials};
pub use safety::{SafetyGuard, SessionRiskAnalysis, SessionRiskBookmarkDraft};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmProviderKind {
    #[default]
    Bedrock,
    Anthropic,
    Openai,
    Gemini,
    Ollama,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiCatalogModel {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub provider: LlmProviderKind,
    #[serde(default)]
    pub model_id: String,
    #[serde(default)]
    pub endpoint_url: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub enabled: bool,
}

impl AiCatalogModel {
    pub fn normalize(&mut self, default_provider: LlmProviderKind) {
        if self.name.is_empty() && !self.label.is_empty() {
            self.name.clone_from(&self.label);
        }
        if self.label.is_empty() {
            self.label = if self.name.is_empty() {
                self.id.clone()
            } else {
                self.name.clone()
            };
        }
        if self.name.is_empty() {
            self.name.clone_from(&self.label);
        }
        if self.model_id.is_empty() {
            self.model_id.clone_from(&self.id);
        }
        if self.provider == LlmProviderKind::default()
            && default_provider != LlmProviderKind::default()
        {
            self.provider = default_provider;
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SharedAiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub account_id: String,
    #[serde(default)]
    pub account_label: String,
    #[serde(default)]
    pub binding_id: String,
    #[serde(default)]
    pub endpoint_url: String,
    #[serde(default, skip_serializing)]
    pub base_url: String,
    #[serde(default, skip_serializing)]
    pub api_key: String,
    #[serde(default)]
    pub models: Vec<AiCatalogModel>,
}

impl SharedAiConfig {
    #[must_use]
    pub fn to_public_json(&self) -> serde_json::Value {
        let configured = self.enabled
            && (!self.models.is_empty()
                || !self.model.trim().is_empty()
                || !self.provider.trim().is_empty());
        let has_key = !self.api_key.is_empty();
        serde_json::json!({
            "configured": configured,
            "enabled": self.enabled,
            "provider": if self.provider.is_empty() { "bedrock" } else { &self.provider },
            "model": self.model,
            "region": if self.region.is_empty() { "us-east-1" } else { &self.region },
            "account_id": self.account_id,
            "account_label": self.account_label,
            "binding_id": self.binding_id,
            "endpoint_url": self.endpoint_url,
            "base_url": self.endpoint_url,
            "has_api_key": has_key,
            "key_configured": has_key,
            "models": self.models,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub provider: LlmProviderKind,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub endpoint_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub system: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
}

const fn default_max_tokens() -> u32 {
    1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub reply: String,
    #[serde(default)]
    pub proposed_commands: Vec<CommandProposal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandProposal {
    pub command: String,
    pub blocked: bool,
    pub reason: String,
}

pub struct LlmGateway {
    safety: SafetyGuard,
    catalog: RwLock<HashMap<String, Vec<AiCatalogModel>>>,
    shared: RwLock<HashMap<String, SharedAiConfig>>,
    http: reqwest::Client,
}

impl Default for LlmGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl LlmGateway {
    #[must_use]
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap_or_default();
        Self {
            safety: SafetyGuard::new(),
            catalog: RwLock::new(HashMap::new()),
            shared: RwLock::new(HashMap::new()),
            http,
        }
    }

    #[must_use]
    pub const fn safety(&self) -> &SafetyGuard {
        &self.safety
    }

    /// Analyze a session recording (`.cast` or plain transcript) using PII-sanitized heuristics
    /// first and optional LLM enrichment when an AI provider is enabled for `tenant_id` (`M11.2`).
    pub async fn analyze_session_risk_bookmarks(
        &self,
        tenant_id: &str,
        raw_transcript: &str,
        aws_creds: Option<&AwsCredentials>,
    ) -> SessionRiskAnalysis {
        let mut analysis = self.safety.extract_session_risk_bookmarks(raw_transcript);
        let cfg = self.get_shared_config(tenant_id).await;
        if !cfg.enabled {
            return analysis;
        }
        let Some(provider_kind) =
            parse_provider_kind(&cfg.provider).or_else(|| cfg.models.first().map(|m| m.provider))
        else {
            return analysis;
        };
        let model = if !cfg.model.trim().is_empty() {
            cfg.model.clone()
        } else if let Some(m) = cfg.models.first() {
            if m.model_id.is_empty() {
                m.id.clone()
            } else {
                m.model_id.clone()
            }
        } else {
            return analysis;
        };

        let sanitized_excerpt: String = self
            .safety
            .redact_pii(raw_transcript)
            .chars()
            .take(8192)
            .collect();
        let prompt = format!(
            "Review the following PII-sanitized terminal recording excerpt and respond ONLY with JSON \
             matching {{\"summary\":\"...\",\"bookmarks\":[{{\"offset_secs\":0.0,\"severity\":\"medium|high|critical\",\
             \"category\":\"...\",\"title\":\"...\",\"detail\":\"...\"}}]}}.\n\n{sanitized_excerpt}"
        );
        let req = ChatRequest {
            provider: provider_kind,
            model,
            endpoint_url: cfg.endpoint_url,
            api_key: cfg.api_key,
            region: cfg.region,
            system: "You are a SOC 2 security session reviewer. Summarize risk events concisely without inventing secrets.".to_owned(),
            messages: vec![ChatMessage {
                role: "user".to_owned(),
                content: prompt,
            }],
            max_tokens: 768,
        };
        if let Ok(resp) = self.chat(&req, aws_creds).await {
            let trimmed = resp.reply.trim();
            let json_slice = trimmed
                .strip_prefix("```json")
                .or_else(|| trimmed.strip_prefix("```"))
                .and_then(|s| s.strip_suffix("```"))
                .unwrap_or(trimmed)
                .trim();
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_slice) {
                if let Some(summary) = val["summary"].as_str().filter(|s| !s.trim().is_empty()) {
                    analysis.summary = self.safety.redact_pii(summary.trim());
                }
                if let Some(items) = val["bookmarks"].as_array() {
                    for item in items.iter().take(25) {
                        let title = item["title"].as_str().unwrap_or("").trim();
                        if title.is_empty() {
                            continue;
                        }
                        let bm = SessionRiskBookmarkDraft {
                            offset_secs: item["offset_secs"].as_f64().unwrap_or(0.0),
                            severity: item["severity"].as_str().unwrap_or("medium").to_owned(),
                            category: item["category"].as_str().unwrap_or("ai_review").to_owned(),
                            title: self.safety.redact_pii(title),
                            detail: self
                                .safety
                                .redact_pii(item["detail"].as_str().unwrap_or("")),
                            source: "llm".to_owned(),
                        };
                        analysis.bookmarks.push(bm);
                    }
                }
            }
        }
        analysis
    }

    pub async fn get_catalog(&self, tenant_id: &str) -> Vec<AiCatalogModel> {
        let existing = self.catalog.read().await.get(tenant_id).cloned();
        existing.unwrap_or_else(default_catalog_models)
    }

    pub async fn set_catalog(
        &self,
        tenant_id: &str,
        mut models: Vec<AiCatalogModel>,
    ) -> Vec<AiCatalogModel> {
        for m in &mut models {
            m.normalize(LlmProviderKind::Bedrock);
        }
        self.catalog
            .write()
            .await
            .insert(tenant_id.to_owned(), models.clone());
        let mut s = self.shared.write().await;
        let entry = s.entry(tenant_id.to_owned()).or_default();
        entry.models.clone_from(&models);
        entry.enabled = !models.is_empty();
        models
    }

    pub async fn get_shared_config(&self, tenant_id: &str) -> SharedAiConfig {
        let guard = self.shared.read().await;
        if let Some(cfg) = guard.get(tenant_id) {
            return cfg.clone();
        }
        drop(guard);
        let models = self
            .catalog
            .read()
            .await
            .get(tenant_id)
            .cloned()
            .unwrap_or_default();
        SharedAiConfig {
            enabled: !models.is_empty(),
            models,
            ..SharedAiConfig::default()
        }
    }

    pub async fn set_shared_config(
        &self,
        tenant_id: &str,
        mut next: SharedAiConfig,
    ) -> SharedAiConfig {
        if next.endpoint_url.trim().is_empty() && !next.base_url.trim().is_empty() {
            next.endpoint_url = next.base_url.trim().to_owned();
        }
        next.base_url.clear();
        let prov_kind = parse_provider_kind(&next.provider).unwrap_or(LlmProviderKind::Bedrock);
        for m in &mut next.models {
            m.normalize(prov_kind);
        }
        if next.api_key.is_empty() {
            if let Some(prev) = self.shared.read().await.get(tenant_id) {
                next.api_key.clone_from(&prev.api_key);
            }
        }
        if !next.models.is_empty() {
            self.catalog
                .write()
                .await
                .insert(tenant_id.to_owned(), next.models.clone());
        }
        self.shared
            .write()
            .await
            .insert(tenant_id.to_owned(), next.clone());
        next
    }

    pub async fn discover_models(
        &self,
        provider: &str,
        api_key: &str,
        endpoint_url: &str,
        region: &str,
        aws_creds: Option<&AwsCredentials>,
    ) -> Result<(Vec<AiCatalogModel>, bool), String> {
        let prov = provider.trim().to_ascii_lowercase();
        let reg = if region.trim().is_empty() {
            "us-east-1"
        } else {
            region.trim()
        };
        match prov.as_str() {
            "openai" => {
                if api_key.trim().is_empty() {
                    return Err("OpenAI API key is required".into());
                }
                let base = if endpoint_url.trim().is_empty() {
                    "https://api.openai.com/v1"
                } else {
                    endpoint_url.trim().trim_end_matches('/')
                };
                let url = if base.ends_with("/models") {
                    base.to_owned()
                } else {
                    format!("{base}/models")
                };
                let val: serde_json::Value = self
                    .http
                    .get(&url)
                    .bearer_auth(api_key.trim())
                    .send()
                    .await
                    .map_err(|e| format!("OpenAI models error: {e}"))?
                    .error_for_status()
                    .map_err(|e| format!("OpenAI models HTTP error: {e}"))?
                    .json()
                    .await
                    .map_err(|e| format!("OpenAI models JSON error: {e}"))?;
                let mut models: Vec<AiCatalogModel> =
                    val["data"].as_array().map_or_default(|arr| {
                        arr.iter()
                            .filter_map(|item| item["id"].as_str())
                            .map(|id| AiCatalogModel {
                                id: id.to_owned(),
                                name: id.to_owned(),
                                label: id.to_owned(),
                                provider: LlmProviderKind::Openai,
                                model_id: id.to_owned(),
                                endpoint_url: endpoint_url.to_owned(),
                                region: String::new(),
                                enabled: true,
                            })
                            .collect()
                    });
                models.sort_by(|a, b| a.id.cmp(&b.id));
                Ok((models, false))
            }
            "anthropic" => {
                if api_key.trim().is_empty() {
                    return Err("Anthropic API key is required".into());
                }
                let base = if endpoint_url.trim().is_empty() {
                    "https://api.anthropic.com/v1"
                } else {
                    endpoint_url.trim().trim_end_matches('/')
                };
                let url = if base.ends_with("/models") {
                    base.to_owned()
                } else {
                    format!("{base}/models")
                };
                let val: serde_json::Value = self
                    .http
                    .get(&url)
                    .header("x-api-key", api_key.trim())
                    .header("anthropic-version", "2023-06-01")
                    .send()
                    .await
                    .map_err(|e| format!("Anthropic models error: {e}"))?
                    .error_for_status()
                    .map_err(|e| format!("Anthropic models HTTP error: {e}"))?
                    .json()
                    .await
                    .map_err(|e| format!("Anthropic models JSON error: {e}"))?;
                let models: Vec<AiCatalogModel> = val["data"].as_array().map_or_default(|arr| {
                    arr.iter()
                        .filter_map(|item| {
                            let id = item["id"].as_str()?;
                            let disp = item["display_name"].as_str().unwrap_or(id);
                            Some(AiCatalogModel {
                                id: id.to_owned(),
                                name: disp.to_owned(),
                                label: disp.to_owned(),
                                provider: LlmProviderKind::Anthropic,
                                model_id: id.to_owned(),
                                endpoint_url: endpoint_url.to_owned(),
                                region: String::new(),
                                enabled: true,
                            })
                        })
                        .collect()
                });
                Ok((models, false))
            }
            "gemini" => {
                if api_key.trim().is_empty() {
                    return Err("Gemini API key is required".into());
                }
                let url = if endpoint_url.trim().is_empty() {
                    "https://generativelanguage.googleapis.com/v1beta/models".to_owned()
                } else {
                    endpoint_url.trim().to_owned()
                };
                let val: serde_json::Value = self
                    .http
                    .get(&url)
                    .header("x-goog-api-key", api_key.trim())
                    .send()
                    .await
                    .map_err(|e| format!("Gemini models error: {e}"))?
                    .error_for_status()
                    .map_err(|e| format!("Gemini models HTTP error: {e}"))?
                    .json()
                    .await
                    .map_err(|e| format!("Gemini models JSON error: {e}"))?;
                let models: Vec<AiCatalogModel> = val["models"].as_array().map_or_default(|arr| {
                    arr.iter()
                        .filter_map(|item| {
                            let raw_name = item["name"].as_str()?;
                            let id = raw_name.strip_prefix("models/").unwrap_or(raw_name);
                            let disp = item["displayName"].as_str().unwrap_or(id);
                            Some(AiCatalogModel {
                                id: id.to_owned(),
                                name: disp.to_owned(),
                                label: disp.to_owned(),
                                provider: LlmProviderKind::Gemini,
                                model_id: id.to_owned(),
                                endpoint_url: endpoint_url.to_owned(),
                                region: String::new(),
                                enabled: true,
                            })
                        })
                        .collect()
                });
                Ok((models, false))
            }
            "ollama" => {
                let base = if endpoint_url.trim().is_empty() {
                    "http://127.0.0.1:11434"
                } else {
                    endpoint_url.trim().trim_end_matches('/')
                };
                let url = format!("{base}/api/tags");
                let val: serde_json::Value = self
                    .http
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| format!("Ollama models error: {e}"))?
                    .error_for_status()
                    .map_err(|e| format!("Ollama models HTTP error: {e}"))?
                    .json()
                    .await
                    .map_err(|e| format!("Ollama models JSON error: {e}"))?;
                let models: Vec<AiCatalogModel> = val["models"].as_array().map_or_default(|arr| {
                    arr.iter()
                        .filter_map(|item| item["name"].as_str())
                        .map(|id| AiCatalogModel {
                            id: id.to_owned(),
                            name: id.to_owned(),
                            label: id.to_owned(),
                            provider: LlmProviderKind::Ollama,
                            model_id: id.to_owned(),
                            endpoint_url: endpoint_url.to_owned(),
                            region: String::new(),
                            enabled: true,
                        })
                        .collect()
                });
                Ok((models, false))
            }
            "bedrock" | "" => {
                let creds = aws_creds.ok_or_else(|| {
                    "AWS credentials are required for Bedrock model discovery".to_owned()
                })?;
                let url = format!(
                    "https://bedrock.{reg}.amazonaws.com/foundation-models?byOutputModality=TEXT"
                );
                let mut headers = reqwest::header::HeaderMap::new();
                sign_request("GET", &url, &mut headers, b"", creds, reg, "bedrock", None)?;
                let val: serde_json::Value = self
                    .http
                    .get(&url)
                    .headers(headers)
                    .send()
                    .await
                    .map_err(|e| format!("Bedrock models error: {e}"))?
                    .error_for_status()
                    .map_err(|e| format!("Bedrock models HTTP error: {e}"))?
                    .json()
                    .await
                    .map_err(|e| format!("Bedrock models JSON error: {e}"))?;
                let models: Vec<AiCatalogModel> =
                    val["modelSummaries"].as_array().map_or_default(|arr| {
                        arr.iter()
                            .filter_map(|item| {
                                let id = item["modelId"].as_str()?;
                                let disp = item["modelName"].as_str().unwrap_or(id);
                                Some(AiCatalogModel {
                                    id: id.to_owned(),
                                    name: disp.to_owned(),
                                    label: disp.to_owned(),
                                    provider: LlmProviderKind::Bedrock,
                                    model_id: id.to_owned(),
                                    endpoint_url: String::new(),
                                    region: reg.to_owned(),
                                    enabled: true,
                                })
                            })
                            .collect()
                    });
                Ok((models, false))
            }
            other => Err(format!("unsupported AI provider '{other}'")),
        }
    }

    pub async fn chat(
        &self,
        req: &ChatRequest,
        aws_creds: Option<&AwsCredentials>,
    ) -> Result<ChatResponse, String> {
        let safe_msgs: Vec<ChatMessage> = req
            .messages
            .iter()
            .map(|m| ChatMessage {
                role: m.role.clone(),
                content: self.safety.redact_pii(&m.content),
            })
            .collect();
        let safe_sys = self.safety.redact_pii(&req.system);

        let reply = match req.provider {
            LlmProviderKind::Openai => self.call_openai(req, &safe_sys, &safe_msgs).await?,
            LlmProviderKind::Anthropic => self.call_anthropic(req, &safe_sys, &safe_msgs).await?,
            LlmProviderKind::Gemini => self.call_gemini(req, &safe_sys, &safe_msgs).await?,
            LlmProviderKind::Ollama => self.call_ollama(req, &safe_sys, &safe_msgs).await?,
            LlmProviderKind::Bedrock => {
                let creds = aws_creds
                    .cloned()
                    .ok_or_else(|| "AWS credentials required for Bedrock".to_owned())?;
                self.call_bedrock(req, &safe_sys, &safe_msgs, &creds)
                    .await?
            }
        };

        let proposed_commands = extract_fenced_commands(&reply)
            .into_iter()
            .map(|cmd| {
                let verdict = self.safety.check_command(&cmd);
                CommandProposal {
                    command: cmd,
                    blocked: verdict.blocked,
                    reason: verdict.reason,
                }
            })
            .collect();

        Ok(ChatResponse {
            reply,
            proposed_commands,
        })
    }

    async fn call_openai(
        &self,
        req: &ChatRequest,
        sys: &str,
        msgs: &[ChatMessage],
    ) -> Result<String, String> {
        let url = if req.endpoint_url.is_empty() {
            "https://api.openai.com/v1/chat/completions".to_owned()
        } else {
            req.endpoint_url.clone()
        };
        let mut all = Vec::with_capacity(msgs.len() + 1);
        if !sys.is_empty() {
            all.push(serde_json::json!({ "role": "system", "content": sys }));
        }
        for m in msgs {
            all.push(serde_json::json!({ "role": m.role, "content": m.content }));
        }
        let val: serde_json::Value = self
            .http
            .post(&url)
            .bearer_auth(&req.api_key)
            .json(&serde_json::json!({
                "model": if req.model.is_empty() { "gpt-4o-mini" } else { &req.model },
                "messages": all,
                "max_tokens": req.max_tokens,
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        Ok(val["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or_default()
            .to_owned())
    }

    async fn call_anthropic(
        &self,
        req: &ChatRequest,
        sys: &str,
        msgs: &[ChatMessage],
    ) -> Result<String, String> {
        let url = if req.endpoint_url.is_empty() {
            "https://api.anthropic.com/v1/messages".to_owned()
        } else {
            req.endpoint_url.clone()
        };
        let val: serde_json::Value = self
            .http
            .post(&url)
            .header("x-api-key", &req.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&serde_json::json!({
                "model": if req.model.is_empty() { "claude-3-5-sonnet-latest" } else { &req.model },
                "max_tokens": req.max_tokens,
                "system": sys,
                "messages": msgs,
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        Ok(val["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_owned())
    }

    async fn call_gemini(
        &self,
        req: &ChatRequest,
        sys: &str,
        msgs: &[ChatMessage],
    ) -> Result<String, String> {
        let model = if req.model.is_empty() {
            "gemini-2.0-flash"
        } else {
            &req.model
        };
        let url = if req.endpoint_url.is_empty() {
            format!(
                "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            )
        } else {
            req.endpoint_url.clone()
        };
        let prompt = msgs
            .iter()
            .map(|m| format!("{}: {}", m.role, m.content))
            .collect::<Vec<_>>()
            .join("\n");
        let val: serde_json::Value = self
            .http
            .post(&url)
            .header("x-goog-api-key", &req.api_key)
            .json(&serde_json::json!({
                "systemInstruction": { "parts": [{ "text": sys }] },
                "contents": [{ "parts": [{ "text": prompt }] }],
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        Ok(val["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_owned())
    }

    async fn call_ollama(
        &self,
        req: &ChatRequest,
        sys: &str,
        msgs: &[ChatMessage],
    ) -> Result<String, String> {
        let url = if req.endpoint_url.is_empty() {
            "http://127.0.0.1:11434/api/chat".to_owned()
        } else {
            req.endpoint_url.clone()
        };
        let mut all = Vec::with_capacity(msgs.len() + 1);
        if !sys.is_empty() {
            all.push(serde_json::json!({ "role": "system", "content": sys }));
        }
        for m in msgs {
            all.push(serde_json::json!({ "role": m.role, "content": m.content }));
        }
        let val: serde_json::Value = self
            .http
            .post(&url)
            .json(&serde_json::json!({
                "model": if req.model.is_empty() { "llama3.2" } else { &req.model },
                "stream": false,
                "messages": all,
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        Ok(val["message"]["content"]
            .as_str()
            .unwrap_or_default()
            .to_owned())
    }

    async fn call_bedrock(
        &self,
        req: &ChatRequest,
        sys: &str,
        msgs: &[ChatMessage],
        creds: &AwsCredentials,
    ) -> Result<String, String> {
        let region = if req.region.is_empty() {
            "us-east-1"
        } else {
            &req.region
        };
        let model = if req.model.is_empty() {
            "anthropic.claude-3-5-sonnet-20241022-v2:0"
        } else {
            &req.model
        };
        let url = if req.endpoint_url.is_empty() {
            format!("https://bedrock-runtime.{region}.amazonaws.com/model/{model}/converse")
        } else {
            req.endpoint_url.clone()
        };
        let converse_msgs: Vec<serde_json::Value> = msgs
            .iter()
            .map(|m| {
                serde_json::json!({
                    "role": if m.role == "assistant" { "assistant" } else { "user" },
                    "content": [{ "text": m.content }],
                })
            })
            .collect();
        let body = serde_json::json!({
            "system": if sys.is_empty() { Vec::<serde_json::Value>::new() } else { vec![serde_json::json!({ "text": sys })] },
            "messages": converse_msgs,
            "inferenceConfig": { "maxTokens": req.max_tokens },
        })
        .to_string();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        sign_request(
            "POST",
            &url,
            &mut headers,
            body.as_bytes(),
            creds,
            region,
            "bedrock",
            None,
        )?;
        let val: serde_json::Value = self
            .http
            .post(&url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        Ok(val["output"]["message"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_owned())
    }
}

#[must_use]
pub fn parse_provider_kind(raw: &str) -> Option<LlmProviderKind> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "bedrock" => Some(LlmProviderKind::Bedrock),
        "anthropic" => Some(LlmProviderKind::Anthropic),
        "openai" => Some(LlmProviderKind::Openai),
        "gemini" => Some(LlmProviderKind::Gemini),
        "ollama" => Some(LlmProviderKind::Ollama),
        _ => None,
    }
}

fn default_catalog_models() -> Vec<AiCatalogModel> {
    vec![
        AiCatalogModel {
            id: "anthropic.claude-3-5-sonnet-20241022-v2:0".into(),
            name: "AWS Bedrock Claude 3.5 Sonnet".into(),
            label: "AWS Bedrock Claude 3.5 Sonnet".into(),
            provider: LlmProviderKind::Bedrock,
            model_id: "anthropic.claude-3-5-sonnet-20241022-v2:0".into(),
            endpoint_url: String::new(),
            region: "us-east-1".into(),
            enabled: true,
        },
        AiCatalogModel {
            id: "gpt-4o-mini".into(),
            name: "OpenAI GPT-4o Mini".into(),
            label: "OpenAI GPT-4o Mini".into(),
            provider: LlmProviderKind::Openai,
            model_id: "gpt-4o-mini".into(),
            endpoint_url: String::new(),
            region: String::new(),
            enabled: true,
        },
        AiCatalogModel {
            id: "llama3.2".into(),
            name: "Ollama Local Llama 3.2".into(),
            label: "Ollama Local Llama 3.2".into(),
            provider: LlmProviderKind::Ollama,
            model_id: "llama3.2".into(),
            endpoint_url: "http://127.0.0.1:11434/api/chat".into(),
            region: String::new(),
            enabled: true,
        },
    ]
}

fn extract_fenced_commands(markdown: &str) -> Vec<String> {
    let mut cmds = Vec::new();
    let mut in_fence = false;
    let mut cur = Vec::new();
    for line in markdown.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            if in_fence {
                let block = cur.join("\n").trim().to_owned();
                if !block.is_empty() {
                    cmds.push(block);
                }
                cur.clear();
            }
            in_fence = !in_fence;
        } else if in_fence {
            cur.push(line);
        }
    }
    cmds
}

#[cfg(test)]
mod tests {
    use axum::routing::post;
    use axum::{Json, Router};
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn blocks_destructive_commands_redacts_secrets_and_proxies_multi_llm() {
        let gw = LlmGateway::new();
        assert!(gw.safety().check_command("echo hi | rm -rf /").blocked);
        assert!(!gw.safety().check_command("kubectl get pods").blocked);
        let cleaned = gw
            .safety()
            .redact_pii("key=AKIAIOSFODNN7EXAMPLE db=postgres://admin:S3cret@db:5432/app");
        assert!(!cleaned.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!cleaned.contains("S3cret"));

        let app = Router::new().route(
            "/chat",
            post(|| async {
                Json(serde_json::json!({
                    "choices": [{
                        "message": { "content": "Check disk:\n```bash\ndf -h\n```\nAnd NEVER run:\n```bash\nrm -rf /tmp/*\n```" }
                    }]
                }))
            }),
        );
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(ln, app).await;
        });

        let resp = gw
            .chat(
                &ChatRequest {
                    provider: LlmProviderKind::Openai,
                    model: "gpt-4o-mini".into(),
                    endpoint_url: format!("http://{addr}/chat"),
                    api_key: "sk-test".into(),
                    region: String::new(),
                    system: "helpful ops".into(),
                    messages: vec![ChatMessage {
                        role: "user".into(),
                        content: "disk?".into(),
                    }],
                    max_tokens: 256,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(resp.proposed_commands.len(), 2);
        assert!(!resp.proposed_commands[0].blocked);
        assert!(resp.proposed_commands[1].blocked);
    }

    #[tokio::test]
    async fn extracts_sanitized_cast_risk_bookmarks_with_exact_offsets() {
        let gw = LlmGateway::new();
        let cast = concat!(
            "{\"version\":2,\"width\":120,\"height\":32}\n",
            "[1.5,\"o\",\"$ sudo cat /etc/shadow\\r\\n\"]\n",
            "[4.25,\"o\",\"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\\r\\n\"]\n",
            "[9.0,\"o\",\"rm -rf /var/lib/data\\r\\n\"]\n",
        );
        let res = gw.analyze_session_risk_bookmarks("acme", cast, None).await;
        assert!(res.risk_score >= 90);
        assert!(res
            .bookmarks
            .iter()
            .any(|b| (b.offset_secs - 1.5).abs() < 0.01 && b.category == "sensitive_file"));
        assert!(res
            .bookmarks
            .iter()
            .any(|b| (b.offset_secs - 4.25).abs() < 0.01
                && b.category == "secret_exposure"
                && !b.detail.contains("AKIAIOSFODNN7EXAMPLE")));
        assert!(res
            .bookmarks
            .iter()
            .any(|b| (b.offset_secs - 9.0).abs() < 0.01 && b.category == "destructive_command"));
    }
}
