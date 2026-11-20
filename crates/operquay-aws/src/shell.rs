#![forbid(unsafe_code)]

//! Live AWS SSM `StartSession` / `ResumeSession` `DataChannel` client,
//! interactive shell resume state store, and transcript exporter (`/export-session`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub use operquay_ssm::{build_open_data_channel_json, encode_ssm_resize, SsmShellChannel};
use operquay_ssm::{connect_ssm_datachannel_stream, open_ssm_shell_channel, SsmVirtualStream};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, RwLock};
use uuid::Uuid;

use crate::sigv4::{now_unix_secs, sign_request, AwsCredentials};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartedSsmSession {
    pub session_id: String,
    pub stream_url: String,
    pub token_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedUserShell {
    pub tenant_id: String,
    pub user_id: String,
    pub session_id: String,
    pub terminal_id: String,
    pub instance_id: String,
    pub region: String,
    pub role_id: String,
    pub ssm_session_id: String,
    pub updated_at: i64,
}

const MAX_TRANSCRIPT_BYTES: usize = 2 * 1024 * 1024;
const MAX_TRANSCRIPT_SESSIONS: usize = 256;

#[derive(Debug, Clone)]
pub struct SessionTranscript {
    pub tenant_id: String,
    pub owner_user_id: String,
    pub session_id: String,
    pub instance_id: String,
    pub data: Vec<u8>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedSessionFile {
    pub id: String,
    pub tenant_id: String,
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
    pub created_at: i64,
}

pub struct SsmShellStore {
    user_shells: RwLock<HashMap<(String, String, String, String), PersistedUserShell>>,
    exports: RwLock<HashMap<String, ExportedSessionFile>>,
    transcripts: RwLock<HashMap<(String, String), SessionTranscript>>,
    http: reqwest::Client,
    ssm_endpoint_override: Option<String>,
}

impl Default for SsmShellStore {
    fn default() -> Self {
        Self::new(None)
    }
}

impl SsmShellStore {
    #[must_use]
    pub fn new(ssm_endpoint_override: Option<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self {
            user_shells: RwLock::new(HashMap::new()),
            exports: RwLock::new(HashMap::new()),
            transcripts: RwLock::new(HashMap::new()),
            http,
            ssm_endpoint_override,
        }
    }

    pub async fn init_session_transcript(
        &self,
        tenant_id: &str,
        owner_user_id: &str,
        session_id: &str,
        instance_id: &str,
    ) {
        if session_id.trim().is_empty() {
            return;
        }
        let mut guard = self.transcripts.write().await;
        if guard.len() >= MAX_TRANSCRIPT_SESSIONS {
            if let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, v)| v.updated_at)
                .map(|(k, _)| k.clone())
            {
                guard.remove(&oldest_key);
            }
        }
        guard.insert(
            (tenant_id.to_owned(), session_id.to_owned()),
            SessionTranscript {
                tenant_id: tenant_id.to_owned(),
                owner_user_id: owner_user_id.to_owned(),
                session_id: session_id.to_owned(),
                instance_id: instance_id.to_owned(),
                data: Vec::with_capacity(16 * 1024),
                updated_at: now_unix_secs(),
            },
        );
    }

    pub async fn append_session_output(&self, tenant_id: &str, session_id: &str, chunk: &[u8]) {
        if chunk.is_empty() || session_id.trim().is_empty() {
            return;
        }
        let mut guard = self.transcripts.write().await;
        let Some(entry) = guard.get_mut(&(tenant_id.to_owned(), session_id.to_owned())) else {
            return;
        };
        if chunk.len() >= MAX_TRANSCRIPT_BYTES {
            entry.data.clear();
            entry
                .data
                .extend_from_slice(&chunk[chunk.len() - MAX_TRANSCRIPT_BYTES..]);
        } else {
            let new_len = entry.data.len() + chunk.len();
            if new_len > MAX_TRANSCRIPT_BYTES {
                let drop = new_len - MAX_TRANSCRIPT_BYTES;
                entry.data.drain(..drop);
            }
            entry.data.extend_from_slice(chunk);
        }
        entry.updated_at = now_unix_secs();
    }

    pub async fn get_session_transcript(
        &self,
        tenant_id: &str,
        owner_user_id: &str,
        session_id: &str,
    ) -> Option<SessionTranscript> {
        let guard = self.transcripts.read().await;
        guard
            .get(&(tenant_id.to_owned(), session_id.to_owned()))
            .filter(|t| {
                t.owner_user_id.is_empty()
                    || owner_user_id.is_empty()
                    || t.owner_user_id == owner_user_id
            })
            .cloned()
    }

    pub async fn save_user_shell(&self, rec: PersistedUserShell) {
        self.user_shells.write().await.insert(
            (
                rec.tenant_id.clone(),
                rec.user_id.clone(),
                rec.session_id.clone(),
                rec.terminal_id.clone(),
            ),
            rec,
        );
    }

    pub async fn lookup_user_shell(
        &self,
        tenant_id: &str,
        user_id: &str,
        session_id: &str,
        terminal_id: &str,
    ) -> Option<PersistedUserShell> {
        self.user_shells
            .read()
            .await
            .get(&(
                tenant_id.to_owned(),
                user_id.to_owned(),
                session_id.to_owned(),
                terminal_id.to_owned(),
            ))
            .cloned()
    }

    pub async fn forget_user_shell(
        &self,
        tenant_id: &str,
        user_id: &str,
        session_id: &str,
        terminal_id: &str,
    ) {
        self.user_shells.write().await.remove(&(
            tenant_id.to_owned(),
            user_id.to_owned(),
            session_id.to_owned(),
            terminal_id.to_owned(),
        ));
    }

    /// Call AWS `ssm:StartSession` (`AmazonSSM.StartSession`) or `ssm:ResumeSession`.
    pub async fn start_or_resume_session(
        &self,
        region: &str,
        target: &str,
        document_name: Option<&str>,
        parameters: Option<serde_json::Value>,
        resume_session_id: Option<&str>,
        creds: &AwsCredentials,
    ) -> Result<StartedSsmSession, String> {
        let url = self
            .ssm_endpoint_override
            .clone()
            .unwrap_or_else(|| format!("https://ssm.{region}.amazonaws.com/"));
        let (target_header, body) = if let Some(sid) = resume_session_id {
            (
                "AmazonSSM.ResumeSession",
                serde_json::json!({ "SessionId": sid }).to_string(),
            )
        } else {
            let mut obj = serde_json::json!({ "Target": target });
            if let Some(doc) = document_name {
                obj["DocumentName"] = serde_json::Value::String(doc.to_owned());
            }
            if let Some(params) = parameters {
                obj["Parameters"] = params;
            }
            ("AmazonSSM.StartSession", obj.to_string())
        };

        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-amz-json-1.1"),
        );
        headers.insert(
            http::HeaderName::from_static("x-amz-target"),
            http::HeaderValue::from_static(target_header),
        );
        sign_request(
            "POST",
            &url,
            &mut headers,
            body.as_bytes(),
            creds,
            region,
            "ssm",
            None,
        )?;
        let resp = self
            .http
            .post(&url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|e| format!("SSM request failed: {e}"))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("SSM response read failed: {e}"))?;
        if !status.is_success() {
            return Err(format!("SSM returned {status}: {text}"));
        }
        let val: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("SSM JSON parse error: {e}"))?;
        Ok(StartedSsmSession {
            session_id: val["SessionId"]
                .as_str()
                .or(resume_session_id)
                .unwrap_or_default()
                .to_owned(),
            stream_url: val["StreamUrl"].as_str().unwrap_or_default().to_owned(),
            token_value: val["TokenValue"].as_str().unwrap_or_default().to_owned(),
        })
    }

    /// Terminate an active AWS SSM session (`AmazonSSM.TerminateSession`).
    pub async fn terminate_session(
        &self,
        region: &str,
        session_id: &str,
        creds: &AwsCredentials,
    ) -> Result<(), String> {
        let url = self
            .ssm_endpoint_override
            .clone()
            .unwrap_or_else(|| format!("https://ssm.{region}.amazonaws.com/"));
        let body = serde_json::json!({ "SessionId": session_id }).to_string();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-amz-json-1.1"),
        );
        headers.insert(
            http::HeaderName::from_static("x-amz-target"),
            http::HeaderValue::from_static("AmazonSSM.TerminateSession"),
        );
        sign_request(
            "POST",
            &url,
            &mut headers,
            body.as_bytes(),
            creds,
            region,
            "ssm",
            None,
        )?;
        let resp = self
            .http
            .post(&url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|e| format!("SSM TerminateSession failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("SSM TerminateSession returned {}", resp.status()));
        }
        Ok(())
    }

    /// Open a live `SigV4` `AWS-StartPortForwardingSession` tunnel returning `(StartedSsmSession, SsmVirtualStream)`
    /// for RDP, VNC, SQL, or Port Forwarder traffic.
    pub async fn connect_port_forward_tunnel(
        &self,
        region: &str,
        instance_id: &str,
        remote_port: u16,
        creds: &AwsCredentials,
        shutdown: Arc<Notify>,
    ) -> Result<(StartedSsmSession, SsmVirtualStream), String> {
        let started = self
            .start_or_resume_session(
                region,
                instance_id,
                Some("AWS-StartPortForwardingSession"),
                Some(serde_json::json!({
                    "portNumber": [remote_port.to_string()]
                })),
                None,
                creds,
            )
            .await?;
        let stream =
            connect_ssm_datachannel_stream(&started.stream_url, &started.token_value, shutdown)
                .await?;
        Ok((started, stream))
    }

    /// Open a live interactive SSM shell `DataChannel` (`StartSession` / `ResumeSession`).
    pub async fn connect_live_shell(
        &self,
        region: &str,
        instance_id: &str,
        resume_session_id: Option<&str>,
        creds: &AwsCredentials,
    ) -> Result<(StartedSsmSession, SsmShellChannel), String> {
        let started = self
            .start_or_resume_session(region, instance_id, None, None, resume_session_id, creds)
            .await?;
        let chan = open_ssm_shell_channel(&started.stream_url, &started.token_value).await?;
        Ok((started, chan))
    }

    pub async fn store_export(
        &self,
        tenant_id: &str,
        instance_id: &str,
        format: &str,
        transcript: &str,
    ) -> ExportedSessionFile {
        let id = Uuid::new_v4().to_string();
        let (ext, ctype, bytes) = match format {
            "json" => (
                "json",
                "application/json; charset=utf-8",
                serde_json::json!({
                    "instance_id": instance_id,
                    "exported_at": now_unix_secs(),
                    "transcript": transcript,
                })
                .to_string()
                .into_bytes(),
            ),
            "cast" => {
                let hdr = serde_json::json!({
                    "version": 2,
                    "width": 120,
                    "height": 32,
                    "timestamp": now_unix_secs(),
                    "title": instance_id,
                })
                .to_string();
                let line = serde_json::json!([0.0_f64, "o", transcript]).to_string();
                (
                    "cast",
                    "application/x-asciicast",
                    format!("{hdr}\n{line}\n").into_bytes(),
                )
            }
            _ => (
                "txt",
                "text/plain; charset=utf-8",
                transcript.as_bytes().to_vec(),
            ),
        };
        let filename = format!("operquay-session-{instance_id}.{ext}");
        let entry = ExportedSessionFile {
            id: id.clone(),
            tenant_id: tenant_id.to_owned(),
            filename,
            content_type: ctype.to_owned(),
            data: bytes,
            created_at: now_unix_secs(),
        };
        self.exports.write().await.insert(id, entry.clone());
        entry
    }

    pub async fn get_export(&self, tenant_id: &str, id: &str) -> Option<ExportedSessionFile> {
        self.exports
            .read()
            .await
            .get(id)
            .filter(|e| e.tenant_id == tenant_id)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn transcripts_ring_buffer_caps_bytes_and_enforces_owner() {
        let store = SsmShellStore::default();
        store
            .init_session_transcript("t1", "alice", "sess-1", "i-1")
            .await;
        store.append_session_output("t1", "sess-1", b"hello ").await;
        store.append_session_output("t1", "sess-1", b"world").await;

        let ok = store
            .get_session_transcript("t1", "alice", "sess-1")
            .await
            .unwrap();
        assert_eq!(ok.data, b"hello world");
        assert!(store
            .get_session_transcript("t1", "bob", "sess-1")
            .await
            .is_none());

        let huge = vec![b'x'; MAX_TRANSCRIPT_BYTES + 128];
        store.append_session_output("t1", "sess-1", &huge).await;
        let capped = store
            .get_session_transcript("t1", "alice", "sess-1")
            .await
            .unwrap();
        assert_eq!(capped.data.len(), MAX_TRANSCRIPT_BYTES);
    }
}
