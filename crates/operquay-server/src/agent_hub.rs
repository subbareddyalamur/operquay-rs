#![forbid(unsafe_code)]

//! Zero-Inbound Hybrid Reverse-Tunnel Agent Registry & Mux Stream Router (`M12.2`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use constant_time_eq::constant_time_eq;
use operquay_auth::crypto::fill_csprng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use uuid::Uuid;

use crate::jit::now_unix_secs;

const TUNNEL_CHANNEL_CAPACITY: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTargetSpec {
    pub protocol: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAgentRecord {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub enrollment_token_hash: String,
    #[serde(default)]
    pub cert_fingerprint_sha256: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub targets: Vec<AgentTargetSpec>,
    pub status: String,
    #[serde(default)]
    pub last_heartbeat_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicHybridAgent {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub cert_fingerprint_sha256: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub labels: HashMap<String, String>,
    pub targets: Vec<AgentTargetSpec>,
    pub status: String,
    pub online: bool,
    pub last_heartbeat_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub enum AgentOutboundFrame {
    ControlJson(String),
    MuxData { stream_id: u32, data: Vec<u8> },
    MuxClose { stream_id: u32 },
}

pub struct LiveTunnelHandle {
    pub agent_id: String,
    pub tenant_id: String,
    out_tx: mpsc::Sender<AgentOutboundFrame>,
    next_stream_id: AtomicU32,
    pending_dials: Mutex<HashMap<u32, oneshot::Sender<Result<(), String>>>>,
    streams: Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>,
}

impl LiveTunnelHandle {
    pub async fn notify_dial_result(&self, stream_id: u32, ok: bool, err: String) {
        if let Some(tx) = self.pending_dials.lock().await.remove(&stream_id) {
            let _ = tx.send(if ok { Ok(()) } else { Err(err) });
        }
    }

    pub async fn forward_data_from_agent(&self, stream_id: u32, payload: Vec<u8>) {
        if let Some(tx) = self.streams.lock().await.get(&stream_id).cloned() {
            let _ = tx.send(payload).await;
        }
    }

    pub async fn close_stream_from_agent(&self, stream_id: u32) {
        self.streams.lock().await.remove(&stream_id);
    }

    pub fn send_data_to_agent(&self, stream_id: u32, data: Vec<u8>) -> Result<(), String> {
        self.out_tx
            .try_send(AgentOutboundFrame::MuxData { stream_id, data })
            .map_err(|e| format!("agent outbound queue saturated/closed: {e}"))
    }

    pub fn send_close_to_agent(&self, stream_id: u32) {
        let _ = self
            .out_tx
            .try_send(AgentOutboundFrame::MuxClose { stream_id });
    }
}

#[must_use]
pub fn hash_agent_token(raw: &str) -> String {
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}

#[derive(Default)]
pub struct AgentHub {
    agents: RwLock<HashMap<String, HybridAgentRecord>>,
    live: RwLock<HashMap<(String, String), Arc<LiveTunnelHandle>>>,
}

impl AgentHub {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn enroll_agent(
        &self,
        tenant_id: &str,
        name: &str,
        labels: HashMap<String, String>,
        targets: Vec<AgentTargetSpec>,
    ) -> Result<(HybridAgentRecord, String), String> {
        let clean = name.trim();
        if clean.is_empty() {
            return Err("agent name is required".to_owned());
        }
        let mut raw_bytes = [0u8; 24];
        fill_csprng(&mut raw_bytes)?;
        let raw_token = format!("oqag_{}", hex::encode(raw_bytes));
        let rec = HybridAgentRecord {
            id: format!("agt-{}", Uuid::new_v4()),
            tenant_id: tenant_id.to_owned(),
            name: clean.to_owned(),
            enrollment_token_hash: hash_agent_token(&raw_token),
            cert_fingerprint_sha256: String::new(),
            hostname: String::new(),
            os: String::new(),
            arch: String::new(),
            labels,
            targets,
            status: "enrolled".to_owned(),
            last_heartbeat_at: None,
            created_at: now_unix_secs(),
        };
        self.agents
            .write()
            .await
            .insert(rec.id.clone(), rec.clone());
        Ok((rec, raw_token))
    }

    pub async fn authenticate_token(
        &self,
        tenant_id: &str,
        raw_token: &str,
    ) -> Option<HybridAgentRecord> {
        let candidate = hash_agent_token(raw_token.trim());
        self.agents
            .read()
            .await
            .values()
            .find(|a| {
                a.tenant_id == tenant_id
                    && constant_time_eq(a.enrollment_token_hash.as_bytes(), candidate.as_bytes())
            })
            .cloned()
    }

    pub async fn mark_registered(
        &self,
        tenant_id: &str,
        agent_id: &str,
        hostname: String,
        os: String,
        arch: String,
        fingerprint: String,
        labels: HashMap<String, String>,
        targets: Vec<AgentTargetSpec>,
    ) -> Result<
        (
            HybridAgentRecord,
            Arc<LiveTunnelHandle>,
            mpsc::Receiver<AgentOutboundFrame>,
        ),
        String,
    > {
        let mut guard = self.agents.write().await;
        let rec = guard
            .get_mut(agent_id)
            .filter(|a| a.tenant_id == tenant_id)
            .ok_or_else(|| "agent not found".to_owned())?;
        if !hostname.trim().is_empty() {
            rec.hostname = hostname;
        }
        if !os.trim().is_empty() {
            rec.os = os;
        }
        if !arch.trim().is_empty() {
            rec.arch = arch;
        }
        if !fingerprint.trim().is_empty() {
            rec.cert_fingerprint_sha256 = fingerprint;
        }
        if !labels.is_empty() {
            rec.labels = labels;
        }
        if !targets.is_empty() {
            rec.targets = targets;
        }
        "online".clone_into(&mut rec.status);
        rec.last_heartbeat_at = Some(now_unix_secs());
        let saved = rec.clone();
        drop(guard);

        let (out_tx, out_rx) = mpsc::channel(TUNNEL_CHANNEL_CAPACITY);
        let handle = Arc::new(LiveTunnelHandle {
            agent_id: agent_id.to_owned(),
            tenant_id: tenant_id.to_owned(),
            out_tx,
            next_stream_id: AtomicU32::new(1),
            pending_dials: Mutex::new(HashMap::new()),
            streams: Mutex::new(HashMap::new()),
        });
        self.live.write().await.insert(
            (tenant_id.to_owned(), agent_id.to_owned()),
            Arc::clone(&handle),
        );
        Ok((saved, handle, out_rx))
    }

    pub async fn touch_heartbeat(&self, tenant_id: &str, agent_id: &str) {
        if let Some(rec) = self
            .agents
            .write()
            .await
            .get_mut(agent_id)
            .filter(|a| a.tenant_id == tenant_id)
        {
            rec.last_heartbeat_at = Some(now_unix_secs());
            "online".clone_into(&mut rec.status);
        }
    }

    pub async fn mark_offline(&self, tenant_id: &str, agent_id: &str) {
        self.live
            .write()
            .await
            .remove(&(tenant_id.to_owned(), agent_id.to_owned()));
        if let Some(rec) = self
            .agents
            .write()
            .await
            .get_mut(agent_id)
            .filter(|a| a.tenant_id == tenant_id)
        {
            "offline".clone_into(&mut rec.status);
        }
    }

    pub async fn dial_through_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
        target: &str,
    ) -> Result<(u32, mpsc::Receiver<Vec<u8>>, Arc<LiveTunnelHandle>), String> {
        let handle = self
            .live
            .read()
            .await
            .get(&(tenant_id.to_owned(), agent_id.to_owned()))
            .cloned()
            .ok_or_else(|| "hybrid agent tunnel is offline".to_owned())?;
        let stream_id = handle.next_stream_id.fetch_add(1, Ordering::Relaxed).max(1);
        let (dial_tx, dial_rx) = oneshot::channel();
        let (data_tx, data_rx) = mpsc::channel(TUNNEL_CHANNEL_CAPACITY);
        handle.pending_dials.lock().await.insert(stream_id, dial_tx);
        handle.streams.lock().await.insert(stream_id, data_tx);

        let msg = serde_json::json!({
            "type": "dial",
            "stream_id": stream_id,
            "target": target.trim(),
        })
        .to_string();
        if let Err(err) = handle.out_tx.try_send(AgentOutboundFrame::ControlJson(msg)) {
            handle.pending_dials.lock().await.remove(&stream_id);
            handle.streams.lock().await.remove(&stream_id);
            return Err(format!("failed queuing agent dial frame: {err}"));
        }

        match tokio::time::timeout(Duration::from_secs(5), dial_rx).await {
            Ok(Ok(Ok(()))) => Ok((stream_id, data_rx, handle)),
            Ok(Ok(Err(err))) => {
                handle.streams.lock().await.remove(&stream_id);
                Err(err)
            }
            _ => {
                handle.pending_dials.lock().await.remove(&stream_id);
                handle.streams.lock().await.remove(&stream_id);
                Err("agent dial timed out waiting for tunnel ACK".to_owned())
            }
        }
    }

    pub async fn list_agents(&self, tenant_id: &str) -> Vec<PublicHybridAgent> {
        let live_guard = self.live.read().await;
        let mut out: Vec<_> = self
            .agents
            .read()
            .await
            .values()
            .filter(|a| a.tenant_id == tenant_id)
            .map(|a| {
                let online = live_guard.contains_key(&(a.tenant_id.clone(), a.id.clone()));
                PublicHybridAgent {
                    id: a.id.clone(),
                    tenant_id: a.tenant_id.clone(),
                    name: a.name.clone(),
                    cert_fingerprint_sha256: a.cert_fingerprint_sha256.clone(),
                    hostname: a.hostname.clone(),
                    os: a.os.clone(),
                    arch: a.arch.clone(),
                    labels: a.labels.clone(),
                    targets: a.targets.clone(),
                    status: if online {
                        "online".to_owned()
                    } else {
                        a.status.clone()
                    },
                    online,
                    last_heartbeat_at: a.last_heartbeat_at,
                    created_at: a.created_at,
                }
            })
            .collect();
        out.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        out
    }

    pub async fn delete_agent(&self, tenant_id: &str, id: &str) -> bool {
        self.live
            .write()
            .await
            .remove(&(tenant_id.to_owned(), id.to_owned()));
        let mut guard = self.agents.write().await;
        if guard.get(id).is_some_and(|a| a.tenant_id == tenant_id) {
            guard.remove(id).is_some()
        } else {
            false
        }
    }

    pub async fn hydrate_agents(&self, items: Vec<HybridAgentRecord>) {
        let mut guard = self.agents.write().await;
        for mut a in items {
            if a.status == "online" {
                "offline".clone_into(&mut a.status);
            }
            guard.insert(a.id.clone(), a);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enrolls_authenticates_and_tracks_live_tunnel_status() {
        let hub = AgentHub::new();
        let (rec, tok) = hub
            .enroll_agent(
                "default",
                "dc-01-bastion",
                HashMap::new(),
                vec![AgentTargetSpec {
                    protocol: "ssh".into(),
                    host: "10.20.0.5".into(),
                    port: 22,
                }],
            )
            .await
            .unwrap();
        assert!(tok.starts_with("oqag_"));
        assert_eq!(
            hub.authenticate_token("default", &tok).await.unwrap().id,
            rec.id
        );

        let (_saved, handle, _rx) = hub
            .mark_registered(
                "default",
                &rec.id,
                "dc-host".into(),
                "linux".into(),
                "amd64".into(),
                "deadbeef".into(),
                HashMap::new(),
                Vec::new(),
            )
            .await
            .unwrap();
        assert!(hub.list_agents("default").await[0].online);
        handle.notify_dial_result(999, true, String::new()).await;
        hub.mark_offline("default", &rec.id).await;
        assert!(!hub.list_agents("default").await[0].online);
    }
}
