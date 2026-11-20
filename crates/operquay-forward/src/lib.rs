#![forbid(unsafe_code)]

//! Port Forwarder, Single-Use Pairing Codes, 5-Byte `[kind|id_be]` Stream Multiplexer,
//! and Native `operquay forward` CLI Client (`crates/operquay-forward`).

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};

pub mod cli;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as WsMsg;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MuxFrameKind {
    Open = 1,
    Data = 2,
    Close = 3,
    Heartbeat = 4,
}

impl MuxFrameKind {
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Open),
            2 => Some(Self::Data),
            3 => Some(Self::Close),
            4 => Some(Self::Heartbeat),
            _ => None,
        }
    }
}

/// Encode a 5-byte `[kind | stream_id_be]` multiplexed frame.
#[must_use]
pub fn encode_mux_frame(kind: MuxFrameKind, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(kind as u8);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decode a 5-byte `[kind | stream_id_be]` multiplexed frame.
#[must_use]
pub fn decode_mux_frame(raw: &[u8]) -> Option<(MuxFrameKind, u32, &[u8])> {
    if raw.len() < 5 {
        return None;
    }
    let kind = MuxFrameKind::from_byte(raw[0])?;
    let id = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]);
    Some((kind, id, &raw[5..]))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardTunnel {
    pub id: String,
    pub tenant_id: String,
    pub owner_user_id: String,
    pub instance_id: String,
    #[serde(default)]
    pub instance_name: String,
    #[serde(default)]
    pub binding_id: String,
    pub region: String,
    pub remote_host: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub pairing_code: String,
    pub status: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct PairingEntry {
    pub tunnel: ForwardTunnel,
    pub expires_at: Instant,
}

pub struct ForwardManager {
    tunnels: RwLock<HashMap<String, ForwardTunnel>>,
    pairings: RwLock<HashMap<String, PairingEntry>>,
}

impl Default for ForwardManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ForwardManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tunnels: RwLock::new(HashMap::new()),
            pairings: RwLock::new(HashMap::new()),
        }
    }

    pub async fn start_tunnel(
        &self,
        tenant_id: &str,
        owner_user_id: &str,
        instance_id: &str,
        region: &str,
        remote_host: &str,
        remote_port: u16,
        local_port: u16,
    ) -> ForwardTunnel {
        self.start_tunnel_with_binding(
            tenant_id,
            owner_user_id,
            instance_id,
            "",
            "",
            region,
            remote_host,
            remote_port,
            local_port,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn start_tunnel_with_binding(
        &self,
        tenant_id: &str,
        owner_user_id: &str,
        instance_id: &str,
        instance_name: &str,
        binding_id: &str,
        region: &str,
        remote_host: &str,
        remote_port: u16,
        local_port: u16,
    ) -> ForwardTunnel {
        let id = format!("fwd-{}", Uuid::new_v4());
        let pairing = format!(
            "pair-{}",
            Uuid::new_v4().to_string().split('-').next().unwrap_or("0")
        );
        let tunnel = ForwardTunnel {
            id: id.clone(),
            tenant_id: tenant_id.to_owned(),
            owner_user_id: owner_user_id.to_owned(),
            instance_id: instance_id.to_owned(),
            instance_name: instance_name.to_owned(),
            binding_id: binding_id.to_owned(),
            region: region.to_owned(),
            remote_host: remote_host.to_owned(),
            remote_port,
            local_port,
            pairing_code: pairing.clone(),
            status: "active".to_owned(),
            created_at: now_unix(),
        };
        self.tunnels.write().await.insert(id, tunnel.clone());
        self.pairings.write().await.insert(
            pairing,
            PairingEntry {
                tunnel: tunnel.clone(),
                expires_at: Instant::now() + Duration::from_secs(300),
            },
        );
        tunnel
    }

    pub async fn take_pairing(&self, code: &str) -> Option<ForwardTunnel> {
        let entry = self.pairings.write().await.remove(code)?;
        if Instant::now() > entry.expires_at {
            return None;
        }
        Some(entry.tunnel)
    }

    pub async fn stop_tunnel(&self, tenant_id: &str, id: &str) -> bool {
        let mut guard = self.tunnels.write().await;
        if guard.get(id).is_some_and(|t| t.tenant_id == tenant_id) {
            guard.remove(id).is_some()
        } else {
            false
        }
    }

    pub async fn list_active(&self, tenant_id: &str) -> Vec<ForwardTunnel> {
        self.tunnels
            .read()
            .await
            .values()
            .filter(|t| t.tenant_id == tenant_id)
            .cloned()
            .collect()
    }
}

/// Native CLI TCP-over-WebSocket forwarder (`operquay forward`).
pub async fn run_forward_cli(
    ws_url: &str,
    pairing_code: &str,
    listen_addr: &str,
) -> Result<(), String> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| format!("bind {listen_addr}: {e}"))?;
    tracing::info!(listen = %listen_addr, "operquay forward listening");

    loop {
        let (tcp, _) = listener
            .accept()
            .await
            .map_err(|e| format!("accept error: {e}"))?;
        let url = ws_url.to_owned();
        let code = pairing_code.to_owned();
        tokio::spawn(async move {
            let _ = bridge_single_tcp(tcp, &url, &code).await;
        });
    }
}

async fn bridge_single_tcp(
    mut tcp: TcpStream,
    ws_url: &str,
    pairing_code: &str,
) -> Result<(), String> {
    let (mut ws, _) = connect_async(ws_url)
        .await
        .map_err(|e| format!("ws connect: {e}"))?;
    let handshake = serde_json::json!({ "pairing_code": pairing_code }).to_string();
    ws.send(WsMsg::Text(handshake.into()))
        .await
        .map_err(|e| format!("ws handshake send: {e}"))?;

    let stream_id: u32 = 1;
    let _ = ws
        .send(WsMsg::Binary(
            encode_mux_frame(MuxFrameKind::Open, stream_id, &[]).into(),
        ))
        .await;

    let (mut r_tcp, mut w_tcp) = tcp.split();
    let (mut w_ws, mut r_ws) = ws.split();

    let up = async {
        let mut buf = vec![0u8; 16_384];
        loop {
            let n = r_tcp.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                let _ = w_ws
                    .send(WsMsg::Binary(
                        encode_mux_frame(MuxFrameKind::Close, stream_id, &[]).into(),
                    ))
                    .await;
                break;
            }
            w_ws.send(WsMsg::Binary(
                encode_mux_frame(MuxFrameKind::Data, stream_id, &buf[..n]).into(),
            ))
            .await
            .map_err(|e| e.to_string())?;
        }
        Ok::<(), String>(())
    };

    let down = async {
        while let Some(Ok(msg)) = r_ws.next().await {
            if let WsMsg::Binary(b) = msg {
                if let Some((kind, _, payload)) = decode_mux_frame(&b) {
                    match kind {
                        MuxFrameKind::Data => {
                            w_tcp.write_all(payload).await.map_err(|e| e.to_string())?;
                        }
                        MuxFrameKind::Close => break,
                        _ => {}
                    }
                }
            }
        }
        Ok::<(), String>(())
    };

    let _ = tokio::select! {
        r = up => r,
        r = down => r,
    };
    Ok(())
}

fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn encodes_5byte_mux_frames_and_enforces_single_use_pairing() {
        let frame = encode_mux_frame(MuxFrameKind::Data, 42, b"SELECT 1;");
        assert_eq!(frame.len(), 5 + 9);
        let (kind, sid, body) = decode_mux_frame(&frame).unwrap();
        assert_eq!(kind, MuxFrameKind::Data);
        assert_eq!(sid, 42);
        assert_eq!(body, b"SELECT 1;");

        let mgr = ForwardManager::new();
        let tun = mgr
            .start_tunnel("acme", "u1", "i-1", "us-east-1", "127.0.0.1", 5432, 15432)
            .await;
        assert!(mgr.take_pairing(&tun.pairing_code).await.is_some());
        assert!(mgr.take_pairing(&tun.pairing_code).await.is_none());
        assert!(mgr.stop_tunnel("acme", &tun.id).await);
    }
}
