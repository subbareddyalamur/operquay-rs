#![forbid(unsafe_code)]

//! Lightweight Zero-Inbound Hybrid Reverse-Tunnel Agent (`operquay-agent`, `M12.2`).
//!
//! Connects strictly outbound over WebSocket / mTLS 1.3 to the Operquay control plane and
//! multiplexes approved local TCP targets (on-prem SSH, RDP, PostgreSQL/MySQL, Kubernetes API)
//! using the 5-byte `operquay-forward` frame protocol and bounded channels.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use http::HeaderValue;
use operquay_forward::{decode_mux_frame, encode_mux_frame, MuxFrameKind};
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as WsMsg;
use tokio_tungstenite::{connect_async_tls_with_config, Connector};

const AGENT_FRAME_CHANNEL: usize = 256;
const HEARTBEAT_SECS: u64 = 15;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTargetConfig {
    pub protocol: String,
    pub host: String,
    pub port: u16,
}

impl AgentTargetConfig {
    #[must_use]
    pub fn addr_key(&self) -> String {
        format!("{}:{}", self.host.trim(), self.port)
    }
}

pub fn parse_target_spec(raw: &str) -> Result<AgentTargetConfig, String> {
    let trimmed = raw.trim();
    let parts: Vec<&str> = trimmed.split(':').collect();
    if parts.len() != 3 {
        return Err(format!(
            "invalid target '{raw}': expected <protocol>:<host>:<port>"
        ));
    }
    let protocol = parts[0].trim().to_ascii_lowercase();
    let host = parts[1].trim().to_owned();
    let port: u16 = parts[2]
        .trim()
        .parse()
        .map_err(|_| format!("invalid port in target '{raw}'"))?;
    if protocol.is_empty() || host.is_empty() || port == 0 {
        return Err(format!("invalid target specification '{raw}'"));
    }
    Ok(AgentTargetConfig {
        protocol,
        host,
        port,
    })
}

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub server_url: String,
    pub enrollment_token: String,
    pub name: String,
    pub hostname: String,
    pub labels: HashMap<String, String>,
    pub targets: Vec<AgentTargetConfig>,
    pub ca_cert_path: Option<PathBuf>,
    pub client_cert_path: Option<PathBuf>,
    pub client_key_path: Option<PathBuf>,
}

fn decode_pem_certificates(pem: &str) -> Vec<Vec<u8>> {
    use base64_or_pem::decode_blocks;
    decode_blocks(pem, "CERTIFICATE")
}

mod base64_or_pem {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn decode_blocks(pem: &str, label: &str) -> Vec<Vec<u8>> {
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let mut out = Vec::new();
        let mut rest = pem;
        while let Some(s) = rest.find(&begin) {
            let after = &rest[s + begin.len()..];
            let Some(e) = after.find(&end) else {
                break;
            };
            let body: String = after[..e]
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect();
            if let Ok(bytes) = decode_b64(&body) {
                out.push(bytes);
            }
            rest = &after[e + end.len()..];
        }
        out
    }

    fn decode_b64(input: &str) -> Result<Vec<u8>, ()> {
        let mut rev = [255u8; 128];
        for (idx, &ch) in TABLE.iter().enumerate() {
            rev[usize::from(ch)] = u8::try_from(idx).unwrap_or(255);
        }
        let mut out = Vec::with_capacity((input.len() * 3) / 4);
        let bytes = input.as_bytes();
        let mut chunk = [0u8; 4];
        let mut i = 0usize;
        while i < bytes.len() {
            let rem = bytes.len() - i;
            if rem < 4 {
                return Err(());
            }
            chunk.copy_from_slice(&bytes[i..i + 4]);
            let v0 = rev.get(usize::from(chunk[0])).copied().unwrap_or(255);
            let v1 = rev.get(usize::from(chunk[1])).copied().unwrap_or(255);
            if v0 == 255 || v1 == 255 {
                return Err(());
            }
            let p2 = chunk[2] == b'=';
            let p3 = chunk[3] == b'=';
            let v2 = if p2 {
                0
            } else {
                rev.get(usize::from(chunk[2])).copied().unwrap_or(255)
            };
            let v3 = if p3 {
                0
            } else {
                rev.get(usize::from(chunk[3])).copied().unwrap_or(255)
            };
            if v2 == 255 || v3 == 255 {
                return Err(());
            }
            let n = (u32::from(v0) << 18)
                | (u32::from(v1) << 12)
                | (u32::from(v2) << 6)
                | u32::from(v3);
            out.push(((n >> 16) & 0xff) as u8);
            if !p2 {
                out.push(((n >> 8) & 0xff) as u8);
            }
            if !p3 {
                out.push((n & 0xff) as u8);
            }
            i += 4;
        }
        Ok(out)
    }
}

fn load_private_key(pem: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    if let Some(der) = base64_or_pem::decode_blocks(pem, "PRIVATE KEY")
        .into_iter()
        .next()
    {
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(der.into()));
    }
    if let Some(der) = base64_or_pem::decode_blocks(pem, "EC PRIVATE KEY")
        .into_iter()
        .next()
    {
        return Ok(rustls::pki_types::PrivateKeyDer::Sec1(der.into()));
    }
    if let Some(der) = base64_or_pem::decode_blocks(pem, "RSA PRIVATE KEY")
        .into_iter()
        .next()
    {
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(der.into()));
    }
    Err("no supported PRIVATE KEY block found in PEM".to_owned())
}

/// Build strict TLS 1.2/1.3 (with optional mTLS client certificate) configuration and leaf
/// SHA-256 fingerprint for agent attestation.
pub fn build_agent_tls_config(
    ca_cert_path: Option<&Path>,
    client_cert_path: Option<&Path>,
    client_key_path: Option<&Path>,
) -> Result<(rustls::ClientConfig, String), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    if let Some(ca_path) = ca_cert_path {
        let ca_pem = std::fs::read_to_string(ca_path)
            .map_err(|e| format!("failed reading CA cert '{}': {e}", ca_path.display()))?;
        let ders = decode_pem_certificates(&ca_pem);
        if ders.is_empty() {
            return Err("CA cert PEM contained zero certificates".to_owned());
        }
        for der in ders {
            roots
                .add(CertificateDer::from(der))
                .map_err(|e| format!("invalid CA certificate: {e}"))?;
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let mut fingerprint = String::new();
    let cfg = match (client_cert_path, client_key_path) {
        (Some(cert_p), Some(key_p)) => {
            let cert_pem = std::fs::read_to_string(cert_p)
                .map_err(|e| format!("failed reading client cert '{}': {e}", cert_p.display()))?;
            let key_pem = std::fs::read_to_string(key_p)
                .map_err(|e| format!("failed reading client key '{}': {e}", key_p.display()))?;
            let certs: Vec<CertificateDer<'static>> = decode_pem_certificates(&cert_pem)
                .into_iter()
                .map(CertificateDer::from)
                .collect();
            if let Some(leaf) = certs.first() {
                let mut h = Sha256::new();
                h.update(leaf.as_ref());
                fingerprint = hex::encode(h.finalize());
            } else {
                return Err("client cert PEM contained no CERTIFICATE blocks".to_owned());
            }
            let key = load_private_key(&key_pem)?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("invalid agent mTLS identity: {e}"))?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => {
            return Err("both --client-cert and --client-key must be provided together".to_owned());
        }
    };

    Ok((cfg, fingerprint))
}

#[must_use]
pub fn is_target_allowlisted<S: std::hash::BuildHasher>(
    allowed: &HashSet<String, S>,
    host_port: &str,
) -> bool {
    allowed.contains(host_port.trim())
}

/// Run a single outbound WebSocket/mTLS tunnel session until closed or `shutdown` flips `true`.
pub async fn run_agent_tunnel_once(
    cfg: &AgentConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), String> {
    let mut req = cfg
        .server_url
        .as_str()
        .into_client_request()
        .map_err(|e| format!("invalid agent server URL: {e}"))?;
    let auth_hv = HeaderValue::from_str(&format!("Bearer {}", cfg.enrollment_token))
        .map_err(|e| format!("invalid enrollment token header: {e}"))?;
    req.headers_mut()
        .insert(http::header::AUTHORIZATION, auth_hv);

    let (tls_cfg, fingerprint) = build_agent_tls_config(
        cfg.ca_cert_path.as_deref(),
        cfg.client_cert_path.as_deref(),
        cfg.client_key_path.as_deref(),
    )?;
    let connector = if cfg.server_url.starts_with("wss://") {
        Some(Connector::Rustls(Arc::new(tls_cfg)))
    } else {
        None
    };

    let (ws, _) = connect_async_tls_with_config(req, None, false, connector)
        .await
        .map_err(|e| format!("agent WS connect failed: {e}"))?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    let register_msg = serde_json::json!({
        "type": "register",
        "name": cfg.name,
        "hostname": cfg.hostname,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "cert_fingerprint_sha256": fingerprint,
        "labels": cfg.labels,
        "targets": cfg.targets,
    });
    ws_tx
        .send(WsMsg::Text(register_msg.to_string().into()))
        .await
        .map_err(|e| format!("failed sending register envelope: {e}"))?;

    let allowed_addrs: HashSet<String> = cfg
        .targets
        .iter()
        .map(AgentTargetConfig::addr_key)
        .collect();
    let (out_tx, mut out_rx) = mpsc::channel::<WsMsg>(AGENT_FRAME_CHANNEL);
    let streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut hb_tick = tokio::time::interval(Duration::from_secs(HEARTBEAT_SECS));
    hb_tick.tick().await;

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    let _ = ws_tx.send(WsMsg::Close(None)).await;
                    break;
                }
            }
            _ = hb_tick.tick() => {
                let hb = serde_json::json!({ "type": "heartbeat" }).to_string();
                if ws_tx.send(WsMsg::Text(hb.into())).await.is_err() {
                    break;
                }
            }
            Some(msg) = out_rx.recv() => {
                if ws_tx.send(msg).await.is_err() {
                    break;
                }
            }
            inbound = ws_rx.next() => {
                let Some(Ok(msg)) = inbound else { break; };
                match msg {
                    WsMsg::Close(_) => break,
                    WsMsg::Binary(bytes) => {
                        if let Some((kind, stream_id, payload)) = decode_mux_frame(&bytes) {
                            let guard = streams.lock().await;
                            match kind {
                                MuxFrameKind::Data => {
                                    if let Some(tx) = guard.get(&stream_id) {
                                        let _ = tx.try_send(payload.to_vec());
                                    }
                                }
                                MuxFrameKind::Close => {
                                    drop(guard);
                                    streams.lock().await.remove(&stream_id);
                                }
                                _ => {}
                            }
                        }
                    }
                    WsMsg::Text(txt) => {
                        let Ok(val) = serde_json::from_str::<serde_json::Value>(&txt) else { continue; };
                        if val["type"].as_str() == Some("dial") {
                            let stream_id = u32::try_from(val["stream_id"].as_u64().unwrap_or(0)).unwrap_or(0);
                            let target = val["target"].as_str().unwrap_or("").trim().to_owned();
                            if stream_id == 0 || !is_target_allowlisted(&allowed_addrs, &target) {
                                let err_msg = serde_json::json!({
                                    "type": "dial_err",
                                    "stream_id": stream_id,
                                    "error": format!("target '{target}' is not in agent allowlist"),
                                });
                                let _ = out_tx.try_send(WsMsg::Text(err_msg.to_string().into()));
                                continue;
                            }
                            let streams_c = Arc::clone(&streams);
                            let out_c = out_tx.clone();
                            tokio::spawn(async move {
                                match TcpStream::connect(&target).await {
                                    Ok(tcp) => {
                                        let (mut r_tcp, mut w_tcp) = tcp.into_split();
                                        let (to_tcp_tx, mut to_tcp_rx) = mpsc::channel::<Vec<u8>>(AGENT_FRAME_CHANNEL);
                                        streams_c.lock().await.insert(stream_id, to_tcp_tx);
                                        let ok_msg = serde_json::json!({
                                            "type": "dial_ok",
                                            "stream_id": stream_id,
                                        });
                                        if out_c.send(WsMsg::Text(ok_msg.to_string().into())).await.is_err() {
                                            return;
                                        }
                                        let out_up = out_c.clone();
                                        let upload = async move {
                                            let mut buf = vec![0u8; 16_384];
                                            while let Ok(n) = r_tcp.read(&mut buf).await {
                                                if n == 0 {
                                                    let _ = out_up.send(WsMsg::Binary(encode_mux_frame(MuxFrameKind::Close, stream_id, &[]).into())).await;
                                                    break;
                                                }
                                                if out_up.send(WsMsg::Binary(encode_mux_frame(MuxFrameKind::Data, stream_id, &buf[..n]).into())).await.is_err() {
                                                    break;
                                                }
                                            }
                                        };
                                        let download = async move {
                                            while let Some(chunk) = to_tcp_rx.recv().await {
                                                if w_tcp.write_all(&chunk).await.is_err() {
                                                    break;
                                                }
                                            }
                                        };
                                        tokio::select! {
                                            () = upload => {}
                                            () = download => {}
                                        }
                                        streams_c.lock().await.remove(&stream_id);
                                    }
                                    Err(err) => {
                                        let err_msg = serde_json::json!({
                                            "type": "dial_err",
                                            "stream_id": stream_id,
                                            "error": err.to_string(),
                                        });
                                        let _ = out_c.try_send(WsMsg::Text(err_msg.to_string().into()));
                                    }
                                }
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_targets_enforces_allowlist_and_builds_mtls_identity() {
        let t = parse_target_spec("ssh:10.0.1.20:22").unwrap();
        assert_eq!(t.addr_key(), "10.0.1.20:22");
        assert!(parse_target_spec("invalid").is_err());

        let allowed: HashSet<String> = [t.addr_key()].into_iter().collect();
        assert!(is_target_allowlisted(&allowed, "10.0.1.20:22"));
        assert!(!is_target_allowlisted(&allowed, "169.254.169.254:80"));

        let ca_cert = rcgen::generate_simple_self_signed(vec!["ca.operquay.test".into()]).unwrap();
        let cli_cert =
            rcgen::generate_simple_self_signed(vec!["agent.operquay.test".into()]).unwrap();
        let dir = std::env::temp_dir().join(format!("oq-agent-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let root_pem_path = dir.join("ca.pem");
        let agent_cert_path = dir.join("client.pem");
        let agent_key_path = dir.join("client.key");
        std::fs::write(&root_pem_path, ca_cert.cert.pem()).unwrap();
        std::fs::write(&agent_cert_path, cli_cert.cert.pem()).unwrap();
        std::fs::write(&agent_key_path, cli_cert.key_pair.serialize_pem()).unwrap();

        let (_cfg, fp) = build_agent_tls_config(
            Some(&root_pem_path),
            Some(&agent_cert_path),
            Some(&agent_key_path),
        )
        .unwrap();
        assert_eq!(fp.len(), 64);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
