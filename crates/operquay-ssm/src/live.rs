//! Live AWS SSM `DataChannel` WebSocket client (`tokio-tungstenite` over `rustls`),
//! handling `OpenDataChannelInput`, `HandshakeRequest`/`Response`/`Complete`, automatic
//! `acknowledge` frames, terminal `PayloadType::Size` resize messages, and `SsmVirtualStream` I/O.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Notify};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use uuid::Uuid;

use crate::{message_type, AgentMessage, PayloadType, SsmVirtualStream};

/// `xtaci/smux` v1 protocol version & commands used by `amazon-ssm-agent >= 3.0.196.0`
/// for `AWS-StartPortForwardingSession` multiplexed streams.
pub const SMUX_VERSION: u8 = 1;
pub const SMUX_CMD_SYN: u8 = 0;
pub const SMUX_CMD_FIN: u8 = 1;
pub const SMUX_CMD_PSH: u8 = 2;
pub const SMUX_CMD_NOP: u8 = 3;
pub const SMUX_HEADER_LEN: usize = 8;
pub const SMUX_CLIENT_STREAM_ID: u32 = 3;
/// AWS Session Manager protocol client version capability advertised to `amazon-ssm-agent`.
/// Must be `>= "1.2.331.0"` so `amazon-ssm-agent` enables `MuxPortSession` (`smux` v1)
/// with `KeepAliveDisabled = true`.
pub const SSM_CLIENT_VERSION: &str = "1.2.779.0";

/// Encode a single `smux` v1 frame (`ver=1`, `cmd`, `length: u16 LE`, `stream_id: u32 LE`, `payload`).
#[must_use]
pub fn encode_smux_frame(cmd: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let chunk_len = payload.len().min(usize::from(u16::MAX));
    let mut out = Vec::with_capacity(SMUX_HEADER_LEN + chunk_len);
    out.push(SMUX_VERSION);
    out.push(cmd);
    out.extend_from_slice(&(u16::try_from(chunk_len).unwrap_or(u16::MAX)).to_le_bytes());
    out.extend_from_slice(&stream_id.to_le_bytes());
    out.extend_from_slice(&payload[..chunk_len]);
    out
}

/// Decoded `smux` v1 frame emitted by [`decode_smux_frames`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmuxFrame {
    pub cmd: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

/// Incrementally drain complete `smux` v1 frames from `buf`.
pub fn decode_smux_frames(buf: &mut BytesMut) -> Vec<SmuxFrame> {
    let mut frames = Vec::new();
    while buf.len() >= SMUX_HEADER_LEN {
        if buf[0] != SMUX_VERSION {
            // Desync guard: treat remaining buffer as invalid/end
            break;
        }
        let cmd = buf[1];
        let payload_len = usize::from(u16::from_le_bytes([buf[2], buf[3]]));
        if buf.len() < SMUX_HEADER_LEN + payload_len {
            break;
        }
        let stream_id = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let _ = buf.split_to(SMUX_HEADER_LEN);
        let payload = buf.split_to(payload_len).to_vec();
        frames.push(SmuxFrame {
            cmd,
            stream_id,
            payload,
        });
    }
    frames
}

/// Build the initial `OpenDataChannelInput` JSON frame required on AWS SSM `StreamUrl`.
#[must_use]
pub fn build_open_data_channel_json(token_value: &str) -> String {
    serde_json::json!({
        "MessageSchemaVersion": "1.0",
        "RequestId": Uuid::new_v4().to_string(),
        "TokenValue": token_value,
        "ClientVersion": SSM_CLIENT_VERSION,
    })
    .to_string()
}

/// Build an encoded SSM terminal resize `AgentMessage` (`PayloadType::Size`).
#[must_use]
pub fn encode_ssm_resize(seq: i64, cols: u32, rows: u32) -> Vec<u8> {
    let payload = serde_json::json!({ "cols": cols, "rows": rows })
        .to_string()
        .into_bytes();
    AgentMessage::data(
        message_type::INPUT_STREAM_DATA,
        seq,
        PayloadType::Size,
        payload,
    )
    .encode()
}

#[derive(Debug, Deserialize)]
struct HandshakeRequestPayload {
    #[serde(rename = "AgentVersion", default)]
    agent_version: String,
    #[serde(rename = "RequestedClientActions", default)]
    requested_client_actions: Vec<RequestedClientAction>,
}

#[derive(Debug, Deserialize)]
struct RequestedClientAction {
    #[serde(rename = "ActionType", default)]
    action_type: String,
    #[serde(rename = "ActionParameters", default)]
    action_parameters: serde_json::Value,
}

fn parse_semver_gte(version: &str, min: (u32, u32, u32)) -> bool {
    let mut parts = version
        .trim()
        .split('.')
        .map(|p| p.parse::<u32>().unwrap_or(0));
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    let patch = parts.next().unwrap_or(0);
    (major, minor, patch) >= min
}

fn handshake_requests_smux(req_payload: &[u8]) -> bool {
    let Ok(parsed) = serde_json::from_slice::<HandshakeRequestPayload>(req_payload) else {
        return false;
    };
    let is_port_session = parsed.requested_client_actions.iter().any(|a| {
        a.action_type == "SessionType"
            && a.action_parameters
                .get("SessionType")
                .and_then(|v| v.as_str())
                == Some("Port")
    });
    is_port_session && parse_semver_gte(&parsed.agent_version, (3, 0, 196))
}

#[derive(Debug, Serialize)]
struct HandshakeResponsePayload {
    #[serde(rename = "ClientVersion")]
    client_version: &'static str,
    #[serde(rename = "ProcessedClientActions")]
    processed_client_actions: Vec<ProcessedClientAction>,
    #[serde(rename = "Errors")]
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ProcessedClientAction {
    #[serde(rename = "ActionType")]
    action_type: String,
    #[serde(rename = "ActionStatus")]
    action_status: u8,
    #[serde(rename = "ActionResult")]
    action_result: serde_json::Value,
    #[serde(rename = "Error")]
    error: String,
}

fn build_acknowledge_frame(msg: &AgentMessage) -> Vec<u8> {
    let payload = serde_json::json!({
        "AcknowledgedMessageType": msg.message_type,
        "AcknowledgedMessageId": msg.message_id.to_string(),
        "AcknowledgedMessageSequenceNumber": msg.sequence_number,
        "IsSequentialMessage": true,
    })
    .to_string()
    .into_bytes();
    let mut ack = AgentMessage::data(message_type::ACKNOWLEDGE, 0, PayloadType::Output, payload);
    ack.flags = 3;
    ack.payload_type = 0;
    ack.encode()
}

fn build_handshake_response(req_payload: &[u8], seq_out: &AtomicI64) -> Vec<u8> {
    let processed = serde_json::from_slice::<HandshakeRequestPayload>(req_payload).map_or_else(
        |_| Vec::new(),
        |parsed| {
            parsed
                .requested_client_actions
                .into_iter()
                .map(|a| ProcessedClientAction {
                    action_type: a.action_type,
                    action_status: 1, // Success
                    action_result: serde_json::json!({}),
                    error: String::new(),
                })
                .collect()
        },
    );
    let payload = serde_json::to_vec(&HandshakeResponsePayload {
        client_version: SSM_CLIENT_VERSION,
        processed_client_actions: processed,
        errors: Vec::new(),
    })
    .unwrap_or_default();
    let seq = seq_out.fetch_add(1, Ordering::Relaxed);
    AgentMessage::data(
        message_type::INPUT_STREAM_DATA,
        seq,
        PayloadType::HandshakeResponse,
        payload,
    )
    .encode()
}

enum OutboundFrame {
    PreEncoded(Vec<u8>),
    Data {
        payload_type: PayloadType,
        payload: Vec<u8>,
    },
}

/// Interactive shell handle over a live AWS SSM `DataChannel` WebSocket.
pub struct SsmShellChannel {
    pub rx_output: mpsc::Receiver<Vec<u8>>,
    tx_control: mpsc::Sender<OutboundFrame>,
    shutdown: Arc<Notify>,
}

impl SsmShellChannel {
    pub async fn send_input(&self, bytes: &[u8]) -> Result<(), String> {
        self.tx_control
            .send(OutboundFrame::Data {
                payload_type: PayloadType::Output,
                payload: bytes.to_vec(),
            })
            .await
            .map_err(|_| "SSM DataChannel closed".to_owned())
    }

    pub async fn send_resize(&self, cols: u32, rows: u32) -> Result<(), String> {
        let payload = serde_json::json!({ "cols": cols, "rows": rows })
            .to_string()
            .into_bytes();
        self.tx_control
            .send(OutboundFrame::Data {
                payload_type: PayloadType::Size,
                payload,
            })
            .await
            .map_err(|_| "SSM DataChannel closed".to_owned())
    }

    pub fn close(&self) {
        self.shutdown.notify_waiters();
    }
}

async fn spawn_ws_pump(
    stream_url: &str,
    token_value: &str,
    shutdown: Arc<Notify>,
    raw_frames: bool,
) -> Result<(mpsc::Receiver<Vec<u8>>, mpsc::Sender<OutboundFrame>), String> {
    let (ws_stream, _) = connect_async(stream_url)
        .await
        .map_err(|e| format!("SSM WebSocket connect failed: {e}"))?;
    let (mut ws_sink, mut ws_source) = ws_stream.split();

    let open_json = build_open_data_channel_json(token_value);
    ws_sink
        .send(WsMessage::Text(open_json.into()))
        .await
        .map_err(|e| format!("SSM OpenDataChannel send failed: {e}"))?;

    let (to_caller_tx, to_caller_rx) = mpsc::channel::<Vec<u8>>(128);
    let (from_caller_tx, mut from_caller_rx) = mpsc::channel::<OutboundFrame>(128);
    let seq_pump = Arc::new(AtomicI64::new(0));

    tokio::spawn(async move {
        let mut handshake_ready = false;
        let mut smux_active = false;
        let mut smux_syn_sent = false;
        let mut expected_in_seq: i64 = 0;
        let mut in_buffer: BTreeMap<i64, (AgentMessage, Vec<u8>)> = BTreeMap::new();
        let mut smux_rx_buf = BytesMut::with_capacity(64 * 1024);
        let mut deadline: Option<Pin<Box<tokio::time::Sleep>>> =
            Some(Box::pin(tokio::time::sleep(Duration::from_millis(1500))));

        loop {
            tokio::select! {
                biased;

                () = shutdown.notified() => {
                    if smux_active && smux_syn_sent {
                        let seq = seq_pump.fetch_add(1, Ordering::Relaxed);
                        let fin = AgentMessage::data(
                            message_type::INPUT_STREAM_DATA,
                            seq,
                            PayloadType::Output,
                            encode_smux_frame(SMUX_CMD_FIN, SMUX_CLIENT_STREAM_ID, &[]),
                        )
                        .encode();
                        let _ = ws_sink.send(WsMessage::Binary(fin.into())).await;
                    }
                    let _ = ws_sink.send(WsMessage::Close(None)).await;
                    break;
                }

                () = async {
                    if let Some(d) = deadline.as_mut() {
                        d.as_mut().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }, if !handshake_ready => {
                    handshake_ready = true;
                    deadline = None;
                }

                outbound = from_caller_rx.recv(), if handshake_ready => {
                    let Some(item) = outbound else {
                        let _ = ws_sink.send(WsMessage::Close(None)).await;
                        break;
                    };
                    let frame = match item {
                        OutboundFrame::PreEncoded(raw) => raw,
                        OutboundFrame::Data { payload_type, payload } => {
                            let seq = seq_pump.fetch_add(1, Ordering::Relaxed);
                            AgentMessage::data(
                                message_type::INPUT_STREAM_DATA,
                                seq,
                                payload_type,
                                payload,
                            )
                            .encode()
                        }
                    };
                    if raw_frames && smux_active {
                        if let Ok(decoded_out) = AgentMessage::decode(&frame) {
                            if decoded_out.payload.is_empty() {
                                continue;
                            }
                            let mut failed = false;
                            for chunk in decoded_out.payload.chunks(32 * 1024) {
                                let seq = seq_pump.fetch_add(1, Ordering::Relaxed);
                                tracing::debug!(
                                    seq,
                                    stream_id = SMUX_CLIENT_STREAM_ID,
                                    bytes = chunk.len(),
                                    "SSM sending smux PSH"
                                );
                                let wrapped = AgentMessage::data(
                                    message_type::INPUT_STREAM_DATA,
                                    seq,
                                    PayloadType::Output,
                                    encode_smux_frame(SMUX_CMD_PSH, SMUX_CLIENT_STREAM_ID, chunk),
                                )
                                .encode();
                                if ws_sink.send(WsMessage::Binary(wrapped.into())).await.is_err() {
                                    failed = true;
                                    break;
                                }
                            }
                            if failed {
                                break;
                            }
                            continue;
                        }
                    }
                    if ws_sink.send(WsMessage::Binary(frame.into())).await.is_err() {
                        break;
                    }
                }

                inbound = ws_source.next() => {
                    let Some(Ok(msg)) = inbound else { break; };
                    let WsMessage::Binary(raw) = msg else {
                        if matches!(msg, WsMessage::Close(_)) {
                            break;
                        }
                        continue;
                    };
                    let Ok(first_msg) = AgentMessage::decode(&raw) else {
                        continue;
                    };
                    if first_msg.message_type == message_type::ACKNOWLEDGE {
                        continue;
                    }
                    if first_msg.message_type == message_type::CHANNEL_CLOSED {
                        tracing::info!(
                            seq = first_msg.sequence_number,
                            raw_frames,
                            payload = %String::from_utf8_lossy(&first_msg.payload),
                            "SSM channel_closed received"
                        );
                        if raw_frames {
                            let _ = to_caller_tx.send(raw.to_vec()).await;
                        }
                        break;
                    }
                    let ack = build_acknowledge_frame(&first_msg);
                    let _ = ws_sink.send(WsMessage::Binary(ack.into())).await;

                    if first_msg.sequence_number < expected_in_seq {
                        continue;
                    }
                    let mut ready: Vec<(AgentMessage, Vec<u8>)> = Vec::new();
                    if first_msg.sequence_number == expected_in_seq {
                        ready.push((first_msg, raw.to_vec()));
                        expected_in_seq += 1;
                        while let Some(next_item) = in_buffer.remove(&expected_in_seq) {
                            ready.push(next_item);
                            expected_in_seq += 1;
                        }
                    } else {
                        in_buffer
                            .entry(first_msg.sequence_number)
                            .or_insert_with(|| (first_msg, raw.to_vec()));
                    }

                    let mut close_pump = false;
                    for (decoded, raw_vec) in ready {
                        if decoded.payload_type == PayloadType::Error as u32 {
                            let err_text = String::from_utf8_lossy(&decoded.payload).to_string();
                            tracing::warn!(
                                seq = decoded.sequence_number,
                                raw_frames,
                                error = %err_text,
                                "SSM agent error payload"
                            );
                            if !raw_frames {
                                let _ = to_caller_tx.send(decoded.payload).await;
                            }
                            continue;
                        }

                        if decoded.payload_type == PayloadType::HandshakeRequest as u32 {
                            let req_str = String::from_utf8_lossy(&decoded.payload);
                            if raw_frames && handshake_requests_smux(&decoded.payload) {
                                smux_active = true;
                            }
                            tracing::info!(
                                raw_frames,
                                smux_active,
                                request = %req_str,
                                "SSM HandshakeRequest received"
                            );
                            let rsp = build_handshake_response(&decoded.payload, &seq_pump);
                            if ws_sink.send(WsMessage::Binary(rsp.into())).await.is_err() {
                                close_pump = true;
                                break;
                            }
                            deadline = Some(Box::pin(tokio::time::sleep(Duration::from_millis(1500))));
                            continue;
                        }
                        if decoded.payload_type == PayloadType::HandshakeComplete as u32 {
                            tracing::info!(
                                raw_frames,
                                smux_active,
                                payload = %String::from_utf8_lossy(&decoded.payload),
                                "SSM HandshakeComplete received"
                            );
                            handshake_ready = true;
                            deadline = None;
                            if raw_frames && smux_active && !smux_syn_sent {
                                smux_syn_sent = true;
                                let seq = seq_pump.fetch_add(1, Ordering::Relaxed);
                                tracing::info!(
                                    seq,
                                    stream_id = SMUX_CLIENT_STREAM_ID,
                                    "SSM sending smux SYN"
                                );
                                let syn = AgentMessage::data(
                                    message_type::INPUT_STREAM_DATA,
                                    seq,
                                    PayloadType::Output,
                                    encode_smux_frame(SMUX_CMD_SYN, SMUX_CLIENT_STREAM_ID, &[]),
                                )
                                .encode();
                                if ws_sink.send(WsMessage::Binary(syn.into())).await.is_err() {
                                    close_pump = true;
                                    break;
                                }
                            }
                            continue;
                        }
                        if decoded.payload_type == PayloadType::Flag as u32 {
                            let flag_val = if decoded.payload.len() >= 4 {
                                u32::from_be_bytes([
                                    decoded.payload[0],
                                    decoded.payload[1],
                                    decoded.payload[2],
                                    decoded.payload[3],
                                ])
                            } else {
                                0
                            };
                            tracing::info!(flag = flag_val, raw_frames, "SSM Flag received");
                            // Flag(ConnectToPort = 1) unblocks port data; Flag(TerminateSession = 2) ends
                            if flag_val == 2 {
                                close_pump = true;
                                break;
                            }
                            handshake_ready = true;
                            deadline = None;
                            continue;
                        }

                        // First real payload also marks handshake complete for minimal peers.
                        if !handshake_ready {
                            handshake_ready = true;
                            deadline = None;
                        }

                        if raw_frames
                            && smux_active
                            && decoded.payload_type == PayloadType::Output as u32
                        {
                            if decoded.payload.is_empty() {
                                continue;
                            }
                            smux_rx_buf.extend_from_slice(&decoded.payload);
                            for sf in decode_smux_frames(&mut smux_rx_buf) {
                                match sf.cmd {
                                    SMUX_CMD_PSH => {
                                        if !sf.payload.is_empty() {
                                            tracing::debug!(
                                                stream_id = sf.stream_id,
                                                bytes = sf.payload.len(),
                                                "SSM received smux PSH"
                                            );
                                            let unwrapped = AgentMessage::data(
                                                message_type::OUTPUT_STREAM_DATA,
                                                decoded.sequence_number,
                                                PayloadType::Output,
                                                sf.payload,
                                            )
                                            .encode();
                                            if to_caller_tx.send(unwrapped).await.is_err() {
                                                close_pump = true;
                                                break;
                                            }
                                        }
                                    }
                                    SMUX_CMD_FIN => {
                                        tracing::info!(
                                            stream_id = sf.stream_id,
                                            "SSM smux FIN received"
                                        );
                                        let closed = AgentMessage::data(
                                            message_type::CHANNEL_CLOSED,
                                            decoded.sequence_number,
                                            PayloadType::Output,
                                            Vec::new(),
                                        )
                                        .encode();
                                        let _ = to_caller_tx.send(closed).await;
                                        close_pump = true;
                                        break;
                                    }
                                    other => {
                                        tracing::debug!(
                                            cmd = other,
                                            stream_id = sf.stream_id,
                                            "SSM smux control frame"
                                        );
                                    }
                                }
                            }
                            if close_pump {
                                break;
                            }
                            continue;
                        }

                        let forward = if raw_frames {
                            raw_vec
                        } else if decoded.payload.is_empty() {
                            continue;
                        } else {
                            decoded.payload
                        };
                        if to_caller_tx.send(forward).await.is_err() {
                            close_pump = true;
                            break;
                        }
                    }
                    if close_pump {
                        break;
                    }
                }
            }
        }
    });

    Ok((to_caller_rx, from_caller_tx))
}

/// Dial an AWS SSM `StreamUrl` (`wss://` or `ws://`), send `OpenDataChannelInput`, handle the
/// `AgentMessage` handshake and automatic sequence ACKs, and return an `SsmVirtualStream`
/// (`AsyncRead + AsyncWrite`) suitable for piping raw RDP/VNC/TCP bytes directly.
pub async fn connect_ssm_datachannel_stream(
    stream_url: &str,
    token_value: &str,
    shutdown: Arc<Notify>,
) -> Result<SsmVirtualStream, String> {
    let (to_stream_rx, from_caller_tx) =
        spawn_ws_pump(stream_url, token_value, shutdown, true).await?;
    let (raw_tx, mut raw_rx) = mpsc::channel::<Vec<u8>>(128);
    tokio::spawn(async move {
        while let Some(raw) = raw_rx.recv().await {
            if from_caller_tx
                .send(OutboundFrame::PreEncoded(raw))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    Ok(SsmVirtualStream::new(to_stream_rx, raw_tx))
}

/// Dial an AWS SSM `StreamUrl` as an interactive shell channel (UTF-8 / VT stream + resize).
pub async fn open_ssm_shell_channel(
    stream_url: &str,
    token_value: &str,
) -> Result<SsmShellChannel, String> {
    let shutdown = Arc::new(Notify::new());
    let (rx_output, tx_control) =
        spawn_ws_pump(stream_url, token_value, shutdown.clone(), false).await?;
    Ok(SsmShellChannel {
        rx_output,
        tx_control,
        shutdown,
    })
}

#[cfg(test)]
mod tests {
    use axum::extract::ws::{Message as WsMsg, WebSocketUpgrade};
    use axum::routing::get;
    use axum::Router;
    use futures_util::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn performs_real_ws_open_handshake_ack_and_virtual_stream_io() {
        let app = Router::new().route(
            "/v1/data-channel/sess-1",
            get(|ws: WebSocketUpgrade| async move {
                ws.on_upgrade(|mut sock| async move {
                    // 1. Expect OpenDataChannelInput JSON with TokenValue
                    let Some(Ok(WsMsg::Text(open))) = sock.next().await else {
                        panic!("expected OpenDataChannelInput");
                    };
                    let val: serde_json::Value = serde_json::from_str(&open).unwrap();
                    assert_eq!(val["TokenValue"].as_str(), Some("tok-live"));

                    // 2. Send HandshakeRequest
                    let hs_req = serde_json::json!({
                        "AgentVersion": "3.3.0",
                        "RequestedClientActions": [{ "ActionType": "SessionType", "ActionParameters": {} }]
                    })
                    .to_string()
                    .into_bytes();
                    let msg = AgentMessage::data(
                        message_type::OUTPUT_STREAM_DATA,
                        0,
                        PayloadType::HandshakeRequest,
                        hs_req,
                    );
                    sock.send(WsMsg::Binary(msg.encode().into())).await.unwrap();

                    // 3. Expect Acknowledge + HandshakeResponse, then echo payload back
                    let mut saw_hs_rsp = false;
                    while let Some(Ok(WsMsg::Binary(raw))) = sock.next().await {
                        let dec = AgentMessage::decode(&raw).unwrap();
                        if dec.payload_type == PayloadType::HandshakeResponse as u32 {
                            saw_hs_rsp = true;
                            let out = AgentMessage::data(
                                message_type::OUTPUT_STREAM_DATA,
                                1,
                                PayloadType::Output,
                                b"SSM_BANNER".to_vec(),
                            );
                            sock.send(WsMsg::Binary(out.encode().into())).await.unwrap();
                        } else if saw_hs_rsp
                            && dec.message_type == message_type::INPUT_STREAM_DATA
                            && dec.payload == b"PING_TUNNEL"
                        {
                            let reply = AgentMessage::data(
                                message_type::OUTPUT_STREAM_DATA,
                                2,
                                PayloadType::Output,
                                b"PONG_TUNNEL".to_vec(),
                            );
                            sock.send(WsMsg::Binary(reply.encode().into())).await.unwrap();
                            break;
                        }
                    }
                })
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let shutdown = Arc::new(Notify::new());
        let url = format!("ws://{addr}/v1/data-channel/sess-1");
        let mut stream = connect_ssm_datachannel_stream(&url, "tok-live", shutdown.clone())
            .await
            .unwrap();

        let mut banner = [0u8; 10];
        stream.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSM_BANNER");

        stream.write_all(b"PING_TUNNEL").await.unwrap();
        let mut pong = [0u8; 11];
        stream.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"PONG_TUNNEL");

        shutdown.notify_waiters();
        srv.abort();
    }

    #[tokio::test]
    async fn handles_handshake_complete_and_smux_v1_port_forwarding() {
        let app = Router::new().route(
            "/v1/data-channel/sess-smux",
            get(|ws: WebSocketUpgrade| async move {
                ws.on_upgrade(|mut sock| async move {
                    let Some(Ok(WsMsg::Text(_open))) = sock.next().await else {
                        panic!("expected OpenDataChannelInput");
                    };
                    let hs_req = serde_json::json!({
                        "AgentVersion": "3.2.532.0",
                        "RequestedClientActions": [{
                            "ActionType": "SessionType",
                            "ActionParameters": { "SessionType": "Port" }
                        }]
                    })
                    .to_string()
                    .into_bytes();
                    let msg = AgentMessage::data(
                        message_type::OUTPUT_STREAM_DATA,
                        0,
                        PayloadType::HandshakeRequest,
                        hs_req,
                    );
                    sock.send(WsMsg::Binary(msg.encode().into())).await.unwrap();

                    let mut saw_hs_rsp = false;
                    let mut saw_syn = false;
                    let mut rx_buf = BytesMut::new();
                    while let Some(Ok(WsMsg::Binary(raw))) = sock.next().await {
                        let dec = AgentMessage::decode(&raw).unwrap();
                        if dec.payload_type == PayloadType::HandshakeResponse as u32 {
                            saw_hs_rsp = true;
                            let complete = AgentMessage::data(
                                message_type::OUTPUT_STREAM_DATA,
                                1,
                                PayloadType::HandshakeComplete,
                                serde_json::json!({"HandshakeTimeToComplete": 12000})
                                    .to_string()
                                    .into_bytes(),
                            );
                            sock.send(WsMsg::Binary(complete.encode().into()))
                                .await
                                .unwrap();
                        } else if saw_hs_rsp && dec.message_type == message_type::INPUT_STREAM_DATA
                        {
                            rx_buf.extend_from_slice(&dec.payload);
                            for sf in decode_smux_frames(&mut rx_buf) {
                                if sf.cmd == SMUX_CMD_SYN {
                                    saw_syn = true;
                                } else if sf.cmd == SMUX_CMD_PSH
                                    && saw_syn
                                    && sf.payload == b"HELLO"
                                {
                                    let reply_smux =
                                        encode_smux_frame(SMUX_CMD_PSH, sf.stream_id, b"WORLD");
                                    let reply = AgentMessage::data(
                                        message_type::OUTPUT_STREAM_DATA,
                                        2,
                                        PayloadType::Output,
                                        reply_smux,
                                    );
                                    sock.send(WsMsg::Binary(reply.encode().into()))
                                        .await
                                        .unwrap();
                                    return;
                                }
                            }
                        }
                    }
                })
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let shutdown = Arc::new(Notify::new());
        let url = format!("ws://{addr}/v1/data-channel/sess-smux");
        let mut stream = connect_ssm_datachannel_stream(&url, "tok-smux", shutdown.clone())
            .await
            .unwrap();

        stream.write_all(b"HELLO").await.unwrap();
        let mut reply = [0u8; 5];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"WORLD");

        shutdown.notify_waiters();
        srv.abort();
    }

    #[tokio::test]
    async fn assigns_monotonic_seq_numbers_when_shell_resize_queued_before_handshake() {
        let seen = Arc::new(tokio::sync::Mutex::new(Vec::<(u32, i64, Vec<u8>)>::new()));
        let seen_srv = seen.clone();
        let app = Router::new().route(
            "/v1/data-channel/sess-shell-seq",
            get(move |ws: WebSocketUpgrade| {
                let seen_ws = seen_srv.clone();
                async move {
                    ws.on_upgrade(move |mut sock| async move {
                        let Some(Ok(WsMsg::Text(_open))) = sock.next().await else {
                            panic!("expected OpenDataChannelInput");
                        };
                        // Wait briefly so caller queues resize before HandshakeRequest is sent
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        let hs_req = serde_json::json!({
                            "AgentVersion": "3.3.0",
                            "RequestedClientActions": [{ "ActionType": "SessionType", "ActionParameters": {} }]
                        })
                        .to_string()
                        .into_bytes();
                        let msg = AgentMessage::data(
                            message_type::OUTPUT_STREAM_DATA,
                            0,
                            PayloadType::HandshakeRequest,
                            hs_req,
                        );
                        sock.send(WsMsg::Binary(msg.encode().into())).await.unwrap();

                        while let Some(Ok(WsMsg::Binary(raw))) = sock.next().await {
                            let dec = AgentMessage::decode(&raw).unwrap();
                            if dec.message_type == message_type::ACKNOWLEDGE {
                                continue;
                            }
                            let pt = dec.payload_type;
                            let seq = dec.sequence_number;
                            let payload = dec.payload.clone();
                            seen_ws.lock().await.push((pt, seq, payload));
                            if pt == PayloadType::HandshakeResponse as u32 {
                                let complete = AgentMessage::data(
                                    message_type::OUTPUT_STREAM_DATA,
                                    1,
                                    PayloadType::HandshakeComplete,
                                    b"{}".to_vec(),
                                );
                                sock.send(WsMsg::Binary(complete.encode().into())).await.unwrap();
                            } else if pt == PayloadType::Output as u32 && dec.payload == b"S" {
                                break;
                            }
                        }
                    })
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let chan = open_ssm_shell_channel(
            &format!("ws://{addr}/v1/data-channel/sess-shell-seq"),
            "tok-seq",
        )
        .await
        .unwrap();
        // Queue resize & input BEFORE HandshakeRequest arrives
        chan.send_resize(140, 40).await.unwrap();
        chan.send_input(b"S").await.unwrap();

        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if seen.lock().await.len() >= 3 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let recorded = seen.lock().await;
        assert_eq!(recorded[0].0, PayloadType::HandshakeResponse as u32);
        assert_eq!(recorded[0].1, 0);
        assert_eq!(recorded[1].0, PayloadType::Size as u32);
        assert_eq!(recorded[1].1, 1);
        assert_eq!(recorded[2].0, PayloadType::Output as u32);
        assert_eq!(recorded[2].1, 2);
        assert_eq!(recorded[2].2, b"S");

        chan.close();
        srv.abort();
    }
}
