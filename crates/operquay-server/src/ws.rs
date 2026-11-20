use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use futures_util::StreamExt;
use operquay_aws::accounts::AwsAccountStore;
use operquay_aws::sigv4::AwsCredentials;
use operquay_core::{
    CertPolicy, DesktopEngine, DesktopSessionInput, DisplaySink, SecretString, SessionConfig,
};
use operquay_display::{DisplayOp, FrameEncodeConfig, FramebufferPlanner, Oqr2Message};
use operquay_guac::{ClientInstruction, GuacInstruction, GuacParser, SyncTracker};
use operquay_rdp::connect_live_rdp_host;
use operquay_recording::RecordingTee;
use operquay_ssm::SsmVirtualStream;
use operquay_telemetry::TelemetryHub;
use operquay_vnc::{connect_live_vnc_host, run_live_vnc_over_stream};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::Instrument;
use uuid::Uuid;

use crate::stores::{LaunchMode, TicketLaunchPayload};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct WsConnectQuery {
    pub ticket: Option<String>,
    pub token: Option<String>,
    pub protocol: Option<String>,
    pub mode: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub target: Option<String>,
    pub layout: Option<String>,
    pub tenant: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Oqr2ClientEvent {
    Pointer { x: u16, y: u16, button_mask: u8 },
    Key { keysym: u32, pressed: bool },
    Resize { width: u32, height: u32 },
    KeyboardLayout { layout: String },
    Clipboard { text: String },
    Sas,
    SyncAck { server_ts_ms: u64 },
}

enum OutboundFrame {
    Oqr2(Oqr2Message),
    Guac(String),
    Progress {
        stage: &'static str,
        label: &'static str,
        percent: u8,
    },
    Error(String),
}

struct PlannerDisplaySink {
    tx: mpsc::Sender<OutboundFrame>,
    planner: Mutex<FramebufferPlanner>,
    sync: Mutex<SyncTracker>,
    recording: Arc<Mutex<Option<RecordingTee>>>,
    recording_aborted: AtomicBool,
    binary_mode: bool,
    quality_floor: Mutex<u8>,
    telemetry: Arc<TelemetryHub>,
    protocol: String,
    stream_seq: AtomicU32,
    dropped_frames: AtomicU64,
    dropped_total: Arc<AtomicU64>,
    config: Mutex<FrameEncodeConfig>,
}

impl PlannerDisplaySink {
    fn abort_with_recording_error(&self, reason: String) {
        if !self.recording_aborted.swap(true, Ordering::AcqRel) {
            self.telemetry.record_frame_dropped("recording_fail_closed");
            let _ = self.tx.try_send(OutboundFrame::Error(reason));
        }
    }

    fn record_guac_line(&self, line: &str) -> bool {
        if self.recording_aborted.load(Ordering::Acquire) {
            return false;
        }
        let res = {
            if let Ok(mut guard) = self.recording.lock() {
                if let Some(tee) = guard.as_mut() {
                    tee.record_guac_line(line)
                } else {
                    Ok(())
                }
            } else {
                Ok(())
            }
        };
        if let Err(err) = res {
            self.abort_with_recording_error(err.to_string());
            return false;
        }
        true
    }

    fn emit_oqr2_or_guac(&self, msg: Oqr2Message, guac_fallback: Option<Vec<GuacInstruction>>) {
        if self.recording_aborted.load(Ordering::Acquire) {
            return;
        }
        if self.binary_mode {
            if self.tx.try_send(OutboundFrame::Oqr2(msg)).is_err() {
                self.dropped_frames.fetch_add(1, Ordering::Relaxed);
                self.dropped_total.fetch_add(1, Ordering::Relaxed);
                self.telemetry.record_frame_dropped("channel_backpressure");
            }
        } else if let Some(list) = guac_fallback {
            for inst in list {
                let encoded = inst.encode();
                if self.tx.try_send(OutboundFrame::Guac(encoded)).is_err() {
                    self.dropped_frames.fetch_add(1, Ordering::Relaxed);
                    self.dropped_total.fetch_add(1, Ordering::Relaxed);
                    self.telemetry.record_frame_dropped("channel_backpressure");
                    break;
                }
            }
        }
    }
}

impl DisplaySink for PlannerDisplaySink {
    fn resize(&self, layer_id: i32, width: u32, height: u32) {
        if let Ok(mut p) = self.planner.lock() {
            p.resize(width, height);
            p.mark_all_dirty();
        }
        let guac = GuacInstruction::new(
            "size",
            vec![layer_id.to_string(), width.to_string(), height.to_string()],
        );
        if !self.record_guac_line(&guac.encode()) {
            return;
        }
        let msg = Oqr2Message::ResizeSurface {
            layer: layer_id,
            w: width as u16,
            h: height as u16,
        };
        self.emit_oqr2_or_guac(msg, Some(vec![guac]));
    }

    fn draw_rgba_rect(
        &self,
        _layer_id: i32,
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        rgba: &[u8],
        stride: usize,
    ) {
        if let Ok(mut p) = self.planner.lock() {
            p.draw_rgba_rect(x, y, w, h, rgba, stride);
        }
    }

    fn draw_jpeg_rect(&self, layer_id: i32, x: u32, y: u32, w: u32, h: u32, jpeg: &[u8]) {
        let op = DisplayOp::ImageJpeg {
            x,
            y,
            w,
            h,
            bytes: jpeg.to_vec(),
        };
        let stream_idx = self.stream_seq.fetch_add(1, Ordering::Relaxed);
        let guac_ops = op.to_guac_instructions(layer_id, stream_idx);
        for g in &guac_ops {
            if !self.record_guac_line(&g.encode()) {
                return;
            }
        }
        self.emit_oqr2_or_guac(op.to_oqr2(layer_id), Some(guac_ops));
    }

    fn fill_solid_rect(&self, _layer_id: i32, x: u32, y: u32, w: u32, h: u32, rgba: [u8; 4]) {
        if let Ok(mut p) = self.planner.lock() {
            p.fill_solid_rect(x, y, w, h, rgba);
        }
    }

    fn copy_rect(
        &self,
        _src_layer: i32,
        sx: u32,
        sy: u32,
        w: u32,
        h: u32,
        _dst_layer: i32,
        dx: u32,
        dy: u32,
    ) {
        if let Ok(mut p) = self.planner.lock() {
            p.copy_rect_in_back(sx, sy, w, h, dx, dy);
        }
    }

    fn set_cursor(&self, hot_x: u32, hot_y: u32, w: u32, h: u32, rgba: &[u8]) {
        if self.binary_mode {
            let msg = Oqr2Message::CursorShape {
                hot_x: hot_x as u16,
                hot_y: hot_y as u16,
                w: w as u16,
                h: h as u16,
                rgba: rgba.to_vec(),
            };
            self.emit_oqr2_or_guac(msg, None);
        }
    }

    fn move_cursor(&self, x: u32, y: u32) {
        if self.binary_mode {
            let msg = Oqr2Message::CursorMove {
                x: x as u16,
                y: y as u16,
            };
            self.emit_oqr2_or_guac(msg, None);
        } else {
            let guac = GuacInstruction::new("mouse", vec![x.to_string(), y.to_string()]);
            let _ = self.tx.try_send(OutboundFrame::Guac(guac.encode()));
        }
    }

    fn flush_frame(&self, timestamp_ms: u64) {
        if self.recording_aborted.load(Ordering::Acquire) {
            return;
        }
        let start = Instant::now();
        let (in_flight, lag_ms, dynamic_q) = if let Ok(sync) = self.sync.lock() {
            let floor = self.quality_floor.lock().map_or(55, |f| *f);
            (
                sync.in_flight_count(),
                sync.processing_lag_ms(),
                sync.adaptive_jpeg_quality(floor),
            )
        } else {
            (0, 0, 90)
        };

        if in_flight >= 3 && lag_ms > 180 {
            self.dropped_frames.fetch_add(1, Ordering::Relaxed);
            self.dropped_total.fetch_add(1, Ordering::Relaxed);
            self.telemetry.record_frame_dropped("sync_congestion");
            return;
        }

        let mut cfg = self
            .config
            .lock()
            .map_or_else(|_| FrameEncodeConfig::default(), |c| c.clone());
        cfg.jpeg_quality = dynamic_q;

        let (ops, _stats) = if let Ok(mut planner) = self.planner.lock() {
            planner.flush(&cfg)
        } else {
            return;
        };

        let encode_ms = start.elapsed().as_secs_f64() * 1000.0;
        let codec_tag = if cfg.codec_mode == operquay_core::CodecMode::LosslessCrisp {
            "oqr2_lossless_png"
        } else {
            "oqr2_hybrid"
        };
        self.telemetry.record_frame_encoded(codec_tag, encode_ms);

        for op in ops {
            let sidx = self.stream_seq.fetch_add(1, Ordering::Relaxed) % 60;
            // Fail-closed recording commit MUST succeed before network frame emit
            let rec_res = {
                if let Ok(mut guard) = self.recording.lock() {
                    if let Some(tee) = guard.as_mut() {
                        tee.record_display_op(&op, sidx)
                    } else {
                        Ok(())
                    }
                } else {
                    Ok(())
                }
            };
            if let Err(err) = rec_res {
                self.abort_with_recording_error(err.to_string());
                return;
            }

            let guac = if self.binary_mode {
                None
            } else {
                Some(op.to_guac_instructions(0, sidx))
            };
            self.emit_oqr2_or_guac(op.to_oqr2(0), guac);
        }

        if let Ok(mut sync) = self.sync.lock() {
            sync.record_sent(timestamp_ms, Instant::now());
        }

        let sync_guac = GuacInstruction::new("sync", vec![timestamp_ms.to_string()]);
        if !self.record_guac_line(&sync_guac.encode()) {
            return;
        }
        let stats_msg = Oqr2Message::StatsSync {
            server_ts_ms: timestamp_ms,
            lag_ms,
            fps: cfg.estimated_fps,
            jpeg_quality: dynamic_q,
            dropped_frames: self.dropped_total.load(Ordering::Relaxed),
            codec_tag: format!("{}:{}", self.protocol, codec_tag),
        };
        self.emit_oqr2_or_guac(stats_msg, Some(vec![sync_guac]));
    }

    fn draw_h264_nalu(&self, layer_id: i32, x: u32, y: u32, w: u32, h: u32, annex_b: &[u8]) {
        if self.binary_mode && !annex_b.is_empty() {
            let msg = Oqr2Message::H264Frame {
                layer: layer_id,
                x: x as u16,
                y: y as u16,
                w: w as u16,
                h: h as u16,
                annex_b: annex_b.to_vec(),
            };
            self.emit_oqr2_or_guac(msg, None);
        }
    }

    fn on_clipboard_text(&self, text: &str) {
        if self.binary_mode {
            let msg = Oqr2Message::ClipboardText {
                text: text.to_owned(),
            };
            self.emit_oqr2_or_guac(msg, None);
        }
    }
}

pub async fn ws_desktop_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(query): Query<WsConnectQuery>,
) -> impl IntoResponse {
    let redeemed = if let Some(raw_ticket) = query.ticket.as_ref().or(query.token.as_ref()) {
        let Ok(ticket_uuid) = Uuid::parse_str(raw_ticket.trim()) else {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "malformed session ticket" })),
            )
                .into_response();
        };
        let Some(payload) = state.tickets.redeem(ticket_uuid).await else {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "invalid, expired, or already-used session ticket" })),
            )
                .into_response();
        };
        Some(payload)
    } else {
        #[cfg(not(test))]
        {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "session ticket is required; mock desktop sessions are disabled" })),
            )
                .into_response();
        }
        #[cfg(test)]
        None
    };

    ws.protocols(["operquay-rdp-v2", "guacamole"])
        .on_upgrade(move |socket| handle_ws_connection(socket, state, query, redeemed))
}

fn classic_rdp_hints(
) -> &'static tokio::sync::RwLock<std::collections::HashMap<(String, String), Instant>> {
    static HINTS: std::sync::OnceLock<
        tokio::sync::RwLock<std::collections::HashMap<(String, String), Instant>>,
    > = std::sync::OnceLock::new();
    HINTS.get_or_init(|| tokio::sync::RwLock::new(std::collections::HashMap::new()))
}

enum SessionDriver {
    Demo {
        engine: Box<dyn DesktopEngine>,
    },
    Live {
        input_tx: mpsc::Sender<DesktopSessionInput>,
        shutdown: Arc<Notify>,
        error_rx: Option<oneshot::Receiver<Result<(), String>>>,
    },
}

async fn handle_ws_connection(
    mut socket: WebSocket,
    state: AppState,
    query: WsConnectQuery,
    ticket: Option<TicketLaunchPayload>,
) {
    let session_id = ticket
        .as_ref()
        .map_or_else(|| Uuid::new_v4().to_string(), |t| t.session_id.clone());
    let tenant = ticket.as_ref().map_or_else(
        || query.tenant.as_deref().unwrap_or("default").to_owned(),
        |t| t.tenant_id.clone(),
    );
    let user_id = ticket
        .as_ref()
        .map_or_else(String::new, |t| t.user_id.clone());
    let auth_session_id = ticket
        .as_ref()
        .map_or_else(String::new, |t| t.auth_session_id.clone());
    let protocol = ticket.as_ref().map_or_else(
        || query.protocol.as_deref().unwrap_or("rdp").to_owned(),
        |t| t.protocol.clone(),
    );
    let launch_mode = ticket.as_ref().map_or(LaunchMode::Demo, |t| t.launch_mode);
    let mode_str = ticket
        .as_ref()
        .and_then(|t| t.transport_mode.as_deref())
        .or(query.mode.as_deref())
        .unwrap_or("oqr2");
    let binary_mode = mode_str != "guacamole";

    let mut settings = state.settings.get(&tenant).await.unwrap_or_default();
    if let Some(layout) = ticket
        .as_ref()
        .and_then(|t| t.keyboard_layout.as_ref())
        .or(query.layout.as_ref())
    {
        settings.keyboard_layout = layout.clone();
    }

    let width = query
        .width
        .unwrap_or_else(|| ticket.as_ref().map_or(1280, |t| t.width))
        .clamp(200, 4096)
        & !1;
    let height = query
        .height
        .unwrap_or_else(|| ticket.as_ref().map_or(720, |t| t.height))
        .clamp(200, 4096);

    let target_host = ticket.as_ref().map_or_else(
        || {
            query
                .target
                .clone()
                .unwrap_or_else(|| "win2025-ssm.internal".into())
        },
        |t| t.target_host.clone(),
    );
    let target_port = ticket.as_ref().map_or_else(
        || if protocol == "vnc" { 5900 } else { 3389 },
        |t| t.target_port,
    );
    let username = ticket
        .as_ref()
        .map_or_else(|| "operator".to_owned(), |t| t.username.clone());
    let password = ticket
        .as_ref()
        .map_or_else(|| SecretString::new(""), |t| t.password.clone());
    let expected_pin = ticket.as_ref().and_then(|t| t.expected_cert_sha256);
    if let Some(sec_mode) = ticket.as_ref().and_then(|t| t.rdp_security_mode) {
        settings.rdp_security_mode = sec_mode;
    }
    let simulate_fault = ticket.as_ref().is_some_and(|t| t.simulate_recording_fault);
    let ticket_aws_profile = ticket.as_ref().and_then(|t| t.aws_profile.clone());
    let ticket_aws_region = ticket.as_ref().and_then(|t| t.aws_region.clone());

    let span = tracing::info_span!(
        "operquay.desktop.session",
        session_id = %session_id,
        protocol = %protocol,
        preset = settings.network_preset.as_str(),
        binary_mode = binary_mode
    );

    async move {
        let trace_id = TelemetryHub::current_trace_id_hex();
        state
            .telemetry
            .record_session_started(&protocol, settings.network_preset.as_str());

        let rec_policy = state
            .platform
            .rec_policies
            .read()
            .await
            .get(&tenant)
            .cloned()
            .unwrap_or_default();
        let should_record = simulate_fault
            || rec_policy.should_record_instance(&protocol, &target_host, "");
        let recording_arc = if should_record {
            state.ensure_tenant_dek_persisted(&tenant).await;
            let mut tee = match state
                .recordings
                .start_session(
                    session_id.clone(),
                    tenant.clone(),
                    protocol.clone(),
                    target_host.clone(),
                    settings.fail_closed_recording,
                )
                .await
            {
                Ok(t) => t,
                Err(err) => {
                    let _ = socket
                        .send(Message::Text(
                            serde_json::json!({ "type": "error", "error": err.to_string() })
                                .to_string()
                                .into(),
                        ))
                        .await;
                    state.telemetry.record_session_ended(&protocol);
                    return;
                }
            };
            if simulate_fault {
                tee.simulated_fault = true;
            }
            let _ = tee.record_guac_line(
                &GuacInstruction::new("size", vec!["0".into(), width.to_string(), height.to_string()])
                    .encode(),
            );
            Arc::new(Mutex::new(Some(tee)))
        } else {
            Arc::new(Mutex::new(None))
        };

        if launch_mode == LaunchMode::SsmTunnel
            && expected_pin.is_none()
            && state
                .cert_pins
                .get_pin(&tenant, &target_host, target_port, &protocol)
                .await
                .is_none()
        {
            settings.cert_policy = operquay_core::CertPolicy::SsmLoopbackIgnore;
        }

        let mut cfg = SessionConfig {
            session_id: session_id.clone(),
            tenant_id: tenant.clone(),
            protocol: protocol.clone(),
            target_host: target_host.clone(),
            target_port,
            width,
            height,
            dpi: 96,
            username: username.clone(),
            password,
            settings: settings.clone(),
        };
        let compliance = operquay_core::compliance_mode_enabled();
        let legacy_ssm_allowed =
            launch_mode == LaunchMode::SsmTunnel && cfg.settings.allow_legacy_crypto_over_ssm;
        if matches!(
            cfg.settings.rdp_security_mode,
            operquay_core::RdpSecurityMode::Any
        ) && (!compliance || legacy_ssm_allowed)
        {
            if let Some(hinted_at) = classic_rdp_hints()
                .read()
                .await
                .get(&(tenant.clone(), target_host.clone()))
                .copied()
            {
                if hinted_at.elapsed() < Duration::from_mins(15) {
                    cfg.settings.rdp_security_mode = operquay_core::RdpSecurityMode::ClassicRdp;
                }
            }
        }

        let (tx, mut rx) = mpsc::channel::<OutboundFrame>(256);
        let dropped_total = Arc::new(AtomicU64::new(0));
        let sink = Arc::new(PlannerDisplaySink {
            tx,
            planner: Mutex::new(FramebufferPlanner::new(width, height)),
            sync: Mutex::new(SyncTracker::new()),
            recording: recording_arc.clone(),
            recording_aborted: AtomicBool::new(false),
            binary_mode,
            quality_floor: Mutex::new(settings.jpeg_quality_floor),
            telemetry: state.telemetry.clone(),
            protocol: protocol.clone(),
            stream_seq: AtomicU32::new(1),
            dropped_frames: AtomicU64::new(0),
            dropped_total,
            config: Mutex::new(FrameEncodeConfig {
                codec_mode: settings.codec_mode,
                jpeg_quality: settings.jpeg_quality_floor,
                enable_copy_rect: settings.enable_copy_rect,
                estimated_fps: u16::from(settings.target_fps),
            }),
        });

        let mut driver = match launch_mode {
            LaunchMode::Demo => match state.engines.create_engine(&protocol, cfg) {
                Ok(engine) => SessionDriver::Demo { engine },
                Err(err) => {
                    let _ = socket
                        .send(Message::Text(
                            serde_json::json!({ "type": "error", "error": err.to_string() })
                                .to_string()
                                .into(),
                        ))
                        .await;
                    finalize_session_audit(&state, &recording_arc, &tenant, &trace_id, &session_id, &protocol, &target_host, "session_error").await;
                    return;
                }
            },
            LaunchMode::DirectTcp => {
                let (input_tx, input_rx) = mpsc::channel::<DesktopSessionInput>(128);
                let shutdown = Arc::new(Notify::new());
                let (err_tx, error_rx) = oneshot::channel::<Result<(), String>>();
                let existing_pin = match expected_pin {
                    Some(pin) => Some(pin),
                    None => {
                        state
                            .cert_pins
                            .get_pin(&tenant, &target_host, target_port, &protocol)
                            .await
                    }
                };
                let sink_dyn: Arc<dyn DisplaySink> = sink.clone();
                let shut_c = shutdown.clone();
                let pins = state.cert_pins.clone();
                let host_c = target_host.clone();
                let tenant_c = tenant.clone();
                let proto_c = protocol.clone();
                let policy = cfg.settings.cert_policy;
                let tx_prog = sink.tx.clone();
                tokio::spawn(async move {
                    let _ = tx_prog
                        .send(OutboundFrame::Progress {
                            stage: "tcp",
                            label: "Connecting to remote desktop...",
                            percent: 25,
                        })
                        .await;
                    let res = match proto_c.as_str() {
                        "vnc" => {
                            connect_live_vnc_host(
                                &host_c,
                                target_port,
                                &cfg,
                                sink_dyn,
                                input_rx,
                                shut_c,
                            )
                            .await
                        }
                        _ => {
                            match connect_live_rdp_host(
                                &host_c,
                                target_port,
                                &cfg,
                                sink_dyn,
                                input_rx,
                                existing_pin,
                                shut_c,
                            )
                            .await
                            {
                                Ok(fp) => {
                                    if policy == CertPolicy::TofuPinned {
                                        pins.pin_if_absent(
                                            &tenant_c,
                                            &host_c,
                                            target_port,
                                            &proto_c,
                                            fp,
                                        )
                                        .await;
                                    }
                                    Ok(())
                                }
                                Err(e) => Err(e),
                            }
                        }
                    };
                    let _ = err_tx.send(res.map_err(|e| e.to_string()));
                });
                SessionDriver::Live {
                    input_tx,
                    shutdown,
                    error_rx: Some(error_rx),
                }
            }
            LaunchMode::SsmTunnel => {
                state.telemetry.record_ssm_tunnel(&protocol, "started");
                let (input_tx, input_rx) = mpsc::channel::<DesktopSessionInput>(128);
                let shutdown = Arc::new(Notify::new());
                let (err_tx, error_rx) = oneshot::channel::<Result<(), String>>();
                let sink_dyn: Arc<dyn DisplaySink> = sink.clone();
                let shut_c = shutdown.clone();
                let host_c = target_host.clone();
                let proto_c = protocol.clone();
                let w_u16 = width as u16;
                let h_u16 = height as u16;
                let existing_pin = match expected_pin {
                    Some(pin) => Some(pin),
                    None => {
                        state
                            .cert_pins
                            .get_pin(&tenant, &target_host, target_port, &protocol)
                            .await
                    }
                };
                let aws_accounts = state.aws.accounts.clone();
                let aws_shells = state.aws.shells.clone();
                let aws_discovery = state.aws.discovery.clone();
                let tenant_aws = tenant.clone();
                let audit_c = state.audit.clone();
                let trace_c = trace_id.clone();
                let sid_c = session_id.clone();
                let ticket_aws_profile_c = ticket_aws_profile.clone();
                let (prog_tx, mut prog_rx) =
                    mpsc::channel::<(&'static str, &'static str, u8)>(32);
                let tx_prog = sink.tx.clone();
                tokio::spawn(async move {
                    while let Some((stage, label, percent)) = prog_rx.recv().await {
                        if tx_prog
                            .send(OutboundFrame::Progress {
                                stage,
                                label,
                                percent,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
                tokio::spawn(async move {
                    let _ = prog_tx.try_send((
                        "ssm",
                        "Opening AWS SSM Port-Forwarding tunnel...",
                        20,
                    ));
                    let is_real_instance =
                        host_c.starts_with("i-") || host_c.starts_with("mi-");
                    let (client_ssm, live_meta): (
                        SsmVirtualStream,
                        Option<(String, String, AwsCredentials)>,
                    ) = if host_c == "ssm-loopback" || target_port == 0 {
                        let (client, mut agent) = SsmVirtualStream::loopback_pair(64);
                        tokio::spawn(async move {
                            run_ssm_loopback_vnc_peer(&mut agent, w_u16, h_u16).await;
                        });
                        (client, None)
                    } else if is_real_instance {
                        let discovered_region = aws_discovery
                            .find_instance(&tenant_aws, &host_c)
                            .await
                            .map(|i| i.region);
                        let Some((creds, profile_region)) = resolve_tenant_aws_creds_and_region(
                            &aws_accounts,
                            &tenant_aws,
                            ticket_aws_profile_c.as_deref(),
                        )
                        .await
                        else {
                            let _ = err_tx.send(Err(format!(
                                "No AWS credentials configured for live SSM tunnel to {host_c} (checked tenant accounts, env vars, and ~/.aws profiles)"
                            )));
                            return;
                        };
                        let region = ticket_aws_region
                            .clone()
                            .filter(|r| !r.trim().is_empty())
                            .or(discovered_region)
                            .or(profile_region)
                            .or_else(|| {
                                std::env::var("AWS_REGION")
                                    .ok()
                                    .filter(|r| !r.trim().is_empty())
                            })
                            .unwrap_or_else(|| "us-east-1".to_owned());
                        match aws_shells
                            .connect_port_forward_tunnel(
                                &region,
                                &host_c,
                                target_port,
                                &creds,
                                shut_c.clone(),
                            )
                            .await
                        {
                            Ok((started, stream)) => (stream, Some((region, started.session_id, creds))),
                            Err(e) => {
                                let _ = err_tx.send(Err(e));
                                return;
                            }
                        }
                    } else {
                        let (client, mut agent) = SsmVirtualStream::loopback_pair(64);
                        let peer_addr = format!("{host_c}:{target_port}");
                        tokio::spawn(async move {
                            if let Ok(mut tcp) = TcpStream::connect(peer_addr).await {
                                let _ = tcp.set_nodelay(true);
                                let _ = tokio::io::copy_bidirectional(&mut agent, &mut tcp).await;
                            }
                        });
                        (client, None)
                    };

                    let mut live_meta = live_meta;
                    let res = if host_c == "ssm-loopback" || proto_c == "vnc" {
                        run_live_vnc_over_stream(
                            client_ssm,
                            &cfg,
                            sink_dyn,
                            input_rx,
                            shut_c,
                        )
                        .await
                    } else {
                        let mut input_rx = input_rx;
                        let first_res = operquay_rdp::run_live_rdp_over_stream_with_progress(
                            client_ssm,
                            &cfg,
                            sink_dyn.clone(),
                            &mut input_rx,
                            existing_pin,
                            shut_c.clone(),
                            Some(prog_tx.clone()),
                        )
                        .await
                        .map(|_| ());
                        match first_res {
                            Ok(()) => Ok(()),
                            Err(err)
                                if operquay_rdp::is_standard_rdp_only_error(&err)
                                    && matches!(
                                        cfg.settings.rdp_security_mode,
                                        operquay_core::RdpSecurityMode::Any
                                    ) =>
                            {
                                if compliance && !cfg.settings.allow_legacy_crypto_over_ssm {
                                    audit_c
                                        .record(
                                            &tenant_aws,
                                            &trace_c,
                                            &sid_c,
                                            "legacy_crypto_blocked",
                                            &proto_c,
                                            &host_c,
                                            "Blocked Standard RDP Security (RC4) fallback in Compliance Mode",
                                            Some(sid_c.clone()),
                                        )
                                        .await;
                                    Err(operquay_core::OperquayError::SecurityPolicy(
                                        "Standard RDP Security (RC4) fallback is blocked in Compliance Mode unless allow_legacy_crypto_over_ssm is enabled"
                                            .to_owned(),
                                    ))
                                } else {
                                    if compliance {
                                        audit_c
                                            .record(
                                                &tenant_aws,
                                                &trace_c,
                                                &sid_c,
                                                "legacy_crypto_ssm_exception",
                                                &proto_c,
                                                &host_c,
                                                "Allowed Standard RDP Security (RC4) fallback under explicit AWS SSM exception",
                                                Some(sid_c.clone()),
                                            )
                                            .await;
                                    }
                                    classic_rdp_hints()
                                        .write()
                                        .await
                                        .insert((tenant_aws.clone(), host_c.clone()), Instant::now());
                                    if let Some((reg, sid, creds)) = live_meta.take() {
                                        let _ = aws_shells.terminate_session(&reg, &sid, &creds).await;
                                        tracing::warn!(
                                            instance_id = %host_c,
                                            region = %reg,
                                            "Target rejected Enhanced RDP Security; retrying SSM tunnel with Standard RDP Security"
                                        );
                                        let _ = prog_tx.try_send((
                                            "rdp-retry",
                                            "Retrying tunnel with Standard RDP Security...",
                                            48,
                                        ));
                                        let mut fallback_cfg = cfg.clone();
                                        fallback_cfg.settings.rdp_security_mode =
                                            operquay_core::RdpSecurityMode::ClassicRdp;
                                        match aws_shells
                                            .connect_port_forward_tunnel(
                                                &reg,
                                                &host_c,
                                                target_port,
                                                &creds,
                                                shut_c.clone(),
                                            )
                                            .await
                                        {
                                            Ok((started2, stream2)) => {
                                                live_meta =
                                                    Some((reg, started2.session_id, creds));
                                                operquay_rdp::run_live_rdp_over_stream_with_progress(
                                                    stream2,
                                                    &fallback_cfg,
                                                    sink_dyn,
                                                    &mut input_rx,
                                                    existing_pin,
                                                    shut_c,
                                                    Some(prog_tx.clone()),
                                                )
                                                .await
                                                .map(|_| ())
                                            }
                                            Err(e2) => Err(operquay_core::OperquayError::Protocol(e2)),
                                        }
                                    } else {
                                        Err(err)
                                    }
                                }
                            }
                            Err(err) => Err(err),
                        }
                    };
                    if let Some((reg, sid, creds)) = live_meta {
                        let _ = aws_shells.terminate_session(&reg, &sid, &creds).await;
                    }
                    let _ = err_tx.send(res.map_err(|e| e.to_string()));
                });
                SessionDriver::Live {
                    input_tx,
                    shutdown,
                    error_rx: Some(error_rx),
                }
            }
        };

        state
            .audit
            .record(
                &tenant,
                &trace_id,
                &session_id,
                "session_connected",
                &protocol,
                &target_host,
                format!("mode={launch_mode:?} binary={binary_mode} fail_closed={}", settings.fail_closed_recording),
                Some(session_id.clone()),
            )
            .await;

        let mut seq: u32 = 1;
        if binary_mode {
            let hello = Oqr2Message::HelloAck {
                width: width as u16,
                height: height as u16,
                cursor_prediction: settings.enable_local_cursor_prediction,
                trace_id: trace_id.clone(),
                protocol: protocol.clone(),
            };
            if socket
                .send(Message::Binary(hello.encode(seq).into()))
                .await
                .is_err()
            {
                finalize_session_audit(&state, &recording_arc, &tenant, &trace_id, &session_id, &protocol, &target_host, "session_closed").await;
                return;
            }
            seq += 1;
        } else {
            let ready = GuacInstruction::new("ready", vec![session_id.clone()]).encode();
            if socket.send(Message::Text(ready.into())).await.is_err() {
                finalize_session_audit(&state, &recording_arc, &tenant, &trace_id, &session_id, &protocol, &target_host, "session_closed").await;
                return;
            }
        }

        if let SessionDriver::Demo { ref mut engine } = driver {
            let _ = engine.tick(sink.as_ref()).await;
        }

        let mut tick_interval = tokio::time::interval(Duration::from_millis(
            (1000 / u64::from(settings.target_fps.max(10))).max(16),
        ));
        let mut guac_parser = GuacParser::new();
        let mut live_err_rx = match &mut driver {
            SessionDriver::Live { error_rx, .. } => error_rx.take(),
            SessionDriver::Demo { .. } => None,
        };
        let aws_binding_for_fence = if launch_mode == LaunchMode::SsmTunnel {
            Some(
                ticket_aws_profile
                    .as_deref()
                    .and_then(|p| p.strip_prefix("user:"))
                    .filter(|s| !s.is_empty())
                    .unwrap_or("aws-ssm"),
            )
        } else {
            None
        };
        let auth_check_active = !user_id.is_empty()
            && !auth_session_id.is_empty()
            && auth_session_id != "anonymous-lab";
        let mut fence_guard = state.session_fence.register_with_session(
            &tenant,
            &user_id,
            &auth_session_id,
            aws_binding_for_fence,
            &session_id,
            None,
        );
        let mod_handle = state.moderation.register_session(
            &tenant,
            &session_id,
            &protocol,
            &target_host,
            &user_id,
            &username,
            should_record.then(|| session_id.clone()),
        );
        let mut fence_tick = tokio::time::interval(Duration::from_secs(5));
        fence_tick.tick().await;

        let mut close_action = "session_closed";

        loop {
            tokio::select! {
                biased;

                reason = fence_guard.revoked() => {
                    close_action = "session_revoked";
                    let _ = socket
                        .send(Message::Text(
                            serde_json::json!({
                                "type": "session_ended",
                                "reason": reason
                            })
                            .to_string()
                            .into(),
                        ))
                        .await;
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }

                _ = fence_tick.tick(), if auth_check_active => {
                    if !state
                        .auth
                        .is_session_active(&tenant, &auth_session_id, &user_id)
                        .await
                    {
                        close_action = "session_revoked";
                        let _ = socket
                            .send(Message::Text(
                                serde_json::json!({
                                    "type": "session_ended",
                                    "reason": "session_revoked_or_expired"
                                })
                                .to_string()
                                .into(),
                            ))
                            .await;
                        let _ = socket.send(Message::Close(None)).await;
                        break;
                    }
                }

                err_res = async {
                    match &mut live_err_rx {
                        Some(rx_e) => rx_e.await,
                        None => std::future::pending().await,
                    }
                } => {
                    live_err_rx = None;
                    match err_res {
                        Ok(Ok(())) => {
                            close_action = "remote_logout";
                            let _ = socket
                                .send(Message::Text(
                                    serde_json::json!({
                                        "type": "session_ended",
                                        "reason": "remote_logout"
                                    })
                                    .to_string()
                                    .into(),
                                ))
                                .await;
                            let _ = socket.send(Message::Close(None)).await;
                            break;
                        }
                        Ok(Err(err_msg)) => {
                            close_action = "session_error";
                            let _ = socket
                                .send(Message::Text(
                                    serde_json::json!({ "type": "error", "error": err_msg })
                                        .to_string()
                                        .into(),
                                ))
                                .await;
                            let _ = socket.send(Message::Close(None)).await;
                            break;
                        }
                        Err(_) => {}
                    }
                }

                inbound = socket.next() => {
                    match inbound {
                        Some(Ok(Message::Text(txt))) => {
                            if binary_mode {
                                if let Ok(ev) = serde_json::from_str::<Oqr2ClientEvent>(&txt) {
                                    let frozen = mod_handle.is_frozen();
                                    match ev {
                                        Oqr2ClientEvent::Pointer { x, y, button_mask } => {
                                            if !frozen {
                                                dispatch_input(&mut driver, sink.as_ref(), DesktopSessionInput::Pointer { x, y, button_mask }, false).await;
                                            }
                                        }
                                        Oqr2ClientEvent::Key { keysym, pressed } => {
                                            if !frozen {
                                                dispatch_input(&mut driver, sink.as_ref(), DesktopSessionInput::Key { keysym, pressed }, false).await;
                                            }
                                        }
                                        Oqr2ClientEvent::Resize { width, height } => {
                                            dispatch_input(&mut driver, sink.as_ref(), DesktopSessionInput::Resize { width, height, dpi: 96 }, true).await;
                                        }
                                        Oqr2ClientEvent::KeyboardLayout { layout } => {
                                            if !frozen {
                                                dispatch_input(&mut driver, sink.as_ref(), DesktopSessionInput::KeyboardLayout { layout }, true).await;
                                            }
                                        }
                                        Oqr2ClientEvent::Clipboard { text } => {
                                            if !frozen {
                                                dispatch_input(&mut driver, sink.as_ref(), DesktopSessionInput::ClipboardText { text }, false).await;
                                            }
                                        }
                                        Oqr2ClientEvent::Sas => {
                                            if !frozen {
                                                dispatch_input(&mut driver, sink.as_ref(), DesktopSessionInput::SecureAttentionSequence, true).await;
                                            }
                                        }
                                        Oqr2ClientEvent::SyncAck { server_ts_ms } => {
                                            if let Ok(mut sync) = sink.sync.lock() {
                                                if let Some(rtt) = sync.record_ack(server_ts_ms, Instant::now()) {
                                                    state.telemetry.record_input_rtt(&protocol, rtt.as_secs_f64() * 1000.0);
                                                }
                                            }
                                        }
                                    }
                                }
                            } else if let Ok(list) = guac_parser.push_str(&txt) {
                                let frozen = mod_handle.is_frozen();
                                for inst in list {
                                    match inst.into_client() {
                                        ClientInstruction::Mouse { x, y, button_mask } => {
                                            if !frozen {
                                                dispatch_input(&mut driver, sink.as_ref(), DesktopSessionInput::Pointer { x, y, button_mask }, false).await;
                                            }
                                        }
                                        ClientInstruction::Key { keysym, pressed } => {
                                            if !frozen {
                                                dispatch_input(&mut driver, sink.as_ref(), DesktopSessionInput::Key { keysym, pressed }, false).await;
                                            }
                                        }
                                        ClientInstruction::Size { width, height, dpi } => {
                                            dispatch_input(&mut driver, sink.as_ref(), DesktopSessionInput::Resize { width, height, dpi }, true).await;
                                        }
                                        ClientInstruction::Sync { timestamp_ms } => {
                                            if let Ok(mut sync) = sink.sync.lock() {
                                                if let Some(rtt) = sync.record_ack(timestamp_ms, Instant::now()) {
                                                    state.telemetry.record_input_rtt(&protocol, rtt.as_secs_f64() * 1000.0);
                                                }
                                            }
                                        }
                                        ClientInstruction::Disconnect => {
                                            break;
                                        }
                                        ClientInstruction::Nop | ClientInstruction::Other(_) => {}
                                    }
                                }
                            }
                        }
                        Some(Ok(Message::Ping(payload))) => {
                            let _ = socket.send(Message::Pong(payload)).await;
                        }
                        Some(Ok(Message::Close(_)) | Err(_)) | None => {
                            break;
                        }
                        Some(Ok(_)) => {}
                    }
                }

                outbound = rx.recv() => {
                    match outbound {
                        Some(OutboundFrame::Oqr2(msg)) => {
                            seq = seq.wrapping_add(1);
                            if socket.send(Message::Binary(msg.encode(seq).into())).await.is_err() {
                                break;
                            }
                        }
                        Some(OutboundFrame::Guac(text)) => {
                            if socket.send(Message::Text(text.into())).await.is_err() {
                                break;
                            }
                        }
                        Some(OutboundFrame::Progress {
                            stage,
                            label,
                            percent,
                        }) => {
                            if socket
                                .send(Message::Text(
                                    serde_json::json!({
                                        "type": "progress",
                                        "stage": stage,
                                        "label": label,
                                        "percent": percent,
                                    })
                                    .to_string()
                                    .into(),
                                ))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Some(OutboundFrame::Error(reason)) => {
                            close_action = "recording_fail_closed_abort";
                            let _ = socket.send(Message::Text(serde_json::json!({ "type": "error", "code": "recording_required", "error": reason }).to_string().into())).await;
                            let _ = socket.send(Message::Close(None)).await;
                            break;
                        }
                        None => break,
                    }
                }

                _ = tick_interval.tick() => {
                    if let SessionDriver::Demo { ref mut engine } = driver {
                        let _ = engine.tick(sink.as_ref()).await;
                    }
                    if sink.recording_aborted.load(Ordering::Acquire) {
                        close_action = "recording_fail_closed_abort";
                        break;
                    }
                }
            }
        }

        if let SessionDriver::Live { shutdown, .. } = &driver {
            shutdown.notify_waiters();
        }
        finalize_session_audit(
            &state,
            &recording_arc,
            &tenant,
            &trace_id,
            &session_id,
            &protocol,
            &target_host,
            close_action,
        )
        .await;
        tracing::info!(session_id = %session_id, close_action, "desktop websocket session closed");
    }
    .instrument(span)
    .await;
}

async fn dispatch_input(
    driver: &mut SessionDriver,
    sink: &dyn DisplaySink,
    ev: DesktopSessionInput,
    tick_demo: bool,
) {
    match driver {
        SessionDriver::Demo { engine } => {
            let _ = engine.handle_input(ev).await;
            if tick_demo {
                let _ = engine.tick(sink).await;
            }
        }
        SessionDriver::Live { input_tx, .. } => {
            let _ = input_tx.try_send(ev);
        }
    }
}

pub(crate) async fn resolve_tenant_aws_creds_and_region(
    accounts: &AwsAccountStore,
    tenant: &str,
    preferred_profile: Option<&str>,
) -> Option<(AwsCredentials, Option<String>)> {
    if let Some(pref) = preferred_profile.map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(lease) = accounts.find_connected_role_lease(tenant, pref).await {
            let reg = (!lease.region.trim().is_empty()).then(|| lease.region.clone());
            return Some((lease.credentials, reg));
        }
    }
    let list = accounts.list_accounts(tenant).await;
    if let Some(pref) = preferred_profile.map(str::trim).filter(|s| !s.is_empty()) {
        for acc in &list {
            if acc.id == pref || acc.name == pref {
                if let Ok(creds) = accounts.credentials_for_account(tenant, &acc.id).await {
                    if !creds.access_key_id.is_empty() && !creds.secret_access_key.is_empty() {
                        let region = (!acc.default_region.trim().is_empty())
                            .then(|| acc.default_region.clone());
                        return Some((creds, region));
                    }
                }
            }
        }
    }
    for acc in list {
        if let Ok(creds) = accounts.credentials_for_account(tenant, &acc.id).await {
            if !creds.access_key_id.is_empty() && !creds.secret_access_key.is_empty() {
                let region =
                    (!acc.default_region.trim().is_empty()).then(|| acc.default_region.clone());
                return Some((creds, region));
            }
        }
    }
    if let (Ok(ak), Ok(sk)) = (
        std::env::var("AWS_ACCESS_KEY_ID"),
        std::env::var("AWS_SECRET_ACCESS_KEY"),
    ) {
        if !ak.trim().is_empty() && !sk.trim().is_empty() {
            return Some((
                AwsCredentials {
                    access_key_id: ak,
                    secret_access_key: sk,
                    session_token: std::env::var("AWS_SESSION_TOKEN")
                        .ok()
                        .filter(|s| !s.trim().is_empty()),
                },
                std::env::var("AWS_REGION")
                    .ok()
                    .filter(|s| !s.trim().is_empty()),
            ));
        }
    }
    if preferred_profile.is_some() || !cfg!(test) {
        return operquay_aws::profiles::resolve_local_profile_or_default(preferred_profile).await;
    }
    None
}

pub(crate) async fn resolve_tenant_aws_creds(
    accounts: &AwsAccountStore,
    tenant: &str,
) -> Option<AwsCredentials> {
    resolve_tenant_aws_creds_and_region(accounts, tenant, None)
        .await
        .map(|(creds, _)| creds)
}

async fn finalize_session_audit(
    state: &AppState,
    recording_arc: &Arc<Mutex<Option<RecordingTee>>>,
    tenant: &str,
    trace_id: &str,
    session_id: &str,
    protocol: &str,
    target_host: &str,
    action: &str,
) {
    let taken = recording_arc.lock().ok().and_then(|mut guard| guard.take());
    let detail = if let Some(tee) = taken {
        let entry = state.recordings.finalize(tee).await;
        state.persist_recording_metadata(&entry).await;
        format!(
            "bytes={} frames={} sha256={}",
            entry.bytes_written, entry.frame_count, entry.sha256_hex
        )
    } else {
        "no active recording handle".to_owned()
    };
    state
        .audit
        .record(
            tenant,
            trace_id,
            session_id,
            action,
            protocol,
            target_host,
            detail,
            Some(session_id.to_owned()),
        )
        .await;
    state.telemetry.record_session_ended(protocol);
}

/// Embedded pure-Rust RFB 3.8 responder running across `SsmVirtualStream` for zero-AWS offline SSM validation.
async fn run_ssm_loopback_vnc_peer(stream: &mut SsmVirtualStream, width: u16, height: u16) {
    if stream
        .write_all(operquay_vnc::rfb::RFB_VERSION_3_8)
        .await
        .is_err()
    {
        return;
    }
    let mut cli_ver = [0u8; 12];
    if stream.read_exact(&mut cli_ver).await.is_err() {
        return;
    }
    if stream.write_all(&[1, 1]).await.is_err() {
        return;
    }
    let mut chosen = [0u8; 1];
    if stream.read_exact(&mut chosen).await.is_err() {
        return;
    }
    if stream.write_u32(0).await.is_err() {
        return;
    }
    let mut shared = [0u8; 1];
    if stream.read_exact(&mut shared).await.is_err() {
        return;
    }

    let name = b"AWS-SSM-Loopback";
    let mut init = Vec::with_capacity(24 + name.len());
    init.extend_from_slice(&width.to_be_bytes());
    init.extend_from_slice(&height.to_be_bytes());
    init.extend_from_slice(&[32, 24, 0, 1]);
    init.extend_from_slice(&[0u8; 12]);
    init.extend_from_slice(&(name.len() as u32).to_be_bytes());
    init.extend_from_slice(name);
    if stream.write_all(&init).await.is_err() {
        return;
    }

    let mut hdr = [0u8; 1];
    let mut frame_no = 0u8;
    while stream.read_exact(&mut hdr).await.is_ok() {
        match hdr[0] {
            0 => {
                let mut rest = [0u8; 19];
                let _ = stream.read_exact(&mut rest).await;
            }
            2 => {
                let mut head = [0u8; 3];
                if stream.read_exact(&mut head).await.is_ok() {
                    let count = usize::from(u16::from_be_bytes([head[1], head[2]]));
                    let mut encs = vec![0u8; count * 4];
                    let _ = stream.read_exact(&mut encs).await;
                }
            }
            3 => {
                let mut rest = [0u8; 9];
                if stream.read_exact(&mut rest).await.is_err() {
                    break;
                }
                if rest[0] != 0 {
                    tokio::time::sleep(Duration::from_millis(33)).await;
                }
                let bw = 96u16.min(width);
                let bh = 48u16.min(height);
                let mut upd = Vec::with_capacity(16 + usize::from(bw) * usize::from(bh) * 4);
                upd.extend_from_slice(&[0, 0, 0, 1]);
                upd.extend_from_slice(&40u16.to_be_bytes());
                upd.extend_from_slice(&40u16.to_be_bytes());
                upd.extend_from_slice(&bw.to_be_bytes());
                upd.extend_from_slice(&bh.to_be_bytes());
                upd.extend_from_slice(&0i32.to_be_bytes());
                for i in 0..(usize::from(bw) * usize::from(bh)) {
                    let stripe = ((i as u8).wrapping_add(frame_no)) % 64;
                    upd.extend_from_slice(&[13, 148, 136u8.saturating_add(stripe), 255]);
                }
                frame_no = frame_no.wrapping_add(8);
                if stream.write_all(&upd).await.is_err() {
                    break;
                }
            }
            4 => {
                let mut rest = [0u8; 7];
                let _ = stream.read_exact(&mut rest).await;
            }
            5 => {
                let mut rest = [0u8; 5];
                let _ = stream.read_exact(&mut rest).await;
            }
            251 => {
                let mut rest = [0u8; 23];
                let _ = stream.read_exact(&mut rest).await;
            }
            _ => break,
        }
    }
}
