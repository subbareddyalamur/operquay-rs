use std::borrow::Cow;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use ironrdp_cliprdr::pdu::{ClipboardFormat, ClipboardFormatId, OwnedFormatDataResponse};
use ironrdp_cliprdr::CliprdrClient;
use ironrdp_connector::connection_activation::{
    ConnectionActivationFactory, ConnectionActivationState,
};
use ironrdp_connector::sspi::generator::NetworkRequest;
use ironrdp_connector::{
    BitmapConfig, ClientConnector, Config as ConnectorConfig, ConnectorResult, Credentials,
    DesktopSize, Sequence, ServerName, Written,
};
use ironrdp_core::WriteBuf;
use ironrdp_displaycontrol::client::DisplayControlClient;
use ironrdp_displaycontrol::pdu::MonitorLayoutEntry;
use ironrdp_dvc::DrdynvcClient;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::gcc;
use ironrdp_pdu::geometry::Rectangle;
use ironrdp_pdu::input::fast_path::{
    FastPathInputEvent as IronFastPathInputEvent, KeyboardFlags as IronKeyboardFlags,
    SynchronizeFlags as IronSynchronizeFlags,
};
use ironrdp_pdu::input::mouse::{MousePdu, PointerFlags};
use ironrdp_pdu::rdp::capability_sets::{MajorPlatformType, RailSupportLevel};
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_tokio::{Framed, FramedRead, FramedWrite, NetworkClient, StreamWrapper};
use operquay_core::settings::KEYBOARD_LAYOUTS;
use operquay_core::{
    compliance_mode_enabled, CertPolicy, ClipboardNormalization, DesktopSessionInput, DisplaySink,
    OperquayError, RdpSecurityMode, SessionConfig,
};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};
use tokio_rustls::client::TlsStream;

struct RdpAsyncStream<S>(S);

impl<S> StreamWrapper for RdpAsyncStream<S> {
    type InnerStream = S;

    fn from_inner(stream: Self::InnerStream) -> Self {
        Self(stream)
    }

    fn into_inner(self) -> Self::InnerStream {
        self.0
    }

    fn get_inner(&self) -> &Self::InnerStream {
        &self.0
    }

    fn get_inner_mut(&mut self) -> &mut Self::InnerStream {
        &mut self.0
    }
}

impl<S> FramedRead for RdpAsyncStream<S>
where
    S: AsyncRead + Unpin + Send,
{
    type ReadFut<'read>
        = Pin<Box<dyn Future<Output = std::io::Result<usize>> + Send + 'read>>
    where
        Self: 'read;

    fn read<'a>(&'a mut self, buf: &'a mut bytes::BytesMut) -> Self::ReadFut<'a> {
        Box::pin(async { self.0.read_buf(buf).await })
    }
}

impl<S> FramedWrite for RdpAsyncStream<S>
where
    S: AsyncWrite + Unpin + Send,
{
    type WriteAllFut<'write>
        = Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'write>>
    where
        Self: 'write;

    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> Self::WriteAllFut<'a> {
        Box::pin(async {
            self.0.write_all(buf).await?;
            self.0.flush().await?;
            Ok(())
        })
    }
}

type RdpFramed<S> = Framed<RdpAsyncStream<S>>;

fn split_rdp_framed<S>(framed: RdpFramed<S>) -> (RdpFramed<ReadHalf<S>>, RdpFramed<WriteHalf<S>>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (stream, leftover) = framed.into_inner();
    let (read_half, write_half) = tokio::io::split(stream);
    (
        RdpFramed::new_with_leftover(read_half, leftover),
        RdpFramed::new(write_half),
    )
}

use crate::clipboard::{encode_clipboard_text_utf16le, OperquayCliprdrBackend, RdpClipboardEvent};
use crate::keymap::KeymapState;
use crate::pdu::{clamp_rdp_display_size, FastPathInputEvent as LocalFastPathInputEvent};
use crate::standard_sec::{is_standard_rdp_only_error, StandardRdpSecurityStream};
use crate::tls::upgrade_rdp_tls;
use ironrdp_connector::ClientConnectorState;
use std::task::{Context, Poll};

enum PreTlsStream<S> {
    Direct(S),
    Standard(Box<StandardRdpSecurityStream<S>>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for PreTlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Direct(s) => Pin::new(s).poll_read(cx, buf),
            Self::Standard(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for PreTlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Direct(s) => Pin::new(s).poll_write(cx, buf),
            Self::Standard(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Direct(s) => Pin::new(s).poll_flush(cx),
            Self::Standard(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Direct(s) => Pin::new(s).poll_shutdown(cx),
            Self::Standard(s) => Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

enum ActiveWireStream<S> {
    Plain(PreTlsStream<S>),
    Tls(Box<TlsStream<PreTlsStream<S>>>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ActiveWireStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ActiveWireStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

struct NoopNetworkClient;

impl NetworkClient for NoopNetworkClient {
    #[allow(clippy::manual_async_fn)]
    fn send(
        &mut self,
        _network_request: &NetworkRequest,
    ) -> impl Future<Output = ConnectorResult<Vec<u8>>> {
        async {
            Err(ironrdp_connector::general_err!(
                "CredSSP external HTTP requests (KDC proxy) are disabled by policy"
            ))
        }
    }
}

struct IronRdpSessionDriver {
    keymap: KeymapState,
    unicode_fallback: bool,
    clipboard_policy: ClipboardNormalization,
    local_clipboard_utf8: String,
    mouse_button_mask: u8,
    last_mouse_pos: Option<(u16, u16)>,
}

impl IronRdpSessionDriver {
    fn new(config: &SessionConfig) -> Self {
        Self {
            keymap: KeymapState::new(&config.settings.keyboard_layout),
            unicode_fallback: config.settings.unicode_fallback,
            clipboard_policy: config.settings.clipboard_normalization,
            local_clipboard_utf8: String::new(),
            mouse_button_mask: 0,
            last_mouse_pos: None,
        }
    }

    fn translate_pointer_pdu(
        &mut self,
        x: u16,
        y: u16,
        button_mask: u8,
    ) -> Vec<IronFastPathInputEvent> {
        let mut events = Vec::new();
        let btn_bits = button_mask & 0x07;
        let wheel_up = (button_mask & 0x08) != 0;
        let wheel_down = (button_mask & 0x10) != 0;
        let prev = self.mouse_button_mask;
        self.mouse_button_mask = btn_bits;
        let moved = self.last_mouse_pos != Some((x, y));

        // Emit pure cursor movement before any button transition; MS-RDPBCGR servers
        // ignore button state changes when PTRFLAGS_MOVE is OR'd with button flags.
        if moved || (prev == btn_bits && !wheel_up && !wheel_down) {
            events.push(IronFastPathInputEvent::MouseEvent(MousePdu {
                flags: PointerFlags::MOVE,
                number_of_wheel_rotation_units: 0,
                x_position: x,
                y_position: y,
            }));
            self.last_mouse_pos = Some((x, y));
        }

        let button_defs = [
            (0x01u8, PointerFlags::LEFT_BUTTON),
            (0x02u8, PointerFlags::MIDDLE_BUTTON_OR_WHEEL),
            (0x04u8, PointerFlags::RIGHT_BUTTON),
        ];

        for (bit, pflag) in button_defs {
            let was = (prev & bit) != 0;
            let now = (btn_bits & bit) != 0;
            if was != now {
                let flags = if now {
                    pflag | PointerFlags::DOWN
                } else {
                    pflag
                };
                events.push(IronFastPathInputEvent::MouseEvent(MousePdu {
                    flags,
                    number_of_wheel_rotation_units: 0,
                    x_position: x,
                    y_position: y,
                }));
            }
        }

        if wheel_up {
            events.push(IronFastPathInputEvent::MouseEvent(MousePdu {
                flags: PointerFlags::VERTICAL_WHEEL,
                number_of_wheel_rotation_units: 120,
                x_position: x,
                y_position: y,
            }));
        } else if wheel_down {
            events.push(IronFastPathInputEvent::MouseEvent(MousePdu {
                flags: PointerFlags::VERTICAL_WHEEL | PointerFlags::WHEEL_NEGATIVE,
                number_of_wheel_rotation_units: -120,
                x_position: x,
                y_position: y,
            }));
        }

        events
    }

    fn translate_key_events(&mut self, keysym: u32, pressed: bool) -> Vec<IronFastPathInputEvent> {
        let translated = self
            .keymap
            .translate(keysym, pressed, self.unicode_fallback);
        translated
            .pdu_bytes
            .into_iter()
            .filter_map(|ev| match ev {
                LocalFastPathInputEvent::Scancode {
                    extended,
                    release,
                    code,
                } => {
                    let mut flags = IronKeyboardFlags::empty();
                    if release {
                        flags |= IronKeyboardFlags::RELEASE;
                    }
                    if extended {
                        flags |= IronKeyboardFlags::EXTENDED;
                    }
                    Some(IronFastPathInputEvent::KeyboardEvent(flags, code))
                }
                LocalFastPathInputEvent::Unicode { release, code_unit } => {
                    let mut flags = IronKeyboardFlags::empty();
                    if release {
                        flags |= IronKeyboardFlags::RELEASE;
                    }
                    Some(IronFastPathInputEvent::UnicodeKeyboardEvent(
                        flags, code_unit,
                    ))
                }
                LocalFastPathInputEvent::SyncLocks {
                    scroll,
                    num,
                    caps,
                    kana,
                } => {
                    let mut flags = IronSynchronizeFlags::empty();
                    if scroll {
                        flags |= IronSynchronizeFlags::SCROLL_LOCK;
                    }
                    if num {
                        flags |= IronSynchronizeFlags::NUM_LOCK;
                    }
                    if caps {
                        flags |= IronSynchronizeFlags::CAPS_LOCK;
                    }
                    if kana {
                        flags |= IronSynchronizeFlags::KANA_LOCK;
                    }
                    Some(IronFastPathInputEvent::SyncEvent(flags))
                }
                LocalFastPathInputEvent::Mouse { .. } => None,
            })
            .collect()
    }

    fn build_sas_events() -> Vec<IronFastPathInputEvent> {
        let ctrl = 0x1Du8;
        let alt = 0x38u8;
        let del = 0x53u8;
        vec![
            IronFastPathInputEvent::KeyboardEvent(IronKeyboardFlags::empty(), ctrl),
            IronFastPathInputEvent::KeyboardEvent(IronKeyboardFlags::empty(), alt),
            IronFastPathInputEvent::KeyboardEvent(IronKeyboardFlags::EXTENDED, del),
            IronFastPathInputEvent::KeyboardEvent(
                IronKeyboardFlags::EXTENDED | IronKeyboardFlags::RELEASE,
                del,
            ),
            IronFastPathInputEvent::KeyboardEvent(IronKeyboardFlags::RELEASE, alt),
            IronFastPathInputEvent::KeyboardEvent(IronKeyboardFlags::RELEASE, ctrl),
        ]
    }
}

fn build_ironrdp_connector_config(
    config: &SessionConfig,
) -> Result<ConnectorConfig, OperquayError> {
    let (domain_str, username_str) = split_domain_username(&config.username);
    let (w_u32, h_u32) = clamp_rdp_display_size(config.width, config.height);
    let w = u16::try_from(w_u32).unwrap_or(1280);
    let h = u16::try_from(h_u32).unwrap_or(720);
    let lcid = KEYBOARD_LAYOUTS
        .iter()
        .find(|l| l.id == config.settings.keyboard_layout)
        .map_or(0x0409, |l| l.lcid);

    let (enable_tls, enable_credssp, enable_standard_rdp_security) =
        match config.settings.rdp_security_mode {
            RdpSecurityMode::Tls => (true, false, false),
            RdpSecurityMode::Nla | RdpSecurityMode::NlaExt => (false, true, false),
            RdpSecurityMode::ClassicRdp => (false, false, true),
            RdpSecurityMode::Any | RdpSecurityMode::Vmconnect => (true, true, false),
        };

    let codecs = ironrdp_pdu::rdp::capability_sets::client_codecs_capabilities(&[])
        .map_err(|e| OperquayError::Protocol(format!("failed to build client codecs: {e}")))?;

    Ok(ConnectorConfig {
        desktop_size: DesktopSize {
            width: w,
            height: h,
        },
        monitor_layout: None,
        desktop_scale_factor: 100,
        desktop_physical_size: None,
        desktop_orientation: None,
        device_scale_factor: Some(100),
        monitor_extended_layout: None,
        relative_mouse_input: false,
        enable_tls,
        enable_credssp,
        enable_standard_rdp_security,
        credentials: Credentials::UsernamePassword {
            username: username_str.to_owned(),
            password: config.password.expose().to_owned(),
        },
        domain: (!domain_str.is_empty()).then(|| domain_str.to_owned()),
        client_build: 19045,
        client_name: "Operquay".to_owned(),
        keyboard_type: gcc::KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: lcid,
        connection_type: gcc::ConnectionType::Lan,
        ime_file_name: String::new(),
        bitmap: Some(BitmapConfig {
            lossy_compression: true,
            color_depth: 32,
            codecs,
        }),
        dig_product_id: String::new(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        remote_application_mode: false,
        rail_support_level: RailSupportLevel::empty(),
        platform: MajorPlatformType::UNIX,
        hardware_id: None,
        request_data: None,
        autologon: true,
        enable_audio_playback: false,
        enable_audio_capture: false,
        performance_flags: PerformanceFlags::DISABLE_WALLPAPER
            | PerformanceFlags::DISABLE_FULLWINDOWDRAG
            | PerformanceFlags::DISABLE_MENUANIMATIONS
            | PerformanceFlags::DISABLE_CURSOR_SHADOW
            | PerformanceFlags::ENABLE_FONT_SMOOTHING,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        compression_type: None,
        enable_server_pointer: true,
        pointer_software_rendering: false,
        multitransport_flags: None,
        support_dyn_vc_gfx_protocol: false,
    })
}

fn flush_sink_now(sink: &Arc<dyn DisplaySink>) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    sink.flush_frame(now_ms);
}

async fn handle_active_stage_outputs<R, W>(
    outputs: Vec<ActiveStageOutput>,
    image: &mut DecodedImage,
    active_stage: &mut ActiveStage,
    activation_factory: &ConnectionActivationFactory,
    reader: &mut RdpFramed<ReadHalf<R>>,
    writer: &mut W,
    sink: &Arc<dyn DisplaySink>,
) -> Result<(bool, bool, bool), OperquayError>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin,
{
    let mut should_terminate = false;
    let mut had_graphics = false;
    let mut reactivated = false;
    let has_pointer_override = outputs.iter().any(|o| {
        matches!(
            o,
            ActiveStageOutput::PointerBitmap(_) | ActiveStageOutput::PointerDefault
        )
    });

    for output in outputs {
        match output {
            ActiveStageOutput::ResponseFrame(frame) => {
                if !frame.is_empty() {
                    writer.write_all(&frame).await?;
                    writer.flush().await?;
                }
            }
            ActiveStageOutput::GraphicsUpdate(rect) => {
                let region = image.data_for_rect(&rect);
                tracing::debug!(
                    left = rect.left,
                    top = rect.top,
                    width = rect.width(),
                    height = rect.height(),
                    non_zero = region
                        .iter()
                        .filter(|&&b| b != 0 && b != 255)
                        .take(4)
                        .count(),
                    "IronRDP GraphicsUpdate rect"
                );
                sink.draw_rgba_rect(
                    0,
                    u32::from(rect.left),
                    u32::from(rect.top),
                    u32::from(rect.width()),
                    u32::from(rect.height()),
                    region,
                    image.stride(),
                );
                had_graphics = true;
            }
            ActiveStageOutput::PointerPosition { x, y } => {
                sink.move_cursor(u32::from(x), u32::from(y));
            }
            ActiveStageOutput::PointerBitmap(ptr) => {
                sink.set_cursor(
                    u32::from(ptr.hotspot_x),
                    u32::from(ptr.hotspot_y),
                    u32::from(ptr.width),
                    u32::from(ptr.height),
                    &ptr.bitmap_data,
                );
            }
            ActiveStageOutput::PointerDefault => {
                sink.set_cursor(0, 0, 0, 0, &[]);
            }
            ActiveStageOutput::PointerHidden => {
                if !has_pointer_override {
                    sink.set_cursor(0, 0, 1, 1, &[0, 0, 0, 0]);
                }
            }
            ActiveStageOutput::DeactivateAll => {
                drive_reactivation(
                    activation_factory,
                    active_stage,
                    image,
                    reader,
                    writer,
                    sink,
                )
                .await?;
                reactivated = true;
            }
            ActiveStageOutput::ServerRedirection(redir) => {
                return Err(OperquayError::Protocol(format!(
                    "RDP server requested session redirection (session_id={})",
                    redir.session_id
                )));
            }
            ActiveStageOutput::Terminate(reason) => {
                tracing::info!(?reason, "IronRDP ActiveStage received Terminate");
                should_terminate = true;
            }
            ActiveStageOutput::MonitorLayout(_)
            | ActiveStageOutput::WindowingOrders(_)
            | ActiveStageOutput::WindowSurfaceUpdates(_)
            | ActiveStageOutput::SaveSessionInfo { .. }
            | ActiveStageOutput::SessionId(_)
            | ActiveStageOutput::MultitransportRequest(_)
            | ActiveStageOutput::AutoDetect(_)
            | ActiveStageOutput::AutoReconnectCookie(_)
            | ActiveStageOutput::LogonErrors(_)
            | ActiveStageOutput::AutoReconnectFailed => {}
        }
    }

    Ok((should_terminate, had_graphics, reactivated))
}

async fn drive_reactivation<R, W>(
    activation_factory: &ConnectionActivationFactory,
    active_stage: &mut ActiveStage,
    image: &mut DecodedImage,
    reader: &mut RdpFramed<ReadHalf<R>>,
    writer: &mut W,
    sink: &Arc<dyn DisplaySink>,
) -> Result<(), OperquayError>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin,
{
    let mut activation = activation_factory.create();
    let mut buf = WriteBuf::new();

    loop {
        let payload = if let Some(hint) = activation.next_pdu_hint() {
            reader
                .read_by_hint(hint)
                .await
                .map_err(|e| OperquayError::Protocol(format!("reactivation read failed: {e}")))?
        } else {
            Bytes::new()
        };

        buf.clear();
        let written = activation
            .step(&payload, None, &mut buf)
            .map_err(|e| OperquayError::Protocol(format!("reactivation step failed: {e}")))?;
        if let Written::Size(size) = written {
            writer.write_all(&buf[..size.get()]).await?;
            writer.flush().await?;
        }

        if let ConnectionActivationState::Finalized {
            desktop_size,
            share_id,
            enable_server_pointer,
            pointer_software_rendering,
            static_channel_chunk_size,
            ..
        } = activation.connection_activation_state()
        {
            let _ = active_stage.reactivate(
                activation.io_channel_id(),
                activation.user_channel_id(),
                share_id,
                enable_server_pointer,
                pointer_software_rendering,
                static_channel_chunk_size,
            );
            if image.width() != desktop_size.width || image.height() != desktop_size.height {
                *image =
                    DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
                sink.resize(
                    0,
                    u32::from(desktop_size.width),
                    u32::from(desktop_size.height),
                );
            }
            break;
        }
    }

    Ok(())
}

/// Perform complete in-process `IronRDP 0.17` handshake and active graphics/input/clipboard/resize
/// loop over ANY `AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static` stream
/// (`TcpStream` OR `SsmVirtualStream`). Zero sidecar processes.
pub async fn run_live_rdp_over_stream<S>(
    stream: S,
    config: &SessionConfig,
    sink: Arc<dyn DisplaySink>,
    mut input_rx: mpsc::Receiver<DesktopSessionInput>,
    expected_cert_sha256: Option<[u8; 32]>,
    shutdown: Arc<Notify>,
) -> Result<[u8; 32], OperquayError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    run_live_rdp_over_stream_ref(
        stream,
        config,
        sink,
        &mut input_rx,
        expected_cert_sha256,
        shutdown,
    )
    .await
}

/// Variant of [`run_live_rdp_over_stream`] borrowing `input_rx` so callers can retry
/// X.224 Standard RDP Security fallback on a fresh stream without losing buffered user input.
pub async fn run_live_rdp_over_stream_ref<S>(
    stream: S,
    config: &SessionConfig,
    sink: Arc<dyn DisplaySink>,
    input_rx: &mut mpsc::Receiver<DesktopSessionInput>,
    expected_cert_sha256: Option<[u8; 32]>,
    shutdown: Arc<Notify>,
) -> Result<[u8; 32], OperquayError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    run_live_rdp_over_stream_with_progress(
        stream,
        config,
        sink,
        input_rx,
        expected_cert_sha256,
        shutdown,
        None,
    )
    .await
}

/// Reject Standard RDP Security (`RC4` / `ClassicRdp`) in Compliance Mode unless explicitly
/// allowlisted inside an AWS SSM tunnel (`SsmLoopbackIgnore && allow_legacy_crypto_over_ssm`).
pub fn check_rdp_legacy_crypto_policy(
    compliance_mode: bool,
    cert_policy: CertPolicy,
    allow_legacy_crypto_over_ssm: bool,
) -> Result<(), OperquayError> {
    if compliance_mode
        && !(cert_policy == CertPolicy::SsmLoopbackIgnore && allow_legacy_crypto_over_ssm)
    {
        return Err(OperquayError::SecurityPolicy(
            "Standard RDP Security (RC4) is blocked in Compliance Mode; enable NLA/TLS or set allow_legacy_crypto_over_ssm over AWS SSM"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Variant accepting an optional handshake progress channel `(stage, label, percent)`.
pub async fn run_live_rdp_over_stream_with_progress<S>(
    stream: S,
    config: &SessionConfig,
    sink: Arc<dyn DisplaySink>,
    input_rx: &mut mpsc::Receiver<DesktopSessionInput>,
    expected_cert_sha256: Option<[u8; 32]>,
    shutdown: Arc<Notify>,
    progress_tx: Option<mpsc::Sender<(&'static str, &'static str, u8)>>,
) -> Result<[u8; 32], OperquayError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let emit_progress = |stage: &'static str, label: &'static str, percent: u8| {
        if let Some(ref ptx) = progress_tx {
            let _ = ptx.try_send((stage, label, percent));
        }
    };

    emit_progress("rdp_handshake", "Negotiating RDP security & TLS…", 45);
    let iron_config = build_ironrdp_connector_config(config)?;
    let (clip_tx, mut clip_rx) = mpsc::channel(32);
    let cliprdr = CliprdrClient::new(Box::new(OperquayCliprdrBackend::new(
        clip_tx,
        config.settings.clipboard_normalization,
    )));
    let drdynvc = if matches!(
        config.settings.transport_mode,
        operquay_core::TransportMode::Oqr2Binary
    ) && !matches!(
        config.settings.codec_mode,
        operquay_core::CodecMode::LosslessCrisp
    ) {
        DrdynvcClient::new()
            .with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new())))
            .with_dynamic_channel(crate::egfx::build_egfx_channel(
                Arc::clone(&sink),
                config.width,
                config.height,
            ))
    } else {
        DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new())))
    };

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let mut connector = ClientConnector::new(iron_config, client_addr)
        .with_static_channel(drdynvc)
        .with_static_channel(cliprdr);

    let pre_tls_stream = if matches!(
        config.settings.rdp_security_mode,
        RdpSecurityMode::ClassicRdp
    ) {
        check_rdp_legacy_crypto_policy(
            compliance_mode_enabled(),
            config.settings.cert_policy,
            config.settings.allow_legacy_crypto_over_ssm,
        )?;
        PreTlsStream::Standard(Box::new(StandardRdpSecurityStream::new(stream)))
    } else {
        PreTlsStream::Direct(stream)
    };

    let mut initial_framed = RdpFramed::new(pre_tls_stream);
    let should_upgrade = ironrdp_tokio::connect_begin(&mut initial_framed, &mut connector)
        .await
        .map_err(|e| OperquayError::Protocol(format!("RDP X.224 negotiation failed: {e}")))?;

    let is_standard_rdp = matches!(
        connector.state,
        ClientConnectorState::EnhancedSecurityUpgrade { selected_protocol }
            if selected_protocol.is_standard_rdp_security()
    );
    let (raw_stream, leftover) = initial_framed.into_inner();
    let (cert_sha256, server_public_key, active_wire) = if is_standard_rdp {
        check_rdp_legacy_crypto_policy(
            compliance_mode_enabled(),
            config.settings.cert_policy,
            config.settings.allow_legacy_crypto_over_ssm,
        )?;
        ([0u8; 32], Vec::new(), ActiveWireStream::Plain(raw_stream))
    } else {
        let tls_info = upgrade_rdp_tls(
            raw_stream,
            &config.target_host,
            config.settings.cert_policy,
            expected_cert_sha256,
        )
        .await
        .map_err(|e| OperquayError::SecurityPolicy(e.to_string()))?;
        (
            tls_info.cert_sha256,
            tls_info.server_public_key,
            ActiveWireStream::Tls(Box::new(tls_info.stream)),
        )
    };

    emit_progress("rdp_activating", "Signing in to Windows session…", 75);
    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let mut upgraded_framed = RdpFramed::new_with_leftover(active_wire, leftover);
    let mut network_client = NoopNetworkClient;

    let connection_result = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut upgraded_framed,
        &mut network_client,
        ServerName::new(&config.target_host),
        server_public_key,
        None,
    )
    .await
    .map_err(|e| OperquayError::Protocol(format!("RDP CredSSP/MCS activation failed: {e}")))?
    .into_connected()
    .map_err(|e| OperquayError::Protocol(format!("RDP connection did not complete: {e}")))?;

    emit_progress("rdp_rendering", "Loading Windows desktop…", 92);
    let activation_factory = connection_result.activation_factory.clone();
    let initial_width = connection_result.desktop_size.width;
    let initial_height = connection_result.desktop_size.height;
    let (req_w, req_h) = clamp_rdp_display_size(config.width, config.height);
    tracing::info!(
        requested_width = req_w,
        requested_height = req_h,
        negotiated_width = initial_width,
        negotiated_height = initial_height,
        "IronRDP desktop activated"
    );
    let mut image = DecodedImage::new(PixelFormat::RgbA32, initial_width, initial_height);
    sink.resize(0, u32::from(initial_width), u32::from(initial_height));

    let mut active_stage = ActiveStageBuilder {
        static_channels: connection_result.static_channels,
        user_channel_id: connection_result.user_channel_id,
        io_channel_id: connection_result.io_channel_id,
        message_channel_id: connection_result.message_channel_id,
        share_id: connection_result.share_id,
        compression_type: connection_result.compression_type,
        enable_server_pointer: connection_result.enable_server_pointer,
        pointer_software_rendering: connection_result.pointer_software_rendering,
    }
    .build();

    let (mut reader, writer_framed) = split_rdp_framed(upgraded_framed);
    let mut writer = writer_framed.into_inner_no_leftover();
    let mut driver = IronRdpSessionDriver::new(config);
    let mut pending_resize: Option<(u32, u32)> = if config.settings.enable_dynamic_resize
        && ((u32::from(initial_width) as i32 - req_w as i32).abs() >= 4
            || (u32::from(initial_height) as i32 - req_h as i32).abs() >= 4)
    {
        Some((req_w, req_h))
    } else {
        None
    };

    let coalesce_window = std::time::Duration::from_millis(
        (1000 / u64::from(config.settings.target_fps.max(10))).clamp(16, 33),
    );
    let mut pending_flush = false;
    let mut first_frame_sent = false;
    let mut flush_deadline: Option<tokio::time::Instant> = None;

    loop {
        tokio::select! {
            () = shutdown.notified() => break,
            () = async {
                match flush_deadline {
                    Some(dl) => tokio::time::sleep_until(dl).await,
                    None => std::future::pending().await,
                }
            }, if pending_flush => {
                flush_sink_now(&sink);
                pending_flush = false;
                flush_deadline = None;
                first_frame_sent = true;
            }
            pdu_res = reader.read_pdu() => {
                let (action, payload) = match pdu_res {
                    Ok(v) => v,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::UnexpectedEof {
                            break;
                        }
                        return Err(OperquayError::Io(e));
                    }
                };

                let outputs = active_stage
                    .process(&mut image, action, &payload, None)
                    .map_err(|e| OperquayError::Protocol(format!("IronRDP process failed: {e}")))?;

                let (term, had_graphics, reactivated) = handle_active_stage_outputs(
                    outputs,
                    &mut image,
                    &mut active_stage,
                    &activation_factory,
                    &mut reader,
                    &mut writer,
                    &sink,
                ).await?;
                if reactivated {
                    first_frame_sent = false;
                }
                if had_graphics {
                    if first_frame_sent {
                        pending_flush = true;
                        if flush_deadline.is_none() {
                            flush_deadline = Some(tokio::time::Instant::now() + coalesce_window);
                        }
                    } else {
                        flush_sink_now(&sink);
                        pending_flush = false;
                        flush_deadline = None;
                        first_frame_sent = true;
                    }
                }
                if term {
                    if pending_flush {
                        flush_sink_now(&sink);
                    }
                    break;
                }

                if let Some((cw, ch)) = pending_resize {
                    if active_stage.display_control_ready() == Some(true) {
                        pending_resize = try_send_dynamic_resize(
                            &mut active_stage,
                            &image,
                            &mut writer,
                            cw,
                            ch,
                        )
                        .await?;
                    }
                }
            }
            Some(clip_ev) = clip_rx.recv() => {
                match clip_ev {
                    RdpClipboardEvent::RequestFormatList => {
                        if !driver.local_clipboard_utf8.is_empty() {
                            if let Some(clip) = active_stage.get_svc_processor_mut::<CliprdrClient>() {
                                let formats = vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)];
                                if let Ok(svc_msgs) = clip.initiate_copy(&formats) {
                                    if let Ok(frame) = active_stage.process_svc_processor_messages(svc_msgs) {
                                        if !frame.is_empty() {
                                            writer.write_all(&frame).await?;
                                            writer.flush().await?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    RdpClipboardEvent::RemoteCopy(fmt) => {
                        if let Some(clip) = active_stage.get_svc_processor_mut::<CliprdrClient>() {
                            if let Ok(svc_msgs) = clip.initiate_paste(fmt) {
                                if let Ok(frame) = active_stage.process_svc_processor_messages(svc_msgs) {
                                    if !frame.is_empty() {
                                        writer.write_all(&frame).await?;
                                        writer.flush().await?;
                                    }
                                }
                            }
                        }
                    }
                    RdpClipboardEvent::FormatDataRequest(fmt) => {
                        let data = if fmt == ClipboardFormatId::CF_UNICODETEXT {
                            encode_clipboard_text_utf16le(
                                &driver.local_clipboard_utf8,
                                driver.clipboard_policy,
                            )
                        } else {
                            let mut bytes = driver.local_clipboard_utf8.as_bytes().to_vec();
                            bytes.push(0);
                            bytes
                        };
                        if let Some(clip) = active_stage.get_svc_processor_mut::<CliprdrClient>() {
                            if let Ok(svc_msgs) = clip.submit_format_data(OwnedFormatDataResponse::new_data(data)) {
                                if let Ok(frame) = active_stage.process_svc_processor_messages(svc_msgs) {
                                    if !frame.is_empty() {
                                        writer.write_all(&frame).await?;
                                        writer.flush().await?;
                                    }
                                }
                            }
                        }
                    }
                    RdpClipboardEvent::RemoteText(text) => {
                        sink.on_clipboard_text(&text);
                    }
                }
            }
            maybe_input = input_rx.recv() => {
                let Some(input) = maybe_input else { break };
                match input {
                    DesktopSessionInput::Pointer { x, y, button_mask } => {
                        let events = driver.translate_pointer_pdu(x, y, button_mask);
                        if !events.is_empty() {
                            let outs = active_stage
                                .process_fastpath_input(&mut image, &events)
                                .map_err(|e| OperquayError::Protocol(format!("fastpath input encode failed: {e}")))?;
                            let (term, had_graphics, _) = handle_active_stage_outputs(
                                outs,
                                &mut image,
                                &mut active_stage,
                                &activation_factory,
                                &mut reader,
                                &mut writer,
                                &sink,
                            ).await?;
                            if had_graphics {
                                pending_flush = true;
                                if flush_deadline.is_none() {
                                    flush_deadline = Some(tokio::time::Instant::now() + coalesce_window);
                                }
                            }
                            if term {
                                break;
                            }
                        }
                    }
                    DesktopSessionInput::Key { keysym, pressed } => {
                        let events = driver.translate_key_events(keysym, pressed);
                        if !events.is_empty() {
                            let outs = active_stage
                                .process_fastpath_input(&mut image, &events)
                                .map_err(|e| OperquayError::Protocol(format!("fastpath key encode failed: {e}")))?;
                            let (term, had_graphics, _) = handle_active_stage_outputs(
                                outs,
                                &mut image,
                                &mut active_stage,
                                &activation_factory,
                                &mut reader,
                                &mut writer,
                                &sink,
                            ).await?;
                            if had_graphics {
                                pending_flush = true;
                                if flush_deadline.is_none() {
                                    flush_deadline = Some(tokio::time::Instant::now() + coalesce_window);
                                }
                            }
                            if term {
                                break;
                            }
                        }
                    }
                    DesktopSessionInput::SecureAttentionSequence => {
                        let events = IronRdpSessionDriver::build_sas_events();
                        let outs = active_stage
                            .process_fastpath_input(&mut image, &events)
                            .map_err(|e| OperquayError::Protocol(format!("fastpath SAS failed: {e}")))?;
                        let (term, had_graphics, _) = handle_active_stage_outputs(
                            outs,
                            &mut image,
                            &mut active_stage,
                            &activation_factory,
                            &mut reader,
                            &mut writer,
                            &sink,
                        ).await?;
                        if had_graphics {
                            pending_flush = true;
                            if flush_deadline.is_none() {
                                flush_deadline = Some(tokio::time::Instant::now() + coalesce_window);
                            }
                        }
                        if term {
                            break;
                        }
                    }
                    DesktopSessionInput::Resize { width, height, .. } => {
                        if config.settings.enable_dynamic_resize {
                            pending_resize = try_send_dynamic_resize(
                                &mut active_stage,
                                &image,
                                &mut writer,
                                width,
                                height,
                            )
                            .await?;
                        }
                    }
                    DesktopSessionInput::KeyboardLayout { layout } => {
                        driver.keymap.set_layout(&layout);
                        tracing::debug!(layout = %driver.keymap.layout_id(), "switched live RDP keyboard layout");
                    }
                    DesktopSessionInput::ClipboardText { text } => {
                        driver.local_clipboard_utf8 = text;
                        if let Some(clip) = active_stage.get_svc_processor_mut::<CliprdrClient>() {
                            let formats = vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)];
                            if let Ok(svc_msgs) = clip.initiate_copy(&formats) {
                                if let Ok(frame) = active_stage.process_svc_processor_messages(svc_msgs) {
                                    if !frame.is_empty() {
                                        writer.write_all(&frame).await?;
                                        writer.flush().await?;
                                    }
                                }
                            }
                        }
                    }
                    DesktopSessionInput::SyncAck { .. } => {}
                }
            }
        }
    }

    Ok(cert_sha256)
}

async fn try_send_dynamic_resize<W: AsyncWrite + Unpin>(
    active_stage: &mut ActiveStage,
    image: &DecodedImage,
    writer: &mut W,
    width: u32,
    height: u32,
) -> Result<Option<(u32, u32)>, OperquayError> {
    let (cw, ch) = MonitorLayoutEntry::adjust_display_size(width, height);
    if cw == u32::from(image.width()) && ch == u32::from(image.height()) {
        return Ok(None);
    }
    match active_stage.encode_resize(cw, ch, None, None) {
        Some(Ok(frame)) => {
            if !frame.is_empty() {
                writer.write_all(&frame).await?;
                writer.flush().await?;
                tracing::info!(width = cw, height = ch, "sent MS-RDPEDISP dynamic resize");
            }
            Ok(None)
        }
        Some(Err(err)) => {
            tracing::warn!(
                error = %err,
                width = cw,
                height = ch,
                "MS-RDPEDISP resize encode error"
            );
            Ok(None)
        }
        None => Ok(Some((cw, ch))),
    }
}

/// Connect directly over TCP (`SocketAddr`) to a live Windows or `xrdp` target.
pub async fn connect_live_rdp_tcp(
    addr: SocketAddr,
    config: &SessionConfig,
    sink: Arc<dyn DisplaySink>,
    mut input_rx: mpsc::Receiver<DesktopSessionInput>,
    expected_cert_sha256: Option<[u8; 32]>,
    shutdown: Arc<Notify>,
) -> Result<[u8; 32], OperquayError> {
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    match run_live_rdp_over_stream_ref(
        tcp,
        config,
        sink.clone(),
        &mut input_rx,
        expected_cert_sha256,
        shutdown.clone(),
    )
    .await
    {
        Ok(fp) => Ok(fp),
        Err(err)
            if is_standard_rdp_only_error(&err)
                && matches!(config.settings.rdp_security_mode, RdpSecurityMode::Any) =>
        {
            let mut fallback = config.clone();
            fallback.settings.rdp_security_mode = RdpSecurityMode::ClassicRdp;
            let tcp2 = TcpStream::connect(addr).await?;
            tcp2.set_nodelay(true)?;
            run_live_rdp_over_stream_ref(
                tcp2,
                &fallback,
                sink,
                &mut input_rx,
                expected_cert_sha256,
                shutdown,
            )
            .await
        }
        Err(err) => Err(err),
    }
}

/// Resolve hostname/IP via DNS and connect directly over TCP to a live RDP target.
pub async fn connect_live_rdp_host(
    host: &str,
    port: u16,
    config: &SessionConfig,
    sink: Arc<dyn DisplaySink>,
    input_rx: mpsc::Receiver<DesktopSessionInput>,
    expected_cert_sha256: Option<[u8; 32]>,
    shutdown: Arc<Notify>,
) -> Result<[u8; 32], OperquayError> {
    let addr = tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| {
            OperquayError::Protocol(format!(
                "DNS resolution returned no addresses for {host}:{port}"
            ))
        })?;
    connect_live_rdp_tcp(addr, config, sink, input_rx, expected_cert_sha256, shutdown).await
}

fn split_domain_username(raw: &str) -> (&str, &str) {
    if let Some((dom, usr)) = raw.split_once('\\') {
        (dom, usr)
    } else {
        ("", raw)
    }
}

async fn read_tpkt_for_test<S>(stream: &mut S) -> Result<Vec<u8>, OperquayError>
where
    S: AsyncRead + Unpin,
{
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    let total = usize::from(u16::from_be_bytes([hdr[2], hdr[3]]));
    if total < 4 {
        return Err(OperquayError::Protocol(format!("short TPKT len: {total}")));
    }
    let mut buf = vec![0u8; total];
    buf[..4].copy_from_slice(&hdr);
    stream.read_exact(&mut buf[4..]).await?;
    Ok(buf)
}

/// Loopback helper for tests (`operquay-rdp` and `operquay-server`): performs an authentic
/// `IronRDP` X.224 -> TLS -> MCS -> ClientInfo -> License ValidClient -> DemandActive ->
/// Connection Finalization handshake and returns the TLS server stream ready to exchange
/// Fast-Path bitmap & input PDUs.
#[doc(hidden)]
pub async fn accept_ironrdp_tls_handshake_for_test<S>(
    mut stream: S,
    acceptor: tokio_rustls::TlsAcceptor,
    width: u16,
    height: u16,
) -> Result<tokio_rustls::server::TlsStream<S>, OperquayError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use ironrdp_core::{decode as pdu_decode, encode_vec as pdu_encode_vec};
    use ironrdp_pdu::gcc::{
        ConferenceCreateResponse, KeyboardType, RdpVersion, ServerCoreData, ServerCoreOptionalData,
        ServerEarlyCapabilityFlags, ServerGccBlocks, ServerNetworkData, ServerSecurityData,
    };
    use ironrdp_pdu::mcs::{
        AttachUserConfirm, ChannelJoinConfirm, ConnectInitial, ConnectResponse, DomainParameters,
        McsMessage, SendDataIndication,
    };
    use ironrdp_pdu::nego::{
        ConnectionConfirm, ConnectionRequest, ResponseFlags, SecurityProtocol,
    };
    use ironrdp_pdu::rdp::capability_sets::{
        Bitmap, BitmapDrawingFlags, CapabilitySet, DemandActive, General, GeneralExtraFlags, Input,
        InputFlags, MinorPlatformType, Order, OrderFlags, OrderSupportExFlags, Pointer,
        ServerDemandActive, VirtualChannel, VirtualChannelFlags, PROTOCOL_VER,
    };
    use ironrdp_pdu::rdp::client_info::CompressionType;
    use ironrdp_pdu::rdp::finalization_messages::{
        ControlAction, ControlPdu, FontPdu, SynchronizePdu,
    };
    use ironrdp_pdu::rdp::headers::{
        CompressionFlags, ShareControlHeader, ShareControlPdu, ShareDataHeader, ShareDataPdu,
        StreamPriority,
    };
    use ironrdp_pdu::rdp::server_license::{LicensePdu, LicensingErrorMessage};
    use ironrdp_pdu::x224::{X224Data, X224};

    // 1. X.224 Connection Request -> Connection Confirm (SSL)
    let neg_req_bytes = read_tpkt_for_test(&mut stream).await?;
    let neg_req: X224<ConnectionRequest> = pdu_decode(&neg_req_bytes)
        .map_err(|e| OperquayError::Protocol(format!("test srv X224 req decode: {e}")))?;
    let neg_rsp = X224(ConnectionConfirm::Response {
        flags: ResponseFlags::empty(),
        protocol: SecurityProtocol::SSL,
    });
    let rsp_bytes = pdu_encode_vec(&neg_rsp)
        .map_err(|e| OperquayError::Protocol(format!("test srv X224 rsp encode: {e}")))?;
    stream.write_all(&rsp_bytes).await?;

    // 2. TLS Upgrade
    let mut tls = acceptor.accept(stream).await?;

    // 3. MCS Connect Initial -> MCS Connect Response
    let ci_raw = read_tpkt_for_test(&mut tls).await?;
    let ci_x224: X224<X224Data<'_>> = pdu_decode(&ci_raw)
        .map_err(|e| OperquayError::Protocol(format!("test srv CI X224 decode: {e}")))?;
    let ci: ConnectInitial = pdu_decode(ci_x224.0.data.as_ref())
        .map_err(|e| OperquayError::Protocol(format!("test srv CI decode: {e}")))?;

    let req_channels = ci
        .conference_create_request
        .gcc_blocks()
        .network
        .as_ref()
        .map_or_else(Vec::new, |net| {
            net.channels
                .iter()
                .enumerate()
                .map(|(i, _)| 1004u16 + u16::try_from(i).unwrap_or(0))
                .collect()
        });
    let io_channel: u16 = 1003;
    let user_channel: u16 = 1004 + u16::try_from(req_channels.len()).unwrap_or(0) + 1;
    let share_id: u32 = 0x0001_03EA;

    let gcc_blocks = ServerGccBlocks {
        core: ServerCoreData {
            version: RdpVersion::V5_PLUS,
            optional_data: ServerCoreOptionalData {
                client_requested_protocols: Some(neg_req.0.protocol),
                early_capability_flags: Some(
                    ServerEarlyCapabilityFlags::SKIP_CHANNELJOIN_SUPPORTED,
                ),
            },
        },
        network: ServerNetworkData {
            channel_ids: req_channels,
            io_channel,
        },
        security: ServerSecurityData::no_security(),
        message_channel: None,
        multi_transport_channel: None,
    };
    let cr = ConnectResponse {
        conference_create_response: ConferenceCreateResponse::new(user_channel, gcc_blocks)
            .map_err(|e| OperquayError::Protocol(format!("test srv CR gcc: {e}")))?,
        called_connect_id: 0,
        domain_parameters: DomainParameters::target(),
    };
    let cr_inner = pdu_encode_vec(&cr)
        .map_err(|e| OperquayError::Protocol(format!("test srv CR encode: {e}")))?;
    let cr_frame = pdu_encode_vec(&X224(X224Data {
        data: Cow::Owned(cr_inner),
    }))
    .map_err(|e| OperquayError::Protocol(format!("test srv CR wrap: {e}")))?;
    tls.write_all(&cr_frame).await?;

    // 4. MCS ErectDomain / AttachUser / ChannelJoin + ClientInfo PDU
    loop {
        let raw = read_tpkt_for_test(&mut tls).await?;
        let msg: X224<McsMessage<'_>> = pdu_decode(&raw)
            .map_err(|e| OperquayError::Protocol(format!("test srv MCS decode: {e}")))?;
        match msg.0 {
            McsMessage::AttachUserRequest(_) => {
                let confirm = X224(McsMessage::AttachUserConfirm(AttachUserConfirm {
                    result: 0,
                    initiator_id: user_channel,
                }));
                let enc = pdu_encode_vec(&confirm)
                    .map_err(|e| OperquayError::Protocol(format!("test srv AUC encode: {e}")))?;
                tls.write_all(&enc).await?;
            }
            McsMessage::ChannelJoinRequest(req) => {
                let confirm = X224(McsMessage::ChannelJoinConfirm(ChannelJoinConfirm {
                    result: 0,
                    initiator_id: req.initiator_id,
                    requested_channel_id: req.channel_id,
                    channel_id: req.channel_id,
                }));
                let enc = pdu_encode_vec(&confirm)
                    .map_err(|e| OperquayError::Protocol(format!("test srv CJC encode: {e}")))?;
                tls.write_all(&enc).await?;
            }
            McsMessage::SendDataRequest(_) => {
                break;
            }
            _ => {}
        }
    }

    // 5. Server Licensing Valid Client ErrorAlert
    let valid_license = LicensePdu::LicensingErrorMessage(
        LicensingErrorMessage::new_valid_client()
            .map_err(|e| OperquayError::Protocol(format!("test srv license build: {e}")))?,
    );
    let lic_bytes = pdu_encode_vec(&valid_license)
        .map_err(|e| OperquayError::Protocol(format!("test srv license encode: {e}")))?;
    let lic_ind = X224(SendDataIndication {
        initiator_id: user_channel,
        channel_id: io_channel,
        user_data: Cow::Owned(lic_bytes),
    });
    let lic_frame = pdu_encode_vec(&lic_ind)
        .map_err(|e| OperquayError::Protocol(format!("test srv license wrap: {e}")))?;
    tls.write_all(&lic_frame).await?;

    // 6. Server Demand Active
    let demand_active = ShareControlHeader {
        share_control_pdu: ShareControlPdu::ServerDemandActive(ServerDemandActive {
            pdu: DemandActive {
                source_descriptor: "RDP\0".to_owned(),
                capability_sets: vec![
                    CapabilitySet::General(General {
                        major_platform_type: MajorPlatformType::WINDOWS,
                        minor_platform_type: MinorPlatformType::WINDOWS_NT,
                        protocol_version: PROTOCOL_VER,
                        extra_flags: GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED
                            | GeneralExtraFlags::LONG_CREDENTIALS_SUPPORTED
                            | GeneralExtraFlags::AUTORECONNECT_SUPPORTED
                            | GeneralExtraFlags::ENC_SALTED_CHECKSUM,
                        refresh_rect_support: true,
                        suppress_output_support: true,
                    }),
                    CapabilitySet::Bitmap(Bitmap {
                        pref_bits_per_pix: 32,
                        desktop_width: width,
                        desktop_height: height,
                        desktop_resize_flag: true,
                        drawing_flags: BitmapDrawingFlags::ALLOW_DYNAMIC_COLOR_FIDELITY,
                    }),
                    CapabilitySet::Order(Order::new(
                        OrderFlags::NEGOTIATE_ORDER_SUPPORT
                            | OrderFlags::ZERO_BOUNDS_DELTAS_SUPPORT,
                        OrderSupportExFlags::empty(),
                        0,
                        1252,
                    )),
                    CapabilitySet::Pointer(Pointer {
                        color_pointer_cache_size: 25,
                        pointer_cache_size: 25,
                    }),
                    CapabilitySet::Input(Input {
                        input_flags: InputFlags::SCANCODES
                            | InputFlags::MOUSEX
                            | InputFlags::FASTPATH_INPUT
                            | InputFlags::UNICODE
                            | InputFlags::FASTPATH_INPUT_2,
                        keyboard_layout: 0x0409,
                        keyboard_type: Some(KeyboardType::IBM_ENHANCED),
                        keyboard_subtype: 0,
                        keyboard_function_key: 12,
                        keyboard_ime_filename: String::new(),
                    }),
                    CapabilitySet::VirtualChannel(VirtualChannel {
                        flags: VirtualChannelFlags::NO_COMPRESSION,
                        chunk_size: Some(1600),
                    }),
                ],
            },
        }),
        pdu_source: io_channel,
        share_id,
    };
    let da_bytes = pdu_encode_vec(&demand_active)
        .map_err(|e| OperquayError::Protocol(format!("test srv DA encode: {e}")))?;
    let da_ind = X224(SendDataIndication {
        initiator_id: io_channel,
        channel_id: io_channel,
        user_data: Cow::Owned(da_bytes),
    });
    let da_frame = pdu_encode_vec(&da_ind)
        .map_err(|e| OperquayError::Protocol(format!("test srv DA wrap: {e}")))?;
    tls.write_all(&da_frame).await?;

    // 7. Read Confirm Active + Finalization, then emit Server Synchronize/Control/FontMap
    let mut saw_confirm = false;
    let mut saw_font_list = false;
    while !(saw_confirm && saw_font_list) {
        let raw = read_tpkt_for_test(&mut tls).await?;
        let msg: X224<McsMessage<'_>> = pdu_decode(&raw)
            .map_err(|e| OperquayError::Protocol(format!("test srv act MCS decode: {e}")))?;
        if let McsMessage::SendDataRequest(sdr) = msg.0 {
            if sdr.channel_id == io_channel {
                if let Ok(sc) = pdu_decode::<ShareControlHeader>(sdr.user_data.as_ref()) {
                    match sc.share_control_pdu {
                        ShareControlPdu::ClientConfirmActive(_) => saw_confirm = true,
                        ShareControlPdu::Data(ShareDataHeader {
                            share_data_pdu: ShareDataPdu::FontList(_),
                            ..
                        }) => saw_font_list = true,
                        _ => {}
                    }
                }
            }
        }
    }

    let send_share_data = |pdu: ShareDataPdu| -> Result<Vec<u8>, OperquayError> {
        let sc = ShareControlHeader {
            share_control_pdu: ShareControlPdu::Data(ShareDataHeader {
                share_data_pdu: pdu,
                stream_priority: StreamPriority::Low,
                compression_flags: CompressionFlags::empty(),
                compression_type: CompressionType::K8,
            }),
            pdu_source: io_channel,
            share_id,
        };
        let sc_bytes = pdu_encode_vec(&sc)
            .map_err(|e| OperquayError::Protocol(format!("test srv share_data encode: {e}")))?;
        let mcs_ind = X224(SendDataIndication {
            initiator_id: io_channel,
            channel_id: io_channel,
            user_data: Cow::Owned(sc_bytes),
        });
        pdu_encode_vec(&mcs_ind)
            .map_err(|e| OperquayError::Protocol(format!("test srv share_data wrap: {e}")))
    };

    for pdu in [
        ShareDataPdu::Synchronize(SynchronizePdu {
            target_user_id: user_channel,
        }),
        ShareDataPdu::Control(ControlPdu {
            action: ControlAction::Cooperate,
            grant_id: 0,
            control_id: 0,
        }),
        ShareDataPdu::Control(ControlPdu {
            action: ControlAction::GrantedControl,
            grant_id: user_channel,
            control_id: 1,
        }),
        ShareDataPdu::FontMap(FontPdu::default()),
    ] {
        let bytes = send_share_data(pdu)?;
        tls.write_all(&bytes).await?;
    }
    tls.flush().await?;

    Ok(tls)
}

/// Loopback helper for tests: encodes a 32-bpp Fast-Path Bitmap Update PDU (`width`x`height` solid RGBA fill).
#[doc(hidden)]
pub fn encode_fastpath_solid_bitmap_for_test(
    width: u16,
    height: u16,
) -> Result<Vec<u8>, OperquayError> {
    use ironrdp_core::{encode_vec as pdu_encode_vec, WriteBuf};
    use ironrdp_pdu::bitmap::{BitmapData, BitmapUpdateData, Compression};
    use ironrdp_pdu::fast_path::{
        EncryptionFlags, FastPathHeader, FastPathUpdatePdu, Fragmentation, UpdateCode,
    };
    use ironrdp_pdu::geometry::InclusiveRectangle;

    let bgra = vec![0xFFu8; usize::from(width) * usize::from(height) * 4];
    let bmp = BitmapUpdateData {
        rectangles: vec![BitmapData {
            rectangle: InclusiveRectangle {
                left: 0,
                top: 0,
                right: width.saturating_sub(1),
                bottom: height.saturating_sub(1),
            },
            width,
            height,
            bits_per_pixel: 32,
            compression_flags: Compression::empty(),
            compressed_data_header: None,
            bitmap_data: &bgra,
        }],
    };
    let bmp_payload = pdu_encode_vec(&bmp)
        .map_err(|e| OperquayError::Protocol(format!("test fp bitmap encode: {e}")))?;
    let fp_upd = FastPathUpdatePdu {
        fragmentation: Fragmentation::Single,
        update_code: UpdateCode::Bitmap,
        compression_flags: None,
        compression_type: None,
        data: &bmp_payload,
    };
    let upd_bytes = pdu_encode_vec(&fp_upd)
        .map_err(|e| OperquayError::Protocol(format!("test fp upd encode: {e}")))?;
    let fp_hdr = FastPathHeader::new(EncryptionFlags::empty(), upd_bytes.len());
    let mut full = WriteBuf::new();
    ironrdp_core::encode_buf(&fp_hdr, &mut full)
        .map_err(|e| OperquayError::Protocol(format!("test fp hdr encode: {e}")))?;
    full.write_slice(&upd_bytes);
    Ok(full.filled().to_vec())
}

/// Loopback helper for tests: decodes a `FastPathInput` PDU and returns its event count.
#[doc(hidden)]
pub fn decode_fastpath_input_events_len_for_test(raw: &[u8]) -> Result<usize, OperquayError> {
    use ironrdp_core::decode as pdu_decode;
    use ironrdp_pdu::input::fast_path::FastPathInput;

    let fp_in: FastPathInput = pdu_decode(raw)
        .map_err(|e| OperquayError::Protocol(format!("test fp input decode: {e}")))?;
    Ok(fp_in.input_events().len())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use ironrdp_core::{decode as pdu_decode, encode_vec as pdu_encode_vec, WriteBuf};
    use ironrdp_pdu::bitmap::{BitmapData, BitmapUpdateData, Compression};
    use ironrdp_pdu::fast_path::{
        EncryptionFlags, FastPathHeader, FastPathUpdatePdu, Fragmentation, UpdateCode,
    };
    use ironrdp_pdu::geometry::InclusiveRectangle;
    use ironrdp_pdu::input::fast_path::FastPathInput;
    use operquay_core::{CertPolicy, RemoteDesktopSettings, SecretString};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use sha2::{Digest, Sha256};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    type DrawnRect = (u32, u32, u32, u32, usize);

    #[derive(Default)]
    struct TestSink {
        flushed: std::sync::atomic::AtomicUsize,
        drawn: Mutex<Vec<DrawnRect>>,
    }

    impl DisplaySink for TestSink {
        fn resize(&self, _layer_id: i32, _width: u32, _height: u32) {}
        fn draw_rgba_rect(
            &self,
            _layer_id: i32,
            x: u32,
            y: u32,
            w: u32,
            h: u32,
            rgba: &[u8],
            _stride: usize,
        ) {
            self.drawn.lock().unwrap().push((x, y, w, h, rgba.len()));
        }
        fn fill_solid_rect(
            &self,
            _layer_id: i32,
            _x: u32,
            _y: u32,
            _w: u32,
            _h: u32,
            _rgba: [u8; 4],
        ) {
        }
        fn copy_rect(&self, _: i32, _: u32, _: u32, _: u32, _: u32, _: i32, _: u32, _: u32) {}
        fn set_cursor(&self, _: u32, _: u32, _: u32, _: u32, _: &[u8]) {}
        fn move_cursor(&self, _: u32, _: u32) {}
        fn flush_frame(&self, _ts: u64) {
            self.flushed
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn live_ironrdp_session_connects_over_tls_renders_fastpath_bitmap_and_forwards_keys() {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let cert_sha: [u8; 32] = Sha256::digest(&cert_der).into();
        let key_der = cert.key_pair.serialize_der();

        let server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = accept_ironrdp_tls_handshake_for_test(tcp, acceptor, 640, 480)
                .await
                .unwrap();

            // Send an uncompressed 32-bpp 4x4 BGRA Fast-Path Bitmap update at (16, 16)
            let bgra_pixels = [0xFFu8; 4 * 4 * 4];
            let bmp = BitmapUpdateData {
                rectangles: vec![BitmapData {
                    rectangle: InclusiveRectangle {
                        left: 16,
                        top: 16,
                        right: 19,
                        bottom: 19,
                    },
                    width: 4,
                    height: 4,
                    bits_per_pixel: 32,
                    compression_flags: Compression::empty(),
                    compressed_data_header: None,
                    bitmap_data: &bgra_pixels,
                }],
            };
            let bmp_payload = pdu_encode_vec(&bmp).unwrap();
            let fp_upd = FastPathUpdatePdu {
                fragmentation: Fragmentation::Single,
                update_code: UpdateCode::Bitmap,
                compression_flags: None,
                compression_type: None,
                data: &bmp_payload,
            };
            let upd_bytes = pdu_encode_vec(&fp_upd).unwrap();
            let fp_hdr = FastPathHeader::new(EncryptionFlags::empty(), upd_bytes.len());
            let mut full = WriteBuf::new();
            ironrdp_core::encode_buf(&fp_hdr, &mut full).unwrap();
            full.write_slice(&upd_bytes);
            tls.write_all(full.filled()).await.unwrap();
            tls.flush().await.unwrap();

            // Read client Fast-Path Input PDU ('a' keysym -> scancode 0x1E)
            let mut rx = vec![0u8; 256];
            let n = tokio::time::timeout(std::time::Duration::from_secs(3), tls.read(&mut rx))
                .await
                .unwrap()
                .unwrap();
            assert!(n >= 4);
            let fp_in: FastPathInput = pdu_decode(&rx[..n]).unwrap();
            assert_ne!(fp_in.input_events().len(), 0);
        });

        let settings = RemoteDesktopSettings {
            cert_policy: CertPolicy::TofuPinned,
            rdp_security_mode: RdpSecurityMode::Tls,
            ..RemoteDesktopSettings::default()
        };
        let cfg = SessionConfig {
            session_id: "test-rdp".into(),
            tenant_id: "default".into(),
            protocol: "rdp".into(),
            target_host: "127.0.0.1".into(),
            target_port: addr.port(),
            width: 640,
            height: 480,
            dpi: 96,
            username: "Administrator".into(),
            password: SecretString::new("Secret123"),
            settings,
        };

        let sink = Arc::new(TestSink::default());
        let (tx, rx) = mpsc::channel(16);
        let shutdown = Arc::new(Notify::new());
        let sh2 = shutdown.clone();
        let sink2 = sink.clone();

        let client_task = tokio::spawn(async move {
            connect_live_rdp_tcp(addr, &cfg, sink2, rx, Some(cert_sha), sh2).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        if let Err(e) = tx
            .send(DesktopSessionInput::Key {
                keysym: 0x0061,
                pressed: true,
            })
            .await
        {
            let client_res = client_task.await.unwrap();
            panic!("key send failed ({e:?}); client result was: {client_res:?}");
        }

        tokio::time::timeout(std::time::Duration::from_secs(4), server_task)
            .await
            .unwrap()
            .unwrap();
        shutdown.notify_waiters();
        let res = client_task.await.unwrap();
        assert!(res.is_ok(), "client failed: {res:?}");
        assert!(
            sink.flushed.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "expected at least one flushed FastPath frame"
        );
        assert!(
            !sink.drawn.lock().unwrap().is_empty(),
            "expected drawn RGBA region"
        );
    }

    #[test]
    fn pointer_pdu_separates_move_from_button_flags_and_handles_wheel() {
        let cfg = SessionConfig {
            session_id: "test-ptr".into(),
            tenant_id: "default".into(),
            protocol: "rdp".into(),
            target_host: "127.0.0.1".into(),
            target_port: 3389,
            width: 1280,
            height: 720,
            dpi: 96,
            username: "Administrator".into(),
            password: SecretString::new("Secret123"),
            settings: RemoteDesktopSettings::default(),
        };
        let mut driver = IronRdpSessionDriver::new(&cfg);

        // Moving to (400, 300) and clicking left button emits MOVE first, then pure LEFT_BUTTON|DOWN
        let down = driver.translate_pointer_pdu(400, 300, 0x01);
        assert_eq!(down.len(), 2);
        match down[0] {
            IronFastPathInputEvent::MouseEvent(pdu) => {
                assert_eq!(pdu.flags, PointerFlags::MOVE);
                assert_eq!((pdu.x_position, pdu.y_position), (400, 300));
            }
            other => panic!("unexpected first event: {other:?}"),
        }
        match down[1] {
            IronFastPathInputEvent::MouseEvent(pdu) => {
                assert_eq!(pdu.flags, PointerFlags::LEFT_BUTTON | PointerFlags::DOWN);
                assert!(!pdu.flags.contains(PointerFlags::MOVE));
                assert_eq!((pdu.x_position, pdu.y_position), (400, 300));
            }
            other => panic!("unexpected second event: {other:?}"),
        }

        // Releasing left button at same coords emits pure LEFT_BUTTON without MOVE or DOWN
        let up = driver.translate_pointer_pdu(400, 300, 0x00);
        assert_eq!(up.len(), 1);
        match up[0] {
            IronFastPathInputEvent::MouseEvent(pdu) => {
                assert_eq!(pdu.flags, PointerFlags::LEFT_BUTTON);
                assert!(!pdu.flags.contains(PointerFlags::MOVE));
                assert!(!pdu.flags.contains(PointerFlags::DOWN));
            }
            other => panic!("unexpected release event: {other:?}"),
        }

        // Right click at same position emits pure RIGHT_BUTTON | DOWN then release
        let rdown = driver.translate_pointer_pdu(400, 300, 0x04);
        assert_eq!(rdown.len(), 1);
        match rdown[0] {
            IronFastPathInputEvent::MouseEvent(pdu) => {
                assert_eq!(pdu.flags, PointerFlags::RIGHT_BUTTON | PointerFlags::DOWN);
            }
            other => panic!("unexpected right-down event: {other:?}"),
        }
        let rup = driver.translate_pointer_pdu(400, 300, 0x00);
        assert_eq!(rup.len(), 1);
        match rup[0] {
            IronFastPathInputEvent::MouseEvent(pdu) => {
                assert_eq!(pdu.flags, PointerFlags::RIGHT_BUTTON);
            }
            other => panic!("unexpected right-up event: {other:?}"),
        }

        // Wheel up / down must not corrupt persistent mouse_button_mask
        let wheel_up = driver.translate_pointer_pdu(400, 300, 0x08);
        assert_eq!(wheel_up.len(), 1);
        match wheel_up[0] {
            IronFastPathInputEvent::MouseEvent(pdu) => {
                assert_eq!(pdu.flags, PointerFlags::VERTICAL_WHEEL);
                assert_eq!(pdu.number_of_wheel_rotation_units, 120);
            }
            other => panic!("unexpected wheel-up event: {other:?}"),
        }
        let wheel_down = driver.translate_pointer_pdu(400, 300, 0x10);
        assert_eq!(wheel_down.len(), 1);
        match wheel_down[0] {
            IronFastPathInputEvent::MouseEvent(pdu) => {
                assert_eq!(
                    pdu.flags,
                    PointerFlags::VERTICAL_WHEEL | PointerFlags::WHEEL_NEGATIVE
                );
                assert_eq!(pdu.number_of_wheel_rotation_units, -120);
            }
            other => panic!("unexpected wheel-down event: {other:?}"),
        }
        // Moving after wheel emits only pure MOVE (no fake button release)
        let after = driver.translate_pointer_pdu(410, 305, 0x00);
        assert_eq!(after.len(), 1);
        match after[0] {
            IronFastPathInputEvent::MouseEvent(pdu) => {
                assert_eq!(pdu.flags, PointerFlags::MOVE);
                assert_eq!((pdu.x_position, pdu.y_position), (410, 305));
            }
            other => panic!("unexpected post-wheel event: {other:?}"),
        }
    }

    #[test]
    fn compliance_mode_gates_standard_rdp_rc4_unless_explicit_ssm_exception() {
        assert!(matches!(
            check_rdp_legacy_crypto_policy(true, CertPolicy::TofuPinned, false),
            Err(OperquayError::SecurityPolicy(_))
        ));
        assert!(matches!(
            check_rdp_legacy_crypto_policy(true, CertPolicy::SsmLoopbackIgnore, false),
            Err(OperquayError::SecurityPolicy(_))
        ));
        assert!(check_rdp_legacy_crypto_policy(true, CertPolicy::SsmLoopbackIgnore, true).is_ok());
        assert!(check_rdp_legacy_crypto_policy(false, CertPolicy::TofuPinned, false).is_ok());
    }
}
