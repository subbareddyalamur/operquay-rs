use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use operquay_core::{
    compliance_mode_enabled, CertPolicy, DesktopSessionInput, DisplaySink, OperquayError,
    SessionConfig,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};

use crate::rfb::{
    encode_client_cut_text, encode_framebuffer_update_request, encode_key_event,
    encode_pointer_event, encode_set_desktop_size, encode_set_encodings,
    encode_set_pixel_format_rgba32, negotiate_rfb_over_stream_with_credentials,
    read_framebuffer_update_with_state, ZrleDecoder, SUPPORTED_ENCODINGS,
};

fn pack_dims(w: u16, h: u16) -> u32 {
    (u32::from(w) << 16) | u32::from(h)
}

fn unpack_dims(packed: u32) -> (u16, u16) {
    ((packed >> 16) as u16, (packed & 0xFFFF) as u16)
}

/// Reject legacy `VNCAuth` (`DES`) / unencrypted RFB in Compliance Mode unless explicitly
/// allowlisted inside an AWS SSM tunnel (`SsmLoopbackIgnore && allow_legacy_crypto_over_ssm`).
pub fn check_vnc_legacy_crypto_policy(
    compliance_mode: bool,
    cert_policy: CertPolicy,
    allow_legacy_crypto_over_ssm: bool,
) -> Result<(), OperquayError> {
    if compliance_mode
        && !(cert_policy == CertPolicy::SsmLoopbackIgnore && allow_legacy_crypto_over_ssm)
    {
        return Err(OperquayError::SecurityPolicy(
            "Legacy VNCAuth (DES) / None security is blocked in Compliance Mode unless tunneled over AWS SSM with allow_legacy_crypto_over_ssm"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Execute a live RFC 6143 RFB VNC session over any `AsyncRead + AsyncWrite + Unpin` stream
/// (TCP socket or `SsmVirtualStream`) using split I/O so `read_framebuffer_update` is never
/// cancelled mid-frame inside `tokio::select!`.
pub async fn run_live_vnc_over_stream<S>(
    mut stream: S,
    config: &SessionConfig,
    sink: Arc<dyn DisplaySink>,
    mut input_rx: mpsc::Receiver<DesktopSessionInput>,
    shutdown: Arc<Notify>,
) -> Result<(), OperquayError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    check_vnc_legacy_crypto_policy(
        compliance_mode_enabled(),
        config.settings.cert_policy,
        config.settings.allow_legacy_crypto_over_ssm,
    )?;
    let init = negotiate_rfb_over_stream_with_credentials(
        &mut stream,
        &config.username,
        config.password.expose(),
        true,
    )
    .await
    .map_err(|e| OperquayError::Protocol(e.to_string()))?;

    sink.resize(0, u32::from(init.width), u32::from(init.height));
    stream.write_all(&encode_set_pixel_format_rgba32()).await?;
    stream
        .write_all(&encode_set_encodings(SUPPORTED_ENCODINGS))
        .await?;
    stream
        .write_all(&encode_framebuffer_update_request(
            false,
            0,
            0,
            init.width,
            init.height,
        ))
        .await?;
    stream.flush().await?;

    let dims = Arc::new(AtomicU32::new(pack_dims(init.width, init.height)));
    let dims_reader = dims.clone();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(128);
    let out_tx_reader = out_tx.clone();
    let sink_reader = sink.clone();

    let read_loop = async move {
        let mut zrle = ZrleDecoder::new();
        loop {
            let rects =
                read_framebuffer_update_with_state(&mut reader, sink_reader.as_ref(), &mut zrle)
                    .await
                    .map_err(|e| OperquayError::Protocol(e.to_string()))?;

            if let Some((nw, nh)) = zrle.latest_desktop_size.take() {
                dims_reader.store(pack_dims(nw, nh), Ordering::Relaxed);
            }

            if rects > 0 {
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                sink_reader.flush_frame(now_ms);
            }

            let (w, h) = unpack_dims(dims_reader.load(Ordering::Relaxed));
            let req = encode_framebuffer_update_request(true, 0, 0, w, h).to_vec();
            if out_tx_reader.send(req).await.is_err() {
                break;
            }
        }
        Ok::<(), OperquayError>(())
    };

    let input_pump = async move {
        while let Some(ev) = input_rx.recv().await {
            let bytes = match ev {
                DesktopSessionInput::Key { keysym, pressed } => {
                    encode_key_event(pressed, keysym).to_vec()
                }
                DesktopSessionInput::Pointer { x, y, button_mask } => {
                    encode_pointer_event(button_mask, x, y).to_vec()
                }
                DesktopSessionInput::Resize {
                    width: w,
                    height: h,
                    ..
                } => {
                    let nw = u16::try_from(w.clamp(200, 4096)).unwrap_or(1280);
                    let nh = u16::try_from(h.clamp(200, 4096)).unwrap_or(720);
                    dims.store(pack_dims(nw, nh), Ordering::Relaxed);
                    encode_set_desktop_size(nw, nh).to_vec()
                }
                DesktopSessionInput::ClipboardText { text } => encode_client_cut_text(&text),
                DesktopSessionInput::SecureAttentionSequence => {
                    let mut seq = Vec::with_capacity(6 * 8);
                    for ks in [0xFFE3u32, 0xFFE9u32, 0xFFFFu32] {
                        seq.extend_from_slice(&encode_key_event(true, ks));
                    }
                    for ks in [0xFFFFu32, 0xFFE9u32, 0xFFE3u32] {
                        seq.extend_from_slice(&encode_key_event(false, ks));
                    }
                    seq
                }
                DesktopSessionInput::KeyboardLayout { .. }
                | DesktopSessionInput::SyncAck { .. } => continue,
            };
            if out_tx.send(bytes).await.is_err() {
                break;
            }
        }
        Ok::<(), OperquayError>(())
    };

    let write_loop = async move {
        while let Some(chunk) = out_rx.recv().await {
            writer.write_all(&chunk).await?;
            writer.flush().await?;
        }
        Ok::<(), OperquayError>(())
    };

    let session_fut = async {
        tokio::select! {
            res = read_loop => res,
            res = input_pump => res,
            res = write_loop => res,
        }
    };

    tokio::select! {
        () = shutdown.notified() => Ok(()),
        res = session_fut => res,
    }
}

/// Resolve hostname/IP and connect a live VNC session over TCP.
pub async fn connect_live_vnc_host(
    host: &str,
    port: u16,
    config: &SessionConfig,
    sink: Arc<dyn DisplaySink>,
    input_rx: mpsc::Receiver<DesktopSessionInput>,
    shutdown: Arc<Notify>,
) -> Result<(), OperquayError> {
    let tcp = TcpStream::connect((host, port)).await?;
    tcp.set_nodelay(true)?;
    run_live_vnc_over_stream(tcp, config, sink, input_rx, shutdown).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compliance_mode_gates_vnc_des_unless_explicit_ssm_exception() {
        assert!(matches!(
            check_vnc_legacy_crypto_policy(true, CertPolicy::TofuPinned, false),
            Err(OperquayError::SecurityPolicy(_))
        ));
        assert!(matches!(
            check_vnc_legacy_crypto_policy(true, CertPolicy::SsmLoopbackIgnore, false),
            Err(OperquayError::SecurityPolicy(_))
        ));
        assert!(check_vnc_legacy_crypto_policy(true, CertPolicy::SsmLoopbackIgnore, true).is_ok());
        assert!(check_vnc_legacy_crypto_policy(false, CertPolicy::TofuPinned, false).is_ok());
    }
}
