use bytes::{BufMut, BytesMut};
use operquay_core::DisplaySink;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::auth::{encrypt_apple_ard_credentials, encrypt_vnc_challenge};

pub const RFB_VERSION_3_8: &[u8; 12] = b"RFB 003.008\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RfbSecurityType {
    Invalid = 0,
    None = 1,
    VncAuth = 2,
    Tight = 16,
    VeNCrypt = 19,
    AppleArd = 30,
}

impl RfbSecurityType {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Invalid),
            1 => Some(Self::None),
            2 => Some(Self::VncAuth),
            16 => Some(Self::Tight),
            19 => Some(Self::VeNCrypt),
            30 => Some(Self::AppleArd),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum RfBError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unexpected RFB greeting '{0}'")]
    InvalidGreeting(String),
    #[error("security handshake failed: {0}")]
    AuthFailed(String),
    #[error("no acceptable RFB security type offered")]
    NoSupportedSecurity,
    #[error("unsupported encoding {0}")]
    UnsupportedEncoding(i32),
    #[error("RFB protocol framing error: {0}")]
    Protocol(String),
}

/// Preferred RFC 6143 + Tier-2 RFB encodings sent in `SetEncodings` (most compact first).
pub const SUPPORTED_ENCODINGS: &[i32] = &[
    16,   // ZRLE
    7,    // Tight (Fill, JPEG, Copy/Palette/Gradient)
    5,    // Hextile
    2,    // RRE
    1,    // CopyRect
    0,    // Raw
    -308, // ExtendedDesktopSize
    -223, // DesktopSize
    -239, // RichCursor
];

const MAX_ZRLE_COMPRESSED_BYTES: usize = 32 * 1024 * 1024;
const MAX_ZRLE_UNCOMPRESSED_BYTES: usize = 64 * 1024 * 1024;

/// Persistent RFC 6143 §7.7.6 zlib stream state (plus 4 `Tight` zlib streams) retained across
/// all framebuffer updates on a single VNC connection.
#[derive(Debug)]
pub struct ZrleDecoder {
    inflate: flate2::Decompress,
    tight_streams: [flate2::Decompress; 4],
    pub latest_desktop_size: Option<(u16, u16)>,
}

impl Default for ZrleDecoder {
    fn default() -> Self {
        Self::new()
    }
}

fn inflate_persistent_zlib(
    inflate: &mut flate2::Decompress,
    compressed: &[u8],
    max_uncompressed: usize,
) -> Result<Vec<u8>, RfBError> {
    let mut out = Vec::with_capacity(compressed.len().saturating_mul(4).max(256));
    let mut offset = 0usize;
    while offset < compressed.len() {
        if out.len() >= max_uncompressed {
            return Err(RfBError::Protocol(
                "RFB uncompressed payload exceeded 64 MiB limit".into(),
            ));
        }
        let before_in = inflate.total_in();
        let before_out = inflate.total_out();
        out.reserve(4096);
        let status = inflate
            .decompress_vec(
                &compressed[offset..],
                &mut out,
                flate2::FlushDecompress::Sync,
            )
            .map_err(|e| RfBError::Protocol(format!("RFB zlib inflate failed: {e}")))?;
        let consumed = usize::try_from(inflate.total_in() - before_in).unwrap_or(0);
        let produced = usize::try_from(inflate.total_out() - before_out).unwrap_or(0);
        offset += consumed;
        if consumed == 0 && produced == 0 {
            break;
        }
        if status == flate2::Status::StreamEnd {
            break;
        }
    }
    Ok(out)
}

impl ZrleDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inflate: flate2::Decompress::new(true),
            tight_streams: [
                flate2::Decompress::new(true),
                flate2::Decompress::new(true),
                flate2::Decompress::new(true),
                flate2::Decompress::new(true),
            ],
            latest_desktop_size: None,
        }
    }

    pub fn decompress(&mut self, compressed: &[u8]) -> Result<Vec<u8>, RfBError> {
        inflate_persistent_zlib(&mut self.inflate, compressed, MAX_ZRLE_UNCOMPRESSED_BYTES)
    }

    pub fn reset_tight_streams(&mut self, reset_mask: u8) {
        for (idx, stream) in self.tight_streams.iter_mut().enumerate() {
            if (reset_mask & (1 << idx)) != 0 {
                stream.reset(true);
            }
        }
    }

    pub fn decompress_tight(
        &mut self,
        stream_id: usize,
        compressed: &[u8],
    ) -> Result<Vec<u8>, RfBError> {
        let idx = stream_id.min(3);
        inflate_persistent_zlib(
            &mut self.tight_streams[idx],
            compressed,
            MAX_ZRLE_UNCOMPRESSED_BYTES,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInit {
    pub width: u16,
    pub height: u16,
    pub bpp: u8,
    pub depth: u8,
    pub big_endian: bool,
    pub true_color: bool,
    pub name: String,
}

#[must_use]
pub fn encode_framebuffer_update_request(
    incremental: bool,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
) -> [u8; 10] {
    let mut b = [0u8; 10];
    b[0] = 3;
    b[1] = u8::from(incremental);
    b[2..4].copy_from_slice(&x.to_be_bytes());
    b[4..6].copy_from_slice(&y.to_be_bytes());
    b[6..8].copy_from_slice(&w.to_be_bytes());
    b[8..10].copy_from_slice(&h.to_be_bytes());
    b
}

#[must_use]
pub fn encode_key_event(pressed: bool, keysym: u32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0] = 4;
    b[1] = u8::from(pressed);
    b[4..8].copy_from_slice(&keysym.to_be_bytes());
    b
}

#[must_use]
pub fn encode_pointer_event(button_mask: u8, x: u16, y: u16) -> [u8; 6] {
    let mut b = [0u8; 6];
    b[0] = 5;
    b[1] = button_mask;
    b[2..4].copy_from_slice(&x.to_be_bytes());
    b[4..6].copy_from_slice(&y.to_be_bytes());
    b
}

#[must_use]
pub fn encode_client_cut_text(text: &str) -> Vec<u8> {
    // RFC 6143 ISO-8859-1 / UTF-8 clipboard buffer
    let bytes = text.as_bytes();
    let mut buf = BytesMut::with_capacity(8 + bytes.len());
    buf.put_u8(6);
    buf.put_bytes(0, 3);
    buf.put_u32(bytes.len() as u32);
    buf.put_slice(bytes);
    buf.to_vec()
}

/// Request canonical 32-bpp little-endian RGBA (`R@0, G@8, B@16`) pixel format per RFC 6143 §7.5.1.
#[must_use]
pub fn encode_set_pixel_format_rgba32() -> [u8; 20] {
    let mut b = [0u8; 20];
    b[0] = 0; // SetPixelFormat
    b[4] = 32; // bits-per-pixel
    b[5] = 24; // depth
    b[6] = 0; // big-endian = false
    b[7] = 1; // true-colour = true
    b[8..10].copy_from_slice(&255u16.to_be_bytes()); // red-max
    b[10..12].copy_from_slice(&255u16.to_be_bytes()); // green-max
    b[12..14].copy_from_slice(&255u16.to_be_bytes()); // blue-max
    b[14] = 0; // red-shift
    b[15] = 8; // green-shift
    b[16] = 16; // blue-shift
    b
}

/// Advertise supported encodings (`Raw`, `CopyRect`, `DesktopSize`, `RichCursor`).
#[must_use]
pub fn encode_set_encodings(encodings: &[i32]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(4 + encodings.len() * 4);
    buf.put_u8(2); // SetEncodings
    buf.put_u8(0);
    buf.put_u16(encodings.len() as u16);
    for &enc in encodings {
        buf.put_i32(enc);
    }
    buf.to_vec()
}

/// RFC 6143 `SetDesktopSize` (`0xfb` message = 251) observed in `guac_vnc_display_set_size @ 0x7f7b`.
#[must_use]
pub fn encode_set_desktop_size(width: u16, height: u16) -> [u8; 24] {
    let mut b = [0u8; 24];
    b[0] = 251;
    b[2..4].copy_from_slice(&width.to_be_bytes());
    b[4..6].copy_from_slice(&height.to_be_bytes());
    b[6] = 1; // number of screens
    b[12..14].copy_from_slice(&width.to_be_bytes());
    b[14..16].copy_from_slice(&height.to_be_bytes());
    b
}

/// Complete RFC 6143 3.8 client handshake over any `AsyncRead + AsyncWrite` stream
/// (TCP socket, SSH channel, or `SsmVirtualStream`).
pub async fn negotiate_rfb_over_stream<S>(
    stream: &mut S,
    password: &str,
    shared: bool,
) -> Result<ServerInit, RfBError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_rfb_over_stream_with_credentials(stream, "", password, shared).await
}

/// Complete RFC 6143 3.8 client handshake supporting `Apple ARD` (`30`), `VncAuth` (`2`),
/// and `None` (`1`) authentication over any `AsyncRead + AsyncWrite` stream.
pub async fn negotiate_rfb_over_stream_with_credentials<S>(
    stream: &mut S,
    username: &str,
    password: &str,
    shared: bool,
) -> Result<ServerInit, RfBError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut greeting = [0u8; 12];
    stream.read_exact(&mut greeting).await?;
    if !greeting.starts_with(b"RFB ") {
        return Err(RfBError::InvalidGreeting(
            String::from_utf8_lossy(&greeting).into_owned(),
        ));
    }
    stream.write_all(RFB_VERSION_3_8).await?;

    let num_sec = stream.read_u8().await?;
    if num_sec == 0 {
        let reason_len = stream.read_u32().await? as usize;
        let mut reason = vec![0u8; reason_len.min(4096)];
        stream.read_exact(&mut reason).await?;
        return Err(RfBError::AuthFailed(
            String::from_utf8_lossy(&reason).into_owned(),
        ));
    }

    let mut sec_types = vec![0u8; usize::from(num_sec)];
    stream.read_exact(&mut sec_types).await?;

    let chosen = if sec_types.contains(&(RfbSecurityType::AppleArd as u8))
        && (!username.is_empty() || !password.is_empty())
    {
        RfbSecurityType::AppleArd
    } else if sec_types.contains(&(RfbSecurityType::VncAuth as u8)) && !password.is_empty() {
        RfbSecurityType::VncAuth
    } else if sec_types.contains(&(RfbSecurityType::None as u8)) {
        RfbSecurityType::None
    } else if sec_types.contains(&(RfbSecurityType::VncAuth as u8)) {
        RfbSecurityType::VncAuth
    } else {
        return Err(RfBError::NoSupportedSecurity);
    };

    stream.write_u8(chosen as u8).await?;

    match chosen {
        RfbSecurityType::VncAuth => {
            let mut challenge = [0u8; 16];
            stream.read_exact(&mut challenge).await?;
            let response = encrypt_vnc_challenge(password, &challenge);
            stream.write_all(&response).await?;
        }
        RfbSecurityType::AppleArd => {
            let generator = stream.read_u16().await?;
            let key_len = usize::from(stream.read_u16().await?);
            if key_len == 0 || key_len > 2048 {
                return Err(RfBError::AuthFailed(
                    "invalid Apple ARD DH key length".into(),
                ));
            }
            let mut prime = vec![0u8; key_len];
            let mut peer_pub = vec![0u8; key_len];
            stream.read_exact(&mut prime).await?;
            stream.read_exact(&mut peer_pub).await?;
            let (client_pub, ciphertext) =
                encrypt_apple_ard_credentials(generator, &prime, &peer_pub, username, password)
                    .map_err(RfBError::AuthFailed)?;
            stream.write_all(&ciphertext).await?;
            stream.write_all(&client_pub).await?;
        }
        _ => {}
    }
    stream.flush().await?;

    let sec_result = stream.read_u32().await?;
    if sec_result != 0 {
        return Err(RfBError::AuthFailed(format!(
            "SecurityResult status {sec_result}"
        )));
    }

    stream.write_u8(u8::from(shared)).await?;

    let width = stream.read_u16().await?;
    let height = stream.read_u16().await?;
    let bpp = stream.read_u8().await?;
    let depth = stream.read_u8().await?;
    let big_endian = stream.read_u8().await? != 0;
    let true_color = stream.read_u8().await? != 0;
    let mut rest_pf = [0u8; 12];
    stream.read_exact(&mut rest_pf).await?;
    let name_len = stream.read_u32().await? as usize;
    let mut name_buf = vec![0u8; name_len.min(4096)];
    stream.read_exact(&mut name_buf).await?;

    Ok(ServerInit {
        width,
        height,
        bpp,
        depth,
        big_endian,
        true_color,
        name: String::from_utf8_lossy(&name_buf).into_owned(),
    })
}

/// Read one server RFB message (`FramebufferUpdate`, `SetColourMapEntries`, `Bell`, or `ServerCutText`).
pub async fn read_framebuffer_update<S>(
    stream: &mut S,
    sink: &dyn DisplaySink,
) -> Result<usize, RfBError>
where
    S: AsyncRead + Unpin,
{
    let mut one_shot_zrle = ZrleDecoder::new();
    read_framebuffer_update_with_state(stream, sink, &mut one_shot_zrle).await
}

/// Read one server RFB message using a persistent stateful [`ZrleDecoder`] across frames.
pub async fn read_framebuffer_update_with_state<S>(
    stream: &mut S,
    sink: &dyn DisplaySink,
    zrle: &mut ZrleDecoder,
) -> Result<usize, RfBError>
where
    S: AsyncRead + Unpin,
{
    let msg_type = stream.read_u8().await?;
    match msg_type {
        0 => {}
        1 => {
            // SetColourMapEntries
            let _pad = stream.read_u8().await?;
            let _first = stream.read_u16().await?;
            let count = usize::from(stream.read_u16().await?);
            let mut buf = vec![0u8; count * 6];
            stream.read_exact(&mut buf).await?;
            return Ok(0);
        }
        3 => {
            // ServerCutText (RFC 6143 §7.6.4, ISO-8859-1)
            let mut pad = [0u8; 3];
            stream.read_exact(&mut pad).await?;
            let len = usize::try_from(stream.read_u32().await?)
                .unwrap_or(0)
                .min(4 * 1024 * 1024);
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            let text: String = buf.into_iter().map(char::from).collect();
            sink.on_clipboard_text(&text);
            return Ok(0);
        }
        // Bell (2) or ignored unknown server message
        _ => return Ok(0),
    }

    let _padding = stream.read_u8().await?;
    let num_rects = stream.read_u16().await?;

    for _ in 0..num_rects {
        let x = u32::from(stream.read_u16().await?);
        let y = u32::from(stream.read_u16().await?);
        let w = u32::from(stream.read_u16().await?);
        let h = u32::from(stream.read_u16().await?);
        let encoding = stream.read_i32().await?;

        match encoding {
            0 => {
                // Raw 32-bpp RGBA pixels (normalize alpha channel to 255)
                let byte_len = (w as usize) * (h as usize) * 4;
                let mut raw = vec![0u8; byte_len];
                stream.read_exact(&mut raw).await?;
                for px in raw.as_chunks_mut::<4>().0 {
                    px[3] = 255;
                }
                sink.draw_rgba_rect(0, x, y, w, h, &raw, (w as usize) * 4);
            }
            1 => {
                // CopyRect
                let sx = u32::from(stream.read_u16().await?);
                let sy = u32::from(stream.read_u16().await?);
                sink.copy_rect(0, sx, sy, w, h, 0, x, y);
            }
            2 => {
                decode_rre_rect(stream, sink, x, y, w, h).await?;
            }
            5 => {
                decode_hextile_rect(stream, sink, x, y, w, h).await?;
            }
            7 => {
                decode_tight_rect(stream, sink, zrle, x, y, w, h).await?;
            }
            16 => {
                decode_zrle_rect(stream, sink, zrle, x, y, w, h).await?;
            }
            -308 => {
                // ExtendedDesktopSize pseudo-encoding
                let num_screens = usize::from(stream.read_u8().await?);
                let mut ext_pad = [0u8; 3];
                stream.read_exact(&mut ext_pad).await?;
                let mut screens = vec![0u8; num_screens * 16];
                stream.read_exact(&mut screens).await?;
                // x == 0 means server-initiated or accepted resize
                if x == 0 && w >= 200 && h >= 200 {
                    let nw = u16::try_from(w).unwrap_or(1280);
                    let nh = u16::try_from(h).unwrap_or(720);
                    zrle.latest_desktop_size = Some((nw, nh));
                    sink.resize(0, w, h);
                }
            }
            -223 => {
                // DesktopSize pseudo-encoding
                let nw = u16::try_from(w).unwrap_or(1280);
                let nh = u16::try_from(h).unwrap_or(720);
                zrle.latest_desktop_size = Some((nw, nh));
                sink.resize(0, w, h);
            }
            -239 => {
                // RichCursor pseudo-encoding: w*h*4 RGBA + ceil(w/8)*h 1bpp bitmask
                let px_len = (w as usize) * (h as usize) * 4;
                let mask_stride = (w as usize).div_ceil(8);
                let mask_len = mask_stride * (h as usize);
                let mut px = vec![0u8; px_len];
                let mut mask = vec![0u8; mask_len];
                stream.read_exact(&mut px).await?;
                stream.read_exact(&mut mask).await?;
                for row in 0..(h as usize) {
                    for col in 0..(w as usize) {
                        let visible = (mask[row * mask_stride + col / 8] >> (7 - (col % 8))) & 1;
                        let off = (row * (w as usize) + col) * 4;
                        px[off + 3] = if visible != 0 { 255 } else { 0 };
                    }
                }
                sink.set_cursor(x, y, w, h, &px);
            }
            other => return Err(RfBError::UnsupportedEncoding(other)),
        }
    }

    Ok(usize::from(num_rects))
}

async fn read_rgba_pixel<S: AsyncRead + Unpin>(stream: &mut S) -> Result<[u8; 4], RfBError> {
    let mut px = [0u8; 4];
    stream.read_exact(&mut px).await?;
    px[3] = 255;
    Ok(px)
}

async fn decode_rre_rect<S: AsyncRead + Unpin>(
    stream: &mut S,
    sink: &dyn DisplaySink,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
) -> Result<(), RfBError> {
    let num_subrects = stream.read_u32().await?;
    let bg = read_rgba_pixel(stream).await?;
    sink.fill_solid_rect(0, x, y, w, h, bg);

    for _ in 0..num_subrects {
        let pixel = read_rgba_pixel(stream).await?;
        let sx = u32::from(stream.read_u16().await?);
        let sy = u32::from(stream.read_u16().await?);
        let sw = u32::from(stream.read_u16().await?);
        let sh = u32::from(stream.read_u16().await?);
        sink.fill_solid_rect(0, x + sx, y + sy, sw, sh, pixel);
    }
    Ok(())
}

async fn decode_hextile_rect<S: AsyncRead + Unpin>(
    stream: &mut S,
    sink: &dyn DisplaySink,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
) -> Result<(), RfBError> {
    let mut bg = [0u8, 0, 0, 255];
    let mut fg = [255u8, 255, 255, 255];

    let mut ty = 0u32;
    while ty < h {
        let th = (h - ty).min(16);
        let mut tx = 0u32;
        while tx < w {
            let tw = (w - tx).min(16);
            let subencoding = stream.read_u8().await?;
            if (subencoding & 0x01) != 0 {
                // Raw Hextile tile
                let byte_len = (tw as usize) * (th as usize) * 4;
                let mut raw = vec![0u8; byte_len];
                stream.read_exact(&mut raw).await?;
                for px in raw.as_chunks_mut::<4>().0 {
                    px[3] = 255;
                }
                sink.draw_rgba_rect(0, x + tx, y + ty, tw, th, &raw, (tw as usize) * 4);
                tx += 16;
                continue;
            }
            if (subencoding & 0x02) != 0 {
                bg = read_rgba_pixel(stream).await?;
            }
            sink.fill_solid_rect(0, x + tx, y + ty, tw, th, bg);
            if (subencoding & 0x04) != 0 {
                fg = read_rgba_pixel(stream).await?;
            }
            if (subencoding & 0x08) != 0 {
                let n_subrects = usize::from(stream.read_u8().await?);
                let coloured = (subencoding & 0x10) != 0;
                for _ in 0..n_subrects {
                    let colour = if coloured {
                        read_rgba_pixel(stream).await?
                    } else {
                        fg
                    };
                    let xy = stream.read_u8().await?;
                    let wh = stream.read_u8().await?;
                    let sx = u32::from(xy >> 4);
                    let sy = u32::from(xy & 0x0F);
                    let sw = u32::from((wh >> 4) + 1);
                    let sh = u32::from((wh & 0x0F) + 1);
                    sink.fill_solid_rect(0, x + tx + sx, y + ty + sy, sw, sh, colour);
                }
            }
            tx += 16;
        }
        ty += 16;
    }
    Ok(())
}

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, RfBError> {
        let &b = self.data.get(self.pos).ok_or_else(|| {
            RfBError::Protocol("unexpected end of ZRLE uncompressed tile stream".into())
        })?;
        self.pos += 1;
        Ok(b)
    }

    fn read_exact(&mut self, n: usize) -> Result<&'a [u8], RfBError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| RfBError::Protocol("ZRLE tile length overflow".into()))?;
        if end > self.data.len() {
            return Err(RfBError::Protocol(
                "truncated ZRLE uncompressed payload".into(),
            ));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_cpixel(&mut self) -> Result<[u8; 4], RfBError> {
        let c = self.read_exact(3)?;
        Ok([c[0], c[1], c[2], 255])
    }

    fn read_rle_length(&mut self) -> Result<usize, RfBError> {
        let mut len = 1usize;
        loop {
            let b = self.read_u8()?;
            len = len.saturating_add(usize::from(b));
            if b != 255 {
                break;
            }
        }
        Ok(len)
    }
}

async fn decode_zrle_rect<S: AsyncRead + Unpin>(
    stream: &mut S,
    sink: &dyn DisplaySink,
    zrle: &mut ZrleDecoder,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
) -> Result<(), RfBError> {
    let comp_len = usize::try_from(stream.read_u32().await?).unwrap_or(usize::MAX);
    if comp_len > MAX_ZRLE_COMPRESSED_BYTES {
        return Err(RfBError::Protocol(format!(
            "ZRLE compressed block too large: {comp_len}"
        )));
    }
    let mut compressed = vec![0u8; comp_len];
    stream.read_exact(&mut compressed).await?;
    let raw = zrle.decompress(&compressed)?;
    let mut cursor = ByteCursor::new(&raw);

    let mut ty = 0u32;
    while ty < h {
        let th = (h - ty).min(64);
        let mut tx = 0u32;
        while tx < w {
            let tw = (w - tx).min(64);
            let sub = cursor.read_u8()?;
            let px_count = (tw as usize) * (th as usize);
            match sub {
                0 => {
                    // Raw CPIXEL
                    let mut rgba = Vec::with_capacity(px_count * 4);
                    for _ in 0..px_count {
                        rgba.extend_from_slice(&cursor.read_cpixel()?);
                    }
                    sink.draw_rgba_rect(0, x + tx, y + ty, tw, th, &rgba, (tw as usize) * 4);
                }
                1 => {
                    // Solid tile
                    let colour = cursor.read_cpixel()?;
                    sink.fill_solid_rect(0, x + tx, y + ty, tw, th, colour);
                }
                2..=16 => {
                    // Packed palette tile
                    let pal_len = usize::from(sub);
                    let mut palette = Vec::with_capacity(pal_len);
                    for _ in 0..pal_len {
                        palette.push(cursor.read_cpixel()?);
                    }
                    let bits_per_index: usize = if pal_len <= 2 {
                        1
                    } else if pal_len <= 4 {
                        2
                    } else {
                        4
                    };
                    let mask = (1u8 << bits_per_index) - 1;
                    let mut rgba = Vec::with_capacity(px_count * 4);
                    for _row in 0..th {
                        let mut byte = 0u8;
                        let mut bits_left = 0usize;
                        for _col in 0..tw {
                            if bits_left == 0 {
                                byte = cursor.read_u8()?;
                                bits_left = 8;
                            }
                            bits_left -= bits_per_index;
                            let idx = usize::from((byte >> bits_left) & mask);
                            let px = palette.get(idx).copied().unwrap_or([0, 0, 0, 255]);
                            rgba.extend_from_slice(&px);
                        }
                    }
                    sink.draw_rgba_rect(0, x + tx, y + ty, tw, th, &rgba, (tw as usize) * 4);
                }
                128 => {
                    // Plain RLE
                    let mut rgba = Vec::with_capacity(px_count * 4);
                    let mut written = 0usize;
                    while written < px_count {
                        let px = cursor.read_cpixel()?;
                        let run = cursor.read_rle_length()?.min(px_count - written);
                        for _ in 0..run {
                            rgba.extend_from_slice(&px);
                        }
                        written += run;
                    }
                    sink.draw_rgba_rect(0, x + tx, y + ty, tw, th, &rgba, (tw as usize) * 4);
                }
                130..=255 => {
                    // Palette RLE
                    let pal_len = usize::from(sub - 128);
                    let mut palette = Vec::with_capacity(pal_len);
                    for _ in 0..pal_len {
                        palette.push(cursor.read_cpixel()?);
                    }
                    let mut rgba = Vec::with_capacity(px_count * 4);
                    let mut written = 0usize;
                    while written < px_count {
                        let idx_byte = cursor.read_u8()?;
                        let is_run = (idx_byte & 0x80) != 0;
                        let idx = usize::from(idx_byte & 0x7F);
                        let run = if is_run { cursor.read_rle_length()? } else { 1 }
                            .min(px_count - written);
                        let px = palette.get(idx).copied().unwrap_or([0, 0, 0, 255]);
                        for _ in 0..run {
                            rgba.extend_from_slice(&px);
                        }
                        written += run;
                    }
                    sink.draw_rgba_rect(0, x + tx, y + ty, tw, th, &rgba, (tw as usize) * 4);
                }
                other => {
                    return Err(RfBError::Protocol(format!(
                        "unsupported ZRLE subencoding {other}"
                    )));
                }
            }
            tx += 64;
        }
        ty += 64;
    }
    Ok(())
}

async fn read_tight_compact_len<S: AsyncRead + Unpin>(stream: &mut S) -> Result<usize, RfBError> {
    let b0 = stream.read_u8().await?;
    let mut len = usize::from(b0 & 0x7F);
    if (b0 & 0x80) != 0 {
        let b1 = stream.read_u8().await?;
        len |= usize::from(b1 & 0x7F) << 7;
        if (b1 & 0x80) != 0 {
            let b2 = stream.read_u8().await?;
            len |= usize::from(b2) << 14;
        }
    }
    if len > MAX_ZRLE_COMPRESSED_BYTES {
        return Err(RfBError::Protocol(format!(
            "Tight payload length {len} exceeds limit"
        )));
    }
    Ok(len)
}

async fn read_tight_payload<S: AsyncRead + Unpin>(
    stream: &mut S,
    zrle: &mut ZrleDecoder,
    stream_id: usize,
    raw_len: usize,
) -> Result<Vec<u8>, RfBError> {
    if raw_len < 12 {
        let mut buf = vec![0u8; raw_len];
        stream.read_exact(&mut buf).await?;
        Ok(buf)
    } else {
        let comp_len = read_tight_compact_len(stream).await?;
        let mut comp = vec![0u8; comp_len];
        stream.read_exact(&mut comp).await?;
        zrle.decompress_tight(stream_id, &comp)
    }
}

async fn decode_tight_rect<S: AsyncRead + Unpin>(
    stream: &mut S,
    sink: &dyn DisplaySink,
    zrle: &mut ZrleDecoder,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
) -> Result<(), RfBError> {
    let ctrl = stream.read_u8().await?;
    zrle.reset_tight_streams(ctrl & 0x0F);

    let comp_type = ctrl >> 4;
    match comp_type {
        0x08 => {
            // FillCompression: single 3-byte TPIXEL [R, G, B]
            let mut rgb = [0u8; 3];
            stream.read_exact(&mut rgb).await?;
            sink.fill_solid_rect(0, x, y, w, h, [rgb[0], rgb[1], rgb[2], 255]);
            Ok(())
        }
        0x09 => {
            // JpegCompression: compact length + raw JPEG image
            let len = read_tight_compact_len(stream).await?;
            let mut jpeg = vec![0u8; len];
            stream.read_exact(&mut jpeg).await?;
            sink.draw_jpeg_rect(0, x, y, w, h, &jpeg);
            Ok(())
        }
        0x00..=0x07 => {
            // BasicCompression
            let stream_id = usize::from((ctrl >> 4) & 0x03);
            let filter_id = if (ctrl & 0x40) != 0 {
                stream.read_u8().await?
            } else {
                0
            };
            let px_count = (w as usize) * (h as usize);
            let mut rgba = vec![0u8; px_count * 4];
            match filter_id {
                0 => {
                    // CopyFilter: RGB24 TPIXELs
                    let raw = read_tight_payload(stream, zrle, stream_id, px_count * 3).await?;
                    if raw.len() < px_count * 3 {
                        return Err(RfBError::Protocol("truncated Tight Copy payload".into()));
                    }
                    for i in 0..px_count {
                        let s = i * 3;
                        let d = i * 4;
                        rgba[d] = raw[s];
                        rgba[d + 1] = raw[s + 1];
                        rgba[d + 2] = raw[s + 2];
                        rgba[d + 3] = 255;
                    }
                }
                1 => {
                    // PaletteFilter
                    let num_colors = usize::from(stream.read_u8().await?) + 1;
                    let mut pal_raw = vec![0u8; num_colors * 3];
                    stream.read_exact(&mut pal_raw).await?;
                    let mut palette = Vec::with_capacity(num_colors);
                    for c in 0..num_colors {
                        let o = c * 3;
                        palette.push([pal_raw[o], pal_raw[o + 1], pal_raw[o + 2], 255]);
                    }
                    if num_colors == 2 {
                        let row_bytes = (w as usize).div_ceil(8);
                        let raw =
                            read_tight_payload(stream, zrle, stream_id, row_bytes * (h as usize))
                                .await?;
                        if raw.len() < row_bytes * (h as usize) {
                            return Err(RfBError::Protocol(
                                "truncated Tight 1bpp Palette payload".into(),
                            ));
                        }
                        for row in 0..(h as usize) {
                            for col in 0..(w as usize) {
                                let bit = (raw[row * row_bytes + col / 8] >> (7 - (col % 8))) & 1;
                                let c = palette[usize::from(bit)];
                                let d = (row * (w as usize) + col) * 4;
                                rgba[d..d + 4].copy_from_slice(&c);
                            }
                        }
                    } else {
                        let raw = read_tight_payload(stream, zrle, stream_id, px_count).await?;
                        if raw.len() < px_count {
                            return Err(RfBError::Protocol(
                                "truncated Tight 8bpp Palette payload".into(),
                            ));
                        }
                        for (i, &idx) in raw.iter().take(px_count).enumerate() {
                            let c = palette
                                .get(usize::from(idx))
                                .copied()
                                .unwrap_or([0, 0, 0, 255]);
                            let d = i * 4;
                            rgba[d..d + 4].copy_from_slice(&c);
                        }
                    }
                }
                2 => {
                    // GradientFilter: predictor est[y,x] = clamp(left + up - up_left, 0..=255)
                    let raw = read_tight_payload(stream, zrle, stream_id, px_count * 3).await?;
                    if raw.len() < px_count * 3 {
                        return Err(RfBError::Protocol(
                            "truncated Tight Gradient payload".into(),
                        ));
                    }
                    let uw = w as usize;
                    let uh = h as usize;
                    for row in 0..uh {
                        for col in 0..uw {
                            let idx = row * uw + col;
                            let s = idx * 3;
                            let d = idx * 4;
                            for ch in 0..3usize {
                                let left = if col > 0 {
                                    i32::from(rgba[(idx - 1) * 4 + ch])
                                } else {
                                    0
                                };
                                let up = if row > 0 {
                                    i32::from(rgba[(idx - uw) * 4 + ch])
                                } else {
                                    0
                                };
                                let up_left = if row > 0 && col > 0 {
                                    i32::from(rgba[(idx - uw - 1) * 4 + ch])
                                } else {
                                    0
                                };
                                let pred = (left + up - up_left).clamp(0, 255);
                                rgba[d + ch] = ((pred + i32::from(raw[s + ch])) & 0xFF) as u8;
                            }
                            rgba[d + 3] = 255;
                        }
                    }
                }
                other => {
                    return Err(RfBError::Protocol(format!(
                        "unsupported Tight filter id {other}"
                    )));
                }
            }
            sink.draw_rgba_rect(0, x, y, w, h, &rgba, (w as usize) * 4);
            Ok(())
        }
        other => Err(RfBError::Protocol(format!(
            "unsupported Tight compression mode {other:#x}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    type SolidRect = (u32, u32, u32, u32, [u8; 4]);
    type JpegRect = (u32, u32, u32, u32, usize);

    #[derive(Default)]
    struct CaptureSink {
        drawn: Mutex<Vec<(u32, u32, u32, u32)>>,
        solids: Mutex<Vec<SolidRect>>,
        clips: Mutex<Vec<String>>,
        resizes: Mutex<Vec<(u32, u32)>>,
        jpegs: Mutex<Vec<JpegRect>>,
    }

    impl DisplaySink for CaptureSink {
        fn resize(&self, _: i32, w: u32, h: u32) {
            self.resizes.lock().unwrap().push((w, h));
        }
        fn draw_rgba_rect(&self, _: i32, x: u32, y: u32, w: u32, h: u32, _: &[u8], _: usize) {
            self.drawn.lock().unwrap().push((x, y, w, h));
        }
        fn fill_solid_rect(&self, _: i32, x: u32, y: u32, w: u32, h: u32, rgba: [u8; 4]) {
            self.solids.lock().unwrap().push((x, y, w, h, rgba));
        }
        fn copy_rect(&self, _: i32, _: u32, _: u32, _: u32, _: u32, _: i32, _: u32, _: u32) {}
        fn set_cursor(&self, _: u32, _: u32, _: u32, _: u32, _: &[u8]) {}
        fn move_cursor(&self, _: u32, _: u32) {}
        fn flush_frame(&self, _: u64) {}
        fn draw_jpeg_rect(&self, _: i32, x: u32, y: u32, w: u32, h: u32, jpeg: &[u8]) {
            self.jpegs.lock().unwrap().push((x, y, w, h, jpeg.len()));
        }
        fn on_clipboard_text(&self, text: &str) {
            self.clips.lock().unwrap().push(text.to_owned());
        }
    }

    #[tokio::test]
    async fn decodes_rre_hextile_stateful_zrle_and_server_cut_text() {
        let mut wire = Vec::<u8>::new();

        // Message 1: ServerCutText("hello")
        wire.extend_from_slice(&[3, 0, 0, 0]);
        wire.extend_from_slice(&5u32.to_be_bytes());
        wire.extend_from_slice(b"hello");

        // Message 2: FramebufferUpdate with 2 rects: RRE(2) + Hextile(5)
        wire.extend_from_slice(&[0, 0, 0, 2]);
        // Rect 1: RRE at (10,20) 32x32, 1 subrect
        wire.extend_from_slice(&10u16.to_be_bytes());
        wire.extend_from_slice(&20u16.to_be_bytes());
        wire.extend_from_slice(&32u16.to_be_bytes());
        wire.extend_from_slice(&32u16.to_be_bytes());
        wire.extend_from_slice(&2i32.to_be_bytes());
        wire.extend_from_slice(&1u32.to_be_bytes());
        wire.extend_from_slice(&[1, 2, 3, 0]); // bg
        wire.extend_from_slice(&[9, 8, 7, 0]); // fg
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&8u16.to_be_bytes());
        wire.extend_from_slice(&8u16.to_be_bytes());

        // Rect 2: Hextile at (0,0) 8x8 -> single tile subencoding bg|fg|subrects (0x02|0x04|0x08=0x0e)
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(&8u16.to_be_bytes());
        wire.extend_from_slice(&8u16.to_be_bytes());
        wire.extend_from_slice(&5i32.to_be_bytes());
        wire.push(0x0E);
        wire.extend_from_slice(&[10, 20, 30, 0]); // bg
        wire.extend_from_slice(&[40, 50, 60, 0]); // fg
        wire.push(1); // 1 subrect
        wire.push(0x12); // xy=(1,2)
        wire.push(0x23); // wh=(3,4)

        // Messages 3 & 4: two stateful ZRLE rects sharing a single zlib stream
        let mut comp = flate2::Compress::new(flate2::Compression::default(), true);
        let compress_chunk = |comp: &mut flate2::Compress, plain: &[u8]| -> Vec<u8> {
            let mut dst = Vec::with_capacity(plain.len() + 128);
            let mut in_off = 0usize;
            while in_off < plain.len() {
                let b_in = comp.total_in();
                if dst.capacity() == dst.len() {
                    dst.reserve(256);
                }
                let _ = comp
                    .compress_vec(&plain[in_off..], &mut dst, flate2::FlushCompress::Sync)
                    .unwrap();
                let adv = usize::try_from(comp.total_in() - b_in).unwrap();
                in_off += adv;
                if adv == 0 {
                    dst.reserve(256);
                }
            }
            dst
        };

        // ZRLE Frame A: 4x4 Solid tile [11, 22, 33]
        let c1 = compress_chunk(&mut comp, &[1, 11, 22, 33]);
        wire.extend_from_slice(&[0, 0, 0, 1]);
        wire.extend_from_slice(&50u16.to_be_bytes());
        wire.extend_from_slice(&60u16.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&16i32.to_be_bytes());
        wire.extend_from_slice(&u32::try_from(c1.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(&c1);

        // ZRLE Frame B (continuing same zlib stream): 2x2 Plain RLE tile (run 4 of [77, 88, 99])
        let c2 = compress_chunk(&mut comp, &[128, 77, 88, 99, 3]);
        wire.extend_from_slice(&[0, 0, 0, 1]);
        wire.extend_from_slice(&70u16.to_be_bytes());
        wire.extend_from_slice(&80u16.to_be_bytes());
        wire.extend_from_slice(&2u16.to_be_bytes());
        wire.extend_from_slice(&2u16.to_be_bytes());
        wire.extend_from_slice(&16i32.to_be_bytes());
        wire.extend_from_slice(&u32::try_from(c2.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(&c2);

        let mut cur = std::io::Cursor::new(wire);
        let sink = Arc::new(CaptureSink::default());
        let mut zrle = ZrleDecoder::new();

        assert_eq!(
            read_framebuffer_update_with_state(&mut cur, sink.as_ref(), &mut zrle)
                .await
                .unwrap(),
            0
        );
        assert_eq!(*sink.clips.lock().unwrap(), vec!["hello".to_owned()]);
        assert_eq!(
            read_framebuffer_update_with_state(&mut cur, sink.as_ref(), &mut zrle)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            read_framebuffer_update_with_state(&mut cur, sink.as_ref(), &mut zrle)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            read_framebuffer_update_with_state(&mut cur, sink.as_ref(), &mut zrle)
                .await
                .unwrap(),
            1
        );
        assert!(sink
            .solids
            .lock()
            .unwrap()
            .contains(&(50, 60, 4, 4, [11, 22, 33, 255])));
        assert_eq!(*sink.drawn.lock().unwrap(), vec![(70, 80, 2, 2)]);
    }

    #[tokio::test]
    async fn full_rfb_3_8_vncauth_loopback_handshake_and_raw_update() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(RFB_VERSION_3_8).await.unwrap();
            let mut client_ver = [0u8; 12];
            sock.read_exact(&mut client_ver).await.unwrap();
            assert_eq!(&client_ver, RFB_VERSION_3_8);

            // Offer security types: None (1) & VncAuth (2)
            sock.write_all(&[2, 1, 2]).await.unwrap();
            let chosen = sock.read_u8().await.unwrap();
            assert_eq!(chosen, 2);

            let challenge = [7u8; 16];
            sock.write_all(&challenge).await.unwrap();
            let mut client_resp = [0u8; 16];
            sock.read_exact(&mut client_resp).await.unwrap();
            assert_eq!(client_resp, encrypt_vnc_challenge("vncpass", &challenge));

            sock.write_u32(0).await.unwrap(); // OK
            let _shared = sock.read_u8().await.unwrap();

            // ServerInit 1024x768 "LoopbackVNC"
            sock.write_u16(1024).await.unwrap();
            sock.write_u16(768).await.unwrap();
            sock.write_all(&[32, 24, 0, 1]).await.unwrap();
            sock.write_all(&[0u8; 12]).await.unwrap();
            sock.write_u32(11).await.unwrap();
            sock.write_all(b"LoopbackVNC").await.unwrap();

            // Wait for FramebufferUpdateRequest (10 bytes), send 2x2 Raw tile
            let mut req = [0u8; 10];
            sock.read_exact(&mut req).await.unwrap();
            sock.write_all(&[0, 0, 0, 1]).await.unwrap(); // FramebufferUpdate, 1 rect
            sock.write_u16(16).await.unwrap();
            sock.write_u16(32).await.unwrap();
            sock.write_u16(2).await.unwrap();
            sock.write_u16(2).await.unwrap();
            sock.write_i32(0).await.unwrap(); // Raw encoding
            sock.write_all(&[255u8; 16]).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let init = negotiate_rfb_over_stream(&mut client, "vncpass", true)
            .await
            .unwrap();
        assert_eq!(init.width, 1024);
        assert_eq!(init.height, 768);
        assert_eq!(init.name, "LoopbackVNC");

        let req = encode_framebuffer_update_request(false, 0, 0, init.width, init.height);
        client.write_all(&req).await.unwrap();

        let sink = Arc::new(CaptureSink::default());
        let count = read_framebuffer_update(&mut client, sink.as_ref())
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(*sink.drawn.lock().unwrap(), vec![(16, 32, 2, 2)]);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn decodes_tight_variants_and_extended_desktop_size() {
        let mut wire = Vec::<u8>::new();
        // FramebufferUpdate with 7 rects:
        // 1) Tight Fill, 2) Tight Basic Copy raw (<12B), 3) Tight Basic Copy zlib (>=12B),
        // 4) Tight Palette 1bpp raw, 5) Tight Palette 3-color 8bpp zlib, 6) Tight Gradient raw,
        // 7) Tight JPEG, plus separate ExtendedDesktopSize (-308) message
        wire.extend_from_slice(&[0, 0, 0, 7]);

        // 1: Tight Fill at (1,2) 4x4 [200, 100, 50]
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&2u16.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&7i32.to_be_bytes());
        wire.push(0x80);
        wire.extend_from_slice(&[200, 100, 50]);

        // 2: Tight Basic Copy raw (<12B) at (10,10) 2x1 -> 6 bytes
        wire.extend_from_slice(&10u16.to_be_bytes());
        wire.extend_from_slice(&10u16.to_be_bytes());
        wire.extend_from_slice(&2u16.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&7i32.to_be_bytes());
        wire.push(0x00); // stream 0, no filter
        wire.extend_from_slice(&[1, 2, 3, 4, 5, 6]);

        // Helper for zlib Tight compression with FlushCompress::Sync
        let zlib_sync = |plain: &[u8]| -> Vec<u8> {
            let mut c = flate2::Compress::new(flate2::Compression::default(), true);
            let mut dst = Vec::with_capacity(plain.len() + 64);
            let mut off = 0usize;
            while off < plain.len() {
                let before = c.total_in();
                if dst.capacity() == dst.len() {
                    dst.reserve(128);
                }
                let _ = c
                    .compress_vec(&plain[off..], &mut dst, flate2::FlushCompress::Sync)
                    .unwrap();
                off += usize::try_from(c.total_in() - before).unwrap();
            }
            dst
        };
        let push_compact_len = |out: &mut Vec<u8>, len: usize| {
            if len < 0x80 {
                out.push(len as u8);
            } else if len < 0x4000 {
                out.push(((len & 0x7F) | 0x80) as u8);
                out.push((len >> 7) as u8);
            } else {
                out.push(((len & 0x7F) | 0x80) as u8);
                out.push((((len >> 7) & 0x7F) | 0x80) as u8);
                out.push((len >> 14) as u8);
            }
        };

        // 3: Tight Basic Copy zlib (>=12B) at (20,20) 4x2 -> 24 bytes
        wire.extend_from_slice(&20u16.to_be_bytes());
        wire.extend_from_slice(&20u16.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&2u16.to_be_bytes());
        wire.extend_from_slice(&7i32.to_be_bytes());
        wire.push(0x01); // stream 0, reset stream 0
        let comp3 = zlib_sync(&[99u8; 24]);
        push_compact_len(&mut wire, comp3.len());
        wire.extend_from_slice(&comp3);

        // 4: Tight Palette 1bpp (2 colors) raw at (30,30) 4x2 (row_bytes=1, total 2B < 12)
        wire.extend_from_slice(&30u16.to_be_bytes());
        wire.extend_from_slice(&30u16.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&2u16.to_be_bytes());
        wire.extend_from_slice(&7i32.to_be_bytes());
        wire.push(0x40); // Basic + filter_id follows
        wire.push(1); // PaletteFilter
        wire.push(1); // 2 colors (num_colors - 1)
        wire.extend_from_slice(&[0, 0, 0, 255, 255, 255]);
        wire.extend_from_slice(&[0b1010_0000, 0b0101_0000]);

        // 5: Tight Palette 3-color 8bpp zlib at (40,40) 4x4 (16B >= 12)
        wire.extend_from_slice(&40u16.to_be_bytes());
        wire.extend_from_slice(&40u16.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&7i32.to_be_bytes());
        wire.push(0x52); // stream 1, filter_id follows, reset bit 1
        wire.push(1); // PaletteFilter
        wire.push(2); // 3 colors
        wire.extend_from_slice(&[1, 1, 1, 2, 2, 2, 3, 3, 3]);
        let comp5 = zlib_sync(&[0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0]);
        push_compact_len(&mut wire, comp5.len());
        wire.extend_from_slice(&comp5);

        // 6: Tight Gradient raw (<12B) at (50,50) 2x1 -> 6B
        wire.extend_from_slice(&50u16.to_be_bytes());
        wire.extend_from_slice(&50u16.to_be_bytes());
        wire.extend_from_slice(&2u16.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&7i32.to_be_bytes());
        wire.push(0x40);
        wire.push(2); // GradientFilter
        wire.extend_from_slice(&[10, 20, 30, 5, 5, 5]);

        // 7: Tight JPEG at (60,60) 8x8 -> fake JPEG header
        wire.extend_from_slice(&60u16.to_be_bytes());
        wire.extend_from_slice(&60u16.to_be_bytes());
        wire.extend_from_slice(&8u16.to_be_bytes());
        wire.extend_from_slice(&8u16.to_be_bytes());
        wire.extend_from_slice(&7i32.to_be_bytes());
        wire.push(0x90);
        push_compact_len(&mut wire, 4);
        wire.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xD9]);

        // Message 2: ExtendedDesktopSize (-308) 1440x900 with 1 screen
        wire.extend_from_slice(&[0, 0, 0, 1]);
        wire.extend_from_slice(&0u16.to_be_bytes()); // x=0 reason (accepted/server)
        wire.extend_from_slice(&0u16.to_be_bytes()); // y
        wire.extend_from_slice(&1440u16.to_be_bytes());
        wire.extend_from_slice(&900u16.to_be_bytes());
        wire.extend_from_slice(&(-308i32).to_be_bytes());
        wire.push(1); // 1 screen
        wire.extend_from_slice(&[0, 0, 0]);
        wire.extend_from_slice(&1u32.to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(&1440u16.to_be_bytes());
        wire.extend_from_slice(&900u16.to_be_bytes());
        wire.extend_from_slice(&0u32.to_be_bytes());

        let mut cur = std::io::Cursor::new(wire);
        let sink = Arc::new(CaptureSink::default());
        let mut dec = ZrleDecoder::new();
        assert_eq!(
            read_framebuffer_update_with_state(&mut cur, sink.as_ref(), &mut dec)
                .await
                .unwrap(),
            7
        );
        assert_eq!(
            read_framebuffer_update_with_state(&mut cur, sink.as_ref(), &mut dec)
                .await
                .unwrap(),
            1
        );

        assert!(sink
            .solids
            .lock()
            .unwrap()
            .contains(&(1, 2, 4, 4, [200, 100, 50, 255])));
        assert_eq!(sink.drawn.lock().unwrap().len(), 5);
        assert_eq!(*sink.jpegs.lock().unwrap(), vec![(60, 60, 8, 8, 4)]);
        assert_eq!(dec.latest_desktop_size, Some((1440, 900)));
        assert_eq!(*sink.resizes.lock().unwrap(), vec![(1440, 900)]);
    }
}
