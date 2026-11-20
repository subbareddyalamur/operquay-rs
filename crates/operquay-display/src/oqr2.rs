use bytes::{BufMut, BytesMut};
use thiserror::Error;

/// Compact binary wire magic for low-latency `"operquay-rdp-v2"` WebSocket frames.
pub const OQR2_MAGIC: [u8; 4] = *b"OQR2";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Oqr2Error {
    #[error("frame too short ({0} bytes)")]
    TooShort(usize),
    #[error("invalid OQR2 magic header")]
    BadMagic,
    #[error("unknown OQR2 opcode 0x{0:02x}")]
    UnknownOpcode(u8),
}

/// Binary desktop frame & control messages eliminating base64/text overhead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Oqr2Message {
    HelloAck {
        width: u16,
        height: u16,
        cursor_prediction: bool,
        trace_id: String,
        protocol: String,
    },
    TilePng {
        layer: i32,
        x: u16,
        y: u16,
        w: u16,
        h: u16,
        png_bytes: Vec<u8>,
    },
    TileJpeg {
        layer: i32,
        x: u16,
        y: u16,
        w: u16,
        h: u16,
        jpeg_bytes: Vec<u8>,
    },
    SolidFill {
        layer: i32,
        x: u16,
        y: u16,
        w: u16,
        h: u16,
        rgba: [u8; 4],
    },
    CopyRect {
        src_layer: i32,
        sx: u16,
        sy: u16,
        w: u16,
        h: u16,
        dst_layer: i32,
        dx: u16,
        dy: u16,
    },
    CursorShape {
        hot_x: u16,
        hot_y: u16,
        w: u16,
        h: u16,
        rgba: Vec<u8>,
    },
    CursorMove {
        x: u16,
        y: u16,
    },
    ResizeSurface {
        layer: i32,
        w: u16,
        h: u16,
    },
    StatsSync {
        server_ts_ms: u64,
        lag_ms: u32,
        fps: u16,
        jpeg_quality: u8,
        dropped_frames: u64,
        codec_tag: String,
    },
    H264Frame {
        layer: i32,
        x: u16,
        y: u16,
        w: u16,
        h: u16,
        annex_b: Vec<u8>,
    },
    ClipboardText {
        text: String,
    },
}

impl Oqr2Message {
    /// Encode as binary `OQR2` payload (`magic[4] | opcode:u8 | seq:u32_le | body...`).
    #[must_use]
    pub fn encode(&self, seq: u32) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(64);
        buf.put_slice(&OQR2_MAGIC);
        match self {
            Self::HelloAck {
                width,
                height,
                cursor_prediction,
                trace_id,
                protocol,
            } => {
                buf.put_u8(0x01);
                buf.put_u32_le(seq);
                buf.put_u16_le(*width);
                buf.put_u16_le(*height);
                buf.put_u8(u8::from(*cursor_prediction));
                put_str(&mut buf, trace_id);
                put_str(&mut buf, protocol);
            }
            Self::TilePng {
                layer,
                x,
                y,
                w,
                h,
                png_bytes,
            } => {
                buf.put_u8(0x02);
                buf.put_u32_le(seq);
                buf.put_i32_le(*layer);
                buf.put_u16_le(*x);
                buf.put_u16_le(*y);
                buf.put_u16_le(*w);
                buf.put_u16_le(*h);
                buf.put_u32_le(png_bytes.len() as u32);
                buf.put_slice(png_bytes);
            }
            Self::TileJpeg {
                layer,
                x,
                y,
                w,
                h,
                jpeg_bytes,
            } => {
                buf.put_u8(0x03);
                buf.put_u32_le(seq);
                buf.put_i32_le(*layer);
                buf.put_u16_le(*x);
                buf.put_u16_le(*y);
                buf.put_u16_le(*w);
                buf.put_u16_le(*h);
                buf.put_u32_le(jpeg_bytes.len() as u32);
                buf.put_slice(jpeg_bytes);
            }
            Self::SolidFill {
                layer,
                x,
                y,
                w,
                h,
                rgba,
            } => {
                buf.put_u8(0x04);
                buf.put_u32_le(seq);
                buf.put_i32_le(*layer);
                buf.put_u16_le(*x);
                buf.put_u16_le(*y);
                buf.put_u16_le(*w);
                buf.put_u16_le(*h);
                buf.put_slice(rgba);
            }
            Self::CopyRect {
                src_layer,
                sx,
                sy,
                w,
                h,
                dst_layer,
                dx,
                dy,
            } => {
                buf.put_u8(0x05);
                buf.put_u32_le(seq);
                buf.put_i32_le(*src_layer);
                buf.put_u16_le(*sx);
                buf.put_u16_le(*sy);
                buf.put_u16_le(*w);
                buf.put_u16_le(*h);
                buf.put_i32_le(*dst_layer);
                buf.put_u16_le(*dx);
                buf.put_u16_le(*dy);
            }
            Self::CursorShape {
                hot_x,
                hot_y,
                w,
                h,
                rgba,
            } => {
                buf.put_u8(0x06);
                buf.put_u32_le(seq);
                buf.put_u16_le(*hot_x);
                buf.put_u16_le(*hot_y);
                buf.put_u16_le(*w);
                buf.put_u16_le(*h);
                buf.put_u32_le(rgba.len() as u32);
                buf.put_slice(rgba);
            }
            Self::CursorMove { x, y } => {
                buf.put_u8(0x07);
                buf.put_u32_le(seq);
                buf.put_u16_le(*x);
                buf.put_u16_le(*y);
            }
            Self::ResizeSurface { layer, w, h } => {
                buf.put_u8(0x08);
                buf.put_u32_le(seq);
                buf.put_i32_le(*layer);
                buf.put_u16_le(*w);
                buf.put_u16_le(*h);
            }
            Self::StatsSync {
                server_ts_ms,
                lag_ms,
                fps,
                jpeg_quality,
                dropped_frames,
                codec_tag,
            } => {
                buf.put_u8(0x09);
                buf.put_u32_le(seq);
                buf.put_u64_le(*server_ts_ms);
                buf.put_u32_le(*lag_ms);
                buf.put_u16_le(*fps);
                buf.put_u8(*jpeg_quality);
                buf.put_u64_le(*dropped_frames);
                put_str(&mut buf, codec_tag);
            }
            Self::H264Frame {
                layer,
                x,
                y,
                w,
                h,
                annex_b,
            } => {
                buf.put_u8(0x0A);
                buf.put_u32_le(seq);
                buf.put_i32_le(*layer);
                buf.put_u16_le(*x);
                buf.put_u16_le(*y);
                buf.put_u16_le(*w);
                buf.put_u16_le(*h);
                buf.put_u32_le(annex_b.len() as u32);
                buf.put_slice(annex_b);
            }
            Self::ClipboardText { text } => {
                buf.put_u8(0x0B);
                buf.put_u32_le(seq);
                let b = text.as_bytes();
                buf.put_u32_le(b.len() as u32);
                buf.put_slice(b);
            }
        }
        buf.to_vec()
    }

    pub fn decode(data: &[u8]) -> Result<(u32, Self), Oqr2Error> {
        if data.len() < 9 {
            return Err(Oqr2Error::TooShort(data.len()));
        }
        if data[0..4] != OQR2_MAGIC {
            return Err(Oqr2Error::BadMagic);
        }
        let opcode = data[4];
        let seq = u32::from_le_bytes([data[5], data[6], data[7], data[8]]);
        let mut cursor = &data[9..];

        let msg = match opcode {
            0x01 => {
                let width = take_u16(&mut cursor)?;
                let height = take_u16(&mut cursor)?;
                let cursor_prediction = take_u8(&mut cursor)? != 0;
                let trace_id = take_str(&mut cursor)?;
                let protocol = take_str(&mut cursor)?;
                Self::HelloAck {
                    width,
                    height,
                    cursor_prediction,
                    trace_id,
                    protocol,
                }
            }
            0x02 => {
                let tile = take_tile(&mut cursor)?;
                Self::TilePng {
                    layer: tile.layer,
                    x: tile.x,
                    y: tile.y,
                    w: tile.w,
                    h: tile.h,
                    png_bytes: tile.bytes,
                }
            }
            0x03 => {
                let tile = take_tile(&mut cursor)?;
                Self::TileJpeg {
                    layer: tile.layer,
                    x: tile.x,
                    y: tile.y,
                    w: tile.w,
                    h: tile.h,
                    jpeg_bytes: tile.bytes,
                }
            }
            0x04 => {
                let layer = take_i32(&mut cursor)?;
                let x = take_u16(&mut cursor)?;
                let y = take_u16(&mut cursor)?;
                let w = take_u16(&mut cursor)?;
                let h = take_u16(&mut cursor)?;
                if cursor.len() < 4 {
                    return Err(Oqr2Error::TooShort(data.len()));
                }
                let rgba = [cursor[0], cursor[1], cursor[2], cursor[3]];
                Self::SolidFill {
                    layer,
                    x,
                    y,
                    w,
                    h,
                    rgba,
                }
            }
            0x05 => {
                let src_layer = take_i32(&mut cursor)?;
                let sx = take_u16(&mut cursor)?;
                let sy = take_u16(&mut cursor)?;
                let w = take_u16(&mut cursor)?;
                let h = take_u16(&mut cursor)?;
                let dst_layer = take_i32(&mut cursor)?;
                let dx = take_u16(&mut cursor)?;
                let dy = take_u16(&mut cursor)?;
                Self::CopyRect {
                    src_layer,
                    sx,
                    sy,
                    w,
                    h,
                    dst_layer,
                    dx,
                    dy,
                }
            }
            0x06 => {
                let hot_x = take_u16(&mut cursor)?;
                let hot_y = take_u16(&mut cursor)?;
                let w = take_u16(&mut cursor)?;
                let h = take_u16(&mut cursor)?;
                let len = take_u32(&mut cursor)? as usize;
                if cursor.len() < len {
                    return Err(Oqr2Error::TooShort(data.len()));
                }
                let rgba = cursor[..len].to_vec();
                Self::CursorShape {
                    hot_x,
                    hot_y,
                    w,
                    h,
                    rgba,
                }
            }
            0x07 => Self::CursorMove {
                x: take_u16(&mut cursor)?,
                y: take_u16(&mut cursor)?,
            },
            0x08 => Self::ResizeSurface {
                layer: take_i32(&mut cursor)?,
                w: take_u16(&mut cursor)?,
                h: take_u16(&mut cursor)?,
            },
            0x09 => Self::StatsSync {
                server_ts_ms: take_u64(&mut cursor)?,
                lag_ms: take_u32(&mut cursor)?,
                fps: take_u16(&mut cursor)?,
                jpeg_quality: take_u8(&mut cursor)?,
                dropped_frames: take_u64(&mut cursor)?,
                codec_tag: take_str(&mut cursor)?,
            },
            0x0A => {
                let tile = take_tile(&mut cursor)?;
                Self::H264Frame {
                    layer: tile.layer,
                    x: tile.x,
                    y: tile.y,
                    w: tile.w,
                    h: tile.h,
                    annex_b: tile.bytes,
                }
            }
            0x0B => {
                let len = take_u32(&mut cursor)? as usize;
                if cursor.len() < len {
                    return Err(Oqr2Error::TooShort(data.len()));
                }
                Self::ClipboardText {
                    text: String::from_utf8_lossy(&cursor[..len]).into_owned(),
                }
            }
            other => return Err(Oqr2Error::UnknownOpcode(other)),
        };

        Ok((seq, msg))
    }
}

fn put_str(buf: &mut BytesMut, val: &str) {
    let bytes = val.as_bytes();
    let len = bytes.len().min(u16::MAX as usize) as u16;
    buf.put_u16_le(len);
    buf.put_slice(&bytes[..usize::from(len)]);
}

fn take_u8(buf: &mut &[u8]) -> Result<u8, Oqr2Error> {
    if buf.is_empty() {
        return Err(Oqr2Error::TooShort(0));
    }
    let v = buf[0];
    *buf = &buf[1..];
    Ok(v)
}

fn take_u16(buf: &mut &[u8]) -> Result<u16, Oqr2Error> {
    if buf.len() < 2 {
        return Err(Oqr2Error::TooShort(buf.len()));
    }
    let v = u16::from_le_bytes([buf[0], buf[1]]);
    *buf = &buf[2..];
    Ok(v)
}

fn take_i32(buf: &mut &[u8]) -> Result<i32, Oqr2Error> {
    if buf.len() < 4 {
        return Err(Oqr2Error::TooShort(buf.len()));
    }
    let v = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    *buf = &buf[4..];
    Ok(v)
}

fn take_u32(buf: &mut &[u8]) -> Result<u32, Oqr2Error> {
    if buf.len() < 4 {
        return Err(Oqr2Error::TooShort(buf.len()));
    }
    let v = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    *buf = &buf[4..];
    Ok(v)
}

fn take_u64(buf: &mut &[u8]) -> Result<u64, Oqr2Error> {
    if buf.len() < 8 {
        return Err(Oqr2Error::TooShort(buf.len()));
    }
    let v = u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    *buf = &buf[8..];
    Ok(v)
}

fn take_str(buf: &mut &[u8]) -> Result<String, Oqr2Error> {
    let len = take_u16(buf)? as usize;
    if buf.len() < len {
        return Err(Oqr2Error::TooShort(buf.len()));
    }
    let s = String::from_utf8_lossy(&buf[..len]).into_owned();
    *buf = &buf[len..];
    Ok(s)
}

struct DecodedTile {
    layer: i32,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    bytes: Vec<u8>,
}

fn take_tile(buf: &mut &[u8]) -> Result<DecodedTile, Oqr2Error> {
    let layer = take_i32(buf)?;
    let x = take_u16(buf)?;
    let y = take_u16(buf)?;
    let w = take_u16(buf)?;
    let h = take_u16(buf)?;
    let len = take_u32(buf)? as usize;
    if buf.len() < len {
        return Err(Oqr2Error::TooShort(buf.len()));
    }
    let bytes = buf[..len].to_vec();
    *buf = &buf[len..];
    Ok(DecodedTile {
        layer,
        x,
        y,
        w,
        h,
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::Oqr2Message;

    #[test]
    fn roundtrips_oqr2_messages() {
        let msgs = [
            Oqr2Message::HelloAck {
                width: 1280,
                height: 720,
                cursor_prediction: true,
                trace_id: "0123456789abcdef0123456789abcdef".into(),
                protocol: "rdp".into(),
            },
            Oqr2Message::SolidFill {
                layer: 0,
                x: 64,
                y: 128,
                w: 256,
                h: 64,
                rgba: [14, 17, 22, 255],
            },
            Oqr2Message::CopyRect {
                src_layer: 0,
                sx: 0,
                sy: 64,
                w: 512,
                h: 512,
                dst_layer: 0,
                dx: 0,
                dy: 0,
            },
            Oqr2Message::StatsSync {
                server_ts_ms: 4242,
                lag_ms: 14,
                fps: 30,
                jpeg_quality: 90,
                dropped_frames: 1,
                codec_tag: "oqr2_hybrid".into(),
            },
            Oqr2Message::H264Frame {
                layer: 0,
                x: 0,
                y: 0,
                w: 64,
                h: 64,
                annex_b: vec![0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1E],
            },
            Oqr2Message::ClipboardText {
                text: "operquay clipboard sync".into(),
            },
        ];

        for (i, msg) in msgs.iter().enumerate() {
            let encoded = msg.encode(i as u32 + 10);
            let (seq, decoded) = Oqr2Message::decode(&encoded).unwrap();
            assert_eq!(seq, i as u32 + 10);
            assert_eq!(&decoded, msg);
        }
    }
}
