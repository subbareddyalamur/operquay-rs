#![forbid(unsafe_code)]

//! `[MS-RDPEGFX]` `AVC420` pass-through bridge to `OQR2` `0x0A H264Frame` / browser `WebCodecs` (`M12.5`).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ironrdp_egfx::client::{BitmapUpdate, GraphicsPipelineClient, GraphicsPipelineHandler};
use ironrdp_egfx::decode::{DecodedFrame, DecoderResult, H264Decoder};
use ironrdp_egfx::pdu::{CapabilitiesV81Flags, CapabilitiesV8Flags, CapabilitySet, Codec1Type};
use operquay_core::DisplaySink;

/// Convert AVCC length-prefixed NAL units into Annex-B (`00 00 00 01`) byte stream expected by
/// browser `WebCodecs` `EncodedVideoChunk` (`avc1.42E01F`), preserving streams already in Annex-B.
#[must_use]
pub fn normalize_avc_to_annex_b(raw: &[u8]) -> Vec<u8> {
    if raw.starts_with(&[0, 0, 0, 1]) || raw.starts_with(&[0, 0, 1]) {
        return raw.to_vec();
    }
    let mut out = Vec::with_capacity(raw.len() + 16);
    let mut cursor = 0usize;
    let mut parsed_any = false;
    while cursor + 4 <= raw.len() {
        let len = u32::from_be_bytes([
            raw[cursor],
            raw[cursor + 1],
            raw[cursor + 2],
            raw[cursor + 3],
        ]) as usize;
        cursor += 4;
        if len == 0 || cursor + len > raw.len() {
            return raw.to_vec();
        }
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(&raw[cursor..cursor + len]);
        cursor += len;
        parsed_any = true;
    }
    if parsed_any && cursor == raw.len() {
        out
    } else {
        raw.to_vec()
    }
}

struct SharedDimensions {
    width: AtomicU32,
    height: AtomicU32,
}

impl SharedDimensions {
    fn new(width: u32, height: u32) -> Self {
        Self {
            width: AtomicU32::new(width.max(16)),
            height: AtomicU32::new(height.max(16)),
        }
    }

    fn get(&self) -> (u32, u32) {
        (
            self.width.load(Ordering::Relaxed).max(16),
            self.height.load(Ordering::Relaxed).max(16),
        )
    }

    fn set(&self, w: u32, h: u32) {
        self.width.store(w.max(16), Ordering::Relaxed);
        self.height.store(h.max(16), Ordering::Relaxed);
    }
}

/// Forwards raw `[MS-RDPEGFX]` `AVC420` H.264 NALUs straight to [`DisplaySink::draw_h264_nalu`]
/// so `OQR2` emits zero-copy `0x0A H264Frame` packets for hardware-accelerated browser `WebCodecs`.
pub struct WebCodecsAvc420Bridge {
    sink: Arc<dyn DisplaySink>,
    dims: Arc<SharedDimensions>,
    frames_forwarded: Arc<AtomicU64>,
}

impl WebCodecsAvc420Bridge {
    #[must_use]
    pub fn forwarded_frames(&self) -> u64 {
        self.frames_forwarded.load(Ordering::Relaxed)
    }
}

impl H264Decoder for WebCodecsAvc420Bridge {
    fn decode(&mut self, data: &[u8]) -> DecoderResult<DecodedFrame> {
        let annex_b = normalize_avc_to_annex_b(data);
        let (w, h) = self.dims.get();
        if !annex_b.is_empty() {
            self.sink.draw_h264_nalu(0, 0, 0, w, h, &annex_b);
            self.frames_forwarded.fetch_add(1, Ordering::Relaxed);
        }
        let rgba_len = usize::try_from(w)
            .unwrap_or(1)
            .saturating_mul(usize::try_from(h).unwrap_or(1))
            .saturating_mul(4);
        Ok(DecodedFrame::new(vec![0u8; rgba_len], w, h))
    }

    fn supports_yuv420(&self) -> bool {
        false
    }
}

/// Client-side EGFX surface/frame callback translating non-H264 bitmaps (`ClearCodec`/`RFX`/Alpha)
/// into [`DisplaySink::draw_rgba_rect`] while letting `AVC420` pass directly to `WebCodecs`.
pub struct OperquayEgfxHandler {
    sink: Arc<dyn DisplaySink>,
    dims: Arc<SharedDimensions>,
}

impl GraphicsPipelineHandler for OperquayEgfxHandler {
    fn capabilities(&self) -> Vec<CapabilitySet> {
        vec![
            CapabilitySet::V8_1 {
                flags: CapabilitiesV81Flags::AVC420_ENABLED | CapabilitiesV81Flags::SMALL_CACHE,
            },
            CapabilitySet::V8 {
                flags: CapabilitiesV8Flags::SMALL_CACHE,
            },
        ]
    }

    fn on_reset_graphics(&mut self, width: u32, height: u32) {
        self.dims.set(width, height);
        self.sink.resize(0, width, height);
    }

    fn on_bitmap_updated(&mut self, update: &BitmapUpdate) {
        if update.codec_id == Codec1Type::Avc420 || update.data.is_empty() {
            return;
        }
        let x = u32::from(update.destination_rectangle.left);
        let y = u32::from(update.destination_rectangle.top);
        let w = u32::from(update.width);
        let h = u32::from(update.height);
        let stride = usize::from(update.width).saturating_mul(4);
        self.sink
            .draw_rgba_rect(0, x, y, w, h, &update.data, stride);
    }

    fn on_frame_complete(&mut self, _frame_id: u32) {
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis()),
        )
        .unwrap_or(0);
        self.sink.flush_frame(now_ms);
    }
}

/// Construct an `IronRDP` `[MS-RDPEGFX]` dynamic virtual channel client wired to `sink`.
#[must_use]
pub fn build_egfx_channel(
    sink: Arc<dyn DisplaySink>,
    width: u32,
    height: u32,
) -> GraphicsPipelineClient {
    let dims = Arc::new(SharedDimensions::new(width, height));
    let frames_forwarded = Arc::new(AtomicU64::new(0));
    let handler = Box::new(OperquayEgfxHandler {
        sink: Arc::clone(&sink),
        dims: Arc::clone(&dims),
    });
    let h264 = Box::new(WebCodecsAvc420Bridge {
        sink,
        dims,
        frames_forwarded,
    });
    GraphicsPipelineClient::new(handler, Some(h264))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct H264CaptureSink {
        nalus: Mutex<Vec<Vec<u8>>>,
    }

    impl DisplaySink for H264CaptureSink {
        fn resize(&self, _layer_id: i32, _width: u32, _height: u32) {}
        fn draw_rgba_rect(&self, _: i32, _: u32, _: u32, _: u32, _: u32, _: &[u8], _: usize) {}
        fn fill_solid_rect(&self, _: i32, _: u32, _: u32, _: u32, _: u32, _: [u8; 4]) {}
        fn copy_rect(&self, _: i32, _: u32, _: u32, _: u32, _: u32, _: i32, _: u32, _: u32) {}
        fn set_cursor(&self, _: u32, _: u32, _: u32, _: u32, _: &[u8]) {}
        fn move_cursor(&self, _: u32, _: u32) {}
        fn flush_frame(&self, _: u64) {}
        fn draw_h264_nalu(&self, _: i32, _: u32, _: u32, _: u32, _: u32, annex_b: &[u8]) {
            self.nalus.lock().unwrap().push(annex_b.to_vec());
        }
    }

    #[test]
    fn converts_avcc_to_annex_b_and_forwards_h264_access_units() {
        let avcc = [0, 0, 0, 3, 0x67, 0x42, 0x80, 0, 0, 0, 2, 0x65, 0x88];
        let annex = normalize_avc_to_annex_b(&avcc);
        assert_eq!(
            annex,
            vec![0, 0, 0, 1, 0x67, 0x42, 0x80, 0, 0, 0, 1, 0x65, 0x88]
        );
        assert_eq!(normalize_avc_to_annex_b(&annex), annex);

        let sink = Arc::new(H264CaptureSink::default());
        let dims = Arc::new(SharedDimensions::new(64, 48));
        let frames = Arc::new(AtomicU64::new(0));
        let mut bridge = WebCodecsAvc420Bridge {
            sink: sink.clone(),
            dims,
            frames_forwarded: Arc::clone(&frames),
        };
        let frame = bridge.decode(&avcc).unwrap();
        assert_eq!(frame.width(), 64);
        assert_eq!(bridge.forwarded_frames(), 1);
        assert_eq!(sink.nalus.lock().unwrap()[0], annex);
    }
}
