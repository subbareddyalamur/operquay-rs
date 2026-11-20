use std::collections::HashMap;
use std::io::Cursor;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use operquay_core::settings::CodecMode;
use operquay_guac::GuacInstruction;

use crate::oqr2::Oqr2Message;

pub const TILE_SIZE: u32 = 64;

#[derive(Debug, Clone)]
pub struct FrameEncodeConfig {
    pub codec_mode: CodecMode,
    pub jpeg_quality: u8,
    pub enable_copy_rect: bool,
    pub estimated_fps: u16,
}

impl Default for FrameEncodeConfig {
    fn default() -> Self {
        Self {
            codec_mode: CodecMode::AdaptiveHybrid,
            jpeg_quality: 90,
            enable_copy_rect: true,
            estimated_fps: 30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayOp {
    SolidFill {
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        rgba: [u8; 4],
    },
    CopyRect {
        sx: u32,
        sy: u32,
        w: u32,
        h: u32,
        dx: u32,
        dy: u32,
    },
    ImagePng {
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        bytes: Vec<u8>,
    },
    ImageJpeg {
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        bytes: Vec<u8>,
    },
}

impl DisplayOp {
    #[must_use]
    pub fn to_oqr2(&self, layer: i32) -> Oqr2Message {
        match self {
            Self::SolidFill { x, y, w, h, rgba } => Oqr2Message::SolidFill {
                layer,
                x: *x as u16,
                y: *y as u16,
                w: *w as u16,
                h: *h as u16,
                rgba: *rgba,
            },
            Self::CopyRect {
                sx,
                sy,
                w,
                h,
                dx,
                dy,
            } => Oqr2Message::CopyRect {
                src_layer: layer,
                sx: *sx as u16,
                sy: *sy as u16,
                w: *w as u16,
                h: *h as u16,
                dst_layer: layer,
                dx: *dx as u16,
                dy: *dy as u16,
            },
            Self::ImagePng { x, y, w, h, bytes } => Oqr2Message::TilePng {
                layer,
                x: *x as u16,
                y: *y as u16,
                w: *w as u16,
                h: *h as u16,
                png_bytes: bytes.clone(),
            },
            Self::ImageJpeg { x, y, w, h, bytes } => Oqr2Message::TileJpeg {
                layer,
                x: *x as u16,
                y: *y as u16,
                w: *w as u16,
                h: *h as u16,
                jpeg_bytes: bytes.clone(),
            },
        }
    }

    #[must_use]
    pub fn to_guac_instructions(&self, layer: i32, stream_idx: u32) -> Vec<GuacInstruction> {
        let layer_s = layer.to_string();
        match self {
            Self::SolidFill { x, y, w, h, rgba } => vec![
                GuacInstruction::new(
                    "rect",
                    vec![
                        layer_s.clone(),
                        x.to_string(),
                        y.to_string(),
                        w.to_string(),
                        h.to_string(),
                    ],
                ),
                GuacInstruction::new(
                    "cfill",
                    vec![
                        "12".into(),
                        layer_s,
                        rgba[0].to_string(),
                        rgba[1].to_string(),
                        rgba[2].to_string(),
                        rgba[3].to_string(),
                    ],
                ),
            ],
            Self::CopyRect {
                sx,
                sy,
                w,
                h,
                dx,
                dy,
            } => vec![GuacInstruction::new(
                "copy",
                vec![
                    layer_s.clone(),
                    sx.to_string(),
                    sy.to_string(),
                    w.to_string(),
                    h.to_string(),
                    "12".into(),
                    layer_s,
                    dx.to_string(),
                    dy.to_string(),
                ],
            )],
            Self::ImagePng { x, y, bytes, .. } => {
                vec![
                    GuacInstruction::new(
                        "img",
                        vec![
                            stream_idx.to_string(),
                            "12".into(),
                            layer_s,
                            "image/png".into(),
                            x.to_string(),
                            y.to_string(),
                        ],
                    ),
                    GuacInstruction::new(
                        "blob",
                        vec![stream_idx.to_string(), BASE64.encode(bytes)],
                    ),
                    GuacInstruction::new("end", vec![stream_idx.to_string()]),
                ]
            }
            Self::ImageJpeg { x, y, bytes, .. } => {
                vec![
                    GuacInstruction::new(
                        "img",
                        vec![
                            stream_idx.to_string(),
                            "12".into(),
                            layer_s,
                            "image/jpeg".into(),
                            x.to_string(),
                            y.to_string(),
                        ],
                    ),
                    GuacInstruction::new(
                        "blob",
                        vec![stream_idx.to_string(), BASE64.encode(bytes)],
                    ),
                    GuacInstruction::new("end", vec![stream_idx.to_string()]),
                ]
            }
        }
    }
}

fn grow_tile_rect(
    kinds: &[TileKind],
    visited: &mut [bool],
    tile_cols: u32,
    tile_rows: u32,
    start_col: u32,
    start_row: u32,
    target: &TileKind,
) -> (u32, u32) {
    let mut end_col = start_col + 1;
    while end_col < tile_cols {
        let idx = (start_row * tile_cols + end_col) as usize;
        if !visited[idx] && kinds[idx] == *target {
            end_col += 1;
        } else {
            break;
        }
    }
    let mut end_row = start_row + 1;
    'rows: while end_row < tile_rows {
        for col in start_col..end_col {
            let idx = (end_row * tile_cols + col) as usize;
            if visited[idx] || kinds[idx] != *target {
                break 'rows;
            }
        }
        end_row += 1;
    }
    for row in start_row..end_row {
        for col in start_col..end_col {
            visited[(row * tile_cols + col) as usize] = true;
        }
    }
    (end_col, end_row)
}

#[derive(Clone, PartialEq, Eq)]
enum TileKind {
    Skip,
    Solid([u8; 4]),
    Copy(u32, u32),
    Bitmap,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FrameStats {
    pub solid_count: usize,
    pub copy_count: usize,
    pub png_count: usize,
    pub jpeg_count: usize,
}

/// Exact reverse-engineered Guacamole complexity heuristic (`libguac.so @ 0xeacf..0xebd3`):
/// `((identical_runs << 8) / max(1, transitions)) - 1024`.
/// Returns `>= 0` for crisp text / flat UI (lossless PNG) and `< 0` for gradients/photos (JPEG eligible).
#[must_use]
pub fn complexity_score(rgba_rect: &[u32]) -> i64 {
    if rgba_rect.is_empty() {
        return 0;
    }
    let mut identical_runs: i64 = 0;
    let mut transitions: i64 = 0;
    let mut prev = rgba_rect[0] | 0xff00_0000;
    for &raw in &rgba_rect[1..] {
        let px = raw | 0xff00_0000;
        if px == prev {
            identical_runs += 1;
        } else {
            transitions += 1;
            prev = px;
        }
    }
    ((identical_runs << 8) / transitions.max(1)) - 1024
}

/// Dual-buffered RGBA compositor implementing Guacamole's 5-phase `64x64` pipeline in pure safe Rust.
pub struct FramebufferPlanner {
    width: u32,
    height: u32,
    tile_cols: u32,
    tile_rows: u32,
    front: Vec<u32>,
    back: Vec<u32>,
    front_tile_hashes: Vec<u64>,
    dirty_tiles: Vec<bool>,
}

impl FramebufferPlanner {
    #[must_use]
    pub fn new(width: u32, height: u32) -> Self {
        let w = width.max(1);
        let h = height.max(1);
        let len = (w as usize) * (h as usize);
        let tile_cols = w.div_ceil(TILE_SIZE);
        let tile_rows = h.div_ceil(TILE_SIZE);
        let front = vec![0xff00_0000; len];
        let total_tiles = (tile_cols * tile_rows) as usize;
        let mut front_tile_hashes = vec![0u64; total_tiles];
        for ty in 0..tile_rows {
            for tx in 0..tile_cols {
                let x = tx * TILE_SIZE;
                let y = ty * TILE_SIZE;
                if x + TILE_SIZE <= w && y + TILE_SIZE <= h {
                    front_tile_hashes[(ty * tile_cols + tx) as usize] = hash_64x64(&front, w, x, y);
                }
            }
        }
        Self {
            width: w,
            height: h,
            tile_cols,
            tile_rows,
            front,
            back: vec![0xff00_0000; len],
            front_tile_hashes,
            dirty_tiles: vec![false; total_tiles],
        }
    }

    #[must_use]
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    pub fn resize(&mut self, width: u32, height: u32) {
        let w = width.max(1);
        let h = height.max(1);
        if w == self.width && h == self.height {
            return;
        }
        *self = Self::new(w, h);
    }

    pub fn mark_all_dirty(&mut self) {
        self.dirty_tiles.fill(true);
    }

    pub fn fill_solid_rect(&mut self, x: u32, y: u32, w: u32, h: u32, rgba: [u8; 4]) {
        let pixel = pack_rgba(rgba);
        let x0 = x.min(self.width);
        let y0 = y.min(self.height);
        let x1 = x.saturating_add(w).min(self.width);
        let y1 = y.saturating_add(h).min(self.height);
        if x0 >= x1 || y0 >= y1 {
            return;
        }
        for row in y0..y1 {
            let start = (row * self.width + x0) as usize;
            let end = (row * self.width + x1) as usize;
            self.back[start..end].fill(pixel);
        }
        self.mark_dirty_rect(x0, y0, x1 - x0, y1 - y0);
    }

    pub fn draw_rgba_rect(&mut self, x: u32, y: u32, w: u32, h: u32, rgba: &[u8], stride: usize) {
        let x0 = x.min(self.width);
        let y0 = y.min(self.height);
        let x1 = x.saturating_add(w).min(self.width);
        let y1 = y.saturating_add(h).min(self.height);
        if x0 >= x1 || y0 >= y1 {
            return;
        }
        let copy_w = (x1 - x0) as usize;
        for dy in 0..(y1 - y0) as usize {
            let src_row_start = dy * stride;
            let dst_row_start = ((y0 as usize + dy) * self.width as usize) + x0 as usize;
            for dx in 0..copy_w {
                let s = src_row_start + dx * 4;
                if s + 4 <= rgba.len() {
                    self.back[dst_row_start + dx] =
                        pack_rgba([rgba[s], rgba[s + 1], rgba[s + 2], rgba[s + 3]]);
                }
            }
        }
        self.mark_dirty_rect(x0, y0, x1 - x0, y1 - y0);
    }

    pub fn copy_rect_in_back(&mut self, sx: u32, sy: u32, w: u32, h: u32, dx: u32, dy: u32) {
        let rw = w
            .min(self.width.saturating_sub(sx))
            .min(self.width.saturating_sub(dx));
        let rh = h
            .min(self.height.saturating_sub(sy))
            .min(self.height.saturating_sub(dy));
        if rw == 0 || rh == 0 {
            return;
        }
        let mut temp = Vec::with_capacity((rw * rh) as usize);
        for row in 0..rh {
            let s = ((sy + row) * self.width + sx) as usize;
            temp.extend_from_slice(&self.back[s..s + rw as usize]);
        }
        for row in 0..rh {
            let d = ((dy + row) * self.width + dx) as usize;
            let t = (row * rw) as usize;
            self.back[d..d + rw as usize].copy_from_slice(&temp[t..t + rw as usize]);
        }
        self.mark_dirty_rect(dx, dy, rw, rh);
    }

    fn mark_dirty_rect(&mut self, x: u32, y: u32, w: u32, h: u32) {
        if w == 0 || h == 0 {
            return;
        }
        let tx0 = x / TILE_SIZE;
        let ty0 = y / TILE_SIZE;
        let tx1 = (x + w - 1) / TILE_SIZE;
        let ty1 = (y + h - 1) / TILE_SIZE;
        for ty in ty0..=ty1.min(self.tile_rows.saturating_sub(1)) {
            for tx in tx0..=tx1.min(self.tile_cols.saturating_sub(1)) {
                self.dirty_tiles[(ty * self.tile_cols + tx) as usize] = true;
            }
        }
    }

    /// Execute Phases 1–5 across dirty tiles and commit `back` -> `front`.
    pub fn flush(&mut self, cfg: &FrameEncodeConfig) -> (Vec<DisplayOp>, FrameStats) {
        let mut ops = Vec::new();
        let mut stats = FrameStats::default();

        // Phase 3 prerequisite: index 64x64 full tiles from cached hashes without re-hashing front buffer.
        let has_dirty = self.dirty_tiles.iter().any(|&d| d);
        let mut front_hashes: HashMap<u64, (u32, u32)> = HashMap::new();
        if cfg.enable_copy_rect && has_dirty {
            front_hashes.reserve(self.front_tile_hashes.len());
            for ty in 0..self.tile_rows {
                for tx in 0..self.tile_cols {
                    let x = tx * TILE_SIZE;
                    let y = ty * TILE_SIZE;
                    if x + TILE_SIZE <= self.width && y + TILE_SIZE <= self.height {
                        let hash = self.front_tile_hashes[(ty * self.tile_cols + tx) as usize];
                        front_hashes.entry(hash).or_insert((x, y));
                    }
                }
            }
        }

        // Classify every dirty tile cleanly into: CleanCopy | Solid | Bitmap.
        let total_tiles = (self.tile_cols * self.tile_rows) as usize;
        let mut kinds = vec![TileKind::Skip; total_tiles];

        for ty in 0..self.tile_rows {
            for tx in 0..self.tile_cols {
                let idx = (ty * self.tile_cols + tx) as usize;
                if !self.dirty_tiles[idx] {
                    continue;
                }
                let x = tx * TILE_SIZE;
                let y = ty * TILE_SIZE;
                let w = (self.width - x).min(TILE_SIZE);
                let h = (self.height - y).min(TILE_SIZE);

                // Phase 1 check: skip unchanged tiles vs frontbuffer.
                if rect_matches(&self.front, &self.back, self.width, x, y, w, h) {
                    continue;
                }

                // Phase 2: uniform solid color check -> collapse to tiny SolidFill.
                if let Some(rgba) = uniform_color(&self.back, self.width, x, y, w, h) {
                    kinds[idx] = TileKind::Solid(rgba);
                    continue;
                }

                // Phase 3: 64x64 rolling-hash CopyRect scroll detection.
                if cfg.enable_copy_rect && w == TILE_SIZE && h == TILE_SIZE {
                    let hval = hash_64x64(&self.back, self.width, x, y);
                    if let Some(&(sx, sy)) = front_hashes.get(&hval) {
                        if tiles_equal(&self.front, &self.back, self.width, sx, sy, x, y, w, h) {
                            kinds[idx] = TileKind::Copy(sx, sy);
                            continue;
                        }
                    }
                }

                kinds[idx] = TileKind::Bitmap;
            }
        }

        // Phase 4 & 5: coalesce adjacent 2D rectangles (horizontal then vertical) and encode.
        let mut visited = vec![false; total_tiles];
        for ty in 0..self.tile_rows {
            for tx in 0..self.tile_cols {
                let idx = (ty * self.tile_cols + tx) as usize;
                if visited[idx] {
                    continue;
                }
                match &kinds[idx] {
                    TileKind::Skip => {
                        visited[idx] = true;
                    }
                    TileKind::Copy(sx, sy) => {
                        visited[idx] = true;
                        let dx = tx * TILE_SIZE;
                        let dy = ty * TILE_SIZE;
                        ops.push(DisplayOp::CopyRect {
                            sx: *sx,
                            sy: *sy,
                            w: TILE_SIZE,
                            h: TILE_SIZE,
                            dx,
                            dy,
                        });
                        stats.copy_count += 1;
                    }
                    TileKind::Solid(rgba) => {
                        let rgba = *rgba;
                        let target = TileKind::Solid(rgba);
                        let (end_col, end_row) = grow_tile_rect(
                            &kinds,
                            &mut visited,
                            self.tile_cols,
                            self.tile_rows,
                            tx,
                            ty,
                            &target,
                        );
                        let x = tx * TILE_SIZE;
                        let y = ty * TILE_SIZE;
                        let w = (end_col * TILE_SIZE).min(self.width) - x;
                        let h = (end_row * TILE_SIZE).min(self.height) - y;
                        ops.push(DisplayOp::SolidFill { x, y, w, h, rgba });
                        stats.solid_count += 1;
                    }
                    TileKind::Bitmap => {
                        let (end_col, end_row) = grow_tile_rect(
                            &kinds,
                            &mut visited,
                            self.tile_cols,
                            self.tile_rows,
                            tx,
                            ty,
                            &TileKind::Bitmap,
                        );
                        let x = tx * TILE_SIZE;
                        let y = ty * TILE_SIZE;
                        let w = (end_col * TILE_SIZE).min(self.width) - x;
                        let h = (end_row * TILE_SIZE).min(self.height) - y;

                        let op = encode_bitmap_rect(&self.back, self.width, x, y, w, h, cfg);
                        match &op {
                            DisplayOp::ImagePng { .. } => stats.png_count += 1,
                            DisplayOp::ImageJpeg { .. } => stats.jpeg_count += 1,
                            _ => {}
                        }
                        ops.push(op);
                    }
                }
            }
        }

        // Commit only dirty tiles back -> front and refresh cached 64x64 hashes incrementally.
        for ty in 0..self.tile_rows {
            for tx in 0..self.tile_cols {
                let idx = (ty * self.tile_cols + tx) as usize;
                if !self.dirty_tiles[idx] {
                    continue;
                }
                let x = tx * TILE_SIZE;
                let y = ty * TILE_SIZE;
                let w = (self.width - x).min(TILE_SIZE);
                let h = (self.height - y).min(TILE_SIZE);
                for row in y..y + h {
                    let s = (row * self.width + x) as usize;
                    self.front[s..s + w as usize].copy_from_slice(&self.back[s..s + w as usize]);
                }
                if x + TILE_SIZE <= self.width && y + TILE_SIZE <= self.height {
                    self.front_tile_hashes[idx] = hash_64x64(&self.front, self.width, x, y);
                }
                self.dirty_tiles[idx] = false;
            }
        }

        (ops, stats)
    }
}

fn encode_bitmap_rect(
    buf: &[u32],
    stride_px: u32,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    cfg: &FrameEncodeConfig,
) -> DisplayOp {
    let mut flat_u32 = Vec::with_capacity((w * h) as usize);
    for row in y..y + h {
        let s = (row * stride_px + x) as usize;
        flat_u32.extend_from_slice(&buf[s..s + w as usize]);
    }

    let score = complexity_score(&flat_u32);
    let area = (w as usize) * (h as usize);
    let jpeg_eligible = cfg.codec_mode != CodecMode::LosslessCrisp
        && (cfg.codec_mode == CodecMode::MotionPriority
            || (score < 0 && cfg.estimated_fps > 2 && area >= 4096));

    if jpeg_eligible {
        let mut rgb = Vec::with_capacity(area * 3);
        for &px in &flat_u32 {
            let [r, g, b, _] = unpack_rgba(px);
            rgb.extend_from_slice(&[r, g, b]);
        }
        let mut out = Vec::with_capacity(area / 2);
        let encoder = jpeg_encoder::Encoder::new(&mut out, cfg.jpeg_quality.clamp(20, 95));
        if encoder
            .encode(&rgb, w as u16, h as u16, jpeg_encoder::ColorType::Rgb)
            .is_ok()
        {
            return DisplayOp::ImageJpeg {
                x,
                y,
                w,
                h,
                bytes: out,
            };
        }
    }

    let mut rgba_bytes = Vec::with_capacity(area * 4);
    for &px in &flat_u32 {
        rgba_bytes.extend_from_slice(&unpack_rgba(px));
    }
    let mut png_bytes = Vec::with_capacity(area);
    let mut encoder = png::Encoder::new(Cursor::new(&mut png_bytes), w, h);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.set_compression(png::Compression::Fast);
    if let Ok(mut writer) = encoder.write_header() {
        let _ = writer.write_image_data(&rgba_bytes);
    }

    DisplayOp::ImagePng {
        x,
        y,
        w,
        h,
        bytes: png_bytes,
    }
}

#[inline]
const fn pack_rgba(c: [u8; 4]) -> u32 {
    u32::from_le_bytes(c)
}

#[inline]
const fn unpack_rgba(px: u32) -> [u8; 4] {
    px.to_le_bytes()
}

/// Rolling polynomial hash matching `libguac.so @ 0xe48c` (`h = h * 0x3e + px`).
fn hash_64x64(buf: &[u32], stride: u32, x: u32, y: u32) -> u64 {
    let mut h: u64 = 0;
    for row in y..y + TILE_SIZE {
        let s = (row * stride + x) as usize;
        for &px in &buf[s..s + TILE_SIZE as usize] {
            h = h.wrapping_mul(0x3e).wrapping_add(u64::from(px));
        }
    }
    h
}

fn rect_matches(a: &[u32], b: &[u32], stride: u32, x: u32, y: u32, w: u32, h: u32) -> bool {
    for row in y..y + h {
        let s = (row * stride + x) as usize;
        if a[s..s + w as usize] != b[s..s + w as usize] {
            return false;
        }
    }
    true
}

fn tiles_equal(
    front: &[u32],
    back: &[u32],
    stride: u32,
    sx: u32,
    sy: u32,
    dx: u32,
    dy: u32,
    w: u32,
    h: u32,
) -> bool {
    for row in 0..h {
        let fs = ((sy + row) * stride + sx) as usize;
        let bs = ((dy + row) * stride + dx) as usize;
        if front[fs..fs + w as usize] != back[bs..bs + w as usize] {
            return false;
        }
    }
    true
}

fn uniform_color(buf: &[u32], stride: u32, x: u32, y: u32, w: u32, h: u32) -> Option<[u8; 4]> {
    let first = buf[(y * stride + x) as usize];
    for row in y..y + h {
        let s = (row * stride + x) as usize;
        if !buf[s..s + w as usize].iter().all(|&p| p == first) {
            return None;
        }
    }
    Some(unpack_rgba(first))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_solid_regions_and_detects_scroll_copy_rect() {
        let mut planner = FramebufferPlanner::new(256, 256);
        let cfg = FrameEncodeConfig::default();

        // Draw textured gradient/pattern in tile (64, 128) size 64x64 so it is non-solid.
        let mut tile = vec![0u8; 64 * 64 * 4];
        for y in 0..64 {
            for x in 0..64 {
                let i = (y * 64 + x) * 4;
                tile[i] = (x * 4) as u8;
                tile[i + 1] = (y * 4) as u8;
                tile[i + 2] = ((x ^ y) * 3) as u8;
                tile[i + 3] = 255;
            }
        }
        planner.draw_rgba_rect(64, 128, 64, 64, &tile, 64 * 4);
        planner.fill_solid_rect(0, 0, 128, 64, [14, 17, 22, 255]);

        let (ops1, stats1) = planner.flush(&cfg);
        assert!(stats1.solid_count >= 1);
        assert!(stats1.png_count + stats1.jpeg_count >= 1);
        assert_ne!(ops1, []);

        // Scroll that exact 64x64 tile up by 64px cleanly into (64, 64).
        planner.fill_solid_rect(64, 128, 64, 64, [0, 0, 0, 255]);
        planner.draw_rgba_rect(64, 64, 64, 64, &tile, 64 * 4);

        let (ops2, stats2) = planner.flush(&cfg);
        assert_eq!(
            stats2.copy_count, 1,
            "expected 64x64 rolling-hash copy rect"
        );
        assert!(ops2.iter().any(|op| matches!(
            op,
            DisplayOp::CopyRect {
                sx: 64,
                sy: 128,
                dx: 64,
                dy: 64,
                w: 64,
                h: 64
            }
        )));
    }

    #[test]
    fn complexity_heuristic_separates_text_and_noise() {
        let flat_text = vec![0xff10_2030_u32; 8192];
        assert!(complexity_score(&flat_text) >= 0);

        let high_entropy: Vec<u32> = (0..8192u32)
            .map(|i| 0xff00_0000 | i.wrapping_mul(2_654_435_761))
            .collect();
        assert!(complexity_score(&high_entropy) < 0);
    }
}
