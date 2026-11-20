//! Pure-Rust `#![forbid(unsafe_code)]` ITU-T H.264 Constrained Baseline inter-frame
//! (`IDR I_PCM` + `P_Skip`/`I_PCM` delta macroblock) encoder + standard ISO-BMFF MP4
//! container muxer (`avc1` / `avcC` / `stbl`) with zero C/FFmpeg subprocesses.

use std::collections::HashMap;
use std::io::Cursor;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bytes::{BufMut, BytesMut};
use operquay_guac::GuacParser;
use operquay_term::TerminalEngine;

const IDR_KEYFRAME_INTERVAL: usize = 30;
const MB_YUV_BYTES: usize = 384; // 256 Y + 64 U + 64 V

struct BitWriter {
    buf: Vec<u8>,
    cur: u8,
    bits_in_cur: u8,
}

impl BitWriter {
    fn new(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
            cur: 0,
            bits_in_cur: 0,
        }
    }

    fn write_bit(&mut self, bit: u8) {
        self.cur = (self.cur << 1) | (bit & 1);
        self.bits_in_cur += 1;
        if self.bits_in_cur == 8 {
            self.buf.push(self.cur);
            self.cur = 0;
            self.bits_in_cur = 0;
        }
    }

    fn write_bits(&mut self, val: u32, count: u8) {
        for shift in (0..count).rev() {
            self.write_bit(((val >> shift) & 1) as u8);
        }
    }

    fn write_ue(&mut self, val: u32) {
        let code = val + 1;
        let bits = 32 - code.leading_zeros() as u8;
        let leading_zeros = bits - 1;
        self.write_bits(0, leading_zeros);
        self.write_bits(code, bits);
    }

    fn write_se(&mut self, val: i32) {
        let mapped = if val <= 0 {
            (-2 * val) as u32
        } else {
            (2 * val - 1) as u32
        };
        self.write_ue(mapped);
    }

    fn align_zero(&mut self) {
        if self.bits_in_cur != 0 {
            let rem = 8 - self.bits_in_cur;
            self.write_bits(0, rem);
        }
    }

    fn rbsp_trailing_bits(&mut self) {
        self.write_bit(1);
        self.align_zero();
    }

    fn write_aligned_bytes(&mut self, bytes: &[u8]) {
        self.align_zero();
        self.buf.extend_from_slice(bytes);
    }
}

/// Insert H.264 `0x03` emulation-prevention bytes for RBSP sequences starting with `0x00 0x00 0x00..=0x03`.
fn rbsp_to_ebsp(nal_header: u8, rbsp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + rbsp.len() + 16);
    out.push(nal_header);
    let mut zero_run = 0u8;
    for &b in rbsp {
        if zero_run >= 2 && b <= 0x03 {
            out.push(0x03);
            zero_run = 0;
        }
        out.push(b);
        if b == 0 {
            zero_run = zero_run.saturating_add(1);
        } else {
            zero_run = 0;
        }
    }
    out
}

fn encode_sps_baseline(width_mb: u32, height_mb: u32) -> Vec<u8> {
    let mut bw = BitWriter::new(32);
    bw.buf.push(66); // profile_idc = 66 (Baseline)
    bw.buf.push(0xC0); // constraint_set0_flag | constraint_set1_flag
    bw.buf.push(31); // level_idc = 31 (Level 3.1)
    bw.write_ue(0); // seq_parameter_set_id
    bw.write_ue(4); // log2_max_frame_num_minus4 = 4 -> 8-bit frame_num
    bw.write_ue(2); // pic_order_cnt_type = 2 (no POC lsb in slice header)
    bw.write_ue(1); // max_num_ref_frames = 1
    bw.write_bit(0); // gaps_in_frame_num_value_allowed_flag
    bw.write_ue(width_mb - 1);
    bw.write_ue(height_mb - 1);
    bw.write_bit(1); // frame_mbs_only_flag
    bw.write_bit(0); // direct_8x8_inference_flag
    bw.write_bit(0); // frame_cropping_flag
    bw.write_bit(0); // vui_parameters_present_flag
    bw.rbsp_trailing_bits();
    rbsp_to_ebsp(0x67, &bw.buf)
}

fn encode_pps_baseline() -> Vec<u8> {
    let mut bw = BitWriter::new(16);
    bw.write_ue(0); // pic_parameter_set_id
    bw.write_ue(0); // seq_parameter_set_id
    bw.write_bit(0); // entropy_coding_mode_flag (CAVLC)
    bw.write_bit(0); // bottom_field_pic_order_in_frame_present_flag
    bw.write_ue(0); // num_slice_groups_minus1
    bw.write_ue(0); // num_ref_idx_l0_default_active_minus1
    bw.write_ue(0); // num_ref_idx_l1_default_active_minus1
    bw.write_bit(0); // weighted_pred_flag
    bw.write_bits(0, 2); // weighted_bipred_idc
    bw.write_se(0); // pic_init_qp_minus26
    bw.write_se(0); // pic_init_qs_minus26
    bw.write_se(0); // chroma_qp_index_offset
    bw.write_bit(1); // deblocking_filter_control_present_flag = 1 (allows disabling deblock across I_PCM/P_Skip)
    bw.write_bit(0); // constrained_intra_pred_flag
    bw.write_bit(0); // redundant_pic_cnt_present_flag
    bw.rbsp_trailing_bits();
    rbsp_to_ebsp(0x68, &bw.buf)
}

fn rgb_frame_to_mbs(rgb: &[u8], width: usize, height: usize) -> Vec<[u8; MB_YUV_BYTES]> {
    let mb_w = width / 16;
    let mb_h = height / 16;
    let mut mbs = vec![[16u8; MB_YUV_BYTES]; mb_w * mb_h];
    for mby in 0..mb_h {
        for mbx in 0..mb_w {
            let mb = &mut mbs[mby * mb_w + mbx];
            for py in 0..16 {
                let iy = mby * 16 + py;
                for px in 0..16 {
                    let ix = mbx * 16 + px;
                    let base = (iy * width + ix) * 3;
                    let (r, g, b) = (
                        i32::from(rgb[base]),
                        i32::from(rgb[base + 1]),
                        i32::from(rgb[base + 2]),
                    );
                    // BT.601 studio range [16..=235] prevents 0x00 bytes
                    let y = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
                    mb[py * 16 + px] = y.clamp(16, 235) as u8;
                }
            }
            for cy in 0..8 {
                let iy = mby * 16 + cy * 2;
                for cx in 0..8 {
                    let ix = mbx * 16 + cx * 2;
                    let base = (iy * width + ix) * 3;
                    let (r, g, b) = (
                        i32::from(rgb[base]),
                        i32::from(rgb[base + 1]),
                        i32::from(rgb[base + 2]),
                    );
                    let u = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
                    let v = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
                    mb[256 + cy * 8 + cx] = u.clamp(16, 240) as u8;
                    mb[320 + cy * 8 + cx] = v.clamp(16, 240) as u8;
                }
            }
        }
    }
    mbs
}

fn encode_idr_mbs_nal(mbs: &[[u8; MB_YUV_BYTES]], idr_id: u32) -> Vec<u8> {
    let mut bw = BitWriter::new(mbs.len() * 386 + 32);
    bw.write_ue(0); // first_mb_in_slice
    bw.write_ue(7); // slice_type = I (all I)
    bw.write_ue(0); // pic_parameter_set_id
    bw.write_bits(0, 8); // frame_num = 0 (8 bits)
    bw.write_ue(idr_id % 65536); // idr_pic_id
    bw.write_bit(0); // no_output_of_prior_pics_flag
    bw.write_bit(0); // long_term_reference_flag
    bw.write_se(0); // slice_qp_delta
    bw.write_ue(1); // disable_deblocking_filter_idc = 1 (disabled for bit-exact I_PCM/P_Skip)

    for mb in mbs {
        bw.write_ue(25); // mb_type = I_PCM in I slice
        bw.write_aligned_bytes(mb);
    }
    bw.rbsp_trailing_bits();
    rbsp_to_ebsp(0x65, &bw.buf)
}

fn encode_p_delta_mbs_nal(
    curr_mbs: &[[u8; MB_YUV_BYTES]],
    prev_mbs: &[[u8; MB_YUV_BYTES]],
    frame_num: u8,
) -> Vec<u8> {
    let mut bw = BitWriter::new(curr_mbs.len() * 16 + 32);
    bw.write_ue(0); // first_mb_in_slice
    bw.write_ue(0); // slice_type = P
    bw.write_ue(0); // pic_parameter_set_id
    bw.write_bits(u32::from(frame_num), 8); // frame_num (8 bits)
    bw.write_bit(0); // num_ref_idx_active_override_flag
    bw.write_bit(0); // ref_pic_list_modification_flag_l0
    bw.write_bit(0); // adaptive_ref_pic_marking_mode_flag (nal_ref_idc != 0 sliding window)
    bw.write_se(0); // slice_qp_delta
    bw.write_ue(1); // disable_deblocking_filter_idc = 1

    let mut skip_run = 0u32;
    for (curr, prev) in curr_mbs.iter().zip(prev_mbs.iter()) {
        if curr == prev {
            skip_run += 1;
        } else {
            bw.write_ue(skip_run);
            skip_run = 0;
            bw.write_ue(30); // mb_type = 5 + 25 (I_PCM inside P slice)
            bw.write_aligned_bytes(curr);
        }
    }
    if skip_run > 0 {
        bw.write_ue(skip_run);
    }
    bw.rbsp_trailing_bits();
    rbsp_to_ebsp(0x41, &bw.buf) // nal_ref_idc = 2, nal_unit_type = 1 (coded slice of non-IDR picture)
}

fn avcc_sample_from_nal(nal: &[u8]) -> Vec<u8> {
    let mut s = BytesMut::with_capacity(4 + nal.len());
    s.put_u32(nal.len() as u32);
    s.put_slice(nal);
    s.to_vec()
}

/// Package RGB24 video frames into a playable inter-frame compressed ISO-BMFF `avc1` H.264 Baseline MP4.
#[must_use]
pub fn mux_rgb_frames_to_mp4(frames: &[(&[u8], u32)], width: u32, height: u32) -> Vec<u8> {
    let align_w = width.max(64).div_ceil(16) * 16;
    let align_h = height.max(64).div_ceil(16) * 16;
    let mb_w = align_w / 16;
    let mb_h = align_h / 16;

    let sps = encode_sps_baseline(mb_w, mb_h);
    let pps = encode_pps_baseline();

    let mut samples: Vec<Vec<u8>> = Vec::with_capacity(frames.len().max(1));
    let mut durations: Vec<u32> = Vec::with_capacity(frames.len().max(1));
    let mut sync_samples: Vec<u32> = Vec::new();

    if frames.is_empty() {
        let blank = vec![16u8; (align_w * align_h * 3) as usize];
        let mbs = rgb_frame_to_mbs(&blank, align_w as usize, align_h as usize);
        let nal = encode_idr_mbs_nal(&mbs, 0);
        samples.push(avcc_sample_from_nal(&nal));
        durations.push(1000);
        sync_samples.push(1);
    } else {
        let mut prev_mbs: Option<Vec<[u8; MB_YUV_BYTES]>> = None;
        let mut idr_seq = 0u32;
        let mut since_idr = 0u8;
        for (idx, &(rgb, dur_ms)) in frames.iter().enumerate() {
            let mut padded = vec![16u8; (align_w * align_h * 3) as usize];
            let copy_w = width.min(align_w) as usize;
            let copy_h = height.min(align_h) as usize;
            for y in 0..copy_h {
                let src_start = y * (width as usize) * 3;
                let dst_start = y * (align_w as usize) * 3;
                let row_bytes = copy_w * 3;
                if src_start + row_bytes <= rgb.len() {
                    padded[dst_start..dst_start + row_bytes]
                        .copy_from_slice(&rgb[src_start..src_start + row_bytes]);
                }
            }
            let curr_mbs = rgb_frame_to_mbs(&padded, align_w as usize, align_h as usize);
            let is_idr = prev_mbs.is_none() || idx % IDR_KEYFRAME_INTERVAL == 0;
            let nal = if is_idr {
                since_idr = 0;
                let n = encode_idr_mbs_nal(&curr_mbs, idr_seq);
                idr_seq = idr_seq.wrapping_add(1);
                sync_samples.push((idx + 1) as u32);
                n
            } else {
                since_idr = since_idr.saturating_add(1);
                encode_p_delta_mbs_nal(&curr_mbs, prev_mbs.as_deref().unwrap_or(&[]), since_idr)
            };
            prev_mbs = Some(curr_mbs);
            samples.push(avcc_sample_from_nal(&nal));
            durations.push(dur_ms.max(33));
        }
    }

    let total_duration: u32 = durations.iter().copied().sum();
    let sample_sizes: Vec<u32> = samples.iter().map(|s| s.len() as u32).collect();

    let ftyp = make_box(*b"ftyp", |b| {
        b.put_slice(b"isom");
        b.put_u32(0x0000_0200);
        b.put_slice(b"isom");
        b.put_slice(b"iso2");
        b.put_slice(b"avc1");
        b.put_slice(b"mp41");
    });

    // Build moov twice so chunk offset inside `stco` points directly to `mdat` payload start
    let moov_pass1 = build_moov(
        align_w,
        align_h,
        total_duration,
        &durations,
        &sample_sizes,
        &sync_samples,
        &sps,
        &pps,
        0,
    );
    let mdat_header_start = ftyp.len() + moov_pass1.len();
    let mdat_payload_offset = (mdat_header_start + 8) as u32;
    let moov = build_moov(
        align_w,
        align_h,
        total_duration,
        &durations,
        &sample_sizes,
        &sync_samples,
        &sps,
        &pps,
        mdat_payload_offset,
    );

    let mdat_payload_len: usize = samples.iter().map(Vec::len).sum();
    let mut mdat = BytesMut::with_capacity(8 + mdat_payload_len);
    mdat.put_u32((8 + mdat_payload_len) as u32);
    mdat.put_slice(b"mdat");
    for s in &samples {
        mdat.put_slice(s);
    }

    let mut mp4 = Vec::with_capacity(ftyp.len() + moov.len() + mdat.len());
    mp4.extend_from_slice(&ftyp);
    mp4.extend_from_slice(&moov);
    mp4.extend_from_slice(&mdat);
    mp4
}

#[allow(clippy::similar_names)]
fn build_moov(
    width: u32,
    height: u32,
    total_duration: u32,
    durations: &[u32],
    sample_sizes: &[u32],
    sync_samples: &[u32],
    sps: &[u8],
    pps: &[u8],
    chunk_offset: u32,
) -> Vec<u8> {
    let mvhd = make_full_box(*b"mvhd", 0, 0, |b| {
        b.put_u32(0);
        b.put_u32(0);
        b.put_u32(1000);
        b.put_u32(total_duration);
        b.put_u32(0x0001_0000);
        b.put_u16(0x0100);
        b.put_u16(0);
        b.put_bytes(0, 8);
        for v in [0x0001_0000u32, 0, 0, 0, 0x0001_0000, 0, 0, 0, 0x4000_0000] {
            b.put_u32(v);
        }
        b.put_bytes(0, 24);
        b.put_u32(2);
    });

    let tkhd = make_full_box(*b"tkhd", 0, 3, |b| {
        b.put_u32(0);
        b.put_u32(0);
        b.put_u32(1);
        b.put_u32(0);
        b.put_u32(total_duration);
        b.put_bytes(0, 12);
        b.put_u16(0);
        b.put_u16(0);
        for v in [0x0001_0000u32, 0, 0, 0, 0x0001_0000, 0, 0, 0, 0x4000_0000] {
            b.put_u32(v);
        }
        b.put_u32(width << 16);
        b.put_u32(height << 16);
    });

    let mdhd = make_full_box(*b"mdhd", 0, 0, |b| {
        b.put_u32(0);
        b.put_u32(0);
        b.put_u32(1000);
        b.put_u32(total_duration);
        b.put_u16(0x55C4);
        b.put_u16(0);
    });

    let hdlr = make_full_box(*b"hdlr", 0, 0, |b| {
        b.put_u32(0);
        b.put_slice(b"vide");
        b.put_bytes(0, 12);
        b.put_slice(b"OperquayVideo\0");
    });

    let vmhd = make_full_box(*b"vmhd", 0, 1, |b| {
        b.put_bytes(0, 8);
    });

    let dref = make_full_box(*b"dref", 0, 0, |b| {
        b.put_u32(1);
        b.put_slice(&make_full_box(*b"url ", 0, 1, |_| {}));
    });
    let dinf = make_box(*b"dinf", |b| b.put_slice(&dref));

    let avcc = make_box(*b"avcC", |b| {
        b.put_u8(1); // configurationVersion
        b.put_u8(66); // AVCProfileIndication
        b.put_u8(0xC0); // profile_compatibility
        b.put_u8(31); // AVCLevelIndication
        b.put_u8(0xFF); // lengthSizeMinusOne = 3 (4 bytes)
        b.put_u8(0xE1); // numOfSequenceParameterSets = 1
        b.put_u16(sps.len() as u16);
        b.put_slice(sps);
        b.put_u8(1); // numOfPictureParameterSets = 1
        b.put_u16(pps.len() as u16);
        b.put_slice(pps);
    });

    let avc1 = make_box(*b"avc1", |b| {
        b.put_bytes(0, 6);
        b.put_u16(1); // data_reference_index
        b.put_bytes(0, 16);
        b.put_u16(width as u16);
        b.put_u16(height as u16);
        b.put_u32(0x0048_0000);
        b.put_u32(0x0048_0000);
        b.put_u32(0);
        b.put_u16(1);
        b.put_bytes(0, 32);
        b.put_u16(0x0018);
        b.put_i16(-1);
        b.put_slice(&avcc);
    });

    let stsd = make_full_box(*b"stsd", 0, 0, |b| {
        b.put_u32(1);
        b.put_slice(&avc1);
    });

    let stts = make_full_box(*b"stts", 0, 0, |b| {
        b.put_u32(durations.len() as u32);
        for &d in durations {
            b.put_u32(1);
            b.put_u32(d);
        }
    });

    let stss = make_full_box(*b"stss", 0, 0, |b| {
        b.put_u32(sync_samples.len() as u32);
        for &idx in sync_samples {
            b.put_u32(idx);
        }
    });

    let stsc = make_full_box(*b"stsc", 0, 0, |b| {
        b.put_u32(1);
        b.put_u32(1);
        b.put_u32(sample_sizes.len() as u32);
        b.put_u32(1);
    });

    let stsz = make_full_box(*b"stsz", 0, 0, |b| {
        b.put_u32(0);
        b.put_u32(sample_sizes.len() as u32);
        for &sz in sample_sizes {
            b.put_u32(sz);
        }
    });

    let stco = make_full_box(*b"stco", 0, 0, |b| {
        b.put_u32(1);
        b.put_u32(chunk_offset);
    });

    let stbl = make_box(*b"stbl", |b| {
        b.put_slice(&stsd);
        b.put_slice(&stts);
        b.put_slice(&stss);
        b.put_slice(&stsc);
        b.put_slice(&stsz);
        b.put_slice(&stco);
    });

    let minf = make_box(*b"minf", |b| {
        b.put_slice(&vmhd);
        b.put_slice(&dinf);
        b.put_slice(&stbl);
    });

    let mdia = make_box(*b"mdia", |b| {
        b.put_slice(&mdhd);
        b.put_slice(&hdlr);
        b.put_slice(&minf);
    });

    let trak = make_box(*b"trak", |b| {
        b.put_slice(&tkhd);
        b.put_slice(&mdia);
    });

    make_box(*b"moov", |b| {
        b.put_slice(&mvhd);
        b.put_slice(&trak);
    })
}

/// Convert an Asciinema `.cast` v2 NDJSON recording into a genuine H.264 Baseline MP4 video
/// rendered using `operquay-term` virtual terminal frames.
#[must_use]
pub fn transcode_cast_to_mp4(cast_ndjson: &str) -> Vec<u8> {
    let mut lines = cast_ndjson.lines();
    let header_cols: u16;
    let header_rows: u16;
    if let Some(first) = lines.next() {
        let v: serde_json::Value = serde_json::from_str(first).unwrap_or_default();
        header_cols = v["width"].as_u64().unwrap_or(80).clamp(20, 120) as u16;
        header_rows = v["height"].as_u64().unwrap_or(24).clamp(8, 40) as u16;
    } else {
        header_cols = 80;
        header_rows = 24;
    }

    let mut term = TerminalEngine::new(header_cols, header_rows, 500);
    let cell_w = 8u32;
    let cell_h = 16u32;
    let frame_w = u32::from(header_cols) * cell_w;
    let frame_h = u32::from(header_rows) * cell_h;

    let mut frames: Vec<(Vec<u8>, u32)> = Vec::new();
    let mut prev_ms = 0u32;

    for raw in lines.take(300) {
        let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(raw) else {
            continue;
        };
        if arr.len() < 3 || arr[1].as_str() != Some("o") {
            continue;
        }
        let ts_ms = (arr[0].as_f64().unwrap_or(0.0) * 1000.0).max(0.0) as u32;
        if let Some(txt) = arr[2].as_str() {
            term.feed_str(txt);
            let dur = ts_ms.saturating_sub(prev_ms).max(40);
            prev_ms = ts_ms;
            frames.push((rasterize_terminal_rgb(&term, cell_w, cell_h), dur));
        }
    }
    if frames.is_empty() {
        frames.push((rasterize_terminal_rgb(&term, cell_w, cell_h), 500));
    }

    let refs: Vec<(&[u8], u32)> = frames.iter().map(|(b, d)| (b.as_slice(), *d)).collect();
    mux_rgb_frames_to_mp4(&refs, frame_w, frame_h)
}

/// Convert a recorded `.guac` instructional stream (`size`, `rect`, `cfill`, `copy`, `img`,
/// `blob`, `end`, `sync`) into a genuine H.264 Baseline MP4 video by replaying graphical ops onto
/// an in-memory framebuffer and downscaling keyframes to multiple-of-16 MP4 dimensions.
#[must_use]
pub fn transcode_guac_to_mp4(raw_guac: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw_guac);
    let mut parser = GuacParser::new();
    let Ok(insts) = parser.push_str(&text) else {
        return mux_rgb_frames_to_mp4(&[(&vec![14u8; 320 * 240 * 3], 1000)], 320, 240);
    };

    let mut fb_w: usize = 960;
    let mut fb_h: usize = 600;
    let mut fb = vec![14u8; fb_w * fb_h * 3];
    let mut pending_rect: Option<(i32, i32, i32, i32)> = None;
    let mut img_streams: HashMap<String, (String, i32, i32, String)> = HashMap::new();
    let mut dirty = false;
    let mut prev_sync_ms: Option<u64> = None;

    let (out_w, out_h) = scaled_mb_dims(fb_w, fb_h);
    let mut active_out_w = out_w;
    let mut active_out_h = out_h;
    let mut keyframes: Vec<(Vec<u8>, u32)> = Vec::new();

    for inst in insts {
        match inst.opcode.as_str() {
            "size" => {
                if inst.args.first().map(String::as_str) == Some("0") {
                    let nw = inst
                        .args
                        .get(1)
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(fb_w)
                        .clamp(64, 4096);
                    let nh = inst
                        .args
                        .get(2)
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(fb_h)
                        .clamp(64, 4096);
                    if nw != fb_w || nh != fb_h {
                        fb_w = nw;
                        fb_h = nh;
                        fb = vec![14u8; fb_w * fb_h * 3];
                        let (sw, sh) = scaled_mb_dims(fb_w, fb_h);
                        active_out_w = sw;
                        active_out_h = sh;
                        keyframes.clear();
                    }
                }
            }
            "rect" => {
                let x = inst
                    .args
                    .get(1)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                let y = inst
                    .args
                    .get(2)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                let w = inst
                    .args
                    .get(3)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                let h = inst
                    .args
                    .get(4)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                pending_rect = Some((x, y, w, h));
            }
            "cfill" => {
                if let Some((rx, ry, rw, rh)) = pending_rect.take() {
                    let r = inst
                        .args
                        .get(2)
                        .and_then(|s| s.parse::<u8>().ok())
                        .unwrap_or(0);
                    let g = inst
                        .args
                        .get(3)
                        .and_then(|s| s.parse::<u8>().ok())
                        .unwrap_or(0);
                    let b = inst
                        .args
                        .get(4)
                        .and_then(|s| s.parse::<u8>().ok())
                        .unwrap_or(0);
                    fill_fb_rect(&mut fb, fb_w, fb_h, rx, ry, rw, rh, [r, g, b]);
                    dirty = true;
                }
            }
            "copy" => {
                let sx = inst
                    .args
                    .get(1)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                let sy = inst
                    .args
                    .get(2)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                let w = inst
                    .args
                    .get(3)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                let h = inst
                    .args
                    .get(4)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                let dx = inst
                    .args
                    .get(7)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                let dy = inst
                    .args
                    .get(8)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(0);
                copy_fb_rect(&mut fb, fb_w, fb_h, sx, sy, w, h, dx, dy);
                dirty = true;
            }
            "img" => {
                if let (Some(sid), Some(mime), Some(x), Some(y)) = (
                    inst.args.first(),
                    inst.args.get(3),
                    inst.args.get(4).and_then(|s| s.parse::<i32>().ok()),
                    inst.args.get(5).and_then(|s| s.parse::<i32>().ok()),
                ) {
                    img_streams.insert(sid.clone(), (mime.clone(), x, y, String::new()));
                }
            }
            "blob" => {
                if let (Some(sid), Some(data)) = (inst.args.first(), inst.args.get(1)) {
                    if let Some(entry) = img_streams.get_mut(sid) {
                        entry.3.push_str(data);
                    }
                }
            }
            "end" => {
                if let Some(sid) = inst.args.first() {
                    if let Some((mime, x, y, b64)) = img_streams.remove(sid) {
                        if mime.eq_ignore_ascii_case("image/png") {
                            if let Ok(png_bytes) = BASE64.decode(b64.as_bytes()) {
                                blit_png_to_fb(&mut fb, fb_w, fb_h, x, y, &png_bytes);
                                dirty = true;
                            }
                        }
                    }
                }
            }
            "sync" => {
                let ts_ms = inst
                    .args
                    .first()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                if dirty && keyframes.len() < 300 {
                    let dur_ms = prev_sync_ms
                        .map_or(200, |p| ts_ms.saturating_sub(p).clamp(40, 2000))
                        as u32;
                    keyframes.push((
                        downscale_rgb(&fb, fb_w, fb_h, active_out_w, active_out_h),
                        dur_ms,
                    ));
                    dirty = false;
                }
                prev_sync_ms = Some(ts_ms);
            }
            _ => {}
        }
    }

    if dirty && keyframes.len() < 300 {
        keyframes.push((
            downscale_rgb(&fb, fb_w, fb_h, active_out_w, active_out_h),
            500,
        ));
    }
    if keyframes.is_empty() {
        keyframes.push((
            downscale_rgb(&fb, fb_w, fb_h, active_out_w, active_out_h),
            1000,
        ));
    }

    let refs: Vec<(&[u8], u32)> = keyframes.iter().map(|(b, d)| (b.as_slice(), *d)).collect();
    mux_rgb_frames_to_mp4(&refs, active_out_w, active_out_h)
}

fn scaled_mb_dims(src_w: usize, src_h: usize) -> (u32, u32) {
    let max_w = 640.0f64;
    let max_h = 368.0f64;
    let scale = (max_w / src_w.max(1) as f64)
        .min(max_h / src_h.max(1) as f64)
        .min(1.0);
    let rw = ((src_w as f64 * scale).round() as u32).max(16);
    let rh = ((src_h as f64 * scale).round() as u32).max(16);
    (
        ((rw + 8) / 16 * 16).clamp(16, 640),
        ((rh + 8) / 16 * 16).clamp(16, 384),
    )
}

fn downscale_rgb(src: &[u8], sw: usize, sh: usize, dw: u32, dh: u32) -> Vec<u8> {
    let out_cols = dw as usize;
    let out_rows = dh as usize;
    let mut out = vec![0u8; out_cols * out_rows * 3];
    for dy in 0..out_rows {
        let sy = (dy * sh) / out_rows;
        for dx in 0..out_cols {
            let sx = (dx * sw) / out_cols;
            let soff = (sy * sw + sx) * 3;
            let doff = (dy * out_cols + dx) * 3;
            out[doff..doff + 3].copy_from_slice(&src[soff..soff + 3]);
        }
    }
    out
}

fn fill_fb_rect(fb: &mut [u8], fw: usize, fh: usize, x: i32, y: i32, w: i32, h: i32, rgb: [u8; 3]) {
    let x0 = x.max(0) as usize;
    let y0 = y.max(0) as usize;
    let x1 = x.saturating_add(w).min(fw as i32).max(0) as usize;
    let y1 = y.saturating_add(h).min(fh as i32).max(0) as usize;
    for py in y0..y1 {
        for px in x0..x1 {
            let off = (py * fw + px) * 3;
            fb[off..off + 3].copy_from_slice(&rgb);
        }
    }
}

fn copy_fb_rect(
    fb: &mut [u8],
    fw: usize,
    fh: usize,
    sx: i32,
    sy: i32,
    w: i32,
    h: i32,
    dx: i32,
    dy: i32,
) {
    if sx < 0 || sy < 0 || dx < 0 || dy < 0 || w <= 0 || h <= 0 {
        return;
    }
    let sx = sx as usize;
    let sy = sy as usize;
    let dx = dx as usize;
    let dy = dy as usize;
    let cw = (w as usize)
        .min(fw.saturating_sub(sx))
        .min(fw.saturating_sub(dx));
    let ch = (h as usize)
        .min(fh.saturating_sub(sy))
        .min(fh.saturating_sub(dy));
    let mut tmp = Vec::with_capacity(cw * ch * 3);
    for row in 0..ch {
        let s = ((sy + row) * fw + sx) * 3;
        tmp.extend_from_slice(&fb[s..s + cw * 3]);
    }
    for row in 0..ch {
        let d = ((dy + row) * fw + dx) * 3;
        let t = row * cw * 3;
        fb[d..d + cw * 3].copy_from_slice(&tmp[t..t + cw * 3]);
    }
}

fn blit_png_to_fb(fb: &mut [u8], fw: usize, fh: usize, ox: i32, oy: i32, png_bytes: &[u8]) {
    let mut dec = png::Decoder::new(Cursor::new(png_bytes));
    dec.set_transformations(png::Transformations::normalize_to_color8());
    let Ok(mut reader) = dec.read_info() else {
        return;
    };
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let Ok(info) = reader.next_frame(&mut buf) else {
        return;
    };
    let pw = info.width as usize;
    let ph = info.height as usize;
    let bpp = match info.color_type {
        png::ColorType::Rgba => 4usize,
        png::ColorType::Rgb => 3usize,
        png::ColorType::GrayscaleAlpha => 2usize,
        png::ColorType::Grayscale => 1usize,
        png::ColorType::Indexed => return,
    };
    for py in 0..ph {
        let dy = oy + py as i32;
        if dy < 0 || dy as usize >= fh {
            continue;
        }
        for px in 0..pw {
            let dx = ox + px as i32;
            if dx < 0 || dx as usize >= fw {
                continue;
            }
            let soff = (py * pw + px) * bpp;
            let doff = (dy as usize * fw + dx as usize) * 3;
            match bpp {
                4 => {
                    let a = u16::from(buf[soff + 3]);
                    if a == 255 {
                        fb[doff..doff + 3].copy_from_slice(&buf[soff..soff + 3]);
                    } else if a > 0 {
                        let inv = 255 - a;
                        for c in 0..3 {
                            fb[doff + c] = ((u16::from(buf[soff + c]) * a
                                + u16::from(fb[doff + c]) * inv)
                                / 255) as u8;
                        }
                    }
                }
                3 => fb[doff..doff + 3].copy_from_slice(&buf[soff..soff + 3]),
                2 | 1 => {
                    let v = buf[soff];
                    fb[doff] = v;
                    fb[doff + 1] = v;
                    fb[doff + 2] = v;
                }
                _ => {}
            }
        }
    }
}

fn rasterize_terminal_rgb(term: &TerminalEngine, cell_w: u32, cell_h: u32) -> Vec<u8> {
    let w = usize::from(term.cols()) * (cell_w as usize);
    let h = usize::from(term.rows()) * (cell_h as usize);
    let mut rgb = vec![14u8; w * h * 3];
    for (row_idx, row) in term.viewport_cells().iter().enumerate() {
        for (col_idx, cell) in row.iter().enumerate() {
            let bg = cell.bg.resolve_rgb([14, 17, 22]);
            let fg = cell.fg.resolve_rgb([230, 234, 240]);
            let is_inv = (cell.attrs & operquay_term::cell::attr::INVERSE) != 0;
            let (bg_c, fg_c) = if is_inv { (fg, bg) } else { (bg, fg) };
            let glyph = ascii_glyph_8x8(cell.ch);
            for (gy, &row_bits) in glyph.iter().enumerate() {
                for dy in 0..2usize {
                    let py = row_idx * (cell_h as usize) + gy * 2 + dy;
                    for gx in 0..8usize {
                        let on = ((row_bits >> (7 - gx)) & 1) != 0;
                        let px = col_idx * (cell_w as usize) + gx;
                        let off = (py * w + px) * 3;
                        let col = if on { fg_c } else { bg_c };
                        rgb[off] = col[0];
                        rgb[off + 1] = col[1];
                        rgb[off + 2] = col[2];
                    }
                }
            }
        }
    }
    rgb
}

const fn ascii_glyph_8x8(ch: char) -> [u8; 8] {
    match ch {
        ' ' => [0; 8],
        '0'..='9' | 'A'..='Z' | 'a'..='z' => {
            // Crisp deterministic 8x8 glyph stroke pattern per character class
            let c = ch as u8;
            [
                0x3C,
                if c & 1 != 0 { 0x66 } else { 0x42 },
                0x42,
                0x7E,
                if c & 2 != 0 { 0x42 } else { 0x5A },
                0x42,
                if c & 4 != 0 { 0x66 } else { 0x3C },
                0x00,
            ]
        }
        '$' | '#' | '>' => [0x10, 0x38, 0x54, 0x30, 0x18, 0x54, 0x38, 0x10],
        '-' | '_' => [0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00],
        '/' => [0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x00, 0x00],
        '.' | ',' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00],
        ':' | ';' => [0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00],
        _ => [0x3C, 0x42, 0x5A, 0x5A, 0x42, 0x3C, 0x00, 0x00],
    }
}

fn make_box(tag: [u8; 4], fill: impl FnOnce(&mut BytesMut)) -> Vec<u8> {
    let mut inner = BytesMut::new();
    fill(&mut inner);
    let len = 8 + inner.len();
    let mut out = BytesMut::with_capacity(len);
    out.put_u32(len as u32);
    out.put_slice(&tag);
    out.put_slice(&inner);
    out.to_vec()
}

fn make_full_box(
    tag: [u8; 4],
    version: u8,
    flags: u32,
    fill: impl FnOnce(&mut BytesMut),
) -> Vec<u8> {
    make_box(tag, |b| {
        b.put_u8(version);
        b.put_u8(((flags >> 16) & 0xFF) as u8);
        b.put_u8(((flags >> 8) & 0xFF) as u8);
        b.put_u8((flags & 0xFF) as u8);
        fill(b);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inter_frame_pskip_delta_compresses_multi_frame_mp4_and_emits_valid_nals() {
        let width = 320u32;
        let height = 240u32;
        let mut frame_bufs: Vec<Vec<u8>> = Vec::with_capacity(20);
        for i in 0..20usize {
            let mut rgb = vec![24u8; (width * height * 3) as usize];
            // Flip only one 16x16 macroblock per frame (simulating cursor/typing updates)
            for py in 16..32 {
                for px in 16..32 {
                    let off = (py * width as usize + px) * 3;
                    rgb[off] = 40 + (i as u8 * 8);
                    rgb[off + 1] = 180;
                    rgb[off + 2] = 120;
                }
            }
            frame_bufs.push(rgb);
        }
        let refs: Vec<(&[u8], u32)> = frame_bufs.iter().map(|b| (b.as_slice(), 100u32)).collect();
        let mp4 = mux_rgb_frames_to_mp4(&refs, width, height);

        let raw_yuv_total = 20 * (width as usize) * (height as usize) * 3 / 2;
        assert!(
            mp4.len() * 5 < raw_yuv_total,
            "expected >5x inter-frame compression: mp4={} bytes, raw_yuv={} bytes",
            mp4.len(),
            raw_yuv_total
        );
        assert_eq!(&mp4[4..8], b"ftyp");
        assert!(mp4.windows(4).any(|w| w == b"moov"));
        assert!(mp4.windows(4).any(|w| w == b"stss"));
        assert!(mp4.windows(4).any(|w| w == b"avc1"));
        assert!(mp4.windows(4).any(|w| w == b"avcC"));

        let mdat_pos = mp4.windows(4).position(|w| w == b"mdat").unwrap() + 4;
        let mut cursor = mdat_pos;
        let mut nal_types = Vec::new();
        while cursor + 5 <= mp4.len() {
            let sz = u32::from_be_bytes([
                mp4[cursor],
                mp4[cursor + 1],
                mp4[cursor + 2],
                mp4[cursor + 3],
            ]) as usize;
            cursor += 4;
            let nal_hdr = mp4[cursor];
            nal_types.push(nal_hdr);
            cursor += sz;
        }
        assert_eq!(nal_types.len(), 20);
        assert_eq!(nal_types[0], 0x65);
        assert!(nal_types[1..].iter().all(|&h| h == 0x41));

        if std::env::var_os("OPERQUAY_VERIFY_FFMPEG").is_some() {
            let tmp = std::env::temp_dir().join("operquay_test_h264.mp4");
            std::fs::write(&tmp, &mp4).unwrap();
            let out = std::process::Command::new("ffmpeg")
                .args([
                    "-v",
                    "error",
                    "-i",
                    tmp.to_str().unwrap(),
                    "-f",
                    "null",
                    "-",
                ])
                .output()
                .expect("invoke ffmpeg");
            let _ = std::fs::remove_file(&tmp);
            assert!(
                out.status.success(),
                "ffmpeg failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                out.stderr.is_empty(),
                "ffmpeg reported H.264 bitstream errors: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
