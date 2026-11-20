#![forbid(unsafe_code)]

//! Clean-room Apache Guacamole `1.0.0..=1.5.0` framing parser, typed instruction
//! codecs, and `SyncTracker` lag estimator derived from binary protocol verification.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use thiserror::Error;

pub const MAX_INSTRUCTION_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_INSTRUCTION_ARGS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuacInstruction {
    pub opcode: String,
    pub args: Vec<String>,
}

impl GuacInstruction {
    #[must_use]
    pub fn new(opcode: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            opcode: opcode.into(),
            args,
        }
    }

    /// Encode instruction as `<scalar_len>.<utf8>,...;` using Unicode scalar lengths
    /// required by Guacamole `1.0.0..=1.5.0`.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut out = String::with_capacity(32);
        write_element(&mut out, &self.opcode);
        for arg in &self.args {
            out.push(',');
            write_element(&mut out, arg);
        }
        out.push(';');
        out
    }

    #[must_use]
    pub fn into_client(self) -> ClientInstruction {
        match self.opcode.as_str() {
            "nop" => ClientInstruction::Nop,
            "disconnect" => ClientInstruction::Disconnect,
            "sync" => {
                let ts = self
                    .args
                    .first()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                ClientInstruction::Sync { timestamp_ms: ts }
            }
            "size" => {
                let width = self
                    .args
                    .first()
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(1280);
                let height = self
                    .args
                    .get(1)
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(720);
                let dpi = self
                    .args
                    .get(2)
                    .and_then(|v| v.parse::<u16>().ok())
                    .unwrap_or(96);
                ClientInstruction::Size { width, height, dpi }
            }
            "mouse" => {
                let x = self
                    .args
                    .first()
                    .and_then(|v| v.parse::<u16>().ok())
                    .unwrap_or(0);
                let y = self
                    .args
                    .get(1)
                    .and_then(|v| v.parse::<u16>().ok())
                    .unwrap_or(0);
                let mask = self
                    .args
                    .get(2)
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0);
                ClientInstruction::Mouse {
                    x,
                    y,
                    button_mask: mask,
                }
            }
            "key" => {
                let keysym = self
                    .args
                    .first()
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(0);
                let pressed = self.args.get(1).is_some_and(|v| v == "1");
                ClientInstruction::Key { keysym, pressed }
            }
            _ => ClientInstruction::Other(self),
        }
    }
}

fn write_element(out: &mut String, val: &str) {
    let scalar_len = val.chars().count();
    let _ = write!(out, "{scalar_len}.{val}");
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientInstruction {
    Nop,
    Disconnect,
    Sync { timestamp_ms: u64 },
    Size { width: u32, height: u32, dpi: u16 },
    Mouse { x: u16, y: u16, button_mask: u8 },
    Key { keysym: u32, pressed: bool },
    Other(GuacInstruction),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GuacParseError {
    #[error("instruction exceeds maximum allowed size of {MAX_INSTRUCTION_BYTES} bytes")]
    FrameTooLarge,
    #[error("instruction argument count exceeds maximum of {MAX_INSTRUCTION_ARGS}")]
    TooManyArguments,
    #[error("invalid element length prefix")]
    InvalidLength,
    #[error("unexpected separator byte '{0}' after element")]
    InvalidSeparator(char),
    #[error("invalid UTF-8 sequence in Guacamole instruction")]
    InvalidUtf8,
}

/// Incremental streaming parser supporting partial WebSocket chunks and multi-byte UTF-8 scalars.
#[derive(Debug, Default)]
pub struct GuacParser {
    buffer: String,
}

impl GuacParser {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_str(&mut self, chunk: &str) -> Result<Vec<GuacInstruction>, GuacParseError> {
        if self.buffer.len().saturating_add(chunk.len()) > MAX_INSTRUCTION_BYTES {
            self.buffer.clear();
            return Err(GuacParseError::FrameTooLarge);
        }
        self.buffer.push_str(chunk);

        let mut decoded = Vec::new();
        while let Some((inst, consumed_bytes)) = parse_one(&self.buffer)? {
            decoded.push(inst);
            self.buffer.drain(..consumed_bytes);
        }
        Ok(decoded)
    }
}

fn parse_one(input: &str) -> Result<Option<(GuacInstruction, usize)>, GuacParseError> {
    if input.is_empty() {
        return Ok(None);
    }

    let mut idx = 0;
    let mut elements = Vec::new();

    loop {
        let rest = &input[idx..];
        let Some(dot_rel) = rest.find('.') else {
            return Ok(None);
        };
        let len_str = &rest[..dot_rel];
        if len_str.is_empty() || !len_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(GuacParseError::InvalidLength);
        }
        let scalar_len: usize = len_str.parse().map_err(|_| GuacParseError::InvalidLength)?;
        idx += dot_rel + 1;

        // Advance `scalar_len` UTF-8 scalar values carefully across byte boundaries.
        let value_start = idx;
        let mut char_iter = input[value_start..].char_indices();
        let value_end = if scalar_len == 0 {
            value_start
        } else {
            let mut end_rel = None;
            let mut count = 0;
            for (byte_offset, ch) in &mut char_iter {
                count += 1;
                if count == scalar_len {
                    end_rel = Some(byte_offset + ch.len_utf8());
                    break;
                }
            }
            let Some(rel) = end_rel else {
                return Ok(None);
            };
            value_start + rel
        };

        let value = input[value_start..value_end].to_owned();
        elements.push(value);
        idx = value_end;

        let Some(sep) = input[idx..].chars().next() else {
            return Ok(None);
        };
        idx += sep.len_utf8();

        match sep {
            ',' => {
                if elements.len() >= MAX_INSTRUCTION_ARGS {
                    return Err(GuacParseError::TooManyArguments);
                }
            }
            ';' => {
                let mut iter = elements.into_iter();
                let opcode = iter.next().ok_or(GuacParseError::InvalidLength)?;
                return Ok(Some((
                    GuacInstruction {
                        opcode,
                        args: iter.collect(),
                    },
                    idx,
                )));
            }
            other => return Err(GuacParseError::InvalidSeparator(other)),
        }
    }
}

/// Reverse-engineered Guacamole `sync` congestion estimator computing `processing_lag_ms`.
#[derive(Debug)]
pub struct SyncTracker {
    in_flight: Vec<(u64, Instant)>,
    last_lag_ms: u32,
}

impl Default for SyncTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            in_flight: Vec::with_capacity(8),
            last_lag_ms: 0,
        }
    }

    pub fn record_sent(&mut self, server_ts_ms: u64, now: Instant) {
        if self.in_flight.len() >= 16 {
            self.in_flight.remove(0);
        }
        self.in_flight.push((server_ts_ms, now));
    }

    pub fn record_ack(&mut self, ack_ts_ms: u64, now: Instant) -> Option<Duration> {
        let pos = self.in_flight.iter().position(|(ts, _)| *ts == ack_ts_ms)?;
        let (_, sent_at) = self.in_flight.remove(pos);
        let rtt = now.saturating_duration_since(sent_at);
        self.last_lag_ms = rtt.as_millis().min(u128::from(u32::MAX)) as u32;
        Some(rtt)
    }

    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    #[must_use]
    pub fn processing_lag_ms(&self) -> u32 {
        self.last_lag_ms
    }

    /// Guacamole `libguac.so` observed quality curve (`<=19ms -> 90`, else `max(floor, 110 - lag)`).
    #[must_use]
    pub fn adaptive_jpeg_quality(&self, quality_floor: u8) -> u8 {
        if self.last_lag_ms <= 19 {
            90
        } else {
            let scaled = 110_i32.saturating_sub(self.last_lag_ms as i32).max(30) as u8;
            scaled.max(quality_floor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_unicode_scalar_lengths_across_partial_chunks() {
        let inst = GuacInstruction::new("clipboard", vec!["0".into(), "text/plain".into()]);
        let encoded_a = inst.encode();
        assert_eq!(encoded_a, "9.clipboard,1.0,10.text/plain;");

        // Multi-byte UTF-8: "4.hi🚀;" is 4 Unicode scalar characters (not 7 UTF-8 bytes)
        let utf8_msg = GuacInstruction::new("name", vec!["hi🚀!".into()]).encode();
        assert_eq!(utf8_msg, "4.name,4.hi🚀!;");

        let mut parser = GuacParser::new();
        let half = utf8_msg.len() / 2;
        assert_eq!(parser.push_str(&utf8_msg[..half]).unwrap().len(), 0);
        let parsed = parser.push_str(&utf8_msg[half..]).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].opcode, "name");
        assert_eq!(parsed[0].args, vec!["hi🚀!"]);
    }

    #[test]
    fn tracks_sync_lag_and_adaptive_quality() {
        let mut tracker = SyncTracker::new();
        let t0 = Instant::now();
        tracker.record_sent(100, t0);
        let rtt = tracker
            .record_ack(100, t0 + Duration::from_millis(45))
            .unwrap();
        assert_eq!(rtt.as_millis(), 45);
        assert_eq!(tracker.processing_lag_ms(), 45);
        assert_eq!(tracker.adaptive_jpeg_quality(30), 65);
    }
}
