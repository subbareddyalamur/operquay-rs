#![forbid(unsafe_code)]

//! Clean-room 5-phase `64x64` display planner, lag-adaptive pure-Rust PNG/JPEG
//! encoders, and `OQR2` binary WebSocket wire framing (`ADR-0001` & `ADR-0007`).

pub mod oqr2;
pub mod planner;

pub use oqr2::{Oqr2Message, OQR2_MAGIC};
pub use planner::{complexity_score, DisplayOp, FrameEncodeConfig, FrameStats, FramebufferPlanner};
