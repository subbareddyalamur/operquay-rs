#![forbid(unsafe_code)]

//! In-process pure-Rust `IronRDP 0.17` RDP engine (`ADR-0002`, zero sidecar processes).
//! Implements X.224 / TLS / `CredSSP` (NLA), MCS/GCC, `[MS-RDPBCGR]` Fast-Path bitmap &
//! pointer decoding, `[MS-RDPEDISP]` dynamic resize, `[MS-RDPECLIP]` bidirectional clipboard,
//! and Guacamole's 25 Windows LCID keyboard mappings.

pub mod clipboard;
pub mod egfx;
pub mod engine;
pub mod keymap;
pub mod live_client;
pub mod pdu;
pub mod standard_sec;
pub mod tls;

pub use clipboard::{
    decode_clipboard_bytes, encode_clipboard_text_utf16le, normalize_clipboard_text,
    OperquayCliprdrBackend, RdpClipboardEvent,
};
pub use engine::{RdpEngine, RdpEngineFactory};
pub use keymap::{KeyEventOutput, KeymapState, KeysymDesc};
pub use live_client::{
    check_rdp_legacy_crypto_policy, connect_live_rdp_host, connect_live_rdp_tcp,
    run_live_rdp_over_stream, run_live_rdp_over_stream_ref, run_live_rdp_over_stream_with_progress,
};
pub use pdu::{
    clamp_rdp_display_size, FastPathInputEvent, NegotiationProtocol, RdpPduError, X224Confirm,
    X224Request,
};
pub use standard_sec::{is_standard_rdp_only_error, StandardRdpSecurityStream};
