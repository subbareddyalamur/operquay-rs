#![forbid(unsafe_code)]

//! Clean-room RFC 6143 VNC / RFB `3.3..=3.8` client & display adapter (`ADR-0003`).
//! Supports `VNCAuth` (pure-Rust bit-reversed DES), `VeNCrypt` TLS subtype negotiation,
//! `Raw` / `CopyRect` / `RRE` / `Hextile` / `ZRLE` / `Cursor` / `SetDesktopSize (0xfb)`,
//! cancellation-safe split RFB I/O, and live TCP/SSM tunneling.

pub mod auth;
pub mod engine;
pub mod live_client;
pub mod rfb;

pub use auth::encrypt_vnc_challenge;
pub use engine::{VncEngine, VncEngineFactory};
pub use live_client::{
    check_vnc_legacy_crypto_policy, connect_live_vnc_host, run_live_vnc_over_stream,
};
pub use rfb::{
    encode_client_cut_text, encode_framebuffer_update_request, encode_key_event,
    encode_pointer_event, encode_set_desktop_size, encode_set_encodings,
    encode_set_pixel_format_rgba32, negotiate_rfb_over_stream, read_framebuffer_update,
    read_framebuffer_update_with_state, RfBError, RfbSecurityType, ServerInit, ZrleDecoder,
    SUPPORTED_ENCODINGS,
};
