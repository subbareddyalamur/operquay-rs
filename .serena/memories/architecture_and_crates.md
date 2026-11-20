# Architecture & Crate Layout (`operquay-rust`)

Single-binary pure-Rust gateway replacing Go + Node `guac-lite` + C `guacd` + spawned AWS/SSM child CLIs (`ADR-0000`–`ADR-0007`). External PostgreSQL remains the system of record.

## Workspace Crates
- `operquay-core`: Domain models, `SecretString` (`ZeroizeOnDrop`), `RemoteDesktopSettings`, `NetworkPreset` simulation math, `EngineRegistry`/`DesktopEngine`/`DisplaySink`/`SettingsStore` traits, SQL schema (`migrations/0001_remote_desktop_settings.sql`).
- `operquay-telemetry`: OpenTelemetry `SdkTracerProvider` (W3C TraceContext + optional OTLP), Prometheus `/metrics` + OTLP meter bridge, structured JSON `tracing` logs with `trace_id`/`span_id`.
- `operquay-guac`: Pure-Rust Guacamole `1.0.0..1.5.0` framing parser/serializer (Unicode scalar lengths, 8 MiB/128-arg bounds) + `SyncTracker`.
- `operquay-display`: 5-phase `64x64` framebuffer pipeline (solid fill, `64x64` hash `copy` detection `h * 62 + px`, coalescing, entropy split `(runs << 8) / transitions - 1024`, lag-adaptive quality `lag <= 19 ? 90 : max(30, 110 - lag)`), plus binary `OQR2` wire frames.
- `operquay-rdp`: Clean-room RDP primitives (strictly zero `ironrdp*`): TPKT, Fast-Path, X.224 `RDP_NEG_REQ`/`RSP`, `25` LCID keymaps + dead-key/Unicode fallback, `MS-RDPEDISP` resize `[200, 8192]` + even width, Fast-Path RLE bitmap decoder, pluggable `RdpEngine`.
- `operquay-vnc`: Clean-room RFB 3.3–3.8 codec (`None`, DES `VNCAuth`, `VeNCrypt`, `Raw`/`CopyRect`/`Cursor`/`SetDesktopSize`), key/pointer/clipboard.
- `operquay-server`: Single Axum HTTP/WS server binary (`operquay`) serving REST APIs, `/metrics`, `/api/v1/ws/rdp` (`guacamole` + `operquay-rdp-v2`), and embedded React SPA (`rust-embed` / `--static-dir`).

