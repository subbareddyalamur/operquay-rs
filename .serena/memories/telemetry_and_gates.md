# OpenTelemetry & Release Verification Gates

## OpenTelemetry
- Traces: W3C `traceparent` HTTP/WS propagation (`operquay.http.request`, `operquay.desktop.session`, `operquay.display.flush`).
- Logs: JSON structured logs via `tracing-subscriber` carrying active `trace_id` & `span_id`.
- Metrics (`/metrics` Prometheus text + optional OTLP push):
  - `operquay_sessions_started_total{protocol,preset}`
  - `operquay_active_sessions{protocol}`
  - `operquay_frames_encoded_total{codec}`
  - `operquay_frames_dropped_total{reason}`
  - `operquay_frame_encode_duration_ms`
  - `operquay_input_rtt_ms`
  - `operquay_settings_updates_total{preset}`

## Verification Commands
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo tree --workspace | grep -i ironrdp` (must return empty)
- `pnpm --dir frontend run typecheck && pnpm --dir frontend run lint && pnpm --dir frontend run test && pnpm --dir frontend run build`
- `pnpm --dir frontend run test:e2e`

