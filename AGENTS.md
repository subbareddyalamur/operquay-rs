# Operquay-Rust Agent Instructions

Follow [RULES.md](RULES.md), [tasks.md](tasks.md), and ADRs in [docs/ADR/](docs/ADR/). Build all protocol engines, AWS SSM, multi-database drivers, and UI assets in-process inside the single binary (no sidecar containers).

## Stack

- **Backend**: Rust (`rustc` 1.100+ / edition 2021), Tokio, Axum, `IronRDP 0.17` (`ironrdp-connector`, `ironrdp-tokio`, `ironrdp-session`, `ironrdp-cliprdr`, `ironrdp-displaycontrol`), `rustls`, OpenTelemetry (`opentelemetry` + `tracing-opentelemetry` + Prometheus `/metrics`), multi-database support (`PostgreSQL` RLS, `ClickHouse` HTTP OLAP, `DuckDB` analytical engine, `MySQL`, `Redis`).
- **Frontend**: React 19, TypeScript 5.8+, Vite 6, Tailwind CSS 3.4, Zod, Zustand, `OperquayTerminal` WASM, Vitest, Playwright + `@axe-core/playwright`.

## Commands

| Scope | Command |
| :--- | :--- |
| Rust format check | `cargo fmt --all -- --check` |
| Rust strict lint | `cargo clippy --workspace --all-targets -- -D warnings` |
| Rust tests | `cargo test --workspace` |
| Frontend typecheck | `pnpm --dir frontend run typecheck` |
| Frontend lint | `pnpm --dir frontend run lint` |
| Frontend unit tests | `pnpm --dir frontend run test` |
| Frontend build | `pnpm --dir frontend run build` |
| WASM build | `cargo build --release --target wasm32-unknown-unknown -p operquay-term-wasm` |

## Structure

- `crates/operquay-core`: Domain settings, `SecretString` (`ZeroizeOnDrop`), extensibility traits, SQL schema (`migrations/`).
- `crates/operquay-telemetry`: OpenTelemetry traces, structured JSON logs, Prometheus `/metrics`.
- `crates/operquay-guac`: Clean-room Guacamole 1.0–1.5 wire parser/serializer + `SyncTracker`.
- `crates/operquay-display`: 5-phase `64x64` display planner, `png` + `jpeg-encoder`, binary `OQR2` protocol packetizer.
- `crates/operquay-rdp`: Pure-Rust in-process `IronRDP 0.17` engine (`ClientConnector`, `ActiveStage`, `CliprdrBackend`, `DisplayControlClient`) + `rustls` TOFU/StrictCA TLS (`Resumption::disabled()`) + 25-LCID keymap + synthetic demo `RdpEngine`.
- `crates/operquay-vnc`: Cancellation-safe RFB 3.3–3.8 codec + DES `VNCAuth`/`VeNCrypt` + `Raw`/`CopyRect`/`RRE`/`Hextile`/`ZRLE`.
- `crates/operquay-ssm`: AWS SSM `AgentMessage` SHA-256 codec + WebSocket DataChannel + `HandshakeComplete` barrier + `smux` v1 port forwarding.
- `crates/operquay-db`: Object-oriented `DatabaseEngineDriver` trait registry (`PostgresDriver`, `ClickHouseDriver`, `DuckDbDriver`, `MySqlDriver`, `RedisDriver`) with read-only SQL guard and parameterized mutations.
- `crates/operquay-server`: Single-binary Axum control plane, REST/WS endpoints, multi-DB control-plane storage, embedded SPA (`rust-embed`).
- `frontend/`: React SPA, semantic Dark/Light design tokens (`frontend/src/styles/tokens.css`), `DesktopStage` (`OQR2`) + `GuacamoleClient`, `DatabasesWorkspace`, `KubernetesWorkspace`, `TerminalSession`, `TopologyRoute`, `FleetDashboard`.

## Boundaries

### Always
- Update checkboxes in `tasks.md` strictly after running verification gates.
- Keep `#![forbid(unsafe_code)]` on all Operquay workspace crates.
- Keep all UI colors in CSS variables inside `frontend/src/styles/tokens.css`.
- Redact secrets in logs, traces, URLs, and tests (`ZeroizeOnDrop`).

### Ask First
- Deploying to shared/live environments or modifying external cloud/DB infrastructure.
- Adding any C/C++ shared library dependency instead of pure Rust.

### Never
- Never add sidecar containers (`guacd`, `guac-lite`, `RDCleanPath` proxy) or push RDP credentials into browser JavaScript/WASM.
- Never commit secrets, `.env` files, or private keys.
- Never claim tests or benchmarks passed without running them after the final edit.

## Commit Attribution

AI commits MUST include:
Co-Authored-By: Antigravity <antigravity@deepmind.google>
