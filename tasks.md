# Operquay-Rust Master Delivery Plan & Task Tracker

Governed by [RULES.md](RULES.md), [AGENTS.md](AGENTS.md), Architecture Decision Records [docs/ADR/0000–0010](docs/ADR/), and Product Strategy in [ideas.md](ideas.md).

> **Strict Verification Rule**: A checkbox (`[x]`) may ONLY be checked after implementation, strict formatting/linting, automated tests, and security/compliance checks pass against real code after the final edit. Never mark future hardening items complete prematurely.

---

## Milestone M1: Governance, ADRs & Object-Oriented Standards

- [x] **M1.1** — Establish clean roadmap tracking single-binary Rust parity & enterprise security architecture.
- [x] **M1.2** — Document pure-Rust architecture rules, `#![forbid(unsafe_code)]`, trait/encapsulation seams, multi-database drivers, and mandatory OpenTelemetry standards in [RULES.md](RULES.md), [AGENTS.md](AGENTS.md), and [CLAUDE.md](CLAUDE.md).
- [x] **M1.3** — Author initial ADRs `0000`–`0009` documenting wire reverse engineering, protocol engines, SSM transport, fail-closed recording, and multi-DB architecture.

---

## Milestone M2: In-Process `IronRDP` Engine (`crates/operquay-rdp`, Zero Sidecars)

- [x] **M2.1** — Integrate pure-Rust server-side `ironrdp-*` crates pinned in [Cargo.toml](Cargo.toml) (`ironrdp-core 0.3`, `ironrdp-cliprdr 0.9`, `ironrdp-displaycontrol 0.10`, `ironrdp-dvc 0.10`, `ironrdp-svc 0.10`, `ironrdp-graphics 0.11`, `ironrdp-pdu 0.11`, `ironrdp-connector 0.12`, `ironrdp-tokio 0.12`, `ironrdp-session 0.13`) inside `crates/operquay-rdp`.
- [x] **M2.2** — Harden `crates/operquay-rdp/src/tls.rs`: set `Resumption::disabled()` on `rustls::ClientConfig` for `[MS-CSSP]` CredSSP binding while preserving `StrictCa`, `TofuPinned` SHA-256 host pinning, and `SsmLoopbackIgnore`.
- [x] **M2.3** — Implement `OperquayCliprdrBackend` (`crates/operquay-rdp/src/clipboard.rs`) bridging `[MS-RDPECLIP]` (`CF_UNICODETEXT` UTF-16LE $\leftrightarrow$ UTF-8).
- [x] **M2.4** — Build `IronRdpSessionDriver` (`crates/operquay-rdp/src/live_client.rs`) + `standard_sec.rs` fallback handling CredSSP/NLA (`HYBRID` & `HYBRID_EX`), `DeactivateAll`, dirty-rect extraction to `DisplaySink`, hardware pointer separation, `[MS-RDPEDISP]` resize (`[200, 8192]`, even width), and 25-LCID keyboard + Unicode fallback.
- [x] **M2.5** — Add health endpoints and loopback + WebSocket `OQR2` integration tests validating `IronRDP` frame delivery.

---

## Milestone M3: Cancellation-Safe VNC Engine & Production AWS SSM Transport

- [x] **M3.1** — Split `AsyncRead`/`AsyncWrite` (`tokio::io::split`) across dedicated reader/writer tasks in `crates/operquay-vnc/src/live_client.rs`.
- [x] **M3.2** — Implement core RFB `3.3..=3.8` codecs in `crates/operquay-vnc/src/rfb.rs` (`Raw`, `CopyRect`, `RRE`, `Hextile`, stateful zlib `ZRLE`, `Cursor`, `DesktopSize`, `VNCAuth`, `VeNCrypt`).
- [x] **M3.3** — Implement in-process AWS SSM DataChannel (`crates/operquay-ssm/src/live.rs`) with `HandshakeComplete` (`PayloadType = 7`) barrier and `smux` v1 framing for `amazon-ssm-agent >= 3.0.196.0`.
- [x] **M3.4** — Wire `aws_profile` & `aws_region` into `TicketLaunchPayload` (`stores.rs`, `platform_routes.rs`, `ws.rs`) and strict `user:` / profile credential resolution.

---

## Milestone M4: Object-Oriented Multi-Database Architecture & Storage Seams

- [x] **M4.1** — Refactor `crates/operquay-db` around `DatabaseEngineDriver` (`PostgresDriver`, `ClickHouseDriver`, `DuckDbDriver` embedded/HTTP, `MySqlDriver`, `RedisDriver`) behind `DbExplorer`.
- [x] **M4.2** — Implement read-only SQL comment-stripping guards (`blocked_by_guard`), parameterized/identifier-validated mutations, and UI contracts in `operquay-db` and `platform_routes.rs`.
- [x] **M4.3** — Implement multi-backend `StorageBackend` / `AuditRepository` / `SettingsStore` factory in `crates/operquay-server/src/stores.rs`.

---

## Milestone M5: OpenTelemetry & Low-Cardinality Diagnostics

- [x] **M5.1** — Add domain counters & latency histograms in `crates/operquay-telemetry/src/lib.rs` (`operquay_db_*`, `operquay_ssm_tunnels_total`, `operquay_auth_events_total`, `operquay_k8s_requests_total`, `operquay_ai_requests_total`, desktop frame metrics).
- [x] **M5.2** — Instrument HTTP/WS middleware, DB explorer, auth, AWS, and desktop sessions with W3C `trace_id`/`span_id` JSON logging and Prometheus/OTLP export.

---

## Milestone M6: Frontend Parity, Component Refactoring & Production Build

- [x] **M6.1** — Rename `GuacamoleClient` to `RdpDesktopClient` (`frontend/src/components/rdp/RdpDesktopClient.tsx` + `DesktopStage.tsx`) and fix WebSocket URL handling.
- [x] **M6.2** — Support all 5 engines (`postgres`, `clickhouse`, `duckdb`, `mysql`, `redis`) in `DatabaseTree.tsx` & `DatabasesWorkspace.tsx`.
- [x] **M6.3** — Compile `operquay-term-wasm` (`wasm32-unknown-unknown`) into the embedded React 19 SPA (`frontend/`).

---

## Milestone M7: Core Build & Test Verification Gates

- [x] **M7.1** — Verify Rust workspace passes `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- [x] **M7.2** — Verify Frontend passes `typecheck`, `lint`, `test` (`76` files / `312` tests), and `build`, plus container image compilation (`deploy-operquay-1`).

---

## Milestone M8: Live AWS Verification, Real-Only Sessions, Trusted Local TLS & Compliance Governance

- [x] **M8.1** — Eliminate mock SSH & mock RDP session fallbacks (`ws.rs:356`, `lib.rs:573`, `lib.rs:1654`), rename AWS instance "scan" to **discovery/fetch**, and remove legacy Guacamole UI wrapper naming in favor of `RdpDesktopClient`.
- [x] **M8.2** — Harden local HTTPS TLS on `:5444` (`mkcert` CA-trusted certs mounted in `deploy/docker-compose.yml`, gitignored in `.gitignore`, `rcgen` 365-day fallback + `tracing::warn!` handshake error logging in `main.rs`) and verify strict-TLS `curl` (`200`) + Brave (`ignore_https_errors=False`) without `-k`.
- [x] **M8.3** — Fix AWS SSO multi-account role fetching (`portal_sem = 2` concurrency limit + 5-attempt `429`/`5xx` `Retry-After` backoff in `crates/operquay-aws/src/sso.rs`, retryable error UI in `CloudConnections.tsx`, account name role labels).
- [x] **M8.4** — Fix async non-blocking SSH connect in `aws_routes.rs` (emit `session_started` only after live SSM connect succeeds, apply initial `cols`/`rows`, scope `user:` role lookups by `tenant_id + user_id`, surface WS handshake/close errors in `ws.ts`/`Xterm.tsx`) and add upfront `401` `user:` lease validation in `legacy_start_rdp` + serialized canvas `paintQueue` in `DesktopStage.tsx`.
- [x] **M8.5** — Update ADRs `0000`–`0009`, author [ADR-0010](docs/ADR/0010-soc2-iso27001-security-and-zero-standing-privileges.md), codify SOC 2 Type II & ISO/IEC 27001:2022 controls in [RULES.md](RULES.md), author GTM strategy in [ideas.md](ideas.md), and align [README.md](README.md) & [tasks.md](tasks.md).

---

## Milestone M9: P0 SOC 2 Type II & ISO/IEC 27001:2022 Security Hardening *(Required Before External Audit / GTM)*

- [x] **M9.1** — Implement pure-Rust **SAML 2.0 XML-DSig verification** (`<ds:Signature>`, Exclusive XML c14n, IdP X.509 pinning, anti-XSW assertion validation, `NotBefore`/`NotOnOrAfter`, `Audience`, `Recipient`) in `crates/operquay-auth/src/sso.rs` with tamper negative tests.
- [x] **M9.2** — Implement **OIDC JWKS signature & claims validation** (`iss`, `aud`, `exp`, `nbf`, `nonce`, reject `alg: none` & HS confusion) replacing unverified Base64 JWT decode in `crates/operquay-auth/src/sso.rs`.
- [x] **M9.3** — Fix **fail-closed PostgreSQL RLS** (`migrations/0002_full_platform_schema.sql`): migrate to `FORCE ROW LEVEL SECURITY` with `tenant_id = NULLIF(current_setting('app.tenant_id', true), '')` under a non-`BYPASSRLS` DB role and add cross-tenant negative SQL tests.
- [x] **M9.4** — Harden HTTP session & perimeter edge (`auth_routes.rs`, `crypto.rs`, `lib.rs`):
  - Add `Secure` & `__Host-` cookie flags on HTTPS, plus explicit `Origin`/anti-CSRF verification on mutating routes & WebSockets.
  - Enforce `TRUSTED_PROXIES` CIDR allowlist before trusting `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, or `X-Operquay-Tenant`.
  - Add `Strict-Transport-Security`, strict `Content-Security-Policy`, `Permissions-Policy`, `Cache-Control: no-store`, and strict non-wildcard CORS.
- [x] **M9.5** — Harden local identity controls (`crates/operquay-auth`): raise default hash strength (`Argon2id` or `bcrypt >= 12`), enforce password complexity + forced bootstrap admin password rotation, add per-IP/account login rate-limiting & lockout, idle + absolute session timeouts, instant global session/token revocation on disable/SCIM `active: false`, and native **WebAuthn/FIDO2 Passkeys + TOTP MFA**.
- [x] **M9.6** — Upgrade AEAD & KMS hygiene (`crates/operquay-auth/src/crypto.rs`): replace UUIDv4-sliced GCM nonces with full 96-bit OS CSPRNG nonces (`OsRng`/`getrandom`), add `key_version` + AWS KMS/Vault envelope wrapping, and ship optional `aws-lc-rs` FIPS 140-3 build profile.
- [x] **M9.7** — Enforce **TLS 1.2+ by default in `MySqlDriver` (`CLIENT_SSL`) and `RedisDriver` (`tokio-rustls`)** (`crates/operquay-db`), rejecting plaintext DB password transmission when Compliance Mode is enabled.
- [x] **M9.8** — Gate legacy protocol crypto (`OPERQUAY_COMPLIANCE_MODE`): block `standard_sec.rs` RC4 RDP and non-TLS raw VNCAuth DES unless explicitly allowlisted per-host inside an encrypted SSM tunnel and audited.
- [x] **M9.9** — Harden SSM shell runtime (`crates/operquay-server/src/aws_routes.rs`): replace `mpsc::unbounded_channel` with bounded queues (`RULES.md` §4.1), attach fail-closed `.cast` `RecordingTee` (`EACCES`/`ENOSPC` aborts session), and enforce live `<= 5s` shared `CancellationToken` PG lease fence termination across active SSH/SSM/RDP/VNC/K8s streams.

---

## Milestone M10: Immutable Audit, Encrypted WORM Evidence, Persistence & Protocol Depth

- [x] **M10.1** — Make `audit_events` cryptographically tamper-evident (`seq`, `prev_hash`, `entry_hash`, `REVOKE UPDATE, DELETE`) with `/api/v1/audit/verify` and real-time **SIEM streaming** (OTLP / Splunk HEC / Datadog / RFC 5424 Syslog).
- [x] **M10.2** — Encrypt session recordings (`.guac`/`.cast`/`.mp4`) at rest with AES-256-GCM/KMS, enforce `fs::canonicalize` containment, add retention/legal-hold purge jobs + WORM **S3 Object Lock** archival, and implement inter-frame compressed MP4/WebM export replacing bulky `I_PCM`-only output.
- [x] **M10.3** — Persist AWS SSO provider sessions, token metadata, role leases, discovery inventory, and clone operations in PostgreSQL RLS (`operquay-aws` + `migrations/`), eliminating loss on container restart and enabling active-active multi-replica HA.
- [x] **M10.4** — Complete protocol depth: real Kubernetes SPDY/WebSocket `exec`/`attach` with fail-closed `.cast` recording, real Teleport Auth/Proxy mTLS + gRPC integration (removing in-memory scaffold in `crates/operquay-k8s/src/lib.rs`), native DuckDB file/remote driver, and Tier-2 VNC (`Tight`, `ExtendedDesktopSize`, `Apple ARD`).
- [x] **M10.5** — Automate supply-chain security gates in CI: `gitleaks`, `cargo audit`, `cargo deny check`, `pnpm audit`, CycloneDX/SPDX SBOM + `cosign` container signing, graceful `SIGTERM` drain tests, and verified PostgreSQL backup/restore + tenant crypto-shredding drills.

---

## Milestone M11: Zero Standing Privileges (ZSP), Dual-Control Moderation & Auditor Portal

- [x] **M11.1** — Build JIT Access Request & Four-Eyes Approval engine (`POST /api/access-requests`) with Slack, Microsoft Teams, PagerDuty, and Jira/ServiceNow interactive webhooks, change-ticket binding, and auto-expiring role leases.
- [x] **M11.2** — Ship real-time **Dual-Control Session Moderation & Live Shadowing** (`observer` / `moderator` force-freeze & kill) plus automated sanitized AI session risk bookmarks via `operquay-llm`.
- [x] **M11.3** — Implement inline **DB & Shell DLP Masking / Command Firewall** (`operquay-db`, `operquay-ssm`, `operquay-k8s`): PII redaction in SQL query rows and policy pause/block rules on destructive commands.
- [x] **M11.4** — Build **Continuous Compliance & Auditor Evidence Portal**: automated quarterly access review campaigns (`SOC 2 CC6.3`), break-glass out-of-band alerting, and one-click signed SOC 2 Type II / ISO 27001 evidence bundle export.

---

## Milestone M12: GTM Market Expansion — Multi-Cloud, Hybrid Agent, Access Graph & AI/MCP Proxy

- [x] **M12.1** — Ship **AI Agent & Model Context Protocol (MCP) Governance Proxy**: per-agent short-lived cryptographic tokens bound to human sponsors, per-tool RBAC/JIT approval, argument/response DLP redaction, and immutable prompt/tool audit logging (`ISO 42001`).
- [x] **M12.2** — Build **`operquay-agent`** (~5–8 MB static outbound-mTLS reverse-tunnel Rust daemon) enabling zero-inbound access to on-prem Linux/Windows AD hosts, bare-metal, and private Kubernetes clusters.
- [x] **M12.3** — Implement first-class **Azure** (Entra ID PIM, Azure Bastion/VM, AKS) and **GCP** (IAM, OS Login/IAP, GKE) connectors replacing UI placeholders.
- [x] **M12.4** — Extend `operquay-aws::topology` (`petgraph`) into a **Unified Identity & Resource Blast-Radius Access Graph** detecting shadow admins, cross-account trust loops, and unused permissions.
- [x] **M12.5** — Ship developer **`operquay` CLI** (`login`/`ssh`/`db`/`kube`/`forward`/`mcp`), **Device Trust** MDM posture checks (CrowdStrike/Jamf/Intune/osquery), **Terraform/OpenTofu Provider**, and `WebCodecs` `AVC420` hardware-decoded RDP (`0x09 H264AccessUnit`).
