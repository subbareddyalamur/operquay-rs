# Operquay-Rust Project Rules, Security Architecture & Compliance Gates

Every contributor and AI agent working in `operquay-rust` MUST follow these engineering, security, and **SOC 2 Type II + ISO/IEC 27001:2022** compliance rules and pass all verification gates before marking any task complete.

---

## 1. Single-Binary & Pure-Rust Protocol Standards

1. **Zero Sidecar Containers & Zero C/FFI Protocol Proxies**:
   - Runtime execution MUST NOT shell out to external helper containers or binaries (`guacd`, `guac-lite`, `RDCleanPath`, `node`, `aws`, `session-manager-plugin`, `socat`, `ffmpeg`, `guacenc`, `agg`, `tsh`).
   - All core protocols (`operquay-rdp`, `operquay-vnc`, `operquay-ssm`, `operquay-display`, `operquay-guac`, `operquay-recording`, `operquay-term` / `operquay-term-wasm`, `operquay-db`, `operquay-k8s`) MUST run in-process across the 19 workspace crates declared in [Cargo.toml](Cargo.toml).
   - RDP MUST use server-side pure-Rust `ironrdp-*` crates pinned in [Cargo.toml](Cargo.toml) (`ironrdp-core 0.3`, `ironrdp-cliprdr 0.9`, `ironrdp-displaycontrol 0.10`, `ironrdp-dvc 0.10`, `ironrdp-svc 0.10`, `ironrdp-graphics 0.11`, `ironrdp-pdu 0.11`, `ironrdp-connector 0.12`, `ironrdp-tokio 0.12`, `ironrdp-session 0.13`). Browser WASM MUST NEVER receive plaintext target credentials.
2. **Zero `unsafe` Code**:
   - All workspace crates MUST declare `#![forbid(unsafe_code)]` (already enforced workspace-wide via `[workspace.lints.rust] unsafe_code = "forbid"`). `operquay-term-wasm` exposes `#[no_mangle]` WASM ABI entrypoints with zero `unsafe` blocks.
3. **Strict No-Mock Runtime Policy**:
   - Production runtime HTTP/WebSocket handlers MUST NOT expose mock SSH shells or mock RDP desktop sessions (`ws.rs`, `lib.rs`, `aws_routes.rs`). Desktop, SSH/SSM, database, and Kubernetes connections MUST target real hosts or fail closed with explicit errors. Mocks are permitted solely inside `#[cfg(test)]` unit/integration tests and Vitest specs.
4. **Canonical Domain Naming**:
   - Use **`RdpDesktopClient`** (`frontend/src/components/rdp/RdpDesktopClient.tsx` + `DesktopStage.tsx`) as the canonical desktop client name (never `GuacamoleClient`).
   - Use AWS EC2 **discovery/fetch** (`crates/operquay-aws/src/discovery.rs`, UI/API wording) — never call account/instance enumeration "scanning".

---

## 2. Object-Oriented & Scrutable Architecture Contracts

1. **Polymorphic Object-Oriented Seams**:
   - Desktop engines (`operquay-rdp`, `operquay-vnc`) implement `operquay_core::DesktopEngine` via `EngineRegistry` + `EngineFactory`.
   - Display encoders (`operquay-display`) consume `DisplaySink` frames agnostic of engine origin (`IronRDP`, RFB 3.3–3.8).
   - Database drivers (`operquay-db`) implement `DatabaseEngineDriver` (`PostgresDriver`, `ClickHouseDriver`, `DuckDbDriver`, `MySqlDriver`, `RedisDriver`) behind `DbExplorer`; HTTP routes MUST NOT branch per SQL engine dialect.
   - Control-plane persistence (`SettingsStore`, `AuditRepository`, `StorageBackend`, `TicketStore`) abstracts storage across PostgreSQL RLS, analytical backends, and bounded in-memory test doubles.
   - Transport adapters (`TcpStream`, `SsmVirtualStream`, duplex streams) expose `AsyncRead + AsyncWrite + Unpin + Send`.
2. **Cancellation-Safe Async Design**:
   - Never place multi-read async stream parsers inside competing `tokio::select!` branches without split read/write halves or internal partial-read state.
3. **Shared Backend/Frontend Validation**:
   - Backend (`operquay-core`) and Frontend (`zod` schemas) MUST enforce identical validation bounds: FPS `[10, 60]`, JPEG quality floor `[20, 95]`, RDP resize `[200, 8192]`, and even pixel width alignment (`width &= !1`).

---

## 3. Security, Cryptography & Compliance Standards (SOC 2 Type II & ISO/IEC 27001:2022)

Every existing and new feature MUST satisfy both **SOC 2 Type II** (Trust Services Criteria `CC6`, `CC7`, `CC8`, `CC9`, `A1`, `C1`, `PI1`) and **ISO/IEC 27001:2022** (`Annex A.5` Organizational, `Annex A.8` Technological Controls). Gaps marked *Required / Tracked in M9–M10* in [tasks.md](tasks.md) are release blockers before enterprise GTM/compliance certification.

### 3.1 Identity, Authentication & Session Security (`SOC 2 CC6.1, CC6.2 | ISO A.8.5`)

1. **SAML 2.0 Cryptographic Verification**:
   - SAML `Assertion` and `Response` processing (`crates/operquay-auth/src/sso.rs`) MUST verify XML-DSig `<ds:Signature>` against the tenant-configured IdP X.509 certificate after Exclusive XML Canonicalization (`XML Signature Wrapping` hardened: single ID match, schema-bound ancestor path), plus strict validation of `InResponseTo`, single-use `AssertionID` replay cache, `NotBefore`/`NotOnOrAfter` clock-skew bounds, `Audience`, and `Recipient` matching the tenant ACS URL. Unsigned or tampered assertions MUST be rejected.
2. **OIDC / OAuth 2.0 Cryptographic Verification**:
   - OIDC token exchange MUST enforce `PKCE S256` + opaque single-use `state` + `nonce`, and verify ID token JWT signatures against the IdP's JWKS keys (`alg` pinned — `none` and symmetric `HS*` confusion rejected), plus strict `iss`, `aud`, `exp`, `nbf`, and `nonce` validation. Decoding Base64 JWT payloads without signature validation MUST NOT happen in production.
3. **Multi-Factor Authentication (MFA)**:
   - Local accounts and break-glass administrator accounts MUST support and enforce phishing-resistant MFA (`WebAuthn / FIDO2` passkeys or RFC 6238 `TOTP` + single-use recovery codes) in compliance/enterprise mode, unless delegated to an SSO IdP asserting verified MFA AuthnContext (`AMR`/`ACR`).
4. **Password Hashing, Complexity & Rotation**:
   - Hash local passwords using **Argon2id** (preferred) or `bcrypt` with cost **`>= 12`**. Reject common/weak passwords, enforce minimum length `>= 12` chars (or passphrase policy), enforce forced rotation of bootstrap `initial_admin_password` on first login when `REQUIRE_AUTH=true`, and use constant-time verification including dummy hashes for unknown users.
5. **Brute-Force Protection & Session Lifecycle**:
   - Enforce per-IP and per-account rate limiting + exponential backoff / temporary lockout on `/api/auth/login` and `/api/auth/password`, emitting audit alerts on threshold breaches.
   - Set session cookies with `__Host-` prefix (on HTTPS) + **`HttpOnly; Secure; SameSite=Lax` (or `Strict`)**. In non-dev environments (`TLS` or `PUBLIC_URL=https://...`), omitting `Secure` MUST be forbidden.
   - Enforce **`Origin` / `Referer`** verification or anti-CSRF tokens on all cookie-authenticated mutating HTTP requests and WebSocket handshakes.
   - Enforce configurable **idle timeout** (`15–30 min` default) and **absolute session lifetime** (`8–12 hr` default).
   - User disablement, password reset, role downgrade, or SCIM `active: false` deprovisioning MUST revoke all active HTTP sessions, API tokens, and running SSM/RDP/VNC/K8s sessions immediately (`<= 5s`).

### 3.2 Authorization, Multi-Tenancy & Zero Standing Privileges (`SOC 2 CC6.1–CC6.3 | ISO A.5.15, A.5.18, A.8.2, A.8.3`)

1. **Default-Deny RBAC**:
   - Every protected route and WebSocket handler MUST authorize via explicit least-privilege permission checks with **explicit deny-overrides** (`allow` cannot override an applicable `deny`).
   - Protect against self-privilege escalation and last-admin lockout (`LastAdmin`, `SelfEscalation`).
2. **Fail-Closed Multi-Tenant Isolation (PostgreSQL RLS)**:
   - All tenant-scoped PostgreSQL tables MUST use `ENABLE ROW LEVEL SECURITY` AND `FORCE ROW LEVEL SECURITY`.
   - RLS predicates MUST require `app.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')` (fail closed with zero rows when unset — NEVER allow `current_setting('app.tenant_id', true) IS NULL OR ... = ''` to bypass isolation in application connections).
3. **Spoof-Proof Proxy & Tenant Headers**:
   - `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, and `X-Operquay-Tenant` MUST ONLY be trusted when the peer TCP socket IP matches an explicitly configured `TRUSTED_PROXIES` CIDR allowlist. Direct/untrusted connections MUST use the real peer socket IP and verified `Host` / URL slug.
4. **Just-In-Time (JIT) Access & Dual-Control Moderation**:
   - Production tiers MUST default to **Zero Standing Privileges (ZSP)**: high-risk targets (production DB mutations, `prod`-tagged EC2/K8s, break-glass roles, policy edits) require time-boxed JIT approval (`ttl`, reason, optional change-ticket reference) and support real-time dual-control moderation / kill-switch.
   - Every break-glass login MUST emit a high-severity audit record and trigger out-of-band webhook/SIEM alerting.
5. **AWS & Cloud Role Isolation**:
   - AWS `user` mode MUST NEVER fall back to ambient host EC2 IMDS / container task role credentials or cross-user leases (`user:` lookups MUST match both `tenant_id` and caller `user_id`).
   - AWS SSO portal API calls MUST honor concurrency pacing (`portal_sem`) and `429`/`5xx` `Retry-After` exponential backoff, and upfront `/api/aws/rdp/start` MUST validate role leases (`401`) before issuing WebSocket tickets.

### 3.3 Cryptography, Secrets & Transport Hardening (`SOC 2 CC6.6, CC6.7, C1.1 | ISO A.8.24`)

1. **Universal TLS 1.2+ Encryption in Transit**:
   - Enforce TLS 1.2+/1.3 via `rustls` across ALL inbound and outbound control and data planes: HTTPS/WSS server, PostgreSQL (`rustls`), ClickHouse HTTPS, **MySQL (`CLIENT_SSL` TLS)**, **Redis (`tokio-rustls` Rediss)**, K8s API (`StrictCa`), OIDC/SSO, and target RDP/VNC.
   - Credential-bearing database/protocol drivers (`MySqlDriver`, `RedisDriver`, `PostgresDriver`, `Rdp`, `Vnc`) MUST require TLS by default and MUST NOT silently transmit passwords over unencrypted TCP unless an explicit, tenant-audited `insecure_allow_plaintext_dev` override is enabled outside Compliance Mode.
   - Local development HTTPS (`5444`) MUST use CA-trusted certificates (`mkcert` under gitignored `deploy/certs/`) or short-lived (`<= 365 days`) auto-generated fallback certs — NEVER multi-century certs that modern browsers reject cleanly.
2. **Legacy Cipher Ban in Compliance Mode**:
   - Standard RDP RC4 security (`crates/operquay-rdp/src/standard_sec.rs`), raw VNCAuth DES (`crates/operquay-vnc/src/auth.rs`), TLS < 1.2, and SHA-1/MD5 digests MUST be **disabled by default** when Compliance/FIPS Mode is active, unless an explicit per-target exception inside an encrypted SSM tunnel is granted and recorded in `audit_events`.
3. **FIPS & Authenticated Encryption Hygiene**:
   - AES-256-GCM sealing (`seal_aead`) MUST use a full **96-bit cryptographically random nonce** generated directly from the OS CSPRNG (`getrandom` / `rand_core::OsRng`) — NEVER truncated UUIDv4 bytes with fixed version/variant bits — or unique deterministic key+counter nonces bound with AAD (`tenant_id|table|record_id|key_version`).
   - Encryption keys MUST support explicit `key_version` metadata and KMS/HSM envelope wrapping (`AWS KMS` / `Vault`) for key rotation without breaking historical rows.
   - Maintain a FIPS 140-3 build profile option (`aws-lc-rs` FIPS mode).
4. **In-Memory Credential Hygiene**:
   - Wrap all passwords, NTLM/CredSSP secrets, private keys, STS tokens, and session secrets in `SecretString` / `ZeroizeOnDrop` with `[REDACTED]` `Debug`/`Display` output.
   - Enforce single-use `60s` atomic tickets (`TicketStore`) for WebSocket session launches; NEVER put passwords, tokens, or PII in URL query strings, HTTP GET requests, HTML attributes, `localStorage`, or OpenTelemetry attributes.
   - Enforce `.gitleaks.toml` across all commits; NEVER commit `.env`, `.pem`, `.key`, or real AWS/corporate tokens.

### 3.4 HTTP Perimeter & Application Hardening (`SOC 2 CC6.6 | ISO A.8.20, A.8.26, A.8.28`)

1. **Mandatory HTTP Security Headers** (`crates/operquay-server/src/lib.rs`):
   - Emit on every response: `Strict-Transport-Security: max-age=31536000; includeSubDomains` (on HTTPS), `Content-Security-Policy` (no unsafe inline scripts; explicit `connect-src 'self' wss:`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (or `SAMEORIGIN`), `Referrer-Policy: same-origin`, `Permissions-Policy`, and `Cache-Control: no-store` on auth/credential/API responses.
2. **CORS, Request Limits & Input Sanitization**:
   - Never configure wildcard CORS (`*`) alongside credentialed cookies.
   - Enforce route-scoped body size limits, multipart upload caps, regex/glob bounds, and strict `fs::canonicalize` containment for recording/file-transfer paths.
   - Guarded DB read-only queries (`/api/db/query`) MUST strip comments (`--`, `/* */`) and block all DML/DDL/admin verbs while executing inside engine-native read-only transactions (`READ ONLY`, `readonly=1`), and mutations MUST validate identifiers strictly (`^[A-Za-z_][A-Za-z0-9_]*$`).
   - Uploaded K8s kubeconfigs MUST restrict exec credential plugins to an explicit binary allowlist and enforce TLS verification by default.

### 3.5 Tamper-Evident Audit Logging & Encrypted Session Recording (`SOC 2 CC7.1–CC7.3 | ISO A.5.33, A.8.15, A.8.16`)

1. **Immutable Cryptographic Audit Trail (`audit_events`)**:
   - Every security-relevant event (auth success/failure, lockouts, break-glass, RBAC/policy edits, JIT approvals, session start/end/kill, DB query/mutate, K8s exec, file upload/download, config changes, admin exports) MUST record: UTC timestamp, W3C `trace_id`, `tenant_id`, `user_id`/`email`, `role`, client IP, user-agent, target identifier, `outcome`, optional `ticket_ref`, and **cryptographic hash-chain** (`prev_hash`, `entry_hash = SHA-256/HMAC(prev_hash || canonical_payload)`).
   - PostgreSQL runtime DB roles MUST hold `REVOKE UPDATE, DELETE ON audit_events` so logs are append-only inside the transactional database, paired with real-time SIEM streaming (OTLP / Splunk HEC / Datadog / RFC 5424 Syslog) and WORM S3 archival.
2. **Universal Fail-Closed Session Recording**:
   - When `fail_closed_recording` or tenant recording policy applies, ALL interactive access channels (**RDP, VNC, SSM/SSH Shell, K8s `exec`/`attach`, Port-Forward / DB sessions**) MUST open recording synchronously (`O_CREAT | O_EXCL | 0600`) BEFORE completing target auth / opening streams, and MUST abort immediately on write failure (`OperquayError::RecordingRequired`).
   - Recordings MUST support AES-256-GCM/KMS encryption at rest, SHA-256 manifest checksums, configurable retention & legal-hold policies, and WORM S3 Object Lock (`COMPLIANCE` / `GOVERNANCE` mode) export.
3. **RDP Security Controls**:
   - Set `CertificatePolicy::SsmLoopbackIgnore` ONLY inside already-authenticated encrypted SSM tunnels; direct connections default to `StrictCa` or `TofuPinned` SHA-256 host pinning.
   - Force CredSSP TLS `rustls::client::Resumption::disabled()` with `TokioFramed::new_with_leftover`.
   - Disable RDP drive redirection (`enable_drive_redirection = false`) by default.

### 3.6 Secure SDLC, Supply Chain & High Availability (`SOC 2 CC7.1, CC8.1, A1.2 | ISO A.8.8, A.8.13, A.8.25, A.8.30, A.8.32`)

1. **Automated Dependency & Supply-Chain Integrity**:
   - CI MUST run `cargo audit`, `cargo deny` (license + advisory policy), `pnpm audit`, and `gitleaks`.
   - Production container releases MUST run in `distroless:nonroot`, generate CycloneDX/SPDX SBOMs, and sign images + binaries via `cosign`.
   - Enforce vulnerability remediation SLAs: **Critical <= 24h**, **High <= 7d**, **Medium <= 30d**, **Low <= 90d**.
2. **State Persistence, HA & Graceful Drain**:
   - Auth state, RBAC, tickets, AWS SSO provider configs, active role leases, recording metadata, and K8s cluster configs MUST persist in PostgreSQL (no critical state stranded solely in process-local `HashMap` across container restarts).
   - On `SIGTERM`, drain active sessions cleanly, flush/finalize `.guac`/`.cast` recordings and hash-chained `audit_events`, and send clean disconnect PDUs.
   - Support automated encrypted backups, tested restore/DR runbooks, and tenant crypto-shredding / GDPR-compliant offboarding purge.

---

## 4. Network Latency, Throughput & Bounded Resource Rules

1. **Zero Unbounded Channels in Data Planes**:
   - Every session `mpsc` queue MUST have a finite bound (`<= 2 MiB` or `<= 64..256` frames). Intermediate visual frames drop/coalesce rather than growing unbounded memory across high RTT. *(Note: existing `unbounded_channel` in `aws_routes.rs` SSM shell loop is tracked for replacement in M9.)*
2. **Input Priority Over Pixels & Ordered Canvas Drawing**:
   - Keyboard, pointer, and resize events MUST dispatch on a prioritized `tokio::select!` `biased` branch ahead of bitmap flushes.
   - Browser `DesktopStage.tsx` MUST serialize async bitmap/copy/fill canvas mutations through a single ordered `paintQueue` and surface WebSocket handshake/close failures visibly.
3. **Hardware Pointer Separation & Dimension Clamping**:
   - Configure IronRDP with `enable_server_pointer: true, pointer_software_rendering: false`.
   - Clamp dynamic resize dimensions to `[200, 8192]` with even width (`width &= !1`) for `[MS-RDPEDISP]`.
4. **Cloud Control-Plane Pacing**:
   - AWS SSO portal queries MUST bound concurrency (`<= 2` in-flight) and back off cleanly on `429` / `5xx` with retry affordances in the UI.

---

## 5. Product Design System, UX & Accessibility Rules

1. **Theme Polarity & Token Discipline**:
   - Maintain Dark and Light themes with Deep Teal accent (`#3fb8af`) in CSS custom properties (`frontend/src/styles/tokens.css`).
   - Avoid hardcoded hex colors inside `.tsx` components outside `<canvas>` surfaces and brand SVG icons.
   - Never double-prefix WebSocket URLs (`ws://` vs relative paths).
2. **Typography & WCAG 2.2 AA Accessibility**:
   - Use `'Inter'` for UI copy and `'JetBrains Mono'` for monospace telemetry, SQL, and trace IDs.
   - Maintain visible `:focus-visible` outlines, full keyboard navigation, ARIA live/alert announcements for connection/session errors, and `@media (prefers-reduced-motion: reduce)` support.

---

## 6. OpenTelemetry & Diagnostics Rules

1. **Mandatory Span & Log Correlation**:
   - Every HTTP request, WebSocket session, database operation, AWS SSM tunnel, Kubernetes request, TLS handshake failure, and AI call MUST emit structured `tracing` JSON events carrying active W3C `trace_id` / `span_id`.
2. **Low-Cardinality Metrics**:
   - Expose Prometheus metrics under `operquay_<subsystem>_<metric>` + optional OTLP export.
   - Keep Prometheus labels strictly low-cardinality (`protocol`, `engine`, `preset`, `codec`, `status`, `reason`). NEVER place `user_id`, `email`, `ip`, `session_id`, `sql`, `hostname`, or `tenant_id` in Prometheus metric labels.

---

## 7. Per-Feature SOC 2 & ISO/IEC 27001:2022 Compliance Matrix

| Feature | Mandatory Security & Safety Invariants | SOC 2 Criteria | ISO 27001:2022 Annex A | Verification Evidence Required |
| :--- | :--- | :--- | :--- | :--- |
| **Local Auth, OIDC & SAML SSO** | SAML XML-DSig + X.509 verify; OIDC JWKS sig + `iss`/`aud`/`nonce` verify; MFA on admins/local; `bcrypt >= 12`/Argon2id; brute-force lockout; `__Host-` `HttpOnly; Secure; SameSite` cookies + CSRF checks; immediate session revocation. | CC6.1, CC6.2, CC6.6 | A.5.16, A.5.17, A.8.5, A.8.24 | Signature-tamper negative tests; lockout test; cookie/CSRF E2E; `audit_events` auth export. |
| **RBAC, SCIM v2 & Multi-Tenancy** | Default-deny + deny-overrides; self-escalation & last-admin guards; fail-closed PG `FORCE ROW LEVEL SECURITY`; SCIM bearer SHA-256 lookup + instant session kill; `TRUSTED_PROXIES` IP/tenant check. | CC6.1–CC6.3, C1.1 | A.5.15, A.5.18, A.8.2, A.8.3, A.8.4 | Cross-tenant RLS isolation SQL test; SCIM deprovision revocation test; quarterly access review export. |
| **JIT Access & Break-Glass** | Zero standing privileges on prod roles; time-boxed approval + ticket ID + peer reviewer != requester; auto-expiry fence `<= 5s`; break-glass out-of-band SIEM alert. | CC6.2, CC6.3, CC8.1 | A.5.15, A.8.2, A.8.15 | JIT approval/expiry integration test; SIEM webhook alert proof; break-glass review log. |
| **AWS SSO & EC2 Discovery/Fetch** | Strict user-scoped lease lookup (`tenant_id + user_id`); zero IMDS fallback in `user` mode; AEAD 96-bit CSPRNG encrypted storage; portal pacing & 429 backoff; persistent DB lease fences. | CC6.1, CC6.6, CC6.7 | A.8.2, A.8.12, A.8.24 | Lease-isolation negative test; live SSO 429 retry test; zero static AWS env keys. |
| **Interactive SSH / SSM Shell** | Real targets only (zero mocks); async non-blocking connect; upfront user lease verification; bounded `mpsc` channels; fail-closed `.cast` recording before shell I/O; `<= 5s` PG fence kill; command DLP/guardrail hooks. | CC6.1, CC6.6, CC7.1, CC7.2 | A.8.2, A.8.15, A.8.16, A.8.20 | Live SSM test (`i-*`); fail-closed EACCES `.cast` abort test; active session fence-kill `< 5s` test. |
| **RDP (`IronRDP`) & VNC Desktop** | Server-side credentials only (`ZeroizeOnDrop`); `60s` single-use ticket; `401` upfront lease check; TLS + `Resumption::disabled()` (`StrictCa`/`TofuPinned`, `SsmLoopbackIgnore` only inside SSM); drive redirection off; Compliance mode blocks raw RC4/DES; fail-closed `.guac` recording; serialized canvas `paintQueue`. | CC6.1, CC6.6, CC6.7, CC7.2 | A.8.5, A.8.12, A.8.15, A.8.20, A.8.24 | Loopback & live Windows IronRDP test; missing-role `401` check; TOFU mismatch abort; fail-closed `.guac` abort test. |
| **Port Forwarding (`operquay-forward`) & Reverse Agent** | Zero unauthenticated localhost listeners exposed across tenants; outbound mTLS + client cert auth for reverse agent; per-tunnel lease check + byte/duration audit + optional L7 protocol inspection. | CC6.1, CC6.6, CC7.2 | A.8.20, A.8.21, A.8.24 | 5-byte mux framing test; unauthorized stream rejection; mTLS tunnel termination test. |
| **Kubernetes Workspace & Exec/Attach** | Exec-plugin strict allowlist; kubeconfig encrypted in PG; real TLS (`insecure_skip_tls_verify=false` default); RBAC per-cluster/namespace; fail-closed `record_exec`/`record_attach` `.cast` recording + command audit; no simulated Teleport sessions. | CC6.1, CC6.6, CC7.2, CC8.1 | A.8.2, A.8.15, A.8.16, A.8.28 | Unsafe `exec: /bin/sh` kubeconfig rejection test; live/TLS K8s WS exec recording test. |
| **Multi-DB Workspace (`PG`/`CH`/`DuckDB`/`MySQL`/`Redis`)** | TLS 1.2+ mandatory across all 5 drivers (no plaintext TCP password send); comment-stripped SQL read-only guard + native DB read-only TX; strict identifier regex on mutations; query row caps + audit of every query/mutation + PII/DLP result masking. | CC6.1, CC6.6, C1.1, PI1.4 | A.8.3, A.8.11, A.8.12, A.8.15, A.8.24 | Write-bypass SQL comment injection tests (`/* */ INSERT`); TLS handshake check per driver; mutation audit test. |
| **File Transfer (SSM/S3) & EC2 Clone** | Upload/download gating policy; byte-size cap (`32 MiB`); S3 TLS + SSE-KMS; POSIX path traversal canonicalization; `audit_events` SHA-256 digest of transferred artifact; clone intent journal + SG/KMS inheritance parity. | CC6.1, CC6.6, CC7.2, CC8.1 | A.8.12, A.8.15, A.8.19, A.8.32 | Path traversal rejection test; policy `disable_upload`/`download` block test; S3 SSE-KMS header check. |
| **Session Recording, MP4 Export & Audit Log** | Fail-closed `.guac`/`.cast`; AES-256-GCM/KMS encryption at rest; SHA-256 manifest + WORM S3 Object Lock archival; append-only hash-chained `audit_events` (`REVOKE UPDATE, DELETE`); SIEM OTLP/Splunk/Syslog streaming; bounded CPU transcoder. | CC7.1–CC7.3, A1.2, C1.1 | A.5.33, A.8.13, A.8.15, A.8.16, A.8.24 | Tamper-chain verifier script; fail-closed `ENOSPC`/`EACCES` test; encrypted `.mp4` / WORM retention test. |
| **AI Assistant, Command Suggest & MCP Proxy** | PII/secret redaction pre-prompt; dangerous-command safety block (`rm -rf`, SQL drop, IAM wildcard); AES-GCM command suggestion isolation; future MCP agent identities bound to human sponsors + short-lived tokens + per-tool JIT/RBAC + full prompt/tool audit log. | CC6.1, CC7.2, C1.1, PI1.4 | A.5.18, A.8.2, A.8.12, A.8.15, A.8.16 | Secret/PII redaction unit tests; blocked destructive command tests; AI tool-call audit log check. |

---

## 8. Verification, Security Audit & Task Discipline

1. **Backend Rust Gates** (MUST pass after every Rust edit):
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
2. **Frontend Gates** (MUST pass after every frontend edit):
   ```bash
   pnpm --dir frontend run typecheck
   pnpm --dir frontend run lint
   pnpm --dir frontend run test
   pnpm --dir frontend run build
   ```
3. **Security, Supply-Chain & Live TLS Gates** (MUST pass before production releases):
   - Secret scan (`gitleaks detect`), Rust & Node dependency advisory scans (`cargo audit`, `cargo deny check`, `pnpm audit`).
   - Strict TLS probe without `-k` (`curl -fsS https://localhost:5444/health`) and browser E2E with `ignore_https_errors=False`.
4. **Honest Reporting**:
   - Track deliverables in [tasks.md](tasks.md) and mark `[x]` ONLY after running verification commands after the final edit and observing zero failures. Never fabricate, extrapolate, or report simulated results as live validation.
