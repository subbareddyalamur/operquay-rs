# Operquay Product Strategy, Competitive Audit & Go-To-Market Roadmap (`ideas.md`)

This document synthesizes:
1. **2025–2026 Market & Competitive Intelligence** across **Teleport**, **StrongDM**, **HashiCorp Boundary**, and **Hoop.dev**.
2. An **Honest Security & Product Audit** of `operquay-rust` as built today.
3. **10 Differentiating Feature Pillars** designed from the ground up for **SOC 2 Type II** & **ISO/IEC 27001:2022** (plus **ISO/IEC 42001** AI governance).
4. **Go-To-Market Wedge, Packaging & Phased Execution Plan**.

---

## 1. Market Trends & Competitive Landscape (2025–2026)

Privileged Access Management (PAM) and bastion gateways have undergone a structural shift away from static jump hosts and password vaults toward **Zero Standing Privileges (ZSP)**, **Identity-Aware Proxies**, and **Human + AI Agent Governance**:

- **Zero Standing Privileges (ZSP) Is Table Stakes**: Standing SSH keys, long-lived DB credentials, and permanent cloud admin bindings are direct audit findings under **SOC 2 CC6.1–CC6.3** and **ISO 27001:2022 Annex A.8.2**. Buyers expect time-boxed Just-In-Time (JIT) access embedded into Slack/Teams/PagerDuty/Jira with automatic revocation.
- **Non-Human Identities (NHIs) & AI Agent / MCP Governance**: Non-human identities (CI/CD bots, service accounts, coding assistants, autonomous MCP agents) vastly outnumber human engineers (`45:1` to `100:1`). Teleport's 2025–2026 *Agentic Identity Framework* and Hoop.dev's inline AI/command guardrails focus on binding AI/MCP agents to human sponsors with per-tool RBAC, PII redaction, and runtime circuit breakers.
- **Browser-First + CLI Dual Ergonomics With Zero Bastion Ports**: Engineers want frictionless browser terminals, Windows RDP, multi-DB SQL explorers, and Kubernetes access alongside fast local CLIs without maintaining `guacd`, Python converters, or fragile VPN split-tunnels.
- **Compliance-as-Code & Auditor-Ready Evidence**: Passing a 6-to-12-month SOC 2 Type II window requires proving controls *operated continuously*, not merely showing settings screenshots—meaning immutable hash-chained logs, encrypted fail-closed recordings, automated quarterly access reviews, and ticket-linked sessions.

### Competitive Positioning Matrix

| Dimension | Teleport | StrongDM | HashiCorp Boundary | Hoop.dev | **Operquay-Rust (Current + Target M9–M12)** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Deployment Footprint** | Multi-service Auth/Proxy/Agents (Go) | SaaS Control Plane + Relay Gateways | Controller + Workers + Vault dependency | Gateway + Agent (Go/Clojure) | **1 `#![forbid(unsafe_code)]` Rust binary + external PG** (~zero sidecars, no Node/C daemons) |
| **Browser Remoting Quality** | SSH web UI; RDP via desktop access | Proxy + native client focus | Desktop via external client / Worker | Web SSH/DB focus (limited desktop) | **In-process WASM Terminal + `IronRDP` (`OQR2` binary canvas) + VNC**, zero secrets in browser |
| **Cloud Native AWS Depth** | EC2/IAM node agents (`tsh`) | Connector-driven | Dynamic Host Catalogs | Agent/Runbooks | **Native SigV4 AWS SSO + multi-account EC2 discovery/fetch + in-process SSM DataChannel + VPC Topology + AMI Clone** |
| **Multi-DB & Data DLP** | DB proxy (`PG`/`MySQL`/`Mongo`/etc.) | Strong multi-DB proxy + query logs | TCP/Broker (Vault creds) | **Strong inline PII masking + runbooks** | **5-engine DB Explorer (`PG`/`CH`/`DuckDB`/`MySQL`/`Redis`) + SQL read-only guard** *(DLP masking in M11)* |
| **AI & MCP Governance** | Agentic Identity + MCP Proxy + Beams | Emerging AI workflows | Minimal | Command review / AI runbooks | **Built-in Bedrock/multi-LLM safety guardrails (`safety.rs`) + Encrypted Suggest Trie** *(MCP Proxy in M12)* |
| **SOC 2 / ISO Audit Readiness** | Mature (Device Trust, Access Lists, Locks, SIEM) | Mature (Slack JIT, logs, access reviews) | Vault integration + session recording | Strong command review + masking | **Foundations built** *(P0 crypto/RLS/immutable audit blockers tracked in M9–M10 before GTM claim)* |

### Operquay's Unfair Structural Advantage

No competitor ships **all** of:
- A single memory-safe `#![forbid(unsafe_code)]` static Rust binary (`0` `guacd`, `0` Node, `0` `aws` CLI, `0` `ffmpeg`),
- A custom `operquay_term.wasm` terminal + in-process `IronRDP` + `OQR2` low-latency binary desktop canvas + VNC,
- Agentless AWS SSM DataChannel (`smux`) + VPC reachability topology graph (`petgraph`) + Kubernetes + 5-engine DB Explorer + fail-closed recording + OpenTelemetry in **one unified control plane**.

Closing the P0 security gaps (**M9–M10**) unlocks that architectural advantage for regulated commercial buyers.

---

## 2. Honest Product & Security Audit (Current Issues in `operquay-rust`)

### P0 — Critical Security & SOC 2 / ISO 27001 Release Blockers (Must Fix Before GTM)

1. **SAML 2.0 XML-DSig Signature & Conditions Missing** (`crates/operquay-auth/src/sso.rs:420-520`):
   - `parse_saml_response_b64` parses XML claims with `quick-xml`, **but never verifies `<ds:Signature>` against the IdP X.509 certificate**, nor enforces `<Conditions>` (`NotBefore`/`NotOnOrAfter`, `Audience`), `<SubjectConfirmationData>` (`Recipient`), or XML Signature Wrapping (XSW) protections. *Impact*: Forged SAMLResponse allows authentication bypass (**SOC 2 CC6.1 | ISO A.8.5**).
2. **OIDC ID-Token JWT Signature & Claims Missing** (`crates/operquay-auth/src/sso.rs:224-232`):
   - `decode_jwt_payload_claims` decodes Base64 payload without verifying cryptographic signatures via the IdP JWKS endpoint or checking `iss`, `aud`, `exp`, `nbf`, `alg`. *Impact*: Token forgery/substitution risk (**SOC 2 CC6.1 | ISO A.8.5**).
3. **PostgreSQL RLS Fails Open When `app.tenant_id` Is Unset** (`migrations/0002_full_platform_schema.sql:257-261`):
   - Policies use `USING (current_setting('app.tenant_id', true) IS NULL OR ... = '' OR tenant_id = ...)`, and tables lack `FORCE ROW LEVEL SECURITY`. Any query missing a `SET LOCAL` call returns rows across all tenants (**SOC 2 CC6.1, C1.1 | ISO A.8.2**).
4. **Missing Cookie `Secure` Flag, CSRF/Origin Enforcement & Proxy Allowlist** (`crates/operquay-server/src/auth_routes.rs:24-42, 219-221`, `crates/operquay-auth/src/crypto.rs:121-130`):
   - Session cookie lacks `Secure` (`__Host-`), `Origin` validation is absent on mutating routes/WebSockets, and `X-Forwarded-For` / `X-Real-IP` / `X-Operquay-Tenant` headers are trusted unconditionally without `TRUSTED_PROXIES` CIDR verification (**SOC 2 CC6.6 | ISO A.8.20**).
5. **Missing HTTP Hardening Headers, Brute-Force Lockout, MFA & Weak Default Hash Cost** (`crates/operquay-server/src/lib.rs:173-185`, `crates/operquay-auth/src/lib.rs:246`):
   - Missing `Strict-Transport-Security`, `Content-Security-Policy`, `Permissions-Policy`, login rate limiting/lockout, forced initial admin password change, password complexity/history, WebAuthn/TOTP MFA, and default `bcrypt` cost `10` (below recommended `12`/Argon2id) (**SOC 2 CC6.1, CC6.2, CC6.6 | ISO A.8.5**).
6. **Plaintext TCP in MySQL & Redis DB Drivers** (`crates/operquay-db/src/mysql_driver.rs:48-55`, `crates/operquay-db/src/redis_driver.rs:58-67`):
   - Both connect over raw unencrypted `TcpStream`, exposing DB credentials and query data in transit unless wrapped in `tokio-rustls` (**SOC 2 CC6.6, CC6.7 | ISO A.8.24**).
7. **AES-GCM Nonce Entropy & Lack of Key Rotation / KMS** (`crates/operquay-auth/src/crypto.rs:32-33`):
   - `seal_aead` slices 12 bytes from `Uuid::new_v4()` (leaving ~90 random bits due to version/variant bits) instead of 96 random bits from `OsRng`, and stores ciphertext without `key_version` or KMS envelope wrapping (**SOC 2 CC6.7 | ISO A.8.24**).
8. **SSM Interactive Shell Violates Channel & Fail-Closed Recording Rules** (`crates/operquay-server/src/aws_routes.rs:1661-1704`):
   - Uses `mpsc::unbounded_channel` (violating `RULES.md` §4.1), does not wire `RecordingTee` fail-closed `.cast` recording, and lacks live 5s PostgreSQL lease fence termination during active streams (**SOC 2 CC6.3, CC7.2 | ISO A.8.15, A.8.16**).
9. **Legacy Protocol Fallbacks Ungated** (`crates/operquay-rdp/src/standard_sec.rs`, `crates/operquay-vnc/src/auth.rs`):
   - Standard RDP RC4 and unencrypted VNCAuth DES are active even when Compliance Mode should reject weak legacy ciphers (**ISO A.8.24**).
10. **Mutable Audit Log & Unencrypted Local Recordings** (`migrations/0002_full_platform_schema.sql:182-190`):
    - `audit_events` lacks `prev_hash`/`entry_hash` tamper-evidence and `REVOKE UPDATE, DELETE`; recordings lack encryption at rest and WORM archival (**SOC 2 CC7.2, C1.1 | ISO A.5.33, A.8.15**).

### P1 — Operational & Feature Parity Gaps

1. **Volatile In-Memory AWS SSO & Role Leases** (`crates/operquay-aws/src/sso.rs:68-70`, `accounts.rs`, `discovery.rs`, `shell.rs`, `clone.rs`): Restarting `deploy-operquay-1` wipes signed-in AWS SSO flows and connected roles, breaking HA replicas and requiring users to re-sign in after upgrades.
2. **Teleport Integration Is Currently an In-Memory State Scaffold** (`crates/operquay-k8s/src/lib.rs:794-822`): `start_teleport_with_callback` stores session metadata in a map rather than executing real Teleport Auth/Proxy WebAPI + mTLS `GenerateUserCerts` gRPC calls.
3. **Uncompressed `I_PCM` H.264 MP4 Output** (`crates/operquay-recording/src/h264_mp4.rs`): Produces valid Baseline H.264 `.mp4` files with zero C dependencies, but uncompressed macroblocks create huge files on long sessions.
4. **`DuckDbDriver` Embedded Sandbox (`duckdb_driver.rs`)**: Uses `EmbeddedColumnarEngine` rather than full native DuckDB `.duckdb`/Parquet SQL engine features; **K8s exec/attach** and **Azure/GCP connectors** (`CloudConnections` "Coming soon") need full production backends.

### P2 — Enterprise GTM & UX Polish Gaps

1. No downloadable local CLI (`operquay ssh/db/kube/forward/mcp`) matching Teleport's `tsh` ergonomics.
2. No Infrastructure-as-Code provider (Terraform/OpenTofu) for managing RBAC roles, SSO providers, recording policies, and JIT workflows.
3. No Slack/Teams/PagerDuty/Jira webhooks for approvals, break-glass alerts, or exception triage.
4. No self-service "Compliance Auditor Mode" generating signed SOC 2 / ISO 27001 evidence packages.

---

## 3. High-Impact Feature Ideas to Compete & Win

### Pillar 1: Zero Standing Privileges (ZSP) & ChatOps JIT Approvals
- **What to build**: Default production AWS roles, production K8s namespaces, and write-capable DB connections to **Zero Standing Privileges**. Add a 1-click JIT Request workflow (`POST /api/access-requests`: target, requested role, duration `15m..4h`, reason, Jira/Linear ticket ID) that notifies Slack/Microsoft Teams/PagerDuty interactive webhooks (`Approve` / `Deny` buttons with four-eyes enforcement: requester != approver).
- **Why it wins**: Matches Teleport Access Requests and StrongDM Approval Workflows natively inside the browser UI + AWS SSM/RDP/DB engine with automatic `<= 5s` session fence kill on TTL expiry.
- **Compliance**: **SOC 2 CC6.2, CC6.3, CC8.1 | ISO A.5.15, A.5.18, A.8.2**.

### Pillar 2: AI Agent & MCP (Model Context Protocol) Zero-Trust Proxy
- **What to build**: Position Operquay as an **MCP Gateway & Agentic Identity Broker**. When engineers connect Claude Desktop, Cursor, Copilot, CI bots, or internal agents to internal databases, K8s clusters, or AWS tools via MCP (`HTTP/SSE/stdio`), Operquay proxies the MCP JSON-RPC stream:
  - Issues per-agent cryptographic short-lived identity bound to a named **human sponsor**.
  - Enforces per-tool RBAC and JIT elevation (e.g., `pg.select` allowed; `pg.mutate` or `aws.ec2.terminate` triggers Slack human-in-the-loop pause!).
  - Runs `operquay-llm::safety` PII/secret scrubbing and blast-radius rate limits on agent outputs/inputs.
  - Logs every prompt, tool call, argument, and masked result in hash-chained `audit_events`.
- **Why it wins**: Directly counters Teleport's flagship 2026 *Agentic Identity Framework* + Hoop.dev, while remaining a lightweight single Rust binary (`ISO/IEC 42001` ready).

### Pillar 3: Real-Time Dual-Control Session Moderation, Live Shadowing & AI Risk Summaries
- **What to build**:
  - **Live Watch / Co-Pilot / Terminate**: Security leads watch active `operquay-term` or `OQR2` desktop streams live in the browser (`observer` read-only vs `moderator` freeze/terminate), and mandate dual-party presence ("Moderated Session") for production break-glass or third-party vendor support.
  - **Automated Risk Summaries & Playback Bookmarks**: Pipe sanitized `.cast` transcripts and DB query logs through `operquay-llm` (supporting local Bedrock/Ollama for data residency) to attach structured timeline bookmarks (`package installed`, `sudo escalated`, `/etc/shadow touched`, `DROP attempted`) so auditors don't review 2-hour videos manually.
- **Why it wins**: Eliminates the SOC 2 "unmonitored session recordings" auditor finding.

### Pillar 4: Inline Database/Terminal DLP Masking & Command Firewalls
- **What to build**:
  - **Result-Set PII/Secret Redaction (`operquay-db`)**: Dynamically detect and mask PAN/credit-card, SSN, AWS keys, JWTs, and marked PII columns (`****-1234`) in `DbExplorer` result sets for non-privileged roles before JSON reaches the browser.
  - **Inline Command Interception (`operquay-ssm` + `operquay-k8s`)**: Inspect interactive/batch commands (`terraform destroy`, `kubectl delete ns prod`, `rm -rf /`, `TRUNCATE`) against policy rules: `allow`, `warn+audit`, `pause-for-approval`, or `block`.
- **Why it wins**: Captures Hoop.dev's strongest enterprise differentiation directly inside Operquay's terminal, DB, and K8s proxies.

### Pillar 5: Unified Identity + Resource Blast-Radius Access Graph
- **What to build**: Extend `operquay-aws::topology` (`petgraph`) from network-only VPC reachability into a unified **Identity -> Role -> Cloud -> Network -> VM/K8s/DB Graph**:
  - Show not only *"can packet reach subnet X:3389 from IGW?"*, but *"which human users, SCIM groups, NHIs, and AI agents can reach production RDS through this EC2 instance or EKS service account, and what is their blast radius if compromised?"*
  - Flag **Shadow Admins**, **Cross-Account Trust Loops**, and **Unused Standing Permissions** cleanly in one visual graph.
- **Why it wins**: Bridges PAM + CIEM/CNAPP (Teleport Access Graph parity) using infrastructure topology code Operquay *already* ships.

### Pillar 6: Zero-Inbound Hybrid Reverse-Tunnel Agent (`operquay-agent`) & Multi-Cloud (Azure/GCP)
- **What to build**:
  - **`operquay-agent`**: Compile a tiny (~5–8 MB) static Rust daemon from existing workspace crates (`operquay-rdp`, `operquay-vnc`, `operquay-ssm`/mux) for **on-premises Linux/Windows Active Directory hosts, VMware, bare-metal, and private K8s clusters** without public IPs or AWS SSM. Agents dial *outbound* over **mTLS 1.3** to Operquay's control plane; no firewall inbound ports required.
  - **First-Class Azure & GCP**: Ship Entra ID PIM + Azure Bastion/VM + AKS discovery/fetch and GCP IAM + OS Login / IAP + GKE discovery/fetch alongside AWS SSO.
- **Why it wins**: Unlocks non-AWS and hybrid enterprise footprints instantly.

### Pillar 7: Hardware Device Trust & Phishing-Resistant Passwordless Identity
- **What to build**:
  - Enforce **WebAuthn / FIDO2 Passkeys** + **TOTP** for local auth and step-up re-authentication before break-glass / RDP / prod DB mutation.
  - Optional lightweight device posture attestation (MDM hooks for CrowdStrike, Jamf, Microsoft Intune, or osquery: disk encryption on, OS patch age, EDR running) before issuing `TicketStore` session tickets.
  - Ephemeral short-lived OpenSSH certificates (OpenSSH CA) and Kubernetes client certificates for CLI users.

### Pillar 8: Continuous Compliance Hub & One-Click Auditor Evidence Portal
- **What to build**: Add an **Auditor & Compliance Workspace**:
  - Automated **Quarterly Access Review Campaigns** (`SOC 2 CC6.3`): notify team owners of every user/group/cloud role binding; export signed attestations (`Kept` / `Revoked`).
  - **One-Click SOC 2 / ISO 27001 Evidence Bundle**: Export a zip/JSON+PDF bundle containing password/MFA policy state, SAML/OIDC verification posture, hash-chain verification proof (`audit_events` integrity OK), sample ticket-linked `.cast`/`.guac` SHA-256 manifests, and SCIM offboarding latency metrics.
  - Native **SIEM Connectors**: Real-time push to Splunk HEC, Datadog Logs, AWS Security Lake / CloudWatch, Microsoft Sentinel, and RFC 5424 Syslog.

### Pillar 9: Developer-First `operquay` CLI & Terraform / OpenTofu Provider
- **What to build**:
  - Upgrade `operquay-forward` into a unified **`operquay` CLI**: `operquay login`, `operquay ssh <host>`, `operquay db connect <db>`, `operquay kube <cluster>`, `operquay mcp proxy`, `operquay record inspect`.
  - Publish an official **`terraform-provider-operquay`** covering SSO providers, RBAC roles, SCIM tokens, JIT policies, K8s recording policies, and AWS account bindings so security teams manage access via Git PRs (`SOC 2 CC8.1`).

### Pillar 10: Next-Gen Streaming (`WebCodecs` H.264) & Compressed WORM Recordings
- **What to build**:
  - Complete `OQR2` message `0x09 H264AccessUnit` (`[MS-RDPEGFX]` `AVC420`) pass-through to browser `WebCodecs` `VideoDecoder` for 60 FPS CAD/video workloads with lossless PNG crisp-text snap on pause.
  - Add inter-frame compressed video export (replacing huge `I_PCM` MP4 files) + client-side/server-side **AES-256-GCM / KMS encrypted WORM S3 Object Lock** archival.

---

## 4. Go-To-Market (GTM) Wedge, Packaging & Sequencing

### Recommended GTM Beachhead ("Wedge")
Don't try to boil the ocean against CyberArk on Day 1. Target **AWS-heavy & Multi-Cloud Engineering Teams (50–1,000 engineers) preparing for SOC 2 Type II or ISO 27001**:
- **Pain point solved in 15 minutes**: Replace leaky bastion VMs, unrecorded `aws ssm`, fragile `guacd`/Node/FreeRDP stacks, and ad-hoc pgAdmin/kubectl tunnels with **one Rust container** featuring browser WASM SSH, fast in-process Windows IronRDP, Multi-DB SQL explorer with read-only guards, VPC topology, and auditor-ready recordings.
- **Compliance differentiator**: Ships with out-of-the-box SOC 2 / ISO 27001 control mappings, hash-chained logs, fail-closed recordings, and Zero Standing Privileges at a fraction of Teleport Enterprise / StrongDM seat cost.

### Suggested Packaging Tiers
| Tier | Target Buyer | Included Capabilities |
| :--- | :--- | :--- |
| **Core / Open-Source (Apache-2.0)** | Startups & DevOps Engineers | Single binary, local/OIDC auth, WASM SSH/SSM terminal, `IronRDP` (`OQR2`), VNC, 5-engine DB Explorer (read-only guard), basic K8s, `.cast`/`.guac` recording. |
| **Pro (Team / Growth)** | Scaling Startups (`SOC 2 Type I/II` prep) | SAML 2.0 + SCIM v2 + RBAC deny-overrides, WebAuthn/TOTP MFA, Multi-account AWS SSO + VPC Topology + AMI Clone, encrypted compressed MP4 export, SIEM webhook export. |
| **Enterprise Compliance & AI** | Regulated Mid-Market / Enterprise | FIPS 140-3 (`aws-lc-rs`) & Compliance Mode (RC4/DES ban), Hash-Chained Immutable Audit + WORM S3 Object Lock, KMS envelope encryption, JIT ChatOps ZSP + Dual Moderation, DB/Shell DLP masking, Identity Access Graph, **MCP / AI Agent Governance Proxy**, `operquay-agent`, Dedicated Compliance Evidence Portal & Terraform Provider. |

### Phased Execution Sequence
1. **Days 1–45 (M9 + M10 — Compliance Floor)**: Close every audited P0 blocker (SAML XML-DSig, OIDC JWKS, fail-closed PG `FORCE ROW LEVEL SECURITY`, `Secure`+CSRF cookies, `TRUSTED_PROXIES`, MFA, MySQL/Redis TLS, compliance-mode RC4/DES ban, bounded SSM channels + fail-closed `.cast` + 5s live fence kill, immutable hash-chained `audit_events`, encrypted WORM recordings, persistent AWS leases, SBOM/`cosign`).
2. **Days 46–120 (M11 — SOC 2 Commercial Readiness)**: Ship ChatOps JIT ZSP approvals, Dual-Control Session Moderation + AI risk summaries, DB/Shell DLP masking, SIEM connectors, Quarterly Access Reviews, and One-Click Evidence Bundle.
3. **Months 5–12 (M12 — Category Leadership)**: Launch MCP & AI Agent Governance Proxy, `operquay-agent` mTLS hybrid connector, Azure/GCP parity, Unified Identity+Network Access Graph, `operquay` CLI + Terraform Provider, and Device Trust.
