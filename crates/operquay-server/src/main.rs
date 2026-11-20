#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use clap::{Parser, Subcommand};
use operquay_forward::run_forward_cli;
use operquay_license::{
    all_enterprise_capabilities, generate_keypair_b64, issue_license_token, verify_license_token,
    EntitlementClaims, PlanTier,
};
use operquay_server::{build_router, AppState};
use operquay_telemetry::TelemetryHub;
use rustls_pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Parser)]
#[command(
    name = "operquay",
    version,
    about = "Single-binary pure-Rust cloud infrastructure & remote desktop gateway"
)]
struct Cli {
    /// TCP bind address for the unified HTTP/WebSocket control plane.
    #[arg(long, env = "OPERQUAY_LISTEN", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Optional TLS/HTTPS bind address for credential-transport security (`wss://` & HTTPS).
    #[arg(long, env = "OPERQUAY_TLS_LISTEN")]
    tls_listen: Option<SocketAddr>,

    /// Optional directory containing built frontend SPA assets (`frontend/dist`).
    #[arg(long, env = "OPERQUAY_STATIC_DIR")]
    static_dir: Option<PathBuf>,

    /// Optional PostgreSQL connection string enabling Row-Level Security persistence.
    #[arg(long, env = "OPERQUAY_DATABASE_URL")]
    database_url: Option<String>,

    /// Optional OpenTelemetry OTLP gRPC endpoint (e.g., `http://127.0.0.1:4317`).
    #[arg(long, env = "OTEL_EXPORTER_OTLP_ENDPOINT")]
    otel_endpoint: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Sign in to an Operquay server and persist strict-TLS session credentials (`0600`).
    Login {
        #[arg(long)]
        server: String,
        #[arg(long)]
        email: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        ca_cert: Option<PathBuf>,
    },
    /// Open an interactive AWS SSM SSH terminal to an EC2 instance.
    Ssh {
        instance_id: String,
        #[arg(long, default_value = "us-east-1")]
        region: String,
        #[arg(long, default_value = "")]
        profile: String,
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        ca_cert: Option<PathBuf>,
    },
    /// Run a DLP-redacted read-only SQL query via `/api/db/query`.
    Db {
        #[arg(long)]
        connection_id: String,
        #[arg(long)]
        sql: String,
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        ca_cert: Option<PathBuf>,
    },
    /// List pods or exec into a Kubernetes container over the control plane.
    Kube {
        #[arg(long)]
        cluster: String,
        #[arg(long, default_value = "default")]
        namespace: String,
        #[arg(long)]
        pod: Option<String>,
        #[arg(long, default_value = "/bin/sh")]
        command: String,
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        ca_cert: Option<PathBuf>,
    },
    /// Bridge stdio Model Context Protocol (MCP) JSON-RPC 2.0 to `/api/mcp/rpc`.
    Mcp {
        #[arg(long)]
        server: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        ca_cert: Option<PathBuf>,
    },
    /// Connect a local TCP listener to a remote Operquay port-forward WebSocket mux endpoint.
    Forward {
        #[arg(long)]
        ws_url: String,
        #[arg(long)]
        pairing_code: String,
        #[arg(long, default_value = "127.0.0.1:15432")]
        listen: String,
    },
    /// Manage Ed25519 offline/online enterprise license tokens.
    Licensectl {
        #[command(subcommand)]
        action: LicenseAction,
    },
}

#[derive(Debug, Subcommand)]
enum LicenseAction {
    /// Generate a fresh Ed25519 signing keypair (`private_key_b64`, `public_key_b64`).
    Keygen,
    /// Issue a signed `OPQL1.` enterprise license token.
    Issue {
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        customer: String,
        #[arg(long, default_value = "enterprise")]
        plan: String,
        #[arg(long, default_value_t = 100)]
        max_seats: u32,
        #[arg(long, default_value_t = 365)]
        days: i64,
    },
    /// Verify a signed `OPQL1.` token offline against a public key.
    Verify {
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        token: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    load_dotenv_defaults();
    let cli = Cli::parse();

    if let Some(cmd) = cli.command {
        return match cmd {
            Commands::Login {
                server,
                email,
                password,
                ca_cert,
            } => {
                operquay_forward::cli::run_login_cli(
                    &server,
                    &email,
                    &password,
                    ca_cert.as_deref(),
                )
                .await
                .map_err(std::io::Error::other)?;
                Ok(())
            }
            Commands::Ssh {
                instance_id,
                region,
                profile,
                server,
                ca_cert,
            } => {
                operquay_forward::cli::run_ssh_cli(
                    &instance_id,
                    &region,
                    &profile,
                    server.as_deref(),
                    ca_cert.as_deref(),
                )
                .await
                .map_err(std::io::Error::other)?;
                Ok(())
            }
            Commands::Db {
                connection_id,
                sql,
                server,
                ca_cert,
            } => {
                operquay_forward::cli::run_db_query_cli(
                    &connection_id,
                    &sql,
                    server.as_deref(),
                    ca_cert.as_deref(),
                )
                .await
                .map_err(std::io::Error::other)?;
                Ok(())
            }
            Commands::Kube {
                cluster,
                namespace,
                pod,
                command,
                server,
                ca_cert,
            } => {
                operquay_forward::cli::run_kube_cli(
                    &cluster,
                    &namespace,
                    pod.as_deref(),
                    &command,
                    server.as_deref(),
                    ca_cert.as_deref(),
                )
                .await
                .map_err(std::io::Error::other)?;
                Ok(())
            }
            Commands::Mcp {
                server,
                token,
                ca_cert,
            } => {
                operquay_forward::cli::run_mcp_stdio_proxy(&server, &token, ca_cert.as_deref())
                    .await
                    .map_err(std::io::Error::other)?;
                Ok(())
            }
            Commands::Forward {
                ws_url,
                pairing_code,
                listen,
            } => {
                run_forward_cli(&ws_url, &pairing_code, &listen).await?;
                Ok(())
            }
            Commands::Licensectl { action } => {
                run_licensectl(action)?;
                Ok(())
            }
        };
    }

    let telemetry = TelemetryHub::build("operquay-rust", cli.otel_endpoint.as_deref(), 1.0, true);
    let settings =
        operquay_server::stores::build_settings_store_from_dsn(cli.database_url.as_deref()).await?;
    let static_dir = cli.static_dir.or_else(|| {
        let candidate = PathBuf::from("frontend/dist");
        candidate.exists().then_some(candidate)
    });

    let state = AppState::with_defaults(settings, telemetry, static_dir);
    if let Some(siem) = operquay_server::siem::SiemDispatcher::spawn_from_env() {
        state.audit.attach_siem(Arc::new(siem)).await;
        tracing::info!("attached bounded SIEM audit stream dispatcher");
    }

    let mut pg_for_discovery = None;
    if let Some(dsn) = &cli.database_url {
        let lower = dsn.trim().to_ascii_lowercase();
        if lower.starts_with("postgres://")
            || lower.starts_with("postgresql://")
            || lower.contains("host=")
        {
            tracing::info!("attaching PostgreSQL RLS auth persistence pool");
            let pg_auth = operquay_auth::pg::PgAuthPool::connect(dsn)
                .await
                .map_err(std::io::Error::other)?;
            if let Err(err) = pg_auth.ensure_runtime_tables().await {
                eprintln!("Warning: ensure_runtime_tables failed: {err}");
            }
            state.set_pg_pool(pg_auth.clone()).await;
            hydrate_pg_state(&state, &pg_auth).await;
            pg_for_discovery = Some(pg_auth.clone());
            state
                .auth
                .attach_pg(pg_auth)
                .await
                .map_err(std::io::Error::other)?;
        } else {
            tracing::info!(
                "control-plane database active without PostgreSQL RLS auth pool (using embedded/analytic backend)"
            );
        }
    }
    if let Ok(admin_pw) = std::env::var("OPERQUAY_ADMIN_PASSWORD") {
        if !admin_pw.is_empty() {
            state
                .auth
                .set_admin_password(&admin_pw)
                .await
                .map_err(std::io::Error::other)?;
            let req_auth = std::env::var("OPERQUAY_REQUIRE_AUTH")
                .or_else(|_| std::env::var("REQUIRE_AUTH"))
                .map_or(true, |v| v == "1" || v.eq_ignore_ascii_case("true"));
            state.auth.set_require_auth(req_auth).await;
        }
    }

    spawn_hourly_retention_purge(state.clone());
    spawn_jit_expiry_reaper(state.clone());
    operquay_server::aws_routes::trigger_tenant_discovery_with_pg(
        state.aws.clone(),
        pg_for_discovery,
        "default".to_owned(),
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let fence = Arc::clone(&state.session_fence);
    let app = build_router(state);

    let tls_addr = resolve_tls_listen_addr(cli.tls_listen);
    let listener = TcpListener::bind(cli.listen).await?;
    tracing::info!(listen = %cli.listen, "operquay-rust HTTP server listening");

    let http_app = app
        .clone()
        .layer(axum::Extension(operquay_server::ListenerScheme(false)));

    if let Some(https_addr) = tls_addr {
        let acceptor = build_tls_acceptor()?;
        let https_tcp = TcpListener::bind(https_addr).await?;
        tracing::info!(listen = %https_addr, "operquay-rust HTTPS/TLS server listening");
        let tls_listener = TlsListener::new(https_tcp, acceptor);
        let tls_app = app.layer(axum::Extension(operquay_server::ListenerScheme(true)));
        let http_srv = axum::serve(
            listener,
            http_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(operquay_server::wait_for_shutdown_and_drain(
            Arc::clone(&fence),
            shutdown_rx.clone(),
            Duration::from_secs(10),
        ));
        let tls_srv = axum::serve(tls_listener, TlsMakeService(tls_app)).with_graceful_shutdown(
            operquay_server::wait_for_shutdown_and_drain(
                fence,
                shutdown_rx,
                Duration::from_secs(10),
            ),
        );
        tokio::try_join!(http_srv, tls_srv)?;
    } else {
        axum::serve(
            listener,
            http_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(operquay_server::wait_for_shutdown_and_drain(
            fence,
            shutdown_rx,
            Duration::from_secs(10),
        ))
        .await?;
    }

    Ok(())
}

async fn hydrate_pg_state(state: &AppState, pg_auth: &operquay_auth::pg::PgAuthPool) {
    if let Ok(rows) = pg_auth.list_tenant_deks().await {
        for r in rows {
            state
                .tenant_keys
                .hydrate_key(&r.tenant_id, r.dek, r.shredded)
                .await;
        }
    }
    if let Ok(Some(dek)) = pg_auth.get_or_create_tenant_dek("default").await {
        state
            .tenant_keys
            .hydrate_key("default", Some(dek), false)
            .await;
    }
    let master_secret = pg_auth.master_secret().await;
    state
        .governance
        .set_cluster_master_secret(&master_secret)
        .await;
    state
        .recordings
        .attach_cluster_crypto(&master_secret, Arc::clone(&state.tenant_keys))
        .await;
    if let Err(err) = state.audit.attach_pg(pg_auth.clone()).await {
        tracing::warn!(error = %err, "failed attaching PG hash-chained audit log");
    }
    if let Ok(rows) = pg_auth.list_recording_metadata().await {
        let items: Vec<operquay_recording::RecordingEntry> = rows
            .into_iter()
            .map(|r| operquay_recording::RecordingEntry {
                id: r.id,
                tenant_id: r.tenant_id,
                protocol: r.protocol,
                target_host: r.target_host,
                format: r.format,
                started_at_ms: u64::try_from(r.started_at_ms).unwrap_or(0),
                bytes_written: usize::try_from(r.bytes_written).unwrap_or(0),
                frame_count: u64::try_from(r.frame_count).unwrap_or(0),
                sha256_hex: r.sha256_hex,
                fail_closed: r.fail_closed,
                status: r.status,
                encrypted: r.encrypted,
                legal_hold: r.legal_hold,
                legal_hold_reason: r.legal_hold_reason,
                retention_until_ms: r.retention_until_ms.map(|v| u64::try_from(v).unwrap_or(0)),
                archived_s3_uri: r.archived_s3_uri,
                archived_at_ms: r.archived_at_ms.map(|v| u64::try_from(v).unwrap_or(0)),
            })
            .collect();
        state.recordings.hydrate_metadata(items).await;
    }
    if let Ok(rows) = pg_auth.list_aws_sso_providers().await {
        let hydrated: Vec<operquay_aws::sso::UserAwsSsoProvider> = rows
            .into_iter()
            .map(|r| operquay_aws::sso::UserAwsSsoProvider {
                id: r.id,
                tenant_id: r.tenant_id,
                label: r.label,
                start_url: r.start_url,
                region: r.region,
                created_at: r.created_at,
            })
            .collect();
        state.aws.sso.hydrate_providers(hydrated).await;
    }
    if let Ok(rows) = pg_auth.list_aws_sso_sessions().await {
        let flows: Vec<operquay_aws::sso::PersistedSsoFlow> = rows
            .into_iter()
            .filter_map(|r| {
                let mut f = serde_json::from_str::<operquay_aws::sso::PersistedSsoFlow>(
                    &r.token_state_json,
                )
                .ok()?;
                f.cancelled = r.cancelled;
                Some(f)
            })
            .collect();
        state.aws.sso.hydrate_flows(flows).await;
    }
    if let Ok(rows) = pg_auth.list_aws_role_bindings().await {
        let bindings: Vec<operquay_aws::accounts::UserRoleBinding> = rows
            .into_iter()
            .filter_map(|r| {
                serde_json::from_str::<operquay_aws::accounts::UserRoleBinding>(&r.payload_json)
                    .ok()
            })
            .collect();
        state.aws.accounts.hydrate_bindings(bindings).await;
    }
    if let Ok(rows) = pg_auth.list_aws_role_leases().await {
        let leases = rows
            .into_iter()
            .filter_map(|r| {
                let creds = serde_json::from_str::<operquay_aws::sigv4::AwsCredentials>(
                    &r.credentials_json,
                )
                .ok()?;
                Some((
                    r.tenant_id,
                    r.user_id,
                    operquay_aws::accounts::ConnectedRoleLease {
                        id: r.id,
                        binding_id: r.binding_id,
                        label: r.label,
                        account_id: r.account_id,
                        role_arn: r.role_arn,
                        role_name: r.role_name,
                        start_url: r.start_url,
                        region: r.region,
                        status: r.status,
                        credential_revision: r.credential_revision,
                        connected_at: r.connected_at,
                        expires_at: r.expires_at,
                        credentials: creds,
                    },
                ))
            })
            .collect();
        state.aws.accounts.hydrate_leases(leases).await;
    }
    if let Ok(rows) = pg_auth.list_user_preferences().await {
        let prefs = rows
            .into_iter()
            .filter_map(|r| {
                let p =
                    serde_json::from_str::<operquay_aws::accounts::UserPreferences>(&r.prefs_json)
                        .ok()?;
                Some((r.tenant_id, r.user_id, p))
            })
            .collect();
        state.aws.accounts.hydrate_preferences(prefs).await;
    }
    if let Ok(rows) = pg_auth.list_aws_saved_inventories().await {
        let saved = rows
            .into_iter()
            .filter_map(|r| {
                let items = serde_json::from_str::<Vec<serde_json::Value>>(&r.items_json).ok()?;
                Some((r.tenant_id, r.user_id, items))
            })
            .collect();
        state.aws.accounts.hydrate_saved_inventory(saved).await;
    }
    if let Ok(rows) = pg_auth.list_aws_discovery_inventories().await {
        for r in rows {
            if let (Ok(instances), Ok(status)) = (
                serde_json::from_str::<Vec<operquay_aws::discovery::Ec2Instance>>(
                    &r.instances_json,
                ),
                serde_json::from_str::<operquay_aws::discovery::DiscoveryStatus>(&r.status_json),
            ) {
                state
                    .aws
                    .discovery
                    .hydrate_inventory(&r.tenant_id, instances, status)
                    .await;
            }
        }
    }
    if let Ok(rows) = pg_auth.list_aws_clone_operations().await {
        let clones = rows
            .into_iter()
            .filter_map(|r| {
                serde_json::from_str::<operquay_aws::clone::CloneStatus>(&r.payload_json).ok()
            })
            .collect();
        state.aws.clones.hydrate_clones(clones).await;
    }
    if let Ok(policies) = pg_auth.list_recording_policies().await {
        let mut guard = state.platform.rec_policies.write().await;
        for (tenant_id, val) in policies {
            if let Ok(parsed) = serde_json::from_value::<operquay_recording::RecordingPolicy>(val) {
                guard.insert(tenant_id, parsed);
            }
        }
    }
    if let Ok(rows) = pg_auth.list_jit_access_requests().await {
        let reqs = rows
            .into_iter()
            .filter_map(|r| {
                serde_json::from_str::<operquay_server::jit::JitAccessRequest>(&r.payload_json).ok()
            })
            .collect();
        state.governance.hydrate_requests(reqs).await;
    }
    if let Ok(rows) = pg_auth.list_governance_webhooks().await {
        let hooks = rows
            .into_iter()
            .map(|r| {
                let events =
                    serde_json::from_str::<Vec<String>>(&r.events_json).unwrap_or_default();
                operquay_server::jit::GovernanceWebhook {
                    id: r.id,
                    tenant_id: r.tenant_id,
                    provider: r.provider,
                    name: r.name,
                    url: r.url,
                    secret: r.secret,
                    events,
                    enabled: r.enabled,
                    created_at: r.created_at,
                }
            })
            .collect();
        state.governance.hydrate_webhooks(hooks).await;
    }
    if let Ok(rows) = pg_auth.list_dlp_policies().await {
        let policies = rows
            .into_iter()
            .filter_map(|r| {
                let pol =
                    serde_json::from_str::<operquay_server::dlp::DlpFirewallPolicy>(&r.policy_json)
                        .ok()?;
                Some((r.tenant_id, pol))
            })
            .collect();
        state.governance.hydrate_dlp_policies(policies).await;
    }
    if let Ok(rows) = pg_auth.list_session_risk_bookmarks().await {
        let bms = rows
            .into_iter()
            .map(|r| operquay_server::jit::SessionRiskBookmark {
                id: r.id,
                tenant_id: r.tenant_id,
                recording_id: r.recording_id,
                session_id: r.session_id,
                offset_secs: r.offset_secs,
                severity: r.severity,
                category: r.category,
                title: r.title,
                detail: r.detail,
                source: r.source,
                created_at: r.created_at,
            })
            .collect();
        state.governance.hydrate_bookmarks(bms).await;
    }
    if let Ok(rows) = pg_auth.list_access_review_campaigns().await {
        let campaigns = rows
            .into_iter()
            .filter_map(|r| {
                serde_json::from_str::<operquay_server::compliance::AccessReviewCampaign>(
                    &r.payload_json,
                )
                .ok()
            })
            .collect();
        state.governance.hydrate_campaigns(campaigns).await;
    }
    if let Ok(rows) = pg_auth.list_mcp_agents().await {
        let agents: Vec<operquay_server::mcp::McpAgent> = rows
            .into_iter()
            .filter_map(|r| {
                let mut a =
                    serde_json::from_str::<operquay_server::mcp::McpAgent>(&r.payload_json).ok()?;
                a.token_hash = r.token_hash;
                Some(a)
            })
            .collect();
        state.mcp.hydrate_agents(agents).await;
    }
    if let Ok(rows) = pg_auth.list_mcp_invocations().await {
        let invs: Vec<operquay_server::mcp::McpToolInvocation> = rows
            .into_iter()
            .map(|r| operquay_server::mcp::McpToolInvocation {
                id: r.id,
                tenant_id: r.tenant_id,
                agent_id: r.agent_id,
                sponsor_user_id: r.sponsor_user_id,
                tool_name: r.tool_name,
                sanitized_args: r.sanitized_args,
                decision: r.decision,
                jit_request_id: r.jit_request_id,
                masked_result_preview: r.masked_result_preview,
                duration_ms: r.duration_ms,
                created_at: r.created_at,
            })
            .collect();
        state.mcp.hydrate_invocations(invs).await;
    }
    if let Ok(rows) = pg_auth.list_hybrid_agents().await {
        let agents: Vec<operquay_server::agent_hub::HybridAgentRecord> = rows
            .into_iter()
            .filter_map(|r| {
                let mut a = serde_json::from_str::<operquay_server::agent_hub::HybridAgentRecord>(
                    &r.payload_json,
                )
                .ok()?;
                a.enrollment_token_hash = r.enrollment_token_hash;
                Some(a)
            })
            .collect();
        state.agent_hub.hydrate_agents(agents).await;
    }
    if let Ok(rows) = pg_auth.list_cloud_connectors().await {
        let conns: Vec<operquay_server::multicloud::CloudConnectorRecord> = rows
            .into_iter()
            .map(|r| operquay_server::multicloud::CloudConnectorRecord {
                id: r.id,
                tenant_id: r.tenant_id,
                provider: r.provider,
                name: r.name,
                account_or_project_id: r.account_or_project_id,
                tenant_or_org_id: r.tenant_or_org_id,
                region: r.region,
                credentials_json: r.credentials_json,
                config: serde_json::from_str(&r.config_json).unwrap_or_default(),
                status: r.status,
                last_synced_at: r.last_synced_at,
                created_at: r.created_at,
            })
            .collect();
        state.multicloud.hydrate_connectors(conns).await;
    }
    if let Ok(rows) = pg_auth.list_device_trust_policies().await {
        let policies = rows
            .into_iter()
            .filter_map(|r| {
                let pol = serde_json::from_str::<operquay_server::device_trust::DeviceTrustPolicy>(
                    &r.policy_json,
                )
                .ok()?;
                Some((r.tenant_id, pol))
            })
            .collect();
        state.device_trust.hydrate_policies(policies).await;
    }
    if let Ok(rows) = pg_auth.list_device_postures().await {
        let postures: Vec<operquay_server::device_trust::DevicePostureAttestation> = rows
            .into_iter()
            .map(
                |r| operquay_server::device_trust::DevicePostureAttestation {
                    id: r.id,
                    tenant_id: r.tenant_id,
                    user_id: r.user_id,
                    device_id: r.device_id,
                    provider: r.provider,
                    hostname: r.hostname,
                    os_version: r.os_version,
                    disk_encrypted: r.disk_encrypted,
                    edr_running: r.edr_running,
                    edr_agent: r.edr_agent,
                    os_patch_age_days: u32::try_from(r.os_patch_age_days).unwrap_or(0),
                    compliant: r.compliant,
                    reasons: serde_json::from_str(&r.reasons_json).unwrap_or_default(),
                    attested_at: r.attested_at,
                    expires_at: r.expires_at,
                },
            )
            .collect();
        state.device_trust.hydrate_attestations(postures).await;
    }
}

fn spawn_jit_expiry_reaper(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.tick().await;
        loop {
            interval.tick().await;
            let expired = state.governance.reap_expired_grants().await;
            for req in expired {
                let terminated = state.session_fence.terminate_jit_grant(
                    &req.tenant_id,
                    &req.id,
                    "jit_lease_expired",
                );
                operquay_server::governance_routes::persist_jit_request(&state, &req).await;
                operquay_server::governance_routes::record_gov_audit(
                    &state,
                    &req.tenant_id,
                    &req.requester_user_id,
                    &req.requester_email,
                    &req.requested_role,
                    "",
                    &req.id,
                    "jit_access_expired",
                    req.target_type.as_str(),
                    &req.target_id,
                    format!("expired JIT lease (terminated_sessions={terminated})"),
                    "success",
                    None,
                )
                .await;
                if let Ok(payload) = serde_json::to_value(&req) {
                    state
                        .governance
                        .dispatch_webhook(&req.tenant_id, "access_request.expired", payload)
                        .await;
                }
            }
        }
    });
}

fn spawn_hourly_retention_purge(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        interval.tick().await;
        loop {
            interval.tick().await;
            let policies_snapshot: Vec<(String, u32)> = {
                let guard = state.platform.rec_policies.read().await;
                let mut pairs: Vec<(String, u32)> = guard
                    .iter()
                    .map(|(tid, pol)| (tid.clone(), pol.retention_days))
                    .collect();
                if !pairs.iter().any(|(t, _)| t == "default") {
                    pairs.push(("default".to_owned(), 90));
                }
                pairs
            };
            let now_ms = operquay_recording::now_unix_ms();
            let pg_opt = state.pg_pool().await;
            for (tid, retention_days) in policies_snapshot {
                let report = state
                    .recordings
                    .purge_expired(&tid, retention_days, now_ms)
                    .await;
                if !report.purged_ids.is_empty() {
                    if let Some(pg) = &pg_opt {
                        for pid in &report.purged_ids {
                            let _ = pg.delete_recording_metadata(&tid, pid).await;
                        }
                    }
                    tracing::info!(
                        tenant = %tid,
                        purged = report.purged_ids.len(),
                        skipped_legal_hold = report.skipped_legal_hold,
                        "hourly recording retention purge completed"
                    );
                }
            }
        }
    });
}

fn load_dotenv_defaults() {
    for candidate in [".env", "../operquay/.env"] {
        if let Ok(content) = std::fs::read_to_string(candidate) {
            for raw_line in content.lines() {
                let line = raw_line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Some((k, v)) = line.split_once('=') else {
                    continue;
                };
                let key = k.trim();
                if key.is_empty() || std::env::var_os(key).is_some() {
                    continue;
                }
                let mut val = v.trim();
                if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
                    || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
                {
                    val = &val[1..val.len() - 1];
                }
                std::env::set_var(key, val);
            }
            break;
        }
    }
}

fn resolve_tls_listen_addr(cli_tls: Option<SocketAddr>) -> Option<SocketAddr> {
    if cli_tls.is_some() {
        return cli_tls;
    }
    if let Ok(raw) = std::env::var("OPERQUAY_TLS_LISTEN") {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("off") || trimmed.eq_ignore_ascii_case("false") {
            return None;
        }
        if let Ok(addr) = trimmed.parse::<SocketAddr>() {
            return Some(addr);
        }
    }
    if let Ok(port_str) = std::env::var("HTTPS_PORT") {
        if let Ok(port) = port_str.trim().parse::<u16>() {
            if port > 0 {
                return Some(SocketAddr::from(([127, 0, 0, 1], port)));
            }
        }
    }
    if std::env::var("OPERQUAY_ADMIN_PASSWORD").is_ok_and(|v| !v.is_empty())
        || std::env::var("TLS_CERT_FILE").is_ok_and(|v| !v.is_empty())
    {
        return Some(SocketAddr::from(([127, 0, 0, 1], 5444)));
    }
    None
}

fn decode_pem_blocks(pem_text: &str, kind: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {kind}-----");
    let end = format!("-----END {kind}-----");
    let mut out = Vec::new();
    let mut rest = pem_text;
    while let Some(b_idx) = rest.find(&begin) {
        let after_begin = &rest[b_idx + begin.len()..];
        let Some(e_idx) = after_begin.find(&end) else {
            break;
        };
        let b64: String = after_begin[..e_idx]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        if let Ok(bytes) = STANDARD.decode(b64) {
            out.push(bytes);
        }
        rest = &after_begin[e_idx + end.len()..];
    }
    out
}

fn parse_private_key_pem(pem_text: &str) -> Result<PrivateKeyDer<'static>, String> {
    if let Some(der) = decode_pem_blocks(pem_text, "PRIVATE KEY")
        .into_iter()
        .next()
    {
        return Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)));
    }
    if let Some(der) = decode_pem_blocks(pem_text, "RSA PRIVATE KEY")
        .into_iter()
        .next()
    {
        return Ok(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)));
    }
    if let Some(der) = decode_pem_blocks(pem_text, "EC PRIVATE KEY")
        .into_iter()
        .next()
    {
        return Ok(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)));
    }
    Err("no supported private key PEM block found".to_owned())
}

fn unix_days_to_ymd(days: i64) -> (i32, u8, u8) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y_base = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    let y = (y_base + i64::from(m <= 2)) as i32;
    (y, m, d)
}

fn build_tls_acceptor() -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert_pair = std::env::var("TLS_CERT_FILE")
        .ok()
        .filter(|s| !s.is_empty())
        .zip(std::env::var("TLS_KEY_FILE").ok().filter(|s| !s.is_empty()))
        .or_else(|| {
            [
                (
                    "/app/certs/operquay-local-cert.pem",
                    "/app/certs/operquay-local-key.pem",
                ),
                (
                    "/app/cache/operquay-local-cert.pem",
                    "/app/cache/operquay-local-key.pem",
                ),
                (
                    "../operquay/.cache/operquay-local-cert.pem",
                    "../operquay/.cache/operquay-local-key.pem",
                ),
            ]
            .into_iter()
            .find(|(c, k)| std::path::Path::new(c).exists() && std::path::Path::new(k).exists())
            .map(|(c, k)| (c.to_owned(), k.to_owned()))
        });

    let (certs, key) = if let Some((cert_path, key_path)) = cert_pair {
        let cert_pem = std::fs::read_to_string(&cert_path)?;
        let key_pem = std::fs::read_to_string(&key_path)?;
        let certs: Vec<CertificateDer<'static>> = decode_pem_blocks(&cert_pem, "CERTIFICATE")
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let key = parse_private_key_pem(&key_pem).map_err(std::io::Error::other)?;
        (certs, key)
    } else {
        let mut params = rcgen::CertificateParams::new(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
            "::1".to_owned(),
        ])?;
        let now_days = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs() / 86_400).unwrap_or(0));
        let (start_year, start_month, start_day) = unix_days_to_ymd(now_days - 1);
        let (end_year, end_month, end_day) = unix_days_to_ymd(now_days + 365);
        params.not_before = rcgen::date_time_ymd(start_year, start_month, start_day);
        params.not_after = rcgen::date_time_ymd(end_year, end_month, end_day);
        let key_pair = rcgen::KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        if std::path::Path::new("/app/cache").is_dir() {
            let _ = std::fs::write("/app/cache/operquay-local-cert.pem", cert.pem());
            let _ = std::fs::write(
                "/app/cache/operquay-local-key.pem",
                key_pair.serialize_pem(),
            );
        }
        let certs = vec![cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        (certs, key)
    };

    let mut tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(tls_cfg)))
}

struct TlsListener {
    local: SocketAddr,
    rx: tokio::sync::mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
}

impl TlsListener {
    fn new(listener: TcpListener, acceptor: TlsAcceptor) -> Self {
        let local = listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0)));
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let _ = stream.set_nodelay(true);
                        let acc = acceptor.clone();
                        let tx_c = tx.clone();
                        tokio::spawn(async move {
                            match tokio::time::timeout(Duration::from_secs(10), acc.accept(stream))
                                .await
                            {
                                Ok(Ok(tls_stream)) => {
                                    let _ = tx_c.send((tls_stream, addr)).await;
                                }
                                Ok(Err(e)) => {
                                    tracing::warn!(error = %e, peer = %addr, "TLS handshake failed");
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, peer = %addr, "TLS handshake failed");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "TLS TCP accept error");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        });
        Self { local, rx }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        if let Some(conn) = self.rx.recv().await {
            conn
        } else {
            std::future::pending().await
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

#[derive(Clone)]
struct TlsMakeService(axum::Router);

impl<'a> tower::Service<axum::serve::IncomingStream<'a, TlsListener>> for TlsMakeService {
    type Response = axum::Router;
    type Error = std::convert::Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: axum::serve::IncomingStream<'a, TlsListener>) -> Self::Future {
        let connect_info = axum::extract::ConnectInfo(*target.remote_addr());
        let svc = self.0.clone().layer(axum::Extension(connect_info));
        std::future::ready(Ok(svc))
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("graceful shutdown signal received");
}

fn run_licensectl(action: LicenseAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        LicenseAction::Keygen => {
            let (sk, pk) = generate_keypair_b64();
            println!("private_key={sk}\npublic_key={pk}");
        }
        LicenseAction::Issue {
            private_key,
            customer,
            plan,
            max_seats,
            days,
        } => {
            let now = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            )
            .unwrap_or(0);
            let tier = match plan.to_ascii_lowercase().as_str() {
                "pro" => PlanTier::Pro,
                "lab" => PlanTier::Lab,
                _ => PlanTier::Enterprise,
            };
            let claims = EntitlementClaims {
                license_id: format!("lic-{}", uuid::Uuid::new_v4()),
                customer,
                plan: tier,
                max_seats,
                issued_at: now,
                expires_at: now + days * 86_400,
                capabilities: all_enterprise_capabilities(),
            };
            let tok = issue_license_token(&claims, &private_key)?;
            println!("{tok}");
        }
        LicenseAction::Verify { public_key, token } => {
            let claims = verify_license_token(&token, &public_key)?;
            println!("{}", serde_json::to_string_pretty(&claims)?);
        }
    }
    Ok(())
}
