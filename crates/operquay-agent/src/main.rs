#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use operquay_agent::{parse_target_spec, run_agent_tunnel_once, AgentConfig};
use tokio::sync::watch;

#[derive(Debug, Parser)]
#[command(
    name = "operquay-agent",
    version,
    about = "Zero-inbound outbound mTLS reverse-tunnel daemon for on-prem & private networks"
)]
struct Cli {
    #[arg(long, env = "OPERQUAY_AGENT_SERVER")]
    server: String,

    #[arg(long, env = "OPERQUAY_AGENT_TOKEN")]
    token: String,

    #[arg(long, env = "OPERQUAY_AGENT_NAME", default_value = "onprem-agent")]
    name: String,

    #[arg(long = "target", value_name = "PROTO:HOST:PORT")]
    targets: Vec<String>,

    #[arg(long = "label", value_name = "KEY=VAL")]
    labels: Vec<String>,

    #[arg(long, env = "OPERQUAY_AGENT_CA_CERT")]
    ca_cert: Option<PathBuf>,

    #[arg(long, env = "OPERQUAY_AGENT_CLIENT_CERT")]
    client_cert: Option<PathBuf>,

    #[arg(long, env = "OPERQUAY_AGENT_CLIENT_KEY")]
    client_key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let mut targets = Vec::with_capacity(cli.targets.len());
    for raw in &cli.targets {
        targets.push(parse_target_spec(raw)?);
    }
    let mut labels = HashMap::new();
    for raw in &cli.labels {
        if let Some((k, v)) = raw.split_once('=') {
            labels.insert(k.trim().to_owned(), v.trim().to_owned());
        }
    }
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| cli.name.clone());
    let cfg = AgentConfig {
        server_url: cli.server,
        enrollment_token: cli.token,
        name: cli.name,
        hostname,
        labels,
        targets,
        ca_cert_path: cli.ca_cert,
        client_cert_path: cli.client_cert,
        client_key_path: cli.client_key,
    };

    let (shut_tx, shut_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shut_tx.send(true);
    });

    let mut backoff = Duration::from_secs(1);
    loop {
        if *shut_rx.borrow() {
            break;
        }
        match run_agent_tunnel_once(&cfg, shut_rx.clone()).await {
            Ok(()) => {
                backoff = Duration::from_secs(1);
                if *shut_rx.borrow() {
                    break;
                }
                tracing::info!("agent tunnel disconnected cleanly; reconnecting");
            }
            Err(err) => {
                tracing::warn!(error = %err, backoff_secs = backoff.as_secs(), "agent tunnel error; backing off");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }

    Ok(())
}
