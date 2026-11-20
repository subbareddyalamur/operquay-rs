#![forbid(unsafe_code)]

//! Bounded, non-blocking real-time SIEM audit log streaming (`M10.1`).
//!
//! Dispatches [`AuditEvent`] records over a bounded `mpsc::channel(1024)` to one or more
//! configured enterprise sinks without blocking control-plane request handling:
//! - OpenTelemetry Logs OTLP HTTP/JSON (`OPERQUAY_SIEM_OTLP_URL`)
//! - Splunk HTTP Event Collector (`OPERQUAY_SIEM_SPLUNK_URL` + `OPERQUAY_SIEM_SPLUNK_TOKEN`)
//! - Datadog Logs HTTP Intake (`OPERQUAY_SIEM_DATADOG_API_KEY` + optional `OPERQUAY_SIEM_DATADOG_URL`)
//! - RFC 5424 Syslog over `udp://`, `tcp://`, or `tls://` (`OPERQUAY_SIEM_SYSLOG_ADDR`)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

use crate::stores::AuditEvent;

const DEFAULT_SIEM_CHANNEL_CAPACITY: usize = 1024;
const DEFAULT_DATADOG_LOGS_URL: &str = "https://http-intake.logs.datadoghq.com/api/v2/logs";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyslogTransport {
    Udp,
    Tcp,
    Tls,
}

#[derive(Debug, Clone)]
pub enum SiemTarget {
    OtlpHttp {
        url: String,
        bearer_token: Option<String>,
    },
    SplunkHec {
        url: String,
        token: String,
    },
    DatadogLogs {
        url: String,
        api_key: String,
    },
    SyslogRfc5424 {
        transport: SyslogTransport,
        host_port: String,
    },
}

impl SiemTarget {
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::OtlpHttp { url, .. } => format!("otlp:{url}"),
            Self::SplunkHec { url, .. } => format!("splunk:{url}"),
            Self::DatadogLogs { url, .. } => format!("datadog:{url}"),
            Self::SyslogRfc5424 {
                transport,
                host_port,
            } => {
                let proto = match transport {
                    SyslogTransport::Udp => "udp",
                    SyslogTransport::Tcp => "tcp",
                    SyslogTransport::Tls => "tls",
                };
                format!("syslog:{proto}://{host_port}")
            }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiemStats {
    pub enabled: bool,
    pub targets: Vec<String>,
    pub enqueued: u64,
    pub delivered: u64,
    pub dropped: u64,
    pub failed: u64,
}

#[derive(Debug, Default)]
struct SiemCounters {
    enqueued: AtomicU64,
    delivered: AtomicU64,
    dropped: AtomicU64,
    failed: AtomicU64,
}

#[derive(Debug)]
pub struct SiemDispatcher {
    tx: mpsc::Sender<AuditEvent>,
    target_labels: Vec<String>,
    counters: Arc<SiemCounters>,
}

impl SiemDispatcher {
    /// Discover configured SIEM targets from environment variables and spawn the background
    /// bounded worker if at least one sink is configured.
    #[must_use]
    pub fn spawn_from_env() -> Option<Self> {
        let targets = parse_targets_from_env();
        if targets.is_empty() {
            return None;
        }
        Some(Self::spawn_with_targets(targets))
    }

    /// Spawn a SIEM dispatcher for an explicit list of targets using the default `1024`-slot
    /// bounded channel.
    #[must_use]
    pub fn spawn_with_targets(targets: Vec<SiemTarget>) -> Self {
        Self::spawn_with_targets_and_capacity(targets, DEFAULT_SIEM_CHANNEL_CAPACITY)
    }

    /// Spawn a SIEM dispatcher with an explicit bounded channel capacity (never unbounded).
    #[must_use]
    pub fn spawn_with_targets_and_capacity(targets: Vec<SiemTarget>, capacity: usize) -> Self {
        let cap = capacity.max(1);
        let (tx, rx) = mpsc::channel(cap);
        let target_labels: Vec<String> = targets.iter().map(SiemTarget::label).collect();
        let counters = Arc::new(SiemCounters::default());
        let worker_counters = Arc::clone(&counters);
        tokio::spawn(run_siem_worker(rx, targets, worker_counters));
        Self {
            tx,
            target_labels,
            counters,
        }
    }

    /// Enqueue an [`AuditEvent`] for non-blocking background SIEM delivery.
    /// Returns `true` if queued, or `false` if the bounded buffer is full (increments `dropped`).
    #[must_use]
    pub fn try_emit(&self, ev: AuditEvent) -> bool {
        if self.tx.try_send(ev).is_ok() {
            self.counters.enqueued.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    #[must_use]
    pub fn stats(&self) -> SiemStats {
        SiemStats {
            enabled: !self.target_labels.is_empty(),
            targets: self.target_labels.clone(),
            enqueued: self.counters.enqueued.load(Ordering::Relaxed),
            delivered: self.counters.delivered.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
            failed: self.counters.failed.load(Ordering::Relaxed),
        }
    }
}

#[must_use]
pub fn parse_targets_from_env() -> Vec<SiemTarget> {
    let mut targets = Vec::new();
    if let Ok(url) = std::env::var("OPERQUAY_SIEM_OTLP_URL") {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            let token = std::env::var("OPERQUAY_SIEM_OTLP_TOKEN")
                .ok()
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty());
            targets.push(SiemTarget::OtlpHttp {
                url: trimmed.to_owned(),
                bearer_token: token,
            });
        }
    }
    if let (Ok(url), Ok(token)) = (
        std::env::var("OPERQUAY_SIEM_SPLUNK_URL"),
        std::env::var("OPERQUAY_SIEM_SPLUNK_TOKEN"),
    ) {
        let u = url.trim();
        let t = token.trim();
        if !u.is_empty() && !t.is_empty() {
            targets.push(SiemTarget::SplunkHec {
                url: u.to_owned(),
                token: t.to_owned(),
            });
        }
    }
    if let Ok(api_key) = std::env::var("OPERQUAY_SIEM_DATADOG_API_KEY") {
        let key = api_key.trim();
        if !key.is_empty() {
            let url = std::env::var("OPERQUAY_SIEM_DATADOG_URL")
                .ok()
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| DEFAULT_DATADOG_LOGS_URL.to_owned());
            targets.push(SiemTarget::DatadogLogs {
                url,
                api_key: key.to_owned(),
            });
        }
    }
    if let Ok(addr) = std::env::var("OPERQUAY_SIEM_SYSLOG_ADDR") {
        if let Some(target) = parse_syslog_addr(&addr) {
            targets.push(target);
        }
    }
    targets
}

#[must_use]
pub fn parse_syslog_addr(raw: &str) -> Option<SiemTarget> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(hp) = trimmed.strip_prefix("udp://") {
        let hp = hp.trim();
        (!hp.is_empty()).then(|| SiemTarget::SyslogRfc5424 {
            transport: SyslogTransport::Udp,
            host_port: hp.to_owned(),
        })
    } else if let Some(hp) = trimmed.strip_prefix("tcp://") {
        let hp = hp.trim();
        (!hp.is_empty()).then(|| SiemTarget::SyslogRfc5424 {
            transport: SyslogTransport::Tcp,
            host_port: hp.to_owned(),
        })
    } else if let Some(hp) = trimmed.strip_prefix("tls://") {
        let hp = hp.trim();
        (!hp.is_empty()).then(|| SiemTarget::SyslogRfc5424 {
            transport: SyslogTransport::Tls,
            host_port: hp.to_owned(),
        })
    } else {
        Some(SiemTarget::SyslogRfc5424 {
            transport: SyslogTransport::Tcp,
            host_port: trimmed.to_owned(),
        })
    }
}

fn sanitize_sd_param_val(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' | '\\' | ']' => {
                out.push('\\');
                out.push(ch);
            }
            '\n' | '\r' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

fn sanitize_msgid(s: &str) -> String {
    let cleaned: String = s.chars().filter(char::is_ascii_graphic).take(32).collect();
    if cleaned.is_empty() {
        "-".to_owned()
    } else {
        cleaned
    }
}

/// Format an [`AuditEvent`] according to RFC 5424 Syslog (facility local0=16, severity info=6 -> PRI 134).
#[must_use]
pub fn format_rfc5424_syslog(ev: &AuditEvent) -> String {
    let ts = if ev.timestamp.trim().is_empty() {
        "-"
    } else {
        ev.timestamp.trim()
    };
    let msgid = sanitize_msgid(&ev.action);
    let sd_tenant = sanitize_sd_param_val(&ev.tenant_id);
    let sd_hash = sanitize_sd_param_val(&ev.entry_hash);
    let payload = serde_json::to_string(ev).unwrap_or_else(|_| "{}".to_owned());
    format!(
        "<134>1 {ts} operquay-rust audit - {msgid} [operquay@55555 tenant=\"{sd_tenant}\" seq=\"{}\" hash=\"{sd_hash}\"] {payload}\n",
        ev.seq
    )
}

async fn run_siem_worker(
    mut rx: mpsc::Receiver<AuditEvent>,
    targets: Vec<SiemTarget>,
    counters: Arc<SiemCounters>,
) {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();
    while let Some(ev) = rx.recv().await {
        for target in &targets {
            match deliver_to_target(&http, target, &ev).await {
                Ok(()) => {
                    counters.delivered.fetch_add(1, Ordering::Relaxed);
                }
                Err(err) => {
                    counters.failed.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(target = %target.label(), error = %err, "SIEM delivery failed");
                }
            }
        }
    }
}

async fn deliver_to_target(
    http: &reqwest::Client,
    target: &SiemTarget,
    ev: &AuditEvent,
) -> Result<(), String> {
    match target {
        SiemTarget::OtlpHttp { url, bearer_token } => {
            let body = build_otlp_logs_json(ev);
            let mut req = http.post(url).json(&body);
            if let Some(tok) = bearer_token {
                req = req.bearer_auth(tok);
            }
            let res = req.send().await.map_err(|e| format!("otlp send: {e}"))?;
            if !res.status().is_success() {
                return Err(format!("otlp status {}", res.status()));
            }
            Ok(())
        }
        SiemTarget::SplunkHec { url, token } => {
            let time_secs = (ev.ts_ms as f64) / 1000.0;
            let payload = serde_json::json!({
                "time": time_secs,
                "host": "operquay-rust",
                "source": "operquay",
                "sourcetype": "operquay:audit",
                "event": ev,
            });
            let res = http
                .post(url)
                .header(reqwest::header::AUTHORIZATION, format!("Splunk {token}"))
                .json(&payload)
                .send()
                .await
                .map_err(|e| format!("splunk hec send: {e}"))?;
            if !res.status().is_success() {
                return Err(format!("splunk hec status {}", res.status()));
            }
            Ok(())
        }
        SiemTarget::DatadogLogs { url, api_key } => {
            let msg = format!(
                "{} protocol={} target={} outcome={} seq={}",
                ev.action, ev.protocol, ev.target_host, ev.outcome, ev.seq
            );
            let payload = serde_json::json!([{
                "ddsource": "operquay",
                "ddtags": format!("tenant:{},outcome:{}", ev.tenant_id, ev.outcome),
                "hostname": "operquay-rust",
                "service": "operquay-control-plane",
                "message": msg,
                "audit": ev,
            }]);
            let res = http
                .post(url)
                .header("DD-API-KEY", api_key)
                .json(&payload)
                .send()
                .await
                .map_err(|e| format!("datadog send: {e}"))?;
            if !res.status().is_success() {
                return Err(format!("datadog status {}", res.status()));
            }
            Ok(())
        }
        SiemTarget::SyslogRfc5424 {
            transport,
            host_port,
        } => {
            let line = format_rfc5424_syslog(ev);
            send_syslog_line(transport, host_port, line.as_bytes()).await
        }
    }
}

fn build_otlp_logs_json(ev: &AuditEvent) -> serde_json::Value {
    let time_ns = u128::from(ev.ts_ms) * 1_000_000;
    let body_str = serde_json::to_string(ev).unwrap_or_else(|_| ev.action.clone());
    serde_json::json!({
        "resourceLogs": [{
            "resource": {
                "attributes": [
                    { "key": "service.name", "value": { "stringValue": "operquay-rust" } },
                    { "key": "tenant.id", "value": { "stringValue": ev.tenant_id } }
                ]
            },
            "scopeLogs": [{
                "scope": { "name": "operquay.audit" },
                "logRecords": [{
                    "timeUnixNano": time_ns.to_string(),
                    "severityNumber": 9,
                    "severityText": "INFO",
                    "body": { "stringValue": body_str },
                    "attributes": [
                        { "key": "audit.seq", "value": { "intValue": ev.seq.to_string() } },
                        { "key": "audit.action", "value": { "stringValue": ev.action } },
                        { "key": "audit.outcome", "value": { "stringValue": ev.outcome } },
                        { "key": "audit.entry_hash", "value": { "stringValue": ev.entry_hash } },
                        { "key": "audit.prev_hash", "value": { "stringValue": ev.prev_hash } }
                    ],
                    "traceId": ev.trace_id
                }]
            }]
        }]
    })
}

async fn send_syslog_line(
    transport: &SyslogTransport,
    host_port: &str,
    line: &[u8],
) -> Result<(), String> {
    match transport {
        SyslogTransport::Udp => {
            let bind_addr = if host_port.starts_with('[') || host_port.contains("::") {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let sock = UdpSocket::bind(bind_addr)
                .await
                .map_err(|e| format!("syslog udp bind: {e}"))?;
            sock.send_to(line, host_port)
                .await
                .map_err(|e| format!("syslog udp send: {e}"))?;
            Ok(())
        }
        SyslogTransport::Tcp => {
            let mut stream =
                tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(host_port))
                    .await
                    .map_err(|_| "syslog tcp connect timed out".to_owned())?
                    .map_err(|e| format!("syslog tcp connect: {e}"))?;
            stream
                .write_all(line)
                .await
                .map_err(|e| format!("syslog tcp write: {e}"))?;
            stream
                .shutdown()
                .await
                .map_err(|e| format!("syslog tcp shutdown: {e}"))?;
            Ok(())
        }
        SyslogTransport::Tls => {
            let host = host_port
                .rsplit_once(':')
                .map_or(host_port, |(h, _)| h)
                .trim_matches(['[', ']'])
                .to_owned();
            let server_name =
                ServerName::try_from(host).map_err(|e| format!("syslog tls server name: {e}"))?;
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("syslog tls versions: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));
            let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(host_port))
                .await
                .map_err(|_| "syslog tls tcp connect timed out".to_owned())?
                .map_err(|e| format!("syslog tls tcp connect: {e}"))?;
            let mut tls = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| format!("syslog tls handshake: {e}"))?;
            tls.write_all(line)
                .await
                .map_err(|e| format!("syslog tls write: {e}"))?;
            tls.shutdown()
                .await
                .map_err(|e| format!("syslog tls shutdown: {e}"))?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use axum::{Json, Router};
    use tokio::io::AsyncReadExt as _;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    fn sample_event(seq: u64) -> AuditEvent {
        AuditEvent {
            id: format!("ev-{seq}"),
            ts_ms: 1_700_000_000_000 + seq,
            timestamp: "2026-11-19T12:00:00Z".to_owned(),
            tenant_id: "acme".to_owned(),
            trace_id: "0123456789abcdef0123456789abcdef".to_owned(),
            session_id: "sess-1".to_owned(),
            action: "session_launch".to_owned(),
            protocol: "rdp".to_owned(),
            target_host: "10.0.1.10".to_owned(),
            detail: "launched".to_owned(),
            details: "launched".to_owned(),
            user_id: "u1".to_owned(),
            user_email: "alice@acme.test".to_owned(),
            role: "admin".to_owned(),
            ip: "198.51.100.1".to_owned(),
            outcome: "success".to_owned(),
            method: "POST".to_owned(),
            status_code: 200,
            user_agent: "operquay-test".to_owned(),
            client: "198.51.100.1".to_owned(),
            instance_id: "i-0abc".to_owned(),
            instance_name: "win-bastion".to_owned(),
            profile: "prod".to_owned(),
            region: "us-east-1".to_owned(),
            recording_id: Some("rec-1".to_owned()),
            recording: Some("rec-1".to_owned()),
            seq,
            prev_hash: "0".repeat(64),
            entry_hash: "a".repeat(64),
        }
    }

    #[tokio::test]
    async fn streams_to_otlp_splunk_datadog_and_syslog_over_loopback() {
        let received = Arc::new(Mutex::new(Vec::<(String, String, serde_json::Value)>::new()));
        let rec_otlp = Arc::clone(&received);
        let rec_splunk = Arc::clone(&received);
        let rec_dd = Arc::clone(&received);

        let app = Router::new()
            .route(
                "/otlp/v1/logs",
                post(
                    move |headers: HeaderMap, Json(body): Json<serde_json::Value>| {
                        let rec = Arc::clone(&rec_otlp);
                        async move {
                            let auth = headers
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_owned();
                            rec.lock().await.push(("otlp".to_owned(), auth, body));
                            StatusCode::OK
                        }
                    },
                ),
            )
            .route(
                "/services/collector/event",
                post(
                    move |headers: HeaderMap, Json(body): Json<serde_json::Value>| {
                        let rec = Arc::clone(&rec_splunk);
                        async move {
                            let auth = headers
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_owned();
                            rec.lock().await.push(("splunk".to_owned(), auth, body));
                            StatusCode::OK
                        }
                    },
                ),
            )
            .route(
                "/api/v2/logs",
                post(
                    move |headers: HeaderMap, Json(body): Json<serde_json::Value>| {
                        let rec = Arc::clone(&rec_dd);
                        async move {
                            let key = headers
                                .get("dd-api-key")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_owned();
                            rec.lock().await.push(("datadog".to_owned(), key, body));
                            StatusCode::ACCEPTED
                        }
                    },
                ),
            );

        let http_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(http_ln, app).await;
        });

        let tcp_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_ln.local_addr().unwrap();
        let tcp_lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let tcp_lines_srv = Arc::clone(&tcp_lines);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp_ln.accept().await {
                let out = Arc::clone(&tcp_lines_srv);
                tokio::spawn(async move {
                    let mut buf = String::new();
                    let _ = stream.read_to_string(&mut buf).await;
                    out.lock().await.push(buf);
                });
            }
        });

        let udp_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_sock.local_addr().unwrap();
        let udp_lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let udp_lines_srv = Arc::clone(&udp_lines);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            if let Ok((n, _)) = udp_sock.recv_from(&mut buf).await {
                let msg = String::from_utf8_lossy(&buf[..n]).into_owned();
                udp_lines_srv.lock().await.push(msg);
            }
        });

        let dispatcher = SiemDispatcher::spawn_with_targets(vec![
            SiemTarget::OtlpHttp {
                url: format!("http://{http_addr}/otlp/v1/logs"),
                bearer_token: Some("otlp-tok".to_owned()),
            },
            SiemTarget::SplunkHec {
                url: format!("http://{http_addr}/services/collector/event"),
                token: "hec-secret".to_owned(),
            },
            SiemTarget::DatadogLogs {
                url: format!("http://{http_addr}/api/v2/logs"),
                api_key: "dd-key-123".to_owned(),
            },
            SiemTarget::SyslogRfc5424 {
                transport: SyslogTransport::Tcp,
                host_port: tcp_addr.to_string(),
            },
            SiemTarget::SyslogRfc5424 {
                transport: SyslogTransport::Udp,
                host_port: udp_addr.to_string(),
            },
        ]);

        assert!(dispatcher.try_emit(sample_event(1)));

        for _ in 0..40 {
            let stats = dispatcher.stats();
            if stats.delivered == 5
                && !tcp_lines.lock().await.is_empty()
                && !udp_lines.lock().await.is_empty()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let stats = dispatcher.stats();
        assert!(stats.enabled);
        assert_eq!(stats.enqueued, 1);
        assert_eq!(stats.delivered, 5);
        assert_eq!(stats.failed, 0);
        assert_eq!(stats.dropped, 0);

        let guard = received.lock().await;
        assert_eq!(guard.len(), 3);
        assert!(guard
            .iter()
            .any(|(k, auth, _)| k == "otlp" && auth == "Bearer otlp-tok"));
        assert!(guard
            .iter()
            .any(|(k, auth, _)| k == "splunk" && auth == "Splunk hec-secret"));
        assert!(guard
            .iter()
            .any(|(k, key, _)| k == "datadog" && key == "dd-key-123"));

        let tcp_msg = &tcp_lines.lock().await[0];
        assert!(tcp_msg.starts_with("<134>1 2026-11-19T12:00:00Z operquay-rust audit - session_launch [operquay@55555 tenant=\"acme\" seq=\"1\""));
        let udp_msg = &udp_lines.lock().await[0];
        assert!(udp_msg.starts_with("<134>1 "));
    }

    #[tokio::test]
    async fn bounded_channel_drops_gracefully_instead_of_blocking() {
        let (tx, _rx) = mpsc::channel(1);
        let dispatcher = SiemDispatcher {
            tx,
            target_labels: vec!["test".to_owned()],
            counters: Arc::new(SiemCounters::default()),
        };
        assert!(dispatcher.try_emit(sample_event(1)));
        assert!(!dispatcher.try_emit(sample_event(2)));
        let stats = dispatcher.stats();
        assert_eq!(stats.enqueued, 1);
        assert_eq!(stats.dropped, 1);
    }
}
