use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as WsMsg;
use tokio_tungstenite::{connect_async_tls_with_config, Connector};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliSessionProfile {
    pub server: String,
    pub cookie: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
}

fn session_file_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
    PathBuf::from(home).join(".operquay").join("session.json")
}

pub fn save_cli_session(profile: &CliSessionProfile) -> Result<(), String> {
    let path = session_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed creating config directory: {e}"))?;
    }
    let body =
        serde_json::to_string_pretty(profile).map_err(|e| format!("serialize session: {e}"))?;
    std::fs::write(&path, body).map_err(|e| format!("failed saving CLI session: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn load_cli_session() -> Result<CliSessionProfile, String> {
    let path = session_file_path();
    let raw = std::fs::read_to_string(&path).map_err(|_| {
        format!(
            "no saved Operquay CLI session at {}; run `operquay login` first",
            path.display()
        )
    })?;
    serde_json::from_str::<CliSessionProfile>(&raw)
        .map_err(|e| format!("invalid CLI session file: {e}"))
}

/// Build strict TLS HTTP client (never skips certificate verification).
pub fn build_strict_http_client(ca_cert: Option<&Path>) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(30));
    if let Some(path) = ca_cert {
        let pem = std::fs::read(path)
            .map_err(|e| format!("failed reading CA certificate '{}': {e}", path.display()))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|e| format!("invalid CA PEM certificate: {e}"))?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build()
        .map_err(|e| format!("failed building HTTP client: {e}"))
}

fn decode_pem_certs(pem: &str) -> Vec<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(s) = rest.find(BEGIN) {
        let after = &rest[s + BEGIN.len()..];
        let Some(e) = after.find(END) else {
            break;
        };
        let b64: String = after[..e]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        if let Ok(bytes) = base64_decode(&b64) {
            out.push(bytes);
        }
        rest = &after[e + END.len()..];
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| e.to_string())
}

fn build_strict_ws_connector(
    ws_url: &str,
    ca_cert: Option<&Path>,
) -> Result<Option<Connector>, String> {
    if !ws_url.starts_with("wss://") {
        return Ok(None);
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    if let Some(path) = ca_cert {
        let pem = std::fs::read_to_string(path)
            .map_err(|e| format!("failed reading CA certificate '{}': {e}", path.display()))?;
        let ders = decode_pem_certs(&pem);
        if ders.is_empty() {
            return Err("CA certificate PEM contained no CERTIFICATE blocks".to_owned());
        }
        for der in ders {
            roots
                .add(CertificateDer::from(der))
                .map_err(|e| format!("invalid CA cert: {e}"))?;
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Some(Connector::Rustls(Arc::new(cfg))))
}

fn resolve_server_and_ca(
    server_opt: Option<&str>,
    ca_opt: Option<&Path>,
) -> Result<(String, String, Option<PathBuf>), String> {
    let saved = load_cli_session().ok();
    let server = server_opt
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_owned())
        .or_else(|| {
            saved
                .as_ref()
                .map(|p| p.server.trim_end_matches('/').to_owned())
        })
        .ok_or_else(|| {
            "server URL is required (pass --server or run `operquay login`)".to_owned()
        })?;
    let cookie = saved
        .as_ref()
        .map_or_else(String::new, |p| p.cookie.clone());
    let ca = ca_opt
        .map(Path::to_path_buf)
        .or_else(|| saved.and_then(|p| p.ca_cert_path.map(PathBuf::from)));
    Ok((server, cookie, ca))
}

fn http_to_ws_url(http_base: &str, path_and_query: &str) -> String {
    let base = http_base.trim_end_matches('/');
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_owned()
    };
    let path = path_and_query.trim_start_matches('/');
    format!("{ws_base}/{path}")
}

/// Authenticate against `/api/auth/login` with strict TLS and store session cookie (`0600`).
pub async fn run_login_cli(
    server: &str,
    email: &str,
    password: &str,
    ca_cert: Option<&Path>,
) -> Result<(), String> {
    let clean_server = server.trim().trim_end_matches('/').to_owned();
    let client = build_strict_http_client(ca_cert)?;
    let resp = client
        .post(format!("{clean_server}/api/auth/login"))
        .header("Origin", &clean_server)
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .map_err(|e| format!("login request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("login failed ({status}): {body}"));
    }

    let cookie = resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|raw| raw.split(';').next())
        .find(|kv| {
            kv.starts_with("operquay_session=") || kv.starts_with("__Host-operquay_session=")
        })
        .ok_or_else(|| "login succeeded but server did not return a session cookie".to_owned())?
        .to_owned();

    save_cli_session(&CliSessionProfile {
        server: clean_server.clone(),
        cookie,
        email: email.to_owned(),
        ca_cert_path: ca_cert.map(|p| p.display().to_string()),
    })?;
    println!("Signed in to {clean_server} as {email}.");
    Ok(())
}

/// Execute SQL query over `/api/db/query` and print DLP-redacted JSON results.
pub async fn run_db_query_cli(
    connection_id: &str,
    sql: &str,
    server: Option<&str>,
    ca_cert: Option<&Path>,
) -> Result<(), String> {
    let (srv, cookie, ca) = resolve_server_and_ca(server, ca_cert)?;
    let client = build_strict_http_client(ca.as_deref())?;
    let mut req = client
        .post(format!("{srv}/api/db/query"))
        .header("Origin", &srv)
        .json(&serde_json::json!({
            "connection_id": connection_id,
            "sql": sql,
            "read_only": true,
        }));
    if !cookie.is_empty() {
        req = req.header(reqwest::header::COOKIE, &cookie);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("db query failed: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("db query error ({status}): {text}"));
    }
    println!("{text}");
    Ok(())
}

/// Connect to a Kubernetes pod (`exec`) or list cluster pods over the Operquay control plane.
pub async fn run_kube_cli(
    cluster: &str,
    namespace: &str,
    pod: Option<&str>,
    command: &str,
    server: Option<&str>,
    ca_cert: Option<&Path>,
) -> Result<(), String> {
    let (srv, cookie, ca) = resolve_server_and_ca(server, ca_cert)?;
    let Some(pod_name) = pod.map(str::trim).filter(|p| !p.is_empty()) else {
        let client = build_strict_http_client(ca.as_deref())?;
        let mut req = client.get(format!(
            "{srv}/api/k8s/resources?cluster={cluster}&namespace={namespace}&kind=pods"
        ));
        if !cookie.is_empty() {
            req = req.header(reqwest::header::COOKIE, &cookie);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("k8s resource query failed: {e}"))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("k8s error ({status}): {body}"));
        }
        println!("{body}");
        return Ok(());
    };

    let ws_url = http_to_ws_url(
        &srv,
        &format!(
            "/api/k8s/exec?cluster={cluster}&namespace={namespace}&pod={pod_name}&command={command}"
        ),
    );
    stream_terminal_ws(&srv, &ws_url, &cookie, ca.as_deref()).await
}

/// Open an interactive AWS SSM shell terminal to `instance_id`.
pub async fn run_ssh_cli(
    instance_id: &str,
    region: &str,
    profile: &str,
    server: Option<&str>,
    ca_cert: Option<&Path>,
) -> Result<(), String> {
    let (srv, cookie, ca) = resolve_server_and_ca(server, ca_cert)?;
    let ws_url = http_to_ws_url(
        &srv,
        &format!("/api/aws/session-ws?instance_id={instance_id}&region={region}&role_id={profile}"),
    );
    stream_terminal_ws(&srv, &ws_url, &cookie, ca.as_deref()).await
}

async fn stream_terminal_ws(
    origin: &str,
    ws_url: &str,
    cookie: &str,
    ca_cert: Option<&Path>,
) -> Result<(), String> {
    let mut req = ws_url
        .into_client_request()
        .map_err(|e| format!("invalid WS URL '{ws_url}': {e}"))?;
    if !cookie.is_empty() {
        let hv = reqwest::header::HeaderValue::from_str(cookie).map_err(|e| e.to_string())?;
        req.headers_mut().insert(reqwest::header::COOKIE, hv);
    }
    let orig_hv = reqwest::header::HeaderValue::from_str(origin).map_err(|e| e.to_string())?;
    req.headers_mut().insert(reqwest::header::ORIGIN, orig_hv);

    let connector = build_strict_ws_connector(ws_url, ca_cert)?;
    let (ws, _) = connect_async_tls_with_config(req, None, false, connector)
        .await
        .map_err(|e| format!("terminal WebSocket failed: {e}"))?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(128);
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if in_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut stdout = tokio::io::stdout();
    loop {
        tokio::select! {
            msg_opt = ws_rx.next() => {
                let Some(Ok(msg)) = msg_opt else { break; };
                match msg {
                    WsMsg::Text(t) => {
                        let _ = stdout.write_all(t.as_bytes()).await;
                        let _ = stdout.flush().await;
                    }
                    WsMsg::Binary(b) => {
                        let _ = stdout.write_all(&b).await;
                        let _ = stdout.flush().await;
                    }
                    WsMsg::Close(_) => break,
                    _ => {}
                }
            }
            bytes_opt = in_rx.recv() => {
                let Some(bytes) = bytes_opt else { break; };
                let frame = serde_json::json!({
                    "type": "input",
                    "data": String::from_utf8_lossy(&bytes),
                })
                .to_string();
                if ws_tx.send(WsMsg::Text(frame.into())).await.is_err() {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Bridge newline-delimited Model Context Protocol (MCP) JSON-RPC 2.0 on stdin/stdout to
/// `POST {server}/api/mcp/rpc` authenticated via `Authorization: Bearer {token}`.
pub async fn run_mcp_stdio_proxy(
    server: &str,
    token: &str,
    ca_cert: Option<&Path>,
) -> Result<(), String> {
    let clean_server = server.trim().trim_end_matches('/');
    let endpoint = format!("{clean_server}/api/mcp/rpc");
    let client = build_strict_http_client(ca_cert)?;
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line_res in stdin.lock().lines() {
        let line = line_res.map_err(|e| format!("stdin read error: {e}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let payload: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(err) => {
                let err_resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": serde_json::Value::Null,
                    "error": { "code": -32700, "message": format!("Parse error: {err}") }
                });
                let _ = writeln!(stdout, "{err_resp}");
                let _ = stdout.flush();
                continue;
            }
        };
        let resp = client
            .post(&endpoint)
            .bearer_auth(token)
            .json(&payload)
            .send()
            .await;
        match resp {
            Ok(r) => {
                let txt = r.text().await.unwrap_or_default();
                if !txt.trim().is_empty() {
                    let _ = writeln!(stdout, "{txt}");
                    let _ = stdout.flush();
                }
            }
            Err(err) => {
                let err_resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": payload["id"].clone(),
                    "error": { "code": -32000, "message": format!("MCP proxy transport error: {err}") }
                });
                let _ = writeln!(stdout, "{err_resp}");
                let _ = stdout.flush();
            }
        }
    }
    Ok(())
}
