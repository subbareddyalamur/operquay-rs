#![forbid(unsafe_code)]

//! Native Teleport v17 `WebAPI` + Kubernetes proxy mTLS connector (`#![forbid(unsafe_code)]`).
//!
//! Uses only HTTPS JSON APIs and pure-Rust `rcgen` P-256 key generation without invoking any
//! external `tsh` or CLI binary.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use reqwest::header::{COOKIE, SET_COOKIE};
use serde::Deserialize;
use uuid::Uuid;

const CERT_TTL_NS: i64 = 43_200_000_000_000; // 12 hours in nanoseconds (Go time.Duration)
const CERT_TTL_SECS: u64 = 43_200;

#[derive(Debug, Clone)]
pub struct TeleportPingInfo {
    pub proxy_base: String,
    pub cluster_name: String,
    pub auth_type: String,
    pub second_factor: String,
    pub kube_api_base: String,
}

#[derive(Debug, Clone)]
pub struct TeleportLoginOutcome {
    pub teleport_cluster: String,
    pub kube_api_base: String,
    pub username: String,
    pub clusters: Vec<String>,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub ca_data_b64: String,
    pub expires_at: u64,
}

#[derive(Debug, Deserialize)]
struct RawPingResponse {
    #[serde(default)]
    cluster_name: String,
    #[serde(default)]
    auth: RawPingAuth,
    #[serde(default)]
    proxy: RawPingProxy,
}

#[derive(Debug, Default, Deserialize)]
struct RawPingAuth {
    #[serde(rename = "type", default)]
    auth_type: String,
    #[serde(default)]
    second_factor: String,
}

#[derive(Debug, Default, Deserialize)]
struct RawPingProxy {
    #[serde(default)]
    tls_routing_enabled: bool,
    #[serde(default)]
    kube: RawPingKube,
}

#[derive(Debug, Default, Deserialize)]
struct RawPingKube {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    listen_addr: String,
    #[serde(default)]
    public_addr: String,
}

#[derive(Debug, Deserialize)]
struct RawSshLoginResponse {
    #[serde(default)]
    username: String,
    #[serde(default)]
    tls_cert: String,
    #[serde(default)]
    host_signers: Vec<RawHostSigner>,
}

#[derive(Debug, Deserialize)]
struct RawHostSigner {
    #[serde(default)]
    tls_certs: Vec<String>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Normalize a user-supplied Teleport proxy URL into a safe base `https://host[:port]` URL.
///
/// Only permits `http://127.0.0.1` or `http://localhost` for local loopback tests; any other host
/// must use HTTPS.
pub fn normalize_proxy_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("Teleport proxy URL is required".to_owned());
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err("Teleport proxy URL contains invalid whitespace".to_owned());
    }
    let with_scheme = if trimmed.starts_with("https://") {
        trimmed.to_owned()
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        let host = rest.split(['/', ':', '?']).next().unwrap_or("");
        if host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" {
            trimmed.to_owned()
        } else {
            return Err(
                "Plaintext http:// is only allowed for localhost Teleport proxies".to_owned(),
            );
        }
    } else {
        format!("https://{trimmed}")
    };
    let parsed = reqwest::Url::parse(&with_scheme)
        .map_err(|e| format!("Invalid Teleport proxy URL '{trimmed}': {e}"))?;
    let Some(host) = parsed.host_str() else {
        return Err("Teleport proxy URL is missing host".to_owned());
    };
    let mut base = format!("{}://{host}", parsed.scheme());
    if let Some(port) = parsed.port() {
        base.push(':');
        base.push_str(&port.to_string());
    }
    Ok(base)
}

/// Extract a human-readable error message from a Teleport `WebAPI` JSON or text response.
#[must_use]
pub fn extract_teleport_error(status: reqwest::StatusCode, body: &str) -> String {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(msg) = val["error"]["message"]
            .as_str()
            .or_else(|| val["error"].as_str())
            .or_else(|| val["message"].as_str())
        {
            let m = msg.trim();
            if !m.is_empty() {
                return m.to_owned();
            }
        }
    }
    let trimmed = body.trim();
    if !trimmed.is_empty() {
        return format!(
            "Teleport proxy returned HTTP {}: {trimmed}",
            status.as_u16()
        );
    }
    format!("Teleport proxy returned HTTP {}", status.as_u16())
}

fn compute_kube_api_base(
    proxy_base: &str,
    kube: &RawPingKube,
    tls_routing_enabled: bool,
) -> String {
    let public_addr = kube.public_addr.trim().trim_end_matches('/');
    if !public_addr.is_empty() {
        if public_addr.starts_with("https://") || public_addr.starts_with("http://") {
            return public_addr.to_owned();
        }
        return format!("https://{public_addr}");
    }
    if tls_routing_enabled {
        return proxy_base.to_owned();
    }
    if let Ok(parsed) = reqwest::Url::parse(proxy_base) {
        let scheme = parsed.scheme();
        if let Some(host) = parsed.host_str() {
            let listen_port = kube
                .listen_addr
                .trim()
                .rsplit(':')
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .filter(|&p| p > 0);
            if let Some(port) = listen_port {
                return format!("{scheme}://{host}:{port}");
            }
            if !kube.enabled && parsed.port().is_some() {
                return proxy_base.to_owned();
            }
            return format!("{scheme}://{host}:3026");
        }
    }
    proxy_base.to_owned()
}

/// Query `GET /webapi/ping` on a Teleport proxy to discover auth settings, cluster name, and Kube API URL.
pub async fn ping_teleport(
    http: &reqwest::Client,
    proxy_url: &str,
) -> Result<TeleportPingInfo, String> {
    let base = normalize_proxy_url(proxy_url)?;
    let url = format!("{base}/webapi/ping");
    let res = http
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Failed connecting to Teleport proxy '{base}': {e}"))?;
    let status = res.status();
    let txt = res
        .text()
        .await
        .map_err(|e| format!("Failed reading Teleport ping response: {e}"))?;
    if !status.is_success() {
        return Err(extract_teleport_error(status, &txt));
    }
    let raw: RawPingResponse =
        serde_json::from_str(&txt).map_err(|e| format!("Invalid Teleport ping JSON: {e}"))?;
    let kube_api_base =
        compute_kube_api_base(&base, &raw.proxy.kube, raw.proxy.tls_routing_enabled);
    Ok(TeleportPingInfo {
        proxy_base: base,
        cluster_name: raw.cluster_name,
        auth_type: raw.auth.auth_type,
        second_factor: raw.auth.second_factor,
        kube_api_base,
    })
}

async fn mint_cluster_mtls_certs(
    http: &reqwest::Client,
    ping: &TeleportPingInfo,
    username: &str,
    password: &str,
    otp: &str,
    kube_cluster: &str,
) -> Result<(String, String, String, String), String> {
    // Step 1: Begin login challenge to confirm credentials and inspect MFA requirements.
    let begin_url = format!("{}/v1/webapi/mfa/login/begin", ping.proxy_base);
    let begin_res = http
        .post(&begin_url)
        .json(&serde_json::json!({
            "user": username,
            "pass": password,
        }))
        .send()
        .await
        .map_err(|e| format!("Teleport MFA begin failed: {e}"))?;
    let begin_status = begin_res.status();
    let begin_txt = begin_res
        .text()
        .await
        .map_err(|e| format!("Failed reading Teleport MFA begin response: {e}"))?;
    if !begin_status.is_success() {
        return Err(extract_teleport_error(begin_status, &begin_txt));
    }
    let begin_val: serde_json::Value = serde_json::from_str(&begin_txt).unwrap_or_default();
    let totp_challenge = begin_val["totp_challenge"].as_bool().unwrap_or(false);
    let has_webauthn = !begin_val["webauthn_challenge"].is_null();
    let otp_trimmed = otp.trim();
    if otp_trimmed.is_empty() && (totp_challenge || has_webauthn || ping.second_factor == "on") {
        if !totp_challenge && has_webauthn {
            return Err(
                "This Teleport cluster enforces hardware WebAuthn passkeys and no TOTP MFA device responded. Enroll a TOTP authenticator in Teleport (tsh mfa add --type=TOTP) or upload a kubeconfig."
                    .to_owned(),
            );
        }
        return Err("MFA verification code (TOTP) is required to sign in to Teleport.".to_owned());
    }

    // Step 2: Generate an ephemeral pure-Rust P-256 ECDSA keypair for short-lived mTLS certs.
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| format!("Failed generating ephemeral Teleport TLS keypair: {e}"))?;
    let pub_pem = key_pair.public_key_pem();
    let priv_pem = key_pair.serialize_pem();
    let tls_pub_key_b64 = STANDARD.encode(pub_pem.as_bytes());

    // Step 3: Finish MFA login and retrieve signed X.509 client cert + Teleport host CAs.
    let finish_url = format!("{}/v1/webapi/mfa/login/finish", ping.proxy_base);
    let mut finish_body = serde_json::json!({
        "user": username,
        "password": password,
        "totp_code": otp_trimmed,
        "tls_pub_key": tls_pub_key_b64,
        "ttl": CERT_TTL_NS,
        "RouteToCluster": ping.cluster_name,
    });
    if !kube_cluster.trim().is_empty() {
        finish_body["KubernetesCluster"] =
            serde_json::Value::String(kube_cluster.trim().to_owned());
    }
    let finish_res = http
        .post(&finish_url)
        .json(&finish_body)
        .send()
        .await
        .map_err(|e| format!("Teleport MFA finish failed: {e}"))?;
    let finish_status = finish_res.status();
    let finish_txt = finish_res
        .text()
        .await
        .map_err(|e| format!("Failed reading Teleport MFA finish response: {e}"))?;
    if !finish_status.is_success() {
        return Err(extract_teleport_error(finish_status, &finish_txt));
    }
    let signed: RawSshLoginResponse = serde_json::from_str(&finish_txt)
        .map_err(|e| format!("Invalid Teleport login finish JSON: {e}"))?;
    let cert_bytes = STANDARD
        .decode(signed.tls_cert.trim())
        .map_err(|e| format!("Invalid base64 tls_cert from Teleport: {e}"))?;
    let client_cert_pem = String::from_utf8(cert_bytes)
        .map_err(|e| format!("Non-UTF8 tls_cert PEM from Teleport: {e}"))?;
    if client_cert_pem.trim().is_empty() {
        return Err("Teleport returned an empty TLS client certificate".to_owned());
    }

    let mut ca_bundle = String::new();
    for signer in signed.host_signers {
        for ca_b64 in signer.tls_certs {
            if let Ok(decoded) = STANDARD.decode(ca_b64.trim()) {
                if let Ok(ca_pem) = String::from_utf8(decoded) {
                    if !ca_bundle.is_empty() && !ca_bundle.ends_with('\n') {
                        ca_bundle.push('\n');
                    }
                    ca_bundle.push_str(ca_pem.trim());
                }
            }
        }
    }
    let ca_data_b64 = if ca_bundle.is_empty() {
        String::new()
    } else {
        STANDARD.encode(ca_bundle.as_bytes())
    };
    let resolved_user = if signed.username.is_empty() {
        username.to_owned()
    } else {
        signed.username
    };
    Ok((resolved_user, client_cert_pem, priv_pem, ca_data_b64))
}

async fn create_web_session_and_list_kubes(
    http: &reqwest::Client,
    ping: &TeleportPingInfo,
    username: &str,
    password: &str,
    otp: &str,
) -> Result<Vec<String>, String> {
    let mut csrf_bytes = [0u8; 32];
    csrf_bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    csrf_bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    let csrf_hex = hex::encode(csrf_bytes);

    let mut body = serde_json::json!({
        "user": username,
        "pass": password,
    });
    if !otp.trim().is_empty() {
        body["second_factor_token"] = serde_json::Value::String(otp.trim().to_owned());
    }

    let sess_url = format!("{}/v1/webapi/sessions/web", ping.proxy_base);
    let sess_res = http
        .post(&sess_url)
        .header(COOKIE, format!("__Host-grv_csrf={csrf_hex}"))
        .header("X-CSRF-Token", &csrf_hex)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Teleport web session request failed: {e}"))?;

    let sess_status = sess_res.status();
    let mut cookie_pairs = Vec::new();
    for val in sess_res.headers().get_all(SET_COOKIE) {
        if let Ok(s) = val.to_str() {
            if let Some(kv) = s.split(';').next() {
                let kv = kv.trim();
                if !kv.is_empty() {
                    cookie_pairs.push(kv.to_owned());
                }
            }
        }
    }
    let sess_txt = sess_res
        .text()
        .await
        .map_err(|e| format!("Failed reading Teleport web session response: {e}"))?;
    if !sess_status.is_success() {
        return Err(extract_teleport_error(sess_status, &sess_txt));
    }
    let sess_val: serde_json::Value = serde_json::from_str(&sess_txt).unwrap_or_default();
    let bearer_token = sess_val["token"].as_str().unwrap_or("").trim().to_owned();

    let cluster_site = if ping.cluster_name.is_empty() {
        "localhost"
    } else {
        ping.cluster_name.as_str()
    };
    let kubes_url = format!(
        "{}/v1/webapi/sites/{cluster_site}/kubernetes",
        ping.proxy_base
    );
    let mut req = http.get(&kubes_url);
    if !bearer_token.is_empty() {
        req = req.bearer_auth(&bearer_token);
    }
    if !cookie_pairs.is_empty() {
        req = req.header(COOKIE, cookie_pairs.join("; "));
    }
    let kubes_res = req
        .send()
        .await
        .map_err(|e| format!("Teleport Kubernetes discovery failed: {e}"))?;
    let kubes_status = kubes_res.status();
    let kubes_txt = kubes_res
        .text()
        .await
        .map_err(|e| format!("Failed reading Teleport Kubernetes cluster list: {e}"))?;
    if !kubes_status.is_success() {
        return Err(extract_teleport_error(kubes_status, &kubes_txt));
    }
    let kubes_val: serde_json::Value = serde_json::from_str(&kubes_txt)
        .map_err(|e| format!("Invalid Teleport Kubernetes list JSON: {e}"))?;
    let items = kubes_val["items"]
        .as_array()
        .ok_or_else(|| "Teleport did not return Kubernetes cluster items".to_owned())?;
    let clusters: Vec<String> = items
        .iter()
        .filter_map(|item| {
            item["name"]
                .as_str()
                .or_else(|| item["metadata"]["name"].as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
        })
        .collect();
    if clusters.is_empty() {
        return Err(
            "No permitted Kubernetes clusters were returned for your Teleport user.".to_owned(),
        );
    }
    Ok(clusters)
}

/// Authenticate locally against a Teleport Proxy via `WebAPI` (`ping` -> `mfa/login` or `sessions/web`).
///
/// Honors single-use TOTP tokens:
/// - When `requested_cluster` is provided, mints a cluster-scoped mTLS certificate directly using
///   `/v1/webapi/mfa/login/begin` + `/v1/webapi/mfa/login/finish`.
/// - When `requested_cluster` is empty (Discovery Hub), creates a web session to enumerate permitted
///   Kubernetes clusters without burning a second TOTP replay; if password-only (empty OTP), also
///   mints a cert for the first discovered cluster.
pub async fn teleport_local_login(
    proxy_url: &str,
    username: &str,
    password: &str,
    otp: &str,
    requested_cluster: &str,
) -> Result<TeleportLoginOutcome, String> {
    let user = username.trim();
    if user.is_empty() {
        return Err("Teleport username is required".to_owned());
    }
    if password.is_empty() {
        return Err("Teleport password is required".to_owned());
    }
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("Failed creating Teleport HTTP client: {e}"))?;

    let ping = ping_teleport(&http, proxy_url).await?;
    let req_cluster = requested_cluster.trim();
    let expires_at = now_unix() + CERT_TTL_SECS;

    if !req_cluster.is_empty() {
        let (resolved_user, client_cert_pem, client_key_pem, ca_data_b64) =
            mint_cluster_mtls_certs(&http, &ping, user, password, otp, req_cluster).await?;
        return Ok(TeleportLoginOutcome {
            teleport_cluster: ping.cluster_name,
            kube_api_base: ping.kube_api_base,
            username: resolved_user,
            clusters: vec![req_cluster.to_owned()],
            client_cert_pem,
            client_key_pem,
            ca_data_b64,
            expires_at,
        });
    }

    let clusters = create_web_session_and_list_kubes(&http, &ping, user, password, otp).await?;
    let mut client_cert_pem = String::new();
    let mut client_key_pem = String::new();
    let mut ca_data_b64 = String::new();
    if otp.trim().is_empty() {
        if let Some(first_cluster) = clusters.first() {
            if let Ok((_, cert, key, ca)) =
                mint_cluster_mtls_certs(&http, &ping, user, password, "", first_cluster).await
            {
                client_cert_pem = cert;
                client_key_pem = key;
                ca_data_b64 = ca;
            }
        }
    }

    Ok(TeleportLoginOutcome {
        teleport_cluster: ping.cluster_name,
        kube_api_base: ping.kube_api_base,
        username: user.to_owned(),
        clusters,
        client_cert_pem,
        client_key_pem,
        ca_data_b64,
        expires_at,
    })
}

/// Build an HTTP/2-capable `reqwest::Client` configured with Teleport mTLS client identity and CA
/// trust roots.
pub fn build_teleport_mtls_client(
    client_cert_pem: &str,
    client_key_pem: &str,
    ca_data_b64_or_pem: &str,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(15));
    let ca_trimmed = ca_data_b64_or_pem.trim();
    if !ca_trimmed.is_empty() {
        let ca_bytes = if ca_trimmed.contains("-----BEGIN CERTIFICATE-----") {
            ca_trimmed.as_bytes().to_vec()
        } else {
            STANDARD
                .decode(ca_trimmed)
                .map_err(|e| format!("Invalid base64 Teleport CA bundle: {e}"))?
        };
        match reqwest::Certificate::from_pem_bundle(&ca_bytes) {
            Ok(certs) if !certs.is_empty() => {
                for cert in certs {
                    builder = builder.add_root_certificate(cert);
                }
            }
            _ => {
                let cert = reqwest::Certificate::from_pem(&ca_bytes)
                    .or_else(|_| reqwest::Certificate::from_der(&ca_bytes))
                    .map_err(|e| format!("Invalid Teleport CA certificate: {e}"))?;
                builder = builder.add_root_certificate(cert);
            }
        }
    }
    let cert_pem = client_cert_pem.trim();
    let key_pem = client_key_pem.trim();
    if !cert_pem.is_empty() && !key_pem.is_empty() {
        let combined = format!("{cert_pem}\n{key_pem}");
        let identity = reqwest::Identity::from_pem(combined.as_bytes())
            .map_err(|e| format!("Invalid Teleport mTLS client identity: {e}"))?;
        builder = builder.identity(identity);
    }
    builder
        .build()
        .map_err(|e| format!("Failed building Teleport mTLS HTTP/2 client: {e}"))
}

/// Encode a protobuf payload into a 5-byte gRPC length-prefixed HTTP/2 data frame.
#[must_use]
pub fn grpc_frame_encode(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + msg.len());
    out.push(0); // uncompressed flag
    let len = u32::try_from(msg.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(msg);
    out
}

/// Decode a single uncompressed gRPC length-prefixed HTTP/2 data frame into its protobuf payload.
pub fn grpc_frame_decode(frame: &[u8]) -> Result<&[u8], String> {
    if frame.len() < 5 {
        return Err(format!(
            "Truncated gRPC frame ({} bytes; expected >= 5)",
            frame.len()
        ));
    }
    if frame[0] != 0 {
        return Err(format!("Unsupported gRPC compression flag: {}", frame[0]));
    }
    let len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
    let end = 5usize
        .checked_add(len)
        .ok_or_else(|| "gRPC frame length overflow".to_owned())?;
    if end > frame.len() {
        return Err(format!(
            "Incomplete gRPC frame: need {end} bytes, got {}",
            frame.len()
        ));
    }
    Ok(&frame[5..end])
}

fn read_protobuf_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    while *pos < buf.len() && shift < 64 {
        let b = buf[*pos];
        *pos += 1;
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
    None
}

fn is_clean_utf8_field(slice: &[u8]) -> Option<String> {
    if slice.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(slice).ok()?;
    if text
        .chars()
        .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
    {
        Some(text.to_owned())
    } else {
        None
    }
}

fn collect_protobuf_strings(buf: &[u8], depth: u8, out: &mut Vec<(u32, String)>) -> bool {
    if depth > 6 {
        return false;
    }
    let mut pos = 0usize;
    let mut local = Vec::new();
    while pos < buf.len() {
        let Some(tag) = read_protobuf_varint(buf, &mut pos) else {
            return false;
        };
        let field_num = u32::try_from(tag >> 3).unwrap_or(0);
        if field_num == 0 {
            return false;
        }
        let wire_type = tag & 0x07;
        match wire_type {
            0 => {
                if read_protobuf_varint(buf, &mut pos).is_none() {
                    return false;
                }
            }
            1 => {
                if pos.checked_add(8).is_none_or(|end| end > buf.len()) {
                    return false;
                }
                pos += 8;
            }
            2 => {
                let Some(len_u64) = read_protobuf_varint(buf, &mut pos) else {
                    return false;
                };
                let Ok(len) = usize::try_from(len_u64) else {
                    return false;
                };
                let Some(end) = pos.checked_add(len) else {
                    return false;
                };
                if end > buf.len() {
                    return false;
                }
                let slice = &buf[pos..end];
                pos = end;
                let mut nested = Vec::new();
                if slice.len() >= 2
                    && collect_protobuf_strings(slice, depth + 1, &mut nested)
                    && !nested.is_empty()
                {
                    local.extend(nested);
                    continue;
                }
                if let Some(s) = is_clean_utf8_field(slice) {
                    local.push((field_num, s));
                }
            }
            5 => {
                if pos.checked_add(4).is_none_or(|end| end > buf.len()) {
                    return false;
                }
                pos += 4;
            }
            _ => return false,
        }
    }
    out.extend(local);
    true
}

/// Extract `(field_number, utf8_string)` pairs from a raw serialized Protobuf message (including
/// nested sub-messages) using pure-Rust wire-format decoding.
#[must_use]
pub fn decode_protobuf_strings(buf: &[u8]) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let _ = collect_protobuf_strings(buf, 0, &mut out);
    out
}

fn check_grpc_response_headers(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Result<(), String> {
    if !status.is_success() {
        return Err(format!("Teleport gRPC HTTP status {status}"));
    }
    if let Some(gs) = headers.get("grpc-status").and_then(|v| v.to_str().ok()) {
        let code = gs.trim();
        if !code.is_empty() && code != "0" {
            let msg = headers
                .get("grpc-message")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("gRPC error");
            return Err(format!("Teleport gRPC failed (grpc-status={code}): {msg}"));
        }
    }
    let content_type = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with("application/grpc") {
        return Err(format!(
            "Unexpected non-gRPC content-type from Teleport AuthService: '{content_type}'"
        ));
    }
    Ok(())
}

/// Probe `POST /proto.AuthService/Ping` over HTTP/2 mTLS using native gRPC framing.
pub async fn probe_teleport_grpc_ping(
    proxy_url: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
    ca_data_b64_or_pem: &str,
) -> Result<TeleportPingInfo, String> {
    let base = normalize_proxy_url(proxy_url)?;
    let client = build_teleport_mtls_client(client_cert_pem, client_key_pem, ca_data_b64_or_pem)?;
    let res = client
        .post(format!("{base}/proto.AuthService/Ping"))
        .header(reqwest::header::CONTENT_TYPE, "application/grpc")
        .header(reqwest::header::TE, "trailers")
        .body(grpc_frame_encode(&[]))
        .send()
        .await
        .map_err(|e| format!("Teleport gRPC Ping failed: {e}"))?;
    check_grpc_response_headers(res.status(), res.headers())?;
    let bytes = res
        .bytes()
        .await
        .map_err(|e| format!("Failed reading Teleport gRPC Ping body: {e}"))?;
    let msg = if bytes.is_empty() {
        &[][..]
    } else {
        grpc_frame_decode(&bytes)?
    };
    let strings = decode_protobuf_strings(msg);
    let cluster_name = strings
        .into_iter()
        .map(|(_, s)| s)
        .find(|s| !s.is_empty())
        .unwrap_or_default();
    Ok(TeleportPingInfo {
        kube_api_base: base.clone(),
        proxy_base: base,
        cluster_name,
        auth_type: "mtls".to_owned(),
        second_factor: "none".to_owned(),
    })
}

/// Discover permitted Teleport Kubernetes clusters using issued mTLS certificates:
/// tries native HTTP/2 gRPC `POST /proto.AuthService/GetKubernetesServers` first and falls back
/// over the same mTLS client to HTTPS `WebAPI` `/v1/webapi/sites/{cluster}/kubernetes`.
pub async fn discover_teleport_kubes_mtls(
    proxy_url: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
    ca_data_b64_or_pem: &str,
) -> Result<Vec<String>, String> {
    let base = normalize_proxy_url(proxy_url)?;
    let client = build_teleport_mtls_client(client_cert_pem, client_key_pem, ca_data_b64_or_pem)?;

    if let Ok(res) = client
        .post(format!("{base}/proto.AuthService/GetKubernetesServers"))
        .header(reqwest::header::CONTENT_TYPE, "application/grpc")
        .header(reqwest::header::TE, "trailers")
        .body(grpc_frame_encode(&[]))
        .send()
        .await
    {
        if check_grpc_response_headers(res.status(), res.headers()).is_ok() {
            if let Ok(bytes) = res.bytes().await {
                if let Ok(msg) = grpc_frame_decode(&bytes) {
                    let mut names: Vec<String> = decode_protobuf_strings(msg)
                        .into_iter()
                        .filter_map(|(field, s)| {
                            let trimmed = s.trim().to_owned();
                            if (field == 1 || field == 2 || field == 3)
                                && !trimmed.is_empty()
                                && trimmed.len() <= 128
                                && !trimmed.contains(' ')
                            {
                                Some(trimmed)
                            } else {
                                None
                            }
                        })
                        .collect();
                    names.sort();
                    names.dedup();
                    if !names.is_empty() {
                        return Ok(names);
                    }
                }
            }
        }
    }

    let ping = ping_teleport(&client, &base).await?;
    let kubes_url = format!("{base}/v1/webapi/sites/{}/kubernetes", ping.cluster_name);
    let res = client
        .get(&kubes_url)
        .send()
        .await
        .map_err(|e| format!("Teleport mTLS Kubernetes discovery failed: {e}"))?;
    let status = res.status();
    let txt = res
        .text()
        .await
        .map_err(|e| format!("Failed reading Teleport mTLS Kubernetes list: {e}"))?;
    if !status.is_success() {
        return Err(extract_teleport_error(status, &txt));
    }
    let val: serde_json::Value = serde_json::from_str(&txt)
        .map_err(|e| format!("Invalid Teleport Kubernetes list JSON: {e}"))?;
    let clusters: Vec<String> = val["items"]
        .as_array()
        .ok_or_else(|| "Teleport did not return Kubernetes cluster items".to_owned())?
        .iter()
        .filter_map(|item| {
            item["name"]
                .as_str()
                .or_else(|| item["metadata"]["name"].as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
        })
        .collect();
    if clusters.is_empty() {
        return Err("No permitted Kubernetes clusters returned for Teleport identity.".to_owned());
    }
    Ok(clusters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    #[test]
    fn normalizes_urls_and_rejects_insecure_remote_http() {
        assert_eq!(
            normalize_proxy_url("tp.example.com:443/").unwrap(),
            "https://tp.example.com"
        );
        assert_eq!(
            normalize_proxy_url("tp.example.com:8443/").unwrap(),
            "https://tp.example.com:8443"
        );
        assert_eq!(
            normalize_proxy_url("http://127.0.0.1:8080/").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert!(normalize_proxy_url("http://tp.example.com").is_err());
    }

    #[tokio::test]
    async fn local_login_cluster_mints_mtls_certs_and_ca_bundle() {
        let cert = rcgen::generate_simple_self_signed(vec!["ca.teleport.local".to_owned()])
            .expect("test CA cert");
        let ca_pem = cert.cert.pem();
        let leaf_pem = cert.cert.pem();

        let finish_calls = Arc::new(AtomicUsize::new(0));
        let fc = finish_calls.clone();

        let app = Router::new()
            .route(
                "/webapi/ping",
                get(|| async {
                    Json(serde_json::json!({
                        "cluster_name": "tp-root",
                        "auth": { "type": "local", "second_factor": "on" },
                        "proxy": {
                            "tls_routing_enabled": false,
                            "kube": { "enabled": true, "listen_addr": "0.0.0.0:3026" }
                        }
                    }))
                }),
            )
            .route(
                "/v1/webapi/mfa/login/begin",
                post(|Json(body): Json<serde_json::Value>| async move {
                    if body["pass"] != "secret" {
                        return (
                            StatusCode::FORBIDDEN,
                            Json(serde_json::json!({"error":{"message":"invalid credentials"}})),
                        );
                    }
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({ "totp_challenge": true })),
                    )
                }),
            )
            .route(
                "/v1/webapi/mfa/login/finish",
                post({
                    let ca_pem = ca_pem.clone();
                    let leaf_pem = leaf_pem.clone();
                    move |State(calls): State<Arc<AtomicUsize>>,
                          Json(body): Json<serde_json::Value>| {
                        let ca_pem = ca_pem.clone();
                        let leaf_pem = leaf_pem.clone();
                        async move {
                            calls.fetch_add(1, Ordering::Relaxed);
                            assert_eq!(body["KubernetesCluster"], "eks-dev");
                            assert_eq!(body["RouteToCluster"], "tp-root");
                            let pub_b64 = body["tls_pub_key"].as_str().unwrap_or("");
                            let pub_bytes = STANDARD.decode(pub_b64).unwrap();
                            let pub_str = String::from_utf8(pub_bytes).unwrap();
                            assert!(pub_str.contains("BEGIN PUBLIC KEY"));
                            Json(serde_json::json!({
                                "username": "alice",
                                "tls_cert": STANDARD.encode(leaf_pem.as_bytes()),
                                "host_signers": [{
                                    "domain_name": "tp-root",
                                    "tls_certs": [STANDARD.encode(ca_pem.as_bytes())]
                                }]
                            }))
                        }
                    }
                }),
            )
            .with_state(fc);

        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(ln, app).await;
        });

        let base = format!("http://{addr}");
        let bad = teleport_local_login(&base, "alice", "wrong", "123456", "eks-dev").await;
        assert_eq!(bad.unwrap_err(), "invalid credentials");

        let ok = teleport_local_login(&base, "alice", "secret", "123456", "eks-dev")
            .await
            .expect("login ok");
        assert_eq!(ok.clusters, vec!["eks-dev"]);
        assert_eq!(ok.kube_api_base, "http://127.0.0.1:3026");
        assert!(ok.client_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ok.client_key_pem.contains("BEGIN PRIVATE KEY"));
        assert_ne!(ok.ca_data_b64, "");
        assert_eq!(finish_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn discovery_login_uses_csrf_session_and_lists_kubes_without_reusing_otp() {
        let app = Router::new()
            .route(
                "/webapi/ping",
                get(|| async {
                    Json(serde_json::json!({
                        "cluster_name": "tp-root",
                        "auth": { "type": "local", "second_factor": "on" },
                        "proxy": { "tls_routing_enabled": true, "kube": { "enabled": true } }
                    }))
                }),
            )
            .route(
                "/v1/webapi/sessions/web",
                post(
                    |headers: HeaderMap, Json(body): Json<serde_json::Value>| async move {
                        let csrf_hdr = headers
                            .get("X-CSRF-Token")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let cookie = headers
                            .get(COOKIE)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        if csrf_hdr.len() != 64
                            || !cookie.contains(&format!("__Host-grv_csrf={csrf_hdr}"))
                        {
                            return (
                                StatusCode::FORBIDDEN,
                                Json(serde_json::json!({"error":{"message":"CSRF mismatch"}})),
                            );
                        }
                        assert_eq!(body["second_factor_token"], "654321");
                        (
                            StatusCode::OK,
                            Json(serde_json::json!({ "token": "web-tok-1" })),
                        )
                    },
                ),
            )
            .route(
                "/v1/webapi/sites/tp-root/kubernetes",
                get(|headers: HeaderMap| async move {
                    let auth = headers
                        .get(reqwest::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    assert_eq!(auth, "Bearer web-tok-1");
                    Json(serde_json::json!({
                        "items": [
                            { "name": "eks-stage" },
                            { "name": "eks-prod" }
                        ]
                    }))
                }),
            );

        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(ln, app).await;
        });

        let out = teleport_local_login(&format!("http://{addr}"), "ops", "pw", "654321", "")
            .await
            .expect("discovery login");
        assert_eq!(out.clusters, vec!["eks-stage", "eks-prod"]);
        assert_eq!(out.client_cert_pem, "");
    }

    fn encode_pb_bytes(field_num: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut tag = (field_num << 3) | 2;
        while tag >= 0x80 {
            out.push((tag as u8 & 0x7f) | 0x80);
            tag >>= 7;
        }
        out.push(tag as u8);
        let mut len = payload.len();
        while len >= 0x80 {
            out.push((len as u8 & 0x7f) | 0x80);
            len >>= 7;
        }
        out.push(len as u8);
        out.extend_from_slice(payload);
        out
    }

    #[tokio::test]
    async fn mtls_grpc_ping_and_discover_kubes_over_http2_loopback() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let ca_kp = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(["tp-ca.local".to_owned()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_kp).unwrap();

        let srv_kp = rcgen::KeyPair::generate().unwrap();
        let mut srv_params =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned(), "localhost".to_owned()])
                .unwrap();
        srv_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let srv_cert = srv_params.signed_by(&srv_kp, &ca_cert, &ca_kp).unwrap();

        let cli_kp = rcgen::KeyPair::generate().unwrap();
        let mut cli_params = rcgen::CertificateParams::new(["alice".to_owned()]).unwrap();
        cli_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
        let cli_cert = cli_params.signed_by(&cli_kp, &ca_cert, &ca_kp).unwrap();

        let mut client_roots = rustls::RootCertStore::empty();
        client_roots.add(ca_cert.der().clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            provider.clone(),
        )
        .build()
        .unwrap();
        let srv_key = rustls::pki_types::PrivateKeyDer::try_from(srv_kp.serialize_der()).unwrap();
        let mut server_cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![srv_cert.der().clone()], srv_key)
            .unwrap();
        server_cfg.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let grpc_calls = Arc::new(AtomicUsize::new(0));
        let grpc_calls_srv = grpc_calls.clone();

        tokio::spawn(async move {
            while let Ok((tcp, _)) = ln.accept().await {
                let acceptor = acceptor.clone();
                let grpc_calls_conn = grpc_calls_srv.clone();
                tokio::spawn(async move {
                    let tls = acceptor.accept(tcp).await.expect("mTLS accept");
                    assert!(
                        tls.get_ref()
                            .1
                            .peer_certificates()
                            .is_some_and(|c| !c.is_empty()),
                        "client mTLS cert must be presented"
                    );
                    let mut h2_conn = h2::server::handshake(tls).await.expect("h2 handshake");
                    while let Some(Ok((req, mut respond))) = h2_conn.accept().await {
                        let grpc_calls_req = grpc_calls_conn.clone();
                        tokio::spawn(async move {
                            let path = req.uri().path().to_owned();
                            let mut req_body = req.into_body();
                            while let Some(chunk) = req_body.data().await {
                                if let Ok(bytes) = chunk {
                                    let _ = req_body.flow_control().release_capacity(bytes.len());
                                }
                            }
                            grpc_calls_req.fetch_add(1, Ordering::Relaxed);
                            let pb = if path == "/proto.AuthService/Ping" {
                                encode_pb_bytes(1, b"tp-grpc-cluster")
                            } else if path == "/proto.AuthService/GetKubernetesServers" {
                                let item1 = encode_pb_bytes(1, b"eks-mtls-1");
                                let item2 = encode_pb_bytes(1, b"eks-mtls-2");
                                let mut combined = encode_pb_bytes(1, &item1);
                                combined.extend_from_slice(&encode_pb_bytes(1, &item2));
                                combined
                            } else {
                                Vec::new()
                            };
                            let resp = http::Response::builder()
                                .status(200)
                                .header("content-type", "application/grpc")
                                .body(())
                                .unwrap();
                            let mut send = respond.send_response(resp, false).unwrap();
                            send.send_data(bytes::Bytes::from(grpc_frame_encode(&pb)), false)
                                .unwrap();
                            let mut trailers = http::HeaderMap::new();
                            trailers.insert("grpc-status", "0".parse().unwrap());
                            send.send_trailers(trailers).unwrap();
                        });
                    }
                });
            }
        });

        let ca_b64 = STANDARD.encode(ca_cert.pem().as_bytes());
        let base = format!("https://127.0.0.1:{}", addr.port());
        let ping =
            probe_teleport_grpc_ping(&base, &cli_cert.pem(), &cli_kp.serialize_pem(), &ca_b64)
                .await
                .expect("gRPC mTLS ping");
        assert_eq!(ping.cluster_name, "tp-grpc-cluster");
        assert_eq!(ping.auth_type, "mtls");

        let kubes =
            discover_teleport_kubes_mtls(&base, &cli_cert.pem(), &cli_kp.serialize_pem(), &ca_b64)
                .await
                .expect("gRPC mTLS kubes discovery");
        assert_eq!(kubes, vec!["eks-mtls-1", "eks-mtls-2"]);
        assert_eq!(grpc_calls.load(Ordering::Relaxed), 2);
    }
}
