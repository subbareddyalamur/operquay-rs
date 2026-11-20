//! Pure-Rust S3 Object Lock (WORM) archival uploader (`M10.2`) using AWS `SigV4`
//! with `Content-MD5`, `x-amz-object-lock-mode`, and `x-amz-object-lock-retain-until-date`.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha2::{Digest, Sha256};

use crate::format_epoch_ms_iso8601;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct S3WormConfig {
    pub bucket: String,
    pub region: String,
    pub prefix: String,
    pub object_lock_mode: String,
    pub retention_days: u32,
    pub endpoint_override: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl S3WormConfig {
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let bucket = std::env::var("OPERQUAY_WORM_S3_BUCKET")
            .ok()
            .filter(|v| !v.trim().is_empty())?;
        let access_key_id = std::env::var("AWS_ACCESS_KEY_ID")
            .ok()
            .filter(|v| !v.trim().is_empty())?;
        let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .ok()
            .filter(|v| !v.trim().is_empty())?;
        let region = std::env::var("OPERQUAY_WORM_S3_REGION")
            .or_else(|_| std::env::var("AWS_REGION"))
            .unwrap_or_else(|_| "us-east-1".to_owned());
        let prefix = std::env::var("OPERQUAY_WORM_S3_PREFIX")
            .unwrap_or_else(|_| "operquay-recordings".to_owned());
        let raw_mode = std::env::var("OPERQUAY_WORM_OBJECT_LOCK_MODE")
            .unwrap_or_else(|_| "COMPLIANCE".to_owned());
        let object_lock_mode = if raw_mode.eq_ignore_ascii_case("GOVERNANCE") {
            "GOVERNANCE".to_owned()
        } else {
            "COMPLIANCE".to_owned()
        };
        let retention_days = std::env::var("OPERQUAY_WORM_RETENTION_DAYS")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|&d| d > 0)
            .unwrap_or(365);
        let endpoint_override = std::env::var("OPERQUAY_WORM_S3_ENDPOINT")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let session_token = std::env::var("AWS_SESSION_TOKEN")
            .ok()
            .filter(|v| !v.trim().is_empty());
        Some(Self {
            bucket: bucket.trim().to_owned(),
            region: region.trim().to_owned(),
            prefix: prefix.trim_matches('/').to_owned(),
            object_lock_mode,
            retention_days,
            endpoint_override,
            access_key_id,
            secret_access_key,
            session_token,
        })
    }
}

#[derive(Debug, Clone)]
pub struct WormArchiveResult {
    pub s3_uri: String,
    pub retain_until_ms: u64,
    pub archived_at_ms: u64,
    pub mode: String,
}

pub struct S3WormArchiver {
    config: S3WormConfig,
    http: reqwest::Client,
}

impl S3WormArchiver {
    #[must_use]
    pub fn new(config: S3WormConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self { config, http }
    }

    #[must_use]
    pub fn from_env() -> Option<Self> {
        S3WormConfig::from_env().map(Self::new)
    }

    pub async fn archive_object(
        &self,
        tenant_id: &str,
        recording_id: &str,
        ext: &str,
        ciphertext_bytes: &[u8],
        legal_hold: bool,
    ) -> Result<WormArchiveResult, String> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let archived_at_ms = now_secs * 1000;
        let retain_secs =
            now_secs.saturating_add(u64::from(self.config.retention_days.max(1)) * 86_400);
        let retain_until_ms = retain_secs * 1000;
        let retain_iso = format_epoch_ms_iso8601(retain_until_ms);

        let clean_ext = ext.trim_start_matches('.');
        let key = if self.config.prefix.is_empty() {
            format!("{tenant_id}/{recording_id}.{clean_ext}.enc")
        } else {
            format!(
                "{}/{tenant_id}/{recording_id}.{clean_ext}.enc",
                self.config.prefix
            )
        };

        let (scheme, host, canonical_uri) = if let Some(ref ep) = self.config.endpoint_override {
            let parsed = reqwest::Url::parse(ep)
                .map_err(|e| format!("invalid OPERQUAY_WORM_S3_ENDPOINT: {e}"))?;
            let host_str = parsed
                .host_str()
                .ok_or("WORM endpoint missing host")?
                .to_owned();
            let host_header = parsed
                .port()
                .map_or_else(|| host_str.clone(), |p| format!("{host_str}:{p}"));
            let base_path = parsed.path().trim_end_matches('/');
            let uri = format!("{base_path}/{}/{key}", self.config.bucket);
            (parsed.scheme().to_owned(), host_header, uri)
        } else {
            let host = format!(
                "{}.s3.{}.amazonaws.com",
                self.config.bucket, self.config.region
            );
            let uri = format!("/{key}");
            ("https".to_owned(), host, uri)
        };
        let url = format!("{scheme}://{host}{canonical_uri}");

        let content_md5 = STANDARD.encode(Md5::digest(ciphertext_bytes));
        let payload_sha256 = hex::encode(Sha256::digest(ciphertext_bytes));
        let (date_stamp, amz_date) = format_amz_datetime(now_secs);

        let mut hdrs: BTreeMap<&'static str, String> = BTreeMap::new();
        hdrs.insert("content-md5", content_md5.clone());
        hdrs.insert("host", host.clone());
        hdrs.insert("x-amz-content-sha256", payload_sha256.clone());
        hdrs.insert("x-amz-date", amz_date.clone());
        hdrs.insert(
            "x-amz-object-lock-mode",
            self.config.object_lock_mode.clone(),
        );
        hdrs.insert("x-amz-object-lock-retain-until-date", retain_iso.clone());
        if legal_hold {
            hdrs.insert("x-amz-object-lock-legal-hold", "ON".to_owned());
        }
        if let Some(ref tok) = self.config.session_token {
            hdrs.insert("x-amz-security-token", tok.clone());
        }

        let mut canon_headers = String::new();
        let mut signed_headers = String::new();
        for (idx, (k, v)) in hdrs.iter().enumerate() {
            use std::fmt::Write as _;
            let _ = writeln!(canon_headers, "{k}:{}", v.trim());
            if idx > 0 {
                signed_headers.push(';');
            }
            signed_headers.push_str(k);
        }

        let canon_req = format!(
            "PUT\n{}\n\n{canon_headers}\n{signed_headers}\n{payload_sha256}",
            encode_s3_uri_path(&canonical_uri)
        );
        let scope = format!("{date_stamp}/{}/s3/aws4_request", self.config.region);
        let canon_hash = hex::encode(Sha256::digest(canon_req.as_bytes()));
        let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canon_hash}");

        let k_date = hmac_sha256(
            format!("AWS4{}", self.config.secret_access_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac_sha256(&k_date, self.config.region.as_bytes());
        let k_service = hmac_sha256(&k_region, b"s3");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        let sig = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={sig}",
            self.config.access_key_id
        );

        let mut req = self
            .http
            .put(&url)
            .header("content-md5", content_md5)
            .header("x-amz-content-sha256", payload_sha256)
            .header("x-amz-date", amz_date)
            .header("x-amz-object-lock-mode", &self.config.object_lock_mode)
            .header("x-amz-object-lock-retain-until-date", retain_iso)
            .header("authorization", auth);
        if legal_hold {
            req = req.header("x-amz-object-lock-legal-hold", "ON");
        }
        if let Some(ref tok) = self.config.session_token {
            req = req.header("x-amz-security-token", tok);
        }

        let resp = req
            .body(ciphertext_bytes.to_vec())
            .send()
            .await
            .map_err(|e| format!("S3 WORM archival upload failed: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let err_txt = resp.text().await.unwrap_or_default();
            return Err(format!("S3 WORM upload HTTP {status}: {}", err_txt.trim()));
        }

        Ok(WormArchiveResult {
            s3_uri: format!("s3://{}/{key}", self.config.bucket),
            retain_until_ms,
            archived_at_ms,
            mode: self.config.object_lock_mode.clone(),
        })
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key valid");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn encode_s3_uri_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(char::from(b));
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn format_amz_datetime(unix_secs: u64) -> (String, String) {
    let iso = format_epoch_ms_iso8601(unix_secs * 1000);
    // YYYY-MM-DDTHH:MM:SSZ -> YYYYMMDD & YYYYMMDDTHHMMSSZ
    let compact: String = iso.chars().filter(|c| *c != '-' && *c != ':').collect();
    let date = compact.chars().take(8).collect();
    (date, compact)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::routing::put;
    use axum::Router;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn s3_worm_archiver_signs_object_lock_headers_and_uploads_ciphertext() {
        #[derive(Default)]
        struct CapturedPut {
            uri: String,
            mode: String,
            retain_until: String,
            legal_hold: String,
            content_md5: String,
            auth: String,
            body: Vec<u8>,
        }
        let captured = Arc::new(Mutex::new(CapturedPut::default()));
        let app = Router::new()
            .route(
                "/{bucket}/{*key}",
                put(
                    |State(cap): State<Arc<Mutex<CapturedPut>>>,
                     uri: axum::http::Uri,
                     headers: HeaderMap,
                     body: Bytes| async move {
                        let mut guard = cap.lock().await;
                        guard.uri = uri.path().to_owned();
                        guard.mode = headers
                            .get("x-amz-object-lock-mode")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned();
                        guard.retain_until = headers
                            .get("x-amz-object-lock-retain-until-date")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned();
                        guard.legal_hold = headers
                            .get("x-amz-object-lock-legal-hold")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned();
                        guard.content_md5 = headers
                            .get("content-md5")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned();
                        guard.auth = headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned();
                        guard.body = body.to_vec();
                        axum::http::StatusCode::OK
                    },
                ),
            )
            .with_state(captured.clone());

        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(ln, app).await;
        });

        let archiver = S3WormArchiver::new(S3WormConfig {
            bucket: "sec-worm-bucket".to_owned(),
            region: "us-east-1".to_owned(),
            prefix: "recordings".to_owned(),
            object_lock_mode: "COMPLIANCE".to_owned(),
            retention_days: 180,
            endpoint_override: Some(format!("http://{addr}")),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_owned(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_owned(),
            session_token: None,
        });

        let payload = b"OQRK1-encrypted-blob-payload";
        let res = archiver
            .archive_object("acme", "rec-42", "cast", payload, true)
            .await
            .unwrap();
        assert_eq!(
            res.s3_uri,
            "s3://sec-worm-bucket/recordings/acme/rec-42.cast.enc"
        );
        assert_eq!(res.mode, "COMPLIANCE");

        let cap = captured.lock().await;
        assert_eq!(cap.uri, "/sec-worm-bucket/recordings/acme/rec-42.cast.enc");
        assert_eq!(cap.mode, "COMPLIANCE");
        assert!(cap.retain_until.ends_with('Z'));
        assert_eq!(cap.legal_hold, "ON");
        assert_eq!(cap.content_md5, STANDARD.encode(Md5::digest(payload)));
        assert!(cap
            .auth
            .starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"));
        assert!(cap
            .auth
            .contains("x-amz-object-lock-mode;x-amz-object-lock-retain-until-date"));
        assert_eq!(cap.body, payload);
    }
}
