#![forbid(unsafe_code)]

//! Pure-Rust AWS Signature Version 4 (`AWS4-HMAC-SHA256`) request & presigned WebSocket URL signer.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use http::{HeaderMap, HeaderName, HeaderValue};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

/// Convert UNIX epoch seconds into `(amz_date: YYYYMMDDTHHMMSSZ, date_stamp: YYYYMMDD)`.
#[must_use]
pub fn format_amz_datetime(unix_secs: i64) -> (String, String) {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    // Howard Hinnant's civil-from-days algorithm
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(m <= 2);

    let stamp = format!("{year:04}{m:02}{d:02}");
    let amz = format!("{stamp}T{hour:02}{minute:02}{second:02}Z");
    (amz, stamp)
}

#[must_use]
pub fn now_unix_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(0)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key valid");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn derive_signing_key(secret: &str, date_stamp: &str, region: &str, service: &str) -> [u8; 32] {
    let k_secret = format!("AWS4{secret}");
    let k_date = hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

#[must_use]
pub fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'_' | b'-' | b'~' | b'.')
            || (!encode_slash && b == b'/')
        {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Sign an HTTP request in-place with AWS `SigV4` (`AWS4-HMAC-SHA256`).
///
/// # Panics
/// Only if internal static header names fail validation (infeasible).
pub fn sign_request(
    method: &str,
    url_str: &str,
    headers: &mut HeaderMap,
    payload: &[u8],
    creds: &AwsCredentials,
    region: &str,
    service: &str,
    unix_secs: Option<i64>,
) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url_str).map_err(|e| format!("invalid URL: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "missing URL host".to_owned())?;
    let host_header = match parsed.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_owned(),
    };

    let (amz_date, date_stamp) = format_amz_datetime(unix_secs.unwrap_or_else(now_unix_secs));
    let payload_hash = hex::encode(Sha256::digest(payload));

    headers.insert(
        HeaderName::from_static("host"),
        HeaderValue::from_str(&host_header).map_err(|e| e.to_string())?,
    );
    headers.insert(
        HeaderName::from_static("x-amz-date"),
        HeaderValue::from_str(&amz_date).map_err(|e| e.to_string())?,
    );
    headers.insert(
        HeaderName::from_static("x-amz-content-sha256"),
        HeaderValue::from_str(&payload_hash).map_err(|e| e.to_string())?,
    );
    if let Some(tok) = &creds.session_token {
        if !tok.is_empty() {
            headers.insert(
                HeaderName::from_static("x-amz-security-token"),
                HeaderValue::from_str(tok).map_err(|e| e.to_string())?,
            );
        }
    }

    let raw_path = parsed.path();
    let canonical_uri = if raw_path.is_empty() {
        "/".to_owned()
    } else {
        uri_encode(raw_path, false)
    };

    let mut q_pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| (uri_encode(&k, true), uri_encode(&v, true)))
        .collect();
    q_pairs.sort();
    let canonical_query: String = q_pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let mut canonical_headers_vec: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| {
            let name = k.as_str().to_ascii_lowercase();
            let val = v
                .to_str()
                .ok()?
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            Some((name, val))
        })
        .collect();
    canonical_headers_vec.sort_by(|a, b| a.0.cmp(&b.0));

    let mut canonical_headers = String::new();
    let mut signed_header_names = Vec::with_capacity(canonical_headers_vec.len());
    for (k, v) in &canonical_headers_vec {
        let _ = writeln!(canonical_headers, "{k}:{v}");
        signed_header_names.push(k.as_str());
    }
    let signed_headers = signed_header_names.join(";");

    let canonical_request = format!(
        "{}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        method.to_ascii_uppercase()
    );
    let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_hash}");

    let signing_key = derive_signing_key(&creds.secret_access_key, &date_stamp, region, service);
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    let auth_header = format!(
        "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key_id
    );
    headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&auth_header).map_err(|e| e.to_string())?,
    );
    Ok(())
}

/// Generate a presigned `GET` URL (`https://` or `wss://`) using query-parameter `SigV4` (`X-Amz-Signature`).
pub fn presign_url(
    method: &str,
    base_url: &str,
    creds: &AwsCredentials,
    region: &str,
    service: &str,
    expires_secs: u64,
    unix_secs: Option<i64>,
) -> Result<String, String> {
    let parsed = reqwest::Url::parse(base_url).map_err(|e| format!("invalid URL: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "missing URL host".to_owned())?;
    let host_header = match parsed.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_owned(),
    };
    let (amz_date, date_stamp) = format_amz_datetime(unix_secs.unwrap_or_else(now_unix_secs));
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");

    let mut q_pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    q_pairs.push(("X-Amz-Algorithm".to_owned(), "AWS4-HMAC-SHA256".to_owned()));
    q_pairs.push((
        "X-Amz-Credential".to_owned(),
        format!("{}/{credential_scope}", creds.access_key_id),
    ));
    q_pairs.push(("X-Amz-Date".to_owned(), amz_date.clone()));
    q_pairs.push(("X-Amz-Expires".to_owned(), expires_secs.to_string()));
    q_pairs.push(("X-Amz-SignedHeaders".to_owned(), "host".to_owned()));
    if let Some(tok) = &creds.session_token {
        if !tok.is_empty() {
            q_pairs.push(("X-Amz-Security-Token".to_owned(), tok.clone()));
        }
    }

    let mut encoded: Vec<(String, String)> = q_pairs
        .into_iter()
        .map(|(k, v)| (uri_encode(&k, true), uri_encode(&v, true)))
        .collect();
    encoded.sort();
    let canonical_query = encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let raw_path = parsed.path();
    let canonical_uri = if raw_path.is_empty() {
        "/".to_owned()
    } else {
        uri_encode(raw_path, false)
    };
    let payload_hash = "UNSIGNED-PAYLOAD";
    let canonical_request = format!(
        "{}\n{canonical_uri}\n{canonical_query}\nhost:{host_header}\n\nhost\n{payload_hash}",
        method.to_ascii_uppercase()
    );
    let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_hash}");
    let signing_key = derive_signing_key(&creds.secret_access_key, &date_stamp, region, service);
    let sig = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    let scheme = parsed.scheme();
    Ok(format!(
        "{scheme}://{host_header}{canonical_uri}?{canonical_query}&X-Amz-Signature={sig}"
    ))
}

/// Generate a bearer token (`k8s-aws-v1.<base64url>`) for Amazon EKS authentication
/// using a SigV4-presigned `sts:GetCallerIdentity` request with `x-k8s-aws-id`.
pub fn presign_eks_token(
    cluster_name: &str,
    region: &str,
    creds: &AwsCredentials,
    unix_secs: Option<i64>,
) -> Result<String, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    if cluster_name.trim().is_empty() {
        return Err("EKS cluster name is required".to_owned());
    }
    let reg = if region.trim().is_empty() {
        "us-east-1"
    } else {
        region.trim()
    };
    let host_header = format!("sts.{reg}.amazonaws.com");
    let (amz_date, date_stamp) = format_amz_datetime(unix_secs.unwrap_or_else(now_unix_secs));
    let credential_scope = format!("{date_stamp}/{reg}/sts/aws4_request");

    let mut q_pairs = vec![
        ("Action".to_owned(), "GetCallerIdentity".to_owned()),
        ("Version".to_owned(), "2011-06-15".to_owned()),
        ("X-Amz-Algorithm".to_owned(), "AWS4-HMAC-SHA256".to_owned()),
        (
            "X-Amz-Credential".to_owned(),
            format!("{}/{credential_scope}", creds.access_key_id),
        ),
        ("X-Amz-Date".to_owned(), amz_date.clone()),
        ("X-Amz-Expires".to_owned(), "60".to_owned()),
        (
            "X-Amz-SignedHeaders".to_owned(),
            "host;x-k8s-aws-id".to_owned(),
        ),
    ];
    if let Some(tok) = &creds.session_token {
        if !tok.is_empty() {
            q_pairs.push(("X-Amz-Security-Token".to_owned(), tok.clone()));
        }
    }

    let mut encoded: Vec<(String, String)> = q_pairs
        .into_iter()
        .map(|(k, v)| (uri_encode(&k, true), uri_encode(&v, true)))
        .collect();
    encoded.sort();
    let canonical_query = encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_headers = format!("host:{host_header}\nx-k8s-aws-id:{}\n", cluster_name.trim());
    let payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let canonical_request = format!(
        "GET\n/\n{canonical_query}\n{canonical_headers}\nhost;x-k8s-aws-id\n{payload_hash}"
    );
    let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_hash}");
    let signing_key = derive_signing_key(&creds.secret_access_key, &date_stamp, reg, "sts");
    let sig = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    let presigned = format!("https://{host_header}/?{canonical_query}&X-Amz-Signature={sig}");
    Ok(format!(
        "k8s-aws-v1.{}",
        URL_SAFE_NO_PAD.encode(presigned.as_bytes())
    ))
}
