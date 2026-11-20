use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use async_trait::async_trait;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use constant_time_eq::constant_time_eq;
use hmac::{Hmac, Mac};
use http::HeaderMap;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const ENVELOPE_MAGIC: &[u8; 4] = b"OQE1";

/// Fill `dest` with cryptographically strong random bytes directly from the OS CSPRNG (`getrandom`).
pub fn fill_csprng(dest: &mut [u8]) -> Result<(), String> {
    getrandom::getrandom(dest).map_err(|e| format!("OS CSPRNG entropy failure: {e}"))
}

/// Generate 32-byte cryptographically unpredictable key/token material using OS CSPRNG.
#[must_use]
pub fn random_token_b64() -> String {
    let mut raw = [0u8; 32];
    if fill_csprng(&mut raw).is_err() {
        // Fallback only if OS entropy source unexpectedly fails in restricted sandbox.
        let u1 = uuid::Uuid::new_v4();
        let u2 = uuid::Uuid::new_v4();
        raw[..16].copy_from_slice(u1.as_bytes());
        raw[16..].copy_from_slice(u2.as_bytes());
    }
    let out = URL_SAFE_NO_PAD.encode(raw);
    raw.zeroize();
    out
}

#[must_use]
pub fn derive_key32(master: &[u8], purpose: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(master).expect("HMAC key valid");
    mac.update(purpose);
    mac.finalize().into_bytes().into()
}

/// Seal `plaintext` using AES-256-GCM with a full 96-bit CSPRNG nonce (`getrandom`).
pub fn seal_aead(key32: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key32).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    fill_csprng(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open_aead(key32: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < 12 {
        return Err("ciphertext shorter than 12-byte nonce".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key32).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&sealed[..12]);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &sealed[12..],
                aad,
            },
        )
        .map_err(|_| "AES-GCM authentication failed".into())
}

/// Versioned key ring enabling seamless rotation across `key_version` without re-encrypting
/// historical rows immediately. Keys drop with `Zeroize`.
#[derive(Clone)]
pub struct KeyRing {
    active_version: u16,
    keys: HashMap<u16, [u8; 32]>,
}

impl Drop for KeyRing {
    fn drop(&mut self) {
        for val in self.keys.values_mut() {
            val.zeroize();
        }
    }
}

impl KeyRing {
    #[must_use]
    pub fn new(active_version: u16, keys: HashMap<u16, [u8; 32]>) -> Self {
        Self {
            active_version,
            keys,
        }
    }

    /// Construct from `master` fallback key (version `1`) plus optional `OPERQUAY_ENCRYPTION_KEYS`
    /// (`v1:<64hex>,v2:<64hex>`) and optional `OPERQUAY_ENCRYPTION_KEY_VERSION`.
    #[must_use]
    pub fn from_master_and_env(master: &[u8], purpose: &[u8]) -> Self {
        let env_spec = std::env::var("OPERQUAY_ENCRYPTION_KEYS").unwrap_or_default();
        let requested_active = std::env::var("OPERQUAY_ENCRYPTION_KEY_VERSION")
            .ok()
            .and_then(|v| v.trim().trim_start_matches('v').parse::<u16>().ok());
        Self::from_master_and_spec(master, purpose, &env_spec, requested_active)
    }

    #[must_use]
    pub fn from_master_and_spec(
        master: &[u8],
        purpose: &[u8],
        spec: &str,
        requested_active: Option<u16>,
    ) -> Self {
        let mut keys = HashMap::new();
        let fallback_v1 = derive_key32(master, purpose);
        keys.insert(1, fallback_v1);

        let mut max_ver = 1u16;
        for entry in spec.split(',') {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Some((ver_raw, hex_raw)) = trimmed.split_once(':') else {
                continue;
            };
            let Ok(ver) = ver_raw.trim().trim_start_matches('v').parse::<u16>() else {
                continue;
            };
            if ver == 0 {
                continue;
            }
            if let Ok(bytes) = hex::decode(hex_raw.trim()) {
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    // Domain-separate raw KEK per purpose so distinct tables never share raw keystream scope.
                    let scoped = derive_key32(&key, purpose);
                    key.zeroize();
                    keys.insert(ver, scoped);
                    if ver > max_ver {
                        max_ver = ver;
                    }
                }
            }
        }

        let active_version = requested_active
            .filter(|v| keys.contains_key(v))
            .unwrap_or(max_ver);
        Self {
            active_version,
            keys,
        }
    }

    #[must_use]
    pub const fn active_version(&self) -> u16 {
        self.active_version
    }

    #[must_use]
    pub fn key(&self, version: u16) -> Option<&[u8; 32]> {
        self.keys.get(&version)
    }
}

/// Seal payload in versioned envelope format (`b"OQE1" || key_version(u16BE) || wrapped_dek_len(0u16BE) || nonce(12B) || ct+tag`).
pub fn seal_aead_versioned(
    ring: &KeyRing,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let ver = ring.active_version();
    let key = ring
        .key(ver)
        .ok_or_else(|| format!("active encryption key version {ver} missing"))?;
    let mut full_aad = Vec::with_capacity(6 + aad.len());
    full_aad.extend_from_slice(ENVELOPE_MAGIC);
    full_aad.extend_from_slice(&ver.to_be_bytes());
    full_aad.extend_from_slice(aad);
    let inner = seal_aead(key, &full_aad, plaintext)?;
    let mut out = Vec::with_capacity(8 + inner.len());
    out.extend_from_slice(ENVELOPE_MAGIC);
    out.extend_from_slice(&ver.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&inner);
    Ok(out)
}

/// Open versioned `OQE1` envelope or fall back cleanly to legacy `open_aead` v1 ciphertext.
pub fn open_aead_versioned(ring: &KeyRing, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() >= 8 && &sealed[..4] == ENVELOPE_MAGIC {
        let ver = u16::from_be_bytes([sealed[4], sealed[5]]);
        let dek_len = usize::from(u16::from_be_bytes([sealed[6], sealed[7]]));
        if dek_len != 0 {
            return Err("envelope contains wrapped DEK; use KMS envelope decryptor".into());
        }
        let key = ring
            .key(ver)
            .ok_or_else(|| format!("unknown encryption key version {ver}"))?;
        let mut full_aad = Vec::with_capacity(6 + aad.len());
        full_aad.extend_from_slice(ENVELOPE_MAGIC);
        full_aad.extend_from_slice(&sealed[4..6]);
        full_aad.extend_from_slice(aad);
        return open_aead(key, &full_aad, &sealed[8..]);
    }
    let v1 = ring
        .key(1)
        .ok_or_else(|| "legacy encryption key version 1 missing".to_owned())?;
    open_aead(v1, aad, sealed)
}

#[async_trait]
pub trait KmsEnvelopeProvider: Send + Sync {
    async fn generate_data_key(&self, aad: &[u8]) -> Result<(u16, [u8; 32], Vec<u8>), String>;
    async fn decrypt_data_key(
        &self,
        key_version: u16,
        aad: &[u8],
        wrapped_dek: &[u8],
    ) -> Result<[u8; 32], String>;
}

/// Local versioned KEK envelope provider generating per-record random DEKs wrapped via [`KeyRing`].
#[derive(Clone)]
pub struct LocalKeyRingProvider {
    ring: KeyRing,
}

impl LocalKeyRingProvider {
    #[must_use]
    pub const fn new(ring: KeyRing) -> Self {
        Self { ring }
    }
}

#[async_trait]
impl KmsEnvelopeProvider for LocalKeyRingProvider {
    async fn generate_data_key(&self, aad: &[u8]) -> Result<(u16, [u8; 32], Vec<u8>), String> {
        let ver = self.ring.active_version();
        let kek = self
            .ring
            .key(ver)
            .ok_or_else(|| format!("active KEK version {ver} missing"))?;
        let mut dek = [0u8; 32];
        fill_csprng(&mut dek)?;
        let mut wrap_aad = Vec::with_capacity(8 + aad.len());
        wrap_aad.extend_from_slice(b"OQE1-DEK");
        wrap_aad.extend_from_slice(&ver.to_be_bytes());
        wrap_aad.extend_from_slice(aad);
        let wrapped = seal_aead(kek, &wrap_aad, &dek)?;
        Ok((ver, dek, wrapped))
    }

    async fn decrypt_data_key(
        &self,
        key_version: u16,
        aad: &[u8],
        wrapped_dek: &[u8],
    ) -> Result<[u8; 32], String> {
        let kek = self
            .ring
            .key(key_version)
            .ok_or_else(|| format!("unknown KEK version {key_version}"))?;
        let mut wrap_aad = Vec::with_capacity(8 + aad.len());
        wrap_aad.extend_from_slice(b"OQE1-DEK");
        wrap_aad.extend_from_slice(&key_version.to_be_bytes());
        wrap_aad.extend_from_slice(aad);
        let raw = open_aead(kek, &wrap_aad, wrapped_dek)?;
        if raw.len() != 32 {
            return Err("unwrapped DEK has invalid length".into());
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&raw);
        Ok(dek)
    }
}

/// Optional AWS KMS envelope wrapping provider configured from `OPERQUAY_KMS_KEY_ID` + AWS `SigV4` env credentials.
pub struct AwsKmsEnvelopeProvider {
    pub key_id: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub endpoint_override: Option<String>,
    http: reqwest::Client,
}

impl AwsKmsEnvelopeProvider {
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let key_id = std::env::var("OPERQUAY_KMS_KEY_ID")
            .ok()
            .filter(|v| !v.trim().is_empty())?;
        let region = std::env::var("OPERQUAY_KMS_REGION")
            .or_else(|_| std::env::var("AWS_REGION"))
            .unwrap_or_else(|_| "us-east-1".into());
        let access_key_id = std::env::var("AWS_ACCESS_KEY_ID")
            .ok()
            .filter(|v| !v.trim().is_empty())?;
        let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .ok()
            .filter(|v| !v.trim().is_empty())?;
        let session_token = std::env::var("AWS_SESSION_TOKEN")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let endpoint_override = std::env::var("OPERQUAY_KMS_ENDPOINT")
            .ok()
            .filter(|v| !v.trim().is_empty());
        Some(Self {
            key_id,
            region,
            access_key_id,
            secret_access_key,
            session_token,
            endpoint_override,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        })
    }

    async fn kms_post(&self, target: &str, body_json: &[u8]) -> Result<serde_json::Value, String> {
        let host = self
            .endpoint_override
            .as_deref()
            .and_then(|u| {
                u.strip_prefix("https://")
                    .or_else(|| u.strip_prefix("http://"))
            })
            .map_or_else(
                || format!("kms.{}.amazonaws.com", self.region),
                |s| s.trim_end_matches('/').to_owned(),
            );
        let url = self
            .endpoint_override
            .as_deref()
            .map_or_else(|| format!("https://{host}/"), ToOwned::to_owned);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (date_stamp, amz_date) = format_amz_datetime(now);
        let payload_hash = sha256_hex(body_json);
        let mut canon_headers = format!(
            "content-type:application/x-amz-json-1.1\nhost:{host}\nx-amz-date:{amz_date}\n"
        );
        let mut signed_headers = "content-type;host;x-amz-date;x-amz-target".to_owned();
        if let Some(ref tok) = self.session_token {
            use std::fmt::Write as _;
            let _ = writeln!(canon_headers, "x-amz-security-token:{tok}");
            "content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
                .clone_into(&mut signed_headers);
        }
        canon_headers.push_str("x-amz-target:");
        canon_headers.push_str(target);
        canon_headers.push('\n');

        let canonical_req = format!("POST\n/\n\n{canon_headers}\n{signed_headers}\n{payload_hash}");
        let scope = format!("{date_stamp}/{}/kms/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical_req.as_bytes())
        );
        let k_date = hmac_sha256(
            format!("AWS4{}", self.secret_access_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, b"kms");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        let sig = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={sig}",
            self.access_key_id
        );

        let mut req = self
            .http
            .post(url)
            .header("content-type", "application/x-amz-json-1.1")
            .header("x-amz-date", &amz_date)
            .header("x-amz-target", target)
            .header("authorization", auth);
        if let Some(ref tok) = self.session_token {
            req = req.header("x-amz-security-token", tok);
        }
        let resp = req
            .body(body_json.to_vec())
            .send()
            .await
            .map_err(|e| format!("KMS HTTP error: {e}"))?;
        if !resp.status().is_success() {
            let st = resp.status();
            let txt = resp.text().await.unwrap_or_default();
            return Err(format!("KMS HTTP {st}: {txt}"));
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| format!("KMS JSON error: {e}"))
    }
}

#[async_trait]
impl KmsEnvelopeProvider for AwsKmsEnvelopeProvider {
    async fn generate_data_key(&self, aad: &[u8]) -> Result<(u16, [u8; 32], Vec<u8>), String> {
        let req = serde_json::json!({
            "KeyId": self.key_id,
            "KeySpec": "AES_256",
            "EncryptionContext": { "aad_sha256": sha256_hex(aad) }
        });
        let body = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        let res = self.kms_post("TrentService.GenerateDataKey", &body).await?;
        let plain_b64 = res["Plaintext"]
            .as_str()
            .ok_or("KMS response missing Plaintext")?;
        let ct_b64 = res["CiphertextBlob"]
            .as_str()
            .ok_or("KMS response missing CiphertextBlob")?;
        let plain = STANDARD
            .decode(plain_b64)
            .map_err(|e| format!("KMS Plaintext decode: {e}"))?;
        let ct = STANDARD
            .decode(ct_b64)
            .map_err(|e| format!("KMS CiphertextBlob decode: {e}"))?;
        if plain.len() != 32 {
            return Err("KMS returned unexpected DEK size".into());
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&plain);
        Ok((2, dek, ct))
    }

    async fn decrypt_data_key(
        &self,
        _key_version: u16,
        aad: &[u8],
        wrapped_dek: &[u8],
    ) -> Result<[u8; 32], String> {
        let req = serde_json::json!({
            "CiphertextBlob": STANDARD.encode(wrapped_dek),
            "EncryptionContext": { "aad_sha256": sha256_hex(aad) }
        });
        let body = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        let res = self.kms_post("TrentService.Decrypt", &body).await?;
        let plain_b64 = res["Plaintext"]
            .as_str()
            .ok_or("KMS Decrypt response missing Plaintext")?;
        let plain = STANDARD
            .decode(plain_b64)
            .map_err(|e| format!("KMS Plaintext decode: {e}"))?;
        if plain.len() != 32 {
            return Err("KMS returned unexpected DEK size".into());
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&plain);
        Ok(dek)
    }
}

pub async fn seal_aead_envelope(
    provider: &dyn KmsEnvelopeProvider,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let (ver, mut dek, wrapped) = provider.generate_data_key(aad).await?;
    let wrapped_len = u16::try_from(wrapped.len())
        .map_err(|_| "wrapped DEK exceeds u16 length bound".to_owned())?;
    let mut full_aad = Vec::with_capacity(8 + wrapped.len() + aad.len());
    full_aad.extend_from_slice(ENVELOPE_MAGIC);
    full_aad.extend_from_slice(&ver.to_be_bytes());
    full_aad.extend_from_slice(&wrapped_len.to_be_bytes());
    full_aad.extend_from_slice(&wrapped);
    full_aad.extend_from_slice(aad);
    let inner = seal_aead(&dek, &full_aad, plaintext);
    dek.zeroize();
    let inner = inner?;
    let mut out = Vec::with_capacity(8 + wrapped.len() + inner.len());
    out.extend_from_slice(ENVELOPE_MAGIC);
    out.extend_from_slice(&ver.to_be_bytes());
    out.extend_from_slice(&wrapped_len.to_be_bytes());
    out.extend_from_slice(&wrapped);
    out.extend_from_slice(&inner);
    Ok(out)
}

pub async fn open_aead_envelope(
    provider: &dyn KmsEnvelopeProvider,
    legacy_ring: &KeyRing,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    if sealed.len() >= 8 && &sealed[..4] == ENVELOPE_MAGIC {
        let ver = u16::from_be_bytes([sealed[4], sealed[5]]);
        let dek_len = usize::from(u16::from_be_bytes([sealed[6], sealed[7]]));
        if dek_len == 0 {
            return open_aead_versioned(legacy_ring, aad, sealed);
        }
        let end_dek = 8 + dek_len;
        if sealed.len() < end_dek + 12 {
            return Err("truncated OQE1 KMS envelope".into());
        }
        let wrapped = &sealed[8..end_dek];
        let mut dek = provider.decrypt_data_key(ver, aad, wrapped).await?;
        let mut full_aad = Vec::with_capacity(8 + dek_len + aad.len());
        full_aad.extend_from_slice(ENVELOPE_MAGIC);
        full_aad.extend_from_slice(&sealed[4..end_dek]);
        full_aad.extend_from_slice(aad);
        let plain = open_aead(&dek, &full_aad, &sealed[end_dek..]);
        dek.zeroize();
        return plain;
    }
    open_aead_versioned(legacy_ring, aad, sealed)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key valid");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn format_amz_datetime(unix_secs: u64) -> (String, String) {
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y_base = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y_base + i64::from(m <= 2);

    let date = format!("{y:04}{m:02}{d:02}");
    let full = format!("{date}T{hour:02}{minute:02}{second:02}Z");
    (date, full)
}

#[must_use]
pub fn sign_session_token(secret: &[u8], session_id: &str) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC key valid");
    mac.update(session_id.as_bytes());
    let sig: [u8; 32] = mac.finalize().into_bytes().into();
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(session_id.as_bytes()),
        URL_SAFE_NO_PAD.encode(sig)
    )
}

#[must_use]
pub fn verify_session_token(secret: &[u8], token: &str) -> Option<String> {
    let (id_b64, sig_b64) = token.split_once('.')?;
    let id_bytes = URL_SAFE_NO_PAD.decode(id_b64).ok()?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).ok()?;
    mac.update(&id_bytes);
    let expected: [u8; 32] = mac.finalize().into_bytes().into();
    if sig_bytes.len() == 32 && constant_time_eq(&sig_bytes, &expected) {
        String::from_utf8(id_bytes).ok()
    } else {
        None
    }
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

#[must_use]
pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[must_use]
pub fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(http::header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let trimmed = pair.trim();
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_owned());
            }
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    fn parse(raw: &str) -> Option<Self> {
        let s = raw.trim();
        if s.is_empty() {
            return None;
        }
        if let Some((ip_s, pfx_s)) = s.split_once('/') {
            let addr: IpAddr = ip_s.trim().parse().ok()?;
            let max_bits = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            let prefix = pfx_s.trim().parse::<u8>().ok()?;
            if prefix > max_bits {
                return None;
            }
            Some(Self { addr, prefix })
        } else {
            let addr: IpAddr = s.parse().ok()?;
            let prefix = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Some(Self { addr, prefix })
        }
    }

    fn contains(&self, candidate: IpAddr) -> bool {
        let norm_self = unmap_v4(self.addr);
        let norm_cand = unmap_v4(candidate);
        match (norm_self, norm_cand) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u32::MAX
                    .checked_shl(u32::from(32 - self.prefix))
                    .unwrap_or(0);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u128::MAX
                    .checked_shl(u32::from(128 - self.prefix))
                    .unwrap_or(0);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

fn unmap_v4(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// Explicit CIDR allowlist governing when proxy forwarding headers
/// (`X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `X-Operquay-Tenant`) may be trusted.
/// Defaults to empty (deny all untrusted proxy headers).
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    nets: Vec<IpNet>,
}

impl TrustedProxies {
    #[must_use]
    pub fn from_env() -> Self {
        let raw = std::env::var("OPERQUAY_TRUSTED_PROXIES")
            .or_else(|_| std::env::var("TRUSTED_PROXIES"))
            .unwrap_or_default();
        Self::parse(&raw)
    }

    #[must_use]
    pub fn parse(spec: &str) -> Self {
        let nets = spec.split(',').filter_map(IpNet::parse).collect();
        Self { nets }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(ip))
    }

    #[must_use]
    pub fn contains_peer(&self, peer: Option<SocketAddr>) -> bool {
        peer.is_some_and(|p| self.contains(p.ip()))
    }
}

/// Resolve client IP using real TCP peer address, honoring `X-Forwarded-For` / `X-Real-IP`
/// **only** when the peer socket address matches [`TrustedProxies`].
#[must_use]
pub fn resolve_client_ip(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted: &TrustedProxies,
) -> String {
    if trusted.contains_peer(peer) {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            // Walk from right-most hop outside trusted proxies when chained, else left-most client.
            let hops: Vec<&str> = xff
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            for hop in hops.iter().rev() {
                if let Ok(ip) = hop.parse::<IpAddr>() {
                    if !trusted.contains(ip) {
                        return unmap_v4(ip).to_string();
                    }
                }
            }
            if let Some(first) = hops.first() {
                return (*first).to_owned();
            }
        }
        if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            let trimmed = xri.trim();
            if !trimmed.is_empty() {
                return trimmed.to_owned();
            }
        }
    }
    peer.map_or_else(
        || IpAddr::V4(Ipv4Addr::LOCALHOST).to_string(),
        |p| unmap_v4(p.ip()).to_string(),
    )
}

/// Extract multi-tenant slug safely: honors `x-operquay-tenant` ONLY when `peer` is in `trusted`,
/// otherwise inspects the verified HTTP `Host` subdomain (ignoring raw IPs and reserved hosts).
#[must_use]
pub fn extract_tenant_id_checked(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted: &TrustedProxies,
) -> String {
    if trusted.contains_peer(peer) {
        if let Some(explicit) = headers
            .get("x-operquay-tenant")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= 64 && s.bytes().all(is_slug_byte))
        {
            return explicit.to_ascii_lowercase();
        }
    }
    extract_tenant_from_host(headers)
}

/// Multi-tenant extractor honoring host subdomain (`{tenant}.domain`) and reserved slugs
/// (`www`, `api`, `app`, `localhost`) defaulting cleanly to `"default"`.
/// Never trusts `x-operquay-tenant` from an unverified peer.
#[must_use]
pub fn extract_tenant_id(headers: &HeaderMap) -> String {
    extract_tenant_from_host(headers)
}

fn extract_tenant_from_host(headers: &HeaderMap) -> String {
    if let Some(host_val) = headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        let host = if host_val.starts_with('[') {
            host_val
                .split_once(']')
                .map_or(host_val, |(h, _)| h.trim_start_matches('['))
        } else {
            host_val.split(':').next().unwrap_or(host_val)
        }
        .trim();
        // Raw IPv4/IPv6 Host headers (e.g. `127.0.0.1:8080`) must not split octets into a tenant slug.
        let is_ip = host.parse::<IpAddr>().is_ok() || host.parse::<Ipv6Addr>().is_ok();
        if !is_ip {
            let parts: Vec<&str> = host.split('.').collect();
            if parts.len() >= 3 {
                let sub = parts[0].to_ascii_lowercase();
                if !matches!(sub.as_str(), "www" | "api" | "app" | "localhost" | "")
                    && sub.bytes().all(is_slug_byte)
                {
                    return sub;
                }
            }
        }
    }
    "default".to_owned()
}

const fn is_slug_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

#[derive(Clone)]
enum TenantKeyState {
    Active([u8; 32]),
    Shredded,
}

impl Drop for TenantKeyState {
    fn drop(&mut self) {
        if let Self::Active(ref mut k) = self {
            k.zeroize();
        }
    }
}

/// Per-tenant Data Encryption Key (`DEK`) registry supporting cryptographic erasure
/// (crypto-shredding) for GDPR/SOC 2 tenant offboarding (`M10.5`).
#[derive(Default)]
pub struct TenantKeyManager {
    keys: tokio::sync::RwLock<HashMap<String, TenantKeyState>>,
}

impl TenantKeyManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get_or_create_key(&self, tenant_id: &str) -> Result<[u8; 32], String> {
        {
            let guard = self.keys.read().await;
            match guard.get(tenant_id) {
                Some(TenantKeyState::Active(k)) => return Ok(*k),
                Some(TenantKeyState::Shredded) => {
                    return Err(format!(
                        "tenant '{tenant_id}' encryption key has been crypto-shredded"
                    ));
                }
                None => {}
            }
        }
        let mut guard = self.keys.write().await;
        match guard.get(tenant_id) {
            Some(TenantKeyState::Active(k)) => return Ok(*k),
            Some(TenantKeyState::Shredded) => {
                return Err(format!(
                    "tenant '{tenant_id}' encryption key has been crypto-shredded"
                ));
            }
            None => {}
        }
        let mut dek = [0u8; 32];
        fill_csprng(&mut dek)?;
        guard.insert(tenant_id.to_owned(), TenantKeyState::Active(dek));
        Ok(dek)
    }

    pub async fn get_key_if_present(&self, tenant_id: &str) -> Result<Option<[u8; 32]>, String> {
        let guard = self.keys.read().await;
        match guard.get(tenant_id) {
            Some(TenantKeyState::Active(k)) => Ok(Some(*k)),
            Some(TenantKeyState::Shredded) => Err(format!(
                "tenant '{tenant_id}' encryption key has been crypto-shredded"
            )),
            None => Ok(None),
        }
    }

    /// Irreversibly zeroize and purge the tenant DEK in memory so all tenant ciphertexts become unrecoverable.
    pub async fn shred_tenant(&self, tenant_id: &str) -> bool {
        let mut guard = self.keys.write().await;
        let existed = guard.remove(tenant_id).is_some();
        guard.insert(tenant_id.to_owned(), TenantKeyState::Shredded);
        existed
    }

    pub async fn is_shredded(&self, tenant_id: &str) -> bool {
        matches!(
            self.keys.read().await.get(tenant_id),
            Some(TenantKeyState::Shredded)
        )
    }

    pub async fn hydrate_key(&self, tenant_id: &str, key: Option<[u8; 32]>, shredded: bool) {
        let mut guard = self.keys.write().await;
        if shredded {
            let _ = guard.remove(tenant_id);
            guard.insert(tenant_id.to_owned(), TenantKeyState::Shredded);
        } else if let Some(k) = key {
            guard.insert(tenant_id.to_owned(), TenantKeyState::Active(k));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csprng_aead_nonces_are_unique_and_open_properly() {
        let key = derive_key32(b"master-test", b"purpose");
        let c1 = seal_aead(&key, b"aad", b"hello").unwrap();
        let c2 = seal_aead(&key, b"aad", b"hello").unwrap();
        assert_ne!(&c1[..12], &c2[..12]);
        assert_eq!(open_aead(&key, b"aad", &c1).unwrap(), b"hello");
        assert!(open_aead(&key, b"wrong-aad", &c1).is_err());
    }

    #[test]
    fn keyring_versioned_envelope_rotates_and_opens_legacy_rows() {
        let v2_hex = "11".repeat(32);
        let ring = KeyRing::from_master_and_spec(
            b"master-secret",
            b"operquay/sso-providers/v1",
            &format!("v2:{v2_hex}"),
            None,
        );
        assert_eq!(ring.active_version(), 2);

        let sealed_v2 = seal_aead_versioned(&ring, b"row-1", b"client-secret").unwrap();
        assert_eq!(&sealed_v2[..4], b"OQE1");
        assert_eq!(
            open_aead_versioned(&ring, b"row-1", &sealed_v2).unwrap(),
            b"client-secret"
        );

        // Legacy ciphertext sealed directly with v1 key must still open seamlessly.
        let v1_key = derive_key32(b"master-secret", b"operquay/sso-providers/v1");
        let legacy = seal_aead(&v1_key, b"row-0", b"old-secret").unwrap();
        assert_eq!(
            open_aead_versioned(&ring, b"row-0", &legacy).unwrap(),
            b"old-secret"
        );
    }

    #[tokio::test]
    async fn local_kms_provider_wraps_and_unwraps_per_record_deks() {
        let ring = KeyRing::from_master_and_spec(b"master", b"kms-test", "", None);
        let provider = LocalKeyRingProvider::new(ring.clone());
        let sealed = seal_aead_envelope(&provider, b"tenant|secret", b"top-secret")
            .await
            .unwrap();
        assert_eq!(&sealed[..4], b"OQE1");
        let opened = open_aead_envelope(&provider, &ring, b"tenant|secret", &sealed)
            .await
            .unwrap();
        assert_eq!(opened, b"top-secret");
        assert!(
            open_aead_envelope(&provider, &ring, b"other-tenant|secret", &sealed)
                .await
                .is_err()
        );
    }

    #[test]
    fn trusted_proxies_blocks_spoofed_headers_from_untrusted_peers() {
        let proxies = TrustedProxies::parse("10.0.0.0/8, 172.16.0.10, fd00::/8");
        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-forwarded-for", "203.0.113.5".parse().unwrap());
        hdrs.insert("x-operquay-tenant", "victim".parse().unwrap());
        hdrs.insert(http::header::HOST, "public.operquay.io".parse().unwrap());

        let untrusted_peer: SocketAddr = "198.51.100.7:4444".parse().unwrap();
        assert_eq!(
            resolve_client_ip(Some(untrusted_peer), &hdrs, &proxies),
            "198.51.100.7"
        );
        assert_eq!(
            extract_tenant_id_checked(Some(untrusted_peer), &hdrs, &proxies),
            "public"
        );

        let trusted_peer: SocketAddr = "10.12.3.4:443".parse().unwrap();
        assert_eq!(
            resolve_client_ip(Some(trusted_peer), &hdrs, &proxies),
            "203.0.113.5"
        );
        assert_eq!(
            extract_tenant_id_checked(Some(trusted_peer), &hdrs, &proxies),
            "victim"
        );

        let mapped_v4_trusted: SocketAddr = "[::ffff:10.2.3.4]:1234".parse().unwrap();
        assert!(proxies.contains(mapped_v4_trusted.ip()));
    }

    #[tokio::test]
    async fn tenant_key_manager_crypto_shredding_renders_tenant_data_unrecoverable() {
        let mgr = TenantKeyManager::new();
        let k_a = mgr.get_or_create_key("tenant-a").await.unwrap();
        let k_b = mgr.get_or_create_key("tenant-b").await.unwrap();
        assert_ne!(k_a, k_b);

        let ct_a = seal_aead(&k_a, b"rec-1", b"secret-recording-a").unwrap();
        let ct_b = seal_aead(&k_b, b"rec-2", b"secret-recording-b").unwrap();

        assert!(mgr.shred_tenant("tenant-a").await);
        assert!(mgr.is_shredded("tenant-a").await);
        assert!(!mgr.is_shredded("tenant-b").await);
        assert!(mgr.get_or_create_key("tenant-a").await.is_err());

        // Attempting re-encryption or retrieval fails; unrelated tenant remains unaffected.
        assert!(mgr.get_key_if_present("tenant-a").await.is_err());
        let k_b_again = mgr.get_or_create_key("tenant-b").await.unwrap();
        assert_eq!(k_b_again, k_b);
        assert_eq!(
            open_aead(&k_b_again, b"rec-2", &ct_b).unwrap(),
            b"secret-recording-b"
        );
        // Zeroizing k_a in caller scope simulates key erasure after shred.
        let mut wiped = k_a;
        wiped.zeroize();
        assert!(open_aead(&wiped, b"rec-1", &ct_a).is_err());
    }
}
