use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use constant_time_eq::constant_time_eq;
use hmac::{Hmac, Mac};
use ring::digest;
use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::crypto::{fill_csprng, sha256_hex};

type HmacSha1 = Hmac<Sha1>;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const RECOVERY_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[must_use]
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = usize::from(((buf >> bits) & 0x1F) as u8);
            out.push(char::from(BASE32_ALPHABET[idx]));
        }
    }
    if bits > 0 {
        let idx = usize::from(((buf << (5 - bits)) & 0x1F) as u8);
        out.push(char::from(BASE32_ALPHABET[idx]));
    }
    out
}

pub fn base32_decode(encoded: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity((encoded.len() * 5) / 8);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    for ch in encoded.chars() {
        if ch == '=' || ch.is_ascii_whitespace() {
            continue;
        }
        let up = ch.to_ascii_uppercase() as u8;
        let val = BASE32_ALPHABET
            .iter()
            .position(|&c| c == up)
            .ok_or_else(|| format!("invalid Base32 character '{ch}'"))? as u32;
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

pub fn generate_totp_secret() -> Result<String, String> {
    let mut raw = [0u8; 20];
    fill_csprng(&mut raw)?;
    Ok(base32_encode(&raw))
}

#[must_use]
pub fn totp_otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    let label = format!("{}:{}", pct_encode(issuer), pct_encode(account));
    format!(
        "otpauth://totp/{label}?secret={secret_b32}&issuer={}&algorithm=SHA1&digits=6&period=30",
        pct_encode(issuer)
    )
}

pub fn compute_totp_code(secret_b32: &str, time_step: i64) -> Result<String, String> {
    let key = base32_decode(secret_b32)?;
    if key.len() < 10 {
        return Err("TOTP secret too short".into());
    }
    let counter = u64::try_from(time_step).unwrap_or(0).to_be_bytes();
    let mut mac = <HmacSha1 as Mac>::new_from_slice(&key).map_err(|e| e.to_string())?;
    mac.update(&counter);
    let hash = mac.finalize().into_bytes();
    let offset = usize::from(hash[19] & 0x0F);
    let bin_code = (u32::from(hash[offset] & 0x7F) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    let otp = bin_code % 1_000_000;
    Ok(format!("{otp:06}"))
}

/// Verify an RFC 6238 6-digit TOTP code across `[step - 1, step, step + 1]` in constant time
/// and prevent same-step replay (`matched_step > last_used_step`). Returns matched step on success.
pub fn verify_totp_code(
    secret_b32: &str,
    code: &str,
    now_unix: i64,
    last_used_step: i64,
) -> Result<i64, String> {
    let clean: String = code
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '-')
        .collect();
    if clean.len() != 6 || !clean.bytes().all(|b| b.is_ascii_digit()) {
        return Err("TOTP code must be 6 digits".into());
    }
    let current_step = now_unix / 30;
    for offset in [-1i64, 0, 1] {
        let step = current_step + offset;
        if step <= last_used_step {
            continue;
        }
        let expected = compute_totp_code(secret_b32, step)?;
        if constant_time_eq(clean.as_bytes(), expected.as_bytes()) {
            return Ok(step);
        }
    }
    Err("invalid or already used TOTP authenticator code".into())
}

pub fn generate_recovery_codes(count: usize) -> Result<Vec<String>, String> {
    let mut codes = Vec::with_capacity(count);
    let mut rand = [0u8; 9];
    for _ in 0..count {
        fill_csprng(&mut rand)?;
        let mut s = String::with_capacity(10);
        for (idx, &b) in rand.iter().enumerate() {
            if idx == 4 {
                s.push('-');
            }
            s.push(char::from(
                RECOVERY_ALPHABET[usize::from(b) % RECOVERY_ALPHABET.len()],
            ));
        }
        codes.push(s);
    }
    Ok(codes)
}

#[must_use]
pub fn hash_recovery_code(code: &str) -> String {
    let normalized: String = code
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    sha256_hex(normalized.as_bytes())
}

pub fn consume_recovery_code(hashes: &mut Vec<String>, candidate: &str) -> bool {
    let target = hash_recovery_code(candidate);
    if target.len() != 64 {
        return false;
    }
    if let Some(pos) = hashes
        .iter()
        .position(|h| h.len() == target.len() && constant_time_eq(h.as_bytes(), target.as_bytes()))
    {
        hashes.remove(pos);
        true
    } else {
        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    pub id: String,
    pub label: String,
    pub public_key_spki_b64: String,
    pub alg: i32,
    pub sign_count: u32,
    pub created_at: i64,
}

enum SpkiPublicKey {
    EcP256(Vec<u8>),
    Ed25519(Vec<u8>),
    RsaPkcs1(Vec<u8>),
}

fn parse_der_tlv(input: &[u8]) -> Option<(u8, &[u8], usize)> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    let first = input[1];
    let (len, hdr) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 || n > 4 || input.len() < 2 + n {
            return None;
        }
        let mut l = 0usize;
        for &b in &input[2..2 + n] {
            l = (l << 8) | usize::from(b);
        }
        (l, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    if input.len() < end {
        return None;
    }
    Some((tag, &input[hdr..end], end))
}

fn parse_spki_der(spki_der: &[u8]) -> Result<SpkiPublicKey, String> {
    const OID_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    const OID_EC: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];

    let (tag, body, _) = parse_der_tlv(spki_der).ok_or("invalid SPKI ASN.1 sequence")?;
    if tag != 0x30 {
        return Err("SPKI is not a SEQUENCE".into());
    }
    let (alg_tag, alg_val, alg_len) =
        parse_der_tlv(body).ok_or("SPKI missing AlgorithmIdentifier")?;
    if alg_tag != 0x30 {
        return Err("SPKI AlgorithmIdentifier is not a SEQUENCE".into());
    }
    let (oid_tag, oid_val, oid_len) = parse_der_tlv(alg_val).ok_or("SPKI missing OID")?;
    if oid_tag != 0x06 {
        return Err("SPKI AlgorithmIdentifier missing OID tag".into());
    }
    let (bs_tag, bs_val, _) = parse_der_tlv(&body[alg_len..]).ok_or("SPKI missing BIT STRING")?;
    if bs_tag != 0x03 || bs_val.len() < 2 {
        return Err("SPKI subjectPublicKey must be BIT STRING".into());
    }
    let raw_key = bs_val[1..].to_vec();

    if oid_val == OID_EC {
        let (curve_tag, curve_val, _) =
            parse_der_tlv(&alg_val[oid_len..]).ok_or("EC SPKI missing curve OID")?;
        if curve_tag != 0x06 || curve_val != OID_P256 {
            return Err("only P-256 ES256 EC passkeys are supported".into());
        }
        Ok(SpkiPublicKey::EcP256(raw_key))
    } else if oid_val == OID_ED25519 {
        Ok(SpkiPublicKey::Ed25519(raw_key))
    } else if oid_val == OID_RSA {
        Ok(SpkiPublicKey::RsaPkcs1(raw_key))
    } else {
        Err("unsupported passkey public key algorithm OID".into())
    }
}

pub fn decode_b64url_flexible(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim().trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s.trim()))
        .map_err(|e| format!("invalid base64url payload: {e}"))
}

pub fn validate_webauthn_client_data(
    client_data_b64: &str,
    expected_type: &str,
    expected_challenge: &str,
    expected_origin: Option<&str>,
) -> Result<Vec<u8>, String> {
    let raw = decode_b64url_flexible(client_data_b64)?;
    let parsed: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| format!("invalid clientDataJSON: {e}"))?;
    if parsed["type"].as_str() != Some(expected_type) {
        return Err(format!(
            "unexpected WebAuthn ceremony type (expected '{expected_type}')"
        ));
    }
    let ch = parsed["challenge"]
        .as_str()
        .ok_or("clientDataJSON missing challenge")?;
    let ch_norm = ch.trim().trim_end_matches('=');
    let exp_norm = expected_challenge.trim().trim_end_matches('=');
    if ch_norm.len() != exp_norm.len() || !constant_time_eq(ch_norm.as_bytes(), exp_norm.as_bytes())
    {
        return Err("WebAuthn challenge mismatch".into());
    }
    if let Some(exp_orig) = expected_origin {
        let actual_orig = parsed["origin"]
            .as_str()
            .ok_or("clientDataJSON missing origin")?;
        if actual_orig.trim_end_matches('/') != exp_orig.trim_end_matches('/') {
            return Err(format!("WebAuthn origin '{actual_orig}' mismatch"));
        }
    }
    Ok(raw)
}

/// Validate registration public key SPKI & clientDataJSON during passkey enrollment.
pub fn validate_webauthn_registration(
    public_key_spki_b64: &str,
    alg: i32,
    client_data_b64: &str,
    expected_challenge: &str,
    expected_origin: Option<&str>,
) -> Result<(), String> {
    let _ = validate_webauthn_client_data(
        client_data_b64,
        "webauthn.create",
        expected_challenge,
        expected_origin,
    )?;
    let spki_der = decode_b64url_flexible(public_key_spki_b64)?;
    let parsed = parse_spki_der(&spki_der)?;
    match (alg, parsed) {
        (-7, SpkiPublicKey::EcP256(_))
        | (-8, SpkiPublicKey::Ed25519(_))
        | (-257, SpkiPublicKey::RsaPkcs1(_)) => Ok(()),
        _ => Err(format!(
            "WebAuthn COSE algorithm {alg} does not match SPKI key"
        )),
    }
}

/// Verify a WebAuthn `webauthn.get` assertion (`clientDataJSON`, `authenticatorData`, `signature`)
/// and return the new monotonic `signCount`.
pub fn verify_webauthn_assertion(
    cred: &WebAuthnCredential,
    expected_challenge: &str,
    expected_origin: Option<&str>,
    expected_rp_id: &str,
    client_data_b64: &str,
    authenticator_data_b64: &str,
    signature_b64: &str,
) -> Result<u32, String> {
    let client_data_raw = validate_webauthn_client_data(
        client_data_b64,
        "webauthn.get",
        expected_challenge,
        expected_origin,
    )?;
    let auth_data = decode_b64url_flexible(authenticator_data_b64)?;
    if auth_data.len() < 37 {
        return Err("WebAuthn authenticatorData shorter than 37 bytes".into());
    }
    let expected_rp_hash: [u8; 32] = Sha256::digest(expected_rp_id.as_bytes()).into();
    if !constant_time_eq(&auth_data[..32], &expected_rp_hash) {
        return Err("WebAuthn rpIdHash mismatch".into());
    }
    let flags = auth_data[32];
    if (flags & 0x01) == 0 {
        return Err("WebAuthn User Present (UP) flag missing".into());
    }
    let new_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    if (cred.sign_count > 0 || new_count > 0) && new_count <= cred.sign_count {
        return Err("WebAuthn signCount did not increase (possible cloned authenticator)".into());
    }

    let client_hash = digest::digest(&digest::SHA256, &client_data_raw);
    let mut signed_msg = Vec::with_capacity(auth_data.len() + 32);
    signed_msg.extend_from_slice(&auth_data);
    signed_msg.extend_from_slice(client_hash.as_ref());

    let sig_bytes = decode_b64url_flexible(signature_b64)?;
    let spki_der = decode_b64url_flexible(&cred.public_key_spki_b64)?;
    match parse_spki_der(&spki_der)? {
        SpkiPublicKey::EcP256(pt) => {
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &pt)
                .verify(&signed_msg, &sig_bytes)
                .or_else(|_| {
                    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &pt)
                        .verify(&signed_msg, &sig_bytes)
                })
                .map_err(|_| "WebAuthn ES256 assertion signature invalid".to_owned())?;
        }
        SpkiPublicKey::Ed25519(pk) => UnparsedPublicKey::new(&signature::ED25519, &pk)
            .verify(&signed_msg, &sig_bytes)
            .map_err(|_| "WebAuthn Ed25519 assertion signature invalid".to_owned())?,
        SpkiPublicKey::RsaPkcs1(der) => {
            UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &der)
                .verify(&signed_msg, &sig_bytes)
                .map_err(|_| "WebAuthn RS256 assertion signature invalid".to_owned())?;
        }
    }

    Ok(new_count)
}

fn pct_encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() * 2);
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    #[test]
    fn totp_verifies_window_and_blocks_same_step_replay() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let now = 1_700_000_010;
        let code = compute_totp_code(secret, now / 30).unwrap();
        assert_eq!(code.len(), 6);
        let step = verify_totp_code(secret, &code, now, 0).unwrap();
        assert_eq!(step, now / 30);
        // Replay on the exact same counter step must fail closed.
        assert!(verify_totp_code(secret, &code, now, step).is_err());
        assert!(verify_totp_code(secret, "000000", now, 0).is_err());
    }

    #[test]
    fn recovery_codes_are_single_use() {
        let codes = generate_recovery_codes(4).unwrap();
        let mut hashes: Vec<String> = codes.iter().map(|c| hash_recovery_code(c)).collect();
        assert!(consume_recovery_code(&mut hashes, &codes[0]));
        assert!(!consume_recovery_code(&mut hashes, &codes[0]));
        assert_eq!(hashes.len(), 3);
    }

    #[test]
    fn webauthn_es256_assertion_verifies_and_enforces_sign_count() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let pub_bytes = kp.public_key().as_ref();
        // Wrap EC uncompressed point into X.509 SPKI DER for P-256.
        let mut spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
            0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        spki.extend_from_slice(pub_bytes);

        let challenge = "challenge-token-123";
        let origin = "https://localhost:5444";
        let rp_id = "localhost";
        let client_data_json = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": origin,
        })
        .to_string();
        let client_b64 = URL_SAFE_NO_PAD.encode(client_data_json.as_bytes());

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        auth_data.push(0x05); // UP | UV
        auth_data.extend_from_slice(&5u32.to_be_bytes());
        let auth_b64 = URL_SAFE_NO_PAD.encode(&auth_data);

        let mut signed = auth_data;
        signed.extend_from_slice(&Sha256::digest(client_data_json.as_bytes()));
        let sig = kp.sign(&rng, &signed).unwrap();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let cred = WebAuthnCredential {
            id: "cred-1".into(),
            label: "MacBook Touch ID".into(),
            public_key_spki_b64: URL_SAFE_NO_PAD.encode(&spki),
            alg: -7,
            sign_count: 1,
            created_at: 1,
        };
        let next_cnt = verify_webauthn_assertion(
            &cred,
            challenge,
            Some(origin),
            rp_id,
            &client_b64,
            &auth_b64,
            &sig_b64,
        )
        .unwrap();
        assert_eq!(next_cnt, 5);

        // Replayed / rolled-back signCount must fail closed.
        let mut stale_cred = cred.clone();
        stale_cred.sign_count = 5;
        assert!(verify_webauthn_assertion(
            &stale_cred,
            challenge,
            Some(origin),
            rp_id,
            &client_b64,
            &auth_b64,
            &sig_b64,
        )
        .is_err());
    }
}
