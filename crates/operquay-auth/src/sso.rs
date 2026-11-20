use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use constant_time_eq::constant_time_eq;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{open_aead_versioned, random_token_b64, seal_aead_versioned, KeyRing};
use crate::xmldsig::{extract_certs_from_idp_metadata, verify_saml_xml_signature, XmlElem};

const CLOCK_SKEW_SECS: i64 = 60;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SsoProviderConfig {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(rename = "type", default)]
    pub provider_type: String, // "oidc" | "saml"
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub redirect_url: String,
    #[serde(default)]
    pub metadata_url: String,
    #[serde(default)]
    pub metadata_xml: String,
    #[serde(default)]
    pub entity_id: String,
    #[serde(default)]
    pub sso_url: String,
    #[serde(default)]
    pub slo_url: String,
    #[serde(default)]
    pub certificate_pem: String,
    #[serde(default)]
    pub groups_attribute: String,
    #[serde(default)]
    pub default_role: String,
    #[serde(default, alias = "domains")]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub viewer_groups: Vec<String>,
    #[serde(default)]
    pub admin_groups: Vec<String>,
    #[serde(default)]
    pub operator_groups: Vec<String>,
    #[serde(default)]
    pub require_email_verified: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SsoProviderPatch {
    pub label: Option<String>,
    #[serde(rename = "type")]
    pub provider_type: Option<String>,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_url: Option<String>,
    pub metadata_url: Option<String>,
    pub metadata_xml: Option<String>,
    pub entity_id: Option<String>,
    pub sso_url: Option<String>,
    pub slo_url: Option<String>,
    pub certificate_pem: Option<String>,
    pub groups_attribute: Option<String>,
    pub default_role: Option<String>,
    #[serde(alias = "domains")]
    pub allowed_domains: Option<Vec<String>>,
    pub viewer_groups: Option<Vec<String>>,
    pub admin_groups: Option<Vec<String>>,
    pub operator_groups: Option<Vec<String>>,
    pub require_email_verified: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoProviderPublic {
    pub id: String,
    pub tenant_id: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    pub label: String,
    pub editable: bool,
    pub issuer: String,
    pub client_id: String,
    pub entity_id: String,
    pub idp_entity_id: String,
    pub idp_metadata_url: String,
    pub sso_url: String,
    pub redirect_url: String,
    pub groups_attribute: String,
    pub default_role: String,
    pub domains: Vec<String>,
    pub viewer_groups: Vec<String>,
    pub admin_groups: Vec<String>,
    pub operator_groups: Vec<String>,
    pub require_email_verified: bool,
    pub secret_configured: bool,
}

impl SsoProviderConfig {
    #[must_use]
    pub fn to_public(&self) -> SsoProviderPublic {
        SsoProviderPublic {
            id: self.id.clone(),
            tenant_id: self.tenant_id.clone(),
            provider_type: self.provider_type.clone(),
            label: self.label.clone(),
            editable: true,
            issuer: self.issuer.clone(),
            client_id: self.client_id.clone(),
            entity_id: self.entity_id.clone(),
            idp_entity_id: self.entity_id.clone(),
            idp_metadata_url: self.metadata_url.clone(),
            sso_url: self.sso_url.clone(),
            redirect_url: self.redirect_url.clone(),
            groups_attribute: self.groups_attribute.clone(),
            default_role: if self.default_role.is_empty() {
                "readonly".to_owned()
            } else {
                self.default_role.clone()
            },
            domains: self.allowed_domains.clone(),
            viewer_groups: self.viewer_groups.clone(),
            admin_groups: self.admin_groups.clone(),
            operator_groups: self.operator_groups.clone(),
            require_email_verified: self.require_email_verified.unwrap_or(true),
            secret_configured: !self.client_secret.is_empty(),
        }
    }

    pub fn seal(&self, master: &[u8]) -> Result<Vec<u8>, String> {
        let ring = KeyRing::from_master_and_env(master, b"operquay/sso-providers/v1");
        let raw = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        seal_aead_versioned(&ring, self.id.as_bytes(), &raw)
    }

    pub fn open(master: &[u8], id: &str, sealed: &[u8]) -> Result<Self, String> {
        let ring = KeyRing::from_master_and_env(master, b"operquay/sso-providers/v1");
        let plain = open_aead_versioned(&ring, id.as_bytes(), sealed)?;
        serde_json::from_slice(&plain).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcPendingState {
    pub provider_id: String,
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub created_ms: u64,
}

#[derive(Debug, Deserialize)]
pub struct OidcDiscovery {
    #[serde(default)]
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwkKey {
    #[serde(default)]
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(rename = "use", default)]
    pub key_use: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct JwkSet {
    #[serde(default)]
    pub keys: Vec<JwkKey>,
}

#[derive(Debug, Clone)]
pub struct OidcValidationParams<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: Option<&'a str>,
    pub now_unix: i64,
    pub require_email_verified: bool,
}

#[derive(Debug, Deserialize)]
pub struct OidcTokenResponse {
    pub access_token: Option<String>,
    pub id_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoIdentityClaims {
    pub email: String,
    pub name: String,
    pub username: String,
    pub subject: String,
    pub groups: Vec<String>,
    pub nonce: Option<String>,
}

/// Build S256 PKCE authorization redirect URL & ephemeral pending state.
#[must_use]
pub fn build_oidc_authorize_url(
    cfg: &SsoProviderConfig,
    auth_endpoint: &str,
) -> (String, OidcPendingState) {
    let state = random_token_b64();
    let nonce = random_token_b64();
    let code_verifier = format!("{}{}", random_token_b64(), random_token_b64());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));

    let sep = if auth_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    let url = format!(
        "{auth_endpoint}{sep}response_type=code&client_id={}&redirect_uri={}&scope=openid%20email%20profile&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        url_encode(&cfg.client_id),
        url_encode(&cfg.redirect_url),
        url_encode(&state),
        url_encode(&nonce),
        url_encode(&challenge),
    );
    let pending = OidcPendingState {
        provider_id: cfg.id.clone(),
        state,
        nonce,
        code_verifier,
        created_ms: 0,
    };
    (url, pending)
}

pub async fn fetch_oidc_jwks(jwks_uri: &str) -> Result<JwkSet, String> {
    if jwks_uri.trim().is_empty() {
        return Err("OIDC discovery document missing jwks_uri".into());
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| format!("JWKS fetch error: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("OIDC JWKS HTTP {}", resp.status()));
    }
    resp.json::<JwkSet>()
        .await
        .map_err(|e| format!("invalid OIDC JWKS JSON: {e}"))
}

fn push_der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x83);
        let b = (len as u32).to_be_bytes();
        out.extend_from_slice(&b[1..]);
    }
}

fn push_der_uint(out: &mut Vec<u8>, mut bytes: &[u8]) {
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes = &bytes[1..];
    }
    let need_pad = bytes.first().is_none_or(|b| *b >= 0x80);
    let len = bytes.len() + usize::from(need_pad);
    out.push(0x02);
    push_der_len(out, len);
    if need_pad {
        out.push(0x00);
    }
    out.extend_from_slice(bytes);
}

fn rsa_jwk_to_pkcs1_der(jwk: &JwkKey) -> Result<Vec<u8>, String> {
    let n_b64 = jwk.n.as_deref().ok_or("RSA JWK missing 'n'")?;
    let e_b64 = jwk.e.as_deref().ok_or("RSA JWK missing 'e'")?;
    let n = URL_SAFE_NO_PAD
        .decode(n_b64)
        .map_err(|err| format!("RSA JWK invalid n: {err}"))?;
    let e = URL_SAFE_NO_PAD
        .decode(e_b64)
        .map_err(|err| format!("RSA JWK invalid e: {err}"))?;
    let mut inner = Vec::with_capacity(n.len() + e.len() + 8);
    push_der_uint(&mut inner, &n);
    push_der_uint(&mut inner, &e);
    let mut seq = Vec::with_capacity(inner.len() + 4);
    seq.push(0x30);
    push_der_len(&mut seq, inner.len());
    seq.extend_from_slice(&inner);
    Ok(seq)
}

fn ec_jwk_to_uncompressed(jwk: &JwkKey, coord_len: usize) -> Result<Vec<u8>, String> {
    let x_b64 = jwk.x.as_deref().ok_or("EC JWK missing 'x'")?;
    let y_b64 = jwk.y.as_deref().ok_or("EC JWK missing 'y'")?;
    let x = URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|e| format!("EC JWK invalid x: {e}"))?;
    let y = URL_SAFE_NO_PAD
        .decode(y_b64)
        .map_err(|e| format!("EC JWK invalid y: {e}"))?;
    if x.len() > coord_len || y.len() > coord_len {
        return Err("EC JWK coordinate length exceeds curve size".into());
    }
    let mut pt = vec![0u8; 1 + coord_len * 2];
    pt[0] = 0x04;
    pt[(1 + (coord_len - x.len()))..=coord_len].copy_from_slice(&x);
    pt[1 + coord_len + (coord_len - y.len())..].copy_from_slice(&y);
    Ok(pt)
}

fn verify_jws_with_jwk(
    alg: &str,
    jwk: &JwkKey,
    signing_input: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    if jwk.key_use.as_deref() == Some("enc") {
        return Err("encryption-only JWK rejected for signature verification".into());
    }
    if let Some(ref key_alg) = jwk.alg {
        if key_alg != alg {
            return Err(format!("JWK alg '{key_alg}' mismatch with JWT alg '{alg}'"));
        }
    }
    match alg {
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => {
            if jwk.kty != "RSA" {
                return Err("non-RSA JWK cannot verify RSA JWT".into());
            }
            let der = rsa_jwk_to_pkcs1_der(jwk)?;
            let ring_alg: &dyn signature::VerificationAlgorithm = match alg {
                "RS256" => &signature::RSA_PKCS1_2048_8192_SHA256,
                "RS384" => &signature::RSA_PKCS1_2048_8192_SHA384,
                "RS512" => &signature::RSA_PKCS1_2048_8192_SHA512,
                "PS256" => &signature::RSA_PSS_2048_8192_SHA256,
                "PS384" => &signature::RSA_PSS_2048_8192_SHA384,
                "PS512" => &signature::RSA_PSS_2048_8192_SHA512,
                _ => unreachable!(),
            };
            UnparsedPublicKey::new(ring_alg, &der)
                .verify(signing_input, sig)
                .map_err(|_| format!("OIDC JWS {alg} signature invalid"))
        }
        "ES256" => {
            if jwk.kty != "EC" || jwk.crv.as_deref() != Some("P-256") {
                return Err("ES256 requires EC P-256 JWK".into());
            }
            let pt = ec_jwk_to_uncompressed(jwk, 32)?;
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &pt)
                .verify(signing_input, sig)
                .map_err(|_| "OIDC JWS ES256 signature invalid".to_owned())
        }
        "ES384" => {
            if jwk.kty != "EC" || jwk.crv.as_deref() != Some("P-384") {
                return Err("ES384 requires EC P-384 JWK".into());
            }
            let pt = ec_jwk_to_uncompressed(jwk, 48)?;
            UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &pt)
                .verify(signing_input, sig)
                .map_err(|_| "OIDC JWS ES384 signature invalid".to_owned())
        }
        "EdDSA" => {
            if jwk.kty != "OKP" || jwk.crv.as_deref() != Some("Ed25519") {
                return Err("EdDSA requires OKP Ed25519 JWK".into());
            }
            let x_b64 = jwk.x.as_deref().ok_or("Ed25519 JWK missing 'x'")?;
            let pk = URL_SAFE_NO_PAD
                .decode(x_b64)
                .map_err(|e| format!("Ed25519 JWK invalid x: {e}"))?;
            UnparsedPublicKey::new(&signature::ED25519, &pk)
                .verify(signing_input, sig)
                .map_err(|_| "OIDC JWS EdDSA signature invalid".to_owned())
        }
        other => Err(format!(
            "unsupported OIDC JWT signature algorithm '{other}'"
        )),
    }
}

/// Cryptographically verify an OIDC ID-token JWS against `IdP` JWKS keys, pinning allowed asymmetric
/// algorithms (explicitly rejecting `alg: none` and HMAC `HS*` confusion) and validating `iss`,
/// `aud`, `exp`, `nbf`, `nonce`, and `email_verified`.
pub fn verify_oidc_id_token(
    jwt: &str,
    jwks: &JwkSet,
    expected: &OidcValidationParams<'_>,
) -> Result<serde_json::Value, String> {
    let segments: Vec<&str> = jwt.split('.').collect();
    if segments.len() != 3 || segments.iter().any(|s| s.is_empty()) {
        return Err("invalid compact OIDC JWT (must have header.payload.signature)".into());
    }
    let hdr_bytes = URL_SAFE_NO_PAD
        .decode(segments[0])
        .map_err(|e| format!("invalid JWT header base64url: {e}"))?;
    let hdr: serde_json::Value =
        serde_json::from_slice(&hdr_bytes).map_err(|e| format!("invalid JWT header JSON: {e}"))?;
    let alg = hdr["alg"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("OIDC JWT header missing 'alg'")?;

    if alg.eq_ignore_ascii_case("none") || alg.to_ascii_uppercase().starts_with("HS") {
        return Err(format!(
            "insecure/symmetric OIDC JWT algorithm '{alg}' rejected"
        ));
    }
    if !matches!(
        alg,
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" | "ES256" | "ES384" | "EdDSA"
    ) {
        return Err(format!("unsupported OIDC JWT algorithm '{alg}'"));
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(segments[2])
        .map_err(|e| format!("invalid JWT signature base64url: {e}"))?;
    let signing_input = format!("{}.{}", segments[0], segments[1]);

    let kid = hdr["kid"].as_str().map(str::trim).filter(|s| !s.is_empty());
    let candidates: Vec<&JwkKey> = jwks
        .keys
        .iter()
        .filter(|k| match kid {
            Some(target_kid) => k.kid.as_deref() == Some(target_kid),
            None => true,
        })
        .collect();
    if candidates.is_empty() {
        return Err("no matching key found in IdP JWKS for ID token 'kid'".into());
    }

    let mut verified = false;
    let mut last_err = "OIDC ID token signature verification failed".to_owned();
    for jwk in candidates {
        match verify_jws_with_jwk(alg, jwk, signing_input.as_bytes(), &sig_bytes) {
            Ok(()) => {
                verified = true;
                break;
            }
            Err(e) => last_err = e,
        }
    }
    if !verified {
        return Err(last_err);
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(segments[1])
        .map_err(|e| format!("invalid JWT payload base64url: {e}"))?;
    let claims: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("invalid JWT JSON: {e}"))?;

    if !expected.issuer.trim().is_empty() {
        let iss = claims["iss"].as_str().unwrap_or("").trim();
        if iss.trim_end_matches('/') != expected.issuer.trim().trim_end_matches('/') {
            return Err("OIDC token 'iss' claim mismatch".into());
        }
    }

    if !expected.client_id.trim().is_empty() {
        let cid = expected.client_id.trim();
        let aud_ok = match &claims["aud"] {
            serde_json::Value::String(s) => s == cid,
            serde_json::Value::Array(arr) => {
                let contains_cid = arr.iter().any(|v| v.as_str() == Some(cid));
                if contains_cid && arr.len() > 1 {
                    claims["azp"].as_str().is_none_or(|azp| azp == cid)
                } else {
                    contains_cid
                }
            }
            _ => false,
        };
        if !aud_ok {
            return Err("OIDC token 'aud'/'azp' claim mismatch".into());
        }
    }

    let exp = claims["exp"]
        .as_i64()
        .ok_or("OIDC token missing integer 'exp' claim")?;
    if expected.now_unix > exp + CLOCK_SKEW_SECS {
        return Err("OIDC ID token is expired ('exp')".into());
    }
    if let Some(nbf) = claims["nbf"].as_i64() {
        if expected.now_unix + CLOCK_SKEW_SECS < nbf {
            return Err("OIDC ID token not yet valid ('nbf')".into());
        }
    }

    if let Some(exp_nonce) = expected.nonce {
        let actual = claims["nonce"]
            .as_str()
            .ok_or("OIDC ID token missing 'nonce' claim")?;
        if actual.len() != exp_nonce.len()
            || !constant_time_eq(actual.as_bytes(), exp_nonce.as_bytes())
        {
            return Err("OIDC nonce mismatch".into());
        }
    }

    if expected.require_email_verified
        && claims
            .get("email_verified")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
    {
        return Err("OIDC identity email is not verified at the IdP".into());
    }

    Ok(claims)
}

pub fn claims_from_oidc_json(
    val: &serde_json::Value,
    groups_attr: &str,
) -> Result<SsoIdentityClaims, String> {
    let email = val["email"]
        .as_str()
        .or_else(|| val["upn"].as_str())
        .or_else(|| val["preferred_username"].as_str())
        .unwrap_or("")
        .trim()
        .to_owned();
    let subject = val["sub"].as_str().unwrap_or(&email).trim().to_owned();
    if email.is_empty() && subject.is_empty() {
        return Err("OIDC token missing email and subject claims".into());
    }
    let name = val["name"].as_str().unwrap_or(&email).trim().to_owned();
    let username = val["preferred_username"]
        .as_str()
        .unwrap_or(&email)
        .trim()
        .to_owned();
    let attr_key = if groups_attr.is_empty() {
        "groups"
    } else {
        groups_attr
    };
    let groups = val[attr_key].as_array().map_or_default(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(str::trim))
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    });

    Ok(SsoIdentityClaims {
        email: if email.is_empty() {
            format!("{subject}@sso.local")
        } else {
            email
        },
        name,
        username,
        subject,
        groups,
        nonce: val["nonce"].as_str().map(str::to_owned),
    })
}

pub async fn discover_oidc(issuer: &str) -> Result<OidcDiscovery, String> {
    let base = issuer.trim_end_matches('/');
    let url = format!("{base}/.well-known/openid-configuration");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("OIDC discovery HTTP {}", resp.status()));
    }
    resp.json::<OidcDiscovery>()
        .await
        .map_err(|e| e.to_string())
}

pub async fn exchange_oidc_code(
    cfg: &SsoProviderConfig,
    token_endpoint: &str,
    code: &str,
    verifier: &str,
) -> Result<OidcTokenResponse, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", cfg.redirect_url.as_str()),
        ("client_id", cfg.client_id.as_str()),
        ("client_secret", cfg.client_secret.as_str()),
        ("code_verifier", verifier),
    ];
    let resp = client
        .post(token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("OIDC token exchange HTTP {}", resp.status()));
    }
    resp.json::<OidcTokenResponse>()
        .await
        .map_err(|e| e.to_string())
}

/// Generate clean SAML 2.0 SP `<EntityDescriptor>` Metadata XML.
#[must_use]
pub fn render_saml_sp_metadata(entity_id: &str, acs_url: &str, slo_url: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="1" isDefault="true"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{slo}"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"#,
        entity = xml_escape(entity_id),
        acs = xml_escape(acs_url),
        slo = xml_escape(slo_url),
    )
}

#[derive(Debug, Default)]
pub struct SamlPendingTracker {
    pending: HashMap<String, Instant>,
    consumed: HashSet<String>,
}

impl SamlPendingTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build_redirect_request(
        &mut self,
        cfg: &SsoProviderConfig,
        acs_url: &str,
        issue_instant: &str,
    ) -> (String, String) {
        let req_id = format!("_oq{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..8]));
        let now = Instant::now();
        self.pending.retain(|_, exp| *exp > now);
        self.pending
            .insert(req_id.clone(), now + Duration::from_secs(600));

        let entity = if cfg.entity_id.is_empty() {
            acs_url
        } else {
            &cfg.entity_id
        };
        let xml = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{req_id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{dest}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{acs}"><saml:Issuer>{issuer}</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>"#,
            dest = xml_escape(&cfg.sso_url),
            acs = xml_escape(acs_url),
            issuer = xml_escape(entity),
        );

        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        let _ = enc.write_all(xml.as_bytes());
        let deflated = enc.finish().unwrap_or_else(|_| xml.into_bytes());
        let saml_req = STANDARD.encode(deflated);
        let sep = if cfg.sso_url.contains('?') { '&' } else { '?' };
        let redirect_url = format!(
            "{}{}SAMLRequest={}",
            cfg.sso_url,
            sep,
            url_encode(&saml_req)
        );
        (redirect_url, req_id)
    }

    pub fn consume_response_id(
        &mut self,
        in_response_to: &str,
        assertion_id: &str,
    ) -> Result<(), String> {
        if !assertion_id.is_empty() && !self.consumed.insert(assertion_id.to_owned()) {
            return Err("replayed SAML assertion ID rejected".into());
        }
        if !in_response_to.is_empty() {
            let Some(exp) = self.pending.remove(in_response_to) else {
                return Err("unrecognized or expired SAML AuthnRequest InResponseTo".into());
            };
            if Instant::now() > exp {
                return Err("SAML AuthnRequest expired".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SamlValidationParams<'a> {
    pub cfg: &'a SsoProviderConfig,
    pub expected_audience: &'a str,
    pub expected_recipient: &'a str,
    pub now_unix: i64,
    pub compliance_mode: bool,
}

fn find_child<'a>(elem: &'a XmlElem, local: &str) -> Option<&'a XmlElem> {
    elem.child_elems()
        .into_iter()
        .find(|c| c.local_name() == local)
}

/// Cryptographically verify SAML 2.0 XML-DSig signature, enforce anti-XSW & Conditions/Audience/Recipient
/// checks, and extract identity claims strictly from the verified `<saml:Assertion>` subtree.
pub fn verify_and_parse_saml_response_b64(
    saml_response_b64: &str,
    params: &SamlValidationParams<'_>,
) -> Result<(String, String, SsoIdentityClaims), String> {
    let xml_bytes = STANDARD
        .decode(saml_response_b64.trim())
        .map_err(|e| format!("invalid SAMLResponse base64: {e}"))?;
    let xml = String::from_utf8(xml_bytes).map_err(|e| format!("invalid SAML XML UTF-8: {e}"))?;

    let mut cert_pems = Vec::new();
    if !params.cfg.certificate_pem.trim().is_empty() {
        cert_pems.push(params.cfg.certificate_pem.clone());
    }
    if !params.cfg.metadata_xml.trim().is_empty() {
        cert_pems.extend(extract_certs_from_idp_metadata(&params.cfg.metadata_xml));
    }

    let verified = verify_saml_xml_signature(&xml, &cert_pems, params.compliance_mode)?;

    // Check top-level Response StatusCode & Destination.
    let status_ok = find_child(&verified.response, "Status")
        .and_then(|st| find_child(st, "StatusCode"))
        .and_then(|sc| sc.attr("Value"))
        .is_some_and(|val| val.ends_with(":Success"));
    if !status_ok {
        return Err("SAML Response StatusCode is not Success".into());
    }

    if let Some(dest) = verified.response.attr("Destination") {
        let exp = params.expected_recipient.trim();
        if !exp.is_empty() && dest.trim() != exp {
            return Err(format!(
                "SAML Response Destination '{dest}' does not match ACS URL '{exp}'"
            ));
        }
    }

    let in_response_to = verified
        .response
        .attr("InResponseTo")
        .unwrap_or("")
        .trim()
        .to_owned();
    let assertion = &verified.assertion;
    let assertion_id = assertion.attr("ID").unwrap_or("").trim().to_owned();

    // Validate <Subject>/<NameID> & <SubjectConfirmationData>.
    let subject = find_child(assertion, "Subject");
    let name_id = subject
        .and_then(|s| find_child(s, "NameID"))
        .map_or_default(|n| n.text_content().trim().to_owned());

    if let Some(subj) = subject {
        if let Some(sc) = find_child(subj, "SubjectConfirmation") {
            if let Some(scd) = find_child(sc, "SubjectConfirmationData") {
                if let Some(recip) = scd.attr("Recipient") {
                    let exp = params.expected_recipient.trim();
                    if !exp.is_empty() && recip.trim() != exp {
                        return Err(format!(
                            "SAML SubjectConfirmationData Recipient '{recip}' does not match '{exp}'"
                        ));
                    }
                }
                if let Some(scd_irt) = scd.attr("InResponseTo") {
                    if !in_response_to.is_empty() && scd_irt.trim() != in_response_to {
                        return Err("SAML SubjectConfirmationData InResponseTo mismatch".into());
                    }
                }
                if let Some(nooa) = scd.attr("NotOnOrAfter") {
                    let ts = parse_iso8601_utc(nooa)?;
                    if params.now_unix > ts + CLOCK_SKEW_SECS {
                        return Err("SAML SubjectConfirmationData expired".into());
                    }
                }
            }
        }
    }

    // Validate <Conditions NotBefore NotOnOrAfter> & <AudienceRestriction>/<Audience>.
    if let Some(cond) = find_child(assertion, "Conditions") {
        if let Some(nb) = cond.attr("NotBefore") {
            let ts = parse_iso8601_utc(nb)?;
            if params.now_unix + CLOCK_SKEW_SECS < ts {
                return Err("SAML Assertion not yet valid (Conditions NotBefore)".into());
            }
        }
        if let Some(nooa) = cond.attr("NotOnOrAfter") {
            let ts = parse_iso8601_utc(nooa)?;
            if params.now_unix > ts + CLOCK_SKEW_SECS {
                return Err("SAML Assertion expired (Conditions NotOnOrAfter)".into());
            }
        }
        let audiences: Vec<String> = cond
            .child_elems()
            .into_iter()
            .filter(|c| c.local_name() == "AudienceRestriction")
            .flat_map(|ar| ar.child_elems())
            .filter(|a| a.local_name() == "Audience")
            .map(|a| a.text_content().trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        if !audiences.is_empty() && !params.expected_audience.trim().is_empty() {
            let exp_aud = params.expected_audience.trim();
            if !audiences.iter().any(|a| a == exp_aud) {
                return Err(format!(
                    "SAML Assertion Audience mismatch (expected '{exp_aud}')"
                ));
            }
        }
    }

    // Extract Attributes strictly from verified assertion's AttributeStatement.
    let mut attrs: HashMap<String, Vec<String>> = HashMap::new();
    for stmt in assertion
        .child_elems()
        .into_iter()
        .filter(|c| c.local_name() == "AttributeStatement")
    {
        for attr in stmt
            .child_elems()
            .into_iter()
            .filter(|c| c.local_name() == "Attribute")
        {
            let Some(attr_name) = attr.attr("Name").filter(|s| !s.is_empty()) else {
                continue;
            };
            for val in attr
                .child_elems()
                .into_iter()
                .filter(|c| c.local_name() == "AttributeValue")
            {
                let txt = val.text_content().trim().to_owned();
                if !txt.is_empty() {
                    attrs.entry(attr_name.to_owned()).or_default().push(txt);
                }
            }
        }
    }

    let first_of = |candidates: &[&str]| -> Option<String> {
        candidates
            .iter()
            .find_map(|k| attrs.get(*k).and_then(|v| v.first()).cloned())
    };
    let email = first_of(&[
        "email",
        "mail",
        "emailaddress",
        "Email",
        "EmailAddress",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "urn:oid:0.9.2342.19200300.100.1.3",
    ])
    .unwrap_or_else(|| name_id.clone());
    if email.is_empty() {
        return Err("SAML Assertion missing NameID/email".into());
    }
    let name = first_of(&[
        "displayName",
        "name",
        "cn",
        "http://schemas.microsoft.com/identity/claims/displayname",
    ])
    .unwrap_or_else(|| email.clone());
    let username =
        first_of(&["username", "uid", "sAMAccountName"]).unwrap_or_else(|| email.clone());

    let mut groups = Vec::new();
    if !params.cfg.groups_attribute.is_empty() {
        if let Some(list) = attrs.get(&params.cfg.groups_attribute) {
            groups.extend(list.iter().cloned());
        }
    }
    for k in [
        "groups",
        "group",
        "memberOf",
        "Groups",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
        "http://schemas.xmlsoap.org/claims/Group",
    ] {
        if let Some(list) = attrs.get(k) {
            groups.extend(list.iter().cloned());
        }
    }

    Ok((
        in_response_to,
        assertion_id,
        SsoIdentityClaims {
            email,
            name,
            username,
            subject: name_id,
            groups,
            nonce: None,
        },
    ))
}

/// Parse RFC 3339 / ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SS[.fff]Z` or `±HH:MM`) into Unix seconds.
pub fn parse_iso8601_utc(raw: &str) -> Result<i64, String> {
    let s = raw.trim();
    if s.len() < 20 {
        return Err(format!("invalid ISO-8601 timestamp '{s}'"));
    }
    let (dt_part, tz_offset) = if let Some(prefix) = s.strip_suffix('Z') {
        (prefix, 0i64)
    } else if let Some(idx) = s.rfind(['+', '-']).filter(|&i| i >= 19) {
        let sign = if s.as_bytes()[idx] == b'+' {
            1i64
        } else {
            -1i64
        };
        let off_str = &s[idx + 1..];
        let (hh_s, mm_s) = off_str
            .split_once(':')
            .ok_or_else(|| format!("invalid ISO-8601 offset in '{s}'"))?;
        let hh: i64 = hh_s
            .parse()
            .map_err(|_| format!("invalid offset in '{s}'"))?;
        let mm: i64 = mm_s
            .parse()
            .map_err(|_| format!("invalid offset in '{s}'"))?;
        (&s[..idx], sign * (hh * 3600 + mm * 60))
    } else {
        return Err(format!("ISO-8601 timestamp missing timezone '{s}'"));
    };

    let (date_s, time_full) = dt_part
        .split_once('T')
        .ok_or_else(|| format!("invalid ISO-8601 timestamp '{s}'"))?;
    let time_s = time_full.split('.').next().unwrap_or(time_full);
    let dp: Vec<&str> = date_s.split('-').collect();
    let tp: Vec<&str> = time_s.split(':').collect();
    if dp.len() != 3 || tp.len() != 3 {
        return Err(format!("invalid ISO-8601 date/time '{s}'"));
    }
    let y: i64 = dp[0].parse().map_err(|_| "invalid year".to_owned())?;
    let m: i64 = dp[1].parse().map_err(|_| "invalid month".to_owned())?;
    let d: i64 = dp[2].parse().map_err(|_| "invalid day".to_owned())?;
    let hh: i64 = tp[0].parse().map_err(|_| "invalid hour".to_owned())?;
    let mm: i64 = tp[1].parse().map_err(|_| "invalid minute".to_owned())?;
    let ss: i64 = tp[2].parse().map_err(|_| "invalid second".to_owned())?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return Err(format!("out-of-range ISO-8601 timestamp '{s}'"));
    }

    // Howard Hinnant days_from_civil:
    let y_adj = y - i64::from(m <= 2);
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    Ok(days * 86_400 + hh * 3600 + mm * 60 + ss - tz_offset)
}

#[must_use]
pub fn format_iso8601_utc(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs = unix_secs.rem_euclid(86_400);
    let hh = secs / 3600;
    let mm = (secs % 3600) / 60;
    let ss = secs % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y_base = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y_base + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn xml_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn url_encode(raw: &str) -> String {
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
