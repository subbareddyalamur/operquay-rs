#![forbid(unsafe_code)]

//! Ed25519-signed Offline & Online License Entitlement Engine (`OPQL1.<payload_b64>.<sig_b64>`),
//! capability gating (`sso_oidc_saml`, `scim_v2`, `multi_tenant`, `session_recording`, `tunnel`,
//! `ai_agent`, `k8s_multi_cluster`, `db_viewer`), and native `operquay licensectl` support.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

pub const TOKEN_PREFIX: &str = "OPQL1.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanTier {
    Unconfigured,
    Lab,
    Pro,
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementClaims {
    pub license_id: String,
    pub customer: String,
    pub plan: PlanTier,
    pub max_seats: u32,
    pub issued_at: i64,
    pub expires_at: i64,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseStatus {
    pub tenant_id: String,
    pub valid: bool,
    pub plan: PlanTier,
    pub customer: String,
    pub max_seats: u32,
    pub expires_at: i64,
    pub capabilities: Vec<String>,
    pub raw_token_preview: String,
}

/// Generate a fresh Ed25519 keypair as `(private_key_b64, public_key_b64)`.
#[must_use]
pub fn generate_keypair_b64() -> (String, String) {
    let mut seed = [0u8; 32];
    let u1 = Uuid::new_v4();
    let u2 = Uuid::new_v4();
    seed[..16].copy_from_slice(u1.as_bytes());
    seed[16..].copy_from_slice(u2.as_bytes());
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();
    (
        URL_SAFE_NO_PAD.encode(sk.to_bytes()),
        URL_SAFE_NO_PAD.encode(pk.to_bytes()),
    )
}

/// Sign `EntitlementClaims` into an `OPQL1.<payload>.<sig>` offline-verifiable license token.
pub fn issue_license_token(
    claims: &EntitlementClaims,
    private_key_b64: &str,
) -> Result<String, String> {
    let key_bytes = URL_SAFE_NO_PAD
        .decode(private_key_b64.trim())
        .map_err(|e| format!("invalid private key base64: {e}"))?;
    let seed: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "Ed25519 private key must be 32 bytes".to_owned())?;
    let signing_key = SigningKey::from_bytes(&seed);
    let payload = serde_json::to_vec(claims).map_err(|e| e.to_string())?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
    let sig: Signature = signing_key.sign(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    Ok(format!("{TOKEN_PREFIX}{payload_b64}.{sig_b64}"))
}

/// Verify an `OPQL1.` token against a base64url Ed25519 public key and check expiration.
pub fn verify_license_token(
    token: &str,
    public_key_b64: &str,
) -> Result<EntitlementClaims, String> {
    let rest = token
        .trim()
        .strip_prefix(TOKEN_PREFIX)
        .ok_or_else(|| "license token must start with OPQL1.".to_owned())?;
    let (payload_b64, sig_b64) = rest
        .split_once('.')
        .ok_or_else(|| "malformed license token".to_owned())?;

    let pk_bytes = URL_SAFE_NO_PAD
        .decode(public_key_b64.trim())
        .map_err(|e| format!("invalid public key base64: {e}"))?;
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| "Ed25519 public key must be 32 bytes".to_owned())?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| e.to_string())?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64.trim())
        .map_err(|e| format!("invalid signature base64: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "Ed25519 signature must be 64 bytes".to_owned())?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(payload_b64.as_bytes(), &sig)
        .map_err(|_| "license signature verification failed".to_owned())?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("invalid payload base64: {e}"))?;
    let claims: EntitlementClaims =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("claims JSON error: {e}"))?;
    if claims.expires_at > 0 && now_unix() > claims.expires_at {
        return Err("license has expired".to_owned());
    }
    Ok(claims)
}

#[must_use]
pub fn all_enterprise_capabilities() -> Vec<String> {
    [
        "multi_tenant",
        "sso_oidc_saml",
        "scim_v2",
        "rbac_custom",
        "session_recording",
        "tunnel",
        "ai_agent",
        "k8s_multi_cluster",
        "db_viewer",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

pub struct LicenseManager {
    public_key_b64: String,
    active: RwLock<HashMap<String, LicenseStatus>>,
}

impl Default for LicenseManager {
    fn default() -> Self {
        let (_, pk) = generate_keypair_b64();
        Self::new(pk)
    }
}

impl LicenseManager {
    #[must_use]
    pub fn new(public_key_b64: String) -> Self {
        Self {
            public_key_b64,
            active: RwLock::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn public_key_b64(&self) -> &str {
        &self.public_key_b64
    }

    pub async fn status(&self, tenant_id: &str) -> LicenseStatus {
        self.active
            .read()
            .await
            .get(tenant_id)
            .cloned()
            .unwrap_or_else(|| LicenseStatus {
                tenant_id: tenant_id.to_owned(),
                valid: true,
                plan: PlanTier::Unconfigured,
                customer: "Community Lab".to_owned(),
                max_seats: 10,
                expires_at: 0,
                capabilities: all_enterprise_capabilities(),
                raw_token_preview: String::new(),
            })
    }

    pub async fn redeem(
        &self,
        tenant_id: &str,
        token: &str,
        override_public_key: Option<&str>,
    ) -> Result<LicenseStatus, String> {
        let pk = override_public_key.unwrap_or(&self.public_key_b64);
        let claims = verify_license_token(token, pk)?;
        let preview = token.chars().take(16).collect::<String>() + "...";
        let st = LicenseStatus {
            tenant_id: tenant_id.to_owned(),
            valid: true,
            plan: claims.plan,
            customer: claims.customer,
            max_seats: claims.max_seats,
            expires_at: claims.expires_at,
            capabilities: claims.capabilities,
            raw_token_preview: preview,
        };
        self.active
            .write()
            .await
            .insert(tenant_id.to_owned(), st.clone());
        Ok(st)
    }

    pub async fn has_capability(&self, tenant_id: &str, cap: &str) -> bool {
        let st = self.status(tenant_id).await;
        st.valid && st.capabilities.iter().any(|c| c == cap || c == "*")
    }
}

fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn signs_verifies_and_redeems_ed25519_license_tokens_and_rejects_tampering() {
        let (sk, pk) = generate_keypair_b64();
        let mgr = LicenseManager::new(pk);
        let claims = EntitlementClaims {
            license_id: "lic-100".into(),
            customer: "SteadVerge Corp".into(),
            plan: PlanTier::Enterprise,
            max_seats: 500,
            issued_at: now_unix(),
            expires_at: now_unix() + 86_400,
            capabilities: all_enterprise_capabilities(),
        };
        let token = issue_license_token(&claims, &sk).unwrap();
        assert!(token.starts_with(TOKEN_PREFIX));

        let st = mgr.redeem("acme", &token, None).await.unwrap();
        assert_eq!(st.plan, PlanTier::Enterprise);
        assert_eq!(st.customer, "SteadVerge Corp");
        assert!(mgr.has_capability("acme", "scim_v2").await);

        let mut tampered = token.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        assert!(mgr.redeem("acme", &tampered, None).await.is_err());
    }
}
