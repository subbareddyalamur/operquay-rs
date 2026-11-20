#![forbid(unsafe_code)]

//! Continuous SOC 2 / ISO 27001 Compliance Posture, Quarterly Access Review Campaigns,
//! and Ed25519 Signed Evidence Bundle Exporter (`M11.4`).

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use operquay_auth::crypto::fill_csprng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessReviewStatus {
    #[default]
    Active,
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessReviewDecision {
    #[default]
    Pending,
    Certified,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessReviewItem {
    pub item_id: String,
    pub principal_id: String,
    pub principal_email: String,
    pub role: String,
    pub target_summary: String,
    pub mfa_enabled: bool,
    pub last_active_at: i64,
    pub decision: AccessReviewDecision,
    #[serde(default)]
    pub reviewer_email: Option<String>,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub decided_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessReviewCampaign {
    pub id: String,
    pub tenant_id: String,
    pub title: String,
    pub quarter: String,
    pub status: AccessReviewStatus,
    pub created_by: String,
    pub created_at: i64,
    #[serde(default)]
    pub completed_at: Option<i64>,
    pub items: Vec<AccessReviewItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceControlStatus {
    pub control_id: String,
    pub framework: String,
    pub title: String,
    pub status: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompliancePostureReport {
    pub tenant_id: String,
    pub generated_at: i64,
    pub compliance_mode: bool,
    pub audit_chain_valid: bool,
    pub audit_source: String,
    pub audit_checked_events: usize,
    pub total_recordings: usize,
    pub encrypted_recordings: usize,
    pub legal_hold_recordings: usize,
    pub jit_pending_requests: usize,
    pub jit_active_grants: usize,
    pub dlp_firewall_enabled: bool,
    pub webhooks_configured: usize,
    pub controls: Vec<ComplianceControlStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundleIntegrity {
    pub algorithm: String,
    pub public_key_b64: String,
    pub payload_sha256: String,
    pub signature_b64: String,
    pub signed_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEvidenceBundle {
    pub bundle: serde_json::Value,
    pub integrity: EvidenceBundleIntegrity,
}

#[must_use]
pub fn generate_ephemeral_evidence_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    if fill_csprng(&mut seed).is_err() {
        let mut h = Sha256::new();
        h.update(b"operquay-ephemeral-evidence-fallback-v1");
        seed.copy_from_slice(&h.finalize());
    }
    seed
}

#[must_use]
pub fn derive_evidence_key_from_master(master_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"operquay/evidence-ed25519/v1");
    hasher.update(master_secret);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hasher.finalize());
    seed
}

pub fn sign_evidence_bundle(
    signing_seed: &[u8; 32],
    bundle: serde_json::Value,
    signed_at: i64,
) -> Result<SignedEvidenceBundle, String> {
    let canonical = serde_json::to_vec(&bundle).map_err(|e| format!("serialize bundle: {e}"))?;
    let mut digest = Sha256::new();
    digest.update(&canonical);
    let payload_sha256 = hex::encode(digest.finalize());

    let signing_key = SigningKey::from_bytes(signing_seed);
    let sig: Signature = signing_key.sign(payload_sha256.as_bytes());
    let vk = signing_key.verifying_key();

    Ok(SignedEvidenceBundle {
        bundle,
        integrity: EvidenceBundleIntegrity {
            algorithm: "Ed25519-SHA256".to_owned(),
            public_key_b64: STANDARD.encode(vk.to_bytes()),
            payload_sha256,
            signature_b64: STANDARD.encode(sig.to_bytes()),
            signed_at,
        },
    })
}

pub fn verify_signed_evidence_bundle(signed: &SignedEvidenceBundle) -> Result<(), String> {
    let canonical =
        serde_json::to_vec(&signed.bundle).map_err(|e| format!("serialize bundle: {e}"))?;
    let mut digest = Sha256::new();
    digest.update(&canonical);
    let expected_sha256 = hex::encode(digest.finalize());
    if expected_sha256 != signed.integrity.payload_sha256 {
        return Err("bundle payload SHA-256 mismatch (content tampered)".to_owned());
    }

    let vk_bytes = STANDARD
        .decode(signed.integrity.public_key_b64.trim())
        .map_err(|e| format!("invalid public_key_b64: {e}"))?;
    let vk_arr: [u8; 32] = vk_bytes
        .try_into()
        .map_err(|_| "Ed25519 public key must be 32 bytes".to_owned())?;
    let vk = VerifyingKey::from_bytes(&vk_arr)
        .map_err(|e| format!("invalid Ed25519 public key: {e}"))?;

    let sig_bytes = STANDARD
        .decode(signed.integrity.signature_b64.trim())
        .map_err(|e| format!("invalid signature_b64: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "Ed25519 signature must be 64 bytes".to_owned())?;
    let sig = Signature::from_bytes(&sig_arr);

    vk.verify(expected_sha256.as_bytes(), &sig)
        .map_err(|e| format!("Ed25519 signature verification failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_and_verifies_evidence_bundle_and_rejects_tamper() {
        let seed = derive_evidence_key_from_master(b"cluster-secret-material-for-tests");
        let payload = serde_json::json!({
            "tenant_id": "acme",
            "audit_chain_valid": true,
            "controls": ["CC6.1", "CC6.3", "CC7.2"]
        });
        let mut signed = sign_evidence_bundle(&seed, payload, 1_700_000_000).unwrap();
        verify_signed_evidence_bundle(&signed).expect("valid bundle signature");

        signed.bundle["audit_chain_valid"] = serde_json::json!(false);
        let err = verify_signed_evidence_bundle(&signed).unwrap_err();
        assert!(err.contains("tampered"));
    }
}
