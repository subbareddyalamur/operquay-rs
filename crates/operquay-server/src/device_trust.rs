#![forbid(unsafe_code)]

//! Hardware Device Trust & MDM Posture Attestation Gate (`M12.5`).
//! Supports `CrowdStrike`, Jamf, Microsoft Intune, and osquery device posture checks before
//! issuing desktop session launch tickets (`TicketStore`).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::jit::now_unix_secs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTrustPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub enforce_on_desktop_launch: bool,
    #[serde(default = "default_true")]
    pub require_disk_encryption: bool,
    #[serde(default = "default_true")]
    pub require_edr_running: bool,
    #[serde(default = "default_max_patch_age")]
    pub max_os_patch_age_days: u32,
    #[serde(default = "default_providers")]
    pub allowed_providers: Vec<String>,
    #[serde(default = "default_ttl")]
    pub attestation_ttl_secs: u64,
}

const fn default_true() -> bool {
    true
}

const fn default_max_patch_age() -> u32 {
    30
}

const fn default_ttl() -> u64 {
    86_400
}

fn default_providers() -> Vec<String> {
    vec![
        "crowdstrike".into(),
        "jamf".into(),
        "intune".into(),
        "osquery".into(),
    ]
}

impl Default for DeviceTrustPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            enforce_on_desktop_launch: true,
            require_disk_encryption: true,
            require_edr_running: true,
            max_os_patch_age_days: 30,
            allowed_providers: default_providers(),
            attestation_ttl_secs: 86_400,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DevicePostureInput {
    pub device_id: String,
    #[serde(default = "default_osquery")]
    pub provider: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub os_version: String,
    pub disk_encrypted: bool,
    pub edr_running: bool,
    #[serde(default)]
    pub edr_agent: String,
    #[serde(default)]
    pub os_patch_age_days: u32,
}

fn default_osquery() -> String {
    "osquery".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePostureAttestation {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub device_id: String,
    pub provider: String,
    pub hostname: String,
    pub os_version: String,
    pub disk_encrypted: bool,
    pub edr_running: bool,
    pub edr_agent: String,
    pub os_patch_age_days: u32,
    pub compliant: bool,
    pub reasons: Vec<String>,
    pub attested_at: i64,
    pub expires_at: i64,
}

#[must_use]
pub fn evaluate_posture(policy: &DeviceTrustPolicy, input: &DevicePostureInput) -> Vec<String> {
    let mut reasons = Vec::new();
    let provider = input.provider.trim().to_ascii_lowercase();
    if !policy.allowed_providers.is_empty()
        && !policy
            .allowed_providers
            .iter()
            .any(|p| p.trim().eq_ignore_ascii_case(&provider))
    {
        reasons.push(format!("MDM/EDR provider '{provider}' is not trusted"));
    }
    if policy.require_disk_encryption && !input.disk_encrypted {
        reasons.push("Full-disk encryption (FileVault/BitLocker) is disabled".to_owned());
    }
    if policy.require_edr_running && !input.edr_running {
        reasons.push("Endpoint Detection & Response (EDR) sensor is not running".to_owned());
    }
    if input.os_patch_age_days > policy.max_os_patch_age_days {
        reasons.push(format!(
            "OS security patches are {}d old (max {}d)",
            input.os_patch_age_days, policy.max_os_patch_age_days
        ));
    }
    reasons
}

#[derive(Default)]
pub struct DeviceTrustStore {
    policies: RwLock<HashMap<String, DeviceTrustPolicy>>,
    attestations: RwLock<Vec<DevicePostureAttestation>>,
}

impl DeviceTrustStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get_policy(&self, tenant_id: &str) -> DeviceTrustPolicy {
        self.policies
            .read()
            .await
            .get(tenant_id)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn set_policy(&self, tenant_id: &str, policy: DeviceTrustPolicy) {
        self.policies
            .write()
            .await
            .insert(tenant_id.to_owned(), policy);
    }

    pub async fn record_attestation(
        &self,
        tenant_id: &str,
        user_id: &str,
        input: DevicePostureInput,
    ) -> Result<DevicePostureAttestation, String> {
        if input.device_id.trim().is_empty() {
            return Err("device_id is required".to_owned());
        }
        let policy = self.get_policy(tenant_id).await;
        let reasons = evaluate_posture(&policy, &input);
        let compliant = reasons.is_empty();
        let now = now_unix_secs();
        let ttl =
            i64::try_from(policy.attestation_ttl_secs.clamp(300, 7 * 86_400)).unwrap_or(86_400);
        let att = DevicePostureAttestation {
            id: format!("dev-{}", Uuid::new_v4()),
            tenant_id: tenant_id.to_owned(),
            user_id: user_id.to_owned(),
            device_id: input.device_id.trim().to_owned(),
            provider: input.provider.trim().to_ascii_lowercase(),
            hostname: input.hostname.trim().to_owned(),
            os_version: input.os_version.trim().to_owned(),
            disk_encrypted: input.disk_encrypted,
            edr_running: input.edr_running,
            edr_agent: input.edr_agent.trim().to_owned(),
            os_patch_age_days: input.os_patch_age_days,
            compliant,
            reasons,
            attested_at: now,
            expires_at: now.saturating_add(ttl),
        };
        let mut guard = self.attestations.write().await;
        guard.retain(|existing| {
            !(existing.tenant_id == tenant_id
                && existing.user_id == user_id
                && existing.device_id == att.device_id)
        });
        guard.push(att.clone());
        Ok(att)
    }

    pub async fn check_desktop_launch(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<(), Vec<String>> {
        let policy = self.get_policy(tenant_id).await;
        if !policy.enabled || !policy.enforce_on_desktop_launch {
            return Ok(());
        }
        let now = now_unix_secs();
        let guard = self.attestations.read().await;
        let latest = guard
            .iter()
            .filter(|a| a.tenant_id == tenant_id && a.user_id == user_id && a.expires_at > now)
            .max_by_key(|a| a.attested_at);
        let Some(att) = latest else {
            return Err(vec![
                "No valid recent MDM/EDR device posture attestation found for user".to_owned(),
            ]);
        };
        if att.compliant {
            Ok(())
        } else {
            Err(att.reasons.clone())
        }
    }

    pub async fn list_attestations(&self, tenant_id: &str) -> Vec<DevicePostureAttestation> {
        let mut out: Vec<_> = self
            .attestations
            .read()
            .await
            .iter()
            .filter(|a| a.tenant_id == tenant_id)
            .cloned()
            .collect();
        out.sort_by_key(|a| std::cmp::Reverse(a.attested_at));
        out
    }

    pub async fn hydrate_policies(&self, items: Vec<(String, DeviceTrustPolicy)>) {
        let mut guard = self.policies.write().await;
        for (tid, pol) in items {
            guard.insert(tid, pol);
        }
    }

    pub async fn hydrate_attestations(&self, items: Vec<DevicePostureAttestation>) {
        let mut guard = self.attestations.write().await;
        *guard = items;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enforces_device_trust_policy_on_desktop_ticket_launch() {
        let store = DeviceTrustStore::new();
        store
            .set_policy(
                "default",
                DeviceTrustPolicy {
                    enabled: true,
                    ..DeviceTrustPolicy::default()
                },
            )
            .await;
        assert!(store.check_desktop_launch("default", "u-1").await.is_err());

        let bad = store
            .record_attestation(
                "default",
                "u-1",
                DevicePostureInput {
                    device_id: "mac-1".into(),
                    provider: "jamf".into(),
                    hostname: "mbp".into(),
                    os_version: "15.2".into(),
                    disk_encrypted: false,
                    edr_running: true,
                    edr_agent: "CrowdStrike Falcon".into(),
                    os_patch_age_days: 5,
                },
            )
            .await
            .unwrap();
        assert!(!bad.compliant);
        assert!(store.check_desktop_launch("default", "u-1").await.is_err());

        let good = store
            .record_attestation(
                "default",
                "u-1",
                DevicePostureInput {
                    device_id: "mac-1".into(),
                    provider: "jamf".into(),
                    hostname: "mbp".into(),
                    os_version: "15.2".into(),
                    disk_encrypted: true,
                    edr_running: true,
                    edr_agent: "CrowdStrike Falcon".into(),
                    os_patch_age_days: 5,
                },
            )
            .await
            .unwrap();
        assert!(good.compliant);
        assert!(store.check_desktop_launch("default", "u-1").await.is_ok());
    }
}
