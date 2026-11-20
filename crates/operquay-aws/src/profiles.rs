#![forbid(unsafe_code)]

//! Local `~/.aws/config`, `~/.aws/credentials`, `~/.aws/sso/cache/*.json`, and environment
//! AWS profile loader for `profiles` access mode (Go parity).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::sigv4::AwsCredentials;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalAwsProfile {
    pub name: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub sso_start_url: Option<String>,
    pub sso_region: Option<String>,
    pub sso_account_id: Option<String>,
    pub sso_role_name: Option<String>,
    pub role_arn: Option<String>,
    pub source_profile: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SsoCacheFile {
    #[serde(default)]
    start_url: String,
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    expires_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SsoPortalCredsResponse {
    role_credentials: SsoRoleCredentials,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SsoRoleCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
}

fn aws_dir() -> Option<PathBuf> {
    if let Ok(cfg) = std::env::var("AWS_CONFIG_FILE") {
        if let Some(parent) = Path::new(&cfg).parent() {
            return Some(parent.to_path_buf());
        }
    }
    let home = std::env::var("HOME").ok().filter(|h| !h.is_empty())?;
    let p = Path::new(&home).join(".aws");
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

fn parse_ini(content: &str) -> HashMap<String, HashMap<String, String>> {
    let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current: Option<String> = None;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = line[1..line.len() - 1].trim().to_string();
            sections.entry(name.clone()).or_default();
            current = Some(name);
            continue;
        }
        if let (Some(sec), Some((k, v))) = (&current, line.split_once('=')) {
            sections
                .entry(sec.clone())
                .or_default()
                .insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    sections
}

/// Discovers local AWS profiles from `~/.aws/config`, `~/.aws/credentials`, and env vars.
#[must_use]
pub fn load_local_profiles() -> Vec<LocalAwsProfile> {
    let mut map: HashMap<String, LocalAwsProfile> = HashMap::new();

    if let Some(dir) = aws_dir() {
        let cfg_path =
            std::env::var("AWS_CONFIG_FILE").map_or_else(|_| dir.join("config"), PathBuf::from);
        if let Ok(raw) = std::fs::read_to_string(&cfg_path) {
            for (sec, kv) in parse_ini(&raw) {
                let name = sec
                    .strip_prefix("profile ")
                    .unwrap_or(&sec)
                    .trim()
                    .to_string();
                let entry = map.entry(name.clone()).or_insert_with(|| LocalAwsProfile {
                    name: name.clone(),
                    region: "us-east-1".into(),
                    ..Default::default()
                });
                if let Some(r) = kv.get("region") {
                    entry.region.clone_from(r);
                }
                entry.sso_start_url = kv
                    .get("sso_start_url")
                    .cloned()
                    .or(entry.sso_start_url.clone());
                entry.sso_region = kv.get("sso_region").cloned().or(entry.sso_region.clone());
                entry.sso_account_id = kv
                    .get("sso_account_id")
                    .cloned()
                    .or(entry.sso_account_id.clone());
                entry.sso_role_name = kv
                    .get("sso_role_name")
                    .cloned()
                    .or(entry.sso_role_name.clone());
                entry.role_arn = kv.get("role_arn").cloned().or(entry.role_arn.clone());
                entry.source_profile = kv
                    .get("source_profile")
                    .cloned()
                    .or(entry.source_profile.clone());
            }
        }

        let creds_path = std::env::var("AWS_SHARED_CREDENTIALS_FILE")
            .map_or_else(|_| dir.join("credentials"), PathBuf::from);
        if let Ok(raw) = std::fs::read_to_string(&creds_path) {
            for (sec, kv) in parse_ini(&raw) {
                let name = sec.trim().to_string();
                let entry = map.entry(name.clone()).or_insert_with(|| LocalAwsProfile {
                    name: name.clone(),
                    region: "us-east-1".into(),
                    ..Default::default()
                });
                if let Some(k) = kv.get("aws_access_key_id") {
                    entry.access_key_id.clone_from(k);
                }
                if let Some(s) = kv.get("aws_secret_access_key") {
                    entry.secret_access_key.clone_from(s);
                }
                if let Some(t) = kv.get("aws_session_token") {
                    entry.session_token = Some(t.clone());
                }
                if let Some(r) = kv.get("region") {
                    entry.region.clone_from(r);
                }
            }
        }
    }

    if let (Ok(ak), Ok(sk)) = (
        std::env::var("AWS_ACCESS_KEY_ID"),
        std::env::var("AWS_SECRET_ACCESS_KEY"),
    ) {
        if !ak.is_empty() && !sk.is_empty() {
            let region = std::env::var("AWS_REGION")
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .unwrap_or_else(|_| "us-east-1".into());
            let token = std::env::var("AWS_SESSION_TOKEN")
                .ok()
                .filter(|t| !t.is_empty());
            map.insert(
                "env".into(),
                LocalAwsProfile {
                    name: "env".into(),
                    region,
                    access_key_id: ak,
                    secret_access_key: sk,
                    session_token: token,
                    ..Default::default()
                },
            );
        }
    }

    let mut out: Vec<LocalAwsProfile> = map.into_values().collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Resolves usable `AwsCredentials` for a local profile (static keys or cached `~/.aws/sso/cache`).
pub async fn resolve_profile_credentials(
    profile: &LocalAwsProfile,
    http: &reqwest::Client,
) -> Option<AwsCredentials> {
    if !profile.access_key_id.is_empty() && !profile.secret_access_key.is_empty() {
        return Some(AwsCredentials {
            access_key_id: profile.access_key_id.clone(),
            secret_access_key: profile.secret_access_key.clone(),
            session_token: profile.session_token.clone(),
        });
    }

    let (start_url, sso_region, account_id, role_name) = (
        profile.sso_start_url.as_deref()?,
        profile.sso_region.as_deref()?,
        profile.sso_account_id.as_deref()?,
        profile.sso_role_name.as_deref()?,
    );

    let cache_dir = aws_dir()?.join("sso").join("cache");
    let entries = std::fs::read_dir(&cache_dir).ok()?;
    let mut best_token: Option<String> = None;
    for entry in entries.flatten() {
        if entry.path().extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(parsed) = serde_json::from_str::<SsoCacheFile>(&raw) else {
            continue;
        };
        if parsed.start_url == start_url && !parsed.access_token.is_empty() {
            best_token = Some(parsed.access_token);
            let _ = parsed.expires_at;
            break;
        }
    }
    let token = best_token?;
    let url = format!(
        "https://portal.sso.{sso_region}.amazonaws.com/federation/credentials?account_id={account_id}&role_name={role_name}"
    );
    let resp = http
        .get(&url)
        .header("x-amz-sso_bearer_token", token)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let creds = resp.json::<SsoPortalCredsResponse>().await.ok()?;
    Some(AwsCredentials {
        access_key_id: creds.role_credentials.access_key_id,
        secret_access_key: creds.role_credentials.secret_access_key,
        session_token: Some(creds.role_credentials.session_token),
    })
}

/// Convenience resolver used by desktop/SSM launch paths when no explicit DB-stored
/// account exists: inspects `~/.aws/config`, `~/.aws/credentials`, and cached AWS SSO tokens
/// in priority order (`preferred_profile` -> `AWS_PROFILE` -> `"default"` -> any valid profile),
/// returning `(credentials, resolved_region)`.
pub async fn resolve_local_profile_or_default(
    preferred_profile: Option<&str>,
) -> Option<(AwsCredentials, Option<String>)> {
    let profiles = load_local_profiles();
    if profiles.is_empty() {
        return None;
    }

    let env_profile = std::env::var("AWS_PROFILE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("AWS_DEFAULT_PROFILE")
                .ok()
                .filter(|s| !s.trim().is_empty())
        });

    let mut ordered: Vec<&LocalAwsProfile> = Vec::with_capacity(profiles.len());
    for wanted in [
        preferred_profile.map(str::trim).filter(|s| !s.is_empty()),
        env_profile.as_deref(),
        Some("default"),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(p) = profiles.iter().find(|p| p.name == wanted) {
            if !ordered.iter().any(|o| o.name == p.name) {
                ordered.push(p);
            }
        }
    }
    for p in &profiles {
        if !ordered.iter().any(|o| o.name == p.name) {
            ordered.push(p);
        }
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;
    for profile in ordered {
        if let Some(creds) = resolve_profile_credentials(profile, &http).await {
            let region = (!profile.region.trim().is_empty()).then(|| profile.region.clone());
            return Some((creds, region));
        }
    }
    None
}
