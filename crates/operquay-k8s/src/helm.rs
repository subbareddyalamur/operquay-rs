#![forbid(unsafe_code)]

//! Helm secret release decoder (`sh.helm.release.v1.*` double/single-base64 + gzip JSON).

use std::io::Read as _;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmChartMeta {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub app_version: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmReleaseInfo {
    pub name: String,
    pub namespace: String,
    pub revision: u64,
    pub status: String,
    #[serde(default)]
    pub updated: String,
    #[serde(default)]
    pub chart: Option<HelmChartMeta>,
}

#[derive(Deserialize)]
struct RawHelmPayload {
    #[serde(default)]
    info: Option<RawHelmInfo>,
    #[serde(default)]
    chart: Option<RawHelmChartWrap>,
}

#[derive(Deserialize)]
struct RawHelmInfo {
    #[serde(default)]
    status: String,
    #[serde(default)]
    last_deployed: String,
}

#[derive(Deserialize)]
struct RawHelmChartWrap {
    #[serde(default)]
    metadata: Option<HelmChartMeta>,
}

/// Decode Helm v3 release secret payload (base64 + gzip + JSON), enforcing a strict decompression cap.
#[must_use]
pub fn decode_helm_release_secret(encoded: &[u8], max_bytes: usize) -> Option<HelmReleaseInfo> {
    let raw_str = std::str::from_utf8(encoded).ok()?.trim();
    // Kubernetes Secret JSON holds base64(gzip(json)), and legacy Helm might hold base64(base64(gzip))
    let first = STANDARD.decode(raw_str).ok()?;
    let gz_bytes = if first.starts_with(&[0x1f, 0x8b]) {
        first
    } else if let Ok(inner_str) = std::str::from_utf8(&first) {
        STANDARD.decode(inner_str.trim()).ok()?
    } else {
        return None;
    };
    let mut decoder = GzDecoder::new(gz_bytes.as_slice());
    let mut out = Vec::new();
    let mut limited = (&mut decoder).take((max_bytes as u64).saturating_add(1));
    limited.read_to_end(&mut out).ok()?;
    if out.len() > max_bytes {
        return None;
    }
    let parsed: RawHelmPayload = serde_json::from_slice(&out).ok()?;
    let meta = parsed.chart.and_then(|c| c.metadata);
    Some(HelmReleaseInfo {
        name: meta.as_ref().map_or_default(|m| m.name.clone()),
        namespace: String::new(),
        revision: 1,
        status: parsed
            .info
            .as_ref()
            .map_or_else(|| "deployed".into(), |i| i.status.clone()),
        updated: parsed
            .info
            .as_ref()
            .map_or_default(|i| i.last_deployed.clone()),
        chart: meta,
    })
}
