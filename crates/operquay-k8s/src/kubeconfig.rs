#![forbid(unsafe_code)]

//! Safe Kubeconfig (`JSON` & `YAML`) parser with exec-plugin binary allowlist enforcement.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

pub const ALLOWED_EXEC_PLUGINS: &[&str] = &[
    "aws",
    "aws-iam-authenticator",
    "gke-gcloud-auth-plugin",
    "kubelogin",
    "tsh",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedKubeCluster {
    pub context_name: String,
    pub cluster_name: String,
    pub server: String,
    #[serde(default)]
    pub insecure_skip_tls_verify: bool,
    #[serde(default)]
    pub ca_data_b64: String,
    #[serde(default)]
    pub bearer_token: String,
    #[serde(default)]
    pub client_cert_pem: String,
    #[serde(default)]
    pub client_key_pem: String,
    #[serde(default)]
    pub exec_command: String,
    #[serde(default)]
    pub exec_args: Vec<String>,
}

fn decode_b64_pem(raw_b64: &str) -> String {
    let trimmed = raw_b64.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    STANDARD
        .decode(trimmed)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default()
}

/// Parse a Kubernetes `kubeconfig` (either JSON or standard multi-section YAML), rejecting unknown exec binaries.
pub fn parse_kubeconfig_safe(raw: &str) -> Result<Vec<ParsedKubeCluster>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty kubeconfig".to_owned());
    }
    if trimmed.starts_with('{') {
        return parse_kubeconfig_json(trimmed);
    }
    parse_kubeconfig_yaml_simple(trimmed)
}

fn parse_kubeconfig_json(raw: &str) -> Result<Vec<ParsedKubeCluster>, String> {
    let val: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("invalid kubeconfig JSON: {e}"))?;
    let exec_cmd = val["users"][0]["user"]["exec"]["command"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    validate_exec_plugin(&exec_cmd)?;
    let exec_args: Vec<String> = val["users"][0]["user"]["exec"]["args"]
        .as_array()
        .map_or_default(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        });
    let token = val["users"][0]["user"]["token"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let client_cert_pem = decode_b64_pem(
        val["users"][0]["user"]["client-certificate-data"]
            .as_str()
            .unwrap_or(""),
    );
    let client_key_pem = decode_b64_pem(
        val["users"][0]["user"]["client-key-data"]
            .as_str()
            .unwrap_or(""),
    );
    let mut clusters = Vec::new();
    if let Some(arr) = val["clusters"].as_array() {
        for c in arr {
            let cname = c["name"].as_str().unwrap_or("default").to_owned();
            let server = c["cluster"]["server"].as_str().unwrap_or("").to_owned();
            let skip = c["cluster"]["insecure-skip-tls-verify"]
                .as_bool()
                .unwrap_or(false);
            let ca = c["cluster"]["certificate-authority-data"]
                .as_str()
                .unwrap_or("")
                .to_owned();
            if !server.is_empty() {
                clusters.push(ParsedKubeCluster {
                    context_name: cname.clone(),
                    cluster_name: cname,
                    server,
                    insecure_skip_tls_verify: skip,
                    ca_data_b64: ca,
                    bearer_token: token.clone(),
                    client_cert_pem: client_cert_pem.clone(),
                    client_key_pem: client_key_pem.clone(),
                    exec_command: exec_cmd.clone(),
                    exec_args: exec_args.clone(),
                });
            }
        }
    }
    if clusters.is_empty() {
        return Err("no valid clusters found in kubeconfig".to_owned());
    }
    Ok(clusters)
}

fn parse_kubeconfig_yaml_simple(raw: &str) -> Result<Vec<ParsedKubeCluster>, String> {
    let mut section = "";
    let mut parsed_clusters: Vec<(String, String, String, bool)> = Vec::new();
    let mut token = String::new();
    let mut client_cert_pem = String::new();
    let mut client_key_pem = String::new();
    let mut exec_cmd = String::new();
    let mut cur_name = String::new();
    let mut cur_server = String::new();
    let mut cur_ca = String::new();
    let mut cur_skip = false;

    let flush_cluster = |out: &mut Vec<(String, String, String, bool)>,
                         cname: &mut String,
                         srv: &mut String,
                         ca: &mut String,
                         skip: &mut bool| {
        if !srv.is_empty() {
            let final_name = if cname.is_empty() {
                format!("cluster-{}", out.len() + 1)
            } else {
                std::mem::take(cname)
            };
            out.push((final_name, std::mem::take(srv), std::mem::take(ca), *skip));
        }
        cname.clear();
        ca.clear();
        *skip = false;
    };

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "clusters:" {
            section = "clusters";
            continue;
        } else if trimmed == "users:" {
            flush_cluster(
                &mut parsed_clusters,
                &mut cur_name,
                &mut cur_server,
                &mut cur_ca,
                &mut cur_skip,
            );
            section = "users";
            continue;
        } else if trimmed == "contexts:" {
            flush_cluster(
                &mut parsed_clusters,
                &mut cur_name,
                &mut cur_server,
                &mut cur_ca,
                &mut cur_skip,
            );
            section = "contexts";
            continue;
        }
        if section == "clusters" {
            if trimmed.starts_with("- ") && !cur_server.is_empty() {
                flush_cluster(
                    &mut parsed_clusters,
                    &mut cur_name,
                    &mut cur_server,
                    &mut cur_ca,
                    &mut cur_skip,
                );
            }
            if let Some(rest) = trimmed
                .strip_prefix("name:")
                .or_else(|| trimmed.strip_prefix("- name:"))
            {
                cur_name = strip_quotes(rest);
            } else if let Some(rest) = trimmed.strip_prefix("server:") {
                cur_server = strip_quotes(rest);
            } else if let Some(rest) = trimmed.strip_prefix("certificate-authority-data:") {
                cur_ca = strip_quotes(rest);
            } else if let Some(rest) = trimmed.strip_prefix("insecure-skip-tls-verify:") {
                cur_skip = strip_quotes(rest).eq_ignore_ascii_case("true");
            }
        } else if section == "users" {
            if let Some(rest) = trimmed.strip_prefix("token:") {
                token = strip_quotes(rest);
            } else if let Some(rest) = trimmed.strip_prefix("client-certificate-data:") {
                client_cert_pem = decode_b64_pem(&strip_quotes(rest));
            } else if let Some(rest) = trimmed.strip_prefix("client-key-data:") {
                client_key_pem = decode_b64_pem(&strip_quotes(rest));
            } else if let Some(rest) = trimmed.strip_prefix("command:") {
                exec_cmd = strip_quotes(rest);
            }
        }
    }
    flush_cluster(
        &mut parsed_clusters,
        &mut cur_name,
        &mut cur_server,
        &mut cur_ca,
        &mut cur_skip,
    );
    validate_exec_plugin(&exec_cmd)?;
    let out: Vec<ParsedKubeCluster> = parsed_clusters
        .into_iter()
        .map(|(cname, server, ca, skip)| ParsedKubeCluster {
            context_name: cname.clone(),
            cluster_name: cname,
            server,
            insecure_skip_tls_verify: skip,
            ca_data_b64: ca,
            bearer_token: token.clone(),
            client_cert_pem: client_cert_pem.clone(),
            client_key_pem: client_key_pem.clone(),
            exec_command: exec_cmd.clone(),
            exec_args: Vec::new(),
        })
        .collect();
    if out.is_empty() {
        return Err("no valid clusters found in YAML kubeconfig".to_owned());
    }
    Ok(out)
}

fn validate_exec_plugin(cmd: &str) -> Result<(), String> {
    if cmd.trim().is_empty() {
        return Ok(());
    }
    let bin = cmd.rsplit('/').next().unwrap_or(cmd).trim();
    if ALLOWED_EXEC_PLUGINS.contains(&bin) {
        Ok(())
    } else {
        Err(format!("disallowed kubeconfig exec binary '{bin}'"))
    }
}

fn strip_quotes(raw: &str) -> String {
    raw.trim().trim_matches('"').trim_matches('\'').to_owned()
}
