#![forbid(unsafe_code)]

//! `SSM SendCommand` chunked file transfers + directory browser + `S3 Express` high-speed transfers.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::sigv4::{sign_request, AwsCredentials};

pub const MAX_TRANSFER_BYTES: usize = 32 * 1024 * 1024;
pub const UPLOAD_CHUNK_B64_LEN: usize = 2048;
/// Divisible by 3 so intermediate base64 chunks have zero padding.
pub const DOWNLOAD_CHUNK_RAW_BYTES: usize = 16_998;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferProgress {
    pub progress: u8,
    pub message: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub done: bool,
    pub total: usize,
    pub speed: u64,
    pub eta: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteDirEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: String,
    pub permissions: String,
}

/// Split payload into safe 2048-char Base64 chunks (`printf '%s' ... >> file`) matching Go `uploadChunkSize`.
#[must_use]
pub fn split_upload_base64_chunks(data: &[u8]) -> Vec<String> {
    if data.is_empty() {
        return vec![String::new()];
    }
    let encoded = STANDARD.encode(data);
    encoded
        .as_bytes()
        .chunks(UPLOAD_CHUNK_B64_LEN)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect()
}

/// Parse `ls -la --time-style=long-iso` output cleanly into sorted [`RemoteDirEntry`] items.
#[must_use]
pub fn parse_ls_output(parent_dir: &str, raw_output: &str) -> Vec<RemoteDirEntry> {
    let base = parent_dir.trim_end_matches('/');
    let mut entries = Vec::new();
    for line in raw_output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("total ") {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 8 {
            continue;
        }
        let perms = parts[0];
        let is_dir = perms.starts_with('d');
        let size = parts[4].parse::<u64>().unwrap_or(0);
        let modified = format!("{} {}", parts[5], parts[6]);
        let name = parts[7..].join(" ");
        if name == "." || name == ".." {
            continue;
        }
        let path = if base.is_empty() {
            format!("/{name}")
        } else {
            format!("{base}/{name}")
        };
        entries.push(RemoteDirEntry {
            name,
            path,
            is_dir,
            size,
            modified,
            permissions: perms.to_owned(),
        });
    }
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
    entries
}

pub struct SsmTransferClient {
    http: reqwest::Client,
    ssm_endpoint_override: Option<String>,
    s3_endpoint_override: Option<String>,
}

impl Default for SsmTransferClient {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl SsmTransferClient {
    #[must_use]
    pub fn new(
        ssm_endpoint_override: Option<String>,
        s3_endpoint_override: Option<String>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            http,
            ssm_endpoint_override,
            s3_endpoint_override,
        }
    }

    /// Execute an `ssm:SendCommand` invocation and fetch its output (mock-friendly & live AWS-ready).
    pub async fn run_ssm_command(
        &self,
        region: &str,
        instance_id: &str,
        platform: &str,
        commands: &[String],
        creds: &AwsCredentials,
    ) -> Result<String, String> {
        let doc = if platform.eq_ignore_ascii_case("windows") {
            "AWS-RunPowerShellScript"
        } else {
            "AWS-RunShellScript"
        };
        let url = self
            .ssm_endpoint_override
            .clone()
            .unwrap_or_else(|| format!("https://ssm.{region}.amazonaws.com/"));

        let send_body = serde_json::json!({
            "DocumentName": doc,
            "InstanceIds": [instance_id],
            "Parameters": { "commands": commands },
        })
        .to_string();
        let send_resp = self
            .signed_ssm_post(&url, "AmazonSSM.SendCommand", &send_body, region, creds)
            .await?;
        let cmd_id = send_resp["Command"]["CommandId"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if cmd_id.is_empty() {
            return Err("SSM SendCommand returned empty CommandId".into());
        }

        let inv_body = serde_json::json!({
            "CommandId": cmd_id,
            "InstanceId": instance_id,
        })
        .to_string();
        for attempt in 0..45 {
            let inv = match self
                .signed_ssm_post(
                    &url,
                    "AmazonSSM.GetCommandInvocation",
                    &inv_body,
                    region,
                    creds,
                )
                .await
            {
                Ok(v) => v,
                Err(e) if attempt < 10 && e.contains("InvocationDoesNotExist") => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let status = inv["Status"].as_str().unwrap_or("");
            match status {
                "Success" => {
                    return Ok(inv["StandardOutputContent"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned());
                }
                "Failed" | "Cancelled" | "TimedOut" => {
                    let err_txt = inv["StandardErrorContent"]
                        .as_str()
                        .filter(|s| !s.trim().is_empty())
                        .or_else(|| inv["StatusDetails"].as_str())
                        .unwrap_or("command failed");
                    return Err(format!("SSM command {status}: {err_txt}"));
                }
                _ => tokio::time::sleep(Duration::from_millis(400)).await,
            }
        }
        Err("SSM command invocation timed out".into())
    }

    pub async fn browse_directory(
        &self,
        region: &str,
        instance_id: &str,
        platform: &str,
        dir_path: &str,
        creds: &AwsCredentials,
    ) -> Result<Vec<RemoteDirEntry>, String> {
        let safe_dir = shell_single_quote(if dir_path.trim().is_empty() {
            "/"
        } else {
            dir_path.trim()
        });
        let cmd = if platform.eq_ignore_ascii_case("windows") {
            format!("Get-ChildItem -LiteralPath {safe_dir} | Select-Object Name,FullName,PSIsContainer,Length | Format-Table -HideTableHeaders")
        } else {
            format!("ls -la --time-style=long-iso {safe_dir}")
        };
        let stdout = self
            .run_ssm_command(region, instance_id, platform, &[cmd], creds)
            .await?;
        Ok(parse_ls_output(dir_path, &stdout))
    }

    pub async fn upload_file(
        &self,
        region: &str,
        instance_id: &str,
        platform: &str,
        remote_path: &str,
        data: &[u8],
        creds: &AwsCredentials,
    ) -> Result<Vec<TransferProgress>, String> {
        if data.len() > MAX_TRANSFER_BYTES {
            return Err("upload exceeds 32 MiB limit".into());
        }
        let chunks = split_upload_base64_chunks(data);
        let safe_target = shell_single_quote(remote_path);
        let total = chunks.len().max(1);
        let mut updates = Vec::with_capacity(total + 1);
        for (idx, chunk) in chunks.iter().enumerate() {
            let cmd = if platform.eq_ignore_ascii_case("windows") {
                format!(
                    "[IO.File]::WriteAllBytes({safe_target}, [Convert]::FromBase64String('{chunk}'))"
                )
            } else if idx == 0 {
                format!("printf '%s' '{chunk}' | base64 -d > {safe_target}")
            } else {
                format!("printf '%s' '{chunk}' | base64 -d >> {safe_target}")
            };
            self.run_ssm_command(region, instance_id, platform, &[cmd], creds)
                .await?;
            let pct = u8::try_from(((idx + 1) * 100) / total).unwrap_or(100);
            updates.push(TransferProgress {
                progress: pct,
                message: format!("Uploaded chunk {}/{}", idx + 1, total),
                status: if idx + 1 == total {
                    "complete".to_owned()
                } else {
                    "progress".to_owned()
                },
                error: None,
                done: idx + 1 == total,
                total: data.len(),
                speed: u64::try_from(data.len()).unwrap_or(0),
                eta: 0,
            });
        }
        Ok(updates)
    }

    pub async fn express_s3_put(
        &self,
        region: &str,
        bucket: &str,
        key: &str,
        data: &[u8],
        creds: &AwsCredentials,
    ) -> Result<String, String> {
        let base = self
            .s3_endpoint_override
            .clone()
            .unwrap_or_else(|| format!("https://{bucket}.s3.{region}.amazonaws.com"));
        let clean_key = key.trim_start_matches('/');
        let url = format!("{base}/{clean_key}");
        let mut headers = http::HeaderMap::new();
        sign_request("PUT", &url, &mut headers, data, creds, region, "s3", None)?;
        let resp = self
            .http
            .put(&url)
            .headers(headers)
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| format!("S3 upload error: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("S3 PUT returned {}", resp.status()));
        }
        Ok(format!("s3://{bucket}/{clean_key}"))
    }

    pub async fn express_s3_get(
        &self,
        region: &str,
        bucket: &str,
        key: &str,
        creds: &AwsCredentials,
    ) -> Result<Vec<u8>, String> {
        let base = self
            .s3_endpoint_override
            .clone()
            .unwrap_or_else(|| format!("https://{bucket}.s3.{region}.amazonaws.com"));
        let clean_key = key.trim_start_matches('/');
        let url = format!("{base}/{clean_key}");
        let mut headers = http::HeaderMap::new();
        sign_request("GET", &url, &mut headers, b"", creds, region, "s3", None)?;
        let resp = self
            .http
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| format!("S3 GET error: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("S3 GET returned {}", resp.status()));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| format!("S3 GET body error: {e}"))
    }

    async fn signed_ssm_post(
        &self,
        url: &str,
        target: &'static str,
        body: &str,
        region: &str,
        creds: &AwsCredentials,
    ) -> Result<serde_json::Value, String> {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-amz-json-1.1"),
        );
        headers.insert(
            http::HeaderName::from_static("x-amz-target"),
            http::HeaderValue::from_static(target),
        );
        sign_request(
            "POST",
            url,
            &mut headers,
            body.as_bytes(),
            creds,
            region,
            "ssm",
            None,
        )?;
        let resp = self
            .http
            .post(url)
            .headers(headers)
            .body(body.to_owned())
            .send()
            .await
            .map_err(|e| format!("SSM HTTP error: {e}"))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("SSM body read error: {e}"))?;
        if !status.is_success() {
            return Err(format!("SSM returned {status}: {text}"));
        }
        serde_json::from_str(&text).map_err(|e| format!("SSM JSON parse: {e}"))
    }
}

#[must_use]
pub fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}
