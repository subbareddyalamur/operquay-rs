#![forbid(unsafe_code)]

//! Multi-cluster Kubernetes API client, EKS/Kubeconfig/Teleport cluster pool,
//! Pod metrics & cost estimation, CRD inspector, Helm releases, K8s recording policies,
//! and native Teleport Web SSO / Proxy connector (`crates/operquay-k8s`).

pub mod helm;
pub mod kubeconfig;
pub mod teleport;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use helm::{decode_helm_release_secret, HelmReleaseInfo};
use kubeconfig::{parse_kubeconfig_safe, ParsedKubeCluster};
use operquay_aws::sigv4::{presign_eks_token, sign_request, uri_encode, AwsCredentials};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    ServerName, UnixTime,
};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{
    connect_async_tls_with_config, Connector, MaybeTlsStream, WebSocketStream,
};
use uuid::Uuid;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct K8sClusterRecord {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub source: String,
    pub api_server: String,
    #[serde(skip_serializing)]
    pub bearer_token: String,
    #[serde(skip_serializing, default)]
    pub client_cert_pem: String,
    #[serde(skip_serializing, default)]
    pub client_key_pem: String,
    #[serde(default)]
    pub ca_data_b64: String,
    #[serde(default)]
    pub insecure_skip_tls_verify: bool,
    #[serde(default)]
    pub connected: bool,
    #[serde(default)]
    pub recording_enabled: bool,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default)]
    pub exec_command: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfiguredKubeCluster {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default, alias = "name")]
    pub label: String,
    #[serde(default)]
    pub proxy: String,
    #[serde(default)]
    pub cluster_name: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub connector: String,
    #[serde(default)]
    pub recording_mode: String,
    #[serde(default)]
    pub api_server: String,
    #[serde(default)]
    pub region: String,
}

fn default_region() -> String {
    "us-east-1".to_owned()
}

fn default_rec_mode() -> String {
    "all".to_owned()
}

const fn default_rec_true() -> bool {
    true
}

const fn default_retention_90() -> u32 {
    90
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sRecordingPolicy {
    #[serde(default = "default_rec_mode")]
    pub mode: String,
    #[serde(default)]
    pub namespaces: Vec<String>,
    #[serde(default = "default_rec_true")]
    pub record_exec: bool,
    #[serde(default = "default_rec_true")]
    pub record_attach: bool,
    #[serde(default)]
    pub record_logs: bool,
    #[serde(default)]
    pub fail_closed: bool,
    #[serde(default = "default_retention_90")]
    pub retention_days: u32,
}

impl Default for K8sRecordingPolicy {
    fn default() -> Self {
        Self {
            mode: "all".to_owned(),
            namespaces: Vec::new(),
            record_exec: true,
            record_attach: true,
            record_logs: false,
            fail_closed: false,
            retention_days: 90,
        }
    }
}

impl K8sRecordingPolicy {
    /// Determine whether interactive `exec` or `attach` in `namespace` must be recorded.
    #[must_use]
    pub fn should_record_namespace(&self, namespace: &str, is_attach: bool) -> bool {
        let mode_enabled = match self.mode.trim().to_ascii_lowercase().as_str() {
            "off" | "none" => false,
            "selected" => self.namespaces.iter().any(|n| n == namespace),
            _ => true,
        };
        if !mode_enabled {
            return false;
        }
        if is_attach {
            self.record_attach
        } else {
            self.record_exec
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeleportSession {
    pub proxy_url: String,
    pub status: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub clusters: Vec<String>,
    #[serde(default)]
    pub callback_id: String,
    #[serde(default)]
    pub expires_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct TeleportCallbackSession {
    pub callback_id: String,
    pub tenant_id: String,
    pub proxy_url: String,
    pub kube_api_base: String,
    pub username: String,
    pub clusters: Vec<String>,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub ca_data_b64: String,
    pub expires_at: u64,
    pub updated_at: u64,
}

pub struct K8sManager {
    clusters: RwLock<HashMap<String, K8sClusterRecord>>,
    configured: RwLock<HashMap<String, ConfiguredKubeCluster>>,
    policies: RwLock<HashMap<String, K8sRecordingPolicy>>,
    cluster_policies: RwLock<HashMap<(String, String), K8sRecordingPolicy>>,
    teleport: RwLock<HashMap<String, TeleportSession>>,
    teleport_callbacks: RwLock<HashMap<String, TeleportCallbackSession>>,
    http: reqwest::Client,
}

impl Default for K8sManager {
    fn default() -> Self {
        Self::new()
    }
}

impl K8sManager {
    #[must_use]
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        let mut initial_clusters = HashMap::new();
        let kubeconfig_path = std::env::var("KUBECONFIG")
            .ok()
            .filter(|p| !p.is_empty())
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .filter(|h| !h.is_empty())
                    .map(|h| format!("{h}/.kube/config"))
            });
        if let Some(path) = kubeconfig_path {
            if let Ok(raw) = std::fs::read_to_string(&path) {
                if let Ok(parsed) = parse_kubeconfig_safe(&raw) {
                    for p in parsed {
                        let id = Uuid::new_v4().to_string();
                        initial_clusters.insert(
                            id.clone(),
                            K8sClusterRecord {
                                id,
                                tenant_id: "default".to_owned(),
                                name: p.cluster_name,
                                source: "kubeconfig".to_owned(),
                                api_server: p.server,
                                bearer_token: p.bearer_token,
                                client_cert_pem: p.client_cert_pem,
                                client_key_pem: p.client_key_pem,
                                ca_data_b64: p.ca_data_b64,
                                insecure_skip_tls_verify: p.insecure_skip_tls_verify,
                                connected: false,
                                recording_enabled: true,
                                region: "custom".to_owned(),
                                exec_command: p.exec_command,
                            },
                        );
                    }
                }
            }
        }
        Self {
            clusters: RwLock::new(initial_clusters),
            configured: RwLock::new(HashMap::new()),
            policies: RwLock::new(HashMap::new()),
            cluster_policies: RwLock::new(HashMap::new()),
            teleport: RwLock::new(HashMap::new()),
            teleport_callbacks: RwLock::new(HashMap::new()),
            http,
        }
    }

    pub async fn list_configured(&self, tenant_id: &str) -> Vec<ConfiguredKubeCluster> {
        let mut out: Vec<_> = self
            .configured
            .read()
            .await
            .values()
            .filter(|c| c.tenant_id == tenant_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.label.cmp(&b.label));
        out
    }

    pub async fn upsert_configured(&self, mut rec: ConfiguredKubeCluster) -> ConfiguredKubeCluster {
        if rec.id.is_empty() {
            rec.id = format!("cfgk8s-{}", Uuid::new_v4());
        }
        if rec.label.is_empty() {
            rec.label.clone_from(&rec.cluster_name);
        }
        if rec.cluster_name.is_empty() {
            rec.cluster_name.clone_from(&rec.label);
        }
        self.configured
            .write()
            .await
            .insert(rec.id.clone(), rec.clone());
        rec
    }

    pub async fn delete_configured(&self, tenant_id: &str, id: &str) -> bool {
        let mut guard = self.configured.write().await;
        if guard.get(id).is_some_and(|c| c.tenant_id == tenant_id) {
            guard.remove(id).is_some()
        } else {
            false
        }
    }

    pub async fn list_clusters(&self, tenant_id: &str) -> Vec<K8sClusterRecord> {
        let mut out: Vec<_> = self
            .clusters
            .read()
            .await
            .values()
            .filter(|c| c.tenant_id == tenant_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub async fn upsert_cluster(&self, mut rec: K8sClusterRecord) -> K8sClusterRecord {
        if rec.id.is_empty() {
            rec.id = format!("k8s-{}", Uuid::new_v4());
        }
        self.clusters
            .write()
            .await
            .insert(rec.id.clone(), rec.clone());
        rec
    }

    pub async fn delete_cluster(&self, tenant_id: &str, id: &str) -> bool {
        let mut guard = self.clusters.write().await;
        if guard.get(id).is_some_and(|c| c.tenant_id == tenant_id) {
            guard.remove(id).is_some()
        } else {
            false
        }
    }

    pub async fn set_connected(
        &self,
        tenant_id: &str,
        id_or_name: &str,
        connected: bool,
    ) -> Option<K8sClusterRecord> {
        let mut guard = self.clusters.write().await;
        let rec = guard
            .values_mut()
            .find(|c| c.tenant_id == tenant_id && (c.id == id_or_name || c.name == id_or_name))?;
        rec.connected = connected;
        Some(rec.clone())
    }

    pub async fn upload_kubeconfig(
        &self,
        tenant_id: &str,
        raw: &str,
        connect: bool,
    ) -> Result<Vec<K8sClusterRecord>, String> {
        let parsed: Vec<ParsedKubeCluster> = parse_kubeconfig_safe(raw)?;
        let mut out = Vec::with_capacity(parsed.len());
        for p in parsed {
            let rec = self
                .upsert_cluster(K8sClusterRecord {
                    id: String::new(),
                    tenant_id: tenant_id.to_owned(),
                    name: p.cluster_name,
                    source: "kubeconfig".to_owned(),
                    api_server: p.server,
                    bearer_token: p.bearer_token,
                    client_cert_pem: p.client_cert_pem,
                    client_key_pem: p.client_key_pem,
                    ca_data_b64: p.ca_data_b64,
                    insecure_skip_tls_verify: p.insecure_skip_tls_verify,
                    connected: connect,
                    recording_enabled: true,
                    region: "custom".to_owned(),
                    exec_command: p.exec_command,
                })
                .await;
            out.push(rec);
        }
        Ok(out)
    }

    pub async fn refresh_cluster_token(
        &self,
        tenant_id: &str,
        id_or_name: &str,
        token: String,
    ) -> Option<K8sClusterRecord> {
        let mut guard = self.clusters.write().await;
        let rec = guard
            .values_mut()
            .find(|c| c.tenant_id == tenant_id && (c.id == id_or_name || c.name == id_or_name))?;
        rec.bearer_token = token;
        rec.connected = true;
        Some(rec.clone())
    }

    pub async fn discover_eks_clusters(
        &self,
        tenant_id: &str,
        region: &str,
        creds: &AwsCredentials,
    ) -> Result<Vec<K8sClusterRecord>, String> {
        let reg = if region.trim().is_empty() {
            "us-east-1"
        } else {
            region.trim()
        };
        let list_url = format!("https://eks.{reg}.amazonaws.com/clusters");
        let mut h = http::HeaderMap::new();
        sign_request("GET", &list_url, &mut h, b"", creds, reg, "eks", None)?;
        let resp = self
            .http
            .get(&list_url)
            .headers(h)
            .send()
            .await
            .map_err(|e| format!("EKS ListClusters error: {e}"))?;
        let status = resp.status();
        let list_val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("EKS ListClusters parse error: {e}"))?;
        if !status.is_success() {
            return Err(format!("EKS ListClusters returned {status}: {list_val}"));
        }
        let names: Vec<String> = list_val["clusters"].as_array().map_or_default(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        });

        let mut out = Vec::with_capacity(names.len());
        for cname in names {
            let desc_url = format!("https://eks.{reg}.amazonaws.com/clusters/{cname}");
            let mut dh = http::HeaderMap::new();
            sign_request("GET", &desc_url, &mut dh, b"", creds, reg, "eks", None)?;
            let dresp = self
                .http
                .get(&desc_url)
                .headers(dh)
                .send()
                .await
                .map_err(|e| format!("EKS DescribeCluster error: {e}"))?;
            if !dresp.status().is_success() {
                continue;
            }
            let dval: serde_json::Value = dresp
                .json()
                .await
                .map_err(|e| format!("EKS DescribeCluster parse error: {e}"))?;
            let endpoint = dval["cluster"]["endpoint"]
                .as_str()
                .unwrap_or("")
                .to_owned();
            if endpoint.is_empty() {
                continue;
            }
            let ca = dval["cluster"]["certificateAuthority"]["data"]
                .as_str()
                .unwrap_or("")
                .to_owned();
            let token = presign_eks_token(&cname, reg, creds, None).unwrap_or_default();
            let id = format!("eks:{reg}:{cname}");
            let already_connected = self
                .get_cluster(tenant_id, &id)
                .await
                .is_some_and(|c| c.connected);
            let rec = self
                .upsert_cluster(K8sClusterRecord {
                    id,
                    tenant_id: tenant_id.to_owned(),
                    name: cname,
                    source: "eks".to_owned(),
                    api_server: endpoint,
                    bearer_token: token,
                    client_cert_pem: String::new(),
                    client_key_pem: String::new(),
                    ca_data_b64: ca,
                    insecure_skip_tls_verify: false,
                    connected: already_connected,
                    recording_enabled: true,
                    region: reg.to_owned(),
                    exec_command: String::new(),
                })
                .await;
            out.push(rec);
        }
        Ok(out)
    }

    pub async fn get_policy(&self, tenant_id: &str) -> K8sRecordingPolicy {
        self.policies
            .read()
            .await
            .get(tenant_id)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn set_policy(
        &self,
        tenant_id: &str,
        mut pol: K8sRecordingPolicy,
    ) -> K8sRecordingPolicy {
        normalize_k8s_policy(&mut pol);
        self.policies
            .write()
            .await
            .insert(tenant_id.to_owned(), pol.clone());
        pol
    }

    pub async fn get_cluster_recording_policy(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> (K8sRecordingPolicy, bool) {
        if let Some(pol) = self
            .cluster_policies
            .read()
            .await
            .get(&(tenant_id.to_owned(), id.to_owned()))
            .cloned()
        {
            return (pol, false);
        }
        (self.get_policy(tenant_id).await, true)
    }

    pub async fn set_cluster_recording_policy(
        &self,
        tenant_id: &str,
        id: &str,
        mut pol: K8sRecordingPolicy,
    ) -> K8sRecordingPolicy {
        normalize_k8s_policy(&mut pol);
        self.cluster_policies
            .write()
            .await
            .insert((tenant_id.to_owned(), id.to_owned()), pol.clone());
        let enabled = pol.mode != "off";
        let _ = self.set_cluster_recording(tenant_id, id, enabled).await;
        if let Some(cfg) = self.configured.write().await.get_mut(id) {
            if cfg.tenant_id == tenant_id {
                cfg.recording_mode.clone_from(&pol.mode);
            }
        }
        pol
    }

    pub async fn set_cluster_recording(
        &self,
        tenant_id: &str,
        id: &str,
        enabled: bool,
    ) -> Option<K8sClusterRecord> {
        let mut guard = self.clusters.write().await;
        let c = guard.get_mut(id).filter(|c| c.tenant_id == tenant_id)?;
        c.recording_enabled = enabled;
        Some(c.clone())
    }

    pub async fn get_cluster(&self, tenant_id: &str, cluster: &str) -> Option<K8sClusterRecord> {
        self.clusters
            .read()
            .await
            .values()
            .find(|c| c.tenant_id == tenant_id && (c.id == cluster || c.name == cluster))
            .cloned()
    }

    fn client_for_cluster(&self, rec: &K8sClusterRecord) -> Result<reqwest::Client, String> {
        self.client_for_cluster_with_timeout(rec, Some(Duration::from_secs(15)))
    }

    fn client_for_cluster_with_timeout(
        &self,
        rec: &K8sClusterRecord,
        total_timeout: Option<Duration>,
    ) -> Result<reqwest::Client, String> {
        if total_timeout.is_some()
            && rec.ca_data_b64.trim().is_empty()
            && rec.client_cert_pem.trim().is_empty()
            && !rec.insecure_skip_tls_verify
        {
            return Ok(self.http.clone());
        }
        let mut builder = reqwest::Client::builder().connect_timeout(Duration::from_secs(15));
        if let Some(timeout) = total_timeout {
            builder = builder.timeout(timeout);
        }
        if rec.insecure_skip_tls_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if !rec.ca_data_b64.trim().is_empty() {
            if let Ok(pem) = STANDARD.decode(rec.ca_data_b64.trim()) {
                match reqwest::Certificate::from_pem_bundle(&pem) {
                    Ok(certs) if !certs.is_empty() => {
                        for cert in certs {
                            builder = builder.add_root_certificate(cert);
                        }
                    }
                    _ => {
                        if let Ok(cert) = reqwest::Certificate::from_pem(&pem) {
                            builder = builder.add_root_certificate(cert);
                        }
                    }
                }
            }
        }
        if !rec.client_cert_pem.trim().is_empty() && !rec.client_key_pem.trim().is_empty() {
            let combined = format!(
                "{}\n{}",
                rec.client_cert_pem.trim(),
                rec.client_key_pem.trim()
            );
            let identity = reqwest::Identity::from_pem(combined.as_bytes())
                .map_err(|e| format!("invalid K8s client mTLS identity: {e}"))?;
            builder = builder.identity(identity);
        }
        builder
            .build()
            .map_err(|e| format!("failed building K8s TLS HTTP client: {e}"))
    }

    pub async fn kube_get_stream_logs(
        &self,
        tenant_id: &str,
        cluster: &str,
        namespace: &str,
        pod: &str,
        container: Option<&str>,
        follow: bool,
        tail_lines: u32,
        timestamps: bool,
    ) -> Result<reqwest::Response, String> {
        let rec = self
            .get_cluster(tenant_id, cluster)
            .await
            .ok_or_else(|| "Kubernetes cluster not found".to_owned())?;
        // Streaming `follow=true` logs stay open indefinitely; only enforce connect timeout.
        let timeout = (!follow).then_some(Duration::from_secs(30));
        let client = self.client_for_cluster_with_timeout(&rec, timeout)?;
        let base = rec.api_server.trim_end_matches('/');
        let ns = if namespace.is_empty() {
            "default"
        } else {
            namespace
        };
        let tail = tail_lines.clamp(1, 50_000);
        let mut url = format!(
            "{base}/api/v1/namespaces/{ns}/pods/{pod}/log?follow={follow}&tailLines={tail}&timestamps={timestamps}"
        );
        if let Some(c) = container.filter(|s| !s.is_empty()) {
            use std::fmt::Write as _;
            let _ = write!(url, "&container={}", uri_encode(c, true));
        }
        let mut req = client.get(&url);
        if !rec.bearer_token.is_empty() {
            req = req.bearer_auth(&rec.bearer_token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("K8s log stream failed: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            let msg = if err_body.trim().is_empty() {
                format!("K8s log stream returned {status}")
            } else {
                format!("K8s log stream returned {status}: {}", err_body.trim())
            };
            return Err(msg);
        }
        Ok(resp)
    }

    pub async fn kube_get_text(
        &self,
        tenant_id: &str,
        cluster: &str,
        api_path: &str,
    ) -> Result<String, String> {
        let rec = self
            .get_cluster(tenant_id, cluster)
            .await
            .ok_or_else(|| "Kubernetes cluster not found".to_owned())?;
        let client = self.client_for_cluster(&rec)?;
        let base = rec.api_server.trim_end_matches('/');
        let path = api_path.trim_start_matches('/');
        let url = format!("{base}/{path}");
        let mut req = client.get(&url);
        if !rec.bearer_token.is_empty() {
            req = req.bearer_auth(&rec.bearer_token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("K8s API error: {e}"))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("K8s API text error: {e}"))?;
        if !status.is_success() {
            return Err(format!("K8s API returned {status}: {text}"));
        }
        Ok(text)
    }

    /// Connect directly to a Kubernetes API server WebSocket endpoint (`v4.channel.k8s.io` or
    /// Connect a Kubernetes WebSocket (`v5.channel.k8s.io`, `v4.channel.k8s.io`, or
    /// `base64.channel.k8s.io`) for live pod `exec` or `attach`, returning the stream and
    /// negotiated subprotocol.
    pub async fn connect_spdy_channel_ws_with_proto(
        &self,
        tenant_id: &str,
        cluster: &str,
        ws_api_path_with_query: &str,
    ) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, &'static str), String> {
        const SUBPROTOCOLS: [&str; 3] = [
            "v5.channel.k8s.io",
            "v4.channel.k8s.io",
            "base64.channel.k8s.io",
        ];
        let rec = self
            .get_cluster(tenant_id, cluster)
            .await
            .ok_or_else(|| "Kubernetes cluster not found".to_owned())?;
        let ws_base = rec
            .api_server
            .trim_end_matches('/')
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        let path = ws_api_path_with_query.trim_start_matches('/');
        let full = format!("{ws_base}/{path}");
        let connector = if full.starts_with("wss://") {
            Some(Connector::Rustls(Arc::new(build_ws_tls_config(&rec)?)))
        } else {
            None
        };
        let bearer = (!rec.bearer_token.is_empty()).then_some(rec.bearer_token.as_str());
        let mut errors = Vec::new();
        for proto in SUBPROTOCOLS {
            match dial_channel_ws(&full, bearer, proto, connector.clone()).await {
                Ok(ws) => return Ok((ws, proto)),
                Err(err) => errors.push(err),
            }
        }
        Err(errors.join("; "))
    }

    /// Connect a Kubernetes WebSocket (`v5` / `v4` / `base64.channel.k8s.io`) for live pod `exec`
    /// or `attach`, using the cluster's custom CA and mTLS client certificate when configured.
    pub async fn connect_spdy_channel_ws(
        &self,
        tenant_id: &str,
        cluster: &str,
        ws_api_path_with_query: &str,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, String> {
        self.connect_spdy_channel_ws_with_proto(tenant_id, cluster, ws_api_path_with_query)
            .await
            .map(|(ws, _)| ws)
    }

    pub async fn kube_get_json(
        &self,
        tenant_id: &str,
        cluster: &str,
        api_path: &str,
    ) -> Result<serde_json::Value, String> {
        let rec = self
            .clusters
            .read()
            .await
            .values()
            .find(|c| c.tenant_id == tenant_id && (c.id == cluster || c.name == cluster))
            .cloned()
            .ok_or_else(|| "Kubernetes cluster not found".to_owned())?;
        let client = self.client_for_cluster(&rec)?;
        let base = rec.api_server.trim_end_matches('/');
        let path = api_path.trim_start_matches('/');
        let url = format!("{base}/{path}");
        let mut req = client.get(&url);
        if !rec.bearer_token.is_empty() {
            req = req.bearer_auth(&rec.bearer_token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("K8s API error: {e}"))?;
        let status = resp.status();
        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("K8s API JSON error: {e}"))?;
        if !status.is_success() {
            return Err(format!("K8s API returned {status}: {val}"));
        }
        Ok(val)
    }

    pub async fn kube_post_json(
        &self,
        tenant_id: &str,
        cluster: &str,
        method: http::Method,
        api_path: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let rec = self
            .clusters
            .read()
            .await
            .values()
            .find(|c| c.tenant_id == tenant_id && (c.id == cluster || c.name == cluster))
            .cloned()
            .ok_or_else(|| "Kubernetes cluster not found".to_owned())?;
        let client = self.client_for_cluster(&rec)?;
        let base = rec.api_server.trim_end_matches('/');
        let path = api_path.trim_start_matches('/');
        let url = format!("{base}/{path}");
        let mut req = match method {
            http::Method::DELETE => {
                if body.as_object().is_some_and(serde_json::Map::is_empty) {
                    client.delete(&url)
                } else {
                    client.delete(&url).json(&body)
                }
            }
            http::Method::PUT => {
                let raw = serde_json::to_vec(&body)
                    .map_err(|e| format!("K8s request encode error: {e}"))?;
                client
                    .put(&url)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(raw)
            }
            http::Method::PATCH => {
                let raw = serde_json::to_vec(&body)
                    .map_err(|e| format!("K8s request encode error: {e}"))?;
                client
                    .patch(&url)
                    .header(
                        reqwest::header::CONTENT_TYPE,
                        "application/merge-patch+json",
                    )
                    .body(raw)
            }
            _ => client.post(&url).json(&body),
        };
        if !rec.bearer_token.is_empty() {
            req = req.bearer_auth(&rec.bearer_token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("K8s API error: {e}"))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("K8s API response read error: {e}"))?;
        let val = if text.trim().is_empty() {
            serde_json::json!({ "status": "ok" })
        } else {
            serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({ "raw": text }))
        };
        if !status.is_success() {
            return Err(format!("K8s API returned {status}: {val}"));
        }
        Ok(val)
    }

    pub async fn helm_releases(
        &self,
        tenant_id: &str,
        cluster: &str,
        namespace: &str,
    ) -> Result<Vec<HelmReleaseInfo>, String> {
        let path = if namespace.is_empty() {
            "api/v1/secrets?labelSelector=owner=helm".to_owned()
        } else {
            format!("api/v1/namespaces/{namespace}/secrets?labelSelector=owner=helm")
        };
        let list = self.kube_get_json(tenant_id, cluster, &path).await?;
        let mut latest: HashMap<String, HelmReleaseInfo> = HashMap::new();
        if let Some(items) = list["items"].as_array() {
            for item in items {
                let meta = &item["metadata"];
                let labels = &meta["labels"];
                if labels["owner"].as_str() != Some("helm") {
                    continue;
                }
                let ns = meta["namespace"].as_str().unwrap_or("default").to_owned();
                let name = labels["name"]
                    .as_str()
                    .or_else(|| meta["name"].as_str())
                    .unwrap_or("release")
                    .to_owned();
                let rev = labels["version"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(1);
                let rel_b64 = item["data"]["release"].as_str().unwrap_or("");
                let decoded = decode_helm_release_secret(rel_b64.as_bytes(), 1024 * 1024);
                let chart = decoded.as_ref().and_then(|d| d.chart.clone());
                let status = labels["status"]
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| decoded.as_ref().map(|d| d.status.clone()))
                    .unwrap_or_else(|| "deployed".to_owned());
                let key = format!("{ns}/{name}");
                let keep = latest.get(&key).is_none_or(|prev| rev >= prev.revision);
                if keep {
                    latest.insert(
                        key,
                        HelmReleaseInfo {
                            name,
                            namespace: ns,
                            revision: rev,
                            status,
                            updated: decoded.map_or_default(|d| d.updated),
                            chart,
                        },
                    );
                }
            }
        }
        let mut out: Vec<_> = latest.into_values().collect();
        out.sort_by(|a, b| {
            a.namespace
                .cmp(&b.namespace)
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(out)
    }

    pub async fn ping_teleport_proxy(
        &self,
        proxy_url: &str,
    ) -> Result<teleport::TeleportPingInfo, String> {
        teleport::ping_teleport(&self.http, proxy_url).await
    }

    pub async fn store_teleport_callback(
        &self,
        tenant_id: &str,
        proxy_url: &str,
        outcome: teleport::TeleportLoginOutcome,
    ) -> TeleportSession {
        let now = now_unix();
        let cb_id = format!("tp-{}", Uuid::new_v4());
        let cb_rec = TeleportCallbackSession {
            callback_id: cb_id.clone(),
            tenant_id: tenant_id.to_owned(),
            proxy_url: proxy_url.to_owned(),
            kube_api_base: outcome.kube_api_base,
            username: outcome.username.clone(),
            clusters: outcome.clusters.clone(),
            client_cert_pem: outcome.client_cert_pem,
            client_key_pem: outcome.client_key_pem,
            ca_data_b64: outcome.ca_data_b64,
            expires_at: outcome.expires_at,
            updated_at: now as u64,
        };
        self.teleport_callbacks
            .write()
            .await
            .insert(cb_id.clone(), cb_rec);
        let sess = TeleportSession {
            proxy_url: proxy_url.to_owned(),
            status: "connected".to_owned(),
            user: outcome.username,
            clusters: outcome.clusters,
            callback_id: cb_id,
            expires_at: outcome.expires_at as i64,
            updated_at: now,
        };
        self.teleport
            .write()
            .await
            .insert(tenant_id.to_owned(), sess.clone());
        sess
    }

    pub async fn teleport_callback(
        &self,
        tenant_id: &str,
        callback_id: &str,
    ) -> Option<TeleportCallbackSession> {
        self.teleport_callbacks
            .read()
            .await
            .get(callback_id.trim())
            .filter(|cb| cb.tenant_id == tenant_id)
            .cloned()
    }

    pub async fn teleport_status_for_callback(
        &self,
        tenant_id: &str,
        callback_id: &str,
    ) -> TeleportSession {
        let cb_id = callback_id.trim();
        let now = now_unix() as u64;
        if !cb_id.is_empty() {
            if let Some(cb) = self.teleport_callback(tenant_id, cb_id).await {
                let status = if cb.expires_at > 0 && now >= cb.expires_at {
                    "expired"
                } else {
                    "connected"
                };
                return TeleportSession {
                    proxy_url: cb.proxy_url,
                    status: status.to_owned(),
                    user: cb.username,
                    clusters: cb.clusters,
                    callback_id: cb.callback_id,
                    expires_at: cb.expires_at as i64,
                    updated_at: cb.updated_at as i64,
                };
            }
            return TeleportSession {
                proxy_url: String::new(),
                status: "disconnected".to_owned(),
                user: String::new(),
                clusters: Vec::new(),
                callback_id: cb_id.to_owned(),
                expires_at: 0,
                updated_at: 0,
            };
        }
        self.teleport_status(tenant_id).await
    }

    pub async fn cancel_teleport_callback(&self, tenant_id: &str, callback_id: &str) {
        let cb_id = callback_id.trim();
        if cb_id.is_empty() {
            self.teleport.write().await.remove(tenant_id);
        } else {
            let mut guard = self.teleport_callbacks.write().await;
            if guard.get(cb_id).is_some_and(|c| c.tenant_id == tenant_id) {
                guard.remove(cb_id);
            }
        }
    }

    pub async fn refresh_teleport_clusters_mtls(
        &self,
        tenant_id: &str,
        callback_id: &str,
    ) -> Result<Vec<String>, String> {
        let cb = self
            .teleport_callback(tenant_id, callback_id)
            .await
            .ok_or_else(|| "Teleport session not found".to_owned())?;
        if cb.expires_at > 0 && (now_unix() as u64) >= cb.expires_at {
            return Err("Teleport mTLS certificate has expired; sign in again".to_owned());
        }
        let clusters = teleport::discover_teleport_kubes_mtls(
            &cb.proxy_url,
            &cb.client_cert_pem,
            &cb.client_key_pem,
            &cb.ca_data_b64,
        )
        .await?;
        let now = now_unix() as u64;
        if let Some(entry) = self
            .teleport_callbacks
            .write()
            .await
            .get_mut(&cb.callback_id)
        {
            if entry.tenant_id == tenant_id {
                entry.clusters.clone_from(&clusters);
                entry.updated_at = now;
            }
        }
        if let Some(sess) = self.teleport.write().await.get_mut(tenant_id) {
            if sess.callback_id == cb.callback_id {
                sess.clusters.clone_from(&clusters);
                sess.updated_at = now as i64;
            }
        }
        Ok(clusters)
    }

    pub async fn teleport_status(&self, tenant_id: &str) -> TeleportSession {
        let now = now_unix();
        let mut sess = self
            .teleport
            .read()
            .await
            .get(tenant_id)
            .cloned()
            .unwrap_or(TeleportSession {
                proxy_url: String::new(),
                status: "disconnected".to_owned(),
                user: String::new(),
                clusters: Vec::new(),
                callback_id: String::new(),
                expires_at: 0,
                updated_at: 0,
            });
        if sess.status == "connected" && sess.expires_at > 0 && now >= sess.expires_at {
            "expired".clone_into(&mut sess.status);
        }
        sess
    }

    pub async fn cancel_teleport(&self, tenant_id: &str) {
        self.teleport.write().await.remove(tenant_id);
    }
}

fn decode_pem_blocks(pem_text: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut rest = pem_text;
    let mut out = Vec::new();
    while let Some(b_idx) = rest.find(&begin) {
        let after_begin = &rest[b_idx + begin.len()..];
        let Some(e_idx) = after_begin.find(&end) else {
            break;
        };
        let b64: String = after_begin[..e_idx]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        if let Ok(bytes) = STANDARD.decode(b64) {
            out.push(bytes);
        }
        rest = &after_begin[e_idx + end.len()..];
    }
    out
}

fn decode_ca_certs(ca_data_b64_or_pem: &str) -> Vec<CertificateDer<'static>> {
    let trimmed = ca_data_b64_or_pem.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.contains("-----BEGIN CERTIFICATE-----") {
        return decode_pem_blocks(trimmed, "CERTIFICATE")
            .into_iter()
            .map(CertificateDer::from)
            .collect();
    }
    let Ok(decoded) = STANDARD.decode(trimmed) else {
        return Vec::new();
    };
    if let Ok(text) = std::str::from_utf8(&decoded) {
        let pems = decode_pem_blocks(text, "CERTIFICATE");
        if !pems.is_empty() {
            return pems.into_iter().map(CertificateDer::from).collect();
        }
    }
    vec![CertificateDer::from(decoded)]
}

fn parse_private_key_pem(pem_text: &str) -> Result<PrivateKeyDer<'static>, String> {
    if let Some(der) = decode_pem_blocks(pem_text, "PRIVATE KEY")
        .into_iter()
        .next()
    {
        return Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)));
    }
    if let Some(der) = decode_pem_blocks(pem_text, "RSA PRIVATE KEY")
        .into_iter()
        .next()
    {
        return Ok(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)));
    }
    if let Some(der) = decode_pem_blocks(pem_text, "EC PRIVATE KEY")
        .into_iter()
        .next()
    {
        return Ok(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)));
    }
    Err("no supported private key PEM block found in K8s client key".to_owned())
}

#[derive(Debug)]
struct InsecureSkipVerify;

impl ServerCertVerifier for InsecureSkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a `rustls::ClientConfig` for Kubernetes/Teleport WebSocket (`wss://`) streams,
/// attaching custom CA roots, `insecure_skip_tls_verify`, mTLS client cert/key, and HTTP/1.1 ALPN.
pub fn build_ws_tls_config(rec: &K8sClusterRecord) -> Result<rustls::ClientConfig, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in decode_ca_certs(&rec.ca_data_b64) {
        let _ = roots.add(cert);
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("failed configuring K8s WS TLS versions: {e}"))?;

    let wants_client_auth =
        !rec.client_cert_pem.trim().is_empty() && !rec.client_key_pem.trim().is_empty();
    let mut config = if rec.insecure_skip_tls_verify {
        let danger = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureSkipVerify));
        if wants_client_auth {
            let certs: Vec<CertificateDer<'static>> =
                decode_pem_blocks(&rec.client_cert_pem, "CERTIFICATE")
                    .into_iter()
                    .map(CertificateDer::from)
                    .collect();
            if certs.is_empty() {
                return Err("K8s client certificate PEM contains no CERTIFICATE blocks".to_owned());
            }
            let key = parse_private_key_pem(&rec.client_key_pem)?;
            danger
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("invalid K8s mTLS client identity: {e}"))?
        } else {
            danger.with_no_client_auth()
        }
    } else if wants_client_auth {
        let certs: Vec<CertificateDer<'static>> =
            decode_pem_blocks(&rec.client_cert_pem, "CERTIFICATE")
                .into_iter()
                .map(CertificateDer::from)
                .collect();
        if certs.is_empty() {
            return Err("K8s client certificate PEM contains no CERTIFICATE blocks".to_owned());
        }
        let key = parse_private_key_pem(&rec.client_key_pem)?;
        builder
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .map_err(|e| format!("invalid K8s mTLS client identity: {e}"))?
    } else {
        builder.with_root_certificates(roots).with_no_client_auth()
    };

    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

async fn dial_channel_ws(
    full_url: &str,
    bearer_token: Option<&str>,
    subprotocol: &'static str,
    connector: Option<Connector>,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, String> {
    let mut req = full_url
        .into_client_request()
        .map_err(|e| format!("invalid K8s WS URI: {e}"))?;
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        http::HeaderValue::from_static(subprotocol),
    );
    if let Some(tok) = bearer_token {
        let hv = http::HeaderValue::from_str(&format!("Bearer {tok}"))
            .map_err(|e| format!("invalid bearer token header: {e}"))?;
        req.headers_mut().insert(http::header::AUTHORIZATION, hv);
    }
    let (ws, resp) = connect_async_tls_with_config(req, None, false, connector)
        .await
        .map_err(|e| format!("K8s WS ({subprotocol}) connect failed: {e}"))?;
    if let Some(negotiated) = resp
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
    {
        if negotiated.trim() != subprotocol {
            return Err(format!(
                "K8s WS server negotiated unexpected subprotocol '{negotiated}' (expected '{subprotocol}')"
            ));
        }
    }
    Ok(ws)
}

fn parse_decimal_num_and_suffix(raw: &str) -> Option<(u128, u128, u32, &str)> {
    let s = raw.trim();
    if s.is_empty() || s.starts_with('-') {
        return None;
    }
    let s = s.strip_prefix('+').unwrap_or(s);
    let split_idx = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let num = &s[..split_idx];
    let suffix = &s[split_idx..];
    if num.is_empty() || num == "." {
        return None;
    }
    let mut parts = num.split('.');
    let int_part = parts.next().unwrap_or("");
    let frac_part = parts.next();
    if parts.next().is_some() {
        return None;
    }
    if int_part.is_empty() && frac_part.is_none_or(str::is_empty) {
        return None;
    }
    let int_val = if int_part.is_empty() {
        0u128
    } else {
        int_part.parse::<u128>().ok()?
    };
    let frac_str = frac_part.unwrap_or("");
    if !frac_str.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let digits = frac_str.len().min(12);
    let frac_val = if digits == 0 {
        0u128
    } else {
        frac_str[..digits].parse::<u128>().ok()?
    };
    Some((
        int_val,
        frac_val,
        u32::try_from(digits).unwrap_or(0),
        suffix,
    ))
}

/// Parse a Kubernetes CPU quantity (e.g. `"250m"`, `"500000n"`, `"500u"`, `"0.5"`, `"2"`)
/// into whole millicores, rounding sub-millicore positive usage up to match `resource.Quantity.MilliValue()`.
#[must_use]
pub fn parse_k8s_cpu_millicores(raw: &str) -> Option<i64> {
    let (int_val, frac_val, frac_digits, suffix) = parse_decimal_num_and_suffix(raw)?;
    let frac_scale = 10u128.pow(frac_digits);
    let (mul, div): (u128, u128) = match suffix {
        "" => (1_000, 1),
        "m" => (1, 1),
        "u" => (1, 1_000),
        "n" => (1, 1_000_000),
        "k" => (1_000_000, 1),
        "M" => (1_000_000_000, 1),
        "G" => (1_000_000_000_000, 1),
        _ => return None,
    };
    let numerator = int_val
        .checked_mul(frac_scale)?
        .checked_add(frac_val)?
        .checked_mul(mul)?;
    let denom = frac_scale.checked_mul(div)?;
    let milli = if div > 1 {
        numerator.div_ceil(denom)
    } else {
        (numerator + denom / 2) / denom
    };
    i64::try_from(milli).ok()
}

/// Parse a Kubernetes memory quantity (e.g. `"128Mi"`, `"1.5Gi"`, `"512M"`, `"1048576"`)
/// into whole bytes.
#[must_use]
pub fn parse_k8s_memory_bytes(raw: &str) -> Option<i64> {
    let (int_val, frac_val, frac_digits, suffix) = parse_decimal_num_and_suffix(raw)?;
    let frac_scale = 10u128.pow(frac_digits);
    let (mul, div): (u128, u128) = match suffix {
        "" => (1, 1),
        "m" => (1, 1_000),
        "Ki" => (1024, 1),
        "Mi" => (1024u128.pow(2), 1),
        "Gi" => (1024u128.pow(3), 1),
        "Ti" => (1024u128.pow(4), 1),
        "Pi" => (1024u128.pow(5), 1),
        "Ei" => (1024u128.pow(6), 1),
        "k" => (1_000, 1),
        "M" => (1_000u128.pow(2), 1),
        "G" => (1_000u128.pow(3), 1),
        "T" => (1_000u128.pow(4), 1),
        "P" => (1_000u128.pow(5), 1),
        "E" => (1_000u128.pow(6), 1),
        _ => return None,
    };
    let numerator = int_val
        .checked_mul(frac_scale)?
        .checked_add(frac_val)?
        .checked_mul(mul)?;
    let denom = frac_scale.checked_mul(div)?;
    let bytes = numerator / denom;
    i64::try_from(bytes).ok()
}

/// Normalize raw `metrics.k8s.io/v1beta1` `PodMetricsList.items` into flat `{ name, namespace, cpu_millicores, memory_bytes }`
/// entries expected by the Kubernetes UI table and detail pane.
#[must_use]
pub fn normalize_pod_metrics_items(items: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(name) = item["metadata"]["name"].as_str().filter(|s| !s.is_empty()) else {
            continue;
        };
        let namespace = item["metadata"]["namespace"].as_str().unwrap_or("");
        let Some(containers) = item["containers"].as_array().filter(|c| !c.is_empty()) else {
            continue;
        };
        let mut total_cpu = 0i64;
        let mut total_mem = 0i64;
        let mut valid = true;
        for container in containers {
            let cpu_s = container["usage"]["cpu"].as_str().unwrap_or("");
            let mem_s = container["usage"]["memory"].as_str().unwrap_or("");
            if let (Some(c), Some(m)) = (
                parse_k8s_cpu_millicores(cpu_s),
                parse_k8s_memory_bytes(mem_s),
            ) {
                total_cpu = total_cpu.saturating_add(c);
                total_mem = total_mem.saturating_add(m);
            } else {
                valid = false;
                break;
            }
        }
        if valid {
            out.push(serde_json::json!({
                "name": name,
                "namespace": namespace,
                "cpu_millicores": total_cpu,
                "memory_bytes": total_mem,
            }));
        }
    }
    out
}

fn normalize_k8s_policy(pol: &mut K8sRecordingPolicy) {
    if pol.mode.trim().is_empty() {
        pol.mode = if pol.record_exec {
            "all".to_owned()
        } else {
            "off".to_owned()
        };
    }
    if pol.mode == "off" {
        pol.record_exec = false;
        pol.record_attach = false;
    } else if !pol.record_exec {
        pol.record_exec = true;
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
    use std::io::Write as _;

    use axum::routing::get;
    use axum::{Json, Router};
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn parses_kubeconfig_blocks_unsafe_exec_and_decodes_helm_releases_over_k8s_api() {
        let bad = r"
clusters:
  - name: bad
    cluster:
      server: https://127.0.0.1:6443
users:
  - name: evil
    user:
      exec:
        command: /bin/sh
";
        assert!(parse_kubeconfig_safe(bad).is_err());

        let release_json = serde_json::json!({
            "info": { "status": "deployed", "last_deployed": "2026-11-16T00:00:00Z" },
            "chart": { "metadata": { "name": "ingress-nginx", "version": "4.11.0", "app_version": "1.11.0" } }
        })
        .to_string();
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(release_json.as_bytes()).unwrap();
        let b64_rel = STANDARD.encode(gz.finish().unwrap());

        let app = Router::new().route(
            "/api/v1/namespaces/prod/secrets",
            get(move || {
                let rel = b64_rel.clone();
                async move {
                    Json(serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "SecretList",
                        "items": [{
                            "metadata": {
                                "name": "sh.helm.release.v1.web.v2",
                                "namespace": "prod",
                                "labels": { "owner": "helm", "name": "web", "version": "2", "status": "deployed" }
                            },
                            "data": { "release": rel }
                        }]
                    }))
                }
            }),
        );
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(ln, app).await;
        });

        let mgr = K8sManager::new();
        let good_yaml = format!(
            "clusters:\n  - name: eks-prod\n    cluster:\n      server: http://{addr}\nusers:\n  - name: ops\n    user:\n      exec:\n        command: aws\n"
        );
        let uploaded = mgr
            .upload_kubeconfig("acme", &good_yaml, true)
            .await
            .unwrap();
        assert_eq!(uploaded.len(), 1);
        assert!(uploaded[0].connected);

        let releases = mgr
            .helm_releases("acme", &uploaded[0].id, "prod")
            .await
            .unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].name, "web");
        assert_eq!(releases[0].chart.as_ref().unwrap().version, "4.11.0");
    }

    #[test]
    fn parses_k8s_cpu_and_memory_quantities_and_normalizes_metrics() {
        assert_eq!(parse_k8s_cpu_millicores("0"), Some(0));
        assert_eq!(parse_k8s_cpu_millicores("0n"), Some(0));
        assert_eq!(parse_k8s_cpu_millicores("250m"), Some(250));
        assert_eq!(parse_k8s_cpu_millicores("1.25"), Some(1250));
        assert_eq!(parse_k8s_cpu_millicores("500000n"), Some(1));
        assert_eq!(parse_k8s_cpu_millicores("250000000n"), Some(250));
        assert_eq!(parse_k8s_cpu_millicores("1500u"), Some(2));
        assert_eq!(parse_k8s_cpu_millicores("-1"), None);
        assert_eq!(parse_k8s_cpu_millicores("bad"), None);

        assert_eq!(parse_k8s_memory_bytes("128Mi"), Some(128 * 1024 * 1024));
        assert_eq!(parse_k8s_memory_bytes("1024Ki"), Some(1024 * 1024));
        assert_eq!(parse_k8s_memory_bytes("1.5Gi"), Some(1_610_612_736));
        assert_eq!(parse_k8s_memory_bytes("512M"), Some(512_000_000));
        assert_eq!(parse_k8s_memory_bytes("4096"), Some(4096));
        assert_eq!(parse_k8s_memory_bytes("-5Mi"), None);

        let raw_items = vec![
            serde_json::json!({
                "metadata": { "name": "api-1", "namespace": "prod" },
                "containers": [
                    { "name": "app", "usage": { "cpu": "125m", "memory": "64Mi" } },
                    { "name": "sidecar", "usage": { "cpu": "25000000n", "memory": "32Mi" } }
                ]
            }),
            serde_json::json!({
                "metadata": { "name": "empty", "namespace": "prod" },
                "containers": []
            }),
        ];
        let norm = normalize_pod_metrics_items(&raw_items);
        assert_eq!(norm.len(), 1);
        assert_eq!(norm[0]["name"], "api-1");
        assert_eq!(norm[0]["namespace"], "prod");
        assert_eq!(norm[0]["cpu_millicores"], 150);
        assert_eq!(norm[0]["memory_bytes"], 96 * 1024 * 1024);
    }

    #[test]
    fn builds_ws_mtls_config_and_evaluates_k8s_recording_policy() {
        let ca_kp = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(["tp-ca".to_owned()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_kp).unwrap();

        let cli_kp = rcgen::KeyPair::generate().unwrap();
        let cli_params = rcgen::CertificateParams::new(["alice".to_owned()]).unwrap();
        let cli_cert = cli_params.signed_by(&cli_kp, &ca_cert, &ca_kp).unwrap();

        let rec = K8sClusterRecord {
            id: "tp:example".to_owned(),
            tenant_id: "default".to_owned(),
            name: "tp-eks".to_owned(),
            source: "teleport".to_owned(),
            api_server: "https://tp.example.com".to_owned(),
            bearer_token: String::new(),
            client_cert_pem: cli_cert.pem(),
            client_key_pem: cli_kp.serialize_pem(),
            ca_data_b64: STANDARD.encode(ca_cert.pem().as_bytes()),
            insecure_skip_tls_verify: false,
            connected: true,
            recording_enabled: true,
            region: "custom".to_owned(),
            exec_command: String::new(),
        };
        let cfg = build_ws_tls_config(&rec).expect("mTLS WS TLS config");
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);

        let off = K8sRecordingPolicy {
            mode: "off".to_owned(),
            ..K8sRecordingPolicy::default()
        };
        assert!(!off.should_record_namespace("prod", false));

        let sel = K8sRecordingPolicy {
            mode: "selected".to_owned(),
            namespaces: vec!["prod".to_owned()],
            record_exec: true,
            record_attach: false,
            ..K8sRecordingPolicy::default()
        };
        assert!(sel.should_record_namespace("prod", false));
        assert!(!sel.should_record_namespace("prod", true));
        assert!(!sel.should_record_namespace("dev", false));
    }

    #[tokio::test]
    async fn spdy_channel_ws_negotiates_v5_and_falls_back_to_base64() {
        use axum::extract::ws::WebSocketUpgrade;
        use axum::routing::get;
        use axum::Router;
        use tokio::net::TcpListener;

        let app = Router::new()
            .route(
                "/v5/exec",
                get(|ws: WebSocketUpgrade| async move {
                    ws.protocols(["v5.channel.k8s.io"])
                        .on_upgrade(|mut sock| async move {
                            let _ = sock
                                .send(axum::extract::ws::Message::Binary(
                                    vec![1, b'h', b'i'].into(),
                                ))
                                .await;
                        })
                }),
            )
            .route(
                "/base64-only/exec",
                get(
                    |headers: http::HeaderMap, ws: WebSocketUpgrade| async move {
                        let req_proto = headers
                            .get("sec-websocket-protocol")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        if req_proto != "base64.channel.k8s.io" {
                            return axum::response::Response::builder()
                                .status(400)
                                .body(axum::body::Body::from("unsupported subprotocol"))
                                .unwrap();
                        }
                        ws.protocols(["base64.channel.k8s.io"])
                            .on_upgrade(|mut sock| async move {
                                let _ = sock
                                    .send(axum::extract::ws::Message::Text("MQ==".into()))
                                    .await;
                            })
                    },
                ),
            );

        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(ln, app).await;
        });

        let mgr = K8sManager::new();
        mgr.upsert_cluster(K8sClusterRecord {
            id: "loopback-ws".to_owned(),
            tenant_id: "t1".to_owned(),
            name: "loopback-ws".to_owned(),
            source: "kubeconfig".to_owned(),
            api_server: format!("http://{addr}"),
            bearer_token: "tok-1".to_owned(),
            connected: true,
            ..K8sClusterRecord::default()
        })
        .await;

        let (_ws_v5, proto_v5) = mgr
            .connect_spdy_channel_ws_with_proto("t1", "loopback-ws", "/v5/exec")
            .await
            .expect("v5 negotiated");
        assert_eq!(proto_v5, "v5.channel.k8s.io");

        let (_ws_b64, proto_b64) = mgr
            .connect_spdy_channel_ws_with_proto("t1", "loopback-ws", "/base64-only/exec")
            .await
            .expect("base64 fallback negotiated");
        assert_eq!(proto_b64, "base64.channel.k8s.io");

        mgr.store_teleport_callback(
            "t1",
            "https://tp.example.com",
            teleport::TeleportLoginOutcome {
                teleport_cluster: "tp".to_owned(),
                kube_api_base: "https://tp.example.com".to_owned(),
                username: "alice".to_owned(),
                clusters: vec!["eks-a".to_owned()],
                client_cert_pem: String::new(),
                client_key_pem: String::new(),
                ca_data_b64: String::new(),
                expires_at: 1, // already expired epoch 1
            },
        )
        .await;
        let st = mgr.teleport_status("t1").await;
        assert_eq!(st.status, "expired");
    }
}
