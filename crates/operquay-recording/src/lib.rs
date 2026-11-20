#![forbid(unsafe_code)]

//! Clean-room fail-closed synchronous encrypted session recorder (`.guac` + `.cast`),
//! path containment (`fs::canonicalize`), retention & legal-hold purge, WORM S3 Object Lock
//! archival (`worm`), and pure-Rust inter-frame H.264 Baseline ISO-BMFF MP4 exporter (`h264_mp4`).

pub mod h264_mp4;
pub mod worm;

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub use h264_mp4::{mux_rgb_frames_to_mp4, transcode_cast_to_mp4, transcode_guac_to_mp4};
use operquay_auth::crypto::{
    derive_key32, fill_csprng, open_aead, seal_aead, KeyRing, KmsEnvelopeProvider,
    LocalKeyRingProvider, TenantKeyManager,
};
use operquay_core::OperquayError;
use operquay_display::DisplayOp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use zeroize::Zeroize;

const OQRK1_MAGIC: &[u8; 5] = b"OQRK1";
const OQRK1_FLAG_TENANT_DEK: u8 = 0x01;
const MAX_OQRK1_CHUNK_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingPolicy {
    #[serde(default = "default_rec_mode")]
    pub mode: String,
    #[serde(default)]
    pub instances: Vec<String>,
    #[serde(default = "default_true")]
    pub record_ssh: bool,
    #[serde(default = "default_true")]
    pub record_rdp: bool,
    #[serde(default = "default_true")]
    pub record_k8s: bool,
    #[serde(default = "default_true")]
    pub fail_closed: bool,
    #[serde(default = "default_retention")]
    pub retention_days: u32,
    #[serde(default = "default_true")]
    pub auto_convert_mp4: bool,
}

fn default_rec_mode() -> String {
    "off".to_owned()
}

fn default_true() -> bool {
    true
}

fn default_retention() -> u32 {
    90
}

impl Default for RecordingPolicy {
    fn default() -> Self {
        Self {
            mode: default_rec_mode(),
            instances: Vec::new(),
            record_ssh: true,
            record_rdp: true,
            record_k8s: true,
            fail_closed: true,
            retention_days: 90,
            auto_convert_mp4: true,
        }
    }
}

impl RecordingPolicy {
    /// Evaluate whether a session for `protocol` on `instance_id` (`environment` tag) must be recorded.
    #[must_use]
    pub fn should_record_instance(
        &self,
        protocol: &str,
        instance_id: &str,
        environment: &str,
    ) -> bool {
        let protocol_enabled = match protocol {
            "ssh" | "ssm" => self.record_ssh,
            "rdp" | "vnc" => self.record_rdp,
            "k8s" => self.record_k8s,
            _ => true,
        };
        if !protocol_enabled {
            return false;
        }
        let req_prod = std::env::var("REQUIRED_PRODUCTION_RECORDING")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        let env_lower = environment.trim().to_ascii_lowercase();
        let is_prod =
            env_lower == "prod" || env_lower == "production" || env_lower.contains("prod");
        match self.mode.trim().to_ascii_lowercase().as_str() {
            "all" => true,
            "selected" => {
                self.instances.iter().any(|id| id == instance_id) || (req_prod && is_prod)
            }
            _ => req_prod && is_prod,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversionStatus {
    pub id: String,
    pub job_id: String,
    pub status: String,
    pub format: String,
    pub output_bytes: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingEntry {
    pub id: String,
    pub tenant_id: String,
    pub protocol: String,
    pub target_host: String,
    pub format: String,
    pub started_at_ms: u64,
    pub bytes_written: usize,
    pub frame_count: u64,
    pub sha256_hex: String,
    pub fail_closed: bool,
    pub status: String,
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default)]
    pub legal_hold: bool,
    #[serde(default)]
    pub legal_hold_reason: String,
    #[serde(default)]
    pub retention_until_ms: Option<u64>,
    #[serde(default)]
    pub archived_s3_uri: Option<String>,
    #[serde(default)]
    pub archived_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PurgeReport {
    pub tenant_id: String,
    pub checked: usize,
    pub purged_ids: Vec<String>,
    pub skipped_legal_hold: usize,
}

/// Strictly validate `filename` and enforce `fs::canonicalize` containment under `canonical_base`,
/// blocking path traversal (`..`, `/`, `\`) and symlinks (`M10.2`).
pub fn safe_recording_path(
    canonical_base: &Path,
    filename: &str,
) -> Result<PathBuf, OperquayError> {
    if filename.is_empty()
        || filename.len() > 255
        || filename.starts_with('.')
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains("..")
        || filename.contains('\0')
        || !filename
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(OperquayError::RecordingRequired(format!(
            "unsafe recording filename '{filename}' rejected"
        )));
    }
    let resolved_base = std::fs::canonicalize(canonical_base).map_err(|e| {
        OperquayError::RecordingRequired(format!(
            "recording base directory canonicalization failed: {e}"
        ))
    })?;
    let candidate = resolved_base.join(filename);
    if let Ok(meta) = std::fs::symlink_metadata(&candidate) {
        if meta.file_type().is_symlink() {
            return Err(OperquayError::RecordingRequired(format!(
                "symlink recording target '{}' rejected",
                candidate.display()
            )));
        }
        let resolved_target = std::fs::canonicalize(&candidate).map_err(|e| {
            OperquayError::RecordingRequired(format!(
                "recording target canonicalization failed: {e}"
            ))
        })?;
        if !resolved_target.starts_with(&resolved_base) {
            return Err(OperquayError::RecordingRequired(format!(
                "recording target '{}' escaped base directory",
                resolved_target.display()
            )));
        }
    }
    Ok(candidate)
}

#[derive(Clone)]
struct CryptoState {
    provider: Arc<dyn KmsEnvelopeProvider>,
    legacy_ring: KeyRing,
    tenant_keys: Arc<TenantKeyManager>,
}

impl std::fmt::Debug for CryptoState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoState")
            .field("active_version", &self.legacy_ring.active_version())
            .finish_non_exhaustive()
    }
}

impl Default for CryptoState {
    fn default() -> Self {
        let mut seed = [0u8; 32];
        if let Ok(env_key) = std::env::var("OPERQUAY_RECORDING_MASTER_KEY") {
            let derived = derive_key32(env_key.as_bytes(), b"operquay/recording-env-seed/v1");
            seed.copy_from_slice(&derived);
        } else {
            let _ = fill_csprng(&mut seed);
        }
        let ring = KeyRing::from_master_and_env(&seed, b"operquay/recording-aead/v1");
        seed.zeroize();
        let provider: Arc<dyn KmsEnvelopeProvider> =
            if let Some(kms) = operquay_auth::crypto::AwsKmsEnvelopeProvider::from_env() {
                Arc::new(kms)
            } else {
                Arc::new(LocalKeyRingProvider::new(ring.clone()))
            };
        Self {
            provider,
            legacy_ring: ring,
            tenant_keys: Arc::new(TenantKeyManager::new()),
        }
    }
}

/// Fail-closed encrypted in-memory + optional filesystem/WORM recording catalog (`M10.2`).
#[derive(Debug, Default)]
pub struct RecordingCatalog {
    entries: RwLock<HashMap<String, RecordingEntry>>,
    blobs: RwLock<HashMap<String, Vec<u8>>>,
    mp4_blobs: RwLock<HashMap<String, Vec<u8>>>,
    storage_dir: Option<PathBuf>,
    crypto: RwLock<CryptoState>,
}

impl RecordingCatalog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a disk-backed recording catalog and hydrate metadata entries using canonical path containment.
    #[allow(clippy::needless_pass_by_value)]
    pub fn with_dir(dir: PathBuf) -> Result<Self, std::io::Error> {
        std::fs::create_dir_all(&dir)?;
        let canonical_dir = std::fs::canonicalize(&dir)?;
        let mut entries = HashMap::new();
        let mut blobs = HashMap::new();
        let mut mp4_blobs = HashMap::new();

        if let Ok(rd) = std::fs::read_dir(&canonical_dir) {
            for item in rd.flatten() {
                let path = item.path();
                if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
                    continue;
                }
                let Some(fname) = path.file_name().and_then(|s| s.to_str()) else {
                    continue;
                };
                let Some(stem) = fname.strip_suffix(".meta.json") else {
                    continue;
                };
                if safe_recording_path(&canonical_dir, fname).is_err() {
                    continue;
                }
                if let Ok(meta_bytes) = std::fs::read(&path) {
                    if let Ok(entry) = serde_json::from_slice::<RecordingEntry>(&meta_bytes) {
                        let ext = if entry.format == "cast" {
                            "cast"
                        } else {
                            "guac"
                        };
                        if let Ok(data_path) =
                            safe_recording_path(&canonical_dir, &format!("{stem}.{ext}"))
                        {
                            if let Ok(data) = std::fs::read(&data_path) {
                                blobs.insert(entry.id.clone(), data);
                            }
                        }
                        if let Ok(mp4_path) =
                            safe_recording_path(&canonical_dir, &format!("{stem}.mp4"))
                        {
                            if let Ok(mp4) = std::fs::read(&mp4_path) {
                                mp4_blobs.insert(entry.id.clone(), mp4);
                            }
                        }
                        entries.insert(entry.id.clone(), entry);
                    }
                }
            }
        }

        Ok(Self {
            entries: RwLock::new(entries),
            blobs: RwLock::new(blobs),
            mp4_blobs: RwLock::new(mp4_blobs),
            storage_dir: Some(canonical_dir),
            crypto: RwLock::new(CryptoState::default()),
        })
    }

    /// Attach a shared [`TenantKeyManager`] synchronously during server state construction.
    #[must_use]
    pub fn with_shared_tenant_keys(mut self, tenant_keys: Arc<TenantKeyManager>) -> Self {
        self.crypto.get_mut().tenant_keys = tenant_keys;
        self
    }

    /// Configure persistent cluster KEK + tenant DEK manager (called after PostgreSQL attaches on startup).
    pub async fn attach_cluster_crypto(
        &self,
        master_secret: &[u8],
        tenant_keys: Arc<TenantKeyManager>,
    ) {
        let ring = KeyRing::from_master_and_env(master_secret, b"operquay/recording-aead/v1");
        let provider: Arc<dyn KmsEnvelopeProvider> =
            if let Some(kms) = operquay_auth::crypto::AwsKmsEnvelopeProvider::from_env() {
                Arc::new(kms)
            } else {
                Arc::new(LocalKeyRingProvider::new(ring.clone()))
            };
        let mut guard = self.crypto.write().await;
        guard.provider = provider;
        guard.legacy_ring = ring;
        guard.tenant_keys = tenant_keys;
    }

    #[must_use]
    pub fn storage_dir(&self) -> Option<&Path> {
        self.storage_dir.as_deref()
    }

    pub async fn hydrate_metadata(&self, items: Vec<RecordingEntry>) {
        let mut guard = self.entries.write().await;
        for item in items {
            guard.entry(item.id.clone()).or_insert(item);
        }
    }

    pub async fn start_session(
        &self,
        id: String,
        tenant_id: String,
        protocol: String,
        target_host: String,
        fail_closed: bool,
    ) -> Result<RecordingTee, OperquayError> {
        if id.is_empty()
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(OperquayError::RecordingRequired(
                "invalid recording session identifier".into(),
            ));
        }
        let format = if matches!(protocol.as_str(), "ssh" | "ssm" | "k8s") {
            "cast"
        } else {
            "guac"
        };

        let crypto = self.crypto.read().await.clone();
        let mut tenant_dek = crypto
            .tenant_keys
            .get_or_create_key(&tenant_id)
            .await
            .map_err(|e| {
                OperquayError::RecordingRequired(format!("tenant encryption key unavailable: {e}"))
            })?;

        let header_aad = session_header_aad(&tenant_id, &id);
        let (key_ver, mut raw_dek, wrapped_dek) = crypto
            .provider
            .generate_data_key(&header_aad)
            .await
            .map_err(|e| {
                OperquayError::RecordingRequired(format!("KMS generate_data_key failed: {e}"))
            })?;
        let mut effective_dek = derive_session_dek(&raw_dek, &tenant_dek);
        raw_dek.zeroize();
        tenant_dek.zeroize();

        let wrapped_len = u16::try_from(wrapped_dek.len()).map_err(|_| {
            OperquayError::RecordingRequired("wrapped DEK exceeds u16 length bound".into())
        })?;
        let mut header_bytes = Vec::with_capacity(10 + wrapped_dek.len());
        header_bytes.extend_from_slice(OQRK1_MAGIC);
        header_bytes.push(OQRK1_FLAG_TENANT_DEK);
        header_bytes.extend_from_slice(&key_ver.to_be_bytes());
        header_bytes.extend_from_slice(&wrapped_len.to_be_bytes());
        header_bytes.extend_from_slice(&wrapped_dek);

        let live_file = if let Some(dir) = &self.storage_dir {
            let fname = format!("{id}.{format}");
            let path = match safe_recording_path(dir, &fname) {
                Ok(p) => p,
                Err(err) if fail_closed => {
                    effective_dek.zeroize();
                    return Err(err);
                }
                Err(_) => {
                    effective_dek.zeroize();
                    return Err(OperquayError::RecordingRequired(
                        "unsafe recording file path".into(),
                    ));
                }
            };
            match open_private_file(&path).and_then(|mut f| {
                use std::io::Write as _;
                f.write_all(&header_bytes)?;
                f.flush()?;
                Ok(f)
            }) {
                Ok(f) => Some(f),
                Err(err) if fail_closed => {
                    effective_dek.zeroize();
                    return Err(OperquayError::RecordingRequired(format!(
                        "cannot open encrypted recording file {}: {err}",
                        path.display()
                    )));
                }
                Err(_) => None,
            }
        } else {
            None
        };

        let now_ms = now_unix_ms();
        let entry = RecordingEntry {
            id: id.clone(),
            tenant_id: tenant_id.clone(),
            protocol,
            target_host,
            format: format.into(),
            started_at_ms: now_ms,
            bytes_written: 0,
            frame_count: 0,
            sha256_hex: String::new(),
            fail_closed,
            status: "active".into(),
            encrypted: true,
            legal_hold: false,
            legal_hold_reason: String::new(),
            retention_until_ms: None,
            archived_s3_uri: None,
            archived_at_ms: None,
        };
        self.entries.write().await.insert(id.clone(), entry);
        self.blobs
            .write()
            .await
            .insert(id.clone(), header_bytes.clone());

        Ok(RecordingTee {
            id,
            tenant_id,
            fail_closed,
            enc_buffer: header_bytes,
            plaintext_len: 0,
            hasher: Sha256::new(),
            frame_count: 0,
            chunk_seq: 0,
            dek: effective_dek,
            simulated_fault: false,
            live_file,
        })
    }

    pub async fn start_cast_session(
        &self,
        id: String,
        tenant_id: String,
        protocol: String,
        target_host: String,
        fail_closed: bool,
        cols: u16,
        rows: u16,
    ) -> Result<RecordingTee, OperquayError> {
        let mut tee = self
            .start_session(id, tenant_id, protocol, target_host, fail_closed)
            .await?;
        let mut hdr = serde_json::json!({
            "version": 2,
            "width": cols.max(20),
            "height": rows.max(5),
            "title": "Operquay Audited SSH/K8s Session"
        })
        .to_string();
        hdr.push('\n');
        tee.record_guac_line(&hdr)?;
        Ok(tee)
    }

    pub async fn finalize(&self, mut tee: RecordingTee) -> RecordingEntry {
        let digest: [u8; 32] = tee.hasher.finalize_reset().into();
        let sha256_hex = hex_encode(&digest);
        let bytes_written = tee.plaintext_len;
        let frame_count = tee.frame_count;

        let id = tee.id.clone();
        let updated = {
            let mut entries = self.entries.write().await;
            if let Some(existing) = entries.get_mut(&id) {
                existing.bytes_written = bytes_written;
                existing.frame_count = frame_count;
                existing.sha256_hex = sha256_hex;
                existing.status = "completed".into();
                existing.encrypted = true;
                existing.clone()
            } else {
                RecordingEntry {
                    id: id.clone(),
                    tenant_id: tee.tenant_id.clone(),
                    protocol: "rdp".into(),
                    target_host: String::new(),
                    format: "guac".into(),
                    started_at_ms: 0,
                    bytes_written,
                    frame_count,
                    sha256_hex,
                    fail_closed: tee.fail_closed,
                    status: "completed".into(),
                    encrypted: true,
                    legal_hold: false,
                    legal_hold_reason: String::new(),
                    retention_until_ms: None,
                    archived_s3_uri: None,
                    archived_at_ms: None,
                }
            }
        };

        let enc_bytes = std::mem::take(&mut tee.enc_buffer);
        if let Some(mut file) = tee.live_file.take() {
            use std::io::Write as _;
            let _ = file.flush();
            let _ = file.sync_data();
        } else if let Some(dir) = &self.storage_dir {
            let ext = if updated.format == "cast" {
                "cast"
            } else {
                "guac"
            };
            if let Ok(data_path) = safe_recording_path(dir, &format!("{id}.{ext}")) {
                let _ = write_private_bytes(&data_path, &enc_bytes);
            }
        }
        if let Some(dir) = &self.storage_dir {
            if let Ok(meta_path) = safe_recording_path(dir, &format!("{id}.meta.json")) {
                if let Ok(meta_json) = serde_json::to_vec(&updated) {
                    let _ = write_private_bytes(&meta_path, &meta_json);
                }
            }
        }

        self.blobs.write().await.insert(id, enc_bytes);
        updated
    }

    pub async fn list(&self, tenant_id: &str) -> Vec<RecordingEntry> {
        let mut items: Vec<_> = self
            .entries
            .read()
            .await
            .values()
            .filter(|e| e.tenant_id == tenant_id)
            .cloned()
            .collect();
        items.sort_by_key(|a| std::cmp::Reverse(a.started_at_ms));
        items
    }

    pub async fn resolve_id(&self, id_or_name: &str) -> Option<String> {
        let entries = self.entries.read().await;
        if entries.contains_key(id_or_name) {
            return Some(id_or_name.to_owned());
        }
        let stem = strip_recording_extension(id_or_name);
        if entries.contains_key(stem) {
            return Some(stem.to_owned());
        }
        for e in entries.values() {
            let canonical = canonical_recording_filename(e);
            if canonical == id_or_name || strip_recording_extension(&canonical) == stem {
                return Some(e.id.clone());
            }
        }
        None
    }

    pub async fn get_entry(&self, id_or_name: &str) -> Option<RecordingEntry> {
        let resolved = self.resolve_id(id_or_name).await;
        let key = resolved.as_deref().unwrap_or(id_or_name);
        self.entries.read().await.get(key).cloned()
    }

    /// Return the raw encrypted `OQRK1` bytes for WORM S3 Object Lock archival (`M10.2`).
    pub async fn get_encrypted_bytes(&self, id_or_name: &str) -> Option<Vec<u8>> {
        let resolved = self.resolve_id(id_or_name).await;
        let key = resolved.as_deref().unwrap_or(id_or_name);
        if let Some(raw) = self.blobs.read().await.get(key).cloned() {
            return Some(raw);
        }
        let dir = self.storage_dir.as_ref()?;
        let ext = self.entries.read().await.get(key).map_or("guac", |e| {
            if e.format == "cast" {
                "cast"
            } else {
                "guac"
            }
        });
        let path = safe_recording_path(dir, &format!("{key}.{ext}")).ok()?;
        std::fs::read(path).ok()
    }

    pub async fn get_guac_bytes(&self, id_or_name: &str) -> Option<Vec<u8>> {
        let resolved = self.resolve_id(id_or_name).await;
        let key = resolved.as_deref().unwrap_or(id_or_name).to_owned();
        let tenant_id = self
            .entries
            .read()
            .await
            .get(&key)
            .map_or_else(|| "default".to_owned(), |e| e.tenant_id.clone());
        let raw = self.get_encrypted_bytes(&key).await?;
        self.decrypt_blob(&tenant_id, &key, &raw).await.ok()
    }

    pub async fn has_mp4(&self, id: &str) -> bool {
        if self.mp4_blobs.read().await.contains_key(id) {
            return true;
        }
        if let Some(dir) = &self.storage_dir {
            if let Ok(p) = safe_recording_path(dir, &format!("{id}.mp4")) {
                return p.exists();
            }
        }
        false
    }

    pub async fn get_mp4_bytes(&self, id_or_name: &str) -> Option<Vec<u8>> {
        let resolved = self.resolve_id(id_or_name).await;
        let key = resolved.as_deref().unwrap_or(id_or_name).to_owned();
        let tenant_id = self
            .entries
            .read()
            .await
            .get(&key)
            .map_or_else(|| "default".to_owned(), |e| e.tenant_id.clone());
        let raw = if let Some(b) = self.mp4_blobs.read().await.get(&key).cloned() {
            b
        } else if let Some(dir) = &self.storage_dir {
            let p = safe_recording_path(dir, &format!("{key}.mp4")).ok()?;
            std::fs::read(p).ok()?
        } else {
            return None;
        };
        self.decrypt_blob(&tenant_id, &key, &raw).await.ok()
    }

    pub async fn set_mp4_bytes(&self, id_or_name: &str, plain_bytes: Vec<u8>) {
        let key = self
            .resolve_id(id_or_name)
            .await
            .unwrap_or_else(|| strip_recording_extension(id_or_name).to_owned());
        let tenant_id = self
            .entries
            .read()
            .await
            .get(&key)
            .map_or_else(|| "default".to_owned(), |e| e.tenant_id.clone());
        let stored = self
            .encrypt_single_blob(&tenant_id, &key, &plain_bytes)
            .await
            .unwrap_or(plain_bytes);
        if let Some(dir) = &self.storage_dir {
            if let Ok(path) = safe_recording_path(dir, &format!("{key}.mp4")) {
                let _ = write_private_bytes(&path, &stored);
            }
        }
        self.mp4_blobs.write().await.insert(key, stored);
    }

    pub async fn set_legal_hold(
        &self,
        tenant_id: &str,
        id_or_name: &str,
        hold: bool,
        reason: &str,
    ) -> Result<RecordingEntry, String> {
        let resolved = self
            .resolve_id(id_or_name)
            .await
            .unwrap_or_else(|| strip_recording_extension(id_or_name).to_owned());
        let updated = {
            let mut entries = self.entries.write().await;
            let entry = entries
                .get_mut(&resolved)
                .filter(|e| e.tenant_id == tenant_id)
                .ok_or_else(|| "recording not found".to_owned())?;
            entry.legal_hold = hold;
            reason.trim().clone_into(&mut entry.legal_hold_reason);
            entry.clone()
        };
        if let Some(dir) = &self.storage_dir {
            if let Ok(meta_path) = safe_recording_path(dir, &format!("{}.meta.json", updated.id)) {
                if let Ok(meta_json) = serde_json::to_vec(&updated) {
                    let _ = write_private_bytes(&meta_path, &meta_json);
                }
            }
        }
        Ok(updated)
    }

    pub async fn mark_archived(
        &self,
        tenant_id: &str,
        id_or_name: &str,
        s3_uri: String,
        retain_until_ms: u64,
        archived_at_ms: u64,
    ) -> Option<RecordingEntry> {
        let resolved = self.resolve_id(id_or_name).await;
        let key = resolved.as_deref().unwrap_or(id_or_name);
        let updated = {
            let mut entries = self.entries.write().await;
            let entry = entries.get_mut(key).filter(|e| e.tenant_id == tenant_id)?;
            entry.archived_s3_uri = Some(s3_uri);
            entry.archived_at_ms = Some(archived_at_ms);
            entry.retention_until_ms = Some(retain_until_ms);
            entry.clone()
        };
        if let Some(dir) = &self.storage_dir {
            if let Ok(meta_path) = safe_recording_path(dir, &format!("{}.meta.json", updated.id)) {
                if let Ok(meta_json) = serde_json::to_vec(&updated) {
                    let _ = write_private_bytes(&meta_path, &meta_json);
                }
            }
        }
        Some(updated)
    }

    pub async fn delete_recording_checked(&self, id_or_name: &str) -> Result<bool, String> {
        let resolved = self.resolve_id(id_or_name).await;
        let key = resolved.as_deref().unwrap_or(id_or_name).to_owned();
        if self
            .entries
            .read()
            .await
            .get(&key)
            .is_some_and(|e| e.legal_hold)
        {
            return Err(format!(
                "recording '{key}' is under legal hold and cannot be deleted"
            ));
        }
        if let Some(dir) = &self.storage_dir {
            for ext in ["guac", "cast", "mp4", "meta.json"] {
                if let Ok(path) = safe_recording_path(dir, &format!("{key}.{ext}")) {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        let removed_entry = self.entries.write().await.remove(&key).is_some();
        let removed_blob = self.blobs.write().await.remove(&key).is_some();
        let removed_mp4 = self.mp4_blobs.write().await.remove(&key).is_some();
        Ok(removed_entry || removed_blob || removed_mp4)
    }

    pub async fn delete_recording(&self, id_or_name: &str) -> bool {
        self.delete_recording_checked(id_or_name)
            .await
            .unwrap_or(false)
    }

    /// Purge expired recordings for `tenant_id` older than `retention_days`,
    /// strictly sparing active sessions and recordings under `legal_hold == true`.
    pub async fn purge_expired(
        &self,
        tenant_id: &str,
        retention_days: u32,
        now_ms: u64,
    ) -> PurgeReport {
        let mut report = PurgeReport {
            tenant_id: tenant_id.to_owned(),
            ..PurgeReport::default()
        };
        if retention_days == 0 {
            return report;
        }
        let retention_window_ms = u64::from(retention_days).saturating_mul(86_400_000);
        let cutoff_ms = now_ms.saturating_sub(retention_window_ms);

        let candidates: Vec<RecordingEntry> = {
            let entries = self.entries.read().await;
            entries
                .values()
                .filter(|e| e.tenant_id == tenant_id && e.status != "active")
                .cloned()
                .collect()
        };
        report.checked = candidates.len();

        let mut victims = Vec::new();
        for entry in candidates {
            if entry.legal_hold {
                report.skipped_legal_hold += 1;
                continue;
            }
            let expired = entry
                .retention_until_ms
                .map_or(entry.started_at_ms <= cutoff_ms, |until| until <= now_ms);
            if expired {
                victims.push(entry.id);
            }
        }
        for id in victims {
            if self.delete_recording_checked(&id).await.unwrap_or(false) {
                report.purged_ids.push(id);
            }
        }
        report
    }

    /// Evict cached blobs from RAM for `tenant_id` (used during tenant crypto-shredding).
    pub async fn evict_tenant_cache(&self, tenant_id: &str) {
        let ids: Vec<String> = self
            .entries
            .read()
            .await
            .values()
            .filter(|e| e.tenant_id == tenant_id)
            .map(|e| e.id.clone())
            .collect();
        let mut blobs = self.blobs.write().await;
        let mut mp4s = self.mp4_blobs.write().await;
        for id in &ids {
            blobs.remove(id);
            mp4s.remove(id);
        }
    }

    async fn encrypt_single_blob(
        &self,
        tenant_id: &str,
        rec_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let crypto = self.crypto.read().await.clone();
        let mut tenant_dek = crypto.tenant_keys.get_or_create_key(tenant_id).await?;
        let header_aad = session_header_aad(tenant_id, rec_id);
        let (key_ver, mut raw_dek, wrapped_dek) =
            crypto.provider.generate_data_key(&header_aad).await?;
        let mut effective_dek = derive_session_dek(&raw_dek, &tenant_dek);
        raw_dek.zeroize();
        tenant_dek.zeroize();

        let aad = chunk_aad(tenant_id, rec_id, 0);
        let ct = seal_aead(&effective_dek, &aad, plaintext);
        effective_dek.zeroize();
        let ct = ct?;

        let wrapped_len = u16::try_from(wrapped_dek.len())
            .map_err(|_| "wrapped DEK exceeds u16 length bound".to_owned())?;
        let ct_len = u32::try_from(ct.len())
            .map_err(|_| "ciphertext exceeds u32 length bound".to_owned())?;
        let mut out = Vec::with_capacity(14 + wrapped_dek.len() + ct.len());
        out.extend_from_slice(OQRK1_MAGIC);
        out.push(OQRK1_FLAG_TENANT_DEK);
        out.extend_from_slice(&key_ver.to_be_bytes());
        out.extend_from_slice(&wrapped_len.to_be_bytes());
        out.extend_from_slice(&wrapped_dek);
        out.extend_from_slice(&ct_len.to_be_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    async fn decrypt_blob(
        &self,
        tenant_id: &str,
        rec_id: &str,
        raw: &[u8],
    ) -> Result<Vec<u8>, String> {
        if raw.len() >= 10 && &raw[..5] == OQRK1_MAGIC {
            let flags = raw[5];
            let key_ver = u16::from_be_bytes([raw[6], raw[7]]);
            let wrapped_len = usize::from(u16::from_be_bytes([raw[8], raw[9]]));
            let header_end = 10 + wrapped_len;
            if raw.len() < header_end {
                return Err("truncated OQRK1 header".into());
            }
            let wrapped = &raw[10..header_end];
            let crypto = self.crypto.read().await.clone();
            let header_aad = session_header_aad(tenant_id, rec_id);
            let mut raw_dek = crypto
                .provider
                .decrypt_data_key(key_ver, &header_aad, wrapped)
                .await?;
            let mut effective_dek = if (flags & OQRK1_FLAG_TENANT_DEK) != 0 {
                let mut tdek = match crypto.tenant_keys.get_key_if_present(tenant_id).await {
                    Ok(Some(k)) => k,
                    Ok(None) => {
                        raw_dek.zeroize();
                        return Err(format!(
                            "tenant encryption key missing or shredded for '{tenant_id}'"
                        ));
                    }
                    Err(e) => {
                        raw_dek.zeroize();
                        return Err(e);
                    }
                };
                let derived = derive_session_dek(&raw_dek, &tdek);
                tdek.zeroize();
                derived
            } else {
                raw_dek
            };
            raw_dek.zeroize();

            let mut out = Vec::new();
            let mut pos = header_end;
            let mut seq = 0u64;
            while pos < raw.len() {
                if pos + 4 > raw.len() {
                    effective_dek.zeroize();
                    return Err("truncated OQRK1 chunk length".into());
                }
                let ct_len =
                    u32::from_be_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]])
                        as usize;
                pos += 4;
                if ct_len > MAX_OQRK1_CHUNK_BYTES || pos + ct_len > raw.len() {
                    effective_dek.zeroize();
                    return Err("truncated or oversized OQRK1 chunk payload".into());
                }
                let aad = chunk_aad(tenant_id, rec_id, seq);
                match open_aead(&effective_dek, &aad, &raw[pos..pos + ct_len]) {
                    Ok(plain) => out.extend_from_slice(&plain),
                    Err(e) => {
                        effective_dek.zeroize();
                        return Err(e);
                    }
                }
                pos += ct_len;
                seq += 1;
            }
            effective_dek.zeroize();
            return Ok(out);
        }

        // Backwards compatibility for pre-M10 unencrypted recordings on disk
        Ok(raw.to_vec())
    }
}

fn session_header_aad(tenant_id: &str, rec_id: &str) -> Vec<u8> {
    format!("OQRK1-HDR|{tenant_id}|{rec_id}").into_bytes()
}

fn chunk_aad(tenant_id: &str, rec_id: &str, chunk_seq: u64) -> Vec<u8> {
    format!("OQRK1|{tenant_id}|{rec_id}|{chunk_seq}").into_bytes()
}

fn derive_session_dek(base_dek: &[u8; 32], tenant_dek: &[u8; 32]) -> [u8; 32] {
    derive_key32(base_dek, tenant_dek)
}

#[must_use]
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[must_use]
pub fn strip_recording_extension(s: &str) -> &str {
    s.strip_suffix(".guac")
        .or_else(|| s.strip_suffix(".cast"))
        .or_else(|| s.strip_suffix(".mp4"))
        .unwrap_or(s)
}

#[must_use]
pub fn canonical_recording_filename(entry: &RecordingEntry) -> String {
    let ext = match entry.protocol.as_str() {
        "ssh" | "ssm" | "k8s" => "cast",
        _ => "guac",
    };
    let host_part: String = entry
        .target_host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if host_part.is_empty() {
        format!("{}.{ext}", entry.id)
    } else {
        format!("{host_part}-{}.{ext}", entry.id)
    }
}

#[must_use]
pub fn format_epoch_ms_iso8601(ms: u64) -> String {
    let total_secs = ms / 1000;
    let days_since_epoch = (total_secs / 86_400) as i64;
    let rem_secs = total_secs % 86_400;
    let hour = rem_secs / 3_600;
    let min = (rem_secs % 3_600) / 60;
    let sec = rem_secs % 60;
    // Howard Hinnant's civil-from-days algorithm (UTC)
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(m <= 2);
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn open_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)
}

fn write_private_bytes(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.flush()
}

/// Fail-closed synchronous chunk-encrypted frame tee (`RULES.md` §3.3 & `M10.2`).
/// Every Guacamole instruction or `DisplayOp` is AES-256-GCM sealed before hitting disk or RAM;
/// when `fail_closed == true`, any sink failure returns `OperquayError::RecordingRequired`.
pub struct RecordingTee {
    pub id: String,
    pub tenant_id: String,
    pub fail_closed: bool,
    enc_buffer: Vec<u8>,
    plaintext_len: usize,
    hasher: Sha256,
    frame_count: u64,
    chunk_seq: u64,
    dek: [u8; 32],
    pub simulated_fault: bool,
    live_file: Option<std::fs::File>,
}

impl Drop for RecordingTee {
    fn drop(&mut self) {
        self.dek.zeroize();
    }
}

impl RecordingTee {
    pub fn record_guac_line(&mut self, line: &str) -> Result<(), OperquayError> {
        if self.simulated_fault && self.fail_closed {
            return Err(OperquayError::RecordingRequired(
                "audit recording sink write failed while fail-closed enforcement is enabled".into(),
            ));
        }
        let bytes = line.as_bytes();
        let aad = chunk_aad(&self.tenant_id, &self.id, self.chunk_seq);
        let ct = seal_aead(&self.dek, &aad, bytes).map_err(|e| {
            OperquayError::RecordingRequired(format!("recording AEAD seal failed: {e}"))
        })?;
        let ct_len = u32::try_from(ct.len()).map_err(|_| {
            OperquayError::RecordingRequired("encrypted recording chunk exceeds u32".into())
        })?;
        let mut frame = Vec::with_capacity(4 + ct.len());
        frame.extend_from_slice(&ct_len.to_be_bytes());
        frame.extend_from_slice(&ct);

        if let Some(ref mut file) = self.live_file {
            use std::io::Write as _;
            if let Err(err) = file.write_all(&frame).and_then(|()| file.flush()) {
                if self.fail_closed {
                    return Err(OperquayError::RecordingRequired(format!(
                        "synchronous encrypted recording write failed while fail-closed: {err}"
                    )));
                }
            }
        }
        self.hasher.update(bytes);
        self.plaintext_len += bytes.len();
        self.chunk_seq += 1;
        self.enc_buffer.extend_from_slice(&frame);
        Ok(())
    }

    pub fn record_display_op(
        &mut self,
        op: &DisplayOp,
        stream_idx: u32,
    ) -> Result<(), OperquayError> {
        for inst in op.to_guac_instructions(0, stream_idx) {
            self.record_guac_line(&inst.encode())?;
        }
        self.frame_count += 1;
        Ok(())
    }

    pub fn record_cast_output(
        &mut self,
        elapsed_secs: f64,
        output: &str,
    ) -> Result<(), OperquayError> {
        let mut line = serde_json::json!([elapsed_secs, "o", output]).to_string();
        line.push('\n');
        self.record_guac_line(&line)?;
        self.frame_count += 1;
        Ok(())
    }

    /// Snapshot live plaintext bytes written during an active session (non-consuming).
    #[must_use]
    pub fn current_bytes_written(&self) -> usize {
        self.plaintext_len
    }
}

/// Format an Asciinema `.cast` v2 stream cleanly from raw terminal frames.
#[must_use]
pub fn encode_asciinema_cast(width: u16, height: u16, events: &[(f64, &str)]) -> String {
    let mut out = serde_json::json!({
        "version": 2,
        "width": width,
        "height": height,
        "title": "Operquay Audited SSH/K8s Session"
    })
    .to_string();
    out.push('\n');
    for &(ts, chunk) in events {
        let row = serde_json::json!([ts, "o", chunk]).to_string();
        out.push_str(&row);
        out.push('\n');
    }
    out
}

/// Export a `.guac` or `.cast` session stream into a genuine pure-Rust H.264 Baseline (`avc1`) MP4
/// container (`ftyp` + `moov`/`mdia`/`stbl`/`avc1` + `mdat`, zero external `ffmpeg` / `guacenc`).
#[must_use]
pub fn build_iso_bmff_mp4(payload: &[u8], _width: u32, _height: u32) -> Vec<u8> {
    if let Ok(text) = std::str::from_utf8(payload) {
        if text.trim_start().starts_with('{') && text.contains("\"version\":2") {
            return transcode_cast_to_mp4(text);
        }
    }
    transcode_guac_to_mp4(payload)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[allow(dead_code)]
fn _arc_guard(_: &Arc<RecordingCatalog>) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enforces_fail_closed_recording_and_exports_valid_mp4_boxes() {
        let catalog = RecordingCatalog::new();
        let mut tee = catalog
            .start_session(
                "rec-1".into(),
                "default".into(),
                "rdp".into(),
                "win2025".into(),
                true,
            )
            .await
            .unwrap();

        tee.record_guac_line("4.size,1.0,3.800,3.600;").unwrap();
        tee.simulated_fault = true;
        assert!(matches!(
            tee.record_guac_line("4.sync,2.10;"),
            Err(OperquayError::RecordingRequired(_))
        ));
        tee.simulated_fault = false;

        let entry = catalog.finalize(tee).await;
        assert_eq!(entry.status, "completed");
        assert!(entry.encrypted);
        assert_eq!(entry.sha256_hex.len(), 64);

        let enc = catalog.get_encrypted_bytes("rec-1").await.unwrap();
        assert!(enc.starts_with(OQRK1_MAGIC));

        let guac = catalog.get_guac_bytes("rec-1").await.unwrap();
        assert_eq!(guac, b"4.size,1.0,3.800,3.600;");
        let mp4 = build_iso_bmff_mp4(&guac, 800, 600);
        assert_eq!(&mp4[4..8], b"ftyp");
        assert!(mp4.windows(4).any(|w| w == b"moov"));
        assert!(mp4.windows(4).any(|w| w == b"avc1"));
        assert!(mp4.windows(4).any(|w| w == b"avcC"));
        assert!(mp4.windows(4).any(|w| w == b"mdat"));

        catalog.set_mp4_bytes("rec-1", mp4.clone()).await;
        assert!(catalog.has_mp4("rec-1").await);
        assert_eq!(catalog.get_mp4_bytes("rec-1").await.unwrap(), mp4);

        let cast = encode_asciinema_cast(40, 8, &[(0.1, "$ echo operquay\r\noperquay\r\n")]);
        let cast_mp4 = transcode_cast_to_mp4(&cast);
        assert_eq!(&cast_mp4[4..8], b"ftyp");
        assert!(cast_mp4.windows(4).any(|w| w == b"avc1"));
    }

    #[test]
    fn recording_policy_respects_mode_and_selected_instances() {
        let off = RecordingPolicy::default();
        assert!(!off.should_record_instance("rdp", "i-123", "dev"));
        assert!(!off.should_record_instance("ssh", "i-123", "dev"));

        let all = RecordingPolicy {
            mode: "all".into(),
            ..RecordingPolicy::default()
        };
        assert!(all.should_record_instance("rdp", "i-123", "dev"));
        assert!(all.should_record_instance("ssh", "i-123", "dev"));

        let selected = RecordingPolicy {
            mode: "selected".into(),
            instances: vec!["i-allowed".into()],
            ..RecordingPolicy::default()
        };
        assert!(selected.should_record_instance("rdp", "i-allowed", "dev"));
        assert!(!selected.should_record_instance("rdp", "i-other", "dev"));
    }

    #[tokio::test]
    async fn synchronous_cast_recording_encrypts_at_rest_0600_and_enforces_containment() {
        let unique = format!("operquay-rec-test-{}-{}", std::process::id(), now_unix_ms());
        let dir = std::env::temp_dir().join(&unique);
        let catalog = RecordingCatalog::with_dir(dir.clone()).unwrap();

        // Canonical path containment blocks traversal and symlinks
        assert!(safe_recording_path(catalog.storage_dir().unwrap(), "../escape.cast").is_err());
        assert!(safe_recording_path(catalog.storage_dir().unwrap(), "sub/dir.cast").is_err());
        #[cfg(unix)]
        {
            let link_path = catalog.storage_dir().unwrap().join("evil-link.cast");
            let _ = std::os::unix::fs::symlink("/etc/passwd", &link_path);
            assert!(safe_recording_path(catalog.storage_dir().unwrap(), "evil-link.cast").is_err());
            let _ = std::fs::remove_file(&link_path);
        }

        let mut tee = catalog
            .start_cast_session(
                "cast-sync-1".into(),
                "default".into(),
                "ssh".into(),
                "i-0abc".into(),
                true,
                80,
                24,
            )
            .await
            .unwrap();
        tee.record_cast_output(0.1, "hello-secret-token\r\n")
            .unwrap();

        let cast_path = dir.join("cast-sync-1.cast");
        let raw_on_disk = std::fs::read(&cast_path).unwrap();
        assert!(
            raw_on_disk.starts_with(OQRK1_MAGIC),
            "disk file must use OQRK1 AEAD encryption at rest"
        );
        assert!(
            !raw_on_disk
                .windows("hello-secret-token".len())
                .any(|w| w == b"hello-secret-token"),
            "plaintext must never be stored unencrypted on disk"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&cast_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let _ = catalog.finalize(tee).await;
        let decrypted = String::from_utf8(catalog.get_guac_bytes("cast-sync-1").await.unwrap())
            .expect("UTF-8 cast output");
        assert!(decrypted.contains("\"version\":2"));
        assert!(decrypted.contains("hello-secret-token\\r\\n"));

        // Re-hydrate from disk with same cluster master key & tenant keys -> still decrypts cleanly
        let catalog_reloaded = RecordingCatalog::with_dir(dir.clone()).unwrap();
        let master = b"cluster-test-master-secret";
        let tk = catalog.crypto.read().await.tenant_keys.clone();
        catalog.attach_cluster_crypto(master, tk.clone()).await;
        let mut tee2 = catalog
            .start_cast_session(
                "cast-sync-2".into(),
                "acme".into(),
                "ssh".into(),
                "i-0def".into(),
                true,
                80,
                24,
            )
            .await
            .unwrap();
        tee2.record_cast_output(0.2, "persisted-across-restart\r\n")
            .unwrap();
        let _ = catalog.finalize(tee2).await;
        drop(catalog_reloaded);

        let catalog_restarted = RecordingCatalog::with_dir(dir.clone()).unwrap();
        catalog_restarted
            .attach_cluster_crypto(master, tk.clone())
            .await;
        let dec2 = String::from_utf8(
            catalog_restarted
                .get_guac_bytes("cast-sync-2")
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(dec2.contains("persisted-across-restart\\r\\n"));

        // Crypto-shredding tenant "acme" renders cast-sync-2 permanently unrecoverable
        assert!(tk.shred_tenant("acme").await);
        catalog_restarted.evict_tenant_cache("acme").await;
        assert!(catalog_restarted
            .get_guac_bytes("cast-sync-2")
            .await
            .is_none());

        // Missing directory fails closed
        let missing_dir = RecordingCatalog {
            entries: RwLock::new(HashMap::new()),
            blobs: RwLock::new(HashMap::new()),
            mp4_blobs: RwLock::new(HashMap::new()),
            storage_dir: Some(dir.join("nonexistent-subdir")),
            crypto: RwLock::new(CryptoState::default()),
        };
        let err = missing_dir
            .start_cast_session(
                "cast-fail-1".into(),
                "default".into(),
                "ssh".into(),
                "i-0abc".into(),
                true,
                80,
                24,
            )
            .await;
        assert!(matches!(err, Err(OperquayError::RecordingRequired(_))));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn legal_hold_blocks_delete_and_retention_purge_spares_held_recordings() {
        let catalog = RecordingCatalog::new();
        for id in ["old-free", "old-held", "fresh-free"] {
            let mut tee = catalog
                .start_session(
                    id.to_owned(),
                    "acme".into(),
                    "ssh".into(),
                    "host".into(),
                    false,
                )
                .await
                .unwrap();
            tee.record_guac_line("{\"version\":2,\"width\":80,\"height\":24}\n")
                .unwrap();
            let _ = catalog.finalize(tee).await;
        }
        // Backdate old-free and old-held by 100 days
        let now = now_unix_ms();
        let old_ts = now.saturating_sub(100 * 86_400_000);
        {
            let mut guard = catalog.entries.write().await;
            guard.get_mut("old-free").unwrap().started_at_ms = old_ts;
            guard.get_mut("old-held").unwrap().started_at_ms = old_ts;
        }

        let held = catalog
            .set_legal_hold("acme", "old-held", true, "Incident-2026-42")
            .await
            .unwrap();
        assert!(held.legal_hold);
        assert!(catalog.delete_recording_checked("old-held").await.is_err());

        let report = catalog.purge_expired("acme", 90, now).await;
        assert_eq!(report.purged_ids, vec!["old-free".to_owned()]);
        assert_eq!(report.skipped_legal_hold, 1);
        assert!(catalog.get_entry("old-free").await.is_none());
        assert!(catalog.get_entry("old-held").await.is_some());
        assert!(catalog.get_entry("fresh-free").await.is_some());
    }
}
