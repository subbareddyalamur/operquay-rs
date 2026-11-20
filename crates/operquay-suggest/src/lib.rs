#![forbid(unsafe_code)]

//! Shell Command Suggest Engine (`operquay-suggest`):
//! Radix Prefix Trie + Exponential Decay Frecency + 47-param Micro-MLP Ranker +
//! Error Knowledge Base + `AES-256-GCM` Encrypted Buckets (`db-viewer`).

pub mod errorkb;
pub mod mlp;
pub mod trie;

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use errorkb::{ErrorKb, LogInsight};
use mlp::{MlpFeatures, MlpRanker};
use operquay_auth::crypto::{derive_key32, open_aead, random_token_b64, seal_aead};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use trie::{CommandTrie, Suggestion};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrecencyEntry {
    pub command: String,
    pub count: u64,
    pub last_used_unix: i64,
    pub last_dir: String,
    pub last_exit_code: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestStatus {
    pub enabled: bool,
    pub indexed_commands: usize,
    pub frecency_entries: usize,
    pub bucket_count: usize,
}

struct SuggestInner {
    trie: CommandTrie,
    frecency: HashMap<String, FrecencyEntry>,
    mlp: MlpRanker,
    errorkb: ErrorKb,
    enabled_sessions: HashMap<String, bool>,
    encrypted_buckets: HashMap<String, HashMap<String, Vec<u8>>>,
    enc_key: [u8; 32],
}

pub struct SuggestEngine {
    inner: RwLock<SuggestInner>,
}

impl Default for SuggestEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SuggestEngine {
    #[must_use]
    pub fn new() -> Self {
        let mut trie = CommandTrie::new();
        for cmd in [
            "systemctl status",
            "journalctl -xeu",
            "docker ps -a",
            "kubectl get pods -A",
            "df -h",
            "ss -tlnp",
            "tail -f /var/log/syslog",
        ] {
            trie.insert(cmd, 0.5);
        }
        let secret = random_token_b64();
        let enc_key = derive_key32(secret.as_bytes(), b"operquay-suggest-buckets-v1");
        Self {
            inner: RwLock::new(SuggestInner {
                trie,
                frecency: HashMap::new(),
                mlp: MlpRanker::new(),
                errorkb: ErrorKb::new(),
                enabled_sessions: HashMap::new(),
                encrypted_buckets: HashMap::new(),
                enc_key,
            }),
        }
    }

    pub async fn set_session_enabled(&self, session_id: &str, enabled: bool) {
        self.inner
            .write()
            .await
            .enabled_sessions
            .insert(session_id.to_owned(), enabled);
    }

    pub async fn learn_command(&self, tenant_id: &str, command: &str, exit_code: i32, dir: &str) {
        let cmd = command.trim();
        if cmd.is_empty() {
            return;
        }
        let now = now_unix();
        let mut guard = self.inner.write().await;
        let entry = guard
            .frecency
            .entry(cmd.to_owned())
            .or_insert(FrecencyEntry {
                command: cmd.to_owned(),
                count: 0,
                last_used_unix: now,
                last_dir: dir.to_owned(),
                last_exit_code: exit_code,
            });
        entry.count += 1;
        entry.last_used_unix = now;
        dir.clone_into(&mut entry.last_dir);
        entry.last_exit_code = exit_code;
        let count_f = u32::try_from(entry.count).map_or(100.0, f64::from);

        let mlp_score = guard.mlp.forward(MlpFeatures {
            age: 0.0,
            length: (cmd.len() as f64 / 80.0).min(1.0),
            exit_code: if exit_code == 0 { 0.0 } else { 1.0 },
            frequency: (count_f / 20.0).min(1.0),
            dir_match: 1.0,
            context_overlap: 0.5,
            selected_count: 0.5,
            env_match: 1.0,
            recent_failure: 0.0,
            occurrences: (count_f / 20.0).min(1.0),
        });
        guard.trie.insert(cmd, count_f * mlp_score);

        // Encrypt & store in tenant bucket
        let bucket = format!("{tenant_id}:history");
        if let Ok(json_bytes) = serde_json::to_vec(&cmd) {
            if let Ok(sealed) = seal_aead(&guard.enc_key, bucket.as_bytes(), &json_bytes) {
                guard
                    .encrypted_buckets
                    .entry(bucket)
                    .or_default()
                    .insert(cmd.to_owned(), sealed);
            }
        }
    }

    pub async fn suggest(&self, prefix: &str, dir: &str, limit: usize) -> Vec<Suggestion> {
        let now = now_unix();
        let guard = self.inner.read().await;
        let mut candidates = guard.trie.search(prefix, limit * 3);
        for item in &mut candidates {
            if let Some(frec) = guard.frecency.get(&item.text) {
                let age_hours = ((now - frec.last_used_unix).max(0) as f64) / 3600.0;
                let decay = 0.5_f64.powf(age_hours / 24.0);
                let dir_boost = if !dir.is_empty() && frec.last_dir == dir {
                    1.25
                } else {
                    1.0
                };
                item.score = (frec.count as f64) * decay * dir_boost + item.score * 0.1;
                "frecency+mlp".clone_into(&mut item.source);
            }
        }
        candidates.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        if limit > 0 && candidates.len() > limit {
            candidates.truncate(limit);
        }
        candidates
    }

    pub async fn analyze_output(&self, raw_output: &str) -> Vec<LogInsight> {
        self.inner.read().await.errorkb.detect_errors(raw_output)
    }

    pub async fn status(&self) -> SuggestStatus {
        let guard = self.inner.read().await;
        SuggestStatus {
            enabled: true,
            indexed_commands: guard.trie.len(),
            frecency_entries: guard.frecency.len(),
            bucket_count: guard.encrypted_buckets.len(),
        }
    }

    /// Decrypt & inspect stored buckets for admin `/db-viewer`.
    pub async fn browse_buckets(&self) -> HashMap<String, HashMap<String, String>> {
        let guard = self.inner.read().await;
        let mut out = HashMap::new();
        for (bucket, entries) in &guard.encrypted_buckets {
            let mut decoded = HashMap::new();
            for (k, ct) in entries {
                let val = open_aead(&guard.enc_key, bucket.as_bytes(), ct).map_or_else(
                    |_| "<encrypted>".to_owned(),
                    |pt| String::from_utf8_lossy(&pt).into_owned(),
                );
                decoded.insert(k.clone(), val);
            }
            out.insert(bucket.clone(), decoded);
        }
        out
    }

    pub async fn put_bucket_key(&self, bucket: &str, key: &str, value: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let sealed = seal_aead(&guard.enc_key, bucket.as_bytes(), value.as_bytes())?;
        guard
            .encrypted_buckets
            .entry(bucket.to_owned())
            .or_default()
            .insert(key.to_owned(), sealed);
        Ok(())
    }

    pub async fn delete_bucket(&self, bucket: &str) -> bool {
        self.inner
            .write()
            .await
            .encrypted_buckets
            .remove(bucket)
            .is_some()
    }

    pub async fn delete_bucket_key(&self, bucket: &str, key: &str) -> bool {
        let mut guard = self.inner.write().await;
        guard
            .encrypted_buckets
            .get_mut(bucket)
            .is_some_and(|m| m.remove(key).is_some())
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
    async fn learns_ranks_commands_with_trie_mlp_aead_buckets_and_errorkb() {
        let eng = SuggestEngine::new();
        eng.learn_command("acme", "kubectl get pods -n prod", 0, "/srv/app")
            .await;
        eng.learn_command("acme", "kubectl get pods -n prod", 0, "/srv/app")
            .await;
        eng.learn_command("acme", "kubectl describe node n1", 0, "/srv/app")
            .await;

        let sugs = eng.suggest("kubectl", "/srv/app", 5).await;
        assert!(!sugs.is_empty());
        assert_eq!(sugs[0].text, "kubectl get pods -n prod");

        let buckets = eng.browse_buckets().await;
        assert!(buckets.contains_key("acme:history"));

        let insights = eng
            .analyze_output("\x1b[31mError:\x1b[0m permission denied reading /etc/shadow")
            .await;
        assert_eq!(insights.len(), 1);
        assert_eq!(insights[0].description, "Permission denied");

        let mut mlp = MlpRanker::new();
        let before = mlp.forward(MlpFeatures::default());
        mlp.train(
            &[mlp::TrainingSample {
                features: MlpFeatures::default(),
                target: 1.0,
            }],
            0.1,
            5,
        );
        let after = mlp.forward(MlpFeatures::default());
        assert!(after >= before);
    }
}
