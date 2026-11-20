#![forbid(unsafe_code)]

//! Dual-Control Live Session Moderation, Bounded Live Shadowing & Freeze/Kill Controls (`M11.2`).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};

use crate::jit::now_unix_secs;
use crate::session_fence::ActiveSessionFence;

const MODERATION_BROADCAST_CAPACITY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationRole {
    #[default]
    Observer,
    Moderator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LiveSessionEvent {
    Snapshot {
        session: LiveSessionInfo,
    },
    Output {
        data: String,
    },
    Notice {
        level: String,
        message: String,
    },
    FrozenState {
        frozen: bool,
        actor: String,
        reason: String,
    },
    Terminated {
        actor: String,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveSessionInfo {
    pub session_id: String,
    pub tenant_id: String,
    pub protocol: String,
    pub target_host: String,
    pub owner_user_id: String,
    pub owner_email: String,
    pub started_at: i64,
    pub recording_id: Option<String>,
    pub frozen: bool,
    pub frozen_by: Option<String>,
    pub frozen_reason: String,
    pub observer_count: usize,
    pub moderator_count: usize,
}

struct LiveSessionEntry {
    info: LiveSessionInfo,
    recent_output: String,
    events_tx: broadcast::Sender<LiveSessionEvent>,
    freeze_tx: watch::Sender<bool>,
}

/// Thread-safe registry of live interactive sessions supporting read-only observers and
/// dual-control moderator freeze/kill actions.
#[derive(Default)]
pub struct SessionModerationHub {
    sessions: RwLock<HashMap<(String, String), LiveSessionEntry>>,
}

pub struct LiveSessionHandle {
    hub: Arc<SessionModerationHub>,
    tenant_id: String,
    session_id: String,
    freeze_rx: watch::Receiver<bool>,
    events_tx: broadcast::Sender<LiveSessionEvent>,
}

impl LiveSessionHandle {
    pub fn publish_output(&self, text: &str) {
        if text.is_empty() {
            return;
        }
        if let Ok(mut guard) = self.hub.sessions.write() {
            if let Some(entry) = guard.get_mut(&(self.tenant_id.clone(), self.session_id.clone())) {
                entry.recent_output.push_str(text);
                if entry.recent_output.len() > 16_384 {
                    let excess = entry.recent_output.len() - 16_384;
                    let drain_idx = entry
                        .recent_output
                        .char_indices()
                        .find(|(idx, _)| *idx >= excess)
                        .map_or(entry.recent_output.len(), |(idx, _)| idx);
                    entry.recent_output.drain(..drain_idx);
                }
            }
        }
        let _ = self.events_tx.send(LiveSessionEvent::Output {
            data: text.to_owned(),
        });
    }

    pub fn publish_notice(&self, level: &str, message: &str) {
        let _ = self.events_tx.send(LiveSessionEvent::Notice {
            level: level.to_owned(),
            message: message.to_owned(),
        });
    }

    #[must_use]
    pub fn is_frozen(&self) -> bool {
        *self.freeze_rx.borrow()
    }

    #[must_use]
    pub fn freeze_reason(&self) -> String {
        self.hub
            .sessions
            .read()
            .ok()
            .and_then(|g| {
                g.get(&(self.tenant_id.clone(), self.session_id.clone()))
                    .map(|e| e.info.frozen_reason.clone())
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "frozen by moderator".to_owned())
    }
}

impl Drop for LiveSessionHandle {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.hub.sessions.write() {
            guard.remove(&(self.tenant_id.clone(), self.session_id.clone()));
        }
    }
}

pub struct ShadowSubscription {
    pub snapshot: LiveSessionInfo,
    pub backlog: String,
    pub rx: broadcast::Receiver<LiveSessionEvent>,
    hub: Arc<SessionModerationHub>,
    tenant_id: String,
    session_id: String,
    role: ModerationRole,
}

impl Drop for ShadowSubscription {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.hub.sessions.write() {
            if let Some(entry) = guard.get_mut(&(self.tenant_id.clone(), self.session_id.clone())) {
                match self.role {
                    ModerationRole::Observer => {
                        entry.info.observer_count = entry.info.observer_count.saturating_sub(1);
                    }
                    ModerationRole::Moderator => {
                        entry.info.moderator_count = entry.info.moderator_count.saturating_sub(1);
                    }
                }
            }
        }
    }
}

impl SessionModerationHub {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn register_session(
        self: &Arc<Self>,
        tenant_id: &str,
        session_id: &str,
        protocol: &str,
        target_host: &str,
        owner_user_id: &str,
        owner_email: &str,
        recording_id: Option<String>,
    ) -> LiveSessionHandle {
        let (events_tx, _) = broadcast::channel(MODERATION_BROADCAST_CAPACITY);
        let (freeze_tx, freeze_rx) = watch::channel(false);
        let info = LiveSessionInfo {
            session_id: session_id.to_owned(),
            tenant_id: tenant_id.to_owned(),
            protocol: protocol.to_owned(),
            target_host: target_host.to_owned(),
            owner_user_id: owner_user_id.to_owned(),
            owner_email: owner_email.to_owned(),
            started_at: now_unix_secs(),
            recording_id,
            frozen: false,
            frozen_by: None,
            frozen_reason: String::new(),
            observer_count: 0,
            moderator_count: 0,
        };
        if let Ok(mut guard) = self.sessions.write() {
            guard.insert(
                (tenant_id.to_owned(), session_id.to_owned()),
                LiveSessionEntry {
                    info,
                    recent_output: String::new(),
                    events_tx: events_tx.clone(),
                    freeze_tx,
                },
            );
        }
        LiveSessionHandle {
            hub: Arc::clone(self),
            tenant_id: tenant_id.to_owned(),
            session_id: session_id.to_owned(),
            freeze_rx,
            events_tx,
        }
    }

    #[must_use]
    pub fn list_sessions(&self, tenant_id: &str) -> Vec<LiveSessionInfo> {
        let mut items: Vec<_> = self.sessions.read().ok().map_or_default(|guard| {
            guard
                .values()
                .filter(|e| e.info.tenant_id == tenant_id)
                .map(|e| e.info.clone())
                .collect()
        });
        items.sort_by_key(|s| std::cmp::Reverse(s.started_at));
        items
    }

    pub fn subscribe(
        self: &Arc<Self>,
        tenant_id: &str,
        session_id: &str,
        role: ModerationRole,
    ) -> Option<ShadowSubscription> {
        let mut guard = self.sessions.write().ok()?;
        let entry = guard.get_mut(&(tenant_id.to_owned(), session_id.to_owned()))?;
        match role {
            ModerationRole::Observer => entry.info.observer_count += 1,
            ModerationRole::Moderator => entry.info.moderator_count += 1,
        }
        Some(ShadowSubscription {
            snapshot: entry.info.clone(),
            backlog: entry.recent_output.clone(),
            rx: entry.events_tx.subscribe(),
            hub: Arc::clone(self),
            tenant_id: tenant_id.to_owned(),
            session_id: session_id.to_owned(),
            role,
        })
    }

    pub fn set_frozen(
        &self,
        tenant_id: &str,
        session_id: &str,
        frozen: bool,
        actor: &str,
        reason: &str,
    ) -> Result<LiveSessionInfo, String> {
        let mut guard = self
            .sessions
            .write()
            .map_err(|_| "moderation registry poisoned".to_owned())?;
        let entry = guard
            .get_mut(&(tenant_id.to_owned(), session_id.to_owned()))
            .ok_or_else(|| "live session not found".to_owned())?;
        entry.info.frozen = frozen;
        entry.info.frozen_by = frozen.then(|| actor.to_owned());
        entry.info.frozen_reason = if frozen {
            if reason.trim().is_empty() {
                "frozen by security moderator".to_owned()
            } else {
                reason.trim().to_owned()
            }
        } else {
            String::new()
        };
        let _ = entry.freeze_tx.send(frozen);
        let _ = entry.events_tx.send(LiveSessionEvent::FrozenState {
            frozen,
            actor: actor.to_owned(),
            reason: entry.info.frozen_reason.clone(),
        });
        Ok(entry.info.clone())
    }

    pub fn kill_session(
        &self,
        fence: &ActiveSessionFence,
        tenant_id: &str,
        session_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<usize, String> {
        let clean_reason = if reason.trim().is_empty() {
            "terminated_by_moderator"
        } else {
            reason.trim()
        };
        let exists = if let Ok(guard) = self.sessions.read() {
            if let Some(entry) = guard.get(&(tenant_id.to_owned(), session_id.to_owned())) {
                let _ = entry.events_tx.send(LiveSessionEvent::Terminated {
                    actor: actor.to_owned(),
                    reason: clean_reason.to_owned(),
                });
                true
            } else {
                false
            }
        } else {
            false
        };
        let killed = fence.terminate_session(tenant_id, session_id, clean_reason);
        if !exists && killed == 0 {
            return Err("live session not found".to_owned());
        }
        Ok(killed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn moderation_streams_output_freezes_and_kills_live_session() {
        let hub = Arc::new(SessionModerationHub::new());
        let fence = Arc::new(ActiveSessionFence::new());
        let mut fg =
            fence.register_with_session("acme", "u-alice", "auth-1", None, "sess-live-1", None);
        let handle = hub.register_session(
            "acme",
            "sess-live-1",
            "ssh",
            "i-0123",
            "u-alice",
            "alice@acme.test",
            Some("rec-1".into()),
        );

        let mut sub = hub
            .subscribe("acme", "sess-live-1", ModerationRole::Moderator)
            .unwrap();
        assert_eq!(sub.snapshot.moderator_count, 1);

        handle.publish_output("whoami\r\nroot\r\n");
        let ev = sub.rx.recv().await.unwrap();
        assert!(matches!(ev, LiveSessionEvent::Output { data } if data.contains("root")));

        assert!(!handle.is_frozen());
        let frozen_info = hub
            .set_frozen(
                "acme",
                "sess-live-1",
                true,
                "secops@acme.test",
                "audit hold",
            )
            .unwrap();
        assert!(frozen_info.frozen);
        assert!(handle.is_frozen());
        assert_eq!(handle.freeze_reason(), "audit hold");

        let killed = hub
            .kill_session(
                &fence,
                "acme",
                "sess-live-1",
                "secops@acme.test",
                "emergency_stop",
            )
            .unwrap();
        assert_eq!(killed, 1);
        let reason = fg.revoked().await;
        assert_eq!(reason, "emergency_stop");
    }
}
