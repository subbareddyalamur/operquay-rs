#![forbid(unsafe_code)]

//! Live session fencing (`M9.9`) for sub-second revocation of active WebSocket
//! streams (`SSM` terminals, `RDP`/`VNC` desktops, and `Kubernetes` shells) upon logout,
//! password change, user deactivation, `SCIM` deprovisioning, or AWS role disconnect.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;
use uuid::Uuid;

struct FencedSession {
    tenant_id: String,
    user_id: String,
    auth_session_id: String,
    aws_role_binding_id: Option<String>,
    session_id: String,
    jit_request_id: Option<String>,
    tx: watch::Sender<Option<String>>,
}

/// Registry of active live proxy/terminal sessions supporting instant watch-channel termination.
#[derive(Default)]
pub struct ActiveSessionFence {
    sessions: Mutex<HashMap<String, FencedSession>>,
}

/// RAII handle keeping an active session registered until dropped or revoked.
pub struct FenceGuard {
    fence: Arc<ActiveSessionFence>,
    entry_id: String,
    rx: watch::Receiver<Option<String>>,
}

impl FenceGuard {
    /// Resolves with the revocation reason as soon as this session is fenced/terminated.
    pub async fn revoked(&mut self) -> String {
        loop {
            if let Some(reason) = self.rx.borrow().clone() {
                return reason;
            }
            if self.rx.changed().await.is_err() {
                return "session fence closed".to_owned();
            }
        }
    }
}

impl Drop for FenceGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.fence.sessions.lock() {
            guard.remove(&self.entry_id);
        }
    }
}

impl ActiveSessionFence {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a live session under tenant/user/auth-session and optional AWS role binding.
    #[must_use]
    pub fn register(
        self: &Arc<Self>,
        tenant_id: &str,
        user_id: &str,
        auth_session_id: &str,
        aws_role_binding_id: Option<&str>,
    ) -> FenceGuard {
        let entry_id = Uuid::new_v4().to_string();
        self.register_internal(
            entry_id.clone(),
            tenant_id,
            user_id,
            auth_session_id,
            aws_role_binding_id,
            entry_id,
            None,
        )
    }

    /// Register a live session with explicit `session_id` and optional `jit_request_id` (`M11.1`/`M11.2`).
    #[must_use]
    pub fn register_with_session(
        self: &Arc<Self>,
        tenant_id: &str,
        user_id: &str,
        auth_session_id: &str,
        aws_role_binding_id: Option<&str>,
        session_id: &str,
        jit_request_id: Option<&str>,
    ) -> FenceGuard {
        let entry_id = Uuid::new_v4().to_string();
        let sid = if session_id.trim().is_empty() {
            entry_id.clone()
        } else {
            session_id.trim().to_owned()
        };
        self.register_internal(
            entry_id,
            tenant_id,
            user_id,
            auth_session_id,
            aws_role_binding_id,
            sid,
            jit_request_id,
        )
    }

    fn register_internal(
        self: &Arc<Self>,
        entry_id: String,
        tenant_id: &str,
        user_id: &str,
        auth_session_id: &str,
        aws_role_binding_id: Option<&str>,
        session_id: String,
        jit_request_id: Option<&str>,
    ) -> FenceGuard {
        let (tx, rx) = watch::channel(None);
        if let Ok(mut guard) = self.sessions.lock() {
            guard.insert(
                entry_id.clone(),
                FencedSession {
                    tenant_id: tenant_id.to_owned(),
                    user_id: user_id.to_owned(),
                    auth_session_id: auth_session_id.to_owned(),
                    aws_role_binding_id: aws_role_binding_id
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned),
                    session_id,
                    jit_request_id: jit_request_id
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned),
                    tx,
                },
            );
        }
        FenceGuard {
            fence: Arc::clone(self),
            entry_id,
            rx,
        }
    }

    /// Instantly terminate all active sessions belonging to `(tenant_id, user_id)`.
    pub fn terminate_user(&self, tenant_id: &str, user_id: &str, reason: &str) -> usize {
        self.terminate_matching(reason, |s| s.tenant_id == tenant_id && s.user_id == user_id)
    }

    /// Instantly terminate all active sessions tied to a specific auth cookie `auth_session_id`.
    pub fn terminate_auth_session(
        &self,
        tenant_id: &str,
        auth_session_id: &str,
        reason: &str,
    ) -> usize {
        if auth_session_id.trim().is_empty() {
            return 0;
        }
        self.terminate_matching(reason, |s| {
            s.tenant_id == tenant_id && s.auth_session_id == auth_session_id
        })
    }

    /// Instantly terminate active AWS-role-backed sessions for `(tenant_id, user_id)`.
    pub fn terminate_aws_role(
        &self,
        tenant_id: &str,
        user_id: &str,
        binding_id: Option<&str>,
        reason: &str,
    ) -> usize {
        let target = binding_id.map(str::trim).filter(|s| !s.is_empty());
        self.terminate_matching(reason, |s| {
            if s.tenant_id != tenant_id || s.user_id != user_id {
                return false;
            }
            match (target, s.aws_role_binding_id.as_deref()) {
                (Some(expected), Some(actual)) => actual == expected || actual == "aws-ssm",
                (None, Some(_)) => true,
                _ => false,
            }
        })
    }

    /// Instantly terminate all active sessions belonging to `tenant_id`.
    pub fn terminate_tenant(&self, tenant_id: &str, reason: &str) -> usize {
        self.terminate_matching(reason, |s| s.tenant_id == tenant_id)
    }

    /// Instantly terminate active sessions matching `(tenant_id, session_id)` (`M11.2`).
    pub fn terminate_session(&self, tenant_id: &str, session_id: &str, reason: &str) -> usize {
        if session_id.trim().is_empty() {
            return 0;
        }
        self.terminate_matching(reason, |s| {
            s.tenant_id == tenant_id && s.session_id == session_id
        })
    }

    /// Instantly terminate active sessions backed by a specific JIT grant (`M11.1`).
    pub fn terminate_jit_grant(
        &self,
        tenant_id: &str,
        jit_request_id: &str,
        reason: &str,
    ) -> usize {
        if jit_request_id.trim().is_empty() {
            return 0;
        }
        self.terminate_matching(reason, |s| {
            s.tenant_id == tenant_id && s.jit_request_id.as_deref() == Some(jit_request_id)
        })
    }

    /// Instantly terminate every active session across all tenants (graceful shutdown drain).
    pub fn terminate_all(&self, reason: &str) -> usize {
        self.terminate_matching(reason, |_| true)
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.sessions.lock().map_or(0, |guard| guard.len())
    }

    fn terminate_matching<F>(&self, reason: &str, predicate: F) -> usize
    where
        F: Fn(&FencedSession) -> bool,
    {
        let senders: Vec<watch::Sender<Option<String>>> = match self.sessions.lock() {
            Ok(guard) => guard
                .values()
                .filter(|s| predicate(s))
                .map(|s| s.tx.clone())
                .collect(),
            Err(_) => Vec::new(),
        };
        let count = senders.len();
        for tx in senders {
            let _ = tx.send(Some(reason.to_owned()));
        }
        count
    }
}
