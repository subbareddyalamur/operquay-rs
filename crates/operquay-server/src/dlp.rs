#![forbid(unsafe_code)]

//! Inline Terminal & Kubernetes Command Firewall + Tenant DLP Policy (`M11.3`).
//!
//! Evaluates command lines against ReDoS-bounded regex rules before execution newlines reach
//! target hosts (`Block`, `PauseApproval`, `Warn`, `Allow`) and pairs with `operquay_db::dlp`
//! for result-set PII/secret masking.

use std::sync::OnceLock;

use operquay_db::dlp::DbDlpPolicy;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

const MAX_COMMAND_BUFFER_BYTES: usize = 4096;
const MAX_REGEX_SIZE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandFirewallAction {
    #[default]
    Allow,
    Warn,
    PauseApproval,
    Block,
}

impl CommandFirewallAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::PauseApproval => "pause_approval",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandFirewallRule {
    pub id: String,
    pub name: String,
    pub pattern: String,
    #[serde(default = "default_protocols")]
    pub protocols: Vec<String>,
    pub action: CommandFirewallAction,
    #[serde(default)]
    pub message: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_protocols() -> Vec<String> {
    vec![
        "ssh".to_owned(),
        "ssm".to_owned(),
        "k8s".to_owned(),
        "db".to_owned(),
    ]
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpFirewallPolicy {
    #[serde(default)]
    pub db_dlp: DbDlpPolicy,
    #[serde(default = "default_true")]
    pub command_firewall_enabled: bool,
    #[serde(default)]
    pub require_jit_for_db_write: bool,
    #[serde(default)]
    pub require_jit_for_prod_shell: bool,
    #[serde(default = "default_command_rules")]
    pub rules: Vec<CommandFirewallRule>,
}

impl Default for DlpFirewallPolicy {
    fn default() -> Self {
        Self {
            db_dlp: DbDlpPolicy::default(),
            command_firewall_enabled: true,
            require_jit_for_db_write: false,
            require_jit_for_prod_shell: false,
            rules: default_command_rules(),
        }
    }
}

#[must_use]
pub fn default_command_rules() -> Vec<CommandFirewallRule> {
    vec![
        CommandFirewallRule {
            id: "block-destructive-fs".to_owned(),
            name: "Block Destructive Filesystem Wipe".to_owned(),
            pattern: r"(?i)\b(rm\s+(-[a-z]*[rf][a-z]*\s+)*(/|/\*|/etc\b|/usr\b|/var\b|/boot\b)|rm\s+-rf\b|mkfs(\.[a-z0-9]+)?\b|dd\s+.*of=/dev/|:\(\)\{\s*:\|:&\s*\};:|chmod\s+-R\s+777\b)".to_owned(),
            protocols: vec!["ssh".into(), "ssm".into(), "k8s".into()],
            action: CommandFirewallAction::Block,
            message: "Blocked destructive filesystem/system command under compliance firewall.".to_owned(),
            enabled: true,
        },
        CommandFirewallRule {
            id: "block-destructive-db".to_owned(),
            name: "Block Drop Database / Truncate Table".to_owned(),
            pattern: r"(?i)\b(drop\s+(database|schema)\b|truncate\s+table\b)".to_owned(),
            protocols: vec!["ssh".into(), "ssm".into(), "k8s".into(), "db".into()],
            action: CommandFirewallAction::Block,
            message: "Blocked DROP DATABASE / TRUNCATE TABLE statement under compliance firewall.".to_owned(),
            enabled: true,
        },
        CommandFirewallRule {
            id: "pause-infra-destroy".to_owned(),
            name: "Require JIT Approval for Infra/Prod Destruction".to_owned(),
            pattern: r"(?i)\b(terraform\s+destroy\b|kubectl\s+delete\s+(ns|namespace|deployment|statefulset)\b|aws\s+(iam|rds|ec2)\s+delete-|shutdown\b|reboot\b)".to_owned(),
            protocols: vec!["ssh".into(), "ssm".into(), "k8s".into()],
            action: CommandFirewallAction::PauseApproval,
            message: "Command paused: peer-approved JIT authorization required before executing destructive infrastructure change.".to_owned(),
            enabled: true,
        },
        CommandFirewallRule {
            id: "warn-priv-secret-inspect".to_owned(),
            name: "Audit Sensitive File / Privilege Inspection".to_owned(),
            pattern: r"(?i)\b(sudo\s+|/etc/shadow\b|/etc/sudoers\b|kubectl\s+get\s+secret|curl\s+[^|]+\|\s*(ba)?sh)".to_owned(),
            protocols: vec!["ssh".into(), "ssm".into(), "k8s".into()],
            action: CommandFirewallAction::Warn,
            message: "Sensitive privilege or secret access logged to immutable audit trail.".to_owned(),
            enabled: true,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandFirewallVerdict {
    pub action: CommandFirewallAction,
    pub rule_id: String,
    pub rule_name: String,
    pub message: String,
    pub sanitized_command: String,
}

fn compile_bounded_regex(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        .size_limit(MAX_REGEX_SIZE_BYTES)
        .dfa_size_limit(MAX_REGEX_SIZE_BYTES)
        .build()
        .map_err(|e| format!("invalid firewall regex `{pattern}`: {e}"))
}

pub fn validate_policy(policy: &DlpFirewallPolicy) -> Result<(), String> {
    if policy.rules.len() > 256 {
        return Err("maximum of 256 command firewall rules allowed".to_owned());
    }
    for rule in &policy.rules {
        if rule.id.trim().is_empty() || rule.pattern.trim().is_empty() {
            return Err("each firewall rule requires a non-empty id and pattern".to_owned());
        }
        compile_bounded_regex(&rule.pattern)?;
    }
    Ok(())
}

#[must_use]
pub fn sanitize_command_for_audit(cmd: &str) -> String {
    static SECRET_RE: OnceLock<[Regex; 3]> = OnceLock::new();
    let res = SECRET_RE.get_or_init(|| {
        [
            Regex::new(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b").expect("aws regex"),
            Regex::new(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-~+/=]{8,}\b").expect("bearer regex"),
            Regex::new(r"(?i)\b([a-z][a-z0-9+.\-]*://[^:\s/]+:)[^@\s]+(@)").expect("dsn regex"),
        ]
    });
    let mut out = res[0].replace_all(cmd, "[REDACTED_AWS_KEY]").into_owned();
    out = res[1]
        .replace_all(&out, "${1}[REDACTED_TOKEN]")
        .into_owned();
    out = res[2]
        .replace_all(&out, "${1}[REDACTED_PASSWORD]${2}")
        .into_owned();
    out.chars().take(256).collect()
}

fn action_priority(action: CommandFirewallAction) -> u8 {
    match action {
        CommandFirewallAction::Allow => 0,
        CommandFirewallAction::Warn => 1,
        CommandFirewallAction::PauseApproval => 2,
        CommandFirewallAction::Block => 3,
    }
}

#[must_use]
pub fn evaluate_command(
    policy: &DlpFirewallPolicy,
    protocol: &str,
    command: &str,
) -> CommandFirewallVerdict {
    let trimmed = command.trim();
    let sanitized = sanitize_command_for_audit(trimmed);
    if !policy.command_firewall_enabled || trimmed.is_empty() {
        return CommandFirewallVerdict {
            action: CommandFirewallAction::Allow,
            rule_id: String::new(),
            rule_name: String::new(),
            message: String::new(),
            sanitized_command: sanitized,
        };
    }

    let proto_lower = protocol.trim().to_ascii_lowercase();
    let mut worst: Option<(u8, CommandFirewallVerdict)> = None;

    for rule in &policy.rules {
        if !rule.enabled {
            continue;
        }
        if !rule.protocols.is_empty()
            && !rule
                .protocols
                .iter()
                .any(|p| p.trim().eq_ignore_ascii_case(&proto_lower))
        {
            continue;
        }
        let Ok(re) = compile_bounded_regex(&rule.pattern) else {
            continue;
        };
        if re.is_match(trimmed) {
            let prio = action_priority(rule.action);
            if worst.as_ref().is_none_or(|(p, _)| prio > *p) {
                worst = Some((
                    prio,
                    CommandFirewallVerdict {
                        action: rule.action,
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        message: rule.message.clone(),
                        sanitized_command: sanitized.clone(),
                    },
                ));
            }
        }
    }

    worst.map_or_else(
        || CommandFirewallVerdict {
            action: CommandFirewallAction::Allow,
            rule_id: String::new(),
            rule_name: String::new(),
            message: String::new(),
            sanitized_command: sanitized,
        },
        |(_, v)| v,
    )
}

#[derive(Debug, Clone)]
pub enum ShellInputDecision {
    Forward(Vec<u8>),
    WarnForward {
        bytes: Vec<u8>,
        verdict: CommandFirewallVerdict,
    },
    Block {
        cancel_bytes: Vec<u8>,
        verdict: CommandFirewallVerdict,
    },
    PauseApproval {
        cancel_bytes: Vec<u8>,
        verdict: CommandFirewallVerdict,
    },
}

/// Line-buffered interactive command firewall that handles backspace/line-kill editing and checks
/// completed lines before forwarding execution newlines (`\r`/`\n`) to the target host.
#[derive(Debug, Default)]
pub struct ShellCommandFirewallBuffer {
    buf: String,
    in_esc_csi: bool,
}

impl ShellCommandFirewallBuffer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed_input(
        &mut self,
        bytes: &[u8],
        policy: &DlpFirewallPolicy,
        protocol: &str,
    ) -> ShellInputDecision {
        let text = String::from_utf8_lossy(bytes);
        let mut pending_verdict: Option<CommandFirewallVerdict> = None;

        for ch in text.chars() {
            if self.in_esc_csi {
                if ('@'..='~').contains(&ch) {
                    self.in_esc_csi = false;
                }
                continue;
            }
            match ch {
                '\x1b' => {
                    self.in_esc_csi = true;
                }
                '\x03' | '\x15' => {
                    self.buf.clear();
                }
                '\x7f' | '\x08' => {
                    self.buf.pop();
                }
                '\r' | '\n' => {
                    let line = std::mem::take(&mut self.buf);
                    if !line.trim().is_empty() {
                        let v = evaluate_command(policy, protocol, &line);
                        match v.action {
                            CommandFirewallAction::Block => {
                                return ShellInputDecision::Block {
                                    cancel_bytes: b"\x15".to_vec(),
                                    verdict: v,
                                };
                            }
                            CommandFirewallAction::PauseApproval => {
                                return ShellInputDecision::PauseApproval {
                                    cancel_bytes: b"\x15".to_vec(),
                                    verdict: v,
                                };
                            }
                            CommandFirewallAction::Warn => {
                                pending_verdict = Some(v);
                            }
                            CommandFirewallAction::Allow => {}
                        }
                    }
                }
                c if (!c.is_control() || c == '\t')
                    && self.buf.len() < MAX_COMMAND_BUFFER_BYTES =>
                {
                    self.buf.push(c);
                }
                _ => {}
            }
        }

        if let Some(verdict) = pending_verdict {
            ShellInputDecision::WarnForward {
                bytes: bytes.to_vec(),
                verdict,
            }
        } else {
            ShellInputDecision::Forward(bytes.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_buffer_tracks_backspaces_blocks_rm_rf_and_pauses_terraform_destroy() {
        let policy = DlpFirewallPolicy::default();
        let mut buf = ShellCommandFirewallBuffer::new();

        // Typing `ls -la\r` is allowed
        assert!(matches!(
            buf.feed_input(b"ls -la\r", &policy, "ssh"),
            ShellInputDecision::Forward(_)
        ));

        // Typing `rm -rfx\x7f /etc\r` removes `x` and evaluates `rm -rf /etc` -> Block
        let dec = buf.feed_input(b"rm -rfx\x7f /etc\r", &policy, "k8s");
        match dec {
            ShellInputDecision::Block {
                cancel_bytes,
                verdict,
            } => {
                assert_eq!(cancel_bytes, b"\x15");
                assert_eq!(verdict.action, CommandFirewallAction::Block);
            }
            other => panic!("expected Block, got {other:?}"),
        }

        // Ctrl-U clears partial dangerous command so subsequent benign newline is allowed
        let _ = buf.feed_input(b"rm -rf /\x15pwd\n", &policy, "ssh");
        // Verify `terraform destroy\r` hits PauseApproval
        let paused = buf.feed_input(b"terraform destroy\r", &policy, "ssm");
        assert!(matches!(paused, ShellInputDecision::PauseApproval { .. }));
    }

    #[test]
    fn validates_and_rejects_malformed_regex_rules() {
        let mut bad = DlpFirewallPolicy::default();
        bad.rules.push(CommandFirewallRule {
            id: "bad-1".into(),
            name: "Bad".into(),
            pattern: "[unclosed".into(),
            protocols: vec!["ssh".into()],
            action: CommandFirewallAction::Block,
            message: "x".into(),
            enabled: true,
        });
        assert!(validate_policy(&bad).is_err());
    }
}
