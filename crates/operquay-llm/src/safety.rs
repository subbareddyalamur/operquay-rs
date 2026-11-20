#![forbid(unsafe_code)]

//! Destructive shell command detection + PII/credential secret scrubber (`operquay-llm`).

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyVerdict {
    pub blocked: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionRiskBookmarkDraft {
    pub offset_secs: f64,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub detail: String,
    pub source: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionRiskAnalysis {
    pub risk_score: u8,
    pub summary: String,
    pub bookmarks: Vec<SessionRiskBookmarkDraft>,
}

pub struct SafetyGuard {
    destructive: Vec<Regex>,
    redactors: Vec<(Regex, &'static str)>,
    priv_esc: Regex,
    sensitive_files: Regex,
    pkg_install: Regex,
    high_impact_cloud: Regex,
    ansi_csi: Regex,
}

impl Default for SafetyGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyGuard {
    #[must_use]
    pub fn new() -> Self {
        let destructive_patterns = [
            r"(?i)\brm\s+(-[a-z]*f|-[a-z]*r|--force|--recursive)\b",
            r"(?i)\brm\s+-rf\b",
            r"(?i)\bmkfs\b",
            r"(?i)\bdd\s+.*of=/dev/",
            r"(?i):\(\)\{\s*:\|:&\s*\};:",
            r"(?i)^\s*shutdown\b",
            r"(?i)^\s*reboot\b",
            r"(?i)^\s*init\s+[06]\b",
            r"(?i)\bsystemctl\s+(stop|disable|mask)\b",
            r"(?i)\biptables\s+-F\b",
            r"(?i)\bchmod\s+-R\s+777\b",
            r"(?i)\bkill\s+-9\s+-1\b",
            r"(?i)>\s*/dev/sd[a-z]",
            r"(?i)^\s*format\b.*\b[cC]:",
            r"(?i)^\s*del\s+/[sS]\b",
            r"(?i)\bStop-Computer\b",
            r"(?i)\bRestart-Computer\b",
            r"(?i)\bdrop\s+database\b",
            r"(?i)\btruncate\s+table\b",
            r"(?i)\bparted\s.*\brm\b",
            r"(?i)\bfdisk\b",
        ];
        let destructive = destructive_patterns
            .into_iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        let redact_patterns = [
            (r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "[REDACTED_AWS_ACCESS_KEY]"),
            (
                r"-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]+ PRIVATE KEY-----",
                "[REDACTED_PRIVATE_KEY]",
            ),
            (
                r"(?i)(bearer\s+)[A-Za-z0-9._\-~+/]+=*",
                "${1}[REDACTED_TOKEN]",
            ),
            (
                r"(?i)(postgres(?:ql)?://[^:]+:)[^@]+(@)",
                "${1}[REDACTED_PASSWORD]${2}",
            ),
            (
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                "[REDACTED_EMAIL]",
            ),
            (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
        ];
        let redactors = redact_patterns
            .into_iter()
            .filter_map(|(p, r)| Regex::new(p).ok().map(|re| (re, r)))
            .collect();

        Self {
            destructive,
            redactors,
            priv_esc: Regex::new(r"(?i)\b(sudo|su\s+-|visudo|chmod\s+[ugo]*\+s|usermod\s+-aG)\b")
                .expect("valid priv_esc regex"),
            sensitive_files: Regex::new(
                r"(?i)(/etc/shadow|/etc/sudoers|\.ssh/id_[a-z0-9_]+|\.aws/credentials|\.kube/config)",
            )
            .expect("valid sensitive_files regex"),
            pkg_install: Regex::new(
                r"(?i)\b(curl\s+[^|]+\|\s*(ba)?sh|wget\s+[^|]+\|\s*(ba)?sh|apt(-get)?\s+install|yum\s+install|dnf\s+install|apk\s+add|pip3?\s+install)\b",
            )
            .expect("valid pkg_install regex"),
            high_impact_cloud: Regex::new(
                r"(?i)\b(kubectl\s+delete|terraform\s+destroy|aws\s+(iam|rds|ec2)\s+delete-|drop\s+(database|table)|truncate\s+table)\b",
            )
            .expect("valid high_impact_cloud regex"),
            ansi_csi: Regex::new(r"\x1b\[[0-9;?]*[ -/]*[@-~]").expect("valid ansi regex"),
        }
    }

    #[must_use]
    pub fn check_command(&self, cmd: &str) -> SafetyVerdict {
        for seg in cmd.split('|') {
            let trimmed = seg.trim();
            for pat in &self.destructive {
                if pat.is_match(trimmed) {
                    return SafetyVerdict {
                        blocked: true,
                        reason: format!("Blocked: matches destructive pattern `{}`", pat.as_str()),
                    };
                }
            }
        }
        SafetyVerdict {
            blocked: false,
            reason: String::new(),
        }
    }

    #[must_use]
    pub fn redact_pii(&self, input: &str) -> String {
        let mut cur = input.to_owned();
        for (re, repl) in &self.redactors {
            cur = re.replace_all(&cur, *repl).into_owned();
        }
        cur
    }

    /// Extract timestamped, PII-redacted risk bookmarks from an asciinema `.cast` stream or plain
    /// session transcript (`M11.2`).
    #[must_use]
    pub fn extract_session_risk_bookmarks(&self, raw_transcript: &str) -> SessionRiskAnalysis {
        let mut bookmarks = Vec::new();
        let mut max_weight: u8 = 0;

        for (idx, raw_line) in raw_transcript.lines().enumerate() {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('{') && trimmed.contains("\"version\"") {
                continue;
            }
            let (offset_secs, text) = if trimmed.starts_with('[') {
                if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
                    if arr.len() >= 3 {
                        let ts = arr[0].as_f64().unwrap_or(idx as f64);
                        let body = arr[2].as_str().unwrap_or("").to_owned();
                        (ts, body)
                    } else {
                        (idx as f64, trimmed.to_owned())
                    }
                } else {
                    (idx as f64, trimmed.to_owned())
                }
            } else {
                (idx as f64, trimmed.to_owned())
            };

            let stripped = self.ansi_csi.replace_all(&text, "");
            for subline in stripped.split(['\r', '\n']) {
                let clean_raw = subline.trim();
                if clean_raw.is_empty() {
                    continue;
                }
                let sanitized = self.redact_pii(clean_raw);
                let snippet: String = sanitized.chars().take(180).collect();

                if sanitized != clean_raw {
                    max_weight = max_weight.max(70);
                    bookmarks.push(SessionRiskBookmarkDraft {
                        offset_secs,
                        severity: "high".to_owned(),
                        category: "secret_exposure".to_owned(),
                        title: "Credential or private secret detected in stream".to_owned(),
                        detail: snippet.clone(),
                        source: "heuristic".to_owned(),
                    });
                }
                if self.check_command(clean_raw).blocked
                    || self.high_impact_cloud.is_match(clean_raw)
                {
                    max_weight = max_weight.max(90);
                    bookmarks.push(SessionRiskBookmarkDraft {
                        offset_secs,
                        severity: "critical".to_owned(),
                        category: "destructive_command".to_owned(),
                        title: "Destructive or high-impact mutation detected".to_owned(),
                        detail: snippet.clone(),
                        source: "heuristic".to_owned(),
                    });
                } else if self.sensitive_files.is_match(clean_raw) {
                    max_weight = max_weight.max(75);
                    bookmarks.push(SessionRiskBookmarkDraft {
                        offset_secs,
                        severity: "high".to_owned(),
                        category: "sensitive_file".to_owned(),
                        title: "Sensitive credential/system file referenced".to_owned(),
                        detail: snippet.clone(),
                        source: "heuristic".to_owned(),
                    });
                } else if self.priv_esc.is_match(clean_raw) {
                    max_weight = max_weight.max(55);
                    bookmarks.push(SessionRiskBookmarkDraft {
                        offset_secs,
                        severity: "medium".to_owned(),
                        category: "privilege_escalation".to_owned(),
                        title: "Privilege escalation command executed".to_owned(),
                        detail: snippet.clone(),
                        source: "heuristic".to_owned(),
                    });
                } else if self.pkg_install.is_match(clean_raw) {
                    max_weight = max_weight.max(30);
                    bookmarks.push(SessionRiskBookmarkDraft {
                        offset_secs,
                        severity: "low".to_owned(),
                        category: "package_or_script".to_owned(),
                        title: "Package or remote script execution observed".to_owned(),
                        detail: snippet.clone(),
                        source: "heuristic".to_owned(),
                    });
                }

                if bookmarks.len() >= 200 {
                    break;
                }
            }
            if bookmarks.len() >= 200 {
                break;
            }
        }

        let bonus = u8::try_from((bookmarks.len().saturating_sub(1) * 4).min(10)).unwrap_or(10);
        let risk_score = if bookmarks.is_empty() {
            0
        } else {
            max_weight.saturating_add(bonus).min(100)
        };
        let summary = if bookmarks.is_empty() {
            "No high-risk commands, privilege escalations, or secret leaks observed.".to_owned()
        } else {
            format!(
                "Identified {} risk event(s); peak risk score {risk_score}/100 (sanitized).",
                bookmarks.len()
            )
        };
        SessionRiskAnalysis {
            risk_score,
            summary,
            bookmarks,
        }
    }
}
