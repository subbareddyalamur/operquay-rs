#![forbid(unsafe_code)]

//! Shell error knowledge base, ANSI escape sequence stripper, and fix recommender.

use std::collections::HashMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogInsight {
    pub description: String,
    pub fix: String,
    pub matched_line: String,
}

struct PatternRule {
    re: Regex,
    desc: &'static str,
    fix: &'static str,
}

pub struct ErrorKb {
    patterns: Vec<PatternRule>,
    learned: HashMap<String, String>,
    ansi_re: Regex,
}

impl Default for ErrorKb {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorKb {
    #[must_use]
    pub fn new() -> Self {
        let defs = [
            (
                r"(?i)permission denied",
                "Permission denied",
                "Check file permissions with `ls -la`. Try `sudo` or `chmod`.",
            ),
            (
                r"(?i)command not found",
                "Command not found",
                "Install the missing command or check `$PATH` with `which`.",
            ),
            (
                r"(?i)no such file or directory",
                "File/directory not found",
                "Verify the path with `ls`.",
            ),
            (
                r"(?i)connection refused",
                "Connection refused",
                "Verify the service is listening via `ss -tlnp`.",
            ),
            (
                r"(?i)connection timed out",
                "Connection timed out",
                "Check security groups, NACL rules, and route tables.",
            ),
            (
                r"(?i)name or service not known",
                "DNS resolution failed",
                "Check `/etc/resolv.conf` or test with `dig`.",
            ),
            (
                r"(?i)no space left on device",
                "Disk full",
                "Check disk usage via `df -h`.",
            ),
            (
                r"(?i)out of memory|OOM|oom-kill",
                "Out of memory",
                "Inspect memory pressure via `free -h` and `dmesg`.",
            ),
            (
                r"(?i)access denied|AccessDenied",
                "Access denied (AWS)",
                "Check IAM policy and role trust relationship.",
            ),
            (
                r"(?i)port.*already in use|address already in use",
                "Port conflict",
                "Inspect socket owner with `lsof -i :<port>`.",
            ),
            (
                r"(?i)CrashLoopBackOff|ImagePullBackOff",
                "Kubernetes pod failure",
                "Run `kubectl describe pod` and `kubectl logs --previous`.",
            ),
        ];
        let patterns = defs
            .into_iter()
            .filter_map(|(pat, desc, fix)| {
                Regex::new(pat).ok().map(|re| PatternRule { re, desc, fix })
            })
            .collect();
        Self {
            patterns,
            learned: HashMap::new(),
            ansi_re: Regex::new(r"\x1b\[[0-9;?]*[ -/]*[@-~]").expect("valid ANSI regex"),
        }
    }

    #[must_use]
    pub fn strip_ansi(&self, raw: &str) -> String {
        self.ansi_re.replace_all(raw, "").into_owned()
    }

    pub fn learn_resolution(&mut self, error_sig: &str, command: &str) {
        if !error_sig.trim().is_empty() && !command.trim().is_empty() {
            self.learned
                .insert(error_sig.trim().to_owned(), command.trim().to_owned());
        }
    }

    #[must_use]
    pub fn detect_errors(&self, raw_output: &str) -> Vec<LogInsight> {
        let clean = self.strip_ansi(raw_output);
        let mut insights = Vec::new();
        for line in clean.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            for rule in &self.patterns {
                if rule.re.is_match(trimmed) {
                    insights.push(LogInsight {
                        description: rule.desc.to_owned(),
                        fix: self
                            .learned
                            .get(trimmed)
                            .cloned()
                            .unwrap_or_else(|| rule.fix.to_owned()),
                        matched_line: trimmed.to_owned(),
                    });
                    break;
                }
            }
        }
        insights
    }
}
