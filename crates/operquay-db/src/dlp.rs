#![forbid(unsafe_code)]

//! Inline Database Result-Set DLP Redaction & PII/Secret Masking (`M11.3`).
//!
//! Dynamically masks sensitive columns (e.g., `password`, `ssn`, `credit_card`, `secret`, `token`)
//! and inline PII/credential patterns (emails, US SSNs, Luhn-validated credit cards, US/global phone
//! numbers, AWS access keys, JWTs, PEM keys, Bearer tokens, and DB DSN passwords) inside
//! [`DbQueryResult`] before JSON serialization reaches the browser.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::driver::DbQueryResult;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbDlpPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub mask_emails: bool,
    #[serde(default = "default_true")]
    pub mask_ssn: bool,
    #[serde(default = "default_true")]
    pub mask_credit_cards: bool,
    #[serde(default = "default_true")]
    pub mask_phones: bool,
    #[serde(default = "default_true")]
    pub mask_secrets: bool,
    #[serde(default = "default_sensitive_column_patterns")]
    pub sensitive_column_patterns: Vec<String>,
    #[serde(default)]
    pub unmasked_roles: Vec<String>,
}

const fn default_true() -> bool {
    true
}

fn default_sensitive_column_patterns() -> Vec<String> {
    [
        "password",
        "passwd",
        "secret",
        "api_key",
        "access_key",
        "private_key",
        "token",
        "ssn",
        "social_security",
        "credit_card",
        "card_number",
        "cvv",
        "dob",
        "birth_date",
        "tax_id",
        "national_id",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

impl Default for DbDlpPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            mask_emails: true,
            mask_ssn: true,
            mask_credit_cards: true,
            mask_phones: true,
            mask_secrets: true,
            sensitive_column_patterns: default_sensitive_column_patterns(),
            unmasked_roles: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpRedactionSummary {
    pub masked_cells: usize,
    pub masked_columns: Vec<String>,
    pub categories: Vec<String>,
}

struct CompiledDlpRegexes {
    email: Regex,
    ssn: Regex,
    card_candidate: Regex,
    phone: Regex,
    aws_key: Regex,
    jwt: Regex,
    pem: Regex,
    bearer: Regex,
    dsn_pw: Regex,
}

fn dlp_regexes() -> &'static CompiledDlpRegexes {
    static RE: OnceLock<CompiledDlpRegexes> = OnceLock::new();
    RE.get_or_init(|| CompiledDlpRegexes {
        email: Regex::new(
            r"\b([A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]*@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b",
        )
        .expect("valid email dlp regex"),
        ssn: Regex::new(r"\b\d{3}-\d{2}-(\d{4})\b").expect("valid ssn dlp regex"),
        card_candidate: Regex::new(r"\b(?:\d[ -]?){13,19}\b").expect("valid card candidate regex"),
        phone: Regex::new(r"(?:\+?1[-.\s]?)?\(?\b\d{3}\)?[-.\s]\d{3}[-.\s](\d{4})\b")
            .expect("valid phone regex"),
        aws_key: Regex::new(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b").expect("valid aws key regex"),
        jwt: Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
            .expect("valid jwt regex"),
        pem: Regex::new(
            r"-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]+ PRIVATE KEY-----",
        )
        .expect("valid pem regex"),
        bearer: Regex::new(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-~+/=]{12,}\b")
            .expect("valid bearer regex"),
        dsn_pw: Regex::new(r"(?i)\b([a-z][a-z0-9+.\-]*://[^:\s/]+:)[^@\s]+(@)")
            .expect("valid dsn regex"),
    })
}

fn luhn_valid(digits: &str) -> bool {
    if !(13..=19).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for b in digits.bytes().rev() {
        let mut d = u32::from(b - b'0');
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum.is_multiple_of(10)
}

fn is_sensitive_column(col: &str, patterns: &[String]) -> bool {
    let lower = col.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    patterns
        .iter()
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .any(|pat| lower.contains(&pat))
}

fn mask_string_value(
    input: &str,
    policy: &DbDlpPolicy,
    categories: &mut BTreeSet<String>,
) -> Option<String> {
    let re = dlp_regexes();
    let mut out = input.to_owned();
    let mut changed = false;

    if policy.mask_secrets {
        let next = re.pem.replace_all(&out, "[REDACTED_PRIVATE_KEY]");
        if next.as_ref() != out {
            out = next.into_owned();
            changed = true;
            categories.insert("private_key".to_owned());
        }
        let next = re.aws_key.replace_all(&out, "[REDACTED_AWS_KEY]");
        if next.as_ref() != out {
            out = next.into_owned();
            changed = true;
            categories.insert("aws_key".to_owned());
        }
        let next = re.jwt.replace_all(&out, "[REDACTED_JWT]");
        if next.as_ref() != out {
            out = next.into_owned();
            changed = true;
            categories.insert("jwt".to_owned());
        }
        let next = re.bearer.replace_all(&out, "${1}[REDACTED_TOKEN]");
        if next.as_ref() != out {
            out = next.into_owned();
            changed = true;
            categories.insert("bearer_token".to_owned());
        }
        let next = re.dsn_pw.replace_all(&out, "${1}[REDACTED_PASSWORD]${2}");
        if next.as_ref() != out {
            out = next.into_owned();
            changed = true;
            categories.insert("dsn_password".to_owned());
        }
    }

    if policy.mask_credit_cards {
        let mut rebuilt = String::with_capacity(out.len());
        let mut last = 0usize;
        let mut card_hit = false;
        for m in re.card_candidate.find_iter(&out) {
            let digits: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
            if luhn_valid(&digits) {
                rebuilt.push_str(&out[last..m.start()]);
                let last4 = &digits[digits.len() - 4..];
                rebuilt.push_str("****-****-****-");
                rebuilt.push_str(last4);
                last = m.end();
                card_hit = true;
            }
        }
        if card_hit {
            rebuilt.push_str(&out[last..]);
            out = rebuilt;
            changed = true;
            categories.insert("credit_card".to_owned());
        }
    }

    if policy.mask_ssn {
        let next = re.ssn.replace_all(&out, "***-**-${1}");
        if next.as_ref() != out {
            out = next.into_owned();
            changed = true;
            categories.insert("ssn".to_owned());
        }
    }

    if policy.mask_emails {
        let next = re.email.replace_all(&out, "${1}***@${2}");
        if next.as_ref() != out {
            out = next.into_owned();
            changed = true;
            categories.insert("email".to_owned());
        }
    }

    if policy.mask_phones {
        let next = re.phone.replace_all(&out, "***-***-${1}");
        if next.as_ref() != out {
            out = next.into_owned();
            changed = true;
            categories.insert("phone".to_owned());
        }
    }

    changed.then_some(out)
}

fn mask_cell_value(
    val: &Value,
    sensitive_col: bool,
    policy: &DbDlpPolicy,
    categories: &mut BTreeSet<String>,
) -> Option<Value> {
    if sensitive_col && !val.is_null() {
        categories.insert("sensitive_column".to_owned());
        return Some(Value::String("[REDACTED]".to_owned()));
    }
    match val {
        Value::String(s) => mask_string_value(s, policy, categories).map(Value::String),
        Value::Array(items) => {
            let mut any = false;
            let mut next_items = Vec::with_capacity(items.len());
            for item in items {
                if let Some(masked) = mask_cell_value(item, false, policy, categories) {
                    any = true;
                    next_items.push(masked);
                } else {
                    next_items.push(item.clone());
                }
            }
            any.then_some(Value::Array(next_items))
        }
        Value::Object(obj) => {
            let mut any = false;
            let mut next_obj = Map::with_capacity(obj.len());
            for (k, v) in obj {
                let child_sens = is_sensitive_column(k, &policy.sensitive_column_patterns);
                if let Some(masked) = mask_cell_value(v, child_sens, policy, categories) {
                    any = true;
                    next_obj.insert(k.clone(), masked);
                } else {
                    next_obj.insert(k.clone(), v.clone());
                }
            }
            any.then_some(Value::Object(next_obj))
        }
        _ => None,
    }
}

/// Apply tenant DLP redaction across `result.rows` and `result.matrix_rows` unless `caller_role`
/// is explicitly allowed in `policy.unmasked_roles`.
pub fn redact_query_result(
    result: &mut DbQueryResult,
    policy: &DbDlpPolicy,
    caller_role: &str,
) -> DlpRedactionSummary {
    if !policy.enabled {
        return DlpRedactionSummary::default();
    }
    let role_trimmed = caller_role.trim();
    if !role_trimmed.is_empty()
        && policy
            .unmasked_roles
            .iter()
            .any(|r| r.trim().eq_ignore_ascii_case(role_trimmed))
    {
        return DlpRedactionSummary::default();
    }

    let mut masked_cells = 0usize;
    let mut masked_columns = BTreeSet::new();
    let mut categories = BTreeSet::new();

    for (col_idx, col_name) in result.columns.iter().enumerate() {
        let sens_col = is_sensitive_column(col_name, &policy.sensitive_column_patterns);
        for (row_idx, row_map) in result.rows.iter_mut().enumerate() {
            if let Some(cell) = row_map.get_mut(col_name) {
                if let Some(masked) = mask_cell_value(cell, sens_col, policy, &mut categories) {
                    *cell = masked.clone();
                    masked_cells += 1;
                    masked_columns.insert(col_name.clone());
                    if let Some(matrix_row) = result.matrix_rows.get_mut(row_idx) {
                        if let Some(mcell) = matrix_row.get_mut(col_idx) {
                            *mcell = masked;
                        }
                    }
                }
            }
        }
    }

    // Also handle rows whose keys weren't strictly listed in result.columns
    for (row_idx, row_map) in result.rows.iter_mut().enumerate() {
        for (col_name, cell) in row_map.iter_mut() {
            if result.columns.iter().any(|c| c == col_name) {
                continue;
            }
            let sens_col = is_sensitive_column(col_name, &policy.sensitive_column_patterns);
            if let Some(masked) = mask_cell_value(cell, sens_col, policy, &mut categories) {
                *cell = masked;
                masked_cells += 1;
                masked_columns.insert(col_name.clone());
                let _ = row_idx;
            }
        }
    }

    let summary = DlpRedactionSummary {
        masked_cells,
        masked_columns: masked_columns.into_iter().collect(),
        categories: categories.into_iter().collect(),
    };
    if masked_cells > 0 {
        result.dlp_summary = Some(summary.clone());
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_pii_luhn_pan_keys_and_sensitive_columns_in_rows_and_matrix() {
        let mut row = Map::new();
        row.insert("id".to_owned(), Value::from(1));
        row.insert("email".to_owned(), Value::from("alice.smith@acme.example"));
        row.insert("tax_ssn".to_owned(), Value::from("123-45-6789"));
        row.insert("pan".to_owned(), Value::from("4111-1111-1111-1111"));
        row.insert("api_secret".to_owned(), Value::from("supersecret99"));
        row.insert(
            "notes".to_owned(),
            Value::from("token AKIAIOSFODNN7EXAMPLE call (415) 555-2671"),
        );

        let mut res = DbQueryResult {
            columns: vec![
                "id".into(),
                "email".into(),
                "tax_ssn".into(),
                "pan".into(),
                "api_secret".into(),
                "notes".into(),
            ],
            rows: vec![row],
            matrix_rows: vec![vec![
                Value::from(1),
                Value::from("alice.smith@acme.example"),
                Value::from("123-45-6789"),
                Value::from("4111-1111-1111-1111"),
                Value::from("supersecret99"),
                Value::from("token AKIAIOSFODNN7EXAMPLE call (415) 555-2671"),
            ]],
            row_count: 1,
            duration_ms: 2,
            truncated: false,
            dlp_summary: None,
        };

        let summary = redact_query_result(&mut res, &DbDlpPolicy::default(), "operator");
        assert_eq!(summary.masked_cells, 5);
        assert_eq!(res.rows[0]["email"], "a***@acme.example");
        assert_eq!(res.rows[0]["tax_ssn"], "[REDACTED]");
        assert_eq!(res.rows[0]["pan"], "****-****-****-1111");
        assert_eq!(res.rows[0]["api_secret"], "[REDACTED]");
        let notes = res.rows[0]["notes"].as_str().unwrap();
        assert!(!notes.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(notes.contains("[REDACTED_AWS_KEY]"));
        assert!(notes.contains("***-***-2671"));
        assert_eq!(res.matrix_rows[0][1], "a***@acme.example");
        assert_eq!(res.matrix_rows[0][3], "****-****-****-1111");
        assert!(res.dlp_summary.is_some());

        // Exempted role sees raw values when explicitly configured
        let mut allow_res = res.clone();
        allow_res.rows[0].insert("email".into(), Value::from("bob@acme.example"));
        let allow_policy = DbDlpPolicy {
            unmasked_roles: vec!["compliance_unmasked".to_owned()],
            ..DbDlpPolicy::default()
        };
        let bypass = redact_query_result(&mut allow_res, &allow_policy, "compliance_unmasked");
        assert_eq!(bypass.masked_cells, 0);
        assert_eq!(allow_res.rows[0]["email"], "bob@acme.example");
    }
}
