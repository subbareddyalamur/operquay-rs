#![forbid(unsafe_code)]

//! Thread-safe prefix trie for shell command lookup (`operquay-suggest`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suggestion {
    pub text: String,
    pub score: f64,
    pub source: String,
    pub match_type: String,
}

#[derive(Debug, Clone, Default)]
struct TrieNode {
    children: BTreeMap<u8, TrieNode>,
    key: String,
    score: f64,
    terminal: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CommandTrie {
    root: TrieNode,
    size: usize,
}

impl CommandTrie {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, command: &str, score: f64) {
        let mut node = &mut self.root;
        for &b in command.to_ascii_lowercase().as_bytes() {
            node = node.children.entry(b).or_default();
        }
        if !node.terminal {
            self.size += 1;
        }
        node.terminal = true;
        command.clone_into(&mut node.key);
        node.score = score;
    }

    #[must_use]
    pub fn search(&self, prefix: &str, limit: usize) -> Vec<Suggestion> {
        let mut node = &self.root;
        for &b in prefix.to_ascii_lowercase().as_bytes() {
            let Some(next) = node.children.get(&b) else {
                return Vec::new();
            };
            node = next;
        }
        let mut out = Vec::new();
        collect_nodes(node, &mut out);
        out.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        if limit > 0 && out.len() > limit {
            out.truncate(limit);
        }
        out
    }

    pub fn remove(&mut self, command: &str) {
        let lower = command.to_ascii_lowercase();
        if remove_recursive(&mut self.root, lower.as_bytes(), 0) {
            self.size = self.size.saturating_sub(1);
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.size
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }
}

fn collect_nodes(node: &TrieNode, out: &mut Vec<Suggestion>) {
    if node.terminal {
        out.push(Suggestion {
            text: node.key.clone(),
            score: node.score,
            source: "trie".to_owned(),
            match_type: "prefix".to_owned(),
        });
    }
    for child in node.children.values() {
        collect_nodes(child, out);
    }
}

fn remove_recursive(node: &mut TrieNode, key: &[u8], depth: usize) -> bool {
    if depth == key.len() {
        if node.terminal {
            node.terminal = false;
            node.key.clear();
            return true;
        }
        return false;
    }
    let b = key[depth];
    let Some(child) = node.children.get_mut(&b) else {
        return false;
    };
    let removed = remove_recursive(child, key, depth + 1);
    if removed && !child.terminal && child.children.is_empty() {
        node.children.remove(&b);
    }
    removed
}
