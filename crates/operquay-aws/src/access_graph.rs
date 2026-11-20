#![forbid(unsafe_code)]

//! Unified Identity, Resource & Network Blast-Radius Access Graph (`M12.4`).
//!
//! Combines `petgraph` graph reachability and strongly connected component (`tarjan_scc`)
//! analysis across human users, groups, AI MCP agents, IAM/Entra/GCP roles, hybrid agents,
//! EC2/Cloud VMs, Kubernetes clusters, and DB connections to uncover Shadow Admins,
//! Cross-Account Trust Loops, Unused Standing Privileges, and per-principal Blast Radius.

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::algo::tarjan_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessNodeKind {
    User,
    Group,
    AiAgent,
    Role,
    CloudRole,
    Instance,
    K8sCluster,
    Database,
    HybridHost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessEdgeKind {
    MemberOf,
    Sponsors,
    AssignedRole,
    CanAssume,
    CanAccess,
    NetworkReaches,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessNode {
    pub id: String,
    pub label: String,
    pub kind: AccessNodeKind,
    #[serde(default)]
    pub account_or_tenant: String,
    #[serde(default)]
    pub environment: String,
    #[serde(default)]
    pub is_admin_capability: bool,
    #[serde(default)]
    pub has_jit_gate: bool,
    #[serde(default)]
    pub last_used_at: Option<i64>,
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEdge {
    pub from: String,
    pub to: String,
    pub kind: AccessEdgeKind,
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessGraphInput {
    pub now_secs: i64,
    #[serde(default = "default_unused_days")]
    pub unused_threshold_days: u32,
    pub nodes: Vec<AccessNode>,
    pub edges: Vec<AccessEdge>,
}

const fn default_unused_days() -> u32 {
    30
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessFindingKind {
    ShadowAdmin,
    CrossAccountTrustLoop,
    UnusedStandingPrivilege,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessFinding {
    pub id: String,
    pub kind: AccessFindingKind,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub node_ids: Vec<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalBlastRadius {
    pub principal_id: String,
    pub principal_label: String,
    pub principal_kind: AccessNodeKind,
    pub reachable_resources: usize,
    pub reachable_prod_resources: usize,
    pub admin_paths: usize,
    pub blast_score: u8,
    pub sample_path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessGraphSummary {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub principals: usize,
    pub shadow_admins: usize,
    pub trust_loops: usize,
    pub unused_standing_privileges: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessGraphReport {
    pub generated_at: i64,
    pub summary: AccessGraphSummary,
    pub nodes: Vec<AccessNode>,
    pub edges: Vec<AccessEdge>,
    pub findings: Vec<AccessFinding>,
    pub blast_radius: Vec<PrincipalBlastRadius>,
}

fn is_principal_kind(kind: AccessNodeKind) -> bool {
    matches!(kind, AccessNodeKind::User | AccessNodeKind::AiAgent)
}

fn is_target_resource(kind: AccessNodeKind) -> bool {
    matches!(
        kind,
        AccessNodeKind::Instance
            | AccessNodeKind::K8sCluster
            | AccessNodeKind::Database
            | AccessNodeKind::HybridHost
    )
}

fn is_privileged_node(node: &AccessNode) -> bool {
    if node.is_admin_capability {
        return true;
    }
    node.permissions.iter().any(|p| {
        matches!(
            p.as_str(),
            "*" | "users:manage"
                | "roles:manage"
                | "sso:manage"
                | "dlp:manage"
                | "aws_accounts:manage"
                | "mcp:manage"
                | "agents:manage"
        )
    })
}

fn is_prod_env(node: &AccessNode) -> bool {
    let lower = node.environment.trim().to_ascii_lowercase();
    let label_l = node.label.to_ascii_lowercase();
    lower.contains("prod") || lower == "prd" || label_l.contains("prod")
}

#[must_use]
pub fn analyze_access_graph(input: &AccessGraphInput) -> AccessGraphReport {
    let mut graph = DiGraph::<usize, AccessEdgeKind>::new();
    let mut idx_by_id: HashMap<String, NodeIndex> = HashMap::new();
    let mut dedup_nodes = Vec::with_capacity(input.nodes.len());

    for node in &input.nodes {
        if idx_by_id.contains_key(&node.id) {
            continue;
        }
        let vec_idx = dedup_nodes.len();
        dedup_nodes.push(node.clone());
        let g_idx = graph.add_node(vec_idx);
        idx_by_id.insert(node.id.clone(), g_idx);
    }

    let mut valid_edges = Vec::with_capacity(input.edges.len());
    for edge in &input.edges {
        let (Some(&from_i), Some(&to_i)) = (idx_by_id.get(&edge.from), idx_by_id.get(&edge.to))
        else {
            continue;
        };
        graph.add_edge(from_i, to_i, edge.kind);
        valid_edges.push(edge.clone());
    }

    let mut findings = Vec::new();
    let mut blast_radius = Vec::new();
    let mut shadow_admin_count = 0usize;
    let mut trust_loop_count = 0usize;
    let mut unused_count = 0usize;

    // 1. Cross-Account Trust Loops via Tarjan Strongly Connected Components
    let mut assumption_graph = DiGraph::<usize, ()>::new();
    let mut assump_map: HashMap<NodeIndex, NodeIndex> = HashMap::new();
    for g_idx in graph.node_indices() {
        let node = &dedup_nodes[graph[g_idx]];
        if matches!(node.kind, AccessNodeKind::Role | AccessNodeKind::CloudRole) {
            let a_idx = assumption_graph.add_node(graph[g_idx]);
            assump_map.insert(g_idx, a_idx);
        }
    }
    for edge in graph.edge_references() {
        if *edge.weight() == AccessEdgeKind::CanAssume {
            if let (Some(&u), Some(&v)) = (
                assump_map.get(&edge.source()),
                assump_map.get(&edge.target()),
            ) {
                assumption_graph.add_edge(u, v, ());
            }
        }
    }
    for comp in tarjan_scc(&assumption_graph) {
        if comp.len() < 2 {
            continue;
        }
        trust_loop_count += 1;
        let ids: Vec<String> = comp
            .iter()
            .map(|c| dedup_nodes[assumption_graph[*c]].id.clone())
            .collect();
        let labels: Vec<String> = comp
            .iter()
            .map(|c| dedup_nodes[assumption_graph[*c]].label.clone())
            .collect();
        findings.push(AccessFinding {
            id: format!("loop-{trust_loop_count}"),
            kind: AccessFindingKind::CrossAccountTrustLoop,
            severity: "critical".to_owned(),
            title: format!("Circular Role Trust Loop ({} roles)", comp.len()),
            description: format!(
                "Cyclic role assumption chain detected across accounts/roles: {}",
                labels.join(" -> ")
            ),
            node_ids: ids,
            remediation:
                "Break mutual sts:AssumeRole trust policies and gate cross-account pivots with JIT approvals."
                    .to_owned(),
        });
    }

    // 2. Unused Standing Privileges
    let stale_cutoff = input
        .now_secs
        .saturating_sub(i64::from(input.unused_threshold_days.max(1)).saturating_mul(86_400));
    for node in &dedup_nodes {
        if matches!(node.kind, AccessNodeKind::Role | AccessNodeKind::CloudRole)
            && is_privileged_node(node)
            && !node.has_jit_gate
            && node
                .last_used_at
                .is_some_and(|ts| ts > 0 && ts < stale_cutoff)
        {
            unused_count += 1;
            findings.push(AccessFinding {
                id: format!("unused-{}", node.id),
                kind: AccessFindingKind::UnusedStandingPrivilege,
                severity: "medium".to_owned(),
                title: format!("Unused Standing Privilege: {}", node.label),
                description: format!(
                    "Privileged role '{}' has no JIT expiration gate and has been inactive for >{} days.",
                    node.label, input.unused_threshold_days
                ),
                node_ids: vec![node.id.clone()],
                remediation: "Convert standing binding to an on-demand JIT request policy (M11.1)."
                    .to_owned(),
            });
        }
    }

    // 3. Per-Principal Blast Radius + Shadow Admin escalation paths
    for start_idx in graph.node_indices() {
        let p_node = &dedup_nodes[graph[start_idx]];
        if !is_principal_kind(p_node.kind) {
            continue;
        }
        let mut visited: HashSet<NodeIndex> = HashSet::new();
        let mut parent: HashMap<NodeIndex, NodeIndex> = HashMap::new();
        let mut queue = VecDeque::new();
        visited.insert(start_idx);
        queue.push_back(start_idx);

        let mut reachable_res = 0usize;
        let mut prod_res = 0usize;
        let mut admin_targets: Vec<NodeIndex> = Vec::new();
        let mut first_target_path: Vec<String> = Vec::new();

        while let Some(cur) = queue.pop_front() {
            let cur_node = &dedup_nodes[graph[cur]];
            if cur != start_idx {
                if is_target_resource(cur_node.kind) {
                    reachable_res += 1;
                    if is_prod_env(cur_node) {
                        prod_res += 1;
                    }
                    if first_target_path.is_empty() {
                        first_target_path =
                            reconstruct_path(&parent, &graph, &dedup_nodes, start_idx, cur);
                    }
                }
                if is_privileged_node(cur_node) {
                    admin_targets.push(cur);
                }
            }
            for edge in graph.edges(cur) {
                let next = edge.target();
                if visited.insert(next) {
                    parent.insert(next, cur);
                    queue.push_back(next);
                }
            }
        }

        if !p_node.is_admin_capability && !admin_targets.is_empty() {
            shadow_admin_count += 1;
            let best_path =
                reconstruct_path(&parent, &graph, &dedup_nodes, start_idx, admin_targets[0]);
            findings.push(AccessFinding {
                id: format!("shadow-{}", p_node.id),
                kind: AccessFindingKind::ShadowAdmin,
                severity: "high".to_owned(),
                title: format!("Shadow Admin Path: {}", p_node.label),
                description: format!(
                    "Non-admin principal '{}' can escalate to privileged capabilities via: {}",
                    p_node.label,
                    best_path.join(" -> ")
                ),
                node_ids: vec![p_node.id.clone()],
                remediation:
                    "Remove transitive group/role inheritance or enforce four-eyes JIT elevation."
                        .to_owned(),
            });
            first_target_path = best_path;
        }

        let raw_score = reachable_res.saturating_mul(6)
            + prod_res.saturating_mul(14)
            + admin_targets.len().saturating_mul(25)
            + if p_node.is_admin_capability { 30 } else { 0 };
        let blast_score = u8::try_from(raw_score.min(100)).unwrap_or(100);

        blast_radius.push(PrincipalBlastRadius {
            principal_id: p_node.id.clone(),
            principal_label: p_node.label.clone(),
            principal_kind: p_node.kind,
            reachable_resources: reachable_res,
            reachable_prod_resources: prod_res,
            admin_paths: admin_targets.len(),
            blast_score,
            sample_path: first_target_path,
        });
    }

    blast_radius.sort_by_key(|b| std::cmp::Reverse(b.blast_score));

    AccessGraphReport {
        generated_at: input.now_secs,
        summary: AccessGraphSummary {
            total_nodes: dedup_nodes.len(),
            total_edges: valid_edges.len(),
            principals: blast_radius.len(),
            shadow_admins: shadow_admin_count,
            trust_loops: trust_loop_count,
            unused_standing_privileges: unused_count,
        },
        nodes: dedup_nodes,
        edges: valid_edges,
        findings,
        blast_radius,
    }
}

fn reconstruct_path(
    parent: &HashMap<NodeIndex, NodeIndex>,
    graph: &DiGraph<usize, AccessEdgeKind>,
    nodes: &[AccessNode],
    start: NodeIndex,
    goal: NodeIndex,
) -> Vec<String> {
    let mut rev = Vec::new();
    let mut cur = goal;
    rev.push(nodes[graph[cur]].label.clone());
    while cur != start {
        if let Some(&prev) = parent.get(&cur) {
            rev.push(nodes[graph[prev]].label.clone());
            cur = prev;
        } else {
            break;
        }
    }
    rev.reverse();
    rev
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_shadow_admin_trust_loops_and_unused_standing_privileges() {
        let now = 1_795_000_000i64;
        let report = analyze_access_graph(&AccessGraphInput {
            now_secs: now,
            unused_threshold_days: 30,
            nodes: vec![
                AccessNode {
                    id: "u-dev".into(),
                    label: "dev@acme.io".into(),
                    kind: AccessNodeKind::User,
                    account_or_tenant: "default".into(),
                    environment: String::new(),
                    is_admin_capability: false,
                    has_jit_gate: false,
                    last_used_at: Some(now),
                    permissions: vec![],
                },
                AccessNode {
                    id: "grp-eng".into(),
                    label: "Engineering".into(),
                    kind: AccessNodeKind::Group,
                    account_or_tenant: "default".into(),
                    environment: String::new(),
                    is_admin_capability: false,
                    has_jit_gate: false,
                    last_used_at: None,
                    permissions: vec![],
                },
                AccessNode {
                    id: "role-a".into(),
                    label: "AccountA/OpsRole".into(),
                    kind: AccessNodeKind::CloudRole,
                    account_or_tenant: "111".into(),
                    environment: "prod".into(),
                    is_admin_capability: true,
                    has_jit_gate: false,
                    last_used_at: Some(now - 45 * 86_400),
                    permissions: vec!["*".into()],
                },
                AccessNode {
                    id: "role-b".into(),
                    label: "AccountB/SecurityPivot".into(),
                    kind: AccessNodeKind::CloudRole,
                    account_or_tenant: "222".into(),
                    environment: "prod".into(),
                    is_admin_capability: true,
                    has_jit_gate: false,
                    last_used_at: Some(now - 5 * 86_400),
                    permissions: vec!["*".into()],
                },
                AccessNode {
                    id: "db-prod".into(),
                    label: "prod-billing-pg".into(),
                    kind: AccessNodeKind::Database,
                    account_or_tenant: "222".into(),
                    environment: "production".into(),
                    is_admin_capability: false,
                    has_jit_gate: false,
                    last_used_at: None,
                    permissions: vec![],
                },
            ],
            edges: vec![
                AccessEdge {
                    from: "u-dev".into(),
                    to: "grp-eng".into(),
                    kind: AccessEdgeKind::MemberOf,
                    label: "member".into(),
                },
                AccessEdge {
                    from: "grp-eng".into(),
                    to: "role-a".into(),
                    kind: AccessEdgeKind::AssignedRole,
                    label: "inherits".into(),
                },
                AccessEdge {
                    from: "role-a".into(),
                    to: "role-b".into(),
                    kind: AccessEdgeKind::CanAssume,
                    label: "sts:AssumeRole".into(),
                },
                AccessEdge {
                    from: "role-b".into(),
                    to: "role-a".into(),
                    kind: AccessEdgeKind::CanAssume,
                    label: "sts:AssumeRole".into(),
                },
                AccessEdge {
                    from: "role-b".into(),
                    to: "db-prod".into(),
                    kind: AccessEdgeKind::CanAccess,
                    label: "read/write".into(),
                },
            ],
        });

        assert_eq!(report.summary.shadow_admins, 1);
        assert_eq!(report.summary.trust_loops, 1);
        assert_eq!(report.summary.unused_standing_privileges, 1);
        assert_eq!(report.blast_radius.len(), 1);
        assert_eq!(report.blast_radius[0].reachable_prod_resources, 1);
        assert!(report.blast_radius[0].blast_score >= 60);
    }
}
