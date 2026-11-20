use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub mod perm {
    pub const ALL: &str = "*";
    pub const INSTANCES_READ: &str = "instances:read";
    pub const INSTANCES_DETAILS: &str = "instances:details";
    pub const INSTANCES_SCAN: &str = "instances:scan";
    pub const INSTANCES_CLONE: &str = "instances:clone";
    pub const SESSION_SSH: &str = "session:ssh";
    pub const SESSION_RDP: &str = "session:rdp";
    pub const FILES_TRANSFER: &str = "files:transfer";
    pub const NETWORK_FORWARD: &str = "network:forward";
    pub const K8S_READ: &str = "k8s:read";
    pub const K8S_CONNECT: &str = "k8s:connect";
    pub const K8S_SECRETS_READ: &str = "k8s:secrets:read";
    pub const K8S_EXEC: &str = "k8s:exec";
    pub const K8S_WRITE: &str = "k8s:write";
    pub const RECORDINGS_READ: &str = "recordings:read";
    pub const AI_USE: &str = "ai:use";
    pub const AI_CATALOG_MANAGE: &str = "ai_catalog:manage";
    pub const USERS_MANAGE: &str = "users:manage";
    pub const GROUPS_MANAGE: &str = "groups:manage";
    pub const ROLES_MANAGE: &str = "roles:manage";
    pub const SSO_MANAGE: &str = "sso:manage";
    pub const AWS_ACCOUNTS_MANAGE: &str = "aws_accounts:manage";
    pub const K8S_CLUSTERS_MANAGE: &str = "k8s_clusters:manage";
    pub const RECORDING_POLICY_MANAGE: &str = "recording_policy:manage";
    pub const AUDIT_READ: &str = "audit:read";
    pub const LICENSE_MANAGE: &str = "license:manage";
    pub const DB_VIEWER: &str = "db_viewer:read";
    pub const ACCESS_REQUESTS_APPROVE: &str = "access_requests:approve";
    pub const SESSIONS_MODERATE: &str = "sessions:moderate";
    pub const DLP_MANAGE: &str = "dlp:manage";
    pub const COMPLIANCE_MANAGE: &str = "compliance:manage";
    pub const MCP_MANAGE: &str = "mcp:manage";
    pub const AGENTS_MANAGE: &str = "agents:manage";
    pub const DEVICE_TRUST_MANAGE: &str = "device_trust:manage";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionInfo {
    pub id: &'static str,
    pub category: &'static str,
    pub description: &'static str,
}

pub const PERMISSION_CATALOG: &[PermissionInfo] = &[
    PermissionInfo {
        id: perm::ALL,
        category: "Administration",
        description: "Full administrative access across all resources and settings",
    },
    PermissionInfo {
        id: perm::INSTANCES_READ,
        category: "Instances",
        description: "View instance inventory and fleet summaries",
    },
    PermissionInfo {
        id: perm::INSTANCES_DETAILS,
        category: "Instances",
        description: "View instance metadata and details",
    },
    PermissionInfo {
        id: perm::INSTANCES_SCAN,
        category: "Instances",
        description: "Trigger EC2/fleet inventory scans",
    },
    PermissionInfo {
        id: perm::INSTANCES_CLONE,
        category: "Instances",
        description: "Clone EC2 instances",
    },
    PermissionInfo {
        id: perm::SESSION_SSH,
        category: "Sessions",
        description: "Open SSH/SSM terminal sessions and export terminal output",
    },
    PermissionInfo {
        id: perm::SESSION_RDP,
        category: "Sessions",
        description: "Open RDP/VNC remote desktop sessions",
    },
    PermissionInfo {
        id: perm::FILES_TRANSFER,
        category: "Sessions",
        description: "Browse directories and upload/download files",
    },
    PermissionInfo {
        id: perm::NETWORK_FORWARD,
        category: "Sessions",
        description: "Start and stop TCP port-forwarding tunnels",
    },
    PermissionInfo {
        id: perm::K8S_READ,
        category: "Kubernetes",
        description: "View Kubernetes clusters, workloads, and metrics",
    },
    PermissionInfo {
        id: perm::K8S_CONNECT,
        category: "Kubernetes",
        description: "Connect and disconnect personal/Teleport Kubernetes sessions",
    },
    PermissionInfo {
        id: perm::K8S_SECRETS_READ,
        category: "Kubernetes",
        description: "Inspect Kubernetes Secret resources",
    },
    PermissionInfo {
        id: perm::K8S_EXEC,
        category: "Kubernetes",
        description: "Stream pod logs, attach, and exec into containers",
    },
    PermissionInfo {
        id: perm::K8S_WRITE,
        category: "Kubernetes",
        description: "Delete, evict, edit, and scale Kubernetes resources",
    },
    PermissionInfo {
        id: perm::RECORDINGS_READ,
        category: "Operations",
        description: "View and download recorded sessions and exports",
    },
    PermissionInfo {
        id: perm::AI_USE,
        category: "Assistant",
        description: "Use AI assistant features and model queries",
    },
    PermissionInfo {
        id: perm::AI_CATALOG_MANAGE,
        category: "Administration",
        description: "Configure shared AI provider catalog",
    },
    PermissionInfo {
        id: perm::USERS_MANAGE,
        category: "Administration",
        description: "Create, edit, disable, and manage users",
    },
    PermissionInfo {
        id: perm::GROUPS_MANAGE,
        category: "Administration",
        description: "Create, edit, delete groups and manage group memberships",
    },
    PermissionInfo {
        id: perm::ROLES_MANAGE,
        category: "Administration",
        description: "Create custom roles and bind roles to groups",
    },
    PermissionInfo {
        id: perm::SSO_MANAGE,
        category: "Administration",
        description: "Manage OIDC/SAML providers and IdP group mappings",
    },
    PermissionInfo {
        id: perm::AWS_ACCOUNTS_MANAGE,
        category: "Administration",
        description: "Configure AWS accounts, role bindings, and AWS SSO shortcuts",
    },
    PermissionInfo {
        id: perm::K8S_CLUSTERS_MANAGE,
        category: "Administration",
        description: "Manage shared Kubernetes cluster configurations",
    },
    PermissionInfo {
        id: perm::RECORDING_POLICY_MANAGE,
        category: "Administration",
        description: "Configure SSH, RDP, and Kubernetes recording policies",
    },
    PermissionInfo {
        id: perm::AUDIT_READ,
        category: "Administration",
        description: "View and export tenant audit logs",
    },
    PermissionInfo {
        id: perm::LICENSE_MANAGE,
        category: "Administration",
        description: "Redeem and manage deployment licenses",
    },
    PermissionInfo {
        id: perm::DB_VIEWER,
        category: "Administration",
        description: "Access the internal database viewer",
    },
    PermissionInfo {
        id: perm::ACCESS_REQUESTS_APPROVE,
        category: "Governance",
        description: "Approve, deny, and revoke Just-In-Time access requests (four-eyes enforced)",
    },
    PermissionInfo {
        id: perm::SESSIONS_MODERATE,
        category: "Governance",
        description: "Shadow, freeze, unfreeze, and terminate live operator sessions",
    },
    PermissionInfo {
        id: perm::DLP_MANAGE,
        category: "Governance",
        description: "Configure inline database DLP masking and terminal command firewall rules",
    },
    PermissionInfo {
        id: perm::COMPLIANCE_MANAGE,
        category: "Compliance",
        description:
            "Manage quarterly access reviews and export signed compliance evidence bundles",
    },
    PermissionInfo {
        id: perm::MCP_MANAGE,
        category: "Governance",
        description:
            "Manage AI agent sponsors, MCP tokens, and tool invocation governance policies",
    },
    PermissionInfo {
        id: perm::AGENTS_MANAGE,
        category: "Administration",
        description: "Enroll and manage outbound hybrid mTLS reverse-tunnel agents",
    },
    PermissionInfo {
        id: perm::DEVICE_TRUST_MANAGE,
        category: "Governance",
        description: "Configure MDM device posture policies and attestations",
    },
];

#[must_use]
pub fn is_valid_permission(p: &str) -> bool {
    PERMISSION_CATALOG.iter().any(|info| info.id == p)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeType {
    #[default]
    Global,
    Environment,
    Instance,
    Cluster,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BindingConditions {
    #[serde(default)]
    pub source_cidrs: Vec<String>,
    #[serde(default)]
    pub allowed_hours_utc: Option<(u8, u8)>,
}

impl BindingConditions {
    #[must_use]
    pub fn matches(&self, client_ip: Option<IpAddr>, hour_utc: u8) -> bool {
        if let Some((start, end)) = self.allowed_hours_utc {
            let in_window = if start <= end {
                hour_utc >= start && hour_utc <= end
            } else {
                hour_utc >= start || hour_utc <= end
            };
            if !in_window {
                return false;
            }
        }
        if !self.source_cidrs.is_empty() {
            let Some(ip) = client_ip else {
                return false;
            };
            let matched = self.source_cidrs.iter().any(|cidr| cidr_contains(cidr, ip));
            if !matched {
                return false;
            }
        }
        true
    }
}

fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else {
        return cidr.parse::<IpAddr>().is_ok_and(|exact| exact == ip);
    };
    let Ok(net_ip) = net_str.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u8>() else {
        return false;
    };
    match (net_ip, ip) {
        (IpAddr::V4(n), IpAddr::V4(c)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(n) & mask) == (u32::from(c) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(c)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(n) & mask) == (u128::from(c) & mask)
        }
        _ => false,
    }
}

#[must_use]
pub fn normalize_role(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "admin" => "admin".to_owned(),
        "operator" | "user" => "user".to_owned(),
        "viewer" | "readonly" => "readonly".to_owned(),
        other => other.to_owned(),
    }
}

#[must_use]
pub fn base_role_permissions(role: &str) -> Vec<String> {
    match normalize_role(role).as_str() {
        "admin" => vec![perm::ALL.to_owned()],
        "user" => vec![
            perm::INSTANCES_READ,
            perm::INSTANCES_DETAILS,
            perm::INSTANCES_SCAN,
            perm::SESSION_SSH,
            perm::SESSION_RDP,
            perm::FILES_TRANSFER,
            perm::NETWORK_FORWARD,
            perm::K8S_READ,
            perm::K8S_CONNECT,
            perm::K8S_EXEC,
            perm::RECORDINGS_READ,
            perm::AI_USE,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        _ => vec![
            perm::INSTANCES_READ,
            perm::INSTANCES_DETAILS,
            perm::K8S_READ,
            perm::RECORDINGS_READ,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    }
}
