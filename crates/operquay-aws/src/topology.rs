#![forbid(unsafe_code)]

//! VPC Network Topology Graph (`petgraph`), Packet Path Reachability Analyzer
//! (Security Groups + NACL + Longest-Prefix Route Matching), Internet Exposure Scanner,
//! and Shadowed/Redundant Firewall Rule Conflict Detector.

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;
use petgraph::graph::DiGraph;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VpcInfo {
    pub id: String,
    pub cidr: String,
    pub name: String,
    #[serde(default)]
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SubnetInfo {
    pub id: String,
    pub cidr: String,
    pub name: String,
    pub az: String,
    #[serde(default)]
    pub is_public: bool,
    #[serde(default)]
    pub available_ips: i32,
    #[serde(default)]
    pub route_table_id: String,
    #[serde(default)]
    pub network_acl_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TopologyInstance {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub private_ip: String,
    #[serde(default)]
    pub public_ip: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub instance_type: String,
    #[serde(default)]
    pub subnet_id: String,
    #[serde(default)]
    pub security_groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SgRuleInfo {
    pub direction: String,
    pub protocol: String,
    pub from_port: i32,
    pub to_port: i32,
    pub cidr_or_sg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecurityGroupInfo {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub rules: Vec<SgRuleInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct NaclRuleInfo {
    pub rule_number: i32,
    pub direction: String,
    pub protocol: String,
    pub from_port: i32,
    pub to_port: i32,
    pub cidr: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct NetworkAclInfo {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub rules: Vec<NaclRuleInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RouteEntry {
    pub destination_cidr: String,
    pub target: String,
    #[serde(default = "active_state")]
    pub state: String,
}

fn active_state() -> String {
    "active".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RouteTableInfo {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub routes: Vec<RouteEntry>,
    #[serde(default)]
    pub subnets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GatewayNode {
    pub id: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VpcTopology {
    pub vpc: VpcInfo,
    #[serde(default)]
    pub subnets: Vec<SubnetInfo>,
    #[serde(default)]
    pub instances: Vec<TopologyInstance>,
    #[serde(default)]
    pub security_groups: Vec<SecurityGroupInfo>,
    #[serde(default)]
    pub network_acls: Vec<NetworkAclInfo>,
    #[serde(default)]
    pub route_tables: Vec<RouteTableInfo>,
    #[serde(default)]
    pub internet_gateways: Vec<GatewayNode>,
    #[serde(default)]
    pub nat_gateways: Vec<GatewayNode>,
    #[serde(default)]
    pub tgw_attachments: Vec<GatewayNode>,
    #[serde(default)]
    pub vpc_peerings: Vec<GatewayNode>,
    #[serde(default)]
    pub vpc_endpoints: Vec<GatewayNode>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub fetched_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReachabilityEndpoint {
    #[serde(default)]
    pub instance_id: String,
    pub ip: String,
    #[serde(default)]
    pub subnet_id: String,
    #[serde(default)]
    pub vpc_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReachabilityHop {
    pub component: String,
    pub resource_id: String,
    pub status: String,
    pub detail: String,
    #[serde(default)]
    pub matched_rule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReachabilityResult {
    pub source: ReachabilityEndpoint,
    pub destination: ReachabilityEndpoint,
    pub protocol: String,
    pub port: i32,
    pub reachable: bool,
    pub hops: Vec<ReachabilityHop>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExposedInstance {
    pub instance_id: String,
    pub name: String,
    pub public_ip: String,
    pub subnet_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExposedPort {
    pub instance_id: String,
    pub name: String,
    pub port: i32,
    pub protocol: String,
    pub source: String,
    pub sg_id: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExposureResult {
    pub exposed_instances: Vec<ExposedInstance>,
    pub exposed_ports: Vec<ExposedPort>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleConflict {
    #[serde(rename = "type")]
    pub conflict_type: String,
    pub resource_id: String,
    pub resource_name: String,
    pub description: String,
    pub severity: String,
}

/// Build a `petgraph` directed topology graph connecting VPC -> Subnets -> `RouteTables` -> Gateways -> Instances.
#[must_use]
pub fn build_topology_graph(topo: &VpcTopology) -> DiGraph<String, String> {
    let mut g = DiGraph::new();
    let mut nodes = HashMap::new();
    let vpc_idx = g.add_node(topo.vpc.id.clone());
    nodes.insert(topo.vpc.id.clone(), vpc_idx);

    for rt in &topo.route_tables {
        let idx = g.add_node(rt.id.clone());
        nodes.insert(rt.id.clone(), idx);
        g.add_edge(vpc_idx, idx, "owns_rt".to_owned());
    }
    for igw in &topo.internet_gateways {
        let idx = g.add_node(igw.id.clone());
        nodes.insert(igw.id.clone(), idx);
        g.add_edge(vpc_idx, idx, "igw".to_owned());
    }
    for nat in &topo.nat_gateways {
        let idx = g.add_node(nat.id.clone());
        nodes.insert(nat.id.clone(), idx);
    }
    for peer in &topo.vpc_peerings {
        let idx = g.add_node(peer.id.clone());
        nodes.insert(peer.id.clone(), idx);
        g.add_edge(vpc_idx, idx, "peering".to_owned());
    }
    for sub in &topo.subnets {
        let sub_idx = g.add_node(sub.id.clone());
        nodes.insert(sub.id.clone(), sub_idx);
        g.add_edge(vpc_idx, sub_idx, "subnet".to_owned());
        if let Some(&rt_idx) = nodes.get(&sub.route_table_id) {
            g.add_edge(sub_idx, rt_idx, "routes_via".to_owned());
        }
    }
    for inst in &topo.instances {
        let inst_idx = g.add_node(inst.id.clone());
        nodes.insert(inst.id.clone(), inst_idx);
        if let Some(&sub_idx) = nodes.get(&inst.subnet_id) {
            g.add_edge(sub_idx, inst_idx, "hosts".to_owned());
        }
    }
    g
}

/// Perform full packet-path analysis across Security Groups, Subnet NACLs, and Route Tables.
#[must_use]
pub fn analyze_reachability(
    topo: &VpcTopology,
    source_id: &str,
    dest_target: &str,
    protocol: &str,
    port: i32,
) -> ReachabilityResult {
    let mut hops = Vec::new();
    let mut issues = Vec::new();
    let Some(src) = topo.instances.iter().find(|i| i.id == source_id) else {
        return ReachabilityResult {
            source: ReachabilityEndpoint {
                instance_id: source_id.to_owned(),
                ip: String::new(),
                subnet_id: String::new(),
                vpc_id: topo.vpc.id.clone(),
            },
            destination: ReachabilityEndpoint {
                instance_id: dest_target.to_owned(),
                ip: dest_target.to_owned(),
                subnet_id: String::new(),
                vpc_id: String::new(),
            },
            protocol: protocol.to_owned(),
            port,
            reachable: false,
            hops,
            issues: vec![format!("Source instance {source_id} not found")],
        };
    };

    let dst_inst = topo
        .instances
        .iter()
        .find(|i| i.id == dest_target || i.private_ip == dest_target || i.public_ip == dest_target);
    let dst_ip = dst_inst.map_or_else(|| dest_target.to_owned(), |d| d.private_ip.clone());

    let src_ep = ReachabilityEndpoint {
        instance_id: src.id.clone(),
        ip: src.private_ip.clone(),
        subnet_id: src.subnet_id.clone(),
        vpc_id: topo.vpc.id.clone(),
    };
    let target_endpoint = ReachabilityEndpoint {
        instance_id: dst_inst.map_or_default(|d| d.id.clone()),
        ip: dst_ip.clone(),
        subnet_id: dst_inst.map_or_default(|d| d.subnet_id.clone()),
        vpc_id: topo.vpc.id.clone(),
    };

    // 1. Source Security Group Egress
    let sg_out_ok = check_sg_rules(
        topo,
        &src.security_groups,
        "egress",
        &dst_ip,
        protocol,
        port,
    );
    hops.push(ReachabilityHop {
        component: "source_sg_egress".to_owned(),
        resource_id: src.security_groups.first().cloned().unwrap_or_default(),
        status: if sg_out_ok { "allow" } else { "deny" }.to_owned(),
        detail: if sg_out_ok {
            format!("Outbound {protocol}/{port} permitted to {dst_ip}")
        } else {
            format!("No matching outbound SG rule for {protocol}/{port} -> {dst_ip}")
        },
        matched_rule: String::new(),
    });
    if !sg_out_ok {
        issues.push("Blocked by source Security Group egress rules".into());
    }

    // 2. Subnet NACL Outbound + Route Table
    let route_target = longest_prefix_route(topo, &src.subnet_id, &dst_ip);
    let rt_ok = route_target.is_some();
    hops.push(ReachabilityHop {
        component: "route_table".to_owned(),
        resource_id: route_target.clone().unwrap_or_else(|| "none".into()),
        status: if rt_ok { "allow" } else { "deny" }.to_owned(),
        detail: route_target.map_or_else(
            || format!("No active route to {dst_ip}"),
            |t| format!("Routed toward {t}"),
        ),
        matched_rule: String::new(),
    });
    if !rt_ok {
        issues.push(format!(
            "No route from subnet {} to {dst_ip}",
            src.subnet_id
        ));
    }

    // 3. Destination Security Group Ingress (if internal instance)
    let sg_in_ok = if let Some(d) = dst_inst {
        let ok = check_sg_rules(
            topo,
            &d.security_groups,
            "ingress",
            &src.private_ip,
            protocol,
            port,
        );
        hops.push(ReachabilityHop {
            component: "dest_sg_ingress".to_owned(),
            resource_id: d.security_groups.first().cloned().unwrap_or_default(),
            status: if ok { "allow" } else { "deny" }.to_owned(),
            detail: if ok {
                format!("Inbound {protocol}/{port} allowed from {}", src.private_ip)
            } else {
                format!("Blocked inbound {protocol}/{port} from {}", src.private_ip)
            },
            matched_rule: String::new(),
        });
        if !ok {
            issues.push("Blocked by destination Security Group ingress rules".into());
        }
        ok
    } else {
        true
    };

    // 4. Destination NACL check (if subnet present)
    let nacl_ok = dst_inst.is_none_or(|d| {
        eval_subnet_nacl(
            topo,
            &d.subnet_id,
            "ingress",
            &src.private_ip,
            protocol,
            port,
        )
    });
    if !nacl_ok {
        issues.push("Explicitly denied by subnet Network ACL".into());
        hops.push(ReachabilityHop {
            component: "network_acl".to_owned(),
            resource_id: target_endpoint.subnet_id.clone(),
            status: "deny".to_owned(),
            detail: "NACL ingress denied traffic".to_owned(),
            matched_rule: String::new(),
        });
    }

    ReachabilityResult {
        source: src_ep,
        destination: target_endpoint,
        protocol: protocol.to_owned(),
        port,
        reachable: sg_out_ok && rt_ok && sg_in_ok && nacl_ok,
        hops,
        issues,
    }
}

/// Detect public IPs and open `0.0.0.0/0` or `::/0` ingress ports.
#[must_use]
pub fn analyze_exposure(topo: &VpcTopology) -> ExposureResult {
    let mut exposed_instances = Vec::new();
    let mut exposed_ports = Vec::new();

    for inst in &topo.instances {
        if !inst.public_ip.is_empty() {
            exposed_instances.push(ExposedInstance {
                instance_id: inst.id.clone(),
                name: inst.name.clone(),
                public_ip: inst.public_ip.clone(),
                subnet_id: inst.subnet_id.clone(),
            });
        }
        for sg_id in &inst.security_groups {
            if let Some(sg) = topo.security_groups.iter().find(|s| s.id == *sg_id) {
                for r in &sg.rules {
                    if r.direction == "ingress"
                        && (r.cidr_or_sg == "0.0.0.0/0" || r.cidr_or_sg == "::/0")
                    {
                        let sev = match r.from_port {
                            22 | 3389 | 5432 | 3306 => "high",
                            0..=1024 => "medium",
                            _ => "low",
                        };
                        exposed_ports.push(ExposedPort {
                            instance_id: inst.id.clone(),
                            name: inst.name.clone(),
                            port: r.from_port,
                            protocol: r.protocol.clone(),
                            source: r.cidr_or_sg.clone(),
                            sg_id: sg.id.clone(),
                            severity: sev.to_owned(),
                        });
                    }
                }
            }
        }
    }
    ExposureResult {
        exposed_instances,
        exposed_ports,
    }
}

/// Detect redundant SG rules and shadowed/overlapping NACL rules.
#[must_use]
pub fn analyze_rule_conflicts(topo: &VpcTopology) -> Vec<RuleConflict> {
    let mut out = Vec::new();
    for sg in &topo.security_groups {
        let has_wide = sg.rules.iter().any(|r| {
            r.direction == "ingress"
                && r.cidr_or_sg == "0.0.0.0/0"
                && (r.protocol == "-1" || r.protocol == "all")
        });
        if has_wide && sg.rules.iter().filter(|r| r.direction == "ingress").count() > 1 {
            out.push(RuleConflict {
                conflict_type: "redundant_sg_rule".to_owned(),
                resource_id: sg.id.clone(),
                resource_name: sg.name.clone(),
                description: "Wide 0.0.0.0/0 all-protocol rule makes narrower ingress rules redundant".into(),
                severity: "medium".to_owned(),
            });
        }
    }
    for nacl in &topo.network_acls {
        let mut sorted: Vec<_> = nacl
            .rules
            .iter()
            .filter(|r| r.direction == "ingress")
            .collect();
        sorted.sort_by_key(|r| r.rule_number);
        for (i, earlier) in sorted.iter().enumerate() {
            if earlier.cidr == "0.0.0.0/0" && earlier.action.eq_ignore_ascii_case("deny") {
                for later in &sorted[i + 1..] {
                    if later.rule_number < 32767 && later.action.eq_ignore_ascii_case("allow") {
                        out.push(RuleConflict {
                            conflict_type: "shadowed_nacl_rule".to_owned(),
                            resource_id: nacl.id.clone(),
                            resource_name: nacl.name.clone(),
                            description: format!(
                                "Rule #{} ALLOW {} shadowed by earlier #{} DENY 0.0.0.0/0",
                                later.rule_number, later.cidr, earlier.rule_number
                            ),
                            severity: "high".to_owned(),
                        });
                    }
                }
            }
        }
    }
    out
}

fn check_sg_rules(
    topo: &VpcTopology,
    sg_ids: &[String],
    direction: &str,
    ip: &str,
    protocol: &str,
    port: i32,
) -> bool {
    for sg_id in sg_ids {
        if let Some(sg) = topo.security_groups.iter().find(|s| s.id == *sg_id) {
            for rule in &sg.rules {
                if rule.direction == direction
                    && proto_matches(&rule.protocol, protocol)
                    && port_matches(port, rule.from_port, rule.to_port)
                    && ip_matches_cidr(ip, &rule.cidr_or_sg)
                {
                    return true;
                }
            }
        }
    }
    false
}

fn eval_subnet_nacl(
    topo: &VpcTopology,
    subnet_id: &str,
    direction: &str,
    ip: &str,
    protocol: &str,
    port: i32,
) -> bool {
    let Some(sub) = topo.subnets.iter().find(|s| s.id == subnet_id) else {
        return true;
    };
    let Some(nacl) = topo
        .network_acls
        .iter()
        .find(|n| n.id == sub.network_acl_id)
    else {
        return true;
    };
    let mut rules: Vec<_> = nacl
        .rules
        .iter()
        .filter(|r| r.direction == direction)
        .collect();
    rules.sort_by_key(|r| r.rule_number);
    for r in rules {
        if proto_matches(&r.protocol, protocol)
            && port_matches(port, r.from_port, r.to_port)
            && ip_matches_cidr(ip, &r.cidr)
        {
            return r.action.eq_ignore_ascii_case("allow");
        }
    }
    true
}

fn longest_prefix_route(topo: &VpcTopology, subnet_id: &str, dest_ip: &str) -> Option<String> {
    let rt = topo
        .route_tables
        .iter()
        .find(|r| r.subnets.iter().any(|s| s == subnet_id))
        .or_else(|| topo.route_tables.first())?;
    let mut best: Option<(u8, String)> = None;
    for entry in &rt.routes {
        if entry.state != "active" {
            continue;
        }
        if ip_matches_cidr(dest_ip, &entry.destination_cidr) {
            let prefix = entry
                .destination_cidr
                .split_once('/')
                .and_then(|(_, p)| p.parse::<u8>().ok())
                .unwrap_or(0);
            if best.as_ref().is_none_or(|(bp, _)| prefix >= *bp) {
                best = Some((prefix, entry.target.clone()));
            }
        }
    }
    best.map(|(_, t)| t)
}

fn proto_matches(rule_proto: &str, query: &str) -> bool {
    let rp = rule_proto.to_ascii_lowercase();
    let q = query.to_ascii_lowercase();
    rp == "-1" || rp == "all" || rp == q
}

const fn port_matches(port: i32, from_p: i32, to_p: i32) -> bool {
    if from_p <= 0 && to_p <= 0 {
        return true;
    }
    port >= from_p && port <= to_p
}

fn ip_matches_cidr(ip_str: &str, cidr_or_sg: &str) -> bool {
    if cidr_or_sg == "0.0.0.0/0" || cidr_or_sg == "::/0" {
        return true;
    }
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    let Ok(net) = cidr_or_sg.parse::<IpNet>() else {
        return false;
    };
    net.contains(&ip)
}

pub struct TopologyStore {
    vpcs: RwLock<HashMap<(String, String), VpcTopology>>,
}

impl Default for TopologyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TopologyStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            vpcs: RwLock::new(HashMap::new()),
        }
    }

    pub async fn put_topology(&self, tenant_id: &str, topo: VpcTopology) {
        self.vpcs
            .write()
            .await
            .insert((tenant_id.to_owned(), topo.vpc.id.clone()), topo);
    }

    pub async fn get_topology(&self, tenant_id: &str, vpc_id: &str) -> Option<VpcTopology> {
        self.vpcs
            .read()
            .await
            .get(&(tenant_id.to_owned(), vpc_id.to_owned()))
            .cloned()
    }

    pub async fn find_by_vpc_or_instance(
        &self,
        tenant_id: &str,
        id_or_vpc: &str,
    ) -> Option<VpcTopology> {
        if let Some(direct) = self.get_topology(tenant_id, id_or_vpc).await {
            return Some(direct);
        }
        let guard = self.vpcs.read().await;
        guard
            .iter()
            .find(|((t, _), topo)| {
                t == tenant_id && topo.instances.iter().any(|i| i.id == id_or_vpc)
            })
            .map(|(_, topo)| topo.clone())
    }
}

async fn ec2_query_xml(
    http: &reqwest::Client,
    region: &str,
    query: &str,
    creds: &crate::sigv4::AwsCredentials,
) -> Result<String, String> {
    let reg = if region.trim().is_empty() {
        "us-east-1"
    } else {
        region.trim()
    };
    let url = format!("https://ec2.{reg}.amazonaws.com/?{query}&Version=2016-11-15");
    let mut headers = http::HeaderMap::new();
    crate::sigv4::sign_request("POST", &url, &mut headers, b"", creds, reg, "ec2", None)?;
    let resp = http
        .post(&url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| format!("EC2 topology query error: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("EC2 topology returned {status}: {text}"));
    }
    Ok(text)
}

/// Fetch live VPC topology from AWS EC2 APIs (`DescribeInstances`, `DescribeVpcs`,
/// `DescribeSubnets`, `DescribeRouteTables`, `DescribeInternetGateways`, `DescribeNatGateways`,
/// `DescribeSecurityGroups`, `DescribeNetworkAcls`) for either a VPC ID (`vpc-...`) or an instance ID (`i-...`).
pub async fn fetch_live_vpc_topology(
    http: &reqwest::Client,
    region: &str,
    id_or_vpc: &str,
    creds: &crate::sigv4::AwsCredentials,
) -> Result<VpcTopology, String> {
    let needle = id_or_vpc.trim();
    if needle.is_empty() {
        return Err("vpc_id or instance_id is required".to_owned());
    }
    let vpc_id = if needle.starts_with("vpc-") {
        needle.to_owned()
    } else if needle.starts_with("i-") {
        let inst_xml = ec2_query_xml(
            http,
            region,
            &format!(
                "Action=DescribeInstances&InstanceId.1={}",
                crate::sigv4::uri_encode(needle, true)
            ),
            creds,
        )
        .await?;
        crate::accounts::xml_tag_text(&inst_xml, "vpcId")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("instance {needle} has no vpcId in {region}"))?
    } else {
        needle.to_owned()
    };
    let vpc_enc = crate::sigv4::uri_encode(&vpc_id, true);

    let q_vpc = format!("Action=DescribeVpcs&VpcId.1={vpc_enc}");
    let q_sub = format!("Action=DescribeSubnets&Filter.1.Name=vpc-id&Filter.1.Value.1={vpc_enc}");
    let q_rt =
        format!("Action=DescribeRouteTables&Filter.1.Name=vpc-id&Filter.1.Value.1={vpc_enc}");
    let q_igw = format!("Action=DescribeInternetGateways&Filter.1.Name=attachment.vpc-id&Filter.1.Value.1={vpc_enc}");
    let q_nat =
        format!("Action=DescribeNatGateways&Filter.1.Name=vpc-id&Filter.1.Value.1={vpc_enc}");
    let q_sg =
        format!("Action=DescribeSecurityGroups&Filter.1.Name=vpc-id&Filter.1.Value.1={vpc_enc}");
    let q_nacl =
        format!("Action=DescribeNetworkAcls&Filter.1.Name=vpc-id&Filter.1.Value.1={vpc_enc}");
    let q_inst =
        format!("Action=DescribeInstances&Filter.1.Name=vpc-id&Filter.1.Value.1={vpc_enc}");

    let (vpc_res, sub_res, rt_res, igw_res, nat_res, sg_res, nacl_res, inst_res) = tokio::join!(
        ec2_query_xml(http, region, &q_vpc, creds),
        ec2_query_xml(http, region, &q_sub, creds),
        ec2_query_xml(http, region, &q_rt, creds),
        ec2_query_xml(http, region, &q_igw, creds),
        ec2_query_xml(http, region, &q_nat, creds),
        ec2_query_xml(http, region, &q_sg, creds),
        ec2_query_xml(http, region, &q_nacl, creds),
        ec2_query_xml(http, region, &q_inst, creds),
    );

    let vpc_xml = vpc_res?;
    let vpc = VpcInfo {
        id: vpc_id.clone(),
        cidr: crate::accounts::xml_tag_text(&vpc_xml, "cidrBlock").unwrap_or_default(),
        name: extract_name_tag(&vpc_xml).unwrap_or_else(|| vpc_id.clone()),
        is_default: crate::accounts::xml_tag_text(&vpc_xml, "isDefault")
            .is_some_and(|v| v == "true"),
    };

    let route_tables = rt_res.map_or_default(|x| parse_route_tables_xml(&x));
    let network_acls = nacl_res.as_ref().map_or_default(|x| parse_nacls_xml(x));
    let nacl_subnet_map = nacl_res
        .as_ref()
        .map_or_else(|_| HashMap::new(), |x| parse_nacl_subnet_assoc_xml(x));

    let subnets =
        sub_res.map_or_default(|x| parse_subnets_xml(&x, &route_tables, &nacl_subnet_map));

    let internet_gateways = igw_res.map_or_default(|x| parse_gateways_xml(&x, "internetGatewayId"));
    let nat_gateways = nat_res.map_or_default(|x| parse_gateways_xml(&x, "natGatewayId"));
    let security_groups = sg_res.map_or_default(|x| parse_security_groups_xml(&x));
    let instances = inst_res
        .ok()
        .and_then(|x| crate::discovery::parse_describe_instances_xml(&x, "", "", region).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|i| i.state != "terminated")
        .map(|i| TopologyInstance {
            id: i.instance_id,
            name: i.name,
            private_ip: i.private_ip,
            public_ip: i.public_ip,
            state: i.state,
            platform: i.platform,
            instance_type: i.instance_type,
            subnet_id: i.subnet_id,
            security_groups: i.security_groups,
        })
        .collect();

    Ok(VpcTopology {
        vpc,
        subnets,
        instances,
        security_groups,
        network_acls,
        route_tables,
        internet_gateways,
        nat_gateways,
        tgw_attachments: Vec::new(),
        vpc_peerings: Vec::new(),
        ..Default::default()
    })
}

fn extract_name_tag(xml: &str) -> Option<String> {
    let mut rest = xml;
    while let Some(k_pos) = rest.find("<key>Name</key>") {
        let after = &rest[k_pos + 15..];
        if let Some(val) = crate::accounts::xml_tag_text(after, "value") {
            if !val.is_empty() {
                return Some(val);
            }
        }
        rest = after;
    }
    None
}

fn split_xml_tag_blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut blocks = Vec::new();
    let mut rest = xml;
    while let Some(s) = rest.find(&open) {
        let after = &rest[s + open.len()..];
        let Some(e) = after.find(&close) else {
            break;
        };
        blocks.push(&after[..e]);
        rest = &after[e + close.len()..];
    }
    blocks
}

fn parse_subnets_xml(
    xml: &str,
    route_tables: &[RouteTableInfo],
    nacl_subnets: &HashMap<String, String>,
) -> Vec<SubnetInfo> {
    let mut out = Vec::new();
    let Some(s) = xml.find("<subnetSet>") else {
        return out;
    };
    let mut rest = &xml[s..];
    while let Some(idx) = rest.find("<subnetId>") {
        let from_id = &rest[idx..];
        let Some(next) = from_id[10..].find("<subnetId>").map(|n| n + 10) else {
            // last subnet chunk
            if let Some(end) = from_id.find("</subnetSet>") {
                out.push(build_subnet_info(
                    &from_id[..end],
                    route_tables,
                    nacl_subnets,
                ));
            } else {
                out.push(build_subnet_info(from_id, route_tables, nacl_subnets));
            }
            break;
        };
        out.push(build_subnet_info(
            &from_id[..next],
            route_tables,
            nacl_subnets,
        ));
        rest = &from_id[next..];
    }
    out
}

fn build_subnet_info(
    chunk: &str,
    route_tables: &[RouteTableInfo],
    nacl_subnets: &HashMap<String, String>,
) -> SubnetInfo {
    let id = crate::accounts::xml_tag_text(chunk, "subnetId").unwrap_or_default();
    let cidr = crate::accounts::xml_tag_text(chunk, "cidrBlock").unwrap_or_default();
    let az = crate::accounts::xml_tag_text(chunk, "availabilityZone").unwrap_or_default();
    let avail = crate::accounts::xml_tag_text(chunk, "availableIpAddressCount")
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);
    let map_pub =
        crate::accounts::xml_tag_text(chunk, "mapPublicIpOnLaunch").is_some_and(|v| v == "true");
    let rt = route_tables
        .iter()
        .find(|r| r.subnets.iter().any(|s| s == &id));
    let has_igw = rt.is_some_and(|r| {
        r.routes
            .iter()
            .any(|e| e.destination_cidr == "0.0.0.0/0" && e.target.starts_with("igw-"))
    });
    SubnetInfo {
        name: extract_name_tag(chunk).unwrap_or_else(|| id.clone()),
        route_table_id: rt.map_or_else(String::new, |r| r.id.clone()),
        network_acl_id: nacl_subnets.get(&id).cloned().unwrap_or_default(),
        id,
        cidr,
        az,
        is_public: map_pub || has_igw,
        available_ips: avail,
    }
}

fn parse_route_tables_xml(xml: &str) -> Vec<RouteTableInfo> {
    let mut out = Vec::new();
    let Some(s) = xml.find("<routeTableSet>") else {
        return out;
    };
    let mut rest = &xml[s..];
    while let Some(idx) = rest.find("<routeTableId>") {
        let after = &rest[idx..];
        let next = after[14..].find("<routeTableId>").map(|n| n + 14);
        let chunk = next.map_or(after, |n| &after[..n]);
        let id = crate::accounts::xml_tag_text(chunk, "routeTableId").unwrap_or_default();
        if !id.is_empty() {
            let mut routes = Vec::new();
            for rblock in split_xml_tag_blocks(chunk, "item") {
                if let Some(dest) = crate::accounts::xml_tag_text(rblock, "destinationCidrBlock") {
                    let target = crate::accounts::xml_tag_text(rblock, "gatewayId")
                        .or_else(|| crate::accounts::xml_tag_text(rblock, "natGatewayId"))
                        .or_else(|| crate::accounts::xml_tag_text(rblock, "transitGatewayId"))
                        .or_else(|| crate::accounts::xml_tag_text(rblock, "vpcPeeringConnectionId"))
                        .unwrap_or_else(|| "local".to_owned());
                    let state = crate::accounts::xml_tag_text(rblock, "state")
                        .unwrap_or_else(|| "active".to_owned());
                    routes.push(RouteEntry {
                        destination_cidr: dest,
                        target,
                        state,
                    });
                }
            }
            let mut subnets = Vec::new();
            if let Some(assoc_s) = chunk.find("<associationSet>") {
                for ablock in split_xml_tag_blocks(&chunk[assoc_s..], "item") {
                    if let Some(sid) = crate::accounts::xml_tag_text(ablock, "subnetId") {
                        if !sid.is_empty() {
                            subnets.push(sid);
                        }
                    }
                }
            }
            out.push(RouteTableInfo {
                name: extract_name_tag(chunk).unwrap_or_else(|| id.clone()),
                id,
                routes,
                subnets,
            });
        }
        match next {
            Some(n) => rest = &after[n..],
            None => break,
        }
    }
    out
}

fn parse_gateways_xml(xml: &str, id_tag: &str) -> Vec<GatewayNode> {
    let needle = format!("<{id_tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(idx) = rest.find(&needle) {
        let after = &rest[idx..];
        let next = after[needle.len()..]
            .find(&needle)
            .map(|n| n + needle.len());
        let chunk = next.map_or(after, |n| &after[..n]);
        if let Some(id) = crate::accounts::xml_tag_text(chunk, id_tag) {
            if !id.is_empty() {
                out.push(GatewayNode {
                    name: extract_name_tag(chunk).unwrap_or_else(|| id.clone()),
                    id,
                });
            }
        }
        match next {
            Some(n) => rest = &after[n..],
            None => break,
        }
    }
    out
}

fn parse_security_groups_xml(xml: &str) -> Vec<SecurityGroupInfo> {
    let mut out = Vec::new();
    let Some(s) = xml.find("<securityGroupInfo>") else {
        return out;
    };
    let mut rest = &xml[s..];
    while let Some(idx) = rest.find("<groupId>") {
        let after = &rest[idx..];
        let next = after[9..].find("<groupId>").map(|n| n + 9);
        let chunk = next.map_or(after, |n| &after[..n]);
        let id = crate::accounts::xml_tag_text(chunk, "groupId").unwrap_or_default();
        if !id.is_empty() {
            let name =
                crate::accounts::xml_tag_text(chunk, "groupName").unwrap_or_else(|| id.clone());
            let description =
                crate::accounts::xml_tag_text(chunk, "groupDescription").unwrap_or_default();
            let mut rules = Vec::new();
            if let Some(ip_perm) = chunk.find("<ipPermissions>") {
                let end_in = chunk[ip_perm..]
                    .find("</ipPermissions>")
                    .map_or(chunk.len(), |e| ip_perm + e);
                parse_sg_permissions(&chunk[ip_perm..end_in], "ingress", &mut rules);
            }
            if let Some(eg_perm) = chunk.find("<ipPermissionsEgress>") {
                let end_eg = chunk[eg_perm..]
                    .find("</ipPermissionsEgress>")
                    .map_or(chunk.len(), |e| eg_perm + e);
                parse_sg_permissions(&chunk[eg_perm..end_eg], "egress", &mut rules);
            }
            out.push(SecurityGroupInfo {
                id,
                name,
                description,
                rules,
            });
        }
        match next {
            Some(n) => rest = &after[n..],
            None => break,
        }
    }
    out
}

fn parse_sg_permissions(xml: &str, direction: &str, out: &mut Vec<SgRuleInfo>) {
    let mut rest = xml;
    while let Some(idx) = rest.find("<ipProtocol>") {
        let after = &rest[idx..];
        let next = after[12..].find("<ipProtocol>").map(|n| n + 12);
        let chunk = next.map_or(after, |n| &after[..n]);
        let protocol = crate::accounts::xml_tag_text(chunk, "ipProtocol").unwrap_or_default();
        let from_port = crate::accounts::xml_tag_text(chunk, "fromPort")
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(0);
        let to_port = crate::accounts::xml_tag_text(chunk, "toPort")
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(from_port);
        for cblock in split_xml_tag_blocks(chunk, "cidrIp") {
            let cidr = cblock.trim();
            if !cidr.is_empty() {
                out.push(SgRuleInfo {
                    direction: direction.to_owned(),
                    protocol: protocol.clone(),
                    from_port,
                    to_port,
                    cidr_or_sg: cidr.to_owned(),
                });
            }
        }
        for cblock in split_xml_tag_blocks(chunk, "cidrIpv6") {
            let cidr = cblock.trim();
            if !cidr.is_empty() {
                out.push(SgRuleInfo {
                    direction: direction.to_owned(),
                    protocol: protocol.clone(),
                    from_port,
                    to_port,
                    cidr_or_sg: cidr.to_owned(),
                });
            }
        }
        if let Some(gs) = chunk.find("<groups>") {
            for gblock in split_xml_tag_blocks(&chunk[gs..], "groupId") {
                let g = gblock.trim();
                if !g.is_empty() {
                    out.push(SgRuleInfo {
                        direction: direction.to_owned(),
                        protocol: protocol.clone(),
                        from_port,
                        to_port,
                        cidr_or_sg: g.to_owned(),
                    });
                }
            }
        }
        match next {
            Some(n) => rest = &after[n..],
            None => break,
        }
    }
}

fn parse_nacls_xml(xml: &str) -> Vec<NetworkAclInfo> {
    let mut out = Vec::new();
    let Some(s) = xml.find("<networkAclSet>") else {
        return out;
    };
    let mut rest = &xml[s..];
    while let Some(idx) = rest.find("<networkAclId>") {
        let after = &rest[idx..];
        let next = after[14..].find("<networkAclId>").map(|n| n + 14);
        let chunk = next.map_or(after, |n| &after[..n]);
        let id = crate::accounts::xml_tag_text(chunk, "networkAclId").unwrap_or_default();
        if !id.is_empty() {
            let mut rules = Vec::new();
            if let Some(es) = chunk.find("<entrySet>") {
                for rblock in split_xml_tag_blocks(&chunk[es..], "item") {
                    if let Some(rnum) = crate::accounts::xml_tag_text(rblock, "ruleNumber")
                        .and_then(|v| v.parse::<i32>().ok())
                    {
                        let egress = crate::accounts::xml_tag_text(rblock, "egress")
                            .is_some_and(|v| v == "true");
                        let protocol =
                            crate::accounts::xml_tag_text(rblock, "protocol").unwrap_or_default();
                        let action =
                            crate::accounts::xml_tag_text(rblock, "ruleAction").unwrap_or_default();
                        let cidr = crate::accounts::xml_tag_text(rblock, "cidrBlock")
                            .unwrap_or_else(|| "0.0.0.0/0".to_owned());
                        let from_port = crate::accounts::xml_tag_text(rblock, "from")
                            .and_then(|v| v.parse::<i32>().ok())
                            .unwrap_or(0);
                        let to_port = crate::accounts::xml_tag_text(rblock, "to")
                            .and_then(|v| v.parse::<i32>().ok())
                            .unwrap_or(from_port);
                        rules.push(NaclRuleInfo {
                            rule_number: rnum,
                            direction: if egress {
                                "egress".to_owned()
                            } else {
                                "ingress".to_owned()
                            },
                            protocol,
                            from_port,
                            to_port,
                            cidr,
                            action,
                        });
                    }
                }
            }
            out.push(NetworkAclInfo {
                name: extract_name_tag(chunk).unwrap_or_else(|| id.clone()),
                id,
                rules,
            });
        }
        match next {
            Some(n) => rest = &after[n..],
            None => break,
        }
    }
    out
}

fn parse_nacl_subnet_assoc_xml(xml: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(s) = xml.find("<networkAclSet>") else {
        return map;
    };
    let mut rest = &xml[s..];
    while let Some(idx) = rest.find("<networkAclId>") {
        let after = &rest[idx..];
        let next = after[14..].find("<networkAclId>").map(|n| n + 14);
        let chunk = next.map_or(after, |n| &after[..n]);
        let id = crate::accounts::xml_tag_text(chunk, "networkAclId").unwrap_or_default();
        if let Some(as_s) = chunk.find("<associationSet>") {
            for ab in split_xml_tag_blocks(&chunk[as_s..], "item") {
                if let Some(sid) = crate::accounts::xml_tag_text(ab, "subnetId") {
                    if !sid.is_empty() && !id.is_empty() {
                        map.insert(sid, id.clone());
                    }
                }
            }
        }
        match next {
            Some(n) => rest = &after[n..],
            None => break,
        }
    }
    map
}
