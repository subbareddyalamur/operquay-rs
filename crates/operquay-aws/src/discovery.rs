#![forbid(unsafe_code)]

//! EC2 / SSM fleet discovery, region scanning, instance details/metrics (`CloudWatch`),
//! and tenant-scoped inventory caching.

use std::collections::HashMap;
use std::time::Duration;

use quick_xml::events::{BytesRef, Event};
use quick_xml::Reader;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::sigv4::{now_unix_secs, sign_request, AwsCredentials};
use crate::transfer::SsmTransferClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ec2Instance {
    pub instance_id: String,
    pub name: String,
    pub state: String,
    pub instance_type: String,
    pub platform: String,
    pub private_ip: String,
    pub public_ip: String,
    pub region: String,
    pub availability_zone: String,
    pub vpc_id: String,
    pub subnet_id: String,
    pub account_id: String,
    pub profile: String,
    pub ssm_online: bool,
    #[serde(default)]
    pub tags: HashMap<String, String>,
    #[serde(default)]
    pub security_groups: Vec<String>,
    pub launch_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeEc2Instance {
    pub instance_id: String,
    pub name: String,
    pub state: String,
    pub platform: String,
    pub os: String,
    pub instance_type: String,
    pub aws_profile: String,
    pub aws_region: String,
    pub account_id: String,
    pub account_alias: String,
    pub tag1_value: String,
    pub tag2_value: String,
    pub private_ip: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub public_ip: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub vpc_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subnet_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub launch_time: String,
    #[serde(default)]
    pub security_groups: Vec<String>,
    #[serde(default)]
    pub tags: HashMap<String, String>,
    pub ssm_online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagGroup {
    pub tag1: String,
    pub tag2: String,
    pub instances: Vec<TreeEc2Instance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionNode {
    pub region: String,
    pub groups: Vec<TagGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountNode {
    pub provider: String,
    pub account_id: String,
    pub account_alias: String,
    pub profile: String,
    pub regions: Vec<RegionNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InstanceTree {
    pub accounts: Vec<AccountNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiscoveryStatus {
    #[serde(default = "default_idle_status")]
    pub status: String,
    pub discovering: bool,
    pub total_accounts: usize,
    pub fetched_accounts: usize,
    pub total_regions: usize,
    pub fetched_regions: usize,
    pub total_instances: usize,
    pub instance_count: usize,
    pub last_discovery_unix: i64,
    #[serde(default)]
    pub last_error: String,
    #[serde(default)]
    pub message: String,
}

fn default_idle_status() -> String {
    "idle".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FleetStats {
    pub total: usize,
    pub running: usize,
    pub stopped: usize,
    pub ssm_online: usize,
    pub windows: usize,
    pub linux: usize,
    pub regions: usize,
    pub vpcs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionFleetSummary {
    pub region: String,
    pub total: usize,
    pub running: usize,
    pub stopped: usize,
    pub ssm_online: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceMetrics {
    pub instance_id: String,
    pub region: String,
    pub cpu_utilization_pct: f64,
    pub network_in_bytes: f64,
    pub network_out_bytes: f64,
    pub status_check_failed: f64,
    #[serde(default)]
    pub cpu_load: Option<f64>,
    #[serde(default)]
    pub cpu_count: Option<u32>,
    #[serde(default)]
    pub mem_used_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_total_mb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_used_mb: Option<u64>,
    #[serde(default)]
    pub disk_used_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_total_gb: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_used_gb: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub sampled_at_unix: i64,
}

pub struct Ec2DiscoveryStore {
    cache: RwLock<HashMap<String, Vec<Ec2Instance>>>,
    status: RwLock<HashMap<String, DiscoveryStatus>>,
    http: reqwest::Client,
    ec2_endpoint_override: Option<String>,
}

impl Default for Ec2DiscoveryStore {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Ec2DiscoveryStore {
    #[must_use]
    pub fn new(ec2_endpoint_override: Option<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self {
            cache: RwLock::new(HashMap::new()),
            status: RwLock::new(HashMap::new()),
            http,
            ec2_endpoint_override,
        }
    }

    pub async fn seed_instances(&self, tenant_id: &str, instances: Vec<Ec2Instance>) {
        let count = instances.len();
        self.cache
            .write()
            .await
            .insert(tenant_id.to_owned(), instances);
        self.status.write().await.insert(
            tenant_id.to_owned(),
            DiscoveryStatus {
                status: "complete".into(),
                discovering: false,
                total_accounts: 1,
                fetched_accounts: 1,
                total_regions: 1,
                fetched_regions: 1,
                total_instances: count,
                instance_count: count,
                last_discovery_unix: now_unix_secs(),
                last_error: String::new(),
                message: format!("Seeded {count} instances"),
            },
        );
    }

    pub async fn list_instances(&self, tenant_id: &str) -> Vec<Ec2Instance> {
        self.cache
            .read()
            .await
            .get(tenant_id)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn get_status(&self, tenant_id: &str) -> DiscoveryStatus {
        self.status
            .read()
            .await
            .get(tenant_id)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn hydrate_inventory(
        &self,
        tenant_id: &str,
        instances: Vec<Ec2Instance>,
        status: DiscoveryStatus,
    ) {
        self.cache
            .write()
            .await
            .insert(tenant_id.to_owned(), instances);
        self.status
            .write()
            .await
            .insert(tenant_id.to_owned(), status);
    }

    pub async fn fleet_stats(&self, tenant_id: &str) -> FleetStats {
        let list = self.list_instances(tenant_id).await;
        let mut stats = FleetStats {
            total: list.len(),
            ..FleetStats::default()
        };
        let mut region_set = std::collections::HashSet::new();
        let mut vpc_set = std::collections::HashSet::new();
        for inst in &list {
            match inst.state.as_str() {
                "running" => stats.running += 1,
                "stopped" => stats.stopped += 1,
                _ => {}
            }
            if inst.ssm_online {
                stats.ssm_online += 1;
            }
            if inst.platform.eq_ignore_ascii_case("windows") {
                stats.windows += 1;
            } else {
                stats.linux += 1;
            }
            if !inst.region.is_empty() {
                region_set.insert(inst.region.clone());
            }
            if !inst.vpc_id.is_empty() {
                vpc_set.insert(inst.vpc_id.clone());
            }
        }
        stats.regions = region_set.len();
        stats.vpcs = vpc_set.len();
        stats
    }

    pub async fn fleet_summary(&self, tenant_id: &str) -> Vec<RegionFleetSummary> {
        let list = self.list_instances(tenant_id).await;
        let mut by_region: HashMap<String, RegionFleetSummary> = HashMap::new();
        for inst in &list {
            let entry =
                by_region
                    .entry(inst.region.clone())
                    .or_insert_with(|| RegionFleetSummary {
                        region: inst.region.clone(),
                        total: 0,
                        running: 0,
                        stopped: 0,
                        ssm_online: 0,
                    });
            entry.total += 1;
            if inst.state == "running" {
                entry.running += 1;
            } else if inst.state == "stopped" {
                entry.stopped += 1;
            }
            if inst.ssm_online {
                entry.ssm_online += 1;
            }
        }
        let mut out: Vec<_> = by_region.into_values().collect();
        out.sort_by(|a, b| a.region.cmp(&b.region));
        out
    }

    pub fn http_client(&self) -> &reqwest::Client {
        &self.http
    }

    pub async fn build_instance_tree(&self, tenant_id: &str) -> InstanceTree {
        let list = self.list_instances(tenant_id).await;
        let mut by_acct: HashMap<String, (String, HashMap<String, Vec<TreeEc2Instance>>)> =
            HashMap::new();
        for inst in list {
            let acct_key = if inst.account_id.is_empty() {
                inst.profile.clone()
            } else {
                inst.account_id.clone()
            };
            let alias = if inst.profile.is_empty() {
                acct_key.clone()
            } else {
                inst.profile.clone()
            };
            let env = inst
                .tags
                .get("Environment")
                .or_else(|| inst.tags.get("env"))
                .cloned()
                .unwrap_or_default();
            let role = inst
                .tags
                .get("Role")
                .or_else(|| inst.tags.get("Service"))
                .cloned()
                .unwrap_or_default();
            let os = if inst.platform == "windows" {
                "windows".into()
            } else {
                "linux".into()
            };
            let tree_inst = TreeEc2Instance {
                instance_id: inst.instance_id,
                name: inst.name,
                state: inst.state,
                platform: inst.platform,
                os,
                instance_type: inst.instance_type,
                aws_profile: inst.profile.clone(),
                aws_region: inst.region.clone(),
                account_id: inst.account_id,
                account_alias: alias.clone(),
                tag1_value: env,
                tag2_value: role,
                private_ip: inst.private_ip,
                public_ip: inst.public_ip,
                vpc_id: inst.vpc_id,
                subnet_id: inst.subnet_id,
                launch_time: inst.launch_time,
                security_groups: inst.security_groups,
                tags: inst.tags,
                ssm_online: inst.ssm_online,
            };
            let entry = by_acct
                .entry(acct_key)
                .or_insert_with(|| (alias, HashMap::new()));
            entry.1.entry(inst.region).or_default().push(tree_inst);
        }

        let mut accounts: Vec<AccountNode> = by_acct
            .into_iter()
            .map(|(account_id, (alias, regions_map))| {
                let mut regions: Vec<RegionNode> = regions_map
                    .into_iter()
                    .map(|(region, mut insts)| {
                        insts.sort_by(|a, b| a.name.cmp(&b.name));
                        let mut by_tags: HashMap<(String, String), Vec<TreeEc2Instance>> =
                            HashMap::new();
                        for i in insts {
                            by_tags
                                .entry((i.tag1_value.clone(), i.tag2_value.clone()))
                                .or_default()
                                .push(i);
                        }
                        let mut groups: Vec<TagGroup> = by_tags
                            .into_iter()
                            .map(|((tag1, tag2), instances)| TagGroup {
                                tag1,
                                tag2,
                                instances,
                            })
                            .collect();
                        groups.sort_by(|a, b| (&a.tag1, &a.tag2).cmp(&(&b.tag1, &b.tag2)));
                        RegionNode { region, groups }
                    })
                    .collect();
                regions.sort_by(|a, b| a.region.cmp(&b.region));
                AccountNode {
                    provider: "aws".into(),
                    account_id,
                    account_alias: alias.clone(),
                    profile: alias,
                    regions,
                }
            })
            .collect();
        accounts.sort_by(|a, b| a.account_id.cmp(&b.account_id));
        InstanceTree { accounts }
    }

    pub async fn find_instance(&self, tenant_id: &str, instance_id: &str) -> Option<Ec2Instance> {
        self.list_instances(tenant_id)
            .await
            .into_iter()
            .find(|i| i.instance_id == instance_id)
    }

    /// Execute live signed `ec2:DescribeInstances` query against AWS EC2.
    pub async fn fetch_region_with_creds(
        &self,
        tenant_id: &str,
        account_id: &str,
        profile: &str,
        region: &str,
        creds: &AwsCredentials,
    ) -> Result<Vec<Ec2Instance>, String> {
        let base = self
            .ec2_endpoint_override
            .clone()
            .unwrap_or_else(|| format!("https://ec2.{region}.amazonaws.com/"));
        let url = format!("{base}?Action=DescribeInstances&Version=2016-11-15");
        let mut headers = http::HeaderMap::new();
        sign_request("POST", &url, &mut headers, b"", creds, region, "ec2", None)?;
        let resp = self
            .http
            .post(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| format!("EC2 DescribeInstances HTTP error: {e}"))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| format!("EC2 DescribeInstances read error: {e}"))?;
        if !status.is_success() {
            let mut st = self.status.write().await;
            let s = st.entry(tenant_id.to_owned()).or_default();
            s.discovering = false;
            s.last_error = format!("EC2 HTTP {status}");
            return Err(format!("EC2 returned {status}: {body}"));
        }

        let instances = parse_describe_instances_xml(&body, account_id, profile, region)?;
        {
            let mut cache = self.cache.write().await;
            let list = cache.entry(tenant_id.to_owned()).or_default();
            list.retain(|existing| {
                !(existing.region == region && existing.account_id == account_id)
            });
            list.extend(instances.clone());
        }
        let total = self.list_instances(tenant_id).await.len();
        self.status.write().await.insert(
            tenant_id.to_owned(),
            DiscoveryStatus {
                status: "complete".into(),
                discovering: false,
                total_accounts: 1,
                fetched_accounts: 1,
                total_regions: 1,
                fetched_regions: 1,
                total_instances: total,
                instance_count: total,
                last_discovery_unix: now_unix_secs(),
                last_error: String::new(),
                message: format!("Fetched {region}"),
            },
        );
        Ok(instances)
    }

    /// Convert an internal [`Ec2Instance`] into frontend [`TreeEc2Instance`] wire format.
    #[must_use]
    pub fn to_tree_instance(
        inst: &Ec2Instance,
        account_alias: &str,
        aws_profile: &str,
    ) -> TreeEc2Instance {
        let env = inst
            .tags
            .get("Environment")
            .or_else(|| inst.tags.get("env"))
            .cloned()
            .unwrap_or_default();
        let role_tag = inst
            .tags
            .get("Role")
            .or_else(|| inst.tags.get("Service"))
            .cloned()
            .unwrap_or_default();
        let os = if inst.platform.eq_ignore_ascii_case("windows") {
            "windows".into()
        } else {
            "linux".into()
        };
        TreeEc2Instance {
            instance_id: inst.instance_id.clone(),
            name: inst.name.clone(),
            state: inst.state.clone(),
            platform: inst.platform.clone(),
            os,
            instance_type: inst.instance_type.clone(),
            aws_profile: aws_profile.to_owned(),
            aws_region: inst.region.clone(),
            account_id: inst.account_id.clone(),
            account_alias: account_alias.to_owned(),
            tag1_value: env,
            tag2_value: role_tag,
            private_ip: inst.private_ip.clone(),
            public_ip: inst.public_ip.clone(),
            vpc_id: inst.vpc_id.clone(),
            subnet_id: inst.subnet_id.clone(),
            launch_time: inst.launch_time.clone(),
            security_groups: inst.security_groups.clone(),
            tags: inst.tags.clone(),
            ssm_online: inst.ssm_online,
        }
    }

    /// Discover opted-in AWS regions for an account via `ec2:DescribeRegions`.
    pub async fn describe_enabled_regions(
        &self,
        home_region: &str,
        creds: &AwsCredentials,
    ) -> Vec<String> {
        if self.ec2_endpoint_override.is_some() {
            return vec![home_region.to_owned()];
        }
        let reg = if home_region.trim().is_empty() {
            "us-east-1"
        } else {
            home_region.trim()
        };
        let url = format!("https://ec2.{reg}.amazonaws.com/?Action=DescribeRegions&AllRegions=true&Version=2016-11-15");
        let mut headers = http::HeaderMap::new();
        if sign_request("POST", &url, &mut headers, b"", creds, reg, "ec2", None).is_ok() {
            if let Ok(resp) = self.http.post(&url).headers(headers).send().await {
                if resp.status().is_success() {
                    if let Ok(xml) = resp.text().await {
                        let regions = parse_describe_regions_xml(&xml);
                        if !regions.is_empty() {
                            return regions;
                        }
                    }
                }
            }
        }
        vec![
            "us-east-1".into(),
            "us-east-2".into(),
            "us-west-1".into(),
            "us-west-2".into(),
            "ap-south-1".into(),
            "ap-southeast-1".into(),
            "eu-west-1".into(),
            "eu-central-1".into(),
        ]
    }

    /// Concurrently fetch active/stopped EC2 instances across all opted-in regions for a role/account
    /// and report any regions that failed to respond.
    pub async fn fetch_all_regions_with_creds(
        &self,
        tenant_id: &str,
        account_id: &str,
        profile: &str,
        home_region: &str,
        creds: &AwsCredentials,
    ) -> (Vec<Ec2Instance>, Vec<String>) {
        let regions = self.describe_enabled_regions(home_region, creds).await;
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(6));
        let mut handles = Vec::with_capacity(regions.len());

        for region in regions {
            let permit = sem.clone().acquire_owned().await;
            let http = self.http.clone();
            let endpoint_override = self.ec2_endpoint_override.clone();
            let acct = account_id.to_owned();
            let prof = profile.to_owned();
            let c = creds.clone();
            handles.push(tokio::spawn(async move {
                let _p = permit;
                let base = endpoint_override
                    .unwrap_or_else(|| format!("https://ec2.{region}.amazonaws.com/"));
                let url = format!("{base}?Action=DescribeInstances&Version=2016-11-15");
                let mut headers = http::HeaderMap::new();
                if let Err(e) =
                    sign_request("POST", &url, &mut headers, b"", &c, &region, "ec2", None)
                {
                    return (region, Err(e));
                }
                let resp = match http.post(&url).headers(headers).send().await {
                    Ok(r) => r,
                    Err(e) => return (region, Err(e.to_string())),
                };
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                if !status.is_success() {
                    return (region, Err(format!("HTTP {status}")));
                }
                let res =
                    parse_describe_instances_xml(&body, &acct, &prof, &region).map(|mut list| {
                        list.retain(|i| i.state != "terminated" && i.state != "shutting-down");
                        list
                    });
                (region, res)
            }));
        }

        let mut collected = Vec::new();
        let mut failed_regions = Vec::new();
        for h in handles {
            match h.await {
                Ok((_reg, Ok(list))) => collected.extend(list),
                Ok((reg, Err(_))) => failed_regions.push(reg),
                Err(_) => {}
            }
        }

        {
            let mut cache = self.cache.write().await;
            let list = cache.entry(tenant_id.to_owned()).or_default();
            list.retain(|existing| existing.account_id != account_id);
            list.extend(collected.clone());
        }
        let total = self.list_instances(tenant_id).await.len();
        self.status.write().await.insert(
            tenant_id.to_owned(),
            DiscoveryStatus {
                status: "complete".into(),
                discovering: false,
                total_accounts: 1,
                fetched_accounts: 1,
                total_regions: 1,
                fetched_regions: 1,
                total_instances: total,
                instance_count: total,
                last_discovery_unix: now_unix_secs(),
                last_error: String::new(),
                message: format!("Fetched {} instances for {account_id}", collected.len()),
            },
        );
        (collected, failed_regions)
    }

    pub async fn set_status(&self, tenant_id: &str, status: DiscoveryStatus) {
        self.status
            .write()
            .await
            .insert(tenant_id.to_owned(), status);
    }

    pub async fn instance_metrics(
        &self,
        tenant_id: &str,
        instance_id: &str,
        region: &str,
    ) -> InstanceMetrics {
        let _inst = self.find_instance(tenant_id, instance_id).await;
        InstanceMetrics {
            instance_id: instance_id.to_owned(),
            region: region.to_owned(),
            cpu_utilization_pct: 0.0,
            network_in_bytes: 0.0,
            network_out_bytes: 0.0,
            status_check_failed: 0.0,
            cpu_load: None,
            cpu_count: None,
            mem_used_pct: None,
            mem_total_mb: None,
            mem_used_mb: None,
            disk_used_pct: None,
            disk_total_gb: None,
            disk_used_gb: None,
            uptime: None,
            source: None,
            sampled_at_unix: now_unix_secs(),
        }
    }

    async fn query_cloudwatch_average(
        &self,
        reg: &str,
        ns: &str,
        metric: &str,
        instance_id: &str,
        start: &str,
        end: &str,
        creds: &AwsCredentials,
    ) -> Option<f64> {
        let url = format!(
            "https://monitoring.{reg}.amazonaws.com/?Action=GetMetricStatistics&Version=2010-08-01&Namespace={}&MetricName={}&Dimensions.member.1.Name=InstanceId&Dimensions.member.1.Value={}&StartTime={}&EndTime={}&Period=300&Statistics.member.1=Average",
            crate::sigv4::uri_encode(ns, true),
            crate::sigv4::uri_encode(metric, true),
            crate::sigv4::uri_encode(instance_id, true),
            crate::sigv4::uri_encode(start, true),
            crate::sigv4::uri_encode(end, true),
        );
        let mut headers = http::HeaderMap::new();
        sign_request(
            "POST",
            &url,
            &mut headers,
            b"",
            creds,
            reg,
            "monitoring",
            None,
        )
        .ok()?;
        let resp = self.http.post(&url).headers(headers).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let xml = resp.text().await.ok()?;
        parse_cloudwatch_latest_average(&xml)
    }

    /// Query live instance metrics via `SSM SendCommand` (OS-level CPU, RAM, Disk, Uptime, matching
    /// Go `operquay`) first, and fall back to `CloudWatch` (`AWS/EC2` + `CWAgent`) if SSM is unavailable.
    pub async fn fetch_instance_metrics_live_with_ssm(
        &self,
        tenant_id: &str,
        instance_id: &str,
        region: &str,
        platform: &str,
        creds: &AwsCredentials,
        transfer: Option<&SsmTransferClient>,
    ) -> Result<InstanceMetrics, String> {
        let reg = if region.trim().is_empty() {
            "us-east-1"
        } else {
            region.trim()
        };
        let now = now_unix_secs();
        let is_win = platform.eq_ignore_ascii_case("windows");

        // 1. Live OS metrics via AWS SSM RunCommand (fast path matching Go `metrics.go`).
        if let Some(tx) = transfer {
            let cmd = if is_win {
                "$cpu=(Get-WmiObject Win32_Processor|Measure-Object -Property LoadPercentage -Average).Average;\
$os=Get-WmiObject Win32_OperatingSystem;\
$memTotal=[math]::Round($os.TotalVisibleMemorySize/1024);\
$memUsed=$memTotal-[math]::Round($os.FreePhysicalMemory/1024);\
$memPct=if($memTotal -gt 0){[math]::Round(($memUsed/$memTotal)*100,1)}else{0};\
$disk=Get-WmiObject Win32_LogicalDisk -Filter \"DeviceID='C:'\";\
$diskTotal=[math]::Round($disk.Size/1GB,1);\
$diskUsed=[math]::Round(($disk.Size-$disk.FreeSpace)/1GB,1);\
$diskPct=if($disk.Size -gt 0){[math]::Round((($disk.Size-$disk.FreeSpace)/$disk.Size)*100,1)}else{0};\
$uptime=(Get-Date)-(Get-CimInstance Win32_OperatingSystem).LastBootUpTime;\
$uptimeStr=\"$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m\";\
$cpuCount=(Get-WmiObject Win32_Processor|Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum;\
\"CPU:$cpu|CPUS:$cpuCount|MEMPCT:$memPct|MEMTOT:$memTotal|MEMUSED:$memUsed|DISKPCT:$diskPct|DISKTOT:$diskTotal|DISKUSED:$diskUsed|UPTIME:$uptimeStr\"".to_owned()
            } else {
                r#"LOAD=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0);CPUS=$(nproc 2>/dev/null || echo 1);eval $(free -m 2>/dev/null | awk '/^Mem:/{if($2>0)printf "MEMUSED=%d MEMTOT=%d MEMPCT=%.1f",$3,$2,$3/$2*100}');eval $(df -Pk / 2>/dev/null | awk 'NR==2{gsub("%","",$5);printf "DISKUSED=%.1f DISKTOT=%.1f DISKPCT=%.1f",$3/1048576,$2/1048576,$5}');UPTIME=$(uptime -p 2>/dev/null || uptime 2>/dev/null | sed 's/.*up/up/');echo "CPU:${LOAD}|CPUS:${CPUS}|MEMPCT:${MEMPCT}|MEMTOT:${MEMTOT}|MEMUSED:${MEMUSED}|DISKPCT:${DISKPCT}|DISKTOT:${DISKTOT}|DISKUSED:${DISKUSED}|UPTIME:${UPTIME}""#.to_owned()
            };
            if let Ok(raw) = tx
                .run_ssm_command(reg, instance_id.trim(), platform, &[cmd], creds)
                .await
            {
                if let Some(parsed) = parse_ssm_metrics_output(&raw) {
                    let cpu_pct = if is_win {
                        parsed.cpu_load.unwrap_or(0.0)
                    } else if let (Some(load), Some(cpus)) = (parsed.cpu_load, parsed.cpu_count) {
                        ((load / f64::from(cpus.max(1))) * 100.0).clamp(0.0, 100.0)
                    } else {
                        0.0
                    };
                    return Ok(InstanceMetrics {
                        instance_id: instance_id.to_owned(),
                        region: reg.to_owned(),
                        cpu_utilization_pct: (cpu_pct * 10.0).round() / 10.0,
                        network_in_bytes: 0.0,
                        network_out_bytes: 0.0,
                        status_check_failed: 0.0,
                        cpu_load: parsed.cpu_load,
                        cpu_count: parsed.cpu_count,
                        mem_used_pct: parsed.mem_used_pct,
                        mem_total_mb: parsed.mem_total_mb,
                        mem_used_mb: parsed.mem_used_mb,
                        disk_used_pct: parsed.disk_used_pct,
                        disk_total_gb: parsed.disk_total_gb,
                        disk_used_gb: parsed.disk_used_gb,
                        uptime: parsed.uptime,
                        source: Some("ssm".to_owned()),
                        sampled_at_unix: now,
                    });
                }
            }
        }

        // 2. Fallback to CloudWatch EC2 + CWAgent metrics (also works with ReadOnly IAM roles).
        let _ = tenant_id;
        let start = format_iso8601_utc(now - 900);
        let end = format_iso8601_utc(now);
        let iid = instance_id.trim();
        let (cpu, net_in, net_out, status_chk, cw_mem, cw_disk) = tokio::join!(
            self.query_cloudwatch_average(
                reg,
                "AWS/EC2",
                "CPUUtilization",
                iid,
                &start,
                &end,
                creds
            ),
            self.query_cloudwatch_average(reg, "AWS/EC2", "NetworkIn", iid, &start, &end, creds),
            self.query_cloudwatch_average(reg, "AWS/EC2", "NetworkOut", iid, &start, &end, creds),
            self.query_cloudwatch_average(
                reg,
                "AWS/EC2",
                "StatusCheckFailed",
                iid,
                &start,
                &end,
                creds
            ),
            self.query_cloudwatch_average(
                reg,
                "CWAgent",
                "mem_used_percent",
                iid,
                &start,
                &end,
                creds
            ),
            self.query_cloudwatch_average(
                reg,
                "CWAgent",
                "disk_used_percent",
                iid,
                &start,
                &end,
                creds
            ),
        );
        Ok(InstanceMetrics {
            instance_id: instance_id.to_owned(),
            region: reg.to_owned(),
            cpu_utilization_pct: cpu.map_or(0.0, |v| (v * 10.0).round() / 10.0),
            network_in_bytes: net_in.unwrap_or(0.0),
            network_out_bytes: net_out.unwrap_or(0.0),
            status_check_failed: status_chk.unwrap_or(0.0),
            cpu_load: cpu.map(|pct| {
                if is_win {
                    (pct * 10.0).round() / 10.0
                } else {
                    (pct / 100.0 * 100.0).round() / 100.0
                }
            }),
            cpu_count: None,
            mem_used_pct: cw_mem.map(|v| (v * 10.0).round() / 10.0),
            mem_total_mb: None,
            mem_used_mb: None,
            disk_used_pct: cw_disk.map(|v| (v * 10.0).round() / 10.0),
            disk_total_gb: None,
            disk_used_gb: None,
            uptime: None,
            source: Some("cloudwatch".to_owned()),
            sampled_at_unix: now,
        })
    }

    /// Query live `CloudWatch` EC2 metrics (`CPUUtilization`, `NetworkIn`, `NetworkOut`, `StatusCheckFailed`).
    pub async fn fetch_instance_metrics_live(
        &self,
        tenant_id: &str,
        instance_id: &str,
        region: &str,
        creds: &AwsCredentials,
    ) -> Result<InstanceMetrics, String> {
        self.fetch_instance_metrics_live_with_ssm(
            tenant_id,
            instance_id,
            region,
            "linux",
            creds,
            None,
        )
        .await
    }

    /// Fetch live EC2 `DescribeInstances` + `DescribeVolumes` + `DescribeSecurityGroups` details for an instance.
    pub async fn fetch_instance_details_live(
        &self,
        tenant_id: &str,
        region: &str,
        instance_id: &str,
        creds: &AwsCredentials,
    ) -> Result<serde_json::Value, String> {
        let reg = if region.trim().is_empty() {
            "us-east-1"
        } else {
            region.trim()
        };
        let base = self
            .ec2_endpoint_override
            .clone()
            .unwrap_or_else(|| format!("https://ec2.{reg}.amazonaws.com/"));
        let sep = if base.contains('?') { '&' } else { '?' };
        let iid_enc = crate::sigv4::uri_encode(instance_id.trim(), true);
        let inst_url = format!(
            "{base}{sep}Action=DescribeInstances&InstanceId.1={iid_enc}&Version=2016-11-15"
        );
        let mut h1 = http::HeaderMap::new();
        sign_request("POST", &inst_url, &mut h1, b"", creds, reg, "ec2", None)?;
        let inst_resp = self
            .http
            .post(&inst_url)
            .headers(h1)
            .send()
            .await
            .map_err(|e| format!("EC2 DescribeInstances error: {e}"))?;
        let st1 = inst_resp.status();
        let inst_xml = inst_resp.text().await.map_err(|e| e.to_string())?;
        if !st1.is_success() {
            return Err(format!("EC2 DescribeInstances returned {st1}: {inst_xml}"));
        }

        let cached = self.find_instance(tenant_id, instance_id).await;
        let parsed = parse_describe_instances_xml(&inst_xml, "", "", reg)
            .ok()
            .and_then(|mut v| v.pop());
        let base_inst = parsed.as_ref().or(cached.as_ref());

        // Deduplicate security groups preserving order.
        let mut sg_ids = Vec::<String>::new();
        if let Some(inst) = base_inst {
            for sg in &inst.security_groups {
                if !sg.is_empty() && !sg_ids.contains(sg) {
                    sg_ids.push(sg.clone());
                }
            }
        }

        let vol_fut = async {
            let vol_url = format!(
                "{base}{sep}Action=DescribeVolumes&Filter.1.Name=attachment.instance-id&Filter.1.Value.1={iid_enc}&Version=2016-11-15"
            );
            let mut h2 = http::HeaderMap::new();
            if sign_request("POST", &vol_url, &mut h2, b"", creds, reg, "ec2", None).is_err() {
                return Vec::new();
            }
            match self.http.post(&vol_url).headers(h2).send().await {
                Ok(r) if r.status().is_success() => {
                    let vxml = r.text().await.unwrap_or_default();
                    parse_describe_volumes_xml(&vxml)
                }
                _ => Vec::new(),
            }
        };

        let sg_fut = async {
            if sg_ids.is_empty() {
                return Vec::new();
            }
            let mut sg_url = format!("{base}{sep}Action=DescribeSecurityGroups&Version=2016-11-15");
            for (idx, sg_id) in sg_ids.iter().enumerate() {
                use std::fmt::Write as _;
                let _ = write!(
                    sg_url,
                    "&GroupId.{}={}",
                    idx + 1,
                    crate::sigv4::uri_encode(sg_id, true)
                );
            }
            let mut h3 = http::HeaderMap::new();
            if sign_request("POST", &sg_url, &mut h3, b"", creds, reg, "ec2", None).is_err() {
                return Vec::new();
            }
            match self.http.post(&sg_url).headers(h3).send().await {
                Ok(r) if r.status().is_success() => {
                    let sxml = r.text().await.unwrap_or_default();
                    parse_security_groups_xml(&sxml)
                }
                _ => Vec::new(),
            }
        };

        let (volumes, sg_details) = tokio::join!(vol_fut, sg_fut);

        let network_interfaces = parse_network_interfaces_xml(&inst_xml);
        let bdm_rows = parse_block_device_mappings_xml(&inst_xml);
        let mut vol_by_id: HashMap<String, serde_json::Value> = HashMap::new();
        for v in &volumes {
            if let Some(vid) = v["volume_id"].as_str() {
                vol_by_id.insert(vid.to_owned(), v.clone());
            }
        }
        let mut block_devices = Vec::new();
        for (device_name, volume_id, delete_on_termination) in bdm_rows {
            if let Some(v) = vol_by_id.get(&volume_id) {
                block_devices.push(serde_json::json!({
                    "device_name": if device_name.is_empty() { v["device"].as_str().unwrap_or("") } else { device_name.as_str() },
                    "volume_id": volume_id,
                    "volume_size": v["size_gib"].as_u64().unwrap_or(0),
                    "volume_type": v["volume_type"].as_str().unwrap_or(""),
                    "iops": v["iops"].as_u64().unwrap_or(0),
                    "encrypted": v["encrypted"].as_bool().unwrap_or(false),
                    "state": v["state"].as_str().unwrap_or(""),
                    "delete_on_termination": delete_on_termination,
                }));
            } else {
                block_devices.push(serde_json::json!({
                    "device_name": device_name,
                    "volume_id": volume_id,
                    "volume_size": 0,
                    "volume_type": "",
                    "iops": 0,
                    "encrypted": false,
                    "state": "",
                    "delete_on_termination": delete_on_termination,
                }));
            }
        }
        if block_devices.is_empty() && !volumes.is_empty() {
            for v in &volumes {
                block_devices.push(serde_json::json!({
                    "device_name": v["device"].as_str().unwrap_or(""),
                    "volume_id": v["volume_id"].as_str().unwrap_or(""),
                    "volume_size": v["size_gib"].as_u64().unwrap_or(0),
                    "volume_type": v["volume_type"].as_str().unwrap_or(""),
                    "iops": v["iops"].as_u64().unwrap_or(0),
                    "encrypted": v["encrypted"].as_bool().unwrap_or(false),
                    "state": v["state"].as_str().unwrap_or(""),
                    "delete_on_termination": false,
                }));
            }
        }

        let owner_id = cached
            .as_ref()
            .map(|c| c.account_id.clone())
            .filter(|s| !s.is_empty())
            .or_else(|| crate::accounts::xml_tag_text(&inst_xml, "ownerId"))
            .unwrap_or_default();
        let account_alias = cached.as_ref().map_or_default(|c| c.profile.clone());
        let private_dns =
            crate::accounts::xml_tag_text(&inst_xml, "privateDnsName").unwrap_or_default();
        let public_dns = crate::accounts::xml_tag_text(&inst_xml, "dnsName").unwrap_or_default();
        let instance_profile = crate::accounts::xml_tag_text(&inst_xml, "iamInstanceProfile")
            .and_then(|b| crate::accounts::xml_tag_text(&b, "arn"))
            .unwrap_or_default();

        Ok(serde_json::json!({
            "instance_id": instance_id,
            "name": base_inst.map_or("", |i| i.name.as_str()),
            "state": base_inst.map_or("", |i| i.state.as_str()),
            "instance_type": base_inst.map_or("", |i| i.instance_type.as_str()),
            "platform": base_inst.map_or("linux", |i| i.platform.as_str()),
            "region": reg,
            "aws_region": reg,
            "account_id": owner_id,
            "account_alias": account_alias,
            "availability_zone": base_inst.map_or("", |i| i.availability_zone.as_str()),
            "vpc_id": base_inst.map_or("", |i| i.vpc_id.as_str()),
            "subnet_id": base_inst.map_or("", |i| i.subnet_id.as_str()),
            "private_ip": base_inst.map_or("", |i| i.private_ip.as_str()),
            "public_ip": base_inst.map_or("", |i| i.public_ip.as_str()),
            "launch_time": base_inst.map_or("", |i| i.launch_time.as_str()),
            "ami_id": crate::accounts::xml_tag_text(&inst_xml, "imageId").unwrap_or_default(),
            "architecture": crate::accounts::xml_tag_text(&inst_xml, "architecture").unwrap_or_default(),
            "key_name": crate::accounts::xml_tag_text(&inst_xml, "keyName").unwrap_or_default(),
            "root_device_type": crate::accounts::xml_tag_text(&inst_xml, "rootDeviceType").unwrap_or_default(),
            "root_device_name": crate::accounts::xml_tag_text(&inst_xml, "rootDeviceName").unwrap_or_default(),
            "ebs_optimized": crate::accounts::xml_tag_text(&inst_xml, "ebsOptimized").is_some_and(|v| v == "true"),
            "private_dns": private_dns,
            "private_dns_name": private_dns,
            "public_dns": public_dns,
            "public_dns_name": public_dns,
            "instance_profile": instance_profile,
            "iam_instance_profile": instance_profile,
            "monitoring_state": crate::accounts::xml_tag_text(&inst_xml, "monitoring")
                .and_then(|b| crate::accounts::xml_tag_text(&b, "state"))
                .unwrap_or_default(),
            "security_groups": sg_ids,
            "security_group_details": sg_details,
            "network_interfaces": network_interfaces,
            "block_devices": block_devices,
            "tags": base_inst.map_or_default(|i| i.tags.clone()),
            "ssm_online": cached.as_ref().is_some_and(|i| i.ssm_online),
            "volumes": volumes,
        }))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedSsmMetrics {
    pub cpu_load: Option<f64>,
    pub cpu_count: Option<u32>,
    pub mem_used_pct: Option<f64>,
    pub mem_total_mb: Option<u64>,
    pub mem_used_mb: Option<u64>,
    pub disk_used_pct: Option<f64>,
    pub disk_total_gb: Option<f64>,
    pub disk_used_gb: Option<f64>,
    pub uptime: Option<String>,
}

/// Parse pipe-delimited `CPU:...|CPUS:...|MEMPCT:...|DISKPCT:...` telemetry from SSM `RunCommand`.
#[must_use]
pub fn parse_ssm_metrics_output(raw: &str) -> Option<ParsedSsmMetrics> {
    let mut kv: HashMap<&str, &str> = HashMap::new();
    for part in raw.trim().split('|') {
        if let Some((k, v)) = part.split_once(':') {
            let kt = k.trim();
            let vt = v.trim();
            if !kt.is_empty() && !vt.is_empty() {
                kv.insert(kt, vt);
            }
        }
    }
    if kv.is_empty() {
        return None;
    }
    let cpu_load = kv.get("CPU").and_then(|s| s.parse::<f64>().ok());
    let cpu_count = kv.get("CPUS").and_then(|s| s.parse::<u32>().ok());
    let mem_used_pct = kv.get("MEMPCT").and_then(|s| s.parse::<f64>().ok());
    let mem_total_mb = kv.get("MEMTOT").and_then(|s| s.parse::<u64>().ok());
    let mem_used_mb = kv.get("MEMUSED").and_then(|s| s.parse::<u64>().ok());
    let disk_used_pct = kv.get("DISKPCT").and_then(|s| s.parse::<f64>().ok());
    let disk_total_gb = kv.get("DISKTOT").and_then(|s| s.parse::<f64>().ok());
    let disk_used_gb = kv.get("DISKUSED").and_then(|s| s.parse::<f64>().ok());
    let uptime = kv.get("UPTIME").map(|s| (*s).to_owned());

    if cpu_load.is_none() && mem_used_pct.is_none() && disk_used_pct.is_none() {
        return None;
    }
    Some(ParsedSsmMetrics {
        cpu_load,
        cpu_count,
        mem_used_pct,
        mem_total_mb,
        mem_used_mb,
        disk_used_pct,
        disk_total_gb,
        disk_used_gb,
        uptime,
    })
}

fn format_iso8601_utc(unix_secs: i64) -> String {
    let (amz, _) = crate::sigv4::format_amz_datetime(unix_secs);
    // YYYYMMDDTHHMMSSZ -> YYYY-MM-DDTHH:MM:SSZ
    if amz.len() == 16 {
        format!(
            "{}-{}-{}T{}:{}:{}Z",
            &amz[0..4],
            &amz[4..6],
            &amz[6..8],
            &amz[9..11],
            &amz[11..13],
            &amz[13..15]
        )
    } else {
        amz
    }
}

fn parse_cloudwatch_latest_average(xml: &str) -> Option<f64> {
    let mut best_ts = String::new();
    let mut best_val = None;
    let mut rest = xml;
    while let Some(start) = rest.find("<member>") {
        let after = &rest[start + 8..];
        let Some(end) = after.find("</member>") else {
            break;
        };
        let block = &after[..end];
        if let Some(avg) =
            crate::accounts::xml_tag_text(block, "Average").and_then(|s| s.parse::<f64>().ok())
        {
            let ts = crate::accounts::xml_tag_text(block, "Timestamp").unwrap_or_default();
            if best_val.is_none() || ts >= best_ts {
                best_ts = ts;
                best_val = Some(avg);
            }
        }
        rest = &after[end + 9..];
    }
    best_val
}

fn append_xml_ref(out: &mut String, r: &BytesRef<'_>) -> Result<(), String> {
    if let Some(ch) = r
        .resolve_char_ref()
        .map_err(|err| format!("XML char ref error: {err}"))?
    {
        out.push(ch);
        return Ok(());
    }
    if let Some(s) = quick_xml::escape::resolve_predefined_entity(r.as_ref()) {
        out.push_str(s);
        return Ok(());
    }
    Err(format!(
        "unsupported XML entity reference: &{};",
        r.as_ref()
    ))
}

pub fn parse_describe_volumes_xml(xml: &str) -> Vec<serde_json::Value> {
    let mut reader = Reader::from_str(xml);
    let mut stack: Vec<String> = Vec::new();
    let mut out = Vec::new();
    let mut cur_text = String::new();
    let mut vid = String::new();
    let mut size = 0u64;
    let mut vtype = String::new();
    let mut iops = 0u64;
    let mut state = String::new();
    let mut az = String::new();
    let mut encrypted = false;
    let mut device = String::new();
    let mut in_vol = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = e.name().into_inner().to_owned();
                let parent = stack.last().map_or("", String::as_str);
                if name == "item" && parent == "volumeSet" {
                    in_vol = true;
                    vid.clear();
                    size = 0;
                    vtype.clear();
                    iops = 0;
                    state.clear();
                    az.clear();
                    encrypted = false;
                    device.clear();
                }
                stack.push(name);
                cur_text.clear();
            }
            Ok(Event::Text(t)) => {
                cur_text.push_str(t.xml10_content().as_ref());
            }
            Ok(Event::GeneralRef(r)) => {
                if append_xml_ref(&mut cur_text, &r).is_err() {
                    break;
                }
            }
            Ok(Event::End(e)) => {
                let name = e.name().into_inner();
                let popped = stack.pop().unwrap_or_default();
                let parent = stack.last().map_or("", String::as_str);
                let grand = if stack.len() >= 2 {
                    stack[stack.len() - 2].as_str()
                } else {
                    ""
                };
                let txt = cur_text.trim();
                if in_vol {
                    if parent == "item" && grand == "volumeSet" {
                        match popped.as_str() {
                            "volumeId" => txt.clone_into(&mut vid),
                            "size" => size = txt.parse::<u64>().unwrap_or(0),
                            "volumeType" => txt.clone_into(&mut vtype),
                            "iops" => iops = txt.parse::<u64>().unwrap_or(0),
                            "status" => txt.clone_into(&mut state),
                            "availabilityZone" => txt.clone_into(&mut az),
                            "encrypted" => encrypted = txt == "true",
                            _ => {}
                        }
                    } else if parent == "item"
                        && grand == "attachmentSet"
                        && popped == "device"
                        && device.is_empty()
                    {
                        txt.clone_into(&mut device);
                    }
                    if name == "item" && parent == "volumeSet" {
                        in_vol = false;
                        if !vid.is_empty() {
                            out.push(serde_json::json!({
                                "volume_id": vid,
                                "size_gib": size,
                                "volume_type": vtype,
                                "iops": iops,
                                "state": state,
                                "availability_zone": az,
                                "encrypted": encrypted,
                                "device": device,
                            }));
                        }
                    }
                }
                cur_text.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    out
}

pub fn parse_network_interfaces_xml(xml: &str) -> Vec<serde_json::Value> {
    let mut reader = Reader::from_str(xml);
    let mut stack: Vec<String> = Vec::new();
    let mut out = Vec::new();
    let mut cur_text = String::new();
    let mut in_eni = false;
    let mut eni_id = String::new();
    let mut subnet_id = String::new();
    let mut private_ip = String::new();
    let mut public_ip = String::new();
    let mut mac_addr = String::new();
    let mut status = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = e.name().into_inner().to_owned();
                let parent = stack.last().map_or("", String::as_str);
                if name == "item" && parent == "networkInterfaceSet" {
                    in_eni = true;
                    eni_id.clear();
                    subnet_id.clear();
                    private_ip.clear();
                    public_ip.clear();
                    mac_addr.clear();
                    status.clear();
                }
                stack.push(name);
                cur_text.clear();
            }
            Ok(Event::Text(t)) => cur_text.push_str(t.xml10_content().as_ref()),
            Ok(Event::GeneralRef(r)) => {
                if append_xml_ref(&mut cur_text, &r).is_err() {
                    break;
                }
            }
            Ok(Event::End(e)) => {
                let name = e.name().into_inner();
                let popped = stack.pop().unwrap_or_default();
                let parent = stack.last().map_or("", String::as_str);
                let grand = if stack.len() >= 2 {
                    stack[stack.len() - 2].as_str()
                } else {
                    ""
                };
                let txt = cur_text.trim();
                if in_eni {
                    if parent == "item" && grand == "networkInterfaceSet" {
                        match popped.as_str() {
                            "networkInterfaceId" => txt.clone_into(&mut eni_id),
                            "subnetId" => txt.clone_into(&mut subnet_id),
                            "privateIpAddress" => txt.clone_into(&mut private_ip),
                            "macAddress" => txt.clone_into(&mut mac_addr),
                            "status" => txt.clone_into(&mut status),
                            _ => {}
                        }
                    } else if parent == "association"
                        && popped == "publicIp"
                        && public_ip.is_empty()
                    {
                        txt.clone_into(&mut public_ip);
                    }
                    if name == "item" && parent == "networkInterfaceSet" {
                        in_eni = false;
                        if !eni_id.is_empty() {
                            out.push(serde_json::json!({
                                "interface_id": eni_id,
                                "subnet_id": subnet_id,
                                "private_ip": private_ip,
                                "public_ip": public_ip,
                                "mac_address": mac_addr,
                                "status": status,
                            }));
                        }
                    }
                }
                cur_text.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    out
}

pub fn parse_block_device_mappings_xml(xml: &str) -> Vec<(String, String, bool)> {
    let mut reader = Reader::from_str(xml);
    let mut stack: Vec<String> = Vec::new();
    let mut out = Vec::new();
    let mut cur_text = String::new();
    let mut in_bdm = false;
    let mut device_name = String::new();
    let mut volume_id = String::new();
    let mut delete_on_term = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = e.name().into_inner().to_owned();
                let parent = stack.last().map_or("", String::as_str);
                if name == "item" && parent == "blockDeviceMapping" {
                    in_bdm = true;
                    device_name.clear();
                    volume_id.clear();
                    delete_on_term = false;
                }
                stack.push(name);
                cur_text.clear();
            }
            Ok(Event::Text(t)) => cur_text.push_str(t.xml10_content().as_ref()),
            Ok(Event::GeneralRef(r)) => {
                if append_xml_ref(&mut cur_text, &r).is_err() {
                    break;
                }
            }
            Ok(Event::End(e)) => {
                let name = e.name().into_inner();
                let popped = stack.pop().unwrap_or_default();
                let parent = stack.last().map_or("", String::as_str);
                let grand = if stack.len() >= 2 {
                    stack[stack.len() - 2].as_str()
                } else {
                    ""
                };
                let txt = cur_text.trim();
                if in_bdm {
                    if parent == "item" && grand == "blockDeviceMapping" && popped == "deviceName" {
                        txt.clone_into(&mut device_name);
                    } else if parent == "ebs" {
                        if popped == "volumeId" {
                            txt.clone_into(&mut volume_id);
                        } else if popped == "deleteOnTermination" {
                            delete_on_term = txt == "true";
                        }
                    }
                    if name == "item" && parent == "blockDeviceMapping" {
                        in_bdm = false;
                        if !volume_id.is_empty() || !device_name.is_empty() {
                            out.push((device_name.clone(), volume_id.clone(), delete_on_term));
                        }
                    }
                }
                cur_text.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    out
}

pub fn parse_security_groups_xml(xml: &str) -> Vec<serde_json::Value> {
    #[derive(Default)]
    struct Perm {
        proto: String,
        from_port: i32,
        to_port: i32,
        rules: Vec<serde_json::Value>,
    }

    let mut reader = Reader::from_str(xml);
    let mut stack: Vec<String> = Vec::new();
    let mut out = Vec::new();
    let mut cur_text = String::new();
    let mut in_sg = false;
    let mut group_id = String::new();
    let mut group_name = String::new();
    let mut group_desc = String::new();
    let mut inbound: Vec<serde_json::Value> = Vec::new();
    let mut outbound: Vec<serde_json::Value> = Vec::new();
    let mut cur_perm: Option<(bool, Perm)> = None;
    let mut cur_cidr = String::new();
    let mut cur_rule_desc = String::new();
    let mut cur_peer_sg = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = e.name().into_inner().to_owned();
                let parent = stack.last().map_or("", String::as_str);
                if name == "item" && parent == "securityGroupInfo" {
                    in_sg = true;
                    group_id.clear();
                    group_name.clear();
                    group_desc.clear();
                    inbound.clear();
                    outbound.clear();
                    cur_perm = None;
                } else if in_sg
                    && name == "item"
                    && (parent == "ipPermissions" || parent == "ipPermissionsEgress")
                {
                    cur_perm = Some((parent == "ipPermissions", Perm::default()));
                } else if cur_perm.is_some()
                    && name == "item"
                    && (parent == "ipRanges" || parent == "ipv6Ranges" || parent == "groups")
                {
                    cur_cidr.clear();
                    cur_rule_desc.clear();
                    cur_peer_sg.clear();
                }
                stack.push(name);
                cur_text.clear();
            }
            Ok(Event::Text(t)) => cur_text.push_str(t.xml10_content().as_ref()),
            Ok(Event::GeneralRef(r)) => {
                if append_xml_ref(&mut cur_text, &r).is_err() {
                    break;
                }
            }
            Ok(Event::End(e)) => {
                let name = e.name().into_inner();
                let popped = stack.pop().unwrap_or_default();
                let parent = stack.last().map_or("", String::as_str);
                let grand = if stack.len() >= 2 {
                    stack[stack.len() - 2].as_str()
                } else {
                    ""
                };
                let txt = cur_text.trim();
                if in_sg {
                    if parent == "item" && grand == "securityGroupInfo" {
                        match popped.as_str() {
                            "groupId" => txt.clone_into(&mut group_id),
                            "groupName" => txt.clone_into(&mut group_name),
                            "groupDescription" => txt.clone_into(&mut group_desc),
                            _ => {}
                        }
                    } else if let Some((_, ref mut perm)) = cur_perm {
                        if parent == "item"
                            && (grand == "ipPermissions" || grand == "ipPermissionsEgress")
                        {
                            match popped.as_str() {
                                "ipProtocol" => txt.clone_into(&mut perm.proto),
                                "fromPort" => perm.from_port = txt.parse::<i32>().unwrap_or(0),
                                "toPort" => perm.to_port = txt.parse::<i32>().unwrap_or(0),
                                _ => {}
                            }
                        } else if parent == "item" && (grand == "ipRanges" || grand == "ipv6Ranges")
                        {
                            match popped.as_str() {
                                "cidrIp" | "cidrIpv6" => txt.clone_into(&mut cur_cidr),
                                "description" => txt.clone_into(&mut cur_rule_desc),
                                _ => {}
                            }
                        } else if parent == "item" && grand == "groups" {
                            match popped.as_str() {
                                "groupId" => txt.clone_into(&mut cur_peer_sg),
                                "description" => txt.clone_into(&mut cur_rule_desc),
                                _ => {}
                            }
                        } else if popped == "item"
                            && (parent == "ipRanges" || parent == "ipv6Ranges")
                        {
                            if !cur_cidr.is_empty() {
                                perm.rules.push(serde_json::json!({
                                    "protocol": perm.proto,
                                    "from_port": perm.from_port,
                                    "to_port": perm.to_port,
                                    "source": cur_cidr,
                                    "description": cur_rule_desc,
                                }));
                            }
                        } else if popped == "item" && parent == "groups" && !cur_peer_sg.is_empty()
                        {
                            perm.rules.push(serde_json::json!({
                                "protocol": perm.proto,
                                "from_port": perm.from_port,
                                "to_port": perm.to_port,
                                "source": cur_peer_sg,
                                "description": cur_rule_desc,
                            }));
                        }
                    }

                    if name == "item"
                        && (parent == "ipPermissions" || parent == "ipPermissionsEgress")
                    {
                        if let Some((is_in, mut finished_perm)) = cur_perm.take() {
                            for r in &mut finished_perm.rules {
                                r["protocol"] = serde_json::json!(finished_perm.proto);
                                r["from_port"] = serde_json::json!(finished_perm.from_port);
                                r["to_port"] = serde_json::json!(finished_perm.to_port);
                            }
                            if is_in {
                                inbound.extend(finished_perm.rules);
                            } else {
                                outbound.extend(finished_perm.rules);
                            }
                        }
                    } else if name == "item" && parent == "securityGroupInfo" {
                        in_sg = false;
                        if !group_id.is_empty() {
                            out.push(serde_json::json!({
                                "group_id": group_id,
                                "group_name": group_name,
                                "description": group_desc,
                                "inbound_rules": inbound,
                                "outbound_rules": outbound,
                            }));
                        }
                    }
                }
                cur_text.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    out
}

/// Parse standard EC2 `DescribeInstancesResponse` XML (`reservationSet/instancesSet/item`).
pub fn parse_describe_instances_xml(
    xml: &str,
    account_id: &str,
    profile: &str,
    region: &str,
) -> Result<Vec<Ec2Instance>, String> {
    let mut reader = Reader::from_str(xml);
    let mut stack: Vec<String> = Vec::new();
    let mut out = Vec::new();
    let mut cur: Option<Ec2Instance> = None;
    let mut tag_key = String::new();
    let mut tag_val = String::new();
    let mut cur_text = String::new();
    let mut cur_sg = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = e.name().into_inner().to_owned();
                let parent = stack.last().map_or("", String::as_str);
                if name == "item" && parent == "instancesSet" {
                    cur = Some(Ec2Instance {
                        instance_id: String::new(),
                        name: String::new(),
                        state: "unknown".to_owned(),
                        instance_type: "t3.micro".to_owned(),
                        platform: "linux".to_owned(),
                        private_ip: String::new(),
                        public_ip: String::new(),
                        region: region.to_owned(),
                        availability_zone: String::new(),
                        vpc_id: String::new(),
                        subnet_id: String::new(),
                        account_id: account_id.to_owned(),
                        profile: profile.to_owned(),
                        ssm_online: true,
                        tags: HashMap::new(),
                        security_groups: Vec::new(),
                        launch_time: String::new(),
                    });
                } else if name == "item" && parent == "tagSet" {
                    tag_key.clear();
                    tag_val.clear();
                } else if name == "item" && parent == "groupSet" {
                    cur_sg.clear();
                }
                stack.push(name);
                cur_text.clear();
            }
            Ok(Event::Text(t)) => {
                cur_text.push_str(t.xml10_content().as_ref());
            }
            Ok(Event::GeneralRef(r)) => {
                append_xml_ref(&mut cur_text, &r)
                    .map_err(|e| format!("EC2 XML parse error: {e}"))?;
            }
            Ok(Event::End(e)) => {
                let name = e.name().into_inner();
                let popped = stack.pop().unwrap_or_default();
                let parent = stack.last().map_or("", String::as_str);
                let grand = if stack.len() >= 2 {
                    stack[stack.len() - 2].as_str()
                } else {
                    ""
                };
                let in_eni = stack.iter().any(|s| s == "networkInterfaceSet");
                let txt = cur_text.trim();
                if let Some(inst) = cur.as_mut() {
                    if parent == "item" && grand == "instancesSet" {
                        match popped.as_str() {
                            "instanceId" => txt.clone_into(&mut inst.instance_id),
                            "instanceType" => txt.clone_into(&mut inst.instance_type),
                            "platform" | "platformDetails"
                                if txt.to_ascii_lowercase().contains("windows") =>
                            {
                                "windows".clone_into(&mut inst.platform);
                            }
                            "privateIpAddress" => txt.clone_into(&mut inst.private_ip),
                            "ipAddress" => txt.clone_into(&mut inst.public_ip),
                            "vpcId" => txt.clone_into(&mut inst.vpc_id),
                            "subnetId" => txt.clone_into(&mut inst.subnet_id),
                            "launchTime" => txt.clone_into(&mut inst.launch_time),
                            _ => {}
                        }
                    } else if parent == "instanceState" && popped == "name" {
                        txt.clone_into(&mut inst.state);
                    } else if parent == "placement" && popped == "availabilityZone" {
                        txt.clone_into(&mut inst.availability_zone);
                    } else if parent == "item" && grand == "tagSet" {
                        if popped == "key" {
                            txt.clone_into(&mut tag_key);
                        } else if popped == "value" {
                            txt.clone_into(&mut tag_val);
                        }
                    } else if popped == "item" && parent == "tagSet" && !tag_key.is_empty() {
                        if tag_key == "Name" {
                            inst.name.clone_from(&tag_val);
                        }
                        inst.tags.insert(tag_key.clone(), tag_val.clone());
                    } else if !in_eni
                        && parent == "item"
                        && grand == "groupSet"
                        && popped == "groupId"
                    {
                        txt.clone_into(&mut cur_sg);
                    } else if !in_eni
                        && popped == "item"
                        && parent == "groupSet"
                        && !cur_sg.is_empty()
                        && !inst.security_groups.contains(&cur_sg)
                    {
                        inst.security_groups.push(cur_sg.clone());
                    }
                }
                if name == "item" && parent == "instancesSet" {
                    if let Some(mut finished) = cur.take() {
                        if finished.name.is_empty() {
                            finished.name.clone_from(&finished.instance_id);
                        }
                        out.push(finished);
                    }
                }
                cur_text.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("EC2 XML parse error: {e}")),
            _ => {}
        }
    }
    Ok(out)
}

fn parse_describe_regions_xml(xml: &str) -> Vec<String> {
    let mut reader = Reader::from_str(xml);
    let mut in_item = false;
    let mut cur_tag = String::new();
    let mut cur_text = String::new();
    let mut region_name = String::new();
    let mut opt_in = String::new();
    let mut out = Vec::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = e.name().into_inner().to_owned();
                if name == "item" {
                    in_item = true;
                    region_name.clear();
                    opt_in.clear();
                } else if in_item {
                    cur_tag = name;
                }
                cur_text.clear();
            }
            Ok(Event::Text(t)) => {
                cur_text.push_str(t.xml10_content().as_ref());
            }
            Ok(Event::GeneralRef(r)) => {
                if append_xml_ref(&mut cur_text, &r).is_err() {
                    break;
                }
            }
            Ok(Event::End(e)) => {
                let name = e.name().into_inner();
                if in_item {
                    if name == "item" {
                        if !region_name.is_empty() && opt_in != "not-opted-in" {
                            out.push(region_name.clone());
                        }
                        in_item = false;
                    } else if cur_tag == "regionName" {
                        cur_text.trim().clone_into(&mut region_name);
                    } else if cur_tag == "optInStatus" {
                        cur_text.trim().clone_into(&mut opt_in);
                    }
                    cur_tag.clear();
                }
                cur_text.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}
