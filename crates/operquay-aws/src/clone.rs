#![forbid(unsafe_code)]

//! EC2 Instance Cloning Lifecycle (`CreateImage` -> Pre-filled Launch Settings -> `RunInstances` + Recovery).

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::accounts::xml_tag_text;
use crate::discovery::Ec2Instance;
use crate::sigv4::{now_unix_secs, sign_request, uri_encode, AwsCredentials};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloneStatus {
    pub id: String,
    pub tenant_id: String,
    pub owner_user_id: String,
    pub source_instance_id: String,
    pub source_name: String,
    pub clone_name: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub ami_id: String,
    #[serde(default)]
    pub image_id: String,
    #[serde(default)]
    pub image_name: String,
    pub phase: String,
    pub progress: u8,
    pub message: String,
    #[serde(default)]
    pub new_instance_id: String,
    #[serde(default)]
    pub instance_id: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetOption {
    pub subnet_id: String,
    pub az: String,
    pub cidr: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SgOption {
    pub group_id: String,
    pub group_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloneSettings {
    pub ami_id: String,
    pub instance_type: String,
    pub subnet_id: String,
    pub security_group_ids: Vec<String>,
    #[serde(default)]
    pub key_name: String,
    #[serde(default)]
    pub iam_profile: String,
    #[serde(default)]
    pub tags: HashMap<String, String>,
    #[serde(default)]
    pub available_subnets: Vec<SubnetOption>,
    #[serde(default)]
    pub available_sgs: Vec<SgOption>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LaunchCloneRequest {
    #[serde(default)]
    pub clone_id: String,
    #[serde(default)]
    pub instance_type: String,
    #[serde(default)]
    pub subnet_id: String,
    #[serde(default)]
    pub security_group_ids: Vec<String>,
    #[serde(default)]
    pub clone_name: String,
    #[serde(default)]
    pub key_name: String,
    #[serde(default)]
    pub iam_profile: String,
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

pub struct CloneManager {
    clones: RwLock<HashMap<String, CloneStatus>>,
    http: reqwest::Client,
    ec2_endpoint_override: Option<String>,
}

impl Default for CloneManager {
    fn default() -> Self {
        Self::new(None)
    }
}

impl CloneManager {
    #[must_use]
    pub fn new(ec2_endpoint_override: Option<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self {
            clones: RwLock::new(HashMap::new()),
            http,
            ec2_endpoint_override,
        }
    }

    pub async fn start_clone(
        &self,
        tenant_id: &str,
        owner_user_id: &str,
        source: &Ec2Instance,
        clone_name: &str,
        creds: Option<&AwsCredentials>,
    ) -> Result<CloneStatus, String> {
        let final_name = if clone_name.trim().is_empty() {
            format!("{}-clone", source.name)
        } else {
            clone_name.trim().to_owned()
        };
        let ami_id = if let Some(c) = creds {
            let base = self
                .ec2_endpoint_override
                .clone()
                .unwrap_or_else(|| format!("https://ec2.{}.amazonaws.com/", source.region));
            let ami_label = format!("{final_name}-{}", now_unix_secs());
            let url = format!(
                "{base}?Action=CreateImage&InstanceId={}&Name={}&NoReboot=true&Version=2016-11-15",
                uri_encode(&source.instance_id, true),
                uri_encode(&ami_label, true),
            );
            let mut headers = http::HeaderMap::new();
            sign_request(
                "POST",
                &url,
                &mut headers,
                b"",
                c,
                &source.region,
                "ec2",
                None,
            )?;
            let resp = self
                .http
                .post(&url)
                .headers(headers)
                .send()
                .await
                .map_err(|e| format!("EC2 CreateImage error: {e}"))?;
            let status = resp.status();
            let text = resp.text().await.map_err(|e| e.to_string())?;
            if !status.is_success() {
                return Err(format!("CreateImage failed ({status}): {text}"));
            }
            xml_tag_text(&text, "imageId")
                .unwrap_or_else(|| format!("ami-{}", &Uuid::new_v4().to_string()[..8]))
        } else {
            format!("ami-{}", &Uuid::new_v4().to_string()[..8])
        };

        let live_aws = creds.is_some() && self.ec2_endpoint_override.is_none();
        let (phase, progress, msg) = if live_aws {
            (
                "image_pending".to_owned(),
                25,
                format!("Creating AMI {ami_id}..."),
            )
        } else {
            (
                "ami_ready".to_owned(),
                50,
                format!("AMI ready for launch: {ami_id}"),
            )
        };

        let status = CloneStatus {
            id: format!("cln-{}", Uuid::new_v4()),
            tenant_id: tenant_id.to_owned(),
            owner_user_id: owner_user_id.to_owned(),
            source_instance_id: source.instance_id.clone(),
            source_name: source.name.clone(),
            clone_name: final_name.clone(),
            region: source.region.clone(),
            ami_id: ami_id.clone(),
            image_id: ami_id,
            image_name: final_name,
            phase,
            progress,
            message: msg,
            new_instance_id: String::new(),
            instance_id: String::new(),
            created_at: now_unix_secs(),
        };
        self.clones
            .write()
            .await
            .insert(status.id.clone(), status.clone());
        Ok(status)
    }

    /// Poll AWS `ec2:DescribeImages` to advance an `image_pending` clone status.
    pub async fn refresh_clone_status(
        &self,
        tenant_id: &str,
        id: &str,
        creds: &AwsCredentials,
    ) -> Result<CloneStatus, String> {
        let cur = self
            .get_status(tenant_id, id)
            .await
            .ok_or_else(|| "clone operation not found".to_owned())?;
        if cur.ami_id.is_empty() || cur.phase == "complete" {
            return Ok(cur);
        }
        let base = self
            .ec2_endpoint_override
            .clone()
            .unwrap_or_else(|| format!("https://ec2.{}.amazonaws.com/", cur.region));
        let url = format!(
            "{base}?Action=DescribeImages&ImageId.1={}&Version=2016-11-15",
            uri_encode(&cur.ami_id, true)
        );
        let mut headers = http::HeaderMap::new();
        sign_request(
            "POST",
            &url,
            &mut headers,
            b"",
            creds,
            &cur.region,
            "ec2",
            None,
        )?;
        let resp = self
            .http
            .post(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| format!("EC2 DescribeImages error: {e}"))?;
        let status = resp.status();
        let text = resp.text().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("DescribeImages failed ({status}): {text}"));
        }
        let img_state = xml_tag_text(&text, "imageState").unwrap_or_default();
        let mut guard = self.clones.write().await;
        let rec = guard
            .get_mut(id)
            .filter(|c| c.tenant_id == tenant_id)
            .ok_or_else(|| "clone operation not found".to_owned())?;
        match img_state.as_str() {
            "available" => {
                "image_ready".clone_into(&mut rec.phase);
                rec.progress = 75;
                rec.message = format!("AMI {} is available for launch", rec.ami_id);
            }
            "failed" | "deregistered" | "error" => {
                "image_failed".clone_into(&mut rec.phase);
                rec.progress = 0;
                rec.message = format!("AMI {} entered state: {img_state}", rec.ami_id);
            }
            _ => {
                "image_pending".clone_into(&mut rec.phase);
                rec.progress = 50;
                rec.message = format!(
                    "AMI {} state: {}",
                    rec.ami_id,
                    if img_state.is_empty() {
                        "pending"
                    } else {
                        &img_state
                    }
                );
            }
        }
        Ok(rec.clone())
    }

    pub async fn list_clones(&self, tenant_id: &str) -> Vec<CloneStatus> {
        let mut out: Vec<_> = self
            .clones
            .read()
            .await
            .values()
            .filter(|c| c.tenant_id == tenant_id)
            .cloned()
            .collect();
        out.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        out
    }

    pub async fn hydrate_clones(&self, items: Vec<CloneStatus>) {
        let mut guard = self.clones.write().await;
        for c in items {
            guard.insert(c.id.clone(), c);
        }
    }

    pub async fn list_recoverable(&self, tenant_id: &str, owner_user_id: &str) -> Vec<CloneStatus> {
        self.list_clones(tenant_id)
            .await
            .into_iter()
            .filter(|c| {
                c.owner_user_id == owner_user_id
                    && !c.ami_id.is_empty()
                    && c.new_instance_id.is_empty()
            })
            .collect()
    }

    pub async fn get_status(&self, tenant_id: &str, id: &str) -> Option<CloneStatus> {
        self.clones
            .read()
            .await
            .get(id)
            .filter(|c| c.tenant_id == tenant_id)
            .cloned()
    }

    pub async fn recover_clone(
        &self,
        tenant_id: &str,
        owner_user_id: &str,
        id: &str,
    ) -> Option<CloneStatus> {
        let mut guard = self.clones.write().await;
        let rec = guard.get_mut(id).filter(|c| c.tenant_id == tenant_id)?;
        owner_user_id.clone_into(&mut rec.owner_user_id);
        rec.message = format!("Clone {} recovered to current session", rec.id);
        Some(rec.clone())
    }

    pub async fn settings_for_clone(
        &self,
        tenant_id: &str,
        id: &str,
        source: Option<&Ec2Instance>,
    ) -> Option<CloneSettings> {
        self.settings_for_clone_live(tenant_id, id, source, None)
            .await
    }

    pub async fn settings_for_clone_live(
        &self,
        tenant_id: &str,
        id: &str,
        source: Option<&Ec2Instance>,
        creds: Option<&AwsCredentials>,
    ) -> Option<CloneSettings> {
        let st = self.get_status(tenant_id, id).await?;
        let inst_type = source.map_or_else(|| "t3.medium".to_owned(), |s| s.instance_type.clone());
        let subnet_id = source.map_or_else(String::new, |s| s.subnet_id.clone());
        let vpc_id = source.map_or_else(String::new, |s| s.vpc_id.clone());
        let sgs = source.map_or_else(Vec::new, |s| s.security_groups.clone());
        let tags = source.map_or_else(HashMap::new, |s| s.tags.clone());

        let mut available_subnets = if subnet_id.is_empty() {
            Vec::new()
        } else {
            vec![SubnetOption {
                subnet_id: subnet_id.clone(),
                az: source.map_or_default(|s| s.availability_zone.clone()),
                cidr: String::new(),
                name: "source-subnet".to_owned(),
            }]
        };
        let mut available_sgs: Vec<SgOption> = sgs
            .iter()
            .cloned()
            .map(|gid| SgOption {
                group_id: gid.clone(),
                group_name: gid,
            })
            .collect();
        let mut warnings = Vec::new();

        if let (Some(c), false) = (creds, vpc_id.is_empty()) {
            let base = self
                .ec2_endpoint_override
                .clone()
                .unwrap_or_else(|| format!("https://ec2.{}.amazonaws.com/", st.region));
            let sub_url = format!(
                "{base}?Action=DescribeSubnets&Filter.1.Name=vpc-id&Filter.1.Value.1={}&Version=2016-11-15",
                uri_encode(&vpc_id, true)
            );
            let mut h1 = http::HeaderMap::new();
            if sign_request("POST", &sub_url, &mut h1, b"", c, &st.region, "ec2", None).is_ok() {
                if let Ok(r) = self.http.post(&sub_url).headers(h1).send().await {
                    if r.status().is_success() {
                        if let Ok(xml) = r.text().await {
                            let parsed = parse_subnet_options_xml(&xml);
                            if !parsed.is_empty() {
                                available_subnets = parsed;
                            }
                        }
                    } else {
                        warnings.push(format!("DescribeSubnets HTTP {}", r.status()));
                    }
                }
            }

            let sg_url = format!(
                "{base}?Action=DescribeSecurityGroups&Filter.1.Name=vpc-id&Filter.1.Value.1={}&Version=2016-11-15",
                uri_encode(&vpc_id, true)
            );
            let mut h2 = http::HeaderMap::new();
            if sign_request("POST", &sg_url, &mut h2, b"", c, &st.region, "ec2", None).is_ok() {
                if let Ok(r) = self.http.post(&sg_url).headers(h2).send().await {
                    if r.status().is_success() {
                        if let Ok(xml) = r.text().await {
                            let parsed = parse_sg_options_xml(&xml);
                            if !parsed.is_empty() {
                                available_sgs = parsed;
                            }
                        }
                    } else {
                        warnings.push(format!("DescribeSecurityGroups HTTP {}", r.status()));
                    }
                }
            }
        }

        Some(CloneSettings {
            ami_id: st.ami_id,
            instance_type: inst_type,
            subnet_id,
            security_group_ids: sgs,
            key_name: String::new(),
            iam_profile: String::new(),
            tags,
            available_subnets,
            available_sgs,
            warnings,
        })
    }

    pub async fn launch_clone(
        &self,
        tenant_id: &str,
        id: &str,
        req: &LaunchCloneRequest,
        creds: Option<&AwsCredentials>,
    ) -> Result<CloneStatus, String> {
        let st = self
            .get_status(tenant_id, id)
            .await
            .ok_or_else(|| "clone operation not found".to_owned())?;
        let new_instance_id = if let Some(c) = creds {
            let base = self
                .ec2_endpoint_override
                .clone()
                .unwrap_or_else(|| format!("https://ec2.{}.amazonaws.com/", st.region));
            let inst_type = if req.instance_type.is_empty() {
                "t3.medium"
            } else {
                &req.instance_type
            };
            let mut url = format!(
                "{base}?Action=RunInstances&ImageId={}&InstanceType={}&MinCount=1&MaxCount=1&Version=2016-11-15",
                uri_encode(&st.ami_id, true),
                uri_encode(inst_type, true),
            );
            if !req.subnet_id.trim().is_empty() {
                url.push_str("&SubnetId=");
                url.push_str(&uri_encode(req.subnet_id.trim(), true));
            }
            for (idx, sg) in req.security_group_ids.iter().enumerate() {
                if !sg.trim().is_empty() {
                    use std::fmt::Write as _;
                    let _ = write!(
                        url,
                        "&SecurityGroupId.{}={}",
                        idx + 1,
                        uri_encode(sg.trim(), true)
                    );
                }
            }
            if !req.key_name.trim().is_empty() {
                url.push_str("&KeyName=");
                url.push_str(&uri_encode(req.key_name.trim(), true));
            }
            if !req.iam_profile.trim().is_empty() {
                url.push_str("&IamInstanceProfile.Name=");
                url.push_str(&uri_encode(req.iam_profile.trim(), true));
            }
            let mut tag_idx = 0usize;
            let name_tag = if req.clone_name.trim().is_empty() {
                &st.clone_name
            } else {
                req.clone_name.trim()
            };
            if !name_tag.is_empty() {
                use std::fmt::Write as _;
                tag_idx += 1;
                let _ = write!(
                    url,
                    "&TagSpecification.1.ResourceType=instance&TagSpecification.1.Tag.{tag_idx}.Key=Name&TagSpecification.1.Tag.{tag_idx}.Value={}",
                    uri_encode(name_tag, true)
                );
            }
            for (k, v) in &req.tags {
                if !k.trim().is_empty() && k != "Name" {
                    use std::fmt::Write as _;
                    if tag_idx == 0 {
                        url.push_str("&TagSpecification.1.ResourceType=instance");
                    }
                    tag_idx += 1;
                    let _ = write!(
                        url,
                        "&TagSpecification.1.Tag.{tag_idx}.Key={}&TagSpecification.1.Tag.{tag_idx}.Value={}",
                        uri_encode(k.trim(), true),
                        uri_encode(v.trim(), true),
                    );
                }
            }
            let mut headers = http::HeaderMap::new();
            sign_request("POST", &url, &mut headers, b"", c, &st.region, "ec2", None)?;
            let resp = self
                .http
                .post(&url)
                .headers(headers)
                .send()
                .await
                .map_err(|e| format!("EC2 RunInstances error: {e}"))?;
            let status = resp.status();
            let text = resp.text().await.map_err(|e| e.to_string())?;
            if !status.is_success() {
                return Err(format!("RunInstances failed ({status}): {text}"));
            }
            xml_tag_text(&text, "instanceId")
                .unwrap_or_else(|| format!("i-{}", &Uuid::new_v4().to_string()[..12]))
        } else {
            format!("i-{}", &Uuid::new_v4().to_string()[..12])
        };

        let mut guard = self.clones.write().await;
        let rec = guard
            .get_mut(id)
            .ok_or_else(|| "clone operation missing".to_owned())?;
        "complete".clone_into(&mut rec.phase);
        rec.progress = 100;
        rec.new_instance_id.clone_from(&new_instance_id);
        rec.instance_id.clone_from(&new_instance_id);
        rec.message = format!("Launched cloned instance {new_instance_id}");
        Ok(rec.clone())
    }
}

fn parse_subnet_options_xml(xml: &str) -> Vec<SubnetOption> {
    let mut out = Vec::new();
    let Some(s) = xml.find("<subnetSet>") else {
        return out;
    };
    let mut rest = &xml[s..];
    while let Some(a) = rest.find("<subnetId>") {
        let block = &rest[a..];
        let Some(end) = block.find("</item>") else {
            break;
        };
        let chunk = &block[..end];
        let subnet_id = xml_tag_text(chunk, "subnetId").unwrap_or_default();
        if !subnet_id.is_empty() {
            let az = xml_tag_text(chunk, "availabilityZone").unwrap_or_default();
            let cidr = xml_tag_text(chunk, "cidrBlock").unwrap_or_default();
            let name = xml_tag_text(chunk, "value").unwrap_or_else(|| subnet_id.clone());
            out.push(SubnetOption {
                subnet_id,
                az,
                cidr,
                name,
            });
        }
        rest = &block[end + 7..];
    }
    out
}

fn parse_sg_options_xml(xml: &str) -> Vec<SgOption> {
    let mut out = Vec::new();
    let Some(s) = xml.find("<securityGroupInfo>") else {
        return out;
    };
    let mut rest = &xml[s..];
    while let Some(a) = rest.find("<groupId>") {
        let block = &rest[a..];
        let Some(end) = block.find("</item>") else {
            break;
        };
        let chunk = &block[..end];
        let group_id = xml_tag_text(chunk, "groupId").unwrap_or_default();
        if !group_id.is_empty() {
            let group_name = xml_tag_text(chunk, "groupName").unwrap_or_else(|| group_id.clone());
            out.push(SgOption {
                group_id,
                group_name,
            });
        }
        rest = &block[end + 7..];
    }
    out
}
