#![forbid(unsafe_code)]

//! Complete pure-Rust AWS Control Plane (`crates/operquay-aws`):
//! `SigV4` request/URL signing, encrypted manual accounts, explicit user role bindings & 5s fences,
//! AWS SSO device auth, EC2/ELB discovery, SSM Shell + resume + transcript exports,
//! chunked SSM file browser/upload/download + S3 Express, AMI EC2 Cloning,
//! and `petgraph` VPC Network Topology & Reachability/Exposure/Conflict analysis.

pub mod access_graph;
pub mod accounts;
pub mod clone;
pub mod discovery;
pub mod profiles;
pub mod shell;
pub mod sigv4;
pub mod sso;
pub mod topology;
pub mod transfer;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::routing::post;
    use axum::{Json, Router};
    use base64::Engine as _;
    use tokio::net::TcpListener;

    use crate::accounts::{AddAwsAccountRequest, AwsAccessMode, AwsAccountStore};
    use crate::clone::{CloneManager, LaunchCloneRequest};
    use crate::discovery::{parse_describe_instances_xml, Ec2DiscoveryStore};
    use crate::sigv4::{format_amz_datetime, presign_url, sign_request, AwsCredentials};
    use crate::sso::AwsSsoManager;
    use crate::topology::{
        analyze_exposure, analyze_reachability, analyze_rule_conflicts, build_topology_graph,
        GatewayNode, NaclRuleInfo, NetworkAclInfo, RouteEntry, RouteTableInfo, SecurityGroupInfo,
        SgRuleInfo, SubnetInfo, TopologyInstance, VpcInfo, VpcTopology,
    };
    use crate::transfer::{parse_ls_output, split_upload_base64_chunks};

    #[test]
    fn formats_amz_datetime_and_signs_sigv4_and_presigned_urls() {
        assert_eq!(
            format_amz_datetime(0),
            ("19700101T000000Z".to_owned(), "19700101".to_owned())
        );
        assert_eq!(
            format_amz_datetime(1_735_689_600),
            ("20250101T000000Z".to_owned(), "20250101".to_owned())
        );

        let creds = AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: Some("tok-123".into()),
        };
        let mut headers = http::HeaderMap::new();
        sign_request(
            "POST",
            "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity",
            &mut headers,
            b"",
            &creds,
            "us-east-1",
            "sts",
            Some(1_735_689_600),
        )
        .unwrap();
        let auth = headers
            .get(http::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(auth.contains(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20250101/us-east-1/sts/aws4_request"
        ));

        let presigned = presign_url(
            "GET",
            "wss://ssmmessages.us-east-1.amazonaws.com/v1/data-channel/sess-1",
            &creds,
            "us-east-1",
            "ssmmessages",
            60,
            Some(1_735_689_600),
        )
        .unwrap();
        assert!(presigned
            .starts_with("wss://ssmmessages.us-east-1.amazonaws.com/v1/data-channel/sess-1?"));
        assert!(presigned.contains("X-Amz-Signature="));

        let eks_tok =
            crate::sigv4::presign_eks_token("prod-eks", "us-west-2", &creds, Some(1_735_689_600))
                .unwrap();
        assert!(eks_tok.starts_with("k8s-aws-v1."));
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(eks_tok.strip_prefix("k8s-aws-v1.").unwrap())
            .unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert!(decoded_str.starts_with("https://sts.us-west-2.amazonaws.com/?"));
        assert!(decoded_str.contains("X-Amz-SignedHeaders=host%3Bx-k8s-aws-id"));
        assert!(decoded_str.contains("X-Amz-Expires=60"));
    }

    #[tokio::test]
    async fn manages_aead_aws_accounts_user_bindings_fence_and_ec2_xml_discovery() {
        let sts_app = Router::new().route(
            "/",
            post(|| async {
                "<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/ops</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>"
            }),
        );
        let sts_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sts_addr = sts_ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(sts_ln, sts_app).await;
        });

        let store = AwsAccountStore::new(AwsAccessMode::User, Some(format!("http://{sts_addr}/")));
        let added = store
            .add_account(
                "acme",
                AddAwsAccountRequest {
                    name: "prod".into(),
                    access_key_id: "AKIA123".into(),
                    secret_access_key: "SECRET999".into(),
                    session_token: String::new(),
                    role_arn: "arn:aws:iam::123456789012:role/OperquayAccess".into(),
                    external_id: "ext-1".into(),
                    default_region: "us-west-2".into(),
                },
            )
            .await
            .unwrap();
        let creds = store
            .credentials_for_account("acme", &added.id)
            .await
            .unwrap();
        assert_eq!(creds.secret_access_key, "SECRET999");

        let verified = store.verify_account("acme", &added.id).await.unwrap();
        assert!(verified.verified);
        assert_eq!(verified.aws_account_id, "123456789012");

        // Role bindings & 5s session fence
        let binding = store
            .create_user_binding(
                "acme",
                "usr-1",
                "Prod Ops",
                "arn:aws:iam::123456789012:role/Ops",
                "",
                "us-west-2",
            )
            .await
            .unwrap();
        let _ = store
            .connect_role_lease("acme", "usr-1", &binding.id, creds)
            .await
            .unwrap();
        assert_eq!(store.list_connected_roles("acme", "usr-1").await.len(), 1);
        store.disconnect_all_user_roles("acme", "usr-1").await;
        assert!(store.is_user_fenced("acme", "usr-1").await);
        assert!(store.list_connected_roles("acme", "usr-1").await.is_empty());

        // EC2 XML parsing + Discovery Store
        let xml = r"<DescribeInstancesResponse>
          <reservationSet><item><instancesSet><item>
            <instanceId>i-0abc123</instanceId>
            <instanceState><name>running</name></instanceState>
            <instanceType>m6i.large</instanceType>
            <privateIpAddress>10.0.1.50</privateIpAddress>
            <vpcId>vpc-1</vpcId><subnetId>subnet-1</subnetId>
            <placement><availabilityZone>us-west-2a</availabilityZone></placement>
            <tagSet><item><key>Name</key><value>web-01</value></item></tagSet>
            <groupSet><item><groupId>sg-1</groupId></item></groupSet>
          </item></instancesSet></item></reservationSet>
        </DescribeInstancesResponse>";
        let parsed =
            parse_describe_instances_xml(xml, "123456789012", "prod", "us-west-2").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "web-01");
        let disc = Ec2DiscoveryStore::default();
        disc.seed_instances("acme", parsed).await;
        assert_eq!(disc.fleet_stats("acme").await.running, 1);
    }

    #[tokio::test]
    async fn runs_aws_sso_device_flow_ec2_clone_chunks_and_petgraph_topology_reachability() {
        let sso_app = Router::new()
            .route(
                "/client/register",
                post(|| async {
                    Json(serde_json::json!({"clientId":"cid","clientSecret":"csec"}))
                }),
            )
            .route(
                "/device_authorization",
                post(|| async {
                    Json(serde_json::json!({
                        "deviceCode": "dc-1",
                        "userCode": "ABCD-EFGH",
                        "verificationUri": "https://device.sso.us-east-1.amazonaws.com/",
                        "expiresIn": 600,
                        "interval": 1
                    }))
                }),
            )
            .route(
                "/token",
                post(|| async { Json(serde_json::json!({"accessToken": "sso-tok-xyz"})) }),
            );
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(ln, sso_app).await;
        });

        let mgr = Arc::new(AwsSsoManager::new(Some(format!("http://{addr}")), None));
        let started = mgr
            .start_device_auth("default", "u1", "us-east-1", "https://my.awsapps.com/start")
            .await
            .unwrap();
        assert_eq!(started.user_code, "ABCD-EFGH");
        assert_eq!(
            mgr.poll_token("default", "u1", &started.id).await.unwrap(),
            "authorized"
        );
        assert_eq!(mgr.session_status("default", "u1").await["connected"], true);

        // Chunks & ls parser
        assert_eq!(split_upload_base64_chunks(&vec![b'A'; 4096]).len(), 3);
        let ls = parse_ls_output(
            "/var/log",
            "total 8\ndrwxr-xr-x 2 root root 4096 2026-11-16 09:00 nginx\n-rw-r--r-- 1 root root 128 2026-11-16 09:01 app.log\n",
        );
        assert_eq!(ls.len(), 2);
        assert!(ls[0].is_dir);

        // Clone manager
        let cm = CloneManager::default();
        let inst = parse_describe_instances_xml(
            "<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-src</instanceId><vpcId>vpc-1</vpcId><subnetId>sub-1</subnetId><instanceState><name>running</name></instanceState></item></instancesSet></item></reservationSet></DescribeInstancesResponse>",
            "123",
            "hub",
            "us-east-1",
        )
        .unwrap()
        .pop()
        .unwrap();
        let cloned = cm
            .start_clone("default", "u1", &inst, "clone-box", None)
            .await
            .unwrap();
        assert_eq!(cloned.phase, "ami_ready");
        let launched = cm
            .launch_clone(
                "default",
                &cloned.id,
                &LaunchCloneRequest {
                    clone_id: cloned.id.clone(),
                    instance_type: "t3.large".into(),
                    subnet_id: "sub-1".into(),
                    security_group_ids: vec![],
                    clone_name: "clone-box".into(),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(launched.phase, "complete");
        assert!(launched.new_instance_id.starts_with("i-"));

        // Petgraph Topology + Reachability + Exposure + Rule Conflicts
        let topo = VpcTopology {
            vpc: VpcInfo {
                id: "vpc-1".into(),
                cidr: "10.0.0.0/16".into(),
                name: "main".into(),
                is_default: false,
            },
            subnets: vec![SubnetInfo {
                id: "sub-1".into(),
                cidr: "10.0.1.0/24".into(),
                name: "pub".into(),
                az: "us-east-1a".into(),
                is_public: true,
                available_ips: 250,
                route_table_id: "rtb-1".into(),
                network_acl_id: "acl-1".into(),
            }],
            instances: vec![
                TopologyInstance {
                    id: "i-a".into(),
                    name: "bastion".into(),
                    private_ip: "10.0.1.10".into(),
                    public_ip: "1.2.3.4".into(),
                    state: "running".into(),
                    platform: "linux".into(),
                    instance_type: "t3.micro".into(),
                    subnet_id: "sub-1".into(),
                    security_groups: vec!["sg-open".into()],
                },
                TopologyInstance {
                    id: "i-b".into(),
                    name: "db".into(),
                    private_ip: "10.0.1.20".into(),
                    public_ip: String::new(),
                    state: "running".into(),
                    platform: "linux".into(),
                    instance_type: "t3.large".into(),
                    subnet_id: "sub-1".into(),
                    security_groups: vec!["sg-db".into()],
                },
            ],
            security_groups: vec![
                SecurityGroupInfo {
                    id: "sg-open".into(),
                    name: "open".into(),
                    description: String::new(),
                    rules: vec![
                        SgRuleInfo {
                            direction: "egress".into(),
                            protocol: "-1".into(),
                            from_port: 0,
                            to_port: 0,
                            cidr_or_sg: "0.0.0.0/0".into(),
                        },
                        SgRuleInfo {
                            direction: "ingress".into(),
                            protocol: "-1".into(),
                            from_port: 0,
                            to_port: 0,
                            cidr_or_sg: "0.0.0.0/0".into(),
                        },
                        SgRuleInfo {
                            direction: "ingress".into(),
                            protocol: "tcp".into(),
                            from_port: 22,
                            to_port: 22,
                            cidr_or_sg: "0.0.0.0/0".into(),
                        },
                    ],
                },
                SecurityGroupInfo {
                    id: "sg-db".into(),
                    name: "db".into(),
                    description: String::new(),
                    rules: vec![SgRuleInfo {
                        direction: "ingress".into(),
                        protocol: "tcp".into(),
                        from_port: 5432,
                        to_port: 5432,
                        cidr_or_sg: "10.0.1.0/24".into(),
                    }],
                },
            ],
            network_acls: vec![NetworkAclInfo {
                id: "acl-1".into(),
                name: "default".into(),
                rules: vec![
                    NaclRuleInfo {
                        rule_number: 50,
                        direction: "ingress".into(),
                        protocol: "-1".into(),
                        from_port: 0,
                        to_port: 0,
                        cidr: "0.0.0.0/0".into(),
                        action: "DENY".into(),
                    },
                    NaclRuleInfo {
                        rule_number: 100,
                        direction: "ingress".into(),
                        protocol: "tcp".into(),
                        from_port: 5432,
                        to_port: 5432,
                        cidr: "10.0.1.0/24".into(),
                        action: "ALLOW".into(),
                    },
                ],
            }],
            route_tables: vec![RouteTableInfo {
                id: "rtb-1".into(),
                name: "main-rt".into(),
                routes: vec![RouteEntry {
                    destination_cidr: "10.0.0.0/16".into(),
                    target: "local".into(),
                    state: "active".into(),
                }],
                subnets: vec!["sub-1".into()],
            }],
            internet_gateways: vec![GatewayNode {
                id: "igw-1".into(),
                name: "igw".into(),
            }],
            ..VpcTopology::default()
        };

        let graph = build_topology_graph(&topo);
        assert!(graph.node_count() >= 5);
        let reach = analyze_reachability(&topo, "i-a", "i-b", "tcp", 5432);
        assert!(!reach.reachable); // blocked by rule #50 DENY 0.0.0.0/0!
        let exp = analyze_exposure(&topo);
        assert_eq!(exp.exposed_instances.len(), 1);
        assert!(!exp.exposed_ports.is_empty());
        let conflicts = analyze_rule_conflicts(&topo);
        assert!(conflicts
            .iter()
            .any(|c| c.conflict_type == "redundant_sg_rule"));
        assert!(conflicts
            .iter()
            .any(|c| c.conflict_type == "shadowed_nacl_rule"));
    }

    #[tokio::test]
    async fn runs_full_sigv4_ssm_start_session_datachannel_and_terminate_roundtrip() {
        use axum::extract::ws::{Message as WsMsg, WebSocketUpgrade};
        use futures_util::StreamExt;
        use operquay_ssm::{message_type, AgentMessage, PayloadType};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ws_url = format!("ws://{addr}/v1/data-channel/ssm-full-1");

        let app = Router::new()
            .route(
                "/",
                post(move |headers: http::HeaderMap, raw_body: String| {
                    let ws_u = ws_url.clone();
                    async move {
                        let body: serde_json::Value =
                            serde_json::from_str(&raw_body).unwrap_or_default();
                        let target = headers
                            .get("x-amz-target")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        assert!(headers.get(http::header::AUTHORIZATION).is_some());
                        if target == "AmazonSSM.StartSession" {
                            assert_eq!(body["Target"].as_str(), Some("i-0deadbeef12345678"));
                            Json(serde_json::json!({
                                "SessionId": "ssm-full-1",
                                "StreamUrl": ws_u,
                                "TokenValue": "tok-full-1"
                            }))
                        } else {
                            assert_eq!(target, "AmazonSSM.TerminateSession");
                            assert_eq!(body["SessionId"].as_str(), Some("ssm-full-1"));
                            Json(serde_json::json!({ "SessionId": "ssm-full-1" }))
                        }
                    }
                }),
            )
            .route(
                "/v1/data-channel/ssm-full-1",
                axum::routing::get(|ws: WebSocketUpgrade| async move {
                    ws.on_upgrade(|mut sock| async move {
                        let _ = sock.next().await; // OpenDataChannelInput
                        let hs = AgentMessage::data(
                            message_type::OUTPUT_STREAM_DATA,
                            0,
                            PayloadType::HandshakeRequest,
                            br#"{"RequestedClientActions":[]}"#.to_vec(),
                        );
                        sock.send(WsMsg::Binary(hs.encode().into())).await.unwrap();
                        while let Some(Ok(WsMsg::Binary(raw))) = sock.next().await {
                            let dec = AgentMessage::decode(&raw).unwrap();
                            if dec.message_type == message_type::INPUT_STREAM_DATA
                                && dec.payload_type == PayloadType::Output as u32
                            {
                                let out = AgentMessage::data(
                                    message_type::OUTPUT_STREAM_DATA,
                                    1,
                                    PayloadType::Output,
                                    dec.payload,
                                );
                                sock.send(WsMsg::Binary(out.encode().into())).await.unwrap();
                                break;
                            }
                        }
                    })
                }),
            );

        let srv = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let store = crate::shell::SsmShellStore::new(Some(format!("http://{addr}/")));
        let creds = AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        };
        let shut = Arc::new(tokio::sync::Notify::new());
        let (started, mut stream) = store
            .connect_port_forward_tunnel(
                "us-east-1",
                "i-0deadbeef12345678",
                3389,
                &creds,
                shut.clone(),
            )
            .await
            .unwrap();
        assert_eq!(started.session_id, "ssm-full-1");

        stream.write_all(b"TPKT-RDP-PING").await.unwrap();
        let mut buf = [0u8; 13];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"TPKT-RDP-PING");

        shut.notify_waiters();
        store
            .terminate_session("us-east-1", &started.session_id, &creds)
            .await
            .unwrap();
        srv.abort();
    }

    #[tokio::test]
    async fn retries_sso_list_account_roles_on_429_throttling() {
        use axum::{http::StatusCode, response::IntoResponse, routing::get, routing::post, Router};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let role_hits = Arc::new(AtomicUsize::new(0));
        let role_hits_c = role_hits.clone();

        let app = Router::new()
            .route(
                "/client/register",
                post(|| async {
                    axum::Json(serde_json::json!({
                        "clientId": "cid-test",
                        "clientSecret": "csec-test"
                    }))
                }),
            )
            .route(
                "/device_authorization",
                post(|| async {
                    axum::Json(serde_json::json!({
                        "deviceCode": "dev-429",
                        "userCode": "AAAA-BBBB",
                        "verificationUri": "https://device.example.com",
                        "expiresIn": 600,
                        "interval": 1
                    }))
                }),
            )
            .route(
                "/token",
                post(|| async {
                    axum::Json(serde_json::json!({
                        "accessToken": "sso-token-429",
                        "expiresIn": 3600
                    }))
                }),
            )
            .route(
                "/assignment/accounts",
                get(|| async {
                    axum::Json(serde_json::json!({
                        "accountList": [{
                            "accountId": "111122223333",
                            "accountName": "Test Account",
                            "emailAddress": "ops@example.com"
                        }]
                    }))
                }),
            )
            .route(
                "/assignment/roles",
                get(move || {
                    let hits = role_hits_c.clone();
                    async move {
                        let n = hits.fetch_add(1, Ordering::SeqCst);
                        if n < 2 {
                            (
                                StatusCode::TOO_MANY_REQUESTS,
                                [(axum::http::header::RETRY_AFTER, "0")],
                                "TooManyRequestsException",
                            )
                                .into_response()
                        } else {
                            (
                                StatusCode::OK,
                                axum::Json(serde_json::json!({
                                    "roleList": [
                                        { "accountId": "111122223333", "roleName": "AdministratorAccess" },
                                        { "accountId": "111122223333", "roleName": "ReadOnly" }
                                    ]
                                })),
                            )
                                .into_response()
                        }
                    }
                }),
            );

        let srv = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let base = format!("http://{addr}");
        let mgr = crate::sso::AwsSsoManager::new(Some(base.clone()), Some(base));
        let start = mgr
            .start_device_auth("t1", "u1", "us-east-2", "https://example.awsapps.com/start")
            .await
            .unwrap();
        let st = mgr.poll_token("t1", "u1", &start.id).await.unwrap();
        assert_eq!(st, "authorized");

        let accts = mgr.list_accounts("t1", "u1", &start.id).await.unwrap();
        assert_eq!(accts.len(), 1);
        assert_eq!(
            mgr.account_name("111122223333").await.as_deref(),
            Some("Test Account")
        );

        let roles = mgr
            .list_account_roles("t1", "u1", &start.id, "111122223333")
            .await
            .unwrap();
        assert_eq!(roles.len(), 2);
        assert_eq!(role_hits.load(Ordering::SeqCst), 3);
        srv.abort();
    }

    #[test]
    fn parses_ec2_details_enis_volumes_security_groups_and_ssm_metrics() {
        let inst_xml = r#"<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
            <reservationSet><item><ownerId>111122223333</ownerId><instancesSet><item>
                <instanceId>i-0abc123</instanceId>
                <instanceType>m5.large</instanceType>
                <instanceState><name>running</name></instanceState>
                <privateIpAddress>10.30.1.142</privateIpAddress>
                <placement><availabilityZone>ap-south-1a</availabilityZone></placement>
                <vpcId>vpc-123</vpcId>
                <subnetId>subnet-123</subnetId>
                <groupSet>
                    <item><groupId>sg-1</groupId><groupName>web</groupName></item>
                    <item><groupId>sg-2</groupId><groupName>ssh</groupName></item>
                </groupSet>
                <blockDeviceMapping>
                    <item><deviceName>/dev/sda1</deviceName><ebs><volumeId>vol-1</volumeId><deleteOnTermination>true</deleteOnTermination></ebs></item>
                    <item><deviceName>/dev/sdb</deviceName><ebs><volumeId>vol-2</volumeId><deleteOnTermination>false</deleteOnTermination></ebs></item>
                </blockDeviceMapping>
                <networkInterfaceSet>
                    <item>
                        <networkInterfaceId>eni-1</networkInterfaceId>
                        <subnetId>subnet-123</subnetId>
                        <macAddress>02:aa:bb:cc:dd:ee</macAddress>
                        <privateIpAddress>10.30.1.142</privateIpAddress>
                        <status>in-use</status>
                        <association><publicIp>13.1.2.3</publicIp></association>
                        <groupSet>
                            <item><groupId>sg-1</groupId></item>
                            <item><groupId>sg-2</groupId></item>
                        </groupSet>
                    </item>
                </networkInterfaceSet>
            </item></instancesSet></item></reservationSet>
        </DescribeInstancesResponse>"#;

        let parsed =
            parse_describe_instances_xml(inst_xml, "111122223333", "p", "ap-south-1").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].security_groups, vec!["sg-1", "sg-2"]);

        let enis = crate::discovery::parse_network_interfaces_xml(inst_xml);
        assert_eq!(enis.len(), 1);
        assert_eq!(enis[0]["interface_id"], "eni-1");
        assert_eq!(enis[0]["private_ip"], "10.30.1.142");
        assert_eq!(enis[0]["public_ip"], "13.1.2.3");
        assert_eq!(enis[0]["status"], "in-use");

        let bdms = crate::discovery::parse_block_device_mappings_xml(inst_xml);
        assert_eq!(bdms.len(), 2);
        assert_eq!(bdms[0], ("/dev/sda1".to_owned(), "vol-1".to_owned(), true));
        assert_eq!(bdms[1], ("/dev/sdb".to_owned(), "vol-2".to_owned(), false));

        let vol_xml = r"<DescribeVolumesResponse><volumeSet>
            <item>
                <volumeId>vol-1</volumeId><size>50</size><volumeType>gp3</volumeType><iops>3000</iops>
                <status>in-use</status><availabilityZone>ap-south-1a</availabilityZone><encrypted>true</encrypted>
                <attachmentSet><item><device>/dev/sda1</device></item></attachmentSet>
            </item>
            <item>
                <volumeId>vol-2</volumeId><size>100</size><volumeType>gp2</volumeType>
                <status>in-use</status><availabilityZone>ap-south-1a</availabilityZone><encrypted>false</encrypted>
                <attachmentSet><item><device>/dev/sdb</device></item></attachmentSet>
            </item>
        </volumeSet></DescribeVolumesResponse>";
        let vols = crate::discovery::parse_describe_volumes_xml(vol_xml);
        assert_eq!(vols.len(), 2);
        assert_eq!(vols[0]["volume_id"], "vol-1");
        assert_eq!(vols[0]["size_gib"], 50);
        assert_eq!(vols[0]["encrypted"], true);
        assert_eq!(vols[1]["volume_id"], "vol-2");
        assert_eq!(vols[1]["device"], "/dev/sdb");

        let sg_xml = r"<DescribeSecurityGroupsResponse><securityGroupInfo>
            <item>
                <groupId>sg-1</groupId><groupName>web</groupName><groupDescription>Web SG</groupDescription>
                <ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>443</fromPort><toPort>443</toPort>
                    <ipRanges><item><cidrIp>0.0.0.0/0</cidrIp><description>HTTPS</description></item></ipRanges>
                </item></ipPermissions>
                <ipPermissionsEgress><item><ipProtocol>-1</ipProtocol>
                    <ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges>
                </item></ipPermissionsEgress>
            </item>
        </securityGroupInfo></DescribeSecurityGroupsResponse>";
        let sgs = crate::discovery::parse_security_groups_xml(sg_xml);
        assert_eq!(sgs.len(), 1);
        assert_eq!(sgs[0]["group_name"], "web");
        assert_eq!(sgs[0]["inbound_rules"][0]["from_port"], 443);
        assert_eq!(sgs[0]["outbound_rules"][0]["protocol"], "-1");

        let linux = crate::discovery::parse_ssm_metrics_output(
            "CPU:0.09|CPUS:4|MEMPCT:42.5|MEMTOT:7950|MEMUSED:3378|DISKPCT:31.2|DISKTOT:50.0|DISKUSED:15.6|UPTIME:up 4 days",
        )
        .unwrap();
        assert_eq!(linux.cpu_load, Some(0.09));
        assert_eq!(linux.cpu_count, Some(4));
        assert_eq!(linux.mem_used_pct, Some(42.5));
        assert_eq!(linux.disk_used_pct, Some(31.2));
        assert_eq!(linux.uptime.as_deref(), Some("up 4 days"));
    }

    #[tokio::test]
    async fn hydrates_sso_flows_role_leases_discovery_and_clones_across_restarts() {
        let now = crate::sigv4::now_unix_secs();
        let flow = crate::sso::PersistedSsoFlow {
            id: "flow-1".into(),
            tenant_id: "acme".into(),
            user_id: "u1".into(),
            region: "us-east-1".into(),
            start_url: "https://acme.awsapps.com/start".into(),
            client_id: "cid".into(),
            client_secret: "csec".into(),
            device_code: "dcode".into(),
            access_token: "atok-secret".into(),
            interval_secs: 5,
            expires_at: now + 3600,
            cancelled: false,
        };
        let sso = AwsSsoManager::default();
        sso.hydrate_flows(vec![flow.clone()]).await;
        let roundtrip = sso
            .get_persisted_flow("acme", "u1", "flow-1")
            .await
            .unwrap();
        assert_eq!(roundtrip.access_token, "atok-secret");
        assert!(sso.session_status("acme", "u1").await["active"]
            .as_bool()
            .unwrap());

        let lease = crate::accounts::ConnectedRoleLease {
            id: "lease-1".into(),
            binding_id: "bind-1".into(),
            label: "Prod Admin".into(),
            account_id: "123456789012".into(),
            role_arn: "arn:aws:iam::123456789012:role/Admin".into(),
            role_name: "Admin".into(),
            start_url: String::new(),
            region: "us-east-1".into(),
            status: "connected".into(),
            credential_revision: "rev-1".into(),
            connected_at: now,
            expires_at: now + 3600,
            credentials: AwsCredentials {
                access_key_id: "AKIA123".into(),
                secret_access_key: "SEC123".into(),
                session_token: Some("TOK123".into()),
            },
        };
        let accts = AwsAccountStore::default();
        accts
            .hydrate_leases(vec![("acme".into(), "u1".into(), lease)])
            .await;
        let loaded_lease = accts
            .find_connected_role_lease_for_user("acme", "u1", "lease-1")
            .await
            .unwrap();
        assert_eq!(loaded_lease.credentials.access_key_id, "AKIA123");

        let disc = Ec2DiscoveryStore::default();
        let inst = crate::discovery::Ec2Instance {
            instance_id: "i-hydr1".into(),
            name: "hydr-web".into(),
            state: "running".into(),
            instance_type: "t3.small".into(),
            platform: "linux".into(),
            private_ip: "10.0.1.5".into(),
            public_ip: String::new(),
            region: "us-east-1".into(),
            availability_zone: "us-east-1a".into(),
            vpc_id: "vpc-1".into(),
            subnet_id: "subnet-1".into(),
            account_id: "123456789012".into(),
            profile: "user:lease-1".into(),
            ssm_online: true,
            tags: std::collections::HashMap::new(),
            security_groups: Vec::new(),
            launch_time: String::new(),
        };
        let status = crate::discovery::DiscoveryStatus {
            status: "complete".into(),
            total_instances: 1,
            instance_count: 1,
            last_discovery_unix: now,
            ..Default::default()
        };
        disc.hydrate_inventory("acme", vec![inst], status).await;
        assert_eq!(disc.list_instances("acme").await.len(), 1);
        assert_eq!(disc.get_status("acme").await.instance_count, 1);

        let clones = CloneManager::default();
        clones
            .hydrate_clones(vec![crate::clone::CloneStatus {
                id: "cln-1".into(),
                tenant_id: "acme".into(),
                owner_user_id: "u1".into(),
                source_instance_id: "i-hydr1".into(),
                source_name: "hydr-web".into(),
                clone_name: "hydr-web-clone".into(),
                region: "us-east-1".into(),
                ami_id: "ami-123".into(),
                image_id: "ami-123".into(),
                image_name: "hydr-web-clone".into(),
                phase: "ami_ready".into(),
                progress: 50,
                message: "ready".into(),
                new_instance_id: String::new(),
                instance_id: String::new(),
                created_at: now,
            }])
            .await;
        assert_eq!(clones.list_clones("acme").await.len(), 1);
    }
}
