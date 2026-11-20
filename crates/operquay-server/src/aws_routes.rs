#![forbid(unsafe_code)]

//! AWS Account Management (`hub`/`profiles`/`user`), User Role Bindings & 5s Fence,
//! AWS SSO Device Flow, EC2 Discovery & Fleet Metrics, SSM Shell & Resume (`/ws`,
//! `/api/aws/session-ws`), File Transfers + S3 Express, EC2 Clone Lifecycle,
//! and `petgraph` VPC Network Topology & Reachability/Exposure/Conflict HTTP routes.

use std::sync::Arc;

use axum::extract::ws::{Message as WsMsg, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, FromRequest, MatchedPath, Multipart, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use futures_util::StreamExt;
use operquay_auth::policy::perm;
use operquay_aws::accounts::{
    ambient_aws_credentials, AddAwsAccountRequest, AwsAccessMode, AwsAccountStore, UserPreferences,
};
use operquay_aws::clone::{CloneManager, LaunchCloneRequest};
use operquay_aws::discovery::{DiscoveryStatus, Ec2DiscoveryStore, Ec2Instance};
use operquay_aws::profiles::{load_local_profiles, resolve_profile_credentials};
use operquay_aws::shell::{PersistedUserShell, SsmShellChannel, SsmShellStore, StartedSsmSession};
use operquay_aws::sigv4::{now_unix_secs, AwsCredentials};
use operquay_aws::sso::AwsSsoManager;
use operquay_aws::topology::{
    analyze_exposure, analyze_reachability, analyze_rule_conflicts, build_topology_graph,
    fetch_live_vpc_topology, SecurityGroupInfo, SubnetInfo, TopologyInstance, TopologyStore,
    VpcInfo, VpcTopology,
};
use operquay_aws::transfer::SsmTransferClient;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth_routes::{require_actor, require_any_perm};
use crate::AppState;

/// Unified state holder for all AWS control-plane engines.
pub struct AwsHubState {
    pub accounts: Arc<AwsAccountStore>,
    pub discovery: Arc<Ec2DiscoveryStore>,
    pub sso: Arc<AwsSsoManager>,
    pub shells: Arc<SsmShellStore>,
    pub transfer: Arc<SsmTransferClient>,
    pub clones: Arc<CloneManager>,
    pub topology: Arc<TopologyStore>,
}

impl Default for AwsHubState {
    fn default() -> Self {
        let mode_raw = std::env::var("OPERQUAY_AWS_ACCESS_MODE")
            .or_else(|_| std::env::var("AWS_ACCESS_MODE"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        let mode = match mode_raw.as_str() {
            "profiles" => AwsAccessMode::Profiles,
            "user" => AwsAccessMode::User,
            "hub" => AwsAccessMode::Hub,
            _ => {
                let auth_on = std::env::var("OPERQUAY_REQUIRE_AUTH")
                    .or_else(|_| std::env::var("REQUIRE_AUTH"))
                    .map_or_else(
                        |_| {
                            std::env::var("OPERQUAY_ADMIN_PASSWORD")
                                .is_ok_and(|v| !v.trim().is_empty())
                        },
                        |v| v == "1" || v.eq_ignore_ascii_case("true"),
                    );
                if auth_on {
                    AwsAccessMode::User
                } else {
                    let home = std::env::var("HOME").unwrap_or_default();
                    if !home.is_empty() && std::path::Path::new(&home).join(".aws").exists() {
                        AwsAccessMode::Profiles
                    } else {
                        AwsAccessMode::Hub
                    }
                }
            }
        };
        Self {
            accounts: Arc::new(AwsAccountStore::new(mode, None)),
            discovery: Arc::new(Ec2DiscoveryStore::default()),
            sso: Arc::new(AwsSsoManager::default()),
            shells: Arc::new(SsmShellStore::default()),
            transfer: Arc::new(SsmTransferClient::default()),
            clones: Arc::new(CloneManager::default()),
            topology: Arc::new(TopologyStore::default()),
        }
    }
}

pub fn aws_router() -> Router<AppState> {
    Router::new()
        .route("/api/aws/onboarding", get(aws_onboarding))
        .route(
            "/aws-accounts",
            get(list_aws_accounts).post(add_aws_account),
        )
        .route("/aws-accounts/{id}", delete(delete_aws_account))
        .route("/aws-accounts/fetch/{id}", post(fetch_aws_account))
        .route("/aws-accounts/verify/{id}", post(verify_aws_account))
        .route("/instances", get(list_instances))
        .route("/discover-instances", get(discover_instances))
        .route("/discover-region", get(discover_region))
        .route("/discovery-status", get(discovery_status))
        .route("/fleet-stats", get(fleet_stats))
        .route("/fleet-summary", get(fleet_summary))
        .route(
            "/preferences",
            get(get_preferences)
                .post(save_preferences)
                .put(save_preferences)
                .patch(patch_preferences),
        )
        .route("/instance-details", get(instance_details))
        .route("/instance-metrics", get(instance_metrics))
        .route(
            "/api/aws/user-bindings",
            get(list_user_bindings).post(create_user_binding),
        )
        .route("/api/aws/user-bindings/{id}", delete(delete_user_binding))
        .route("/api/aws/connected-roles", get(connected_roles))
        .route("/api/aws/role-login", post(user_role_login))
        .route("/api/aws/role-fetch", post(user_role_fetch))
        .route("/api/aws/role-disconnect", post(user_role_disconnect))
        .route("/api/aws/saved-inventory", get(get_saved_inventory))
        .route(
            "/api/aws/saved-inventory/forget",
            post(forget_saved_inventory),
        )
        .route("/api/aws/instance-details", get(instance_details))
        .route("/api/aws/instance-metrics", get(instance_metrics))
        .route("/api/aws/sso/session", get(sso_session_status))
        .route("/api/aws/sso/start", post(sso_start))
        .route("/api/aws/sso/poll", post(sso_poll))
        .route("/api/aws/sso/accounts", post(sso_accounts))
        .route("/api/aws/sso/roles", post(sso_roles))
        .route("/api/aws/sso/connect", post(sso_connect))
        .route("/api/aws/sso/cancel", post(sso_cancel))
        .route(
            "/api/aws/sso-providers",
            get(list_sso_providers).post(add_sso_provider),
        )
        .route("/api/aws/sso-providers/{id}", delete(delete_sso_provider))
        .route("/ws", get(ws_ssm_shell))
        .route("/api/aws/session-ws", get(ws_ssm_shell))
        .route("/export-session", post(export_session))
        .route("/api/aws/session-export", post(export_user_session))
        .route("/exports/{id}", get(serve_export))
        .route("/browse-directory", post(browse_directory))
        .route("/api/aws/transfer/browse", post(browse_directory))
        .route(
            "/upload-file",
            post(upload_file).layer(DefaultBodyLimit::max(40 * 1024 * 1024)),
        )
        .route(
            "/api/aws/transfer/upload",
            post(upload_file).layer(DefaultBodyLimit::max(40 * 1024 * 1024)),
        )
        .route("/download-file", post(download_file))
        .route("/api/aws/transfer/download", post(download_file))
        .route(
            "/express-upload",
            post(express_upload).layer(DefaultBodyLimit::max(40 * 1024 * 1024)),
        )
        .route("/express-download", post(express_download))
        .route("/clone/start", post(clone_start))
        .route("/clone/status/{id}", get(clone_status))
        .route("/clone/settings/{id}", get(clone_settings))
        .route("/clone/launch", post(clone_launch_legacy))
        .route("/api/aws/clones", get(list_clones))
        .route("/api/aws/clones/recoverable", get(list_recoverable_clones))
        .route("/api/aws/clones/start", post(clone_start))
        .route("/api/aws/clones/{id}", get(clone_status))
        .route("/api/aws/clones/{id}/settings", get(clone_settings))
        .route("/api/aws/clones/{id}/recover", post(recover_clone))
        .route("/api/aws/clones/{id}/launch", post(clone_launch_id))
        .route("/topology/{vpc_id}", get(get_topology))
        .route("/topology/reachability", post(topology_reachability))
        .route("/topology/exposure/{vpc_id}", get(topology_exposure))
        .route("/topology/{vpc_id}/exposure", get(topology_exposure))
        .route("/topology/conflicts/{vpc_id}", get(topology_conflicts))
        .route("/topology/{vpc_id}/conflicts", get(topology_conflicts))
        .route("/topology/deep-analyze", post(topology_deep_analyze))
        .route("/api/aws/topology", get(get_topology_query))
        .route(
            "/api/aws/topology/deep-analyze",
            post(topology_deep_analyze),
        )
}

fn json_err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

async fn aws_onboarding(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.aws.accounts.onboarding(&tenant).await).into_response()
}

async fn list_aws_accounts(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::AWS_ACCOUNTS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.aws.accounts.list_accounts(&tenant).await).into_response()
}

async fn add_aws_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AddAwsAccountRequest>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::AWS_ACCOUNTS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state.aws.accounts.add_account(&tenant, body).await {
        Ok(acc) => (StatusCode::CREATED, Json(acc)).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn delete_aws_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::AWS_ACCOUNTS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state.aws.accounts.delete_account(&tenant, &id).await {
        Ok(()) => Json(serde_json::json!({ "status": "deleted" })).into_response(),
        Err(e) => json_err(StatusCode::NOT_FOUND, e.to_string()),
    }
}

async fn fetch_aws_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::INSTANCES_SCAN]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let creds = match state
        .aws
        .accounts
        .resolve_account_credentials(&tenant, &id)
        .await
    {
        Ok(c) => c,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let list = state.aws.accounts.list_accounts(&tenant).await;
    let Some(acc) = list.into_iter().find(|a| a.id == id) else {
        return json_err(StatusCode::NOT_FOUND, "account not found");
    };
    match state
        .aws
        .discovery
        .fetch_region_with_creds(
            &tenant,
            &acc.aws_account_id,
            &acc.name,
            &acc.default_region,
            &creds,
        )
        .await
    {
        Ok(instances) => Json(serde_json::json!({ "instances": instances })).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

async fn verify_aws_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::AWS_ACCOUNTS_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state.aws.accounts.verify_account(&tenant, &id).await {
        Ok(acc) => Json(serde_json::json!({
            "ok": true,
            "account_id": acc.aws_account_id,
            "arn": acc.verified_arn,
            "verified": acc.verified,
            "verified_arn": acc.verified_arn,
            "account": acc,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "ok": false,
                "error": e.to_string(),
            })),
        )
            .into_response(),
    }
}

async fn list_instances(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::INSTANCES_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.aws.discovery.build_instance_tree(&tenant).await).into_response()
}

#[derive(Deserialize)]
struct DiscoveryRegionQuery {
    #[serde(default = "default_us_east")]
    region: String,
    #[serde(default)]
    account_id: String,
}

fn default_us_east() -> String {
    "us-east-1".to_owned()
}

pub fn trigger_tenant_discovery(aws: Arc<AwsHubState>, tenant: String) {
    trigger_tenant_discovery_with_pg(aws, None, tenant);
}

pub fn trigger_tenant_discovery_with_pg(
    aws: Arc<AwsHubState>,
    pg: Option<operquay_auth::pg::PgAuthPool>,
    tenant: String,
) {
    tokio::spawn(async move {
        let mode = aws.accounts.mode().await;
        let local_profiles = if mode == AwsAccessMode::User {
            Vec::new()
        } else {
            load_local_profiles()
        };
        let accounts = aws.accounts.list_accounts(&tenant).await;
        let total_accounts = accounts.len() + local_profiles.len();
        if total_accounts == 0 {
            let total = aws.discovery.list_instances(&tenant).await.len();
            let final_status = DiscoveryStatus {
                status: "complete".into(),
                discovering: false,
                total_accounts: 0,
                fetched_accounts: 0,
                total_regions: 0,
                fetched_regions: 0,
                total_instances: total,
                instance_count: total,
                last_discovery_unix: now_unix_secs(),
                last_error: String::new(),
                message: if mode == AwsAccessMode::User {
                    "User mode: connect an AWS role in the sidebar to discover instances".into()
                } else {
                    "No AWS accounts or profiles configured".into()
                },
            };
            aws.discovery.set_status(&tenant, final_status).await;
            if let Some(pool) = &pg {
                persist_discovery_inventory(&aws, pool, &tenant).await;
            }
            return;
        }

        aws.discovery
            .set_status(
                &tenant,
                DiscoveryStatus {
                    status: "discovering".into(),
                    discovering: true,
                    total_accounts,
                    fetched_accounts: 0,
                    total_regions: total_accounts,
                    fetched_regions: 0,
                    total_instances: 0,
                    instance_count: 0,
                    last_discovery_unix: now_unix_secs(),
                    last_error: String::new(),
                    message: "Fetching EC2 instances across AWS accounts and profiles...".into(),
                },
            )
            .await;

        let mut fetched_accounts = 0usize;
        let mut last_err = String::new();

        for acc in accounts {
            if let Ok(creds) = aws
                .accounts
                .resolve_account_credentials(&tenant, &acc.id)
                .await
            {
                let regions = if acc.default_region.is_empty() {
                    vec!["us-east-1".to_string()]
                } else {
                    vec![acc.default_region.clone()]
                };
                for r in &regions {
                    if let Err(e) = aws
                        .discovery
                        .fetch_region_with_creds(&tenant, &acc.id, &acc.name, r, &creds)
                        .await
                    {
                        last_err = e;
                    }
                }
            }
            fetched_accounts += 1;
        }

        let http = aws.discovery.http_client().clone();
        for prof in local_profiles {
            if let Some(creds) = resolve_profile_credentials(&prof, &http).await {
                let region = if prof.region.is_empty() {
                    "us-east-1".to_string()
                } else {
                    prof.region.clone()
                };
                let acct_id = prof
                    .sso_account_id
                    .clone()
                    .unwrap_or_else(|| prof.name.clone());
                if let Err(e) = aws
                    .discovery
                    .fetch_region_with_creds(&tenant, &acct_id, &prof.name, &region, &creds)
                    .await
                {
                    last_err = e;
                }
            }
            fetched_accounts += 1;
        }

        let total = aws.discovery.list_instances(&tenant).await.len();
        aws.discovery
            .set_status(
                &tenant,
                DiscoveryStatus {
                    status: if total == 0 && !last_err.is_empty() {
                        "error".into()
                    } else {
                        "complete".into()
                    },
                    discovering: false,
                    total_accounts,
                    fetched_accounts,
                    total_regions: total_accounts,
                    fetched_regions: fetched_accounts,
                    total_instances: total,
                    instance_count: total,
                    last_discovery_unix: now_unix_secs(),
                    last_error: last_err,
                    message: format!("Discovered {total} instances"),
                },
            )
            .await;
        if let Some(pool) = &pg {
            persist_discovery_inventory(&aws, pool, &tenant).await;
        }
    });
}

async fn discover_instances(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::INSTANCES_SCAN]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let pg = state.pg_pool().await;
    trigger_tenant_discovery_with_pg(state.aws.clone(), pg, tenant.clone());
    let status = state.aws.discovery.get_status(&tenant).await;
    Json(serde_json::json!({ "status": "discovering", "discovery": status })).into_response()
}

async fn discover_region(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DiscoveryRegionQuery>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::INSTANCES_SCAN]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if !q.account_id.is_empty() {
        if let Ok(creds) = state
            .aws
            .accounts
            .resolve_account_credentials(&tenant, &q.account_id)
            .await
        {
            return match state
                .aws
                .discovery
                .fetch_region_with_creds(&tenant, &q.account_id, &q.account_id, &q.region, &creds)
                .await
            {
                Ok(instances) => {
                    if let Some(pg) = state.pg_pool().await {
                        persist_discovery_inventory(&state.aws, &pg, &tenant).await;
                    }
                    Json(instances).into_response()
                }
                Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
            };
        }
    }
    Json(state.aws.discovery.list_instances(&tenant).await).into_response()
}

async fn discovery_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::INSTANCES_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.aws.discovery.get_status(&tenant).await).into_response()
}

async fn fleet_stats(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::INSTANCES_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.aws.discovery.fleet_stats(&tenant).await).into_response()
}

async fn fleet_summary(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::INSTANCES_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.aws.discovery.fleet_summary(&tenant).await).into_response()
}

async fn get_preferences(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(
        state
            .aws
            .accounts
            .get_preferences(&tenant, &claims.user_id)
            .await,
    )
    .into_response()
}

async fn save_preferences(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(prefs): Json<UserPreferences>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let saved = state
        .aws
        .accounts
        .save_preferences(&tenant, &claims.user_id, prefs)
        .await;
    persist_user_prefs(&state, &tenant, &claims.user_id, &saved).await;
    Json(saved).into_response()
}

async fn patch_preferences(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(patch): Json<serde_json::Value>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let current = state
        .aws
        .accounts
        .get_preferences(&tenant, &claims.user_id)
        .await;
    let mut merged = serde_json::to_value(&current).unwrap_or_else(|_| serde_json::json!({}));
    if let (Some(dst), Some(src)) = (merged.as_object_mut(), patch.as_object()) {
        for (k, v) in src {
            if k == "extra" {
                if let Some(obj) = v.as_object() {
                    for (ek, ev) in obj {
                        dst.insert(ek.clone(), ev.clone());
                    }
                    continue;
                }
            }
            dst.insert(k.clone(), v.clone());
        }
    }
    let updated: UserPreferences = serde_json::from_value(merged).unwrap_or(current);
    let saved = state
        .aws
        .accounts
        .save_preferences(&tenant, &claims.user_id, updated)
        .await;
    persist_user_prefs(&state, &tenant, &claims.user_id, &saved).await;
    Json(saved).into_response()
}

async fn resolve_aws_creds_for_request(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    binding_id: Option<&str>,
    account_id: Option<&str>,
    profile: Option<&str>,
) -> Result<AwsCredentials, Box<Response>> {
    let bid = binding_id.map(str::trim).filter(|s| !s.is_empty());
    let aid = account_id.map(str::trim).filter(|s| !s.is_empty());
    let prof = profile.map(str::trim).filter(|s| !s.is_empty());

    let user_key = bid.or_else(|| prof.and_then(|p| p.strip_prefix("user:").map(|_| p)));
    if let Some(key) = user_key {
        if let Some(lease) = state
            .aws
            .accounts
            .find_connected_role_lease_for_user(tenant, user_id, key)
            .await
        {
            return Ok(lease.credentials);
        }
        return Err(Box::new(json_err(
            StatusCode::UNAUTHORIZED,
            "AWS role session expired or not connected; please sign in to AWS role",
        )));
    }

    if let Some(id) = aid {
        return state
            .aws
            .accounts
            .resolve_account_credentials(tenant, id)
            .await
            .map_err(|e| Box::new(json_err(StatusCode::BAD_REQUEST, e.to_string())));
    }

    if let Some(p) = prof {
        let accounts = state.aws.accounts.list_accounts(tenant).await;
        if let Some(acc) = accounts.into_iter().find(|a| a.id == p || a.name == p) {
            return state
                .aws
                .accounts
                .resolve_account_credentials(tenant, &acc.id)
                .await
                .map_err(|e| Box::new(json_err(StatusCode::BAD_REQUEST, e.to_string())));
        }
        if state.aws.accounts.mode().await != AwsAccessMode::User {
            let local_profiles = load_local_profiles();
            if let Some(lp) = local_profiles.into_iter().find(|lp| lp.name == p) {
                let http = state.aws.discovery.http_client().clone();
                if let Some(c) = resolve_profile_credentials(&lp, &http).await {
                    return Ok(c);
                }
            }
        }
        return Err(Box::new(json_err(
            StatusCode::UNAUTHORIZED,
            format!("AWS credentials not available for profile '{p}'"),
        )));
    }

    if state.aws.accounts.mode().await != AwsAccessMode::User {
        if let Some(ambient) = ambient_aws_credentials() {
            return Ok(ambient);
        }
    }

    Err(Box::new(json_err(
        StatusCode::UNAUTHORIZED,
        "AWS credentials (binding_id, account_id, or profile) are required",
    )))
}

#[derive(Deserialize)]
struct InstanceQuery {
    #[serde(alias = "id")]
    instance_id: String,
    #[serde(default = "default_us_east")]
    region: String,
    #[serde(default)]
    binding_id: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    profile: String,
    #[serde(default)]
    platform: String,
}

async fn instance_details(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<InstanceQuery>,
) -> Response {
    let (tenant, claims) =
        match require_any_perm(&state, &headers, &[perm::INSTANCES_DETAILS]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let explicit_cred_ref = !q.binding_id.trim().is_empty() || !q.account_id.trim().is_empty();
    let cached = state
        .aws
        .discovery
        .find_instance(&tenant, &q.instance_id)
        .await;
    let region = if q.region.trim().is_empty() {
        cached
            .as_ref()
            .map_or_else(|| "us-east-1".to_owned(), |i| i.region.clone())
    } else {
        q.region.trim().to_owned()
    };
    let prof_opt = if q.profile.trim().is_empty() {
        cached
            .as_ref()
            .map(|i| i.profile.as_str())
            .filter(|s| !s.is_empty())
    } else {
        Some(q.profile.as_str())
    };
    if explicit_cred_ref || (!q.binding_id.trim().is_empty() || prof_opt.is_some()) {
        match resolve_aws_creds_for_request(
            &state,
            &tenant,
            &claims.user_id,
            (!q.binding_id.trim().is_empty()).then_some(q.binding_id.as_str()),
            (!q.account_id.trim().is_empty()).then_some(q.account_id.as_str()),
            prof_opt,
        )
        .await
        {
            Ok(creds) => {
                if let Ok(live) = state
                    .aws
                    .discovery
                    .fetch_instance_details_live(&tenant, &region, &q.instance_id, &creds)
                    .await
                {
                    return Json(live).into_response();
                }
            }
            Err(resp) if explicit_cred_ref => return *resp,
            Err(_) => {}
        }
    }
    match cached {
        Some(inst) => Json(inst).into_response(),
        None => json_err(StatusCode::NOT_FOUND, "instance not found"),
    }
}

async fn instance_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<InstanceQuery>,
) -> Response {
    let (tenant, claims) =
        match require_any_perm(&state, &headers, &[perm::INSTANCES_DETAILS]).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let explicit_cred_ref = !q.binding_id.trim().is_empty() || !q.account_id.trim().is_empty();
    let cached = state
        .aws
        .discovery
        .find_instance(&tenant, &q.instance_id)
        .await;
    let region = if q.region.trim().is_empty() {
        cached
            .as_ref()
            .map_or_else(|| "us-east-1".to_owned(), |i| i.region.clone())
    } else {
        q.region.trim().to_owned()
    };
    let prof_opt = if q.profile.trim().is_empty() {
        cached
            .as_ref()
            .map(|i| i.profile.as_str())
            .filter(|s| !s.is_empty())
    } else {
        Some(q.profile.as_str())
    };
    if explicit_cred_ref || prof_opt.is_some() {
        match resolve_aws_creds_for_request(
            &state,
            &tenant,
            &claims.user_id,
            (!q.binding_id.trim().is_empty()).then_some(q.binding_id.as_str()),
            (!q.account_id.trim().is_empty()).then_some(q.account_id.as_str()),
            prof_opt,
        )
        .await
        {
            Ok(creds) => {
                let mut platform = if q.platform.trim().is_empty() {
                    cached
                        .as_ref()
                        .map_or_else(String::new, |i| i.platform.clone())
                } else {
                    q.platform.trim().to_owned()
                };
                if platform.is_empty() {
                    if let Ok(details) = state
                        .aws
                        .discovery
                        .fetch_instance_details_live(&tenant, &region, &q.instance_id, &creds)
                        .await
                    {
                        details["platform"]
                            .as_str()
                            .unwrap_or("linux")
                            .clone_into(&mut platform);
                    }
                }
                if platform.is_empty() {
                    "linux".clone_into(&mut platform);
                }
                if let Ok(live) = state
                    .aws
                    .discovery
                    .fetch_instance_metrics_live_with_ssm(
                        &tenant,
                        &q.instance_id,
                        &region,
                        &platform,
                        &creds,
                        Some(&state.aws.transfer),
                    )
                    .await
                {
                    return Json(live).into_response();
                }
            }
            Err(resp) if explicit_cred_ref => return *resp,
            Err(_) => {}
        }
    }
    Json(
        state
            .aws
            .discovery
            .instance_metrics(&tenant, &q.instance_id, &region)
            .await,
    )
    .into_response()
}

#[derive(Deserialize, Default)]
struct UserBindingsQuery {
    #[serde(default)]
    user_id: String,
}

async fn list_user_bindings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<UserBindingsQuery>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let requested = q.user_id.trim();
    if !requested.is_empty() && requested != claims.user_id {
        if let Err(r) = require_any_perm(&state, &headers, &[perm::USERS_MANAGE]).await {
            return *r;
        }
        if requested == "*" {
            return Json(state.aws.accounts.list_all_tenant_bindings(&tenant).await)
                .into_response();
        }
        return Json(
            state
                .aws
                .accounts
                .list_user_bindings(&tenant, requested)
                .await,
        )
        .into_response();
    }
    Json(
        state
            .aws
            .accounts
            .list_user_bindings(&tenant, &claims.user_id)
            .await,
    )
    .into_response()
}

#[derive(Deserialize)]
struct CreateBindingBody {
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    label: String,
    role_arn: String,
    #[serde(default)]
    external_id: String,
    #[serde(default)]
    principal_arn: String,
    #[serde(default)]
    principal_id: String,
    #[serde(default = "default_us_east")]
    region: String,
}

async fn create_user_binding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateBindingBody>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let target_user = if body.user_id.trim().is_empty() || body.user_id.trim() == claims.user_id {
        claims.user_id.clone()
    } else {
        if let Err(r) = require_any_perm(&state, &headers, &[perm::USERS_MANAGE]).await {
            return *r;
        }
        body.user_id.trim().to_owned()
    };
    match state
        .aws
        .accounts
        .create_user_binding_with_principal(
            &tenant,
            &target_user,
            &body.label,
            &body.role_arn,
            &body.external_id,
            &body.region,
            &body.principal_arn,
            &body.principal_id,
        )
        .await
    {
        Ok(b) => {
            persist_role_binding(&state, &b).await;
            (StatusCode::CREATED, Json(b)).into_response()
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn delete_user_binding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if state
        .aws
        .accounts
        .delete_user_binding(&tenant, &claims.user_id, &id)
        .await
        .is_ok()
    {
        if let Some(pg) = state.pg_pool().await {
            let _ = pg.delete_aws_role_binding(&tenant, &id).await;
        }
        return Json(serde_json::json!({ "status": "deleted" })).into_response();
    }
    if require_any_perm(&state, &headers, &[perm::USERS_MANAGE])
        .await
        .is_ok()
    {
        match state
            .aws
            .accounts
            .delete_binding_any_user(&tenant, &id)
            .await
        {
            Ok(()) => {
                if let Some(pg) = state.pg_pool().await {
                    let _ = pg.delete_aws_role_binding(&tenant, &id).await;
                }
                return Json(serde_json::json!({ "status": "deleted" })).into_response();
            }
            Err(e) => return json_err(StatusCode::NOT_FOUND, e.to_string()),
        }
    }
    json_err(StatusCode::NOT_FOUND, "role binding not found")
}

async fn connected_roles(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(
        state
            .aws
            .accounts
            .list_connected_roles(&tenant, &claims.user_id)
            .await,
    )
    .into_response()
}

#[derive(Deserialize)]
struct RoleLoginBody {
    #[serde(default, alias = "id")]
    binding_id: String,
    #[serde(default)]
    role_arn: String,
    #[serde(default)]
    external_id: String,
    #[serde(default = "default_us_east")]
    region: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    access_key_id: String,
    #[serde(default)]
    secret_access_key: String,
    #[serde(default)]
    session_token: String,
}

async fn user_role_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RoleLoginBody>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let bid = body.binding_id.trim();
    let binding = if bid.is_empty() {
        None
    } else {
        state
            .aws
            .accounts
            .get_user_binding(&tenant, &claims.user_id, bid)
            .await
    };
    if !bid.is_empty() && binding.is_none() && body.role_arn.trim().is_empty() {
        return json_err(StatusCode::NOT_FOUND, "role binding not found");
    }

    let role_arn = if body.role_arn.trim().is_empty() {
        binding
            .as_ref()
            .map_or_else(String::new, |b| b.role_arn.clone())
    } else {
        body.role_arn.trim().to_owned()
    };
    let external_id = if body.external_id.trim().is_empty() {
        binding
            .as_ref()
            .map_or_else(String::new, |b| b.external_id.clone())
    } else {
        body.external_id.trim().to_owned()
    };
    let region = if body.region.trim().is_empty() {
        binding
            .as_ref()
            .map_or_else(|| "us-east-1".to_owned(), |b| b.region.clone())
    } else {
        body.region.trim().to_owned()
    };
    let label = if body.label.trim().is_empty() {
        binding
            .as_ref()
            .map_or_else(|| role_arn.clone(), |b| b.label.clone())
    } else {
        body.label.trim().to_owned()
    };

    let caller_creds =
        if !body.access_key_id.trim().is_empty() && !body.secret_access_key.trim().is_empty() {
            AwsCredentials {
                access_key_id: body.access_key_id.trim().to_owned(),
                secret_access_key: body.secret_access_key.trim().to_owned(),
                session_token: (!body.session_token.trim().is_empty())
                    .then(|| body.session_token.trim().to_owned()),
            }
        } else if let Some(amb) = ambient_aws_credentials() {
            amb
        } else {
            return json_err(
                StatusCode::BAD_REQUEST,
                "AWS access_key_id and secret_access_key are required",
            );
        };

    let (effective_creds, assumed_account_id) = if role_arn.is_empty() {
        (caller_creds, String::new())
    } else {
        let ext_opt = (!external_id.is_empty()).then_some(external_id.as_str());
        match state
            .aws
            .accounts
            .assume_role_with_sts(
                &region,
                &role_arn,
                ext_opt,
                &format!("operquay-{}", claims.user_id),
                &caller_creds,
            )
            .await
        {
            Ok((temp_creds, _arn, acct)) => (temp_creds, acct),
            Err(e) => return json_err(StatusCode::UNAUTHORIZED, e.to_string()),
        }
    };

    if binding.is_some() {
        match state
            .aws
            .accounts
            .connect_role_lease(&tenant, &claims.user_id, bid, effective_creds)
            .await
        {
            Ok(lease) => {
                persist_role_lease(&state, &tenant, &claims.user_id, &lease).await;
                return Json(lease).into_response();
            }
            Err(e) => return json_err(StatusCode::NOT_FOUND, e.to_string()),
        }
    }

    let lease = state
        .aws
        .accounts
        .connect_adhoc_role_lease(
            &tenant,
            &claims.user_id,
            (!bid.is_empty()).then_some(bid),
            &label,
            &assumed_account_id,
            &role_arn,
            &region,
            effective_creds,
        )
        .await;
    persist_role_lease(&state, &tenant, &claims.user_id, &lease).await;
    Json(lease).into_response()
}

#[derive(Deserialize)]
struct RoleFetchBody {
    binding_id: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    region: String,
}

async fn user_role_fetch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RoleFetchBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::INSTANCES_SCAN]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let leases = state
        .aws
        .accounts
        .list_connected_roles(&tenant, &claims.user_id)
        .await;
    let Some(lease) = leases
        .into_iter()
        .find(|l| l.id == body.binding_id || l.binding_id == body.binding_id)
    else {
        return json_err(StatusCode::UNAUTHORIZED, "role is not currently connected");
    };
    let aws_profile = format!("user:{}", lease.id);
    let alias = if !body.display_name.trim().is_empty() {
        body.display_name.trim()
    } else if !lease.label.trim().is_empty() {
        lease.label.trim()
    } else {
        lease.account_id.as_str()
    };

    let (instances, failed_regions) = if body.region.trim().is_empty() {
        state
            .aws
            .discovery
            .fetch_all_regions_with_creds(
                &tenant,
                &lease.account_id,
                &aws_profile,
                &lease.region,
                &lease.credentials,
            )
            .await
    } else {
        match state
            .aws
            .discovery
            .fetch_region_with_creds(
                &tenant,
                &lease.account_id,
                &aws_profile,
                body.region.trim(),
                &lease.credentials,
            )
            .await
        {
            Ok(list) => (list, Vec::new()),
            Err(e) => return json_err(StatusCode::BAD_GATEWAY, e),
        }
    };

    let tree_instances: Vec<_> = instances
        .iter()
        .map(|inst| {
            operquay_aws::discovery::Ec2DiscoveryStore::to_tree_instance(inst, alias, &aws_profile)
        })
        .collect();

    let role_entry = serde_json::json!({
        "account_id": lease.account_id,
        "role_key": lease.id,
        "source": "sso",
        "name": alias,
        "label": lease.label,
        "instances": tree_instances,
        "live_id": lease.id,
        "credential_revision": lease.credential_revision,
    });
    let mut existing = state
        .aws
        .accounts
        .get_saved_inventory(&tenant, &claims.user_id)
        .await;
    existing.retain(|entry| {
        entry["role_key"].as_str() != Some(&lease.id)
            && entry["live_id"].as_str() != Some(&lease.id)
    });
    existing.push(role_entry);
    state
        .aws
        .accounts
        .save_inventory_snapshot(&tenant, &claims.user_id, existing.clone())
        .await;
    persist_saved_inventory(&state, &tenant, &claims.user_id, &existing).await;
    if let Some(pg) = state.pg_pool().await {
        persist_discovery_inventory(&state.aws, &pg, &tenant).await;
    }

    Json(serde_json::json!({
        "instances": tree_instances,
        "failed_regions": failed_regions,
        "credential_revision": lease.credential_revision,
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
struct RoleDisconnectBody {
    #[serde(default)]
    binding_id: String,
}

async fn user_role_disconnect(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<RoleDisconnectBody>>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let bid = body.map_or_default(|b| b.0.binding_id);
    let trimmed_bid = bid.trim();
    if trimmed_bid.is_empty() {
        state
            .aws
            .accounts
            .disconnect_all_user_roles(&tenant, &claims.user_id)
            .await;
        if let Some(pg) = state.pg_pool().await {
            let _ = pg.delete_user_role_leases(&tenant, &claims.user_id).await;
        }
    } else {
        state
            .aws
            .accounts
            .disconnect_user_role(&tenant, &claims.user_id, trimmed_bid)
            .await;
        if let Some(pg) = state.pg_pool().await {
            let _ = pg.delete_aws_role_lease(&tenant, trimmed_bid).await;
        }
    }
    state.session_fence.terminate_aws_role(
        &tenant,
        &claims.user_id,
        (!trimmed_bid.is_empty()).then_some(trimmed_bid),
        "aws_role_disconnected",
    );
    Json(serde_json::json!({ "status": "disconnected", "fence_seconds": 5 })).into_response()
}

async fn get_saved_inventory(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let roles = state
        .aws
        .accounts
        .get_saved_inventory(&tenant, &claims.user_id)
        .await;
    Json(serde_json::json!({ "roles": roles })).into_response()
}

async fn forget_saved_inventory(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    state
        .aws
        .accounts
        .forget_saved_inventory(&tenant, &claims.user_id)
        .await;
    if let Some(pg) = state.pg_pool().await {
        let _ = pg
            .delete_aws_saved_inventory(&tenant, &claims.user_id)
            .await;
    }
    Json(serde_json::json!({ "status": "forgotten" })).into_response()
}

async fn sso_session_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.aws.sso.session_status(&tenant, &claims.user_id).await).into_response()
}

#[derive(Deserialize)]
struct SsoStartBody {
    #[serde(default = "default_us_east")]
    region: String,
    start_url: String,
}

async fn sso_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SsoStartBody>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .aws
        .sso
        .start_device_auth(&tenant, &claims.user_id, &body.region, &body.start_url)
        .await
    {
        Ok(s) => {
            persist_sso_flow(&state, &tenant, &claims.user_id, &s.id).await;
            Json(s).into_response()
        }
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct SsoFlowBody {
    id: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    role_name: String,
    #[serde(default)]
    label: String,
}

async fn sso_poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SsoFlowBody>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .aws
        .sso
        .poll_token(&tenant, &claims.user_id, &body.id)
        .await
    {
        Ok(st) => {
            persist_sso_flow(&state, &tenant, &claims.user_id, &body.id).await;
            Json(serde_json::json!({ "status": st })).into_response()
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e),
    }
}

async fn sso_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SsoFlowBody>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .aws
        .sso
        .list_accounts(&tenant, &claims.user_id, &body.id)
        .await
    {
        Ok(list) => Json(list).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

async fn sso_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SsoFlowBody>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .aws
        .sso
        .list_account_roles(&tenant, &claims.user_id, &body.id, &body.account_id)
        .await
    {
        Ok(list) => Json(list).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

async fn sso_connect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SsoFlowBody>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let (region, start_url, creds) = match state
        .aws
        .sso
        .get_role_credentials_with_portal(
            &tenant,
            &claims.user_id,
            &body.id,
            &body.account_id,
            &body.role_name,
        )
        .await
    {
        Ok(v) => v,
        Err(e) => return json_err(StatusCode::BAD_GATEWAY, e),
    };
    let label = if body.label.is_empty() {
        if let Some(acct_name) = state.aws.sso.account_name(&body.account_id).await {
            format!("{acct_name} · {}", body.role_name)
        } else {
            format!("{} / {}", body.account_id, body.role_name)
        }
    } else {
        body.label
    };
    let lease = state
        .aws
        .accounts
        .connect_sso_role_lease(
            &tenant,
            &claims.user_id,
            &body.account_id,
            &body.role_name,
            &start_url,
            &region,
            &label,
            creds,
        )
        .await;
    persist_role_lease(&state, &tenant, &claims.user_id, &lease).await;
    Json(lease).into_response()
}

async fn sso_cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SsoFlowBody>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    state
        .aws
        .sso
        .cancel(&tenant, &claims.user_id, &body.id)
        .await;
    if let Some(pg) = state.pg_pool().await {
        let _ = pg.delete_aws_sso_session(&tenant, &body.id).await;
    }
    Json(serde_json::json!({ "status": "cancelled" })).into_response()
}

async fn list_sso_providers(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.aws.sso.list_providers(&tenant).await).into_response()
}

#[derive(Deserialize)]
struct AddAwsSsoProviderBody {
    label: String,
    start_url: String,
    #[serde(default = "default_us_east")]
    region: String,
}

async fn add_sso_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AddAwsSsoProviderBody>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::SSO_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .aws
        .sso
        .add_provider(&tenant, &body.label, &body.start_url, &body.region)
        .await
    {
        Ok(item) => {
            if let Some(pg) = state.pg_pool().await {
                let row = operquay_auth::pg::PgAwsSsoProviderRow {
                    id: item.id.clone(),
                    tenant_id: item.tenant_id.clone(),
                    label: item.label.clone(),
                    start_url: item.start_url.clone(),
                    region: item.region.clone(),
                    created_at: item.created_at,
                };
                if let Err(err) = pg.upsert_aws_sso_provider(&row).await {
                    eprintln!(
                        "Warning: failed to persist AWS SSO provider {}: {err}",
                        row.id
                    );
                }
            }
            (StatusCode::CREATED, Json(item)).into_response()
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e),
    }
}

async fn delete_sso_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::SSO_MANAGE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    state.aws.sso.delete_provider(&tenant, &id).await;
    if let Some(pg) = state.pg_pool().await {
        if let Err(err) = pg.delete_aws_sso_provider(&tenant, &id).await {
            eprintln!("Warning: failed to delete AWS SSO provider {id}: {err}");
        }
    }
    Json(serde_json::json!({ "status": "deleted" })).into_response()
}

#[derive(Deserialize)]
struct SsmWsQuery {
    #[serde(default)]
    instance_id: String,
    #[serde(default = "default_us_east")]
    region: String,
    #[serde(default)]
    terminal_id: String,
    #[serde(default)]
    role_id: String,
}

async fn ws_ssm_shell(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SsmWsQuery>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::SESSION_SSH]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if q.instance_id.is_empty() {
        return ws.on_upgrade(move |socket| {
            handle_multiplexed_ws(
                socket,
                state,
                tenant,
                claims.user_id,
                claims.email,
                claims.session_id,
            )
        });
    }
    let ssm_sid = Uuid::new_v4().to_string();
    let tid = if q.terminal_id.is_empty() {
        "term-1".to_owned()
    } else {
        q.terminal_id.clone()
    };
    let tid_c = tid.clone();
    state
        .aws
        .shells
        .save_user_shell(PersistedUserShell {
            tenant_id: tenant.clone(),
            user_id: claims.user_id.clone(),
            session_id: claims.session_id.clone(),
            terminal_id: tid,
            instance_id: q.instance_id.clone(),
            region: q.region.clone(),
            role_id: q.role_id.clone(),
            ssm_session_id: ssm_sid.clone(),
            updated_at: now_unix_secs(),
        })
        .await;
    state
        .audit
        .record(
            &tenant,
            &crate::TelemetryHub::current_trace_id_hex(),
            &ssm_sid,
            "ssm.shell.open",
            "ssh",
            &q.instance_id,
            format!("region={} ssm_session_id={ssm_sid}", q.region),
            Some(ssm_sid.clone()),
        )
        .await;
    ws.on_upgrade(move |socket| {
        handle_ssm_shell_ws(
            socket,
            state,
            tenant,
            claims.user_id,
            claims.email,
            claims.session_id,
            q.instance_id,
            q.region,
            q.role_id,
            tid_c,
            ssm_sid,
        )
    })
}

fn format_ssm_shell_error(err: &str) -> String {
    if err.contains("AccessDeniedException") {
        format!(
            "Access denied: the connected AWS role does not have ssm:StartSession permission for this instance. {err}"
        )
    } else if err.contains("TargetNotConnected") {
        format!(
            "SSM target not connected: verify the instance is running and its SSM Agent is online. {err}"
        )
    } else {
        err.to_owned()
    }
}

async fn handle_multiplexed_ws(
    mut socket: WebSocket,
    state: AppState,
    tenant: String,
    user_id: String,
    user_email: String,
    auth_session_id: String,
) {
    enum ActiveTerm {
        Live {
            tx_in: tokio::sync::mpsc::Sender<Vec<u8>>,
            tx_resize: tokio::sync::mpsc::Sender<(u32, u32)>,
            region: String,
            ssm_session_id: String,
            iid: String,
            creds: AwsCredentials,
            mod_handle: std::sync::Arc<crate::moderation::LiveSessionHandle>,
            fw_buf: crate::dlp::ShellCommandFirewallBuffer,
        },
    }

    enum ConnectOutcome {
        Ok {
            sid: String,
            iid: String,
            region: String,
            creds: Box<AwsCredentials>,
            started: Box<StartedSsmSession>,
            chan: SsmShellChannel,
            cols: u32,
            rows: u32,
        },
        Err {
            sid: String,
            err: String,
        },
    }

    let mut fence_guard =
        if !user_id.is_empty() && !auth_session_id.is_empty() && auth_session_id != "anonymous-lab"
        {
            Some(
                state
                    .session_fence
                    .register(&tenant, &user_id, &auth_session_id, Some("aws-ssm")),
            )
        } else {
            None
        };
    let mut fence_tick = tokio::time::interval(std::time::Duration::from_secs(5));
    fence_tick.tick().await;

    let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<serde_json::Value>(256);
    let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel::<ConnectOutcome>(64);
    let mut sessions: std::collections::HashMap<String, ActiveTerm> =
        std::collections::HashMap::new();
    let mut pending_sids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut pending_resizes: std::collections::HashMap<String, (u32, u32)> =
        std::collections::HashMap::new();

    loop {
        tokio::select! {
            biased;
            reason = async {
                match fence_guard.as_mut() {
                    Some(fg) => fg.revoked().await,
                    None => std::future::pending().await,
                }
            } => {
                let _ = socket
                    .send(WsMsg::Text(
                        serde_json::json!({
                            "type": "session_error",
                            "payload": {
                                "session_id": "",
                                "error": format!("Session terminated: {reason}")
                            }
                        })
                        .to_string()
                        .into(),
                    ))
                    .await;
                let _ = socket.send(WsMsg::Close(None)).await;
                break;
            }
            _ = fence_tick.tick(), if fence_guard.is_some() => {
                if !state
                    .auth
                    .is_session_active(&tenant, &auth_session_id, &user_id)
                    .await
                {
                    let _ = socket
                        .send(WsMsg::Text(
                            serde_json::json!({
                                "type": "session_error",
                                "payload": {
                                    "session_id": "",
                                    "error": "Session terminated: revoked or expired"
                                }
                            })
                            .to_string()
                            .into(),
                        ))
                        .await;
                    let _ = socket.send(WsMsg::Close(None)).await;
                    break;
                }
            }
            Some(ev) = ev_rx.recv() => {
                if ev["type"].as_str() == Some("session_closed") {
                    if let Some(closed_sid) = ev["payload"]["session_id"].as_str() {
                        sessions.remove(closed_sid);
                    }
                }
                if let Ok(txt) = serde_json::to_string(&ev) {
                    if socket.send(WsMsg::Text(txt.into())).await.is_err() {
                        break;
                    }
                }
            }
            Some(outcome) = conn_rx.recv() => {
                match outcome {
                    ConnectOutcome::Ok {
                        sid,
                        iid,
                        region,
                        creds,
                        started,
                        mut chan,
                        cols,
                        rows,
                    } => {
                        if !pending_sids.remove(&sid) {
                            pending_resizes.remove(&sid);
                            chan.close();
                            let shells = state.aws.shells.clone();
                            let ssm_sid = started.session_id;
                            tokio::spawn(async move {
                                let _ = shells.terminate_session(&region, &ssm_sid, &creds).await;
                            });
                            continue;
                        }
                        let (final_cols, final_rows) = pending_resizes.remove(&sid).unwrap_or((cols, rows));
                        let _ = chan.send_resize(final_cols, final_rows).await;
                        let (tx_in, mut rx_in) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
                        let (tx_resize, mut rx_resize) =
                            tokio::sync::mpsc::channel::<(u32, u32)>(32);
                        let ev_tx_c = ev_tx.clone();
                        let sid_c = sid.clone();
                        let ssm_sid = started.session_id.clone();
                        let rec_policy = state
                            .platform
                            .rec_policies
                            .read()
                            .await
                            .get(&tenant)
                            .cloned()
                            .unwrap_or_default();
                        let should_record = rec_policy.should_record_instance("ssh", &iid, "");
                        let fail_closed_rec = rec_policy.fail_closed;
                        let mut rec_tee = if should_record {
                            state.ensure_tenant_dek_persisted(&tenant).await;
                            match state
                                .recordings
                                .start_cast_session(
                                    sid.clone(),
                                    tenant.clone(),
                                    "ssh".to_owned(),
                                    iid.clone(),
                                    rec_policy.fail_closed,
                                    final_cols as u16,
                                    final_rows as u16,
                                )
                                .await
                            {
                                Ok(t) => Some(t),
                                Err(err) if rec_policy.fail_closed => {
                                    chan.close();
                                    let shells = state.aws.shells.clone();
                                    let reg_c = region.clone();
                                    let ssm_c = started.session_id;
                                    let creds_c = *creds;
                                    tokio::spawn(async move {
                                        let _ = shells.terminate_session(&reg_c, &ssm_c, &creds_c).await;
                                    });
                                    let _ = ev_tx.try_send(serde_json::json!({
                                        "type": "session_error",
                                        "payload": {
                                            "session_id": sid,
                                            "error": format!("Recording required (fail-closed): {err}")
                                        }
                                    }));
                                    continue;
                                }
                                Err(_) => None,
                            }
                        } else {
                            None
                        };
                        let recording_active = rec_tee.is_some();
                        let rec_catalog = state.recordings.clone();
                        let state_rec = state.clone();
                        let rec_start = std::time::Instant::now();
                        let banner = format!("\r\n\x1b[1;36m[operquay-ssm]\x1b[0m Live SSM connected to {iid} ({region}) [{ssm_sid}]\r\n");
                        if let Some(tee) = rec_tee.as_mut() {
                            if let Err(err) = tee.record_cast_output(rec_start.elapsed().as_secs_f64(), &banner) {
                                if rec_policy.fail_closed {
                                    chan.close();
                                    if let Some(t) = rec_tee.take() {
                                        let entry = rec_catalog.finalize(t).await;
                                        state_rec.persist_recording_metadata(&entry).await;
                                    }
                                    let shells = state.aws.shells.clone();
                                    let reg_c = region.clone();
                                    let ssm_c = started.session_id;
                                    let creds_c = *creds;
                                    tokio::spawn(async move {
                                        let _ = shells.terminate_session(&reg_c, &ssm_c, &creds_c).await;
                                    });
                                    let _ = ev_tx.try_send(serde_json::json!({
                                        "type": "session_error",
                                        "payload": {
                                            "session_id": sid,
                                            "error": format!("Recording required (fail-closed): {err}")
                                        }
                                    }));
                                    continue;
                                }
                            }
                        }
                        let _ = ev_tx.try_send(serde_json::json!({
                            "type": "session_started",
                            "payload": {
                                "session_id": sid,
                                "instance_id": iid,
                                "recording": recording_active
                            }
                        }));
                        state
                            .aws
                            .shells
                            .init_session_transcript(&tenant, &user_id, &sid, &iid)
                            .await;
                        state
                            .aws
                            .shells
                            .append_session_output(&tenant, &sid, banner.as_bytes())
                            .await;
                        let _ = ev_tx.try_send(serde_json::json!({
                            "type": "terminal_output",
                            "payload": { "session_id": sid, "output": banner }
                        }));
                        let shells_buf = state.aws.shells.clone();
                        let tenant_buf = tenant.clone();
                        let mod_handle = std::sync::Arc::new(state.moderation.register_session(
                            &tenant,
                            &sid,
                            "ssm",
                            &iid,
                            &user_id,
                            &user_email,
                            recording_active.then(|| sid.clone()),
                        ));
                        let mod_handle_c = std::sync::Arc::clone(&mod_handle);
                        let mut tab_fence = state.session_fence.register_with_session(
                            &tenant,
                            &user_id,
                            &auth_session_id,
                            Some("aws-ssm"),
                            &sid,
                            None,
                        );
                        tokio::spawn(async move {
                            loop {
                                tokio::select! {
                                    biased;
                                    reason = tab_fence.revoked() => {
                                        let _ = ev_tx_c.send(serde_json::json!({
                                            "type": "session_error",
                                            "payload": {
                                                "session_id": sid_c,
                                                "error": format!("Session terminated: {reason}")
                                            }
                                        })).await;
                                        break;
                                    }
                                    out = chan.rx_output.recv() => {
                                        let Some(bytes) = out else { break; };
                                        shells_buf.append_session_output(&tenant_buf, &sid_c, &bytes).await;
                                        let output = String::from_utf8_lossy(&bytes).into_owned();
                                        mod_handle_c.publish_output(&output);
                                        if let Some(tee) = rec_tee.as_mut() {
                                            if let Err(err) = tee.record_cast_output(
                                                rec_start.elapsed().as_secs_f64(),
                                                &output,
                                            ) {
                                                if fail_closed_rec {
                                                    let _ = ev_tx_c
                                                        .send(serde_json::json!({
                                                            "type": "session_error",
                                                            "payload": {
                                                                "session_id": sid_c,
                                                                "error": format!("Recording required (fail-closed): {err}")
                                                            }
                                                        }))
                                                        .await;
                                                    break;
                                                }
                                            }
                                        }
                                        let _ = ev_tx_c.send(serde_json::json!({
                                            "type": "terminal_output",
                                            "payload": {
                                                "session_id": sid_c,
                                                "output": output
                                            }
                                        })).await;
                                    }
                                    inp = rx_in.recv() => {
                                        let Some(bytes) = inp else { break; };
                                        let _ = chan.send_input(&bytes).await;
                                    }
                                    rsz = rx_resize.recv() => {
                                        let Some((c, r)) = rsz else { break; };
                                        let _ = chan.send_resize(c, r).await;
                                    }
                                }
                            }
                            chan.close();
                            if let Some(tee) = rec_tee.take() {
                                let entry = rec_catalog.finalize(tee).await;
                                state_rec.persist_recording_metadata(&entry).await;
                            }
                            let _ = ev_tx_c.send(serde_json::json!({
                                "type": "session_closed",
                                "payload": { "session_id": sid_c }
                            })).await;
                        });
                                sessions.insert(
                                    sid,
                                    ActiveTerm::Live {
                                        tx_in,
                                        tx_resize,
                                        region,
                                        ssm_session_id: ssm_sid,
                                        iid,
                                        creds: *creds,
                                        mod_handle,
                                        fw_buf: crate::dlp::ShellCommandFirewallBuffer::new(),
                                    },
                                );
                    }
                    ConnectOutcome::Err { sid, err } => {
                        pending_resizes.remove(&sid);
                        if pending_sids.remove(&sid) {
                            let _ = ev_tx.try_send(serde_json::json!({
                                "type": "session_error",
                                "payload": { "session_id": sid, "error": err }
                            }));
                        }
                    }
                }
            }
            inbound = socket.next() => {
                let Some(Ok(msg)) = inbound else { break; };
                let WsMsg::Text(txt) = msg else {
                    if matches!(msg, WsMsg::Close(_)) { break; }
                    continue;
                };
                let Ok(env) = serde_json::from_str::<serde_json::Value>(&txt) else { continue; };
                let typ = env["type"].as_str().unwrap_or("");
                let payload = &env["payload"];
                match typ {
                    "start_session" => {
                        let sid = payload["session_id"].as_str().unwrap_or("").to_string();
                        let iid = payload["instance_id"].as_str().unwrap_or("").to_string();
                        let region = payload["aws_region"].as_str().filter(|s| !s.is_empty()).unwrap_or("us-east-1").to_string();
                        let profile_name = payload["aws_profile"].as_str().unwrap_or("").to_string();
                        let cols = payload["cols"].as_u64().unwrap_or(120).max(1) as u32;
                        let rows = payload["rows"].as_u64().unwrap_or(32).max(1) as u32;
                        if sid.is_empty() { continue; }

                        let is_real = iid.starts_with("i-") || iid.starts_with("mi-");
                        if !is_real {
                            let _ = ev_tx.try_send(serde_json::json!({
                                "type": "session_error",
                                "payload": {
                                    "session_id": sid,
                                    "error": format!("A real EC2 or SSM managed instance ID is required (got '{iid}')")
                                }
                            }));
                            continue;
                        }

                        let profile_trimmed = profile_name.trim();
                        let creds = if profile_trimmed.starts_with("user:") {
                            let Some(lease) = state
                                .aws
                                .accounts
                                .find_connected_role_lease_for_user(&tenant, &user_id, profile_trimmed)
                                .await
                            else {
                                let _ = ev_tx.try_send(serde_json::json!({
                                    "type": "session_error",
                                    "payload": {
                                        "session_id": sid,
                                        "error": "AWS role session expired or disconnected. Reconnect the AWS role and try again."
                                    }
                                }));
                                continue;
                            };
                            Some(lease.credentials)
                        } else {
                            let mut resolved = crate::ws::resolve_tenant_aws_creds_and_region(
                                &state.aws.accounts,
                                &tenant,
                                (!profile_trimmed.is_empty()).then_some(profile_trimmed),
                            )
                            .await
                            .map(|(c, _)| c);
                            if resolved.is_none()
                                && !profile_trimmed.is_empty()
                                && state.aws.accounts.mode().await != AwsAccessMode::User
                            {
                                let http = state.aws.discovery.http_client().clone();
                                for p in load_local_profiles() {
                                    if p.name == profile_trimmed || p.sso_account_id.as_deref() == Some(profile_trimmed) {
                                        resolved = resolve_profile_credentials(&p, &http).await;
                                        if resolved.is_some() { break; }
                                    }
                                }
                            }
                            resolved
                        };

                        let Some(c) = creds else {
                            let _ = ev_tx.try_send(serde_json::json!({
                                "type": "session_error",
                                "payload": {
                                    "session_id": sid,
                                    "error": format!("Live AWS credentials unavailable for SSM session to {iid}")
                                }
                            }));
                            continue;
                        };

                        pending_sids.insert(sid.clone());
                        let shells = state.aws.shells.clone();
                        let conn_tx_c = conn_tx.clone();
                        tokio::spawn(async move {
                            match shells.connect_live_shell(&region, &iid, None, &c).await {
                                Ok((started, chan)) => {
                                    if let Err(tokio::sync::mpsc::error::SendError(
                                        ConnectOutcome::Ok {
                                            chan,
                                            region,
                                            started,
                                            creds,
                                            ..
                                        },
                                    )) = conn_tx_c.send(ConnectOutcome::Ok {
                                        sid,
                                        iid,
                                        region,
                                        creds: Box::new(c),
                                        started: Box::new(started),
                                        chan,
                                        cols,
                                        rows,
                                    }).await {
                                        chan.close();
                                        let _ = shells
                                            .terminate_session(&region, &started.session_id, &creds)
                                            .await;
                                    }
                                }
                                Err(err) => {
                                    let _ = conn_tx_c.send(ConnectOutcome::Err {
                                        sid,
                                        err: format_ssm_shell_error(&err),
                                    }).await;
                                }
                            }
                        });
                    }
                    "terminal_input" => {
                        let sid = payload["session_id"].as_str().unwrap_or("");
                        let input = payload["input"].as_str().unwrap_or("");
                        if let Some(ActiveTerm::Live {
                            tx_in,
                            iid,
                            mod_handle,
                            fw_buf,
                            ..
                        }) = sessions.get_mut(sid)
                        {
                            let decision = crate::governance_routes::execute_shell_input_firewall(
                                &state,
                                &tenant,
                                sid,
                                "ssm",
                                iid,
                                &user_id,
                                &user_email,
                                mod_handle,
                                fw_buf,
                                input.as_bytes(),
                            )
                            .await;
                            if let Some(banner) = decision.user_banner {
                                let _ = ev_tx.try_send(serde_json::json!({
                                    "type": "terminal_output",
                                    "payload": { "session_id": sid, "output": banner }
                                }));
                            }
                            if !decision.send_upstream.is_empty() {
                                let _ = tx_in.try_send(decision.send_upstream);
                            }
                        }
                    }
                    "terminal_resize" => {
                        let sid = payload["session_id"].as_str().unwrap_or("");
                        let cols = payload["cols"].as_u64().unwrap_or(120).max(1) as u32;
                        let rows = payload["rows"].as_u64().unwrap_or(32).max(1) as u32;
                        if let Some(ActiveTerm::Live { tx_resize, .. }) = sessions.get(sid) {
                            let _ = tx_resize.try_send((cols, rows));
                        } else if pending_sids.contains(sid) {
                            pending_resizes.insert(sid.to_owned(), (cols, rows));
                        }
                    }
                    "terminal_interrupt" => {
                        let sid = payload["session_id"].as_str().unwrap_or("");
                        if let Some(ActiveTerm::Live { tx_in, .. }) = sessions.get(sid) {
                            let _ = tx_in.try_send(vec![3]);
                        }
                    }
                    "close_session" => {
                        let sid = payload["session_id"].as_str().unwrap_or("");
                        pending_sids.remove(sid);
                        pending_resizes.remove(sid);
                        if let Some(ActiveTerm::Live { region, ssm_session_id, creds, .. }) = sessions.remove(sid) {
                            let shells = state.aws.shells.clone();
                            tokio::spawn(async move {
                                let _ = shells.terminate_session(&region, &ssm_session_id, &creds).await;
                            });
                        }
                        let _ = ev_tx.try_send(serde_json::json!({
                            "type": "session_closed",
                            "payload": { "session_id": sid }
                        }));
                    }
                    _ => {}
                }
            }
        }
    }
    for (
        _,
        ActiveTerm::Live {
            region,
            ssm_session_id,
            creds,
            ..
        },
    ) in sessions
    {
        let shells = state.aws.shells.clone();
        tokio::spawn(async move {
            let _ = shells
                .terminate_session(&region, &ssm_session_id, &creds)
                .await;
        });
    }
}

async fn handle_ssm_shell_ws(
    mut socket: WebSocket,
    state: AppState,
    tenant: String,
    user_id: String,
    user_email: String,
    auth_session_id: String,
    instance_id: String,
    region: String,
    role_id: String,
    terminal_id: String,
    ssm_session_id: String,
) {
    let is_real_instance = instance_id.starts_with("i-") || instance_id.starts_with("mi-");
    if !is_real_instance {
        let _ = socket
            .send(WsMsg::Text(
                format!(
                    "\r\n\x1b[1;31m[operquay-ssm error]\x1b[0m Real EC2 instance ID required (got '{instance_id}')\r\n"
                )
                .into(),
            ))
            .await;
        return;
    }

    let mut creds = if role_id.is_empty() {
        None
    } else {
        state
            .aws
            .accounts
            .list_connected_roles(&tenant, &user_id)
            .await
            .into_iter()
            .find(|r| r.id == role_id || r.binding_id == role_id)
            .map(|r| r.credentials)
    };
    if creds.is_none() {
        creds = crate::ws::resolve_tenant_aws_creds_and_region(
            &state.aws.accounts,
            &tenant,
            (!role_id.is_empty()).then_some(role_id.as_str()),
        )
        .await
        .map(|(c, _)| c);
    }
    let Some(c) = creds else {
        let _ = socket
            .send(WsMsg::Text(
                format!(
                    "\r\n\x1b[1;31m[operquay-ssm error]\x1b[0m Live AWS credentials unavailable for instance {instance_id}\r\n"
                )
                .into(),
            ))
            .await;
        return;
    };

    let resume_sid = state
        .aws
        .shells
        .lookup_user_shell(&tenant, &user_id, &auth_session_id, &terminal_id)
        .await
        .map(|s| s.ssm_session_id)
        .filter(|s| s != &ssm_session_id && !s.is_empty());
    match state
        .aws
        .shells
        .connect_live_shell(&region, &instance_id, resume_sid.as_deref(), &c)
        .await
    {
        Ok((started, mut chan)) => {
            let rec_policy = state
                .platform
                .rec_policies
                .read()
                .await
                .get(&tenant)
                .cloned()
                .unwrap_or_default();
            let should_record = rec_policy.should_record_instance("ssh", &instance_id, "");
            let mut rec_tee = if should_record {
                state.ensure_tenant_dek_persisted(&tenant).await;
                match state
                    .recordings
                    .start_cast_session(
                        started.session_id.clone(),
                        tenant.clone(),
                        "ssh".to_owned(),
                        instance_id.clone(),
                        rec_policy.fail_closed,
                        120,
                        32,
                    )
                    .await
                {
                    Ok(t) => Some(t),
                    Err(err) if rec_policy.fail_closed => {
                        chan.close();
                        let _ = state
                            .aws
                            .shells
                            .terminate_session(&region, &started.session_id, &c)
                            .await;
                        let _ = socket
                            .send(WsMsg::Text(
                                format!(
                                    "\r\n\x1b[1;31m[recording fail-closed abort]\x1b[0m {err}\r\n"
                                )
                                .into(),
                            ))
                            .await;
                        let _ = socket.send(WsMsg::Close(None)).await;
                        return;
                    }
                    Err(_) => None,
                }
            } else {
                None
            };
            let auth_check_active = !user_id.is_empty()
                && !auth_session_id.is_empty()
                && auth_session_id != "anonymous-lab";
            let binding = role_id
                .trim()
                .strip_prefix("user:")
                .filter(|s| !s.is_empty())
                .unwrap_or("aws-ssm");
            let mut fence_guard = state.session_fence.register_with_session(
                &tenant,
                &user_id,
                &auth_session_id,
                Some(binding),
                &ssm_session_id,
                None,
            );
            let mod_handle = state.moderation.register_session(
                &tenant,
                &ssm_session_id,
                "ssm",
                &instance_id,
                &user_id,
                &user_email,
                rec_tee.as_ref().map(|_| started.session_id.clone()),
            );
            let mut fw_buf = crate::dlp::ShellCommandFirewallBuffer::new();
            let mut fence_tick = tokio::time::interval(std::time::Duration::from_secs(5));
            fence_tick.tick().await;
            let rec_start = std::time::Instant::now();
            let banner = format!(
                "\r\n\x1b[1;36m[operquay-ssm]\x1b[0m Live SSM DataChannel attached to \x1b[1m{instance_id}\x1b[0m ({region}) [{}]\r\n",
                started.session_id
            );
            let export_sid = if terminal_id.trim().is_empty() {
                started.session_id.clone()
            } else {
                terminal_id.clone()
            };
            state
                .aws
                .shells
                .init_session_transcript(&tenant, &user_id, &export_sid, &instance_id)
                .await;
            state
                .aws
                .shells
                .append_session_output(&tenant, &export_sid, banner.as_bytes())
                .await;
            if let Some(tee) = rec_tee.as_mut() {
                if let Err(err) = tee.record_cast_output(rec_start.elapsed().as_secs_f64(), &banner)
                {
                    if rec_policy.fail_closed {
                        chan.close();
                        if let Some(t) = rec_tee.take() {
                            let entry = state.recordings.finalize(t).await;
                            state.persist_recording_metadata(&entry).await;
                        }
                        let _ = state
                            .aws
                            .shells
                            .terminate_session(&region, &started.session_id, &c)
                            .await;
                        let _ = socket
                            .send(WsMsg::Text(
                                format!(
                                    "\r\n\x1b[1;31m[recording fail-closed abort]\x1b[0m {err}\r\n"
                                )
                                .into(),
                            ))
                            .await;
                        let _ = socket.send(WsMsg::Close(None)).await;
                        return;
                    }
                }
            }
            let _ = socket.send(WsMsg::Text(banner.into())).await;
            loop {
                tokio::select! {
                    biased;
                    reason = fence_guard.revoked() => {
                        let _ = socket
                            .send(WsMsg::Text(
                                format!("\r\n[ssm] session terminated: {reason}\r\n").into(),
                            ))
                            .await;
                        let _ = socket.send(WsMsg::Close(None)).await;
                        break;
                    }
                    _ = fence_tick.tick(), if auth_check_active => {
                        if !state
                            .auth
                            .is_session_active(&tenant, &auth_session_id, &user_id)
                            .await
                        {
                            let _ = socket
                                .send(WsMsg::Text(
                                    "\r\n[ssm] session terminated: revoked or expired\r\n".into(),
                                ))
                                .await;
                            let _ = socket.send(WsMsg::Close(None)).await;
                            break;
                        }
                    }
                    out = chan.rx_output.recv() => {
                        let Some(bytes) = out else { break; };
                        state
                            .aws
                            .shells
                            .append_session_output(&tenant, &export_sid, &bytes)
                            .await;
                        let txt = String::from_utf8_lossy(&bytes).into_owned();
                        mod_handle.publish_output(&txt);
                        if let Some(tee) = rec_tee.as_mut() {
                            if let Err(err) = tee.record_cast_output(rec_start.elapsed().as_secs_f64(), &txt) {
                                if rec_policy.fail_closed {
                                    let _ = socket
                                        .send(WsMsg::Text(
                                            format!("\r\n[recording fail-closed abort] {err}\r\n")
                                                .into(),
                                        ))
                                        .await;
                                    break;
                                }
                            }
                        }
                        if socket.send(WsMsg::Text(txt.into())).await.is_err() {
                            break;
                        }
                    }
                    inbound = socket.next() => {
                        let Some(Ok(msg)) = inbound else { break; };
                        let input_bytes: Option<Vec<u8>> = match msg {
                            WsMsg::Text(txt) => {
                                if let Ok(ctrl) = serde_json::from_str::<serde_json::Value>(&txt) {
                                    match ctrl["type"].as_str().unwrap_or("") {
                                        "resize" => {
                                            let cols = ctrl["cols"].as_u64().unwrap_or(120) as u32;
                                            let rows = ctrl["rows"].as_u64().unwrap_or(32) as u32;
                                            let _ = chan.send_resize(cols, rows).await;
                                            None
                                        }
                                        "input" => Some(ctrl["data"].as_str().unwrap_or("").as_bytes().to_vec()),
                                        _ => Some(txt.as_bytes().to_vec()),
                                    }
                                } else {
                                    Some(txt.as_bytes().to_vec())
                                }
                            }
                            WsMsg::Binary(b) => Some(b.to_vec()),
                            WsMsg::Close(_) => break,
                            _ => None,
                        };
                        if let Some(raw_bytes) = input_bytes {
                            let decision = crate::governance_routes::execute_shell_input_firewall(
                                &state,
                                &tenant,
                                &ssm_session_id,
                                "ssm",
                                &instance_id,
                                &user_id,
                                &user_email,
                                &mod_handle,
                                &mut fw_buf,
                                &raw_bytes,
                            )
                            .await;
                            if let Some(banner) = decision.user_banner {
                                let _ = socket.send(WsMsg::Text(banner.into())).await;
                            }
                            if !decision.send_upstream.is_empty() {
                                let _ = chan.send_input(&decision.send_upstream).await;
                            }
                        }
                    }
                }
            }
            chan.close();
            if let Some(tee) = rec_tee.take() {
                let entry = state.recordings.finalize(tee).await;
                state.persist_recording_metadata(&entry).await;
            }
            let _ = state
                .aws
                .shells
                .terminate_session(&region, &started.session_id, &c)
                .await;
        }
        Err(err) => {
            let _ = socket
                .send(WsMsg::Text(
                    format!("\r\n\x1b[1;31m[operquay-ssm error]\x1b[0m {err}\r\n").into(),
                ))
                .await;
        }
    }
}

#[derive(Deserialize)]
struct ExportSessionBody {
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    instance_id: String,
    #[serde(default = "default_txt_fmt")]
    format: String,
    #[serde(default)]
    transcript: String,
}

fn default_txt_fmt() -> String {
    "txt".to_owned()
}

fn sanitize_export_filename_component(raw: &str) -> String {
    let clean: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if clean.is_empty() {
        "session".to_owned()
    } else {
        clean
    }
}

async fn export_user_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ExportSessionBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::SESSION_SSH]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let sid = body.session_id.trim();
    if sid.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "session_id is required");
    }
    let Some(entry) = state
        .aws
        .shells
        .get_session_transcript(&tenant, &claims.user_id, sid)
        .await
    else {
        return json_err(StatusCode::NOT_FOUND, "Session transcript unavailable");
    };
    let fname = format!(
        "{}.log",
        sanitize_export_filename_component(if entry.instance_id.is_empty() {
            sid
        } else {
            &entry.instance_id
        })
    );
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{fname}\""),
            ),
            (
                header::HeaderName::from_static("x-content-type-options"),
                "nosniff".to_owned(),
            ),
        ],
        entry.data,
    )
        .into_response()
}

async fn export_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut body): Json<ExportSessionBody>,
) -> Response {
    let (tenant, claims) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if body.transcript.is_empty() && !body.session_id.trim().is_empty() {
        if let Some(entry) = state
            .aws
            .shells
            .get_session_transcript(&tenant, &claims.user_id, body.session_id.trim())
            .await
        {
            body.transcript = String::from_utf8_lossy(&entry.data).into_owned();
            if body.instance_id.is_empty() {
                body.instance_id = entry.instance_id;
            }
        }
    }
    if body.instance_id.trim().is_empty() {
        body.instance_id = sanitize_export_filename_component(&body.session_id);
    }
    let exported = state
        .aws
        .shells
        .store_export(&tenant, &body.instance_id, &body.format, &body.transcript)
        .await;
    let url = format!("/exports/{}", exported.id);
    Json(serde_json::json!({
        "id": exported.id,
        "filename": exported.filename,
        "url": url,
        "download_url": url,
    }))
    .into_response()
}

async fn serve_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, _) = match require_actor(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(file) = state.aws.shells.get_export(&tenant, &id).await else {
        return json_err(StatusCode::NOT_FOUND, "export not found");
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, file.content_type),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", file.filename),
            ),
        ],
        file.data,
    )
        .into_response()
}

#[derive(Deserialize)]
struct TransferBrowseBody {
    instance_id: String,
    #[serde(default = "default_us_east", alias = "aws_region")]
    region: String,
    #[serde(default = "default_linux")]
    platform: String,
    #[serde(default = "default_root_path", alias = "remote_path")]
    path: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    binding_id: String,
    #[serde(default, alias = "aws_profile")]
    profile: String,
}

fn default_linux() -> String {
    "linux".to_owned()
}

fn default_root_path() -> String {
    "/".to_owned()
}

async fn browse_directory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TransferBrowseBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::FILES_TRANSFER]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let creds = match resolve_aws_creds_for_request(
        &state,
        &tenant,
        &claims.user_id,
        (!body.binding_id.trim().is_empty()).then_some(body.binding_id.as_str()),
        (!body.account_id.trim().is_empty()).then_some(body.account_id.as_str()),
        (!body.profile.trim().is_empty()).then_some(body.profile.as_str()),
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return *r,
    };
    match state
        .aws
        .transfer
        .browse_directory(
            &body.region,
            &body.instance_id,
            &body.platform,
            &body.path,
            &creds,
        )
        .await
    {
        Ok(entries) => Json(entries).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct UploadBody {
    instance_id: String,
    #[serde(default = "default_us_east", alias = "aws_region")]
    region: String,
    #[serde(default = "default_linux")]
    platform: String,
    remote_path: String,
    data_b64: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    binding_id: String,
    #[serde(default, alias = "aws_profile")]
    profile: String,
    #[serde(default, alias = "s3_bucket")]
    express_bucket: String,
}

async fn parse_upload_request(
    state: &AppState,
    req: axum::extract::Request,
) -> Result<
    (
        String,
        String,
        String,
        String,
        Vec<u8>,
        String,
        String,
        String,
        String,
    ),
    Box<Response>,
> {
    let is_multipart = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.to_ascii_lowercase().starts_with("multipart/form-data"));

    if is_multipart {
        let mut mp = Multipart::from_request(req, state).await.map_err(|e| {
            Box::new(json_err(
                StatusCode::BAD_REQUEST,
                format!("invalid multipart form: {e}"),
            ))
        })?;
        let mut instance_id = String::new();
        let mut region = "us-east-1".to_owned();
        let mut platform = "linux".to_owned();
        let mut remote_path = String::new();
        let mut binding_id = String::new();
        let mut account_id = String::new();
        let mut profile = String::new();
        let mut express_bucket = String::new();
        let mut bytes: Option<Vec<u8>> = None;

        while let Ok(Some(field)) = mp.next_field().await {
            let name = field.name().unwrap_or("").to_owned();
            if name == "file" {
                let raw = field.bytes().await.map_err(|e| {
                    Box::new(json_err(
                        StatusCode::BAD_REQUEST,
                        format!("failed reading uploaded file: {e}"),
                    ))
                })?;
                bytes = Some(raw.to_vec());
            } else {
                let val = field.text().await.unwrap_or_default();
                match name.as_str() {
                    "instance_id" => instance_id = val,
                    "region" | "aws_region" => {
                        if !val.trim().is_empty() {
                            region = val;
                        }
                    }
                    "platform" => {
                        if !val.trim().is_empty() {
                            platform = val;
                        }
                    }
                    "remote_path" => remote_path = val,
                    "binding_id" => binding_id = val,
                    "account_id" => account_id = val,
                    "profile" | "aws_profile" => profile = val,
                    "express_bucket" | "s3_bucket" | "bucket" => express_bucket = val,
                    _ => {}
                }
            }
        }
        let data = bytes
            .ok_or_else(|| Box::new(json_err(StatusCode::BAD_REQUEST, "file field is required")))?;
        if instance_id.trim().is_empty() || remote_path.trim().is_empty() {
            return Err(Box::new(json_err(
                StatusCode::BAD_REQUEST,
                "instance_id and remote_path are required",
            )));
        }
        return Ok((
            instance_id,
            region,
            platform,
            remote_path,
            data,
            binding_id,
            account_id,
            profile,
            express_bucket,
        ));
    }

    let raw = axum::body::to_bytes(req.into_body(), 48 * 1024 * 1024)
        .await
        .map_err(|e| {
            Box::new(json_err(
                StatusCode::BAD_REQUEST,
                format!("failed reading body: {e}"),
            ))
        })?;
    let body: UploadBody = serde_json::from_slice(&raw).map_err(|e| {
        Box::new(json_err(
            StatusCode::BAD_REQUEST,
            format!("invalid JSON payload: {e}"),
        ))
    })?;
    let bytes = STANDARD
        .decode(body.data_b64.trim())
        .map_err(|_| Box::new(json_err(StatusCode::BAD_REQUEST, "invalid base64 payload")))?;
    Ok((
        body.instance_id,
        body.region,
        body.platform,
        body.remote_path,
        bytes,
        body.binding_id,
        body.account_id,
        body.profile,
        body.express_bucket,
    ))
}

async fn upload_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: axum::extract::Request,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::FILES_TRANSFER]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let (
        instance_id,
        region,
        platform,
        remote_path,
        bytes,
        binding_id,
        account_id,
        profile,
        express_bucket,
    ) = match parse_upload_request(&state, req).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let creds = match resolve_aws_creds_for_request(
        &state,
        &tenant,
        &claims.user_id,
        (!binding_id.trim().is_empty()).then_some(binding_id.as_str()),
        (!account_id.trim().is_empty()).then_some(account_id.as_str()),
        (!profile.trim().is_empty()).then_some(profile.as_str()),
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return *r,
    };

    if !express_bucket.trim().is_empty() {
        let key = format!("operquay-tmp/{}", Uuid::new_v4());
        if let Err(e) = state
            .aws
            .transfer
            .express_s3_put(&region, express_bucket.trim(), &key, &bytes, &creds)
            .await
        {
            return json_err(StatusCode::BAD_GATEWAY, e);
        }
        let safe_target = operquay_aws::transfer::shell_single_quote(&remote_path);
        let s3_uri = format!("s3://{}/{key}", express_bucket.trim());
        let cmd = if platform.eq_ignore_ascii_case("windows") {
            format!(
                "aws s3 cp {s3_uri} {safe_target} --region {region}; aws s3 rm {s3_uri} --region {region}"
            )
        } else {
            format!(
                "aws s3 cp {s3_uri} {safe_target} --region {region} && aws s3 rm {s3_uri} --region {region}"
            )
        };
        if let Err(e) = state
            .aws
            .transfer
            .run_ssm_command(&region, &instance_id, &platform, &[cmd], &creds)
            .await
        {
            return json_err(StatusCode::BAD_GATEWAY, e);
        }
        return Json(serde_json::json!({
            "progress": 100,
            "done": true,
            "status": "complete",
            "total": bytes.len(),
            "message": format!("Uploaded via S3 Express bucket {}", express_bucket.trim()),
        }))
        .into_response();
    }

    match state
        .aws
        .transfer
        .upload_file(
            &region,
            &instance_id,
            &platform,
            &remote_path,
            &bytes,
            &creds,
        )
        .await
    {
        Ok(updates) => Json(serde_json::json!({
            "progress": 100,
            "done": true,
            "status": "complete",
            "total": bytes.len(),
            "updates": updates,
        }))
        .into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct DownloadBody {
    instance_id: String,
    #[serde(default = "default_us_east", alias = "aws_region")]
    region: String,
    #[serde(default = "default_linux")]
    platform: String,
    remote_path: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    binding_id: String,
    #[serde(default, alias = "aws_profile")]
    profile: String,
    #[serde(default, alias = "s3_bucket")]
    express_bucket: String,
}

async fn download_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DownloadBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::FILES_TRANSFER]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let creds = match resolve_aws_creds_for_request(
        &state,
        &tenant,
        &claims.user_id,
        (!body.binding_id.trim().is_empty()).then_some(body.binding_id.as_str()),
        (!body.account_id.trim().is_empty()).then_some(body.account_id.as_str()),
        (!body.profile.trim().is_empty()).then_some(body.profile.as_str()),
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return *r,
    };

    let filename = body
        .remote_path
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("download.bin")
        .to_owned();

    if !body.express_bucket.trim().is_empty() {
        let key = format!("operquay-tmp/{}", Uuid::new_v4());
        let safe_path = operquay_aws::transfer::shell_single_quote(&body.remote_path);
        let s3_uri = format!("s3://{}/{key}", body.express_bucket.trim());
        let cmd = format!("aws s3 cp {safe_path} {s3_uri} --region {}", body.region);
        if let Err(e) = state
            .aws
            .transfer
            .run_ssm_command(
                &body.region,
                &body.instance_id,
                &body.platform,
                &[cmd],
                &creds,
            )
            .await
        {
            return json_err(StatusCode::BAD_GATEWAY, e);
        }
        return match state
            .aws
            .transfer
            .express_s3_get(&body.region, body.express_bucket.trim(), &key, &creds)
            .await
        {
            Ok(bytes) => {
                let clean = STANDARD.encode(&bytes);
                Json(serde_json::json!({
                    "progress": 100,
                    "done": true,
                    "status": "complete",
                    "total": bytes.len(),
                    "remote_path": body.remote_path,
                    "filename": filename,
                    "data": clean,
                    "data_b64": clean,
                }))
                .into_response()
            }
            Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
        };
    }

    let safe_path = operquay_aws::transfer::shell_single_quote(&body.remote_path);
    let cmd = if body.platform.eq_ignore_ascii_case("windows") {
        format!("[Convert]::ToBase64String([IO.File]::ReadAllBytes({safe_path}))")
    } else {
        format!("base64 -w0 {safe_path}")
    };
    match state
        .aws
        .transfer
        .run_ssm_command(
            &body.region,
            &body.instance_id,
            &body.platform,
            &[cmd],
            &creds,
        )
        .await
    {
        Ok(b64) => {
            let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
            let decoded_len = STANDARD.decode(&clean).map_or(0, |b| b.len());
            Json(serde_json::json!({
                "progress": 100,
                "done": true,
                "status": "complete",
                "total": decoded_len,
                "remote_path": body.remote_path,
                "filename": filename,
                "data": clean,
                "data_b64": clean,
            }))
            .into_response()
        }
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct ExpressTransferBody {
    #[serde(default, alias = "s3_bucket")]
    bucket: String,
    #[serde(default)]
    key: String,
    #[serde(default = "default_us_east", alias = "aws_region")]
    region: String,
    #[serde(default)]
    data_b64: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    binding_id: String,
    #[serde(default, alias = "aws_profile")]
    profile: String,
    #[serde(default)]
    instance_id: String,
    #[serde(default)]
    remote_path: String,
    #[serde(default = "default_linux")]
    platform: String,
}

async fn express_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: axum::extract::Request,
) -> Response {
    let is_multipart = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.to_ascii_lowercase().starts_with("multipart/form-data"));
    if is_multipart {
        return upload_file(State(state), headers, req).await;
    }

    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::FILES_TRANSFER]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Ok(raw) = axum::body::to_bytes(req.into_body(), 48 * 1024 * 1024).await else {
        return json_err(StatusCode::BAD_REQUEST, "failed reading body");
    };
    let Ok(body) = serde_json::from_slice::<ExpressTransferBody>(&raw) else {
        return json_err(StatusCode::BAD_REQUEST, "invalid JSON payload");
    };
    let Ok(bytes) = STANDARD.decode(body.data_b64.trim()) else {
        return json_err(StatusCode::BAD_REQUEST, "invalid base64 payload");
    };
    let creds = match resolve_aws_creds_for_request(
        &state,
        &tenant,
        &claims.user_id,
        (!body.binding_id.trim().is_empty()).then_some(body.binding_id.as_str()),
        (!body.account_id.trim().is_empty()).then_some(body.account_id.as_str()),
        (!body.profile.trim().is_empty()).then_some(body.profile.as_str()),
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return *r,
    };
    match state
        .aws
        .transfer
        .express_s3_put(&body.region, &body.bucket, &body.key, &bytes, &creds)
        .await
    {
        Ok(uri) => Json(serde_json::json!({ "s3_uri": uri, "status": "complete", "done": true, "progress": 100 })).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

async fn express_download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ExpressTransferBody>,
) -> Response {
    if !body.instance_id.trim().is_empty() && !body.remote_path.trim().is_empty() {
        return download_file(
            State(state),
            headers,
            Json(DownloadBody {
                instance_id: body.instance_id,
                region: body.region,
                platform: body.platform,
                remote_path: body.remote_path,
                account_id: body.account_id,
                binding_id: body.binding_id,
                profile: body.profile,
                express_bucket: body.bucket,
            }),
        )
        .await;
    }

    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::FILES_TRANSFER]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let creds = match resolve_aws_creds_for_request(
        &state,
        &tenant,
        &claims.user_id,
        (!body.binding_id.trim().is_empty()).then_some(body.binding_id.as_str()),
        (!body.account_id.trim().is_empty()).then_some(body.account_id.as_str()),
        (!body.profile.trim().is_empty()).then_some(body.profile.as_str()),
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return *r,
    };
    match state
        .aws
        .transfer
        .express_s3_get(&body.region, &body.bucket, &body.key, &creds)
        .await
    {
        Ok(bytes) => {
            let clean = STANDARD.encode(&bytes);
            Json(serde_json::json!({
                "data": clean,
                "data_b64": clean,
                "progress": 100,
                "done": true,
                "status": "complete",
                "total": bytes.len(),
            }))
            .into_response()
        }
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct CloneStartBody {
    instance_id: String,
    #[serde(default)]
    clone_name: String,
    #[serde(default = "default_us_east")]
    region: String,
    #[serde(default)]
    binding_id: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    profile: String,
    #[serde(default, alias = "requestId")]
    request_id: String,
}

async fn clone_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CloneStartBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::INSTANCES_CLONE]).await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let _ = &body.request_id;
    let has_cred_ref = !body.binding_id.trim().is_empty()
        || !body.account_id.trim().is_empty()
        || !body.profile.trim().is_empty();
    let creds = if has_cred_ref {
        match resolve_aws_creds_for_request(
            &state,
            &tenant,
            &claims.user_id,
            (!body.binding_id.trim().is_empty()).then_some(body.binding_id.as_str()),
            (!body.account_id.trim().is_empty()).then_some(body.account_id.as_str()),
            (!body.profile.trim().is_empty()).then_some(body.profile.as_str()),
        )
        .await
        {
            Ok(c) => Some(c),
            Err(r) => return *r,
        }
    } else {
        None
    };

    let inst = state
        .aws
        .discovery
        .find_instance(&tenant, &body.instance_id)
        .await
        .unwrap_or(Ec2Instance {
            instance_id: body.instance_id.clone(),
            name: body.instance_id.clone(),
            state: "running".to_owned(),
            instance_type: "t3.medium".to_owned(),
            platform: "linux".to_owned(),
            private_ip: String::new(),
            public_ip: String::new(),
            region: body.region,
            availability_zone: String::new(),
            vpc_id: String::new(),
            subnet_id: String::new(),
            account_id: String::new(),
            profile: "default".to_owned(),
            ssm_online: true,
            tags: std::collections::HashMap::new(),
            security_groups: Vec::new(),
            launch_time: String::new(),
        });
    match state
        .aws
        .clones
        .start_clone(
            &tenant,
            &claims.user_id,
            &inst,
            &body.clone_name,
            creds.as_ref(),
        )
        .await
    {
        Ok(st) => {
            persist_clone_op(&state, &st).await;
            (StatusCode::CREATED, Json(st)).into_response()
        }
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

async fn list_clones(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::INSTANCES_CLONE]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    Json(state.aws.clones.list_clones(&tenant).await).into_response()
}

#[derive(Deserialize, Default)]
struct CloneQuery {
    #[serde(default)]
    binding_id: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    profile: String,
    #[serde(default)]
    instance_id: String,
    #[serde(default)]
    region: String,
}

async fn list_recoverable_clones(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CloneQuery>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::INSTANCES_CLONE]).await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let _ = (&q.binding_id, &q.region);
    let mut ops = state
        .aws
        .clones
        .list_recoverable(&tenant, &claims.user_id)
        .await;
    if !q.instance_id.trim().is_empty() {
        ops.retain(|c| c.source_instance_id == q.instance_id.trim());
    }
    Json(serde_json::json!({
        "operations": ops,
        "incomplete": false,
    }))
    .into_response()
}

async fn clone_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<CloneQuery>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::INSTANCES_CLONE]).await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(st) = state.aws.clones.get_status(&tenant, &id).await else {
        return json_err(StatusCode::NOT_FOUND, "clone not found");
    };
    if st.phase == "image_pending"
        && (!q.binding_id.trim().is_empty()
            || !q.account_id.trim().is_empty()
            || !q.profile.trim().is_empty())
    {
        if let Ok(creds) = resolve_aws_creds_for_request(
            &state,
            &tenant,
            &claims.user_id,
            (!q.binding_id.trim().is_empty()).then_some(q.binding_id.as_str()),
            (!q.account_id.trim().is_empty()).then_some(q.account_id.as_str()),
            (!q.profile.trim().is_empty()).then_some(q.profile.as_str()),
        )
        .await
        {
            if let Ok(updated) = state
                .aws
                .clones
                .refresh_clone_status(&tenant, &id, &creds)
                .await
            {
                persist_clone_op(&state, &updated).await;
                return Json(updated).into_response();
            }
        }
    }
    Json(st).into_response()
}

async fn clone_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<CloneQuery>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::INSTANCES_CLONE]).await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(st) = state.aws.clones.get_status(&tenant, &id).await else {
        return json_err(StatusCode::NOT_FOUND, "clone not found");
    };
    let src = state
        .aws
        .discovery
        .find_instance(&tenant, &st.source_instance_id)
        .await;
    let creds = if !q.binding_id.trim().is_empty()
        || !q.account_id.trim().is_empty()
        || !q.profile.trim().is_empty()
    {
        resolve_aws_creds_for_request(
            &state,
            &tenant,
            &claims.user_id,
            (!q.binding_id.trim().is_empty()).then_some(q.binding_id.as_str()),
            (!q.account_id.trim().is_empty()).then_some(q.account_id.as_str()),
            (!q.profile.trim().is_empty()).then_some(q.profile.as_str()),
        )
        .await
        .ok()
    } else {
        None
    };
    match state
        .aws
        .clones
        .settings_for_clone_live(&tenant, &id, src.as_ref(), creds.as_ref())
        .await
    {
        Some(s) => Json(s).into_response(),
        None => json_err(StatusCode::NOT_FOUND, "clone settings not found"),
    }
}

async fn recover_clone(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::INSTANCES_CLONE]).await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match state
        .aws
        .clones
        .recover_clone(&tenant, &claims.user_id, &id)
        .await
    {
        Some(st) => {
            persist_clone_op(&state, &st).await;
            Json(st).into_response()
        }
        None => json_err(StatusCode::NOT_FOUND, "clone not found"),
    }
}

#[derive(Deserialize)]
struct CloneLaunchBody {
    #[serde(default)]
    binding_id: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    profile: String,
    #[serde(default)]
    settings: Option<LaunchCloneRequest>,
    #[serde(flatten)]
    flat: LaunchCloneRequest,
}

async fn clone_launch_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<CloneLaunchBody>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::INSTANCES_CLONE]).await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let has_cred_ref = !body.binding_id.trim().is_empty()
        || !body.account_id.trim().is_empty()
        || !body.profile.trim().is_empty();
    let creds = if has_cred_ref {
        match resolve_aws_creds_for_request(
            &state,
            &tenant,
            &claims.user_id,
            (!body.binding_id.trim().is_empty()).then_some(body.binding_id.as_str()),
            (!body.account_id.trim().is_empty()).then_some(body.account_id.as_str()),
            (!body.profile.trim().is_empty()).then_some(body.profile.as_str()),
        )
        .await
        {
            Ok(c) => Some(c),
            Err(r) => return *r,
        }
    } else {
        None
    };
    let req = body.settings.unwrap_or(body.flat);
    match state
        .aws
        .clones
        .launch_clone(&tenant, &id, &req, creds.as_ref())
        .await
    {
        Ok(st) => {
            persist_clone_op(&state, &st).await;
            Json(st).into_response()
        }
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
    }
}

async fn clone_launch_legacy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CloneLaunchBody>,
) -> Response {
    let id = body
        .settings
        .as_ref()
        .map(|s| s.clone_id.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| body.flat.clone_id.clone());
    clone_launch_id(State(state), headers, Path(id), Json(body)).await
}

async fn resolve_or_synthesize_topology(
    state: &AppState,
    tenant: &str,
    id_or_vpc: &str,
) -> Option<VpcTopology> {
    if let Some(t) = state.aws.topology.get_topology(tenant, id_or_vpc).await {
        return Some(t);
    }
    let instances = state.aws.discovery.list_instances(tenant).await;
    let target_vpc = instances
        .iter()
        .find(|i| i.instance_id == id_or_vpc || i.vpc_id == id_or_vpc)
        .map_or_else(
            || id_or_vpc.to_owned(),
            |i| {
                if i.vpc_id.is_empty() {
                    "vpc-default".to_owned()
                } else {
                    i.vpc_id.clone()
                }
            },
        );

    if let Some(t) = state.aws.topology.get_topology(tenant, &target_vpc).await {
        return Some(t);
    }

    let vpc_instances: Vec<&Ec2Instance> = instances
        .iter()
        .filter(|i| {
            i.vpc_id == target_vpc
                || (target_vpc == "vpc-default" && i.vpc_id.is_empty())
                || i.instance_id == id_or_vpc
        })
        .collect();
    if vpc_instances.is_empty() && !id_or_vpc.starts_with("vpc-") {
        return None;
    }

    let mut seen_subnets = std::collections::HashSet::new();
    let mut subnets = Vec::new();
    let mut seen_sgs = std::collections::HashSet::new();
    let mut security_groups = Vec::new();
    let mut topo_instances = Vec::new();

    for inst in vpc_instances {
        let sub_id = if inst.subnet_id.is_empty() {
            "subnet-default".to_owned()
        } else {
            inst.subnet_id.clone()
        };
        if seen_subnets.insert(sub_id.clone()) {
            subnets.push(SubnetInfo {
                id: sub_id.clone(),
                cidr: "10.0.1.0/24".to_owned(),
                name: sub_id.clone(),
                az: if inst.availability_zone.is_empty() {
                    format!("{}a", inst.region)
                } else {
                    inst.availability_zone.clone()
                },
                is_public: !inst.public_ip.is_empty(),
                ..Default::default()
            });
        }
        for sg in &inst.security_groups {
            if seen_sgs.insert(sg.clone()) {
                security_groups.push(SecurityGroupInfo {
                    id: sg.clone(),
                    name: sg.clone(),
                    ..Default::default()
                });
            }
        }
        topo_instances.push(TopologyInstance {
            id: inst.instance_id.clone(),
            name: inst.name.clone(),
            private_ip: inst.private_ip.clone(),
            public_ip: inst.public_ip.clone(),
            state: inst.state.clone(),
            platform: inst.platform.clone(),
            instance_type: inst.instance_type.clone(),
            subnet_id: sub_id,
            security_groups: inst.security_groups.clone(),
        });
    }

    let topo = VpcTopology {
        vpc: VpcInfo {
            id: target_vpc.clone(),
            cidr: "10.0.0.0/16".to_owned(),
            name: target_vpc,
            is_default: false,
        },
        subnets,
        instances: topo_instances,
        security_groups,
        ..Default::default()
    };
    state.aws.topology.put_topology(tenant, topo.clone()).await;
    Some(topo)
}

async fn resolve_or_fetch_topology(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    id_or_vpc: &str,
    region: &str,
    binding_id: Option<&str>,
    account_id: Option<&str>,
    profile: Option<&str>,
) -> Result<VpcTopology, Box<Response>> {
    if let Some(t) = state
        .aws
        .topology
        .find_by_vpc_or_instance(tenant, id_or_vpc)
        .await
    {
        return Ok(t);
    }
    let has_cred_ref = binding_id.is_some_and(|s| !s.trim().is_empty())
        || account_id.is_some_and(|s| !s.trim().is_empty())
        || profile.is_some_and(|s| !s.trim().is_empty());
    if has_cred_ref {
        match resolve_aws_creds_for_request(state, tenant, user_id, binding_id, account_id, profile)
            .await
        {
            Ok(creds) => {
                match fetch_live_vpc_topology(
                    state.aws.discovery.http_client(),
                    region,
                    id_or_vpc,
                    &creds,
                )
                .await
                {
                    Ok(topo) => {
                        state.aws.topology.put_topology(tenant, topo.clone()).await;
                        return Ok(topo);
                    }
                    Err(e) => return Err(Box::new(json_err(StatusCode::BAD_GATEWAY, e))),
                }
            }
            Err(resp) => return Err(resp),
        }
    }
    resolve_or_synthesize_topology(state, tenant, id_or_vpc)
        .await
        .ok_or_else(|| Box::new(json_err(StatusCode::NOT_FOUND, "VPC topology not found")))
}

async fn get_topology(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vpc_id): Path<String>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::INSTANCES_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match resolve_or_fetch_topology(
        &state,
        &tenant,
        &claims.user_id,
        &vpc_id,
        "us-east-1",
        None,
        None,
        None,
    )
    .await
    {
        Ok(t) => Json(t).into_response(),
        Err(resp) => *resp,
    }
}

#[derive(Deserialize)]
struct TopoQuery {
    #[serde(default, alias = "instance_id", alias = "id")]
    vpc_id: String,
    #[serde(default)]
    binding_id: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    profile: String,
    #[serde(default = "default_us_east")]
    region: String,
}

async fn get_topology_query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TopoQuery>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::INSTANCES_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match resolve_or_fetch_topology(
        &state,
        &tenant,
        &claims.user_id,
        &q.vpc_id,
        &q.region,
        (!q.binding_id.trim().is_empty()).then_some(q.binding_id.as_str()),
        (!q.account_id.trim().is_empty()).then_some(q.account_id.as_str()),
        (!q.profile.trim().is_empty()).then_some(q.profile.as_str()),
    )
    .await
    {
        Ok(t) => Json(t).into_response(),
        Err(resp) => *resp,
    }
}

#[derive(Deserialize)]
struct ReachabilityReq {
    vpc_id: String,
    source_id: String,
    dest_id: String,
    #[serde(default = "default_tcp")]
    protocol: String,
    #[serde(default = "default_port_443")]
    port: i32,
}

fn default_tcp() -> String {
    "tcp".to_owned()
}

const fn default_port_443() -> i32 {
    443
}

async fn topology_reachability(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ReachabilityReq>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::INSTANCES_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(topo) = state.aws.topology.get_topology(&tenant, &body.vpc_id).await else {
        return json_err(StatusCode::NOT_FOUND, "VPC topology not found");
    };
    Json(analyze_reachability(
        &topo,
        &body.source_id,
        &body.dest_id,
        &body.protocol,
        body.port,
    ))
    .into_response()
}

async fn topology_exposure(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vpc_id): Path<String>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::INSTANCES_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(topo) = resolve_or_synthesize_topology(&state, &tenant, &vpc_id).await else {
        return json_err(StatusCode::NOT_FOUND, "VPC topology not found");
    };
    Json(analyze_exposure(&topo)).into_response()
}

async fn topology_conflicts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vpc_id): Path<String>,
) -> Response {
    let (tenant, _) = match require_any_perm(&state, &headers, &[perm::INSTANCES_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(topo) = resolve_or_synthesize_topology(&state, &tenant, &vpc_id).await else {
        return json_err(StatusCode::NOT_FOUND, "VPC topology not found");
    };
    Json(analyze_rule_conflicts(&topo)).into_response()
}

#[derive(Deserialize)]
struct DeepAnalyzeReq {
    #[serde(default)]
    vpc_id: String,
    #[serde(default, alias = "sourceInstanceId", alias = "source_id")]
    instance_id: String,
    #[serde(default)]
    binding_id: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    profile: String,
    #[serde(default = "default_us_east")]
    region: String,
    #[serde(default, alias = "destInstanceId", alias = "dest_id")]
    dest_instance_id: String,
    #[serde(default, alias = "destIp")]
    dest_ip: String,
    #[serde(default = "default_tcp")]
    protocol: String,
    #[serde(default = "default_port_443")]
    port: i32,
}

async fn topology_deep_analyze(
    State(state): State<AppState>,
    matched: MatchedPath,
    headers: HeaderMap,
    Json(body): Json<DeepAnalyzeReq>,
) -> Response {
    let (tenant, claims) = match require_any_perm(&state, &headers, &[perm::INSTANCES_READ]).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let target = if body.vpc_id.trim().is_empty() {
        body.instance_id.clone()
    } else {
        body.vpc_id.clone()
    };
    let topo = match resolve_or_fetch_topology(
        &state,
        &tenant,
        &claims.user_id,
        &target,
        &body.region,
        (!body.binding_id.trim().is_empty()).then_some(body.binding_id.as_str()),
        (!body.account_id.trim().is_empty()).then_some(body.account_id.as_str()),
        (!body.profile.trim().is_empty()).then_some(body.profile.as_str()),
    )
    .await
    {
        Ok(t) => t,
        Err(resp) => return *resp,
    };

    let wants_sse = !matched.as_str().starts_with("/api/aws/")
        && headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|a| a.contains("text/event-stream"));

    let graph = build_topology_graph(&topo);
    let exposure = analyze_exposure(&topo);
    let conflicts = analyze_rule_conflicts(&topo);

    let dest_needle = if body.dest_instance_id.trim().is_empty() {
        body.dest_ip.trim().to_owned()
    } else {
        body.dest_instance_id.trim().to_owned()
    };
    let reach = if !body.instance_id.trim().is_empty() && !dest_needle.is_empty() {
        Some(analyze_reachability(
            &topo,
            body.instance_id.trim(),
            &dest_needle,
            &body.protocol,
            body.port,
        ))
    } else {
        None
    };

    if !wants_sse && matched.as_str().starts_with("/api/aws/") {
        let hops: Vec<serde_json::Value> = reach.as_ref().map_or_default(|r| {
            r.hops
                .iter()
                .enumerate()
                .map(|(idx, h)| {
                    serde_json::json!({
                        "index": idx,
                        "component": h.component,
                        "resource_id": h.resource_id,
                        "status": h.status,
                        "detail": format!("{} ({}): {}", h.component, h.resource_id, h.detail),
                        "matched_rule": h.matched_rule,
                    })
                })
                .collect()
        });
        let mut explanations = Vec::new();
        if let Some(r) = &reach {
            if r.issues.is_empty() {
                explanations.push(format!(
                    "{} -> {} on {}/{}: {}",
                    r.source.instance_id,
                    if r.destination.instance_id.is_empty() {
                        &r.destination.ip
                    } else {
                        &r.destination.instance_id
                    },
                    r.protocol,
                    r.port,
                    if r.reachable { "reachable" } else { "blocked" }
                ));
            } else {
                explanations.extend(r.issues.iter().cloned());
            }
        } else {
            explanations.push(format!(
                "Analyzed VPC {} ({} nodes, {} edges).",
                topo.vpc.id,
                graph.node_count(),
                graph.edge_count()
            ));
        }
        return Json(serde_json::json!({
            "vpc_id": topo.vpc.id,
            "reachable": reach.as_ref().is_some_and(|r| r.reachable),
            "hops": hops,
            "explanations": explanations,
            "graph_nodes": graph.node_count(),
            "graph_edges": graph.edge_count(),
            "exposure": exposure,
            "conflicts": conflicts,
        }))
        .into_response();
    }

    let done_payload = serde_json::json!({
        "vpc_id": topo.vpc.id,
        "graph_nodes": graph.node_count(),
        "graph_edges": graph.edge_count(),
        "exposure": exposure,
        "conflicts": conflicts,
        "reachability": reach,
    });
    let events = vec![
        Ok::<Event, std::convert::Infallible>(
            Event::default()
                .event("step")
                .data(serde_json::json!({ "phase": "graph", "nodes": graph.node_count(), "edges": graph.edge_count() }).to_string()),
        ),
        Ok(Event::default().event("done").data(done_payload.to_string())),
    ];
    Sse::new(futures_util::stream::iter(events))
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn persist_sso_flow(state: &AppState, tenant: &str, user_id: &str, flow_id: &str) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let Some(flow) = state
        .aws
        .sso
        .get_persisted_flow(tenant, user_id, flow_id)
        .await
    else {
        return;
    };
    let token_state_json = serde_json::to_string(&flow).unwrap_or_else(|_| "{}".to_owned());
    let row = operquay_auth::pg::PgAwsSsoSessionRow {
        id: flow.id,
        tenant_id: flow.tenant_id,
        user_id: flow.user_id,
        region: flow.region,
        start_url: flow.start_url,
        token_state_json,
        expires_at: flow.expires_at,
        cancelled: flow.cancelled,
    };
    if let Err(err) = pg.upsert_aws_sso_session(&row).await {
        tracing::warn!(error = %err, "failed persisting AWS SSO session");
    }
}

async fn persist_role_lease(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    lease: &operquay_aws::accounts::ConnectedRoleLease,
) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let credentials_json =
        serde_json::to_string(&lease.credentials).unwrap_or_else(|_| "{}".to_owned());
    let row = operquay_auth::pg::PgAwsRoleLeaseRow {
        id: lease.id.clone(),
        tenant_id: tenant.to_owned(),
        user_id: user_id.to_owned(),
        binding_id: lease.binding_id.clone(),
        label: lease.label.clone(),
        account_id: lease.account_id.clone(),
        role_arn: lease.role_arn.clone(),
        role_name: lease.role_name.clone(),
        start_url: lease.start_url.clone(),
        region: lease.region.clone(),
        status: lease.status.clone(),
        credential_revision: lease.credential_revision.clone(),
        connected_at: lease.connected_at,
        expires_at: lease.expires_at,
        credentials_json,
    };
    if let Err(err) = pg.upsert_aws_role_lease(&row).await {
        tracing::warn!(error = %err, "failed persisting AWS role lease");
    }
}

async fn persist_role_binding(state: &AppState, binding: &operquay_aws::accounts::UserRoleBinding) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let payload_json = serde_json::to_string(binding).unwrap_or_else(|_| "{}".to_owned());
    let row = operquay_auth::pg::PgAwsRoleBindingRow {
        id: binding.id.clone(),
        tenant_id: binding.tenant_id.clone(),
        user_id: binding.user_id.clone(),
        role_arn: binding.role_arn.clone(),
        label: binding.label.clone(),
        payload_json,
    };
    if let Err(err) = pg.upsert_aws_role_binding(&row).await {
        tracing::warn!(error = %err, "failed persisting AWS role binding");
    }
}

async fn persist_user_prefs(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    prefs: &UserPreferences,
) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let prefs_json = serde_json::to_string(prefs).unwrap_or_else(|_| "{}".to_owned());
    let row = operquay_auth::pg::PgUserPrefsRow {
        tenant_id: tenant.to_owned(),
        user_id: user_id.to_owned(),
        prefs_json,
    };
    if let Err(err) = pg.upsert_user_preferences(&row).await {
        tracing::warn!(error = %err, "failed persisting user preferences");
    }
}

async fn persist_saved_inventory(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    items: &[serde_json::Value],
) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let items_json = serde_json::to_string(items).unwrap_or_else(|_| "[]".to_owned());
    let row = operquay_auth::pg::PgAwsSavedInventoryRow {
        tenant_id: tenant.to_owned(),
        user_id: user_id.to_owned(),
        items_json,
    };
    if let Err(err) = pg.upsert_aws_saved_inventory(&row).await {
        tracing::warn!(error = %err, "failed persisting AWS saved inventory");
    }
}

async fn persist_discovery_inventory(
    aws: &AwsHubState,
    pg: &operquay_auth::pg::PgAuthPool,
    tenant: &str,
) {
    let instances = aws.discovery.list_instances(tenant).await;
    let status = aws.discovery.get_status(tenant).await;
    let row = operquay_auth::pg::PgAwsDiscoveryRow {
        tenant_id: tenant.to_owned(),
        instances_json: serde_json::to_string(&instances).unwrap_or_else(|_| "[]".to_owned()),
        status_json: serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_owned()),
    };
    if let Err(err) = pg.upsert_aws_discovery_inventory(&row).await {
        tracing::warn!(tenant = %tenant, error = %err, "failed persisting EC2 discovery inventory");
    }
}

async fn persist_clone_op(state: &AppState, st: &operquay_aws::clone::CloneStatus) {
    let Some(pg) = state.pg_pool().await else {
        return;
    };
    let payload_json = serde_json::to_string(st).unwrap_or_else(|_| "{}".to_owned());
    let row = operquay_auth::pg::PgAwsCloneRow {
        id: st.id.clone(),
        tenant_id: st.tenant_id.clone(),
        user_id: st.owner_user_id.clone(),
        source_instance_id: st.source_instance_id.clone(),
        status: st.phase.clone(),
        payload_json,
    };
    if let Err(err) = pg.upsert_aws_clone_operation(&row).await {
        tracing::warn!(error = %err, "failed persisting clone operation");
    }
}
