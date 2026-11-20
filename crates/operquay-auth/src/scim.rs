use serde::{Deserialize, Serialize};

pub const SCIM_CONTENT_TYPE: &str = "application/scim+json; charset=utf-8";
pub const SCIM_SCHEMA_LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const SCIM_SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCIM_SCHEMA_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const SCIM_SCHEMA_SPC: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
pub const SCIM_SCHEMA_RES_TYPE: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
pub const SCIM_SCHEMA_META: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";
pub const SCIM_SCHEMA_ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimToken {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub prefix: String,
    pub created_by: String,
    pub created_at: i64,
    pub last_used_at: i64,
    pub revoked_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedScimToken {
    pub token: ScimToken,
    pub secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimEmail {
    pub value: String,
    #[serde(default)]
    pub primary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    #[serde(default)]
    pub formatted: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUserResource {
    #[serde(default = "default_user_schemas")]
    pub schemas: Vec<String>,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub external_id: String,
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub name: Option<ScimName>,
    #[serde(default)]
    pub emails: Vec<ScimEmail>,
    #[serde(default = "default_active")]
    pub active: bool,
}

fn default_user_schemas() -> Vec<String> {
    vec![SCIM_SCHEMA_USER.to_owned()]
}

const fn default_active() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimMemberRef {
    pub value: String,
    #[serde(default)]
    pub display: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroupResource {
    #[serde(default = "default_group_schemas")]
    pub schemas: Vec<String>,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub external_id: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub members: Vec<ScimMemberRef>,
}

fn default_group_schemas() -> Vec<String> {
    vec![SCIM_SCHEMA_GROUP.to_owned()]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimPatchRequest {
    #[serde(default)]
    pub operations: Vec<ScimPatchOperation>,
    #[serde(rename = "Operations", default)]
    pub operations_pascal: Vec<ScimPatchOperation>,
}

impl ScimPatchRequest {
    #[must_use]
    pub fn ops(&self) -> &[ScimPatchOperation] {
        if self.operations_pascal.is_empty() {
            &self.operations
        } else {
            &self.operations_pascal
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScimPatchOperation {
    pub op: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub value: serde_json::Value,
}

#[must_use]
pub fn scim_service_provider_config() -> serde_json::Value {
    serde_json::json!({
        "schemas": [SCIM_SCHEMA_SPC],
        "documentationUri": "https://operquay.io/docs/scim",
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Tenant SCIM 2.0 Bearer Token authentication"
        }]
    })
}

#[must_use]
pub fn scim_resource_types() -> serde_json::Value {
    serde_json::json!({
        "schemas": [SCIM_SCHEMA_LIST],
        "totalResults": 2,
        "Resources": [
            {
                "schemas": [SCIM_SCHEMA_RES_TYPE],
                "id": "User",
                "name": "User",
                "endpoint": "/scim/v2/Users",
                "schema": SCIM_SCHEMA_USER
            },
            {
                "schemas": [SCIM_SCHEMA_RES_TYPE],
                "id": "Group",
                "name": "Group",
                "endpoint": "/scim/v2/Groups",
                "schema": SCIM_SCHEMA_GROUP
            }
        ]
    })
}

#[must_use]
pub fn scim_schemas() -> serde_json::Value {
    serde_json::json!({
        "schemas": [SCIM_SCHEMA_LIST],
        "totalResults": 2,
        "Resources": [
            { "id": SCIM_SCHEMA_USER, "name": "User", "description": "SCIM 2.0 Core User", "schemas": [SCIM_SCHEMA_META] },
            { "id": SCIM_SCHEMA_GROUP, "name": "Group", "description": "SCIM 2.0 Core Group", "schemas": [SCIM_SCHEMA_META] }
        ]
    })
}
