package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/operquay/terraform-provider-operquay/internal/client"
)

// AttributeSchema documents a single resource attribute for schema export & validation.
type AttributeSchema struct {
	Type        string `json:"type"`
	Required    bool   `json:"required,omitempty"`
	Computed    bool   `json:"computed,omitempty"`
	Sensitive   bool   `json:"sensitive,omitempty"`
	Description string `json:"description"`
}

// ResourceSchema documents a Terraform-managed Operquay resource type.
type ResourceSchema struct {
	Type        string                     `json:"type"`
	Endpoint    string                     `json:"endpoint"`
	Description string                     `json:"description"`
	Attributes  map[string]AttributeSchema `json:"attributes"`
}

// ResourceSpec represents one declarative resource block in a plan/apply manifest.
type ResourceSpec struct {
	Type       string         `json:"type"`
	Name       string         `json:"name"`
	ID         string         `json:"id,omitempty"`
	Attributes map[string]any `json:"attributes"`
}

// Manifest represents a declarative plan/apply bundle.
type Manifest struct {
	Resources []ResourceSpec `json:"resources"`
}

// PlanItem describes a pending declarative operation.
type PlanItem struct {
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
	Action       string `json:"action"`
	Endpoint     string `json:"endpoint"`
}

// ApplyResult captures applied resource state and returned IDs/secrets.
type ApplyResult struct {
	ResourceType string         `json:"resource_type"`
	ResourceName string         `json:"resource_name"`
	ID           string         `json:"id"`
	StatusCode   int            `json:"status_code"`
	State        map[string]any `json:"state"`
}

// Schemas returns the complete schema registry for all 7 Operquay provider resources.
func Schemas() map[string]ResourceSchema {
	return map[string]ResourceSchema{
		"operquay_role": {
			Type:        "operquay_role",
			Endpoint:    "/api/roles",
			Description: "Manages a custom RBAC role definition.",
			Attributes: map[string]AttributeSchema{
				"id":          {Type: "string", Computed: true, Description: "Server-assigned role ID."},
				"name":        {Type: "string", Required: true, Description: "Unique role display name."},
				"base_role":   {Type: "string", Required: true, Description: "Base tier (admin, user, readonly)."},
				"description": {Type: "string", Description: "Human-readable role summary."},
				"permissions": {Type: "list(string)", Required: true, Description: "Permission strings granted by role."},
			},
		},
		"operquay_recording_policy": {
			Type:        "operquay_recording_policy",
			Endpoint:    "/api/settings/recording-policy",
			Description: "Configures tenant session recording retention and capture mode.",
			Attributes: map[string]AttributeSchema{
				"mode":           {Type: "string", Required: true, Description: "Capture mode (none, all, selected)."},
				"retention_days": {Type: "number", Description: "Retention window in days."},
				"fail_closed":    {Type: "bool", Description: "Terminate sessions if recorder cannot write."},
			},
		},
		"operquay_dlp_policy": {
			Type:        "operquay_dlp_policy",
			Endpoint:    "/api/dlp/policy",
			Description: "Configures command firewall and inline DB PII/secret DLP masking.",
			Attributes: map[string]AttributeSchema{
				"mask_emails":  {Type: "bool", Description: "Mask email addresses in DB results."},
				"mask_ssn":     {Type: "bool", Description: "Mask SSN patterns."},
				"mask_secrets": {Type: "bool", Description: "Mask API keys, JWTs, PEM keys, and passwords."},
			},
		},
		"operquay_mcp_agent": {
			Type:        "operquay_mcp_agent",
			Endpoint:    "/api/mcp/agents",
			Description: "Issues sponsor-bound Model Context Protocol (MCP) AI agent identities.",
			Attributes: map[string]AttributeSchema{
				"id":                 {Type: "string", Computed: true, Description: "Agent ID."},
				"name":               {Type: "string", Required: true, Description: "Agent label."},
				"allowed_tools":      {Type: "list(string)", Description: "Permitted MCP tool names."},
				"require_jit_tools":  {Type: "list(string)", Description: "Tools gated by human JIT approval."},
				"rate_limit_per_min": {Type: "number", Description: "Max requests per minute."},
				"ttl_secs":           {Type: "number", Description: "Token TTL in seconds."},
				"token":              {Type: "string", Computed: true, Sensitive: true, Description: "One-time oqmcp_ bearer token."},
			},
		},
		"operquay_device_trust_policy": {
			Type:        "operquay_device_trust_policy",
			Endpoint:    "/api/device-trust/policy",
			Description: "Enforces hardware MDM/EDR posture before desktop ticket issuance.",
			Attributes: map[string]AttributeSchema{
				"enabled":                   {Type: "bool", Required: true, Description: "Enable device posture policy."},
				"enforce_on_desktop_launch": {Type: "bool", Description: "Gate /api/v1/sessions/launch."},
				"require_disk_encryption":   {Type: "bool", Description: "Require FileVault/BitLocker."},
				"require_edr_running":       {Type: "bool", Description: "Require EDR sensor active."},
				"max_os_patch_age_days":     {Type: "number", Description: "Max allowed OS patch staleness."},
				"allowed_providers":         {Type: "list(string)", Description: "Trusted MDM/EDR providers."},
			},
		},
		"operquay_cloud_connector": {
			Type:        "operquay_cloud_connector",
			Endpoint:    "/api/clouds/connectors",
			Description: "Configures an Azure (Entra) or GCP (Service Account) inventory connector.",
			Attributes: map[string]AttributeSchema{
				"id":                    {Type: "string", Computed: true, Description: "Connector ID."},
				"provider":              {Type: "string", Required: true, Description: "azure or gcp."},
				"name":                  {Type: "string", Required: true, Description: "Connector display name."},
				"account_or_project_id": {Type: "string", Required: true, Description: "Azure Subscription ID or GCP Project ID."},
				"tenant_or_org_id":      {Type: "string", Description: "Entra Tenant ID or GCP Org ID."},
				"region":                {Type: "string", Description: "Default cloud region."},
				"credentials":           {Type: "object", Sensitive: true, Description: "OAuth2 or SA credentials JSON."},
			},
		},
		"operquay_governance_webhook": {
			Type:        "operquay_governance_webhook",
			Endpoint:    "/api/governance/webhooks",
			Description: "Configures Slack/Teams/PagerDuty JIT governance webhooks.",
			Attributes: map[string]AttributeSchema{
				"id":       {Type: "string", Computed: true, Description: "Webhook ID."},
				"provider": {Type: "string", Required: true, Description: "slack, teams, pagerduty, or generic."},
				"name":     {Type: "string", Required: true, Description: "Webhook label."},
				"url":      {Type: "string", Required: true, Description: "Target HTTPS webhook URL."},
				"events":   {Type: "list(string)", Description: "Subscribed lifecycle event names."},
			},
		},
	}
}

// Plan computes the declarative action plan for every resource in the manifest.
func Plan(m Manifest) ([]PlanItem, error) {
	schemas := Schemas()
	plan := make([]PlanItem, 0, len(m.Resources))
	for _, res := range m.Resources {
		schema, ok := schemas[res.Type]
		if !ok {
			return nil, fmt.Errorf("unknown resource type %q", res.Type)
		}
		for attrName, attrDef := range schema.Attributes {
			if attrDef.Required {
				if _, exists := res.Attributes[attrName]; !exists {
					return nil, fmt.Errorf("%s.%s missing required attribute %q", res.Type, res.Name, attrName)
				}
			}
		}
		action := "create"
		if isSingletonPolicy(res.Type) {
			action = "update"
		} else if res.ID != "" {
			action = "update"
		}
		plan = append(plan, PlanItem{
			ResourceType: res.Type,
			ResourceName: res.Name,
			Action:       action,
			Endpoint:     schema.Endpoint,
		})
	}
	return plan, nil
}

// Apply executes create/update actions for all resources in the manifest against Operquay.
func Apply(ctx context.Context, cli *client.Client, m Manifest) ([]ApplyResult, error) {
	if _, err := Plan(m); err != nil {
		return nil, err
	}
	schemas := Schemas()
	results := make([]ApplyResult, 0, len(m.Resources))
	for _, res := range m.Resources {
		schema := schemas[res.Type]
		method := http.MethodPost
		path := schema.Endpoint
		if isSingletonPolicy(res.Type) {
			method = http.MethodPut
		} else if res.ID != "" && res.Type == "operquay_role" {
			method = http.MethodPut
			path = schema.Endpoint + "/" + res.ID
		}

		var body map[string]any
		status, raw, err := cli.DoJSON(ctx, method, path, res.Attributes, &body)
		if err != nil {
			return results, err
		}
		if body == nil {
			_ = json.Unmarshal(raw, &body)
		}
		id := extractResourceID(res.Type, res.ID, body)
		results = append(results, ApplyResult{
			ResourceType: res.Type,
			ResourceName: res.Name,
			ID:           id,
			StatusCode:   status,
			State:        body,
		})
	}
	return results, nil
}

// Destroy deletes resources with explicit IDs where supported by the API.
func Destroy(ctx context.Context, cli *client.Client, m Manifest) error {
	schemas := Schemas()
	for i := len(m.Resources) - 1; i >= 0; i-- {
		res := m.Resources[i]
		if res.ID == "" || isSingletonPolicy(res.Type) {
			continue
		}
		schema, ok := schemas[res.Type]
		if !ok {
			return fmt.Errorf("unknown resource type %q", res.Type)
		}
		if _, _, err := cli.DoJSON(ctx, http.MethodDelete, schema.Endpoint+"/"+res.ID, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func isSingletonPolicy(kind string) bool {
	return kind == "operquay_recording_policy" ||
		kind == "operquay_dlp_policy" ||
		kind == "operquay_device_trust_policy"
}

func extractResourceID(kind, existing string, body map[string]any) string {
	if existing != "" {
		return existing
	}
	if isSingletonPolicy(kind) {
		return "singleton"
	}
	if v, ok := body["id"].(string); ok && v != "" {
		return v
	}
	for _, nestedKey := range []string{"agent", "connector", "role", "webhook"} {
		if sub, ok := body[nestedKey].(map[string]any); ok {
			if id, idOK := sub["id"].(string); idOK && id != "" {
				return id
			}
		}
	}
	return ""
}
