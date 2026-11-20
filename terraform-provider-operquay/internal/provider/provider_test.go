package provider

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/operquay/terraform-provider-operquay/internal/client"
)

func TestSchemaCoverageAndApplyDestroyRoundtrip(t *testing.T) {
	schemas := Schemas()
	expected := []string{
		"operquay_role",
		"operquay_recording_policy",
		"operquay_dlp_policy",
		"operquay_mcp_agent",
		"operquay_device_trust_policy",
		"operquay_cloud_connector",
		"operquay_governance_webhook",
	}
	for _, name := range expected {
		if _, ok := schemas[name]; !ok {
			t.Fatalf("missing resource schema %q", name)
		}
	}

	var mu sync.Mutex
	calls := make([]string, 0)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/roles":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "role-tf-1"})
		case r.Method == http.MethodPut && r.URL.Path == "/api/settings/recording-policy":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"mode": "all"})
		case r.Method == http.MethodPut && r.URL.Path == "/api/dlp/policy":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"mask_ssn": true})
		case r.Method == http.MethodPost && r.URL.Path == "/api/mcp/agents":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent": map[string]any{"id": "mcp-tf-1"},
				"token": "oqmcp_demo",
			})
		case r.Method == http.MethodPut && r.URL.Path == "/api/device-trust/policy":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"enabled": true})
		case r.Method == http.MethodPost && r.URL.Path == "/api/clouds/connectors":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"connector": map[string]any{"id": "cld-tf-1"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/governance/webhooks":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "wh-tf-1"})
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"deleted":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, pemData, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	cli, err := client.NewClient(client.Config{Endpoint: srv.URL, CACertPath: caPath})
	if err != nil {
		t.Fatalf("client init: %v", err)
	}

	manifest := Manifest{
		Resources: []ResourceSpec{
			{Type: "operquay_role", Name: "r1", Attributes: map[string]any{"name": "ops", "base_role": "user", "permissions": []string{"instances:read"}}},
			{Type: "operquay_recording_policy", Name: "rec", Attributes: map[string]any{"mode": "all"}},
			{Type: "operquay_dlp_policy", Name: "dlp", Attributes: map[string]any{"mask_ssn": true}},
			{Type: "operquay_mcp_agent", Name: "ai", Attributes: map[string]any{"name": "claude"}},
			{Type: "operquay_device_trust_policy", Name: "dt", Attributes: map[string]any{"enabled": true}},
			{Type: "operquay_cloud_connector", Name: "az", Attributes: map[string]any{"provider": "azure", "name": "corp", "account_or_project_id": "sub-1"}},
			{Type: "operquay_governance_webhook", Name: "wh", Attributes: map[string]any{"provider": "slack", "name": "secops", "url": "https://hooks.example.com/1"}},
		},
	}

	applied, err := Apply(context.Background(), cli, manifest)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(applied) != 7 {
		t.Fatalf("expected 7 applied resources, got %d", len(applied))
	}
	for i := range applied {
		manifest.Resources[i].ID = applied[i].ID
	}
	if err := Destroy(context.Background(), cli, manifest); err != nil {
		t.Fatalf("destroy failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 11 { // 7 apply + 4 non-singleton destroy
		t.Fatalf("expected 11 HTTP calls, got %d: %v", len(calls), calls)
	}
}
