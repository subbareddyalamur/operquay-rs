package client

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestStrictTLSLoginAndCRUD(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/auth/login":
			if r.Header.Get("Origin") == "" {
				t.Fatalf("expected Origin header on login")
			}
			http.SetCookie(w, &http.Cookie{Name: "operquay_session", Value: "tok-123"})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/roles":
			if r.Header.Get("Cookie") != "operquay_session=tok-123" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "role-1", "name": "ci-ops"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	cert := srv.Certificate()
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(caPath, pemData, 0o600); err != nil {
		t.Fatalf("write temp CA cert: %v", err)
	}

	// Without ca_cert_path, self-signed TLS server must fail strict verification.
	if _, err := NewClient(Config{Endpoint: srv.URL}); err == nil {
		// Note: NewClient itself succeeds until HTTP call when no login happens.
	} else {
		t.Fatalf("unexpected error constructing client: %v", err)
	}

	untrusted, _ := NewClient(Config{Endpoint: srv.URL})
	if err := untrusted.Login(context.Background(), "admin@local", "Pass#123"); err == nil {
		t.Fatalf("expected untrusted TLS server without CA cert to fail verification")
	}

	cli, err := NewClient(Config{
		Endpoint:   srv.URL,
		CACertPath: caPath,
		Email:      "admin@local",
		Password:   "Pass#123",
	})
	if err != nil {
		t.Fatalf("strict client init failed: %v", err)
	}

	var out map[string]any
	status, _, err := cli.DoJSON(context.Background(), http.MethodPost, "/api/roles", map[string]any{
		"name": "ci-ops",
	}, &out)
	if err != nil || status != http.StatusCreated || out["id"] != "role-1" {
		t.Fatalf("expected role creation 201, got status=%d out=%v err=%v", status, out, err)
	}
}
