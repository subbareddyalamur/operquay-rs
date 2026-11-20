package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config defines strict TLS connection and authentication settings for Operquay.
type Config struct {
	Endpoint   string
	CACertPath string
	Token      string
	Email      string
	Password   string
	TenantID   string
}

// Client communicates with the Operquay REST API using strict TLS verification.
type Client struct {
	baseURL  string
	tenantID string
	token    string
	cookie   string
	http     *http.Client
}

// NewClient constructs a strict TLS client. It never disables certificate verification.
func NewClient(cfg Config) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if base == "" {
		return nil, fmt.Errorf("operquay endpoint is required")
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("invalid endpoint URL %q", cfg.Endpoint)
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if strings.TrimSpace(cfg.CACertPath) != "" {
		pemBytes, readErr := os.ReadFile(cfg.CACertPath)
		if readErr != nil {
			return nil, fmt.Errorf("read ca_cert_path %q: %w", cfg.CACertPath, readErr)
		}
		pool, sysErr := x509.SystemCertPool()
		if sysErr != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("ca_cert_path %q did not contain valid PEM certificates", cfg.CACertPath)
		}
		tlsCfg.RootCAs = pool
	}

	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
	}
	tenant := strings.TrimSpace(cfg.TenantID)
	if tenant == "" {
		tenant = "default"
	}

	c := &Client{
		baseURL:  base,
		tenantID: tenant,
		token:    strings.TrimSpace(cfg.Token),
		http: &http.Client{
			Transport: tr,
			Timeout:   30 * time.Second,
		},
	}

	if c.token == "" && strings.TrimSpace(cfg.Email) != "" && cfg.Password != "" {
		if err := c.Login(context.Background(), cfg.Email, cfg.Password); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// Login authenticates via /api/auth/login and captures the session cookie.
func (c *Client) Login(ctx context.Context, email, password string) error {
	body := map[string]string{
		"email":    email,
		"password": password,
	}
	resp, raw, err := c.doRaw(ctx, http.MethodPost, "/api/auth/login", body)
	if err != nil {
		return fmt.Errorf("login request: %w", err)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("login failed (%d): %s", resp.StatusCode, string(raw))
	}
	for _, sc := range resp.Cookies() {
		if sc.Name == "operquay_session" || sc.Name == "__Host-operquay_session" {
			c.cookie = sc.Name + "=" + sc.Value
			return nil
		}
	}
	return fmt.Errorf("login succeeded without operquay session cookie")
}

// DoJSON issues a typed JSON REST call and decodes the response into out (if non-nil).
func (c *Client) DoJSON(ctx context.Context, method, path string, payload any, out any) (int, []byte, error) {
	resp, raw, err := c.doRaw(ctx, method, path, payload)
	if err != nil {
		return 0, nil, err
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, raw, fmt.Errorf("%s %s returned %d: %s", method, path, resp.StatusCode, string(raw))
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if decErr := json.Unmarshal(raw, out); decErr != nil {
			return resp.StatusCode, raw, fmt.Errorf("decode %s %s response: %w", method, path, decErr)
		}
	}
	return resp.StatusCode, raw, nil
}

func (c *Client) doRaw(ctx context.Context, method, path string, payload any) (*http.Response, []byte, error) {
	var reader io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", c.baseURL)
	if c.tenantID != "" {
		req.Header.Set("X-Operquay-Tenant", c.tenantID)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return resp, nil, readErr
	}
	return resp, raw, nil
}
