-- Multi-tenant Remote Desktop settings, TOFU host pins, and audit events
-- Preserves Operquay PostgreSQL Row-Level Security (app.tenant_id) contract.

CREATE TABLE IF NOT EXISTS remote_desktop_settings (
    tenant_id TEXT NOT NULL,
    scope_key TEXT NOT NULL DEFAULT 'default',
    network_preset TEXT NOT NULL DEFAULT 'auto_adaptive',
    protocol_preference TEXT NOT NULL DEFAULT 'auto',
    transport_mode TEXT NOT NULL DEFAULT 'oqr2_binary',
    codec_mode TEXT NOT NULL DEFAULT 'adaptive_hybrid',
    target_fps INTEGER NOT NULL DEFAULT 30 CHECK (target_fps BETWEEN 10 AND 60),
    jpeg_quality_floor INTEGER NOT NULL DEFAULT 55 CHECK (jpeg_quality_floor BETWEEN 20 AND 95),
    enable_copy_rect BOOLEAN NOT NULL DEFAULT TRUE,
    enable_dynamic_resize BOOLEAN NOT NULL DEFAULT TRUE,
    enable_local_cursor_prediction BOOLEAN NOT NULL DEFAULT TRUE,
    enable_mouse_coalescing BOOLEAN NOT NULL DEFAULT TRUE,
    keyboard_layout TEXT NOT NULL DEFAULT 'en-us-qwerty',
    unicode_fallback BOOLEAN NOT NULL DEFAULT TRUE,
    rdp_security_mode TEXT NOT NULL DEFAULT 'any',
    vnc_security_mode TEXT NOT NULL DEFAULT 'auto',
    cert_policy TEXT NOT NULL DEFAULT 'tofu_pinned',
    clipboard_normalization TEXT NOT NULL DEFAULT 'preserve',
    fail_closed_recording BOOLEAN NOT NULL DEFAULT TRUE,
    enable_drive_redirection BOOLEAN NOT NULL DEFAULT FALSE,
    otel_sample_ratio DOUBLE PRECISION NOT NULL DEFAULT 1.0 CHECK (otel_sample_ratio BETWEEN 0.0 AND 1.0),
    show_live_telemetry_hud BOOLEAN NOT NULL DEFAULT TRUE,
    allow_legacy_crypto_over_ssm BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by TEXT NOT NULL DEFAULT 'system',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, scope_key)
);

CREATE TABLE IF NOT EXISTS host_cert_pins (
    tenant_id TEXT NOT NULL,
    target_key TEXT NOT NULL,
    protocol TEXT NOT NULL,
    sha256_fingerprint TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_by TEXT NOT NULL,
    PRIMARY KEY (tenant_id, target_key, protocol)
);

CREATE TABLE IF NOT EXISTS rdp_ephemeral_tickets (
    ticket_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('rdp', 'vnc')),
    target_host TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    payload_encrypted BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

ALTER TABLE remote_desktop_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE remote_desktop_settings FORCE ROW LEVEL SECURITY;
ALTER TABLE host_cert_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE host_cert_pins FORCE ROW LEVEL SECURITY;
ALTER TABLE rdp_ephemeral_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE rdp_ephemeral_tickets FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    DROP POLICY IF EXISTS tenant_iso_remote_desktop_settings ON remote_desktop_settings;
    CREATE POLICY tenant_iso_remote_desktop_settings ON remote_desktop_settings
        USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
        WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

    DROP POLICY IF EXISTS tenant_iso_host_cert_pins ON host_cert_pins;
    CREATE POLICY tenant_iso_host_cert_pins ON host_cert_pins
        USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
        WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

    DROP POLICY IF EXISTS tenant_iso_rdp_ephemeral_tickets ON rdp_ephemeral_tickets;
    CREATE POLICY tenant_iso_rdp_ephemeral_tickets ON rdp_ephemeral_tickets
        USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
        WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));
END $$;

