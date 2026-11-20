-- M12: MCP/AI Agent Governance Proxy (ISO 42001), Zero-Inbound Hybrid Reverse-Tunnel
-- Agents, Multi-Cloud (Azure/GCP) Connectors, and Device Trust Attestations under
-- fail-closed PostgreSQL Row Level Security.

CREATE TABLE IF NOT EXISTS mcp_agents (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    sponsor_user_id TEXT NOT NULL,
    sponsor_email TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    allowed_tools JSONB NOT NULL DEFAULT '[]'::jsonb,
    require_jit_tools JSONB NOT NULL DEFAULT '[]'::jsonb,
    rate_limit_per_min INT NOT NULL DEFAULT 60,
    status TEXT NOT NULL DEFAULT 'active',
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    revoked_at BIGINT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS mcp_agents_tenant_hash_idx
    ON mcp_agents (tenant_id, token_hash);

CREATE TABLE IF NOT EXISTS mcp_tool_invocations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    sponsor_user_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    sanitized_args TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL,
    jit_request_id TEXT,
    masked_result_preview TEXT NOT NULL DEFAULT '',
    duration_ms BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS mcp_tool_invocations_tenant_created_idx
    ON mcp_tool_invocations (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS hybrid_agents (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    enrollment_token_hash TEXT NOT NULL,
    cert_fingerprint_sha256 TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    arch TEXT NOT NULL DEFAULT '',
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    targets JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'pending',
    last_heartbeat_at BIGINT,
    created_at BIGINT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS cloud_connectors (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    name TEXT NOT NULL,
    account_or_project_id TEXT NOT NULL,
    tenant_or_org_id TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL DEFAULT '',
    encrypted_credentials BYTEA NOT NULL,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'configured',
    last_synced_at BIGINT,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_trust_policies (
    tenant_id TEXT PRIMARY KEY,
    policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS device_posture_attestations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    os_version TEXT NOT NULL DEFAULT '',
    disk_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    edr_running BOOLEAN NOT NULL DEFAULT FALSE,
    edr_agent TEXT NOT NULL DEFAULT '',
    os_patch_age_days INT NOT NULL DEFAULT 0,
    compliant BOOLEAN NOT NULL DEFAULT FALSE,
    reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    attested_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS device_posture_user_idx
    ON device_posture_attestations (tenant_id, user_id, attested_at DESC);

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'mcp_agents',
        'mcp_tool_invocations',
        'hybrid_agents',
        'cloud_connectors',
        'device_trust_policies',
        'device_posture_attestations'
    ]
    LOOP
        IF to_regclass(format('public.%I', t)) IS NOT NULL THEN
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
            EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
            EXECUTE format('DROP POLICY IF EXISTS tenant_iso_%I ON %I', t, t);
            EXECUTE format(
                'CREATE POLICY tenant_iso_%I ON %I
                    USING (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), ''''))
                    WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), ''''))',
                t, t
            );
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO operquay_app', t);
        END IF;
    END LOOP;
END $$;
