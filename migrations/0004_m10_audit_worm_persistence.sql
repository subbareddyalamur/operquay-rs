-- M10: Immutable Tamper-Evident Audit Log, Recording WORM Metadata,
-- Full AWS Persistence under PostgreSQL RLS, and Tenant Crypto-Shredding Keys.

ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS seq BIGINT NOT NULL DEFAULT 0;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS entry_hash TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS audit_events_tenant_seq_uniq
    ON audit_events (tenant_id, seq) WHERE seq > 0;

CREATE OR REPLACE FUNCTION prevent_audit_events_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is immutable and append-only (SOC 2 CC7.2 / ISO 27001 A.8.15)';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_no_update_delete ON audit_events;
CREATE TRIGGER audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_events_mutation();

CREATE TABLE IF NOT EXISTS recording_metadata (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    protocol TEXT NOT NULL,
    target_host TEXT NOT NULL DEFAULT '',
    format TEXT NOT NULL,
    started_at_ms BIGINT NOT NULL DEFAULT 0,
    bytes_written BIGINT NOT NULL DEFAULT 0,
    frame_count BIGINT NOT NULL DEFAULT 0,
    sha256_hex TEXT NOT NULL DEFAULT '',
    fail_closed BOOLEAN NOT NULL DEFAULT TRUE,
    status TEXT NOT NULL DEFAULT 'completed',
    encrypted BOOLEAN NOT NULL DEFAULT TRUE,
    legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
    legal_hold_reason TEXT NOT NULL DEFAULT '',
    retention_until_ms BIGINT,
    archived_s3_uri TEXT,
    archived_at_ms BIGINT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS aws_sso_sessions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    region TEXT NOT NULL,
    start_url TEXT NOT NULL,
    encrypted_token_state BYTEA NOT NULL,
    expires_at BIGINT NOT NULL,
    cancelled BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS aws_role_leases (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    binding_id TEXT NOT NULL,
    label TEXT NOT NULL,
    account_id TEXT NOT NULL,
    role_arn TEXT NOT NULL,
    role_name TEXT NOT NULL DEFAULT '',
    start_url TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL,
    status TEXT NOT NULL,
    credential_revision TEXT NOT NULL,
    connected_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    encrypted_credentials BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS aws_discovery_inventory (
    tenant_id TEXT PRIMARY KEY,
    instances JSONB NOT NULL DEFAULT '[]'::jsonb,
    status JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS aws_user_saved_inventory (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    items JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id)
);

ALTER TABLE aws_user_clone_operations ADD COLUMN IF NOT EXISTS payload JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE aws_user_clone_operations ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE aws_user_role_bindings ADD COLUMN IF NOT EXISTS payload JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE TABLE IF NOT EXISTS tenant_encryption_keys (
    tenant_id TEXT PRIMARY KEY,
    key_version INT NOT NULL DEFAULT 1,
    wrapped_dek BYTEA NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    shredded_at TIMESTAMPTZ
);

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'recording_metadata',
        'aws_sso_sessions',
        'aws_role_leases',
        'aws_discovery_inventory',
        'aws_user_saved_inventory',
        'tenant_encryption_keys'
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

REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM operquay_app;
GRANT SELECT, INSERT ON audit_events TO operquay_app;
