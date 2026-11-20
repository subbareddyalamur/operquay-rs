-- Complete multi-tenant PostgreSQL schema preserving 100% compatibility with
-- original Go Operquay (deploy/postgres/001_tenant.sql + internal/auth/pg.go)
-- with strict Row-Level Security (app.tenant_id).

CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'lab',
    status TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    provider TEXT NOT NULL DEFAULT 'local',
    subject TEXT NOT NULL DEFAULT '',
    local_signin_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, email),
    UNIQUE (tenant_id, id)
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT 'local';
ALTER TABLE users ADD COLUMN IF NOT EXISTS subject TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS local_signin_enabled BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE IF NOT EXISTS auth_cluster_state (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    master_secret BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    session_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    user_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS sso_providers (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    provider_type TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    encrypted_config BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'local',
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    external_id TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT 0,
    updated_at BIGINT NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS groups_tenant_lower_name_unique ON groups (tenant_id, lower(name));

CREATE TABLE IF NOT EXISTS roles (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    base_role TEXT NOT NULL DEFAULT '',
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at BIGINT NOT NULL DEFAULT 0,
    updated_at BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS roles_tenant_lower_name_unique ON roles (tenant_id, lower(name));

CREATE TABLE IF NOT EXISTS group_memberships (
    tenant_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'manual',
    created_at BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, group_id, user_id)
);

CREATE TABLE IF NOT EXISTS group_role_bindings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    scope_type TEXT NOT NULL DEFAULT 'global',
    scope_id TEXT NOT NULL DEFAULT '',
    effect TEXT NOT NULL DEFAULT 'allow',
    conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS group_role_bindings_unique
    ON group_role_bindings (tenant_id, group_id, role_id, scope_type, lower(scope_id), effect);

CREATE TABLE IF NOT EXISTS idp_group_mappings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    provider_id TEXT NOT NULL,
    external_group TEXT NOT NULL,
    group_id TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scim_tokens (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT 0,
    last_used_at BIGINT NOT NULL DEFAULT 0,
    revoked_at BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS scim_tokens_hash_idx ON scim_tokens (token_hash);

CREATE TABLE IF NOT EXISTS aws_accounts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    aws_account_id TEXT NOT NULL,
    role_arn TEXT NOT NULL DEFAULT '',
    external_id TEXT NOT NULL DEFAULT '',
    alias TEXT NOT NULL DEFAULT '',
    encrypted_data BYTEA NOT NULL DEFAULT ''::bytea
);

CREATE TABLE IF NOT EXISTS aws_user_role_bindings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role_arn TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS aws_user_sso_providers (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    start_url TEXT NOT NULL,
    region TEXT NOT NULL DEFAULT 'us-east-1',
    created_at BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS aws_user_shell_sessions (
    session_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    region TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS aws_user_clone_operations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    source_instance_id TEXT NOT NULL,
    status TEXT NOT NULL,
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS preferences (
    user_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    document JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS user_preferences (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    encrypted_data BYTEA NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT,
    action TEXT NOT NULL,
    target TEXT,
    event JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS recording_policies (
    tenant_id TEXT PRIMARY KEY,
    policy JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS k8s_recording_policies (
    tenant_id TEXT PRIMARY KEY,
    policy JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS k8s_configured_clusters (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    encrypted_kubeconfig BYTEA NOT NULL DEFAULT ''::bytea,
    recording_required BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS suggest_buckets (
    bucket BYTEA PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS suggest_entries (
    bucket BYTEA NOT NULL REFERENCES suggest_buckets(bucket) ON DELETE CASCADE,
    key BYTEA NOT NULL,
    key_cipher BYTEA NOT NULL,
    value BYTEA NOT NULL,
    PRIMARY KEY (bucket, key)
);

CREATE TABLE IF NOT EXISTS suggest_key_check (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    verifier BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_shared_catalog (
    tenant_id TEXT PRIMARY KEY,
    catalog JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS license_cache (
    deployment_id TEXT PRIMARY KEY,
    entitlement JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'users', 'auth_sessions', 'sso_providers', 'groups', 'roles',
        'group_memberships', 'group_role_bindings', 'idp_group_mappings',
        'scim_tokens', 'aws_accounts', 'aws_user_role_bindings',
        'aws_user_sso_providers',
        'aws_user_shell_sessions', 'aws_user_clone_operations',
        'preferences', 'user_preferences', 'audit_events',
        'recording_policies', 'k8s_recording_policies',
        'k8s_configured_clusters', 'ai_shared_catalog'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_iso_%I ON %I', t, t);
        EXECUTE format(
            'CREATE POLICY tenant_iso_%I ON %I
                USING (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), ''''))
                WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), ''''))',
            t, t
        );
    END LOOP;
END $$;

