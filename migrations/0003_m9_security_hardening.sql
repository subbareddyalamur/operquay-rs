-- M9 Security Hardening: Fail-closed PostgreSQL FORCE ROW LEVEL SECURITY,
-- local password rotation / history, TOTP & WebAuthn MFA persistence, and non-BYPASSRLS role.

ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE remote_desktop_settings ADD COLUMN IF NOT EXISTS allow_legacy_crypto_over_ssm BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_history JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_totp_secret_enc BYTEA NOT NULL DEFAULT ''::bytea;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_recovery_hashes JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_webauthn_creds JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_last_totp_step BIGINT NOT NULL DEFAULT 0;

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'remote_desktop_settings', 'host_cert_pins', 'rdp_ephemeral_tickets',
        'users', 'auth_sessions', 'sso_providers', 'groups', 'roles',
        'group_memberships', 'group_role_bindings', 'idp_group_mappings',
        'scim_tokens', 'aws_accounts', 'aws_user_role_bindings',
        'aws_user_sso_providers', 'aws_user_shell_sessions',
        'aws_user_clone_operations', 'preferences', 'user_preferences',
        'audit_events', 'recording_policies', 'k8s_recording_policies',
        'k8s_configured_clusters', 'ai_shared_catalog'
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
        END IF;
    END LOOP;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'operquay_app') THEN
        CREATE ROLE operquay_app NOLOGIN NOBYPASSRLS;
    ELSE
        ALTER ROLE operquay_app NOBYPASSRLS;
    END IF;
END $$;

GRANT USAGE ON SCHEMA public TO operquay_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO operquay_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO operquay_app;
