-- M11: Zero Standing Privileges (JIT Access Requests & ChatOps Webhooks),
-- Dual-Control Session Risk Bookmarks, Inline DLP/Command Firewall Policies,
-- and Quarterly Access Review Campaigns under fail-closed PostgreSQL RLS.

CREATE TABLE IF NOT EXISTS jit_access_requests (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    requester_user_id TEXT NOT NULL,
    requester_email TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    requested_role TEXT NOT NULL,
    duration_secs BIGINT NOT NULL,
    reason TEXT NOT NULL,
    ticket_id TEXT NOT NULL DEFAULT '',
    ticket_provider TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    approver_user_id TEXT,
    approver_email TEXT,
    decision_note TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    decided_at BIGINT,
    expires_at BIGINT,
    revoked_at BIGINT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS governance_webhooks (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    encrypted_secret BYTEA NOT NULL,
    events JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS dlp_firewall_policies (
    tenant_id TEXT PRIMARY KEY,
    policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS session_risk_bookmarks (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    recording_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    offset_secs DOUBLE PRECISION NOT NULL DEFAULT 0,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'heuristic',
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS session_risk_bookmarks_rec_idx
    ON session_risk_bookmarks (tenant_id, recording_id, offset_secs);

CREATE TABLE IF NOT EXISTS access_review_campaigns (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    title TEXT NOT NULL,
    quarter TEXT NOT NULL,
    status TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    completed_at BIGINT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'jit_access_requests',
        'governance_webhooks',
        'dlp_firewall_policies',
        'session_risk_bookmarks',
        'access_review_campaigns'
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
