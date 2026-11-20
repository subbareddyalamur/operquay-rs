import { useState } from 'react';
import { Check, Copy, Plus } from 'lucide-react';
import { Badge, Button, Input, Select } from '@/components/primitives';
import { api } from '@/lib/api';
import { canSendCredentials } from '@/lib/credentialTransport';

const list = (value: string) => value.split(',').map((item) => item.trim()).filter(Boolean);

export function SAMLDetails({ entityID, acsURL, metadataURL, sloURL }: { entityID: string; acsURL: string; metadataURL: string; sloURL?: string }) {
  const [copiedLabel, setCopiedLabel] = useState<string | null>(null);
  const values = [
    ['Entity ID / Audience URI', entityID],
    ['ACS (reply) URL', acsURL],
    ['SP metadata URL', metadataURL],
    ...(sloURL ? [['SLO response URL', sloURL]] : []),
  ];
  const copy = (label: string, value: string) => {
    void navigator.clipboard?.writeText(value);
    setCopiedLabel(label);
    setTimeout(() => setCopiedLabel(cur => (cur === label ? null : cur)), 1500);
  };
  return (
    <div className="space-y-3 text-[12px]">
      <div className="text-text-mut">Use these Operquay values in your identity provider’s SAML application. Click a value to copy it. The Entity ID is also the Audience URI; it is an identifier, not a redirect URL.</div>
      <div className="rounded-md border border-border bg-bg/60 divide-y divide-border overflow-hidden">
        {values.map(([label, value]) => (
          <div key={label} className="grid grid-cols-1 sm:grid-cols-[175px_1fr] items-center gap-2 px-3 py-2">
            <span className="text-[12px] font-medium text-text-dim">{label}</span>
            <div className="flex items-center justify-between gap-2 min-w-0">
              <button
                type="button"
                aria-label={`Copy ${label}`}
                title="Copy"
                className="font-mono text-[12px] text-accent text-left break-all hover:underline focus-visible:outline-2 focus-visible:outline-accent"
                onClick={() => copy(label, value)}
              >
                {value}
              </button>
              <span className="shrink-0 text-text-dim flex items-center gap-1" aria-hidden="true">
                {copiedLabel === label ? (
                  <Badge variant="success" size="sm"><Check size={11} className="mr-0.5" />Copied</Badge>
                ) : (
                  <Copy size={12} />
                )}
              </span>
            </div>
          </div>
        ))}
      </div>
      <div className="rounded-md border border-border bg-bg/40 px-3.5 py-2.5 space-y-1 text-text-mut">
        <p>The IdP must POST the SAML response to the ACS URL, not the metadata URL. IdP-initiated sign-in starts a fresh Operquay request; it requires HTTPS and an IdP that supports SP-initiated SSO.</p>
        <p>NameID format: unspecified. Send an email attribute or an email-shaped NameID; Operquay requires an email address. Map optional email and username attributes at the IdP if needed; username is optional and is not stored by Operquay.</p>
        <p>SLO is optional and only handles responses to logout started in Operquay; IdP-initiated logout is not supported.</p>
      </div>
    </div>
  );
}

export interface EditableSSOProvider {
  id: string; label: string; type: 'oidc' | 'saml'; issuer?: string; client_id?: string;
  idp_entity_id?: string; idp_metadata_url?: string; domains?: string[]; viewer_groups?: string[]; admin_groups?: string[];
  operator_groups?: string[]; default_role?: string; require_email_verified?: boolean;
}

export function SSOProviderForm({ canManage, onAdded, samlBaseURL = '', editing, onCancel }: { canManage: boolean; onAdded: () => void; samlBaseURL?: string; editing?: EditableSSOProvider; onCancel?: () => void }) {
  const [open, setOpen] = useState(!!editing);
  const [type, setType] = useState<'oidc' | 'saml'>(editing?.type ?? 'oidc');
  const [id, setID] = useState(editing?.id ?? '');
  const [label, setLabel] = useState(editing?.label ?? '');
  const [issuer, setIssuer] = useState(editing?.issuer ?? '');
  const [metadata, setMetadata] = useState('');
  const [metadataXML, setMetadataXML] = useState('');
  const [entityID, setEntityID] = useState(editing?.idp_entity_id ?? '');
  const [clientID, setClientID] = useState(editing?.client_id ?? '');
  const [secret, setSecret] = useState('');
  const [requireVerified, setRequireVerified] = useState(editing?.require_email_verified ?? true);
  const [domains, setDomains] = useState(editing?.domains?.join(', ') ?? '');
  const [groups, setGroups] = useState(editing?.viewer_groups?.join(', ') ?? '');
  const [adminGroups, setAdminGroups] = useState(editing?.admin_groups?.join(', ') ?? '');
  const [operatorGroups, setOperatorGroups] = useState(editing?.operator_groups?.join(', ') ?? '');
  const [role, setRole] = useState(editing?.default_role ?? '');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const providerID = id.trim();
  const samlRoot = samlBaseURL && /^[a-z0-9][a-z0-9-]{0,31}$/.test(providerID) ? `${samlBaseURL.replace(/\/+$/, '')}/api/auth/saml/${providerID}` : '';

  const submit = async () => {
    setError('');
    if (!canSendCredentials('/api/auth/providers')) {
      setError('HTTPS is required to add an SSO provider. Open Operquay at its HTTPS address.');
      return;
    }
    if (!editing && type === 'saml' && !metadata.trim() && !metadataXML.trim()) {
      setError('Provide either a metadata URL or metadata XML.');
      return;
    }
    if (type === 'saml' && metadata.trim() && metadataXML.trim()) {
      setError('Provide only one metadata source: URL or XML.');
      return;
    }
    if (!role && list(groups).length === 0 && !list(adminGroups).length && !list(operatorGroups).length) {
      setError('Provide at least one allowed group, or explicitly allow other users.');
      return;
    }
    setBusy(true);
    const changes: Record<string, unknown> = {};
    if (editing) {
      if (label.trim() !== editing.label) changes.label = label.trim();
      if (issuer.trim() && issuer.trim() !== editing.issuer) changes.issuer = issuer.trim();
      if (clientID.trim() && clientID.trim() !== editing.client_id) changes.client_id = clientID.trim();
      if (secret) changes.client_secret = secret;
      if (metadata.trim()) changes.metadata_url = metadata.trim();
      if (metadataXML.trim()) changes.metadata_xml = metadataXML.trim();
      if (entityID.trim() !== (editing.idp_entity_id ?? '')) changes.entity_id = entityID.trim();
      if (domains !== (editing.domains?.join(', ') ?? '')) changes.allowed_domains = list(domains);
      if (groups !== (editing.viewer_groups?.join(', ') ?? '')) changes.viewer_groups = list(groups);
      if (adminGroups !== (editing.admin_groups?.join(', ') ?? '')) changes.admin_groups = list(adminGroups);
      if (operatorGroups !== (editing.operator_groups?.join(', ') ?? '')) changes.operator_groups = list(operatorGroups);
      if (role !== (editing.default_role ?? '')) changes.default_role = role;
      if (type === 'oidc' && requireVerified !== (editing.require_email_verified ?? true)) changes.require_email_verified = requireVerified;
    }
    if (editing && Object.keys(changes).length === 0) {
      setBusy(false);
      onCancel?.();
      return;
    }
    const result = editing ? await api.put<{ status: string }>(`/api/auth/providers/${encodeURIComponent(id)}`, changes) : await api.post<{ status: string }>('/api/auth/providers', {
      id: id.trim(), type, label: label.trim(),
      ...(type === 'oidc' ? { issuer: issuer.trim(), client_id: clientID.trim(), client_secret: secret, require_email_verified: requireVerified } : { metadata_url: metadata.trim(), metadata_xml: metadataXML.trim(), entity_id: entityID.trim() }),
      allowed_domains: list(domains), viewer_groups: list(groups), default_role: role,
    });
    setBusy(false);
    if (!result.ok) {
      let message = 'Could not save the provider.';
      try { message = (JSON.parse(result.error.message) as { error?: string }).error || message; } catch { /* network or non-JSON error */ }
      setError(message);
      return;
    }
    setSecret('');
    setOpen(false);
    onAdded();
  };

  return (
    <div className="space-y-3">
      {!open && (
        <Button type="button" variant="primary" size="sm" icon={<Plus size={14} />} disabled={!canManage} onClick={() => setOpen(true)}>
          Add SSO provider
        </Button>
      )}
      {!canManage && <p className="text-[12px] text-text-mut">PostgreSQL is required to manage providers here.</p>}
      {open && (
        <form
          className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs"
          onSubmit={(e) => { e.preventDefault(); void submit(); }}
        >
          <div className="px-5 py-3.5 border-b border-border bg-elev/40">
            <div className="text-[14px] font-semibold text-text-pri">{editing ? 'Edit SSO provider' : 'New SSO provider'}</div>
            <p className="text-[12px] text-text-mut mt-0.5">
              Fields marked * are required. Set PUBLIC_URL for SSO callbacks.
            </p>
            {editing && (
              <p className="text-[12px] text-text-mut mt-1">
                Provider ID and type cannot change. Leave replacement secret or metadata blank to keep the existing value. Updating interrupts sign-ins already in progress.
              </p>
            )}
          </div>
          <div className="px-5 py-4 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                <span>Provider type</span>
                <Select
                  disabled={!!editing}
                  value={type}
                  onChange={(e) => setType(e.target.value as 'oidc' | 'saml')}
                >
                  <option value="oidc">OIDC</option>
                  <option value="saml">SAML</option>
                </Select>
              </label>
              <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                <span>Provider ID <span aria-hidden="true">*</span></span>
                <Input required readOnly={!!editing} value={id} onChange={(e) => setID(e.target.value)} placeholder="work" />
              </label>
              <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                <span>Display name (optional)</span>
                <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Defaults to provider ID" />
              </label>
              {type === 'oidc' ? (
                <>
                  <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                    <span>Issuer URL <span aria-hidden="true">*</span></span>
                    <Input type="url" required={!editing} value={issuer} onChange={(e) => setIssuer(e.target.value)} placeholder={editing ? 'Leave blank to keep existing' : 'https://…'} />
                  </label>
                  <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                    <span>Client ID <span aria-hidden="true">*</span></span>
                    <Input required={!editing} value={clientID} onChange={(e) => setClientID(e.target.value)} />
                  </label>
                  <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                    <span>Client secret (if required by provider)</span>
                    <Input type="password" autoComplete="new-password" value={secret} onChange={(e) => setSecret(e.target.value)} placeholder={editing ? 'Leave blank to keep existing' : undefined} />
                  </label>
                  <label className="sm:col-span-2 flex items-center gap-2.5 text-[13px] text-text-pri cursor-pointer pt-1">
                    <input type="checkbox" className="accent-accent" checked={requireVerified} onChange={(e) => setRequireVerified(e.target.checked)} />
                    <span>Require verified email</span>
                  </label>
                </>
              ) : (
                <>
                  <div className="sm:col-span-2 rounded-lg border border-border bg-bg/40 p-4 space-y-2.5">
                    <div className="text-[13px] font-semibold text-text-pri">Operquay SAML application details</div>
                    {!samlBaseURL ? (
                      <p className="text-[12px] text-text-mut">Set PUBLIC_URL on the Operquay server to display SAML URLs.</p>
                    ) : !samlRoot ? (
                      <p className="text-[12px] text-text-mut">Enter a provider ID: 1–32 lowercase letters, digits or hyphens, starting with a letter or digit. The ID identifies this provider in Operquay.</p>
                    ) : (
                      <>
                        <SAMLDetails entityID={`${samlRoot}/metadata`} acsURL={`${samlRoot}/acs`} metadataURL={`${samlRoot}/metadata`} sloURL={`${samlRoot}/slo`} />
                        {!samlBaseURL.startsWith('https://') && (
                          <p className="text-[12px] text-warn">Use an HTTPS PUBLIC_URL; HTTP weakens SAML browser binding.</p>
                        )}
                        {!editing && (
                          <p className="text-[12px] text-text-mut">The SP metadata URL is available after this provider is saved. Use these values to create the IdP application, then provide its metadata below.</p>
                        )}
                      </>
                    )}
                  </div>
                  <div className="sm:col-span-2 space-y-2.5">
                    <p className="text-[12px] text-text-mut">
                      SAML metadata {editing ? ': leave blank to keep the existing source, or provide a replacement URL or XML.' : <><span aria-hidden="true">*</span>: provide either a metadata URL or metadata XML, not both.</>}
                    </p>
                    <p className="text-[12px] text-text-dim">Provide metadata from your identity provider, not Operquay's SP metadata.</p>
                    {editing?.idp_metadata_url && (
                      <p className="text-[12px] font-mono text-text-mut break-all">Current IdP metadata URL: {editing.idp_metadata_url}</p>
                    )}
                    <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                      <span>Metadata URL (optional if XML supplied)</span>
                      <Input type="url" value={metadata} onChange={(e) => setMetadata(e.target.value)} placeholder="https://…" />
                    </label>
                    <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                      <span>Metadata XML (optional if URL supplied)</span>
                      <textarea
                        className="w-full min-h-24 p-3 bg-bg border border-border rounded-md font-mono text-[12px] text-text-pri focus:outline-none focus:border-accent focus:ring-2 focus:ring-[var(--accent-dim)]"
                        value={metadataXML}
                        onChange={(e) => setMetadataXML(e.target.value)}
                      />
                    </label>
                  </div>
                  <label className="block space-y-1.5 text-[12px] font-medium text-text-mut sm:col-span-2">
                    <span>Identity provider entity ID (required if metadata contains multiple IdPs)</span>
                    <Input value={entityID} onChange={(e) => setEntityID(e.target.value)} />
                  </label>
                </>
              )}
              <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                <span>Allowed domains (optional)</span>
                <Input value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="example.com, …" />
              </label>
              {editing && (
                <>
                  <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                    <span>Admin admission groups</span>
                    <Input value={adminGroups} onChange={(e) => setAdminGroups(e.target.value)} placeholder="Comma-separated" />
                  </label>
                  <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                    <span>Operator admission groups</span>
                    <Input value={operatorGroups} onChange={(e) => setOperatorGroups(e.target.value)} placeholder="Comma-separated" />
                  </label>
                </>
              )}
              <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                <span>{editing ? 'Viewer admission groups' : 'Allowed groups'} {role ? '(optional)' : <span aria-hidden="true">*</span>}</span>
                <Input
                  aria-required={!role && !list(adminGroups).length && !list(operatorGroups).length}
                  aria-describedby="sso-groups-help"
                  value={groups}
                  onChange={(e) => setGroups(e.target.value)}
                  placeholder="Comma-separated"
                />
              </label>
              <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                <span>Other users</span>
                <Select value={role} onChange={(e) => setRole(e.target.value)}>
                  <option value="">Deny unless group matches</option>
                  <option value="readonly">Allow (new users start read-only)</option>
                  {role && role !== 'readonly' && <option value={role}>Existing policy: {role}</option>}
                </Select>
              </label>
            </div>
            <p id="sso-groups-help" className="text-[12px] text-text-dim leading-relaxed">
              Specify at least one group when denying other users. Groups control sign-in admission, not roles; new SSO users start read-only until an administrator changes their role. Leaving domains blank permits any domain trusted by the provider. Disabling email verification weakens identity checks.
            </p>
            {error && <p role="alert" className="text-[12px] text-danger font-medium">{error}</p>}
          </div>
          <div className="px-5 py-3 bg-bg/60 border-t border-border flex items-center justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => { setSecret(''); setOpen(false); onCancel?.(); }}
            >
              Cancel
            </Button>
            <Button type="submit" variant="primary" size="sm" loading={busy}>
              Save provider
            </Button>
          </div>
        </form>
      )}
    </div>
  );
}
