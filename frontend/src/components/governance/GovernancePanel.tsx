import { useState, useEffect, useCallback, useRef } from 'react';
import {
  ShieldAlert, KeyRound, Eye, Pause, Play, Skull, Flame,
  Webhook, Trash2, RefreshCw, Plus, Check, X, Ban, Terminal,
} from 'lucide-react';
import { Badge, Button, Input, Select } from '@/components/primitives';
import { api } from '@/lib/api';
import { hasPermission, useAuthStore } from '@/stores/auth';
import { useToastStore } from '@/stores/toast';

type SubTab = 'jit' | 'moderation' | 'dlp' | 'webhooks';

export interface JitAccessRequest {
  id: string;
  tenant_id: string;
  requester_user_id: string;
  requester_email: string;
  target_type: 'aws_role' | 'ssh' | 'rdp' | 'k8s_exec' | 'db_write';
  target_id: string;
  requested_role: string;
  duration_secs: number;
  reason: string;
  ticket_id: string;
  ticket_provider: string;
  status: 'pending' | 'approved' | 'denied' | 'expired' | 'revoked';
  approver_email?: string | null;
  decision_note: string;
  created_at: number;
  decided_at?: number | null;
  expires_at?: number | null;
}

export interface LiveSessionInfo {
  session_id: string;
  tenant_id: string;
  protocol: string;
  target_host: string;
  owner_user_id: string;
  owner_email: string;
  started_at: number;
  recording_id?: string | null;
  frozen: boolean;
  frozen_by?: string | null;
  frozen_reason: string;
  observer_count: number;
  moderator_count: number;
}

export interface CommandFirewallRule {
  id: string;
  name: string;
  pattern: string;
  protocols: string[];
  action: 'allow' | 'warn' | 'pause_approval' | 'block';
  message: string;
  enabled: boolean;
}

export interface DbDlpPolicy {
  enabled: boolean;
  mask_emails: boolean;
  mask_ssn: boolean;
  mask_credit_cards: boolean;
  mask_phones: boolean;
  mask_secrets: boolean;
  sensitive_column_patterns: string[];
  unmasked_roles: string[];
}

export interface DlpFirewallPolicy {
  db_dlp: DbDlpPolicy;
  command_firewall_enabled: boolean;
  require_jit_for_db_write: boolean;
  require_jit_for_prod_shell: boolean;
  rules: CommandFirewallRule[];
}

export interface GovernanceWebhookPublic {
  id: string;
  provider: string;
  name: string;
  url: string;
  has_secret: boolean;
  events: string[];
  enabled: boolean;
  created_at: number;
}

export interface WebhookStats {
  enqueued: number;
  delivered: number;
  dropped: number;
  failed: number;
}

interface DryRunResult {
  verdict: {
    action: string;
    rule_id: string;
    rule_name: string;
    message: string;
    sanitized_command: string;
  };
  dlp_summary?: {
    masked_cells: number;
    masked_columns: string[];
  } | null;
  redacted_sample?: {
    columns: string[];
    rows: Record<string, unknown>[];
  } | null;
}

function statusVariant(status: string): 'default' | 'success' | 'danger' | 'warn' | 'info' {
  switch (status) {
    case 'approved':
      return 'success';
    case 'denied':
    case 'revoked':
      return 'danger';
    case 'pending':
      return 'warn';
    default:
      return 'default';
  }
}

export function GovernancePanel() {
  const me = useAuthStore((s) => s.me);
  const canModerate = hasPermission(me, 'sessions:moderate') || hasPermission(me, 'audit:read');
  const canManageDlp = hasPermission(me, 'dlp:manage') || hasPermission(me, 'audit:read');
  const canEditDlp = hasPermission(me, 'dlp:manage');
  const canManageWebhooks =
    hasPermission(me, 'dlp:manage') ||
    hasPermission(me, 'compliance:manage') ||
    hasPermission(me, 'access_requests:approve') ||
    hasPermission(me, 'audit:read');
  const pushToast = useToastStore((s) => s.push);

  const [subTab, setSubTab] = useState<SubTab>('jit');

  // JIT Access state
  const [requests, setRequests] = useState<JitAccessRequest[]>([]);
  const [canApprove, setCanApprove] = useState(false);
  const [targetType, setTargetType] = useState<JitAccessRequest['target_type']>('aws_role');
  const [targetId, setTargetId] = useState('');
  const [requestedRole, setRequestedRole] = useState('operator');
  const [durationSecs, setDurationSecs] = useState('1800');
  const [ticketProvider, setTicketProvider] = useState('jira');
  const [ticketId, setTicketId] = useState('');
  const [reason, setReason] = useState('');
  const [jitBusy, setJitBusy] = useState(false);

  // Live moderation & shadow WS state
  const [liveSessions, setLiveSessions] = useState<LiveSessionInfo[]>([]);
  const [shadowSessionId, setShadowSessionId] = useState<string | null>(null);
  const [shadowLines, setShadowLines] = useState<string[]>([]);
  const shadowWsRef = useRef<WebSocket | null>(null);

  // DLP & Command firewall state
  const [policy, setPolicy] = useState<DlpFirewallPolicy | null>(null);
  const [testProto, setTestProto] = useState('ssh');
  const [testCmd, setTestCmd] = useState('rm -rf /var/log');
  const [dryRun, setDryRun] = useState<DryRunResult | null>(null);
  const [newRuleName, setNewRuleName] = useState('');
  const [newRulePattern, setNewRulePattern] = useState('');
  const [newRuleAction, setNewRuleAction] = useState<CommandFirewallRule['action']>('block');

  // Webhooks state
  const [webhooks, setWebhooks] = useState<GovernanceWebhookPublic[]>([]);
  const [whStats, setWhStats] = useState<WebhookStats | null>(null);
  const [whProvider, setWhProvider] = useState('slack');
  const [whName, setWhName] = useState('');
  const [whUrl, setWhUrl] = useState('');
  const [whSecret, setWhSecret] = useState('');

  const loadJit = useCallback(async () => {
    const res = await api.get<{ items: JitAccessRequest[]; can_approve: boolean }>('/api/access-requests');
    if (res.ok) {
      setRequests(res.data.items);
      setCanApprove(res.data.can_approve);
    }
  }, []);

  const loadLiveSessions = useCallback(async () => {
    if (!canModerate) return;
    const res = await api.get<{ sessions: LiveSessionInfo[] }>('/api/sessions/live');
    if (res.ok) setLiveSessions(res.data.sessions);
  }, [canModerate]);

  const loadDlp = useCallback(async () => {
    if (!canManageDlp) return;
    const res = await api.get<DlpFirewallPolicy>('/api/governance/dlp-policy');
    if (res.ok) setPolicy(res.data);
  }, [canManageDlp]);

  const loadWebhooks = useCallback(async () => {
    if (!canManageWebhooks) return;
    const res = await api.get<{ webhooks: GovernanceWebhookPublic[]; stats: WebhookStats }>('/api/governance/webhooks');
    if (res.ok) {
      setWebhooks(res.data.webhooks);
      setWhStats(res.data.stats);
    }
  }, [canManageWebhooks]);

  useEffect(() => {
    if (subTab === 'jit') void loadJit();
    if (subTab === 'moderation') void loadLiveSessions();
    if (subTab === 'dlp') void loadDlp();
    if (subTab === 'webhooks') void loadWebhooks();
  }, [subTab, loadJit, loadLiveSessions, loadDlp, loadWebhooks]);

  useEffect(() => () => {
    shadowWsRef.current?.close();
    shadowWsRef.current = null;
  }, []);

  const handleCreateJit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetId.trim() || !reason.trim()) return;
    setJitBusy(true);
    const res = await api.post<JitAccessRequest>('/api/access-requests', {
      target_type: targetType,
      target_id: targetId.trim(),
      requested_role: requestedRole.trim() || 'operator',
      duration_secs: Number(durationSecs) || 1800,
      reason: reason.trim(),
      ticket_id: ticketId.trim(),
      ticket_provider: ticketProvider,
    });
    setJitBusy(false);
    if (!res.ok) {
      pushToast({ title: res.error.message, variant: 'danger' });
      return;
    }
    pushToast({ title: 'JIT access request submitted', variant: 'success' });
    setTargetId('');
    setTicketId('');
    setReason('');
    void loadJit();
  };

  const handleJitDecision = async (id: string, action: 'approve' | 'deny' | 'revoke') => {
    const res = await api.post(`/api/access-requests/${encodeURIComponent(id)}/${action}`, { note: `${action} from console` });
    if (!res.ok) {
      pushToast({ title: res.error.message, variant: 'danger' });
      return;
    }
    pushToast({ title: `Request ${action}d`, variant: 'success' });
    void loadJit();
  };

  const startShadow = (sessionId: string) => {
    shadowWsRef.current?.close();
    setShadowSessionId(sessionId);
    setShadowLines([`[connecting live shadow for ${sessionId}...]`]);
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const role = hasPermission(me, 'sessions:moderate') ? 'moderator' : 'observer';
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/sessions/${encodeURIComponent(sessionId)}/shadow?role=${role}`);
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(String(ev.data)) as { type: string; data?: string; message?: string; actor?: string; reason?: string; frozen?: boolean };
        if (msg.type === 'output' && msg.data) {
          setShadowLines((prev) => [...prev.slice(-199), msg.data ?? '']);
        } else if (msg.type === 'notice' && msg.message) {
          setShadowLines((prev) => [...prev.slice(-199), `[notice] ${msg.message}`]);
        } else if (msg.type === 'frozen_state') {
          setShadowLines((prev) => [...prev.slice(-199), `[${msg.frozen ? 'FROZEN' : 'RESUMED'} by ${msg.actor}: ${msg.reason ?? ''}]`]);
        } else if (msg.type === 'terminated') {
          setShadowLines((prev) => [...prev.slice(-199), `[TERMINATED by ${msg.actor}: ${msg.reason ?? ''}]`]);
        }
      } catch {
        // Ignore unparseable frames
      }
    };
    ws.onclose = () => {
      setShadowLines((prev) => [...prev.slice(-199), '[shadow stream closed]']);
    };
    shadowWsRef.current = ws;
  };

  const handleFreeze = async (sessionId: string, frozen: boolean) => {
    const res = await api.post(`/api/sessions/${encodeURIComponent(sessionId)}/freeze`, {
      frozen,
      reason: frozen ? 'Paused by security moderator' : 'Resumed by moderator',
    });
    if (!res.ok) {
      pushToast({ title: res.error.message, variant: 'danger' });
      return;
    }
    void loadLiveSessions();
  };

  const handleKill = async (sessionId: string) => {
    const res = await api.post(`/api/sessions/${encodeURIComponent(sessionId)}/kill`, {
      reason: 'Terminated by dual-control moderator',
    });
    if (!res.ok) {
      pushToast({ title: res.error.message, variant: 'danger' });
      return;
    }
    pushToast({ title: 'Live session terminated', variant: 'success' });
    void loadLiveSessions();
  };

  const handleSavePolicy = async (next: DlpFirewallPolicy) => {
    const res = await api.put<DlpFirewallPolicy>('/api/governance/dlp-policy', next);
    if (!res.ok) {
      pushToast({ title: res.error.message, variant: 'danger' });
      return;
    }
    setPolicy(res.data);
    pushToast({ title: 'DLP & firewall policy updated', variant: 'success' });
  };

  const handleDryRun = async () => {
    const res = await api.post<DryRunResult>('/api/governance/dlp-policy/test', {
      protocol: testProto,
      command: testCmd,
      sample_columns: ['id', 'email', 'ssn', 'secret_token'],
      sample_rows: [['42', 'ops@company.example', '123-45-6789', 'AKIAIOSFODNN7EXAMPLE']],
      policy: policy ?? undefined,
    });
    if (!res.ok) {
      pushToast({ title: res.error.message, variant: 'danger' });
      return;
    }
    setDryRun(res.data);
  };

  const handleAddRule = () => {
    if (!policy || !newRuleName.trim() || !newRulePattern.trim()) return;
    const next: DlpFirewallPolicy = {
      ...policy,
      rules: [
        ...policy.rules,
        {
          id: `custom-${Date.now()}`,
          name: newRuleName.trim(),
          pattern: newRulePattern.trim(),
          protocols: ['ssh', 'ssm', 'k8s'],
          action: newRuleAction,
          message: `Matched rule ${newRuleName.trim()}`,
          enabled: true,
        },
      ],
    };
    setNewRuleName('');
    setNewRulePattern('');
    void handleSavePolicy(next);
  };

  const handleAddWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!whUrl.trim()) return;
    const res = await api.post<GovernanceWebhookPublic>('/api/governance/webhooks', {
      provider: whProvider,
      name: whName.trim() || `${whProvider} webhook`,
      url: whUrl.trim(),
      secret: whSecret.trim(),
    });
    if (!res.ok) {
      pushToast({ title: res.error.message, variant: 'danger' });
      return;
    }
    pushToast({ title: 'Webhook configured', variant: 'success' });
    setWhName('');
    setWhUrl('');
    setWhSecret('');
    void loadWebhooks();
  };

  const handleDeleteWebhook = async (id: string) => {
    const res = await api.delete(`/api/governance/webhooks/${encodeURIComponent(id)}`);
    if (res.ok) void loadWebhooks();
  };

  const tabs: { id: SubTab; label: string; icon: React.ReactNode; visible: boolean }[] = [
    { id: 'jit', label: 'JIT Access', icon: <KeyRound size={14} />, visible: true },
    { id: 'moderation', label: 'Live Moderation', icon: <Eye size={14} />, visible: canModerate },
    { id: 'dlp', label: 'DLP & Firewall', icon: <Flame size={14} />, visible: canManageDlp },
    { id: 'webhooks', label: 'ChatOps Webhooks', icon: <Webhook size={14} />, visible: canManageWebhooks },
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2 border-b border-border pb-3">
        {tabs.filter((t) => t.visible).map((t) => (
          <Button
            key={t.id}
            size="sm"
            variant={subTab === t.id ? 'primary' : 'secondary'}
            icon={t.icon}
            onClick={() => setSubTab(t.id)}
          >
            {t.label}
          </Button>
        ))}
      </div>

      {subTab === 'jit' && (
        <div className="space-y-5">
          <form onSubmit={(e) => void handleCreateJit(e)} className="bg-surface border border-border rounded-lg p-4 space-y-3">
            <div className="flex items-center gap-2 text-sm font-semibold text-text-pri">
              <ShieldAlert size={15} className="text-accent" />
              Request Ephemeral Just-in-Time Access
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div>
                <label className="block text-[11px] font-medium text-text-dim mb-1">Target Type</label>
                <Select value={targetType} onChange={(e) => setTargetType(e.target.value as JitAccessRequest['target_type'])} aria-label="Target type">
                  <option value="aws_role">AWS IAM Role</option>
                  <option value="ssh">SSH / SSM Host</option>
                  <option value="rdp">RDP / VNC Desktop</option>
                  <option value="k8s_exec">Kubernetes Exec</option>
                  <option value="db_write">Database Write</option>
                </Select>
              </div>
              <div>
                <label className="block text-[11px] font-medium text-text-dim mb-1">Target Resource ID</label>
                <Input value={targetId} onChange={(e) => setTargetId(e.target.value)} placeholder="arn:aws:iam::... or conn-id" aria-label="Target resource ID" />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-text-dim mb-1">Role / Profile</label>
                <Input value={requestedRole} onChange={(e) => setRequestedRole(e.target.value)} placeholder="ProdAdmin" aria-label="Requested role" />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-text-dim mb-1">Lease Duration</label>
                <Select value={durationSecs} onChange={(e) => setDurationSecs(e.target.value)} aria-label="Lease duration">
                  <option value="900">15 minutes</option>
                  <option value="1800">30 minutes</option>
                  <option value="3600">1 hour</option>
                  <option value="14400">4 hours</option>
                </Select>
              </div>
              <div>
                <label className="block text-[11px] font-medium text-text-dim mb-1">Change Ticket System</label>
                <Select value={ticketProvider} onChange={(e) => setTicketProvider(e.target.value)} aria-label="Ticket provider">
                  <option value="jira">Jira</option>
                  <option value="servicenow">ServiceNow</option>
                  <option value="pagerduty">PagerDuty</option>
                  <option value="linear">Linear</option>
                </Select>
              </div>
              <div>
                <label className="block text-[11px] font-medium text-text-dim mb-1">Ticket Reference</label>
                <Input value={ticketId} onChange={(e) => setTicketId(e.target.value)} placeholder="INC-1042" aria-label="Ticket ID" />
              </div>
            </div>
            <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-end">
              <div className="flex-1">
                <label className="block text-[11px] font-medium text-text-dim mb-1">Justification</label>
                <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason for temporary elevation" aria-label="Justification" />
              </div>
              <Button type="submit" size="sm" loading={jitBusy} icon={<Plus size={14} />}>Submit Request</Button>
            </div>
          </form>

          <div className="bg-surface border border-border rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-border bg-elev">
              <span className="text-xs font-semibold text-text-pri">JIT Access Ledger ({requests.length})</span>
              <Button size="xs" variant="ghost" icon={<RefreshCw size={12} />} onClick={() => void loadJit()}>Refresh</Button>
            </div>
            <div className="divide-y divide-border">
              {requests.length === 0 ? (
                <div className="p-6 text-center text-xs text-text-dim">No JIT access requests recorded yet.</div>
              ) : (
                requests.map((r) => (
                  <div key={r.id} className="p-3.5 flex flex-wrap items-center justify-between gap-3">
                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge variant={statusVariant(r.status)}>{r.status.toUpperCase()}</Badge>
                        <span className="font-mono text-xs text-text-pri truncate">{r.target_type}: {r.target_id}</span>
                        {r.ticket_id && <Badge variant="info">{r.ticket_provider || 'ticket'}: {r.ticket_id}</Badge>}
                      </div>
                      <div className="text-[11px] text-text-dim">
                        Requester: <span className="text-text-sec">{r.requester_email}</span> · Role: <span className="text-text-sec">{r.requested_role}</span> ({Math.round(r.duration_secs / 60)}m) · {r.reason}
                      </div>
                    </div>
                    {canApprove && (
                      <div className="flex items-center gap-1.5">
                        {r.status === 'pending' && (
                          <>
                            <Button size="xs" variant="primary" icon={<Check size={12} />} onClick={() => void handleJitDecision(r.id, 'approve')}>Approve</Button>
                            <Button size="xs" variant="danger-ghost" icon={<X size={12} />} onClick={() => void handleJitDecision(r.id, 'deny')}>Deny</Button>
                          </>
                        )}
                        {r.status === 'approved' && (
                          <Button size="xs" variant="danger" icon={<Ban size={12} />} onClick={() => void handleJitDecision(r.id, 'revoke')}>Revoke</Button>
                        )}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {subTab === 'moderation' && canModerate && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="text-xs text-text-sec">Inspect active SSH/SSM, Kubernetes, and RDP/VNC sessions with instant freeze and termination fences.</div>
            <Button size="xs" variant="secondary" icon={<RefreshCw size={12} />} onClick={() => void loadLiveSessions()}>Refresh</Button>
          </div>
          <div className="bg-surface border border-border rounded-lg divide-y divide-border">
            {liveSessions.length === 0 ? (
              <div className="p-6 text-center text-xs text-text-dim">No active interactive sessions right now.</div>
            ) : (
              liveSessions.map((s) => (
                <div key={s.session_id} className="p-3.5 flex flex-wrap items-center justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <Badge variant={s.frozen ? 'warn' : 'success'}>{s.frozen ? 'FROZEN' : 'LIVE'}</Badge>
                      <Badge variant="info">{s.protocol.toUpperCase()}</Badge>
                      <span className="font-mono text-xs text-text-pri">{s.target_host}</span>
                    </div>
                    <div className="text-[11px] text-text-dim">
                      Owner: {s.owner_email} · Observers: {s.observer_count} · Moderators: {s.moderator_count}
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Button size="xs" variant="secondary" icon={<Eye size={12} />} onClick={() => startShadow(s.session_id)}>Shadow</Button>
                    {hasPermission(me, 'sessions:moderate') && (
                      <>
                        <Button
                          size="xs"
                          variant={s.frozen ? 'primary' : 'outline'}
                          icon={s.frozen ? <Play size={12} /> : <Pause size={12} />}
                          onClick={() => void handleFreeze(s.session_id, !s.frozen)}
                        >
                          {s.frozen ? 'Unfreeze' : 'Freeze'}
                        </Button>
                        <Button size="xs" variant="danger" icon={<Skull size={12} />} onClick={() => void handleKill(s.session_id)}>Force Kill</Button>
                      </>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
          {shadowSessionId && (
            <div className="bg-surface border border-border rounded-lg overflow-hidden">
              <div className="px-3 py-2 bg-elev border-b border-border flex items-center justify-between">
                <span className="text-xs font-mono text-text-pri flex items-center gap-1.5">
                  <Terminal size={13} /> Shadow Stream · {shadowSessionId}
                </span>
                <Button size="xs" variant="ghost" onClick={() => { shadowWsRef.current?.close(); setShadowSessionId(null); }}>Disconnect</Button>
              </div>
              <pre className="p-3 bg-bg text-text-pri font-mono text-[11px] max-h-60 overflow-auto whitespace-pre-wrap">
                {shadowLines.join('\n')}
              </pre>
            </div>
          )}
        </div>
      )}

      {subTab === 'dlp' && canManageDlp && policy && (
        <div className="space-y-4">
          <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
            <div className="text-sm font-semibold text-text-pri">Inline Database PII Masking & Zero-Trust Gates</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 text-xs">
              {(
                [
                  ['enabled', 'DB DLP Result Redaction', policy.db_dlp.enabled],
                  ['mask_emails', 'Mask Emails', policy.db_dlp.mask_emails],
                  ['mask_ssn', 'Mask US SSNs', policy.db_dlp.mask_ssn],
                  ['mask_credit_cards', 'Mask Luhn Credit Cards', policy.db_dlp.mask_credit_cards],
                  ['mask_phones', 'Mask Phone Numbers', policy.db_dlp.mask_phones],
                  ['mask_secrets', 'Mask AWS/JWT/PEM Secrets', policy.db_dlp.mask_secrets],
                ] as const
              ).map(([key, label, checked]) => (
                <label key={key} className="flex items-center gap-2 text-text-sec cursor-pointer">
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={!canEditDlp}
                    onChange={(e) => {
                      const next: DlpFirewallPolicy = {
                        ...policy,
                        db_dlp: { ...policy.db_dlp, [key]: e.target.checked },
                      };
                      void handleSavePolicy(next);
                    }}
                  />
                  <span>{label}</span>
                </label>
              ))}
              <label className="flex items-center gap-2 text-text-sec cursor-pointer">
                <input
                  type="checkbox"
                  checked={policy.command_firewall_enabled}
                  disabled={!canEditDlp}
                  onChange={(e) => void handleSavePolicy({ ...policy, command_firewall_enabled: e.target.checked })}
                />
                <span>Inline Shell/K8s Firewall</span>
              </label>
              <label className="flex items-center gap-2 text-text-sec cursor-pointer">
                <input
                  type="checkbox"
                  checked={policy.require_jit_for_db_write}
                  disabled={!canEditDlp}
                  onChange={(e) => void handleSavePolicy({ ...policy, require_jit_for_db_write: e.target.checked })}
                />
                <span>Require JIT for DB Mutations</span>
              </label>
            </div>
          </div>

          <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
            <div className="text-sm font-semibold text-text-pri">Firewall Rules ({policy.rules.length})</div>
            <div className="divide-y divide-border">
              {policy.rules.map((r) => (
                <div key={r.id} className="py-2 flex flex-wrap items-center justify-between gap-2 text-xs">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <Badge variant={r.action === 'block' ? 'danger' : r.action === 'pause_approval' ? 'warn' : 'info'}>{r.action}</Badge>
                      <span className="font-medium text-text-pri">{r.name}</span>
                    </div>
                    <div className="font-mono text-[11px] text-text-dim truncate max-w-xl">{r.pattern}</div>
                  </div>
                  {canEditDlp && (
                    <input
                      type="checkbox"
                      checked={r.enabled}
                      aria-label={`Toggle ${r.name}`}
                      onChange={(e) => {
                        const next = {
                          ...policy,
                          rules: policy.rules.map((item) => (item.id === r.id ? { ...item, enabled: e.target.checked } : item)),
                        };
                        void handleSavePolicy(next);
                      }}
                    />
                  )}
                </div>
              ))}
            </div>
            {canEditDlp && (
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-2 pt-2 border-t border-border">
                <Input value={newRuleName} onChange={(e) => setNewRuleName(e.target.value)} placeholder="Rule name" />
                <Input value={newRulePattern} onChange={(e) => setNewRulePattern(e.target.value)} placeholder="Regex pattern" />
                <Select value={newRuleAction} onChange={(e) => setNewRuleAction(e.target.value as CommandFirewallRule['action'])}>
                  <option value="block">block</option>
                  <option value="pause_approval">pause_approval</option>
                  <option value="warn">warn</option>
                </Select>
                <Button size="sm" onClick={handleAddRule} icon={<Plus size={13} />}>Add Rule</Button>
              </div>
            )}
          </div>

          <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
            <div className="text-sm font-semibold text-text-pri">Dry-Run Firewall & DB DLP Evaluator</div>
            <div className="flex flex-col sm:flex-row gap-2">
              <div className="w-full sm:w-32">
                <Select value={testProto} onChange={(e) => setTestProto(e.target.value)} aria-label="Test protocol">
                  <option value="ssh">ssh</option>
                  <option value="ssm">ssm</option>
                  <option value="k8s">k8s</option>
                </Select>
              </div>
              <div className="flex-1">
                <Input value={testCmd} onChange={(e) => setTestCmd(e.target.value)} placeholder="Command to simulate..." aria-label="Command to simulate" />
              </div>
              <Button size="sm" variant="secondary" onClick={() => void handleDryRun()}>Simulate Policy</Button>
            </div>
            {dryRun && (
              <div className="p-3 rounded bg-bg border border-border text-xs space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className="text-text-dim">Verdict:</span>
                  <Badge variant={dryRun.verdict.action === 'block' ? 'danger' : dryRun.verdict.action === 'pause_approval' ? 'warn' : 'success'}>
                    {dryRun.verdict.action}
                  </Badge>
                  <span className="text-text-pri">{dryRun.verdict.message || 'Command permitted'}</span>
                </div>
                {dryRun.dlp_summary && (
                  <div className="text-[11px] text-text-dim">
                    Sample DB DLP redacted {dryRun.dlp_summary.masked_cells} cells ({dryRun.dlp_summary.masked_columns.join(', ')})
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {subTab === 'webhooks' && canManageWebhooks && (
        <div className="space-y-4">
          {whStats && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {(
                [
                  ['Enqueued', whStats.enqueued],
                  ['Delivered', whStats.delivered],
                  ['Dropped', whStats.dropped],
                  ['Failed', whStats.failed],
                ] as const
              ).map(([label, val]) => (
                <div key={label} className="bg-surface border border-border rounded-lg p-3">
                  <div className="text-[11px] text-text-dim">{label}</div>
                  <div className="text-lg font-semibold text-text-pri">{val}</div>
                </div>
              ))}
            </div>
          )}

          <form onSubmit={(e) => void handleAddWebhook(e)} className="bg-surface border border-border rounded-lg p-4 grid grid-cols-1 sm:grid-cols-4 gap-3 items-end">
            <div>
              <label className="block text-[11px] font-medium text-text-dim mb-1">Provider</label>
              <Select value={whProvider} onChange={(e) => setWhProvider(e.target.value)} aria-label="Webhook provider">
                <option value="slack">Slack</option>
                <option value="teams">Microsoft Teams</option>
                <option value="pagerduty">PagerDuty</option>
                <option value="jira">Jira</option>
                <option value="servicenow">ServiceNow</option>
                <option value="generic">Generic HMAC</option>
              </Select>
            </div>
            <div>
              <label className="block text-[11px] font-medium text-text-dim mb-1">Name</label>
              <Input value={whName} onChange={(e) => setWhName(e.target.value)} placeholder="SecOps Approvals" aria-label="Webhook name" />
            </div>
            <div>
              <label className="block text-[11px] font-medium text-text-dim mb-1">Destination URL</label>
              <Input value={whUrl} onChange={(e) => setWhUrl(e.target.value)} placeholder="https://hooks.slack.com/..." aria-label="Webhook URL" />
            </div>
            <div className="flex gap-2 items-end">
              <div className="flex-1">
                <label className="block text-[11px] font-medium text-text-dim mb-1">HMAC Secret</label>
                <Input type="password" value={whSecret} onChange={(e) => setWhSecret(e.target.value)} placeholder="signing secret" aria-label="Webhook secret" />
              </div>
              <Button type="submit" size="sm" icon={<Plus size={14} />}>Add</Button>
            </div>
          </form>

          <div className="bg-surface border border-border rounded-lg divide-y divide-border">
            {webhooks.length === 0 ? (
              <div className="p-6 text-center text-xs text-text-dim">No ChatOps or break-glass webhooks configured.</div>
            ) : (
              webhooks.map((w) => (
                <div key={w.id} className="p-3 flex items-center justify-between gap-3 text-xs">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <Badge variant="info">{w.provider.toUpperCase()}</Badge>
                      <span className="font-medium text-text-pri">{w.name}</span>
                      {w.has_secret && <Badge variant="success">HMAC Signed</Badge>}
                    </div>
                    <div className="font-mono text-[11px] text-text-dim truncate max-w-xl">{w.url}</div>
                  </div>
                  <Button size="xs" variant="danger-ghost" icon={<Trash2 size={12} />} onClick={() => void handleDeleteWebhook(w.id)} aria-label={`Delete ${w.name}`} />
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
