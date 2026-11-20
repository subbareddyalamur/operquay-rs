import { useState, useEffect, useCallback } from 'react';
import {
  FileCheck2, ShieldCheck, Download, CheckCircle2, XCircle,
  RefreshCw, ClipboardList, Plus, Ban,
} from 'lucide-react';
import { Badge, Button, Input } from '@/components/primitives';
import { api } from '@/lib/api';
import { hasPermission, useAuthStore } from '@/stores/auth';
import { useToastStore } from '@/stores/toast';

export interface ComplianceControlStatus {
  control_id: string;
  framework: string;
  title: string;
  status: 'passing' | 'attention' | 'failing' | string;
  evidence: string;
}

export interface CompliancePostureReport {
  tenant_id: string;
  generated_at: number;
  compliance_mode: boolean;
  audit_chain_valid: boolean;
  audit_source: string;
  audit_checked_events: number;
  total_recordings: number;
  encrypted_recordings: number;
  legal_hold_recordings: number;
  jit_pending_requests: number;
  jit_active_grants: number;
  dlp_firewall_enabled: boolean;
  webhooks_configured: number;
  controls: ComplianceControlStatus[];
}

export interface AccessReviewItem {
  item_id: string;
  principal_id: string;
  principal_email: string;
  role: string;
  target_summary: string;
  mfa_enabled: boolean;
  decision: 'pending' | 'certified' | 'revoked';
  reviewer_email?: string | null;
  note: string;
}

export interface AccessReviewCampaign {
  id: string;
  title: string;
  quarter: string;
  status: 'active' | 'completed';
  created_by: string;
  created_at: number;
  items: AccessReviewItem[];
}

export interface SignedEvidenceBundle {
  bundle: Record<string, unknown>;
  integrity: {
    algorithm: string;
    public_key_b64: string;
    payload_sha256: string;
    signature_b64: string;
    signed_at: number;
  };
}

interface VerifyBundleResult {
  valid: boolean;
  error?: string | null;
  algorithm: string;
  payload_sha256: string;
}

export function CompliancePortal() {
  const me = useAuthStore((s) => s.me);
  const canManage = hasPermission(me, 'compliance:manage');
  const pushToast = useToastStore((s) => s.push);

  const [posture, setPosture] = useState<CompliancePostureReport | null>(null);
  const [campaigns, setCampaigns] = useState<AccessReviewCampaign[]>([]);
  const [title, setTitle] = useState('');
  const [quarter, setQuarter] = useState('2026-Q4');
  const [bundle, setBundle] = useState<SignedEvidenceBundle | null>(null);
  const [verifyRes, setVerifyRes] = useState<VerifyBundleResult | null>(null);
  const [exporting, setExporting] = useState(false);

  const loadAll = useCallback(async () => {
    const [pRes, cRes] = await Promise.all([
      api.get<CompliancePostureReport>('/api/compliance/posture'),
      api.get<{ campaigns: AccessReviewCampaign[] }>('/api/compliance/access-reviews'),
    ]);
    if (pRes.ok) setPosture(pRes.data);
    if (cRes.ok) setCampaigns(cRes.data.campaigns);
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const handleCreateCampaign = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await api.post<AccessReviewCampaign>('/api/compliance/access-reviews', {
      title: title.trim() || `Quarterly Access Review (${quarter})`,
      quarter: quarter.trim() || 'Current',
    });
    if (!res.ok) {
      pushToast({ title: res.error.message, variant: 'danger' });
      return;
    }
    pushToast({ title: 'Access review campaign created', variant: 'success' });
    setTitle('');
    void loadAll();
  };

  const handleDecide = async (campaignId: string, itemId: string, decision: 'certified' | 'revoked') => {
    const res = await api.post<AccessReviewCampaign>(
      `/api/compliance/access-reviews/${encodeURIComponent(campaignId)}/items/${encodeURIComponent(itemId)}`,
      {
        decision,
        note: decision === 'certified' ? 'Access recertified' : 'Revoked during quarterly review',
        disable_user: decision === 'revoked',
      },
    );
    if (!res.ok) {
      pushToast({ title: res.error.message, variant: 'danger' });
      return;
    }
    void loadAll();
  };

  const handleExportEvidence = async () => {
    setExporting(true);
    setVerifyRes(null);
    const res = await api.post<SignedEvidenceBundle>('/api/compliance/evidence-bundle', {});
    setExporting(false);
    if (!res.ok) {
      pushToast({ title: res.error.message, variant: 'danger' });
      return;
    }
    setBundle(res.data);
    try {
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `operquay-evidence-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      // Headless DOM test environments ignore download click failures
    }
    pushToast({ title: 'Signed Ed25519 evidence bundle exported', variant: 'success' });
  };

  const handleVerifyBundle = async () => {
    if (!bundle) return;
    const res = await api.post<VerifyBundleResult>('/api/compliance/evidence-bundle/verify', bundle);
    if (!res.ok) {
      pushToast({ title: res.error.message, variant: 'danger' });
      return;
    }
    setVerifyRes(res.data);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-xs text-text-sec">
          Real-time SOC 2 Type II & ISO/IEC 27001 control attestation, quarterly access recertification, and Ed25519 signed evidence.
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="secondary" icon={<RefreshCw size={13} />} onClick={() => void loadAll()}>Refresh</Button>
          <Button size="sm" loading={exporting} icon={<Download size={14} />} onClick={() => void handleExportEvidence()}>
            Export Signed Evidence
          </Button>
        </div>
      </div>

      {posture && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-surface border border-border rounded-lg p-3">
              <div className="text-[11px] text-text-dim">Audit Hash Chain</div>
              <div className="mt-1 flex items-center gap-1.5 text-sm font-semibold text-text-pri">
                <Badge variant={posture.audit_chain_valid ? 'success' : 'danger'}>
                  {posture.audit_chain_valid ? 'VALID' : 'BROKEN'}
                </Badge>
                <span className="text-xs text-text-dim">({posture.audit_checked_events} events)</span>
              </div>
            </div>
            <div className="bg-surface border border-border rounded-lg p-3">
              <div className="text-[11px] text-text-dim">Encrypted Recordings</div>
              <div className="mt-1 text-lg font-semibold text-text-pri">
                {posture.encrypted_recordings} / {posture.total_recordings}
              </div>
            </div>
            <div className="bg-surface border border-border rounded-lg p-3">
              <div className="text-[11px] text-text-dim">Active JIT Leases</div>
              <div className="mt-1 text-lg font-semibold text-text-pri">
                {posture.jit_active_grants} <span className="text-xs font-normal text-text-dim">({posture.jit_pending_requests} pending)</span>
              </div>
            </div>
            <div className="bg-surface border border-border rounded-lg p-3">
              <div className="text-[11px] text-text-dim">DLP & Command Firewall</div>
              <div className="mt-1">
                <Badge variant={posture.dlp_firewall_enabled ? 'success' : 'warn'}>
                  {posture.dlp_firewall_enabled ? 'ENFORCED' : 'PARTIAL'}
                </Badge>
              </div>
            </div>
          </div>

          <div className="bg-surface border border-border rounded-lg overflow-hidden">
            <div className="px-4 py-2.5 bg-elev border-b border-border text-xs font-semibold text-text-pri flex items-center gap-2">
              <ShieldCheck size={14} className="text-accent" />
              SOC 2 Type II & ISO 27001 Controls ({posture.controls.length})
            </div>
            <div className="divide-y divide-border">
              {posture.controls.map((c) => (
                <div key={c.control_id} className="px-4 py-3 flex flex-wrap items-center justify-between gap-3 text-xs">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-semibold text-accent">{c.control_id}</span>
                      <span className="text-[11px] text-text-dim">{c.framework}</span>
                      <span className="font-medium text-text-pri">{c.title}</span>
                    </div>
                    <div className="text-[11px] text-text-dim mt-0.5">{c.evidence}</div>
                  </div>
                  <Badge variant={c.status === 'passing' ? 'success' : c.status === 'failing' ? 'danger' : 'warn'}>
                    {c.status.toUpperCase()}
                  </Badge>
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {bundle && (
        <div className="bg-surface border border-border rounded-lg p-4 space-y-2 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="font-semibold text-text-pri flex items-center gap-1.5">
              <FileCheck2 size={14} className="text-accent" />
              Evidence Integrity Metadata ({bundle.integrity.algorithm})
            </div>
            <Button size="xs" variant="secondary" onClick={() => void handleVerifyBundle()}>Verify Signature</Button>
          </div>
          <div className="font-mono text-[11px] text-text-dim break-all">
            SHA-256: {bundle.integrity.payload_sha256}
          </div>
          {verifyRes && (
            <div className="flex items-center gap-2 pt-1">
              {verifyRes.valid ? (
                <CheckCircle2 size={14} className="text-success" />
              ) : (
                <XCircle size={14} className="text-danger" />
              )}
              <span className={verifyRes.valid ? 'text-success font-medium' : 'text-danger font-medium'}>
                {verifyRes.valid ? 'Ed25519 signature verified cleanly' : verifyRes.error ?? 'Signature verification failed'}
              </span>
            </div>
          )}
        </div>
      )}

      <div className="bg-surface border border-border rounded-lg p-4 space-y-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-text-pri">
          <ClipboardList size={15} className="text-accent" />
          Quarterly Access Review Campaigns (SOC 2 CC6.3)
        </div>

        {canManage && (
          <form onSubmit={(e) => void handleCreateCampaign(e)} className="flex flex-col sm:flex-row gap-2 items-end">
            <div className="flex-1">
              <label className="block text-[11px] text-text-dim mb-1">Campaign Title</label>
              <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Q4 Privileged Operator Review" aria-label="Campaign title" />
            </div>
            <div className="w-full sm:w-36">
              <label className="block text-[11px] text-text-dim mb-1">Quarter</label>
              <Input value={quarter} onChange={(e) => setQuarter(e.target.value)} placeholder="2026-Q4" aria-label="Review quarter" />
            </div>
            <Button type="submit" size="sm" icon={<Plus size={14} />}>Start Campaign</Button>
          </form>
        )}

        <div className="space-y-3">
          {campaigns.length === 0 ? (
            <div className="text-xs text-text-dim py-3 text-center">No access review campaigns created yet.</div>
          ) : (
            campaigns.map((camp) => (
              <div key={camp.id} className="border border-border rounded-lg overflow-hidden">
                <div className="px-3.5 py-2.5 bg-elev border-b border-border flex items-center justify-between gap-2 text-xs">
                  <div className="flex items-center gap-2">
                    <Badge variant={camp.status === 'completed' ? 'success' : 'info'}>{camp.status.toUpperCase()}</Badge>
                    <span className="font-semibold text-text-pri">{camp.title}</span>
                    <span className="text-text-dim">({camp.quarter})</span>
                  </div>
                  <span className="text-[11px] text-text-dim">{camp.items.length} principal(s)</span>
                </div>
                <div className="divide-y divide-border">
                  {camp.items.map((item) => (
                    <div key={item.item_id} className="px-3.5 py-2.5 flex flex-wrap items-center justify-between gap-2 text-xs">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-text-pri">{item.principal_email}</span>
                          <Badge variant="default">{item.role}</Badge>
                          <Badge variant={item.mfa_enabled ? 'success' : 'warn'}>
                            {item.mfa_enabled ? 'MFA' : 'NO MFA'}
                          </Badge>
                          <Badge
                            variant={
                              item.decision === 'certified'
                                ? 'success'
                                : item.decision === 'revoked'
                                  ? 'danger'
                                  : 'warn'
                            }
                          >
                            {item.decision.toUpperCase()}
                          </Badge>
                        </div>
                        <div className="text-[11px] text-text-dim">{item.target_summary}</div>
                      </div>
                      {canManage && item.decision === 'pending' && (
                        <div className="flex items-center gap-1.5">
                          <Button size="xs" variant="primary" onClick={() => void handleDecide(camp.id, item.item_id, 'certified')}>Certify</Button>
                          <Button size="xs" variant="danger-ghost" icon={<Ban size={12} />} onClick={() => void handleDecide(camp.id, item.item_id, 'revoked')}>Revoke</Button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
