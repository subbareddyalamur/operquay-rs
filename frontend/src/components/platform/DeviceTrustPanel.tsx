import { useCallback, useEffect, useState } from 'react';
import { Laptop, RefreshCw, ShieldCheck } from 'lucide-react';
import { Badge, Button, Input } from '@/components/primitives';
import { api } from '@/lib/api';
import { useToastStore } from '@/stores/toast';

export interface DeviceTrustPolicy {
  enabled: boolean;
  enforce_on_desktop_launch: boolean;
  require_disk_encryption: boolean;
  require_edr_running: boolean;
  max_os_patch_age_days: number;
  allowed_providers: string[];
  attestation_ttl_secs: number;
}

export interface DevicePostureRow {
  id: string;
  user_id: string;
  device_id: string;
  provider: string;
  hostname: string;
  os_version: string;
  disk_encrypted: boolean;
  edr_running: boolean;
  edr_agent: string;
  os_patch_age_days: number;
  compliant: boolean;
  reasons: string[];
  attested_at: number;
}

const DEFAULT_POLICY: DeviceTrustPolicy = {
  enabled: false,
  enforce_on_desktop_launch: true,
  require_disk_encryption: true,
  require_edr_running: true,
  max_os_patch_age_days: 30,
  allowed_providers: ['crowdstrike', 'jamf', 'intune', 'osquery'],
  attestation_ttl_secs: 86400,
};

export function DeviceTrustPanel() {
  const pushToast = useToastStore((s) => s.push);
  const [policy, setPolicy] = useState<DeviceTrustPolicy>(DEFAULT_POLICY);
  const [devices, setDevices] = useState<DevicePostureRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  const [deviceId, setDeviceId] = useState('ws-macbook-pro-1');
  const [provider, setProvider] = useState('jamf');
  const [hostname, setHostname] = useState('eng-workstation');
  const [osVersion, setOsVersion] = useState('macOS 15.3');
  const [diskEncrypted, setDiskEncrypted] = useState(true);
  const [edrRunning, setEdrRunning] = useState(true);
  const [edrAgent, setEdrAgent] = useState('CrowdStrike Falcon');
  const [patchAgeDays, setPatchAgeDays] = useState('4');

  const load = useCallback(async () => {
    setLoading(true);
    const [polRes, devRes] = await Promise.all([
      api.get<DeviceTrustPolicy>('/api/device-trust/policy'),
      api.get<{ devices: DevicePostureRow[] }>('/api/device-trust/devices'),
    ]);
    if (polRes.ok) {
      setPolicy(polRes.data);
    }
    if (devRes.ok) {
      setDevices(devRes.data.devices ?? []);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleSavePolicy = async () => {
    setBusy(true);
    const res = await api.put<DeviceTrustPolicy>('/api/device-trust/policy', policy);
    setBusy(false);
    if (!res.ok) {
      pushToast({ title: res.error?.message || 'Failed saving device trust policy', variant: 'danger' });
      return;
    }
    setPolicy(res.data);
    pushToast({ title: 'Device Trust posture policy saved', variant: 'success' });
  };

  const handleAttest = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    const res = await api.post<{ attestation: DevicePostureRow }>('/api/device-trust/attest', {
      device_id: deviceId.trim(),
      provider: provider.trim(),
      hostname: hostname.trim(),
      os_version: osVersion.trim(),
      disk_encrypted: diskEncrypted,
      edr_running: edrRunning,
      edr_agent: edrAgent.trim(),
      os_patch_age_days: Math.max(0, Number(patchAgeDays) || 0),
    });
    setBusy(false);
    if (!res.ok) {
      pushToast({ title: res.error?.message || 'Attestation submission failed', variant: 'danger' });
      return;
    }
    pushToast({
      title: res.data.attestation.compliant
        ? `Device "${res.data.attestation.device_id}" attested compliant`
        : `Device non-compliant: ${res.data.attestation.reasons.join('; ')}`,
      variant: res.data.attestation.compliant ? 'success' : 'warn',
    });
    void load();
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Laptop size={18} className="text-accent" />
          <div>
            <h3 className="text-sm font-semibold text-text-pri">Hardware Device Trust &amp; MDM Posture</h3>
            <p className="text-xs text-text-mut">Require disk encryption (FileVault/BitLocker), active EDR sensor, and OS patch freshness via CrowdStrike, Jamf, Intune, or osquery before desktop ticket launch.</p>
          </div>
        </div>
        <Button size="sm" variant="ghost" icon={<RefreshCw size={13} />} onClick={() => void load()} disabled={loading}>
          Refresh
        </Button>
      </div>

      <div className="rounded-lg border border-border bg-surface p-4 space-y-4">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-text-sec">Zero-Trust Posture Gate Policy</h4>
          <Badge variant={policy.enabled ? 'success' : 'default'}>
            {policy.enabled ? 'Enforcing' : 'Disabled'}
          </Badge>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs text-text-pri">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={policy.enabled}
              onChange={(e) => setPolicy((p) => ({ ...p, enabled: e.target.checked }))}
            />
            <span>Enable Device Trust enforcement</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={policy.enforce_on_desktop_launch}
              onChange={(e) => setPolicy((p) => ({ ...p, enforce_on_desktop_launch: e.target.checked }))}
            />
            <span>Gate RDP / VNC session tickets</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={policy.require_disk_encryption}
              onChange={(e) => setPolicy((p) => ({ ...p, require_disk_encryption: e.target.checked }))}
            />
            <span>Require full-disk encryption</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={policy.require_edr_running}
              onChange={(e) => setPolicy((p) => ({ ...p, require_edr_running: e.target.checked }))}
            />
            <span>Require active EDR sensor</span>
          </label>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-text-mut mb-1" htmlFor="dt-max-patch">Max OS Patch Age (days)</label>
            <Input
              id="dt-max-patch"
              type="number"
              min="0"
              value={String(policy.max_os_patch_age_days)}
              onChange={(e) => setPolicy((p) => ({ ...p, max_os_patch_age_days: Math.max(0, Number(e.target.value) || 0) }))}
            />
          </div>
          <div>
            <label className="block text-xs text-text-mut mb-1" htmlFor="dt-providers">Trusted Providers (comma-separated)</label>
            <Input
              id="dt-providers"
              value={policy.allowed_providers.join(', ')}
              onChange={(e) =>
                setPolicy((p) => ({
                  ...p,
                  allowed_providers: e.target.value.split(',').map((s) => s.trim()).filter(Boolean),
                }))
              }
            />
          </div>
        </div>

        <div className="flex justify-end">
          <Button size="sm" icon={<ShieldCheck size={14} />} onClick={() => void handleSavePolicy()} loading={busy}>
            Save Policy
          </Button>
        </div>
      </div>

      <form onSubmit={(e) => void handleAttest(e)} className="rounded-lg border border-border bg-surface p-4 space-y-3">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-text-sec">Submit Workstation Posture Attestation</h4>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label className="block text-xs text-text-mut mb-1" htmlFor="att-dev-id">Device ID</label>
            <Input id="att-dev-id" value={deviceId} onChange={(e) => setDeviceId(e.target.value)} required />
          </div>
          <div>
            <label className="block text-xs text-text-mut mb-1" htmlFor="att-provider">MDM/EDR Provider</label>
            <Input id="att-provider" value={provider} onChange={(e) => setProvider(e.target.value)} />
          </div>
          <div>
            <label className="block text-xs text-text-mut mb-1" htmlFor="att-hostname">Hostname</label>
            <Input id="att-hostname" value={hostname} onChange={(e) => setHostname(e.target.value)} />
          </div>
          <div>
            <label className="block text-xs text-text-mut mb-1" htmlFor="att-os">OS Version</label>
            <Input id="att-os" value={osVersion} onChange={(e) => setOsVersion(e.target.value)} />
          </div>
          <div>
            <label className="block text-xs text-text-mut mb-1" htmlFor="att-edr">EDR Agent</label>
            <Input id="att-edr" value={edrAgent} onChange={(e) => setEdrAgent(e.target.value)} />
          </div>
          <div>
            <label className="block text-xs text-text-mut mb-1" htmlFor="att-patch">Patch Age (days)</label>
            <Input id="att-patch" type="number" min="0" value={patchAgeDays} onChange={(e) => setPatchAgeDays(e.target.value)} />
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-4 text-xs text-text-pri">
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={diskEncrypted} onChange={(e) => setDiskEncrypted(e.target.checked)} />
            <span>Disk Encrypted</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={edrRunning} onChange={(e) => setEdrRunning(e.target.checked)} />
            <span>EDR Sensor Running</span>
          </label>
        </div>
        <div className="flex justify-end">
          <Button type="submit" size="sm" variant="secondary" loading={busy}>
            Attest This Device
          </Button>
        </div>
      </form>

      <div className="space-y-2">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-text-sec">
          Attested Workstations ({devices.length})
        </h4>
        {devices.length === 0 ? (
          <p className="text-xs text-text-mut rounded-lg border border-border bg-surface p-4">
            No device posture attestations submitted yet.
          </p>
        ) : (
          <div className="rounded-lg border border-border bg-surface divide-y divide-border">
            {devices.map((d) => (
              <div key={d.id} className="p-3.5 flex flex-wrap items-center justify-between gap-2">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-text-pri">{d.hostname || d.device_id}</span>
                    <Badge variant={d.compliant ? 'success' : 'danger'}>
                      {d.compliant ? 'compliant' : 'blocked'}
                    </Badge>
                    <span className="text-xs text-text-mut font-mono">{d.provider} · {d.os_version}</span>
                  </div>
                  <p className="text-[11px] text-text-sec">
                    FDE: {d.disk_encrypted ? 'yes' : 'no'} · EDR: {d.edr_running ? d.edr_agent || 'running' : 'stopped'} · Patch age: {d.os_patch_age_days}d
                    {d.reasons.length > 0 ? ` · ${d.reasons.join('; ')}` : ''}
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
