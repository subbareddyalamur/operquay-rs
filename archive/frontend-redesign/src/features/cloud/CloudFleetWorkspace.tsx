import { useEffect, useState } from 'react';
import {
  ArrowRightLeft,
  Copy,
  FolderUp,
  KeyRound,
  Monitor,
  Network,
  RefreshCw,
  Server,
  Star,
  Terminal,
} from 'lucide-react';
import { Badge, Button, Card } from '@/design-system/primitives';
import { apiJson, type Ec2Instance } from '../platform/api';
import { usePlatformStore } from '../platform/store';

export interface CloudFleetWorkspaceProps {
  onOpenTerminal: (instance: Ec2Instance) => void;
  onOpenDesktop: (instance: Ec2Instance) => void;
  onOpenTopology: (vpcId: string) => void;
}

export function CloudFleetWorkspace({
  onOpenTerminal,
  onOpenDesktop,
  onOpenTopology,
}: CloudFleetWorkspaceProps) {
  const {
    instances,
    fleetStats,
    favorites,
    toggleFavorite,
    loadFleet,
    pushActivity,
  } = usePlatformStore();

  const [filterText, setFilterText] = useState('');
  const [selected, setSelected] = useState<Ec2Instance | null>(null);
  const [modal, setModal] = useState<'none' | 'files' | 'forward' | 'clone' | 'sso'>('none');
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [errMsg, setErrMsg] = useState<string | null>(null);

  const [remoteDir, setRemoteDir] = useState('/var/log');
  const [forwardPort, setForwardPort] = useState(5432);
  const [cloneName, setCloneName] = useState('');
  const [ssoUrl, setSsoUrl] = useState('https://example.awsapps.com/start');
  const [roleArn, setRoleArn] = useState('arn:aws:iam::123456789012:role/OperquayOps');

  useEffect(() => {
    void loadFleet();
  }, [loadFleet]);

  const filtered = instances.filter((i) => {
    const q = filterText.trim().toLowerCase();
    return (
      !q ||
      i.instance_id.toLowerCase().includes(q) ||
      i.name.toLowerCase().includes(q) ||
      i.private_ip.includes(q) ||
      i.region.toLowerCase().includes(q)
    );
  });

  const startForward = async () => {
    if (!selected) return;
    setErrMsg(null);
    try {
      const tun = await apiJson<{ id: string; pairing_code: string }>('/api/aws/forward/start', {
        method: 'POST',
        body: JSON.stringify({
          instance_id: selected.instance_id,
          region: selected.region,
          remote_port: Number(forwardPort),
          local_port: Number(forwardPort),
        }),
      });
      setStatusMsg(`Tunnel ${tun.id} active · Pairing: ${tun.pairing_code}`);
      pushActivity({ title: 'Port Forward Started', detail: `${selected.instance_id}:${forwardPort}`, status: 'done' });
      setModal('none');
    } catch (e) {
      setErrMsg(e instanceof Error ? e.message : 'Port forward error');
    }
  };

  const startClone = async () => {
    if (!selected) return;
    setErrMsg(null);
    try {
      const res = await apiJson<{ id: string; ami_id: string }>('/clone/start', {
        method: 'POST',
        body: JSON.stringify({
          instance_id: selected.instance_id,
          clone_name: cloneName || `${selected.name}-clone`,
          region: selected.region,
        }),
      });
      setStatusMsg(`Clone job ${res.id} started (AMI ${res.ami_id})`);
      pushActivity({ title: 'EC2 Clone Started', detail: `${selected.instance_id} -> ${res.ami_id}`, status: 'done' });
      setModal('none');
    } catch (e) {
      setErrMsg(e instanceof Error ? e.message : 'Clone error');
    }
  };

  const bindUserRole = async () => {
    setErrMsg(null);
    try {
      await apiJson('/api/aws/user-bindings', {
        method: 'POST',
        body: JSON.stringify({ label: 'Direct STS Ops', role_arn: roleArn, region: 'us-east-1' }),
      });
      setStatusMsg('User AWS IAM role binding saved.');
    } catch (e) {
      setErrMsg(e instanceof Error ? e.message : 'Binding failed');
    }
  };

  const disconnectAllRoles = async () => {
    await apiJson('/api/aws/role-disconnect', { method: 'POST', body: '{}' });
    setStatusMsg('Disconnected all user AWS role leases (5s security fence active).');
  };

  return (
    <div className="max-w-6xl mx-auto px-6 py-6 space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-4">
        <div>
          <h1 className="text-[20px] font-semibold text-text-pri tracking-[-0.02em]">
            AWS Cloud Fleet &amp; Session Launchpad
          </h1>
          <p className="mt-1 text-xs text-text-mut">
            Multi-account EC2/SSM inventory, User STS role bindings with 5-second disconnect fence, S3/SSM transfers, EC2 AMI cloning, and port forwarding.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setModal('sso')} icon={<KeyRound size={14} aria-hidden="true" />}>
            AWS SSO / Role Fence
          </Button>
          <Button variant="outline" size="sm" onClick={() => void loadFleet()} icon={<RefreshCw size={14} aria-hidden="true" />}>
            Refresh Fleet
          </Button>
        </div>
      </div>

      {/* Stat Tiles */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="p-3.5">
          <div className="text-[11px] text-text-dim">Total Instances</div>
          <div className="text-xl font-semibold text-text-pri tabular-mono mt-1">{fleetStats.total}</div>
        </Card>
        <Card className="p-3.5">
          <div className="text-[11px] text-text-dim">Running</div>
          <div className="text-xl font-semibold text-success tabular-mono mt-1">{fleetStats.running}</div>
        </Card>
        <Card className="p-3.5">
          <div className="text-[11px] text-text-dim">SSM Online</div>
          <div className="text-xl font-semibold text-accent tabular-mono mt-1">{fleetStats.ssm_online}</div>
        </Card>
        <Card className="p-3.5">
          <div className="text-[11px] text-text-dim">Regions / VPCs</div>
          <div className="text-xl font-semibold text-text-pri tabular-mono mt-1">{fleetStats.regions} / {fleetStats.vpcs}</div>
        </Card>
      </div>

      {statusMsg && (
        <div className="px-4 py-2.5 rounded-[var(--radius-sm)] border border-border bg-[var(--success-dim)] text-xs text-success">
          {statusMsg}
        </div>
      )}
      {errMsg && (
        <div role="alert" className="px-4 py-2.5 rounded-[var(--radius-sm)] border border-border bg-[var(--danger-dim)] text-xs text-danger">
          {errMsg}
        </div>
      )}

      <Card className="p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-text-pri">
            <Server size={15} className="text-accent" aria-hidden="true" />
            Compute Inventory
          </div>
          <input
            aria-label="Filter instances"
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            placeholder="Filter by name, instance ID, IP, or region..."
            className="h-8 w-72 px-3 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
          />
        </div>

        {filtered.length === 0 ? (
          <div className="py-6 text-center space-y-2">
            <p className="text-xs text-text-dim">
              No discovered instances yet. Configure an AWS account in Admin or launch a quick sandbox SSM/Desktop target.
            </p>
            <Button
              size="sm"
              onClick={() =>
                onOpenTerminal({
                  instance_id: 'i-demo-0001',
                  name: 'sandbox-ssm-host',
                  state: 'running',
                  instance_type: 't3.medium',
                  platform: 'linux',
                  private_ip: '10.0.1.10',
                  public_ip: '',
                  region: 'us-east-1',
                  availability_zone: 'us-east-1a',
                  vpc_id: 'vpc-main',
                  subnet_id: 'sub-pub',
                  account_id: '000000000000',
                  profile: 'hub',
                  ssm_online: true,
                })
              }
              icon={<Terminal size={13} aria-hidden="true" />}
            >
              Open Sandbox SSM Terminal
            </Button>
          </div>
        ) : (
          <div className="divide-y divide-border text-xs">
            {filtered.map((inst) => {
              const fav = favorites.includes(inst.instance_id);
              return (
                <div key={inst.instance_id} className="py-3 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <button
                      type="button"
                      aria-label={fav ? `Unfavorite ${inst.name}` : `Favorite ${inst.name}`}
                      onClick={() => void toggleFavorite(inst.instance_id)}
                      className={fav ? 'text-warn' : 'text-text-dim hover:text-text-pri'}
                    >
                      <Star size={14} aria-hidden="true" />
                    </button>
                    <div>
                      <div className="font-medium text-text-pri">{inst.name}</div>
                      <div className="text-[11px] text-text-dim tabular-mono">
                        {inst.instance_id} · {inst.private_ip || 'no-ip'} · {inst.region} · {inst.platform}
                      </div>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Badge tone={inst.state === 'running' ? 'success' : 'neutral'}>{inst.state}</Badge>
                    <Button size="xs" onClick={() => onOpenTerminal(inst)} icon={<Terminal size={12} aria-hidden="true" />}>
                      SSM Shell
                    </Button>
                    <Button size="xs" variant="outline" onClick={() => onOpenDesktop(inst)} icon={<Monitor size={12} aria-hidden="true" />}>
                      RDP/VNC
                    </Button>
                    <Button
                      size="xs"
                      variant="outline"
                      onClick={() => {
                        setSelected(inst);
                        setModal('files');
                      }}
                      icon={<FolderUp size={12} aria-hidden="true" />}
                    >
                      Files
                    </Button>
                    <Button
                      size="xs"
                      variant="outline"
                      onClick={() => {
                        setSelected(inst);
                        setModal('forward');
                      }}
                      icon={<ArrowRightLeft size={12} aria-hidden="true" />}
                    >
                      Forward
                    </Button>
                    <Button
                      size="xs"
                      variant="outline"
                      onClick={() => {
                        setSelected(inst);
                        setModal('clone');
                      }}
                      icon={<Copy size={12} aria-hidden="true" />}
                    >
                      Clone
                    </Button>
                    {inst.vpc_id && (
                      <Button
                        size="xs"
                        variant="ghost"
                        onClick={() => onOpenTopology(inst.vpc_id)}
                        icon={<Network size={12} aria-hidden="true" />}
                      >
                        VPC
                      </Button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {modal === 'files' && selected && (
        <Card elevated className="p-5 space-y-3 border-[var(--accent-border)]">
          <h2 className="text-sm font-semibold text-text-pri">
            SSM File Browser &amp; S3 Express — {selected.name} ({selected.instance_id})
          </h2>
          <div className="flex flex-wrap gap-2">
            <input
              aria-label="Remote directory path"
              value={remoteDir}
              onChange={(e) => setRemoteDir(e.target.value)}
              className="flex-1 min-w-[200px] h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
            />
            <Button
              size="sm"
              onClick={async () => {
                setErrMsg(null);
                try {
                  await apiJson('/browse-directory', {
                    method: 'POST',
                    body: JSON.stringify({ instance_id: selected.instance_id, region: selected.region, platform: selected.platform, path: remoteDir }),
                  });
                } catch (e) {
                  setErrMsg(e instanceof Error ? e.message : 'Browse error (live EC2 SSM required)');
                }
              }}
            >
              Browse Path
            </Button>
            <Button variant="outline" size="sm" onClick={() => setModal('none')}>Close</Button>
          </div>
        </Card>
      )}

      {modal === 'forward' && selected && (
        <Card elevated className="p-5 space-y-3 border-[var(--accent-border)]">
          <h2 className="text-sm font-semibold text-text-pri">Start 5-Byte Multiplexed Port Forward — {selected.name}</h2>
          <div className="flex flex-wrap items-center gap-2">
            <label htmlFor="fwd-port" className="text-xs text-text-mut">Remote Port</label>
            <input
              id="fwd-port"
              type="number"
              value={forwardPort}
              onChange={(e) => setForwardPort(Number(e.target.value))}
              className="w-28 h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
            />
            <Button size="sm" onClick={() => void startForward()}>Create Tunnel</Button>
            <Button variant="outline" size="sm" onClick={() => setModal('none')}>Cancel</Button>
          </div>
        </Card>
      )}

      {modal === 'clone' && selected && (
        <Card elevated className="p-5 space-y-3 border-[var(--accent-border)]">
          <h2 className="text-sm font-semibold text-text-pri">Clone EC2 Instance via AMI — {selected.name}</h2>
          <div className="flex flex-wrap items-center gap-2">
            <input
              aria-label="Clone instance name"
              value={cloneName}
              onChange={(e) => setCloneName(e.target.value)}
              placeholder={`${selected.name}-clone`}
              className="flex-1 h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
            />
            <Button size="sm" onClick={() => void startClone()}>Create AMI Clone</Button>
            <Button variant="outline" size="sm" onClick={() => setModal('none')}>Cancel</Button>
          </div>
        </Card>
      )}

      {modal === 'sso' && (
        <Card elevated className="p-5 space-y-3 border-[var(--accent-border)] text-xs">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-text-pri">User AWS Onboarding &amp; Role Session Fence</h2>
            <Button variant="outline" size="xs" onClick={() => setModal('none')}>Close</Button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="space-y-2">
              <label htmlFor="aws-role-arn" className="block text-text-mut">Explicit IAM Role ARN</label>
              <input
                id="aws-role-arn"
                value={roleArn}
                onChange={(e) => setRoleArn(e.target.value)}
                className="w-full h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri"
              />
              <div className="flex gap-2">
                <Button size="xs" onClick={() => void bindUserRole()}>Save Role Binding</Button>
                <Button size="xs" variant="danger" onClick={() => void disconnectAllRoles()}>Disconnect All (5s Fence)</Button>
              </div>
            </div>
            <div className="space-y-2">
              <label htmlFor="aws-sso-url" className="block text-text-mut">AWS IAM Identity Center Start URL</label>
              <input
                id="aws-sso-url"
                value={ssoUrl}
                onChange={(e) => setSsoUrl(e.target.value)}
                className="w-full h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri"
              />
              <Button
                size="xs"
                variant="outline"
                onClick={async () => {
                  setErrMsg(null);
                  try {
                    const started = await apiJson<{ user_code: string; verification_url: string }>('/api/aws/sso/start', {
                      method: 'POST',
                      body: JSON.stringify({ region: 'us-east-1', start_url: ssoUrl }),
                    });
                    setStatusMsg(`Device code: ${started.user_code} (${started.verification_url})`);
                  } catch (e) {
                    setErrMsg(e instanceof Error ? e.message : 'AWS SSO unavailable offline');
                  }
                }}
              >
                Start AWS SSO Device Login
              </Button>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}

