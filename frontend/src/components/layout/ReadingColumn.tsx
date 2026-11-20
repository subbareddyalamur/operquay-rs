import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import {
  Activity,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  HardDrive,
  Lock,
  Network,
  RefreshCw,
  Server,
  Shield,
  Tag,
  X,
} from 'lucide-react';
import { Badge, SkeletonRow, Tooltip } from '@/components/primitives';
import { api } from '@/lib/api';
import { useLayoutStore } from '@/stores/layout';
import { useAIStore } from '@/stores/ai';
import { useAuthStore, hasPermission } from '@/stores/auth';
import { useInstancesStore } from '@/stores/instances';
import { useSessionsStore } from '@/stores/sessions';
import { getAllInstances } from '@/lib/filter';
import { AIChatPanel } from '@/components/ai/AIChatPanel';

const known = (n: unknown): n is number => typeof n === 'number' && Number.isFinite(n);

interface SGRule {
  protocol: string;
  from_port: number;
  to_port: number;
  source: string;
  description?: string;
}

interface SecurityGroupDetail {
  group_id: string;
  group_name: string;
  description?: string;
  inbound_rules: SGRule[];
  outbound_rules: SGRule[];
}

interface NetworkInterfaceItem {
  interface_id: string;
  subnet_id: string;
  private_ip: string;
  public_ip?: string;
  mac_address?: string;
  status: string;
}

interface BlockDeviceItem {
  device_name: string;
  volume_id: string;
  volume_size: number;
  volume_type: string;
  iops?: number;
  encrypted: boolean;
  state?: string;
  delete_on_termination?: boolean;
}

interface VolumeFallbackItem {
  volume_id: string;
  device?: string;
  size_gib: number;
  volume_type: string;
  iops?: number;
  encrypted: boolean;
  state?: string;
}

interface InstanceDetails {
  instance_id: string;
  name: string;
  instance_type: string;
  platform: string;
  os?: string;
  state: string;
  aws_region: string;
  account_id: string;
  account_alias: string;
  availability_zone: string;
  vpc_id: string;
  subnet_id: string;
  private_ip: string;
  public_ip?: string;
  private_dns?: string;
  public_dns?: string;
  launch_time: string;
  key_name?: string;
  instance_profile?: string;
  ami_id?: string;
  architecture?: string;
  root_device_type?: string;
  root_device_name?: string;
  ebs_optimized?: boolean;
  monitoring_state?: string;
  security_groups?: string[];
  security_group_details?: SecurityGroupDetail[];
  tags: Record<string, string>;
  block_devices?: BlockDeviceItem[];
  volumes?: VolumeFallbackItem[];
  network_interfaces?: NetworkInterfaceItem[];
}

interface Metrics {
  cpu_utilization_pct?: number;
  cpu_load?: number;
  cpu_count?: number;
  mem_used_pct?: number;
  mem_total_mb?: number;
  mem_used_mb?: number;
  disk_used_pct?: number;
  disk_total_gb?: number;
  disk_used_gb?: number;
  network_in_bytes?: number;
  network_out_bytes?: number;
  uptime?: string;
  source?: string;
}

const SECTIONS = [
  'Overview',
  'Network & Interfaces',
  'Storage',
  'Security groups',
  'Metrics',
  'Tags',
] as const;
type Section = (typeof SECTIONS)[number];

function ruleLabel(r: SGRule): string {
  if (r.protocol === '-1') return 'All traffic';
  const proto = r.protocol || 'tcp';
  if (!r.to_port || r.from_port === r.to_port) return r.from_port ? `${r.from_port}/${proto}` : proto;
  return `${r.from_port}-${r.to_port}/${proto}`;
}

function present(value?: string | number | null): string | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  return String(value);
}

function accountLabel(alias?: string, id?: string): string | undefined {
  const name = present(alias);
  const number = present(id);
  if (name && number) return `${name} · ${number}`;
  return name || number;
}

function formatBytes(bytes?: number): string {
  if (!known(bytes) || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

function stripe(index: number): { background: string } {
  return { background: index % 2 === 0 ? 'transparent' : 'color-mix(in srgb, var(--text-pri) 5%, transparent)' };
}

function stateColor(state?: string): string {
  const s = (state || '').toLowerCase();
  if (s === 'running' || s === 'in-use' || s === 'available') return 'bg-success/15 text-success border-success/30';
  if (s === 'stopped' || s === 'stopping') return 'bg-danger/15 text-danger border-danger/30';
  return 'bg-bg text-text-mut border-border';
}

function CopyValue({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="group text-left hover:text-accent inline-flex items-center gap-1.5 rounded focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--accent)]"
      title={`Copy ${value}`}
      onClick={() => {
        void navigator.clipboard?.writeText(value);
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1200);
      }}
    >
      <span>{value}</span>
      {copied ? (
        <span className="inline-flex items-center gap-0.5 text-[10px] font-sans text-success">
          <Check size={11} aria-hidden="true" />
          Copied
        </span>
      ) : (
        <Copy size={11} aria-hidden="true" className="opacity-0 group-hover:opacity-70 text-text-dim shrink-0 transition-opacity" />
      )}
    </button>
  );
}

function DetailTable({ rows }: { rows: Array<[string, string | number | null | undefined]> }) {
  const visible = rows.flatMap(([label, value]) => {
    const text = present(value);
    return text ? [[label, text] as const] : [];
  });
  if (!visible.length) return null;
  return (
    <table className="w-full border-collapse text-[12px]">
      <tbody>
        {visible.map(([label, value], index) => (
          <tr key={label} style={stripe(index)} className="border-b border-border-2 last:border-b-0">
            <th scope="row" className="w-[8.75rem] border-r border-border-2 px-3 py-1.5 text-left align-top font-medium text-text-dim">{label}</th>
            <td className="px-3 py-1.5 align-top font-mono text-[12px] text-text-pri [overflow-wrap:anywhere]"><CopyValue value={value} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function DataTable({ columns, rows }: { columns: string[]; rows: string[][] }) {
  if (!rows.length) return null;
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-[12px]">
        <thead>
          <tr className="bg-bg/40">
            {columns.map((column) => (
              <th key={column} scope="col" className="border-b border-border-2 px-3 py-1.5 text-left text-[11px] font-semibold text-text-dim">{column}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={`${row[0]}-${index}`} style={stripe(index)} className="border-b border-border-2 last:border-b-0">
              {row.map((cell, column) => (
                <td key={columns[column]} className="px-3 py-1.5 align-top font-mono text-text-pri [overflow-wrap:anywhere]">{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function sectionIcon(section: Section): ReactNode {
  switch (section) {
    case 'Overview':
      return <Server size={13} className="text-accent shrink-0" aria-hidden="true" />;
    case 'Network & Interfaces':
      return <Network size={13} className="text-info shrink-0" aria-hidden="true" />;
    case 'Storage':
      return <HardDrive size={13} className="text-warn shrink-0" aria-hidden="true" />;
    case 'Security groups':
      return <Shield size={13} className="text-success shrink-0" aria-hidden="true" />;
    case 'Metrics':
      return <Activity size={13} className="text-accent shrink-0" aria-hidden="true" />;
    case 'Tags':
      return <Tag size={13} className="text-text-mut shrink-0" aria-hidden="true" />;
  }
}

function sectionBadge(section: Section, d: InstanceDetails, metrics: Metrics | null | 'error'): string | null {
  switch (section) {
    case 'Overview':
      return present(d.instance_type) ?? null;
    case 'Network & Interfaces': {
      const n = d.network_interfaces?.length ?? 0;
      return `${n} ENI${n === 1 ? '' : 's'}`;
    }
    case 'Storage': {
      const count = d.block_devices?.length || d.volumes?.length || 0;
      return `${count} vol${count === 1 ? '' : 's'}`;
    }
    case 'Security groups': {
      const count = d.security_group_details?.length ?? d.security_groups?.length ?? 0;
      return `${count}`;
    }
    case 'Metrics':
      if (metrics && metrics !== 'error' && metrics.source) {
        return metrics.source === 'ssm' ? 'Live SSM' : 'CloudWatch';
      }
      return null;
    case 'Tags': {
      const count = Object.keys(d.tags ?? {}).length;
      return `${count}`;
    }
  }
}

function MetricBarRow({
  label,
  valueText,
  subText,
  percent,
}: {
  label: string;
  valueText: string;
  subText?: string;
  percent: number | null;
}) {
  const color =
    percent === null
      ? 'var(--accent)'
      : percent < 70
        ? 'var(--success)'
        : percent < 90
          ? 'var(--warn)'
          : 'var(--danger)';
  return (
    <div className="px-3 py-2 space-y-1.5 border-b border-border-2 last:border-b-0">
      <div className="flex items-baseline justify-between gap-2 text-[12px]">
        <span className="font-medium text-text-dim">{label}</span>
        <span className="font-mono font-semibold text-text-pri">
          {valueText}
        </span>
      </div>
      {subText && <div className="text-[11px] font-mono text-text-mut text-right">{subText}</div>}
      {percent !== null && (
        <div className="h-1.5 overflow-hidden rounded-full bg-border">
          <div
            className="h-full transition-all duration-300"
            style={{ width: `${Math.max(2, Math.min(percent, 100))}%`, background: color }}
          />
        </div>
      )}
    </div>
  );
}

function SectionBody({ section, d, metrics }: { section: Section; d: InstanceDetails; metrics: Metrics | null | 'error' }) {
  switch (section) {
    case 'Overview':
      return (
        <DetailTable rows={[
          ['Name', d.name],
          ['Id', d.instance_id],
          ['Type', d.instance_type],
          ['State', d.state],
          ['OS', d.os ?? d.platform],
          ['Architecture', d.architecture],
          ['AMI', d.ami_id],
          ['Root device', d.root_device_name ? `${d.root_device_name}${d.root_device_type ? ` (${d.root_device_type})` : ''}` : d.root_device_type],
          ['EBS optimized', d.ebs_optimized === undefined ? undefined : d.ebs_optimized ? 'Yes' : 'No'],
          ['IAM profile', d.instance_profile],
          ['Key pair', d.key_name],
          ['Launched', d.launch_time ? new Date(d.launch_time).toLocaleString() : undefined],
          ['Account', accountLabel(d.account_alias, d.account_id)],
        ]} />
      );
    case 'Network & Interfaces': {
      const enis = d.network_interfaces ?? [];
      return (
        <div className="divide-y divide-border-2">
          <DetailTable rows={[
            ['Private IP', d.private_ip],
            ['Public IP', d.public_ip],
            ['Private DNS', d.private_dns],
            ['Public DNS', d.public_dns],
            ['Subnet', d.subnet_id],
            ['VPC', d.vpc_id],
            ['AZ', d.availability_zone],
            ['Region', d.aws_region],
          ]} />
          {enis.length > 0 ? (
            <div className="divide-y divide-border-2">
              {enis.map((n) => (
                <div key={n.interface_id} className="px-3 py-2 text-[12px] space-y-1 bg-bg/25">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono font-medium text-text-pri">
                      <CopyValue value={n.interface_id} />
                    </span>
                    <span className={`px-1.5 py-0.5 rounded border text-[10px] font-medium ${stateColor(n.status)}`}>
                      {n.status || 'attached'}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[11px] font-mono text-text-mut">
                    <span>Private: <span className="text-text-pri">{n.private_ip || '—'}</span></span>
                    <span>Subnet: <span className="text-text-pri">{n.subnet_id || '—'}</span></span>
                    {n.public_ip && <span>Public: <span className="text-text-pri">{n.public_ip}</span></span>}
                    {n.mac_address && <span>MAC: <span className="text-text-pri">{n.mac_address}</span></span>}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <Empty>No interfaces reported.</Empty>
          )}
        </div>
      );
    }
    case 'Storage': {
      const devices: BlockDeviceItem[] = d.block_devices?.length
        ? d.block_devices
        : (d.volumes ?? []).map((v) => ({
            device_name: v.device ?? '',
            volume_id: v.volume_id,
            volume_size: v.size_gib,
            volume_type: v.volume_type,
            iops: v.iops,
            encrypted: v.encrypted,
            state: v.state,
          }));
      if (!devices.length) return <Empty>No volumes reported.</Empty>;
      return (
        <div className="divide-y divide-border-2">
          {devices.map((v) => (
            <div key={`${v.device_name}-${v.volume_id}`} className="px-3 py-2 text-[12px] space-y-1">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="font-mono font-semibold text-text-pri">{v.device_name || 'volume'}</span>
                  <span className="font-mono text-[11px] text-text-mut truncate">
                    <CopyValue value={v.volume_id} />
                  </span>
                </div>
                <span className="inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded border border-border bg-bg shrink-0">
                  {v.encrypted && <Lock size={10} className="text-success" aria-hidden="true" />}
                  {v.encrypted ? 'encrypted' : 'not encrypted'}
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] font-mono text-text-mut">
                <span>
                  <span className="text-text-pri">{v.volume_size} GiB</span> {v.volume_type || 'ebs'}
                </span>
                {known(v.iops) && v.iops > 0 && <span>{v.iops} IOPS</span>}
                {v.state && <span className="text-text-pri">{v.state}</span>}
                {v.delete_on_termination !== undefined && (
                  <span>{v.delete_on_termination ? 'Del-on-term' : 'Retain'}</span>
                )}
              </div>
            </div>
          ))}
        </div>
      );
    }
    case 'Security groups':
      if (d.security_group_details?.length) {
        return (
          <div className="divide-y divide-border">
            {d.security_group_details.map((sg) => {
              const inbound = (sg.inbound_rules ?? []).map((rule) => [
                'Inbound',
                ruleLabel(rule),
                rule.description ? `${rule.source} (${rule.description})` : rule.source,
              ]);
              const outbound = (sg.outbound_rules ?? []).map((rule) => [
                'Outbound',
                ruleLabel(rule),
                rule.description ? `${rule.source} (${rule.description})` : rule.source,
              ]);
              const rules = [
                ...(inbound.length ? inbound : [['Inbound', 'None', '—']]),
                ...(outbound.length ? outbound : [['Outbound', 'None', '—']]),
              ];
              return (
                <div key={sg.group_id}>
                  <div className="bg-bg/40 border-b border-border-2 px-3 py-1.5">
                    <div className="font-mono text-[12px] font-semibold text-text-pri">{sg.group_name || sg.group_id}</div>
                    {sg.group_name ? (
                      <div className="font-mono text-[11px] text-text-dim">
                        <CopyValue value={sg.group_id} />
                      </div>
                    ) : null}
                  </div>
                  <DataTable columns={['Direction', 'Rule', 'Source']} rows={rules} />
                </div>
              );
            })}
          </div>
        );
      }
      return d.security_groups?.length
        ? <DetailTable rows={d.security_groups.map((group, index) => [`Group ${index + 1}`, group])} />
        : <Empty>No security groups reported.</Empty>;
    case 'Tags': {
      const tags = Object.entries(d.tags ?? {}).sort(([a], [b]) => a.localeCompare(b));
      return tags.length ? <DetailTable rows={tags} /> : <Empty>No tags.</Empty>;
    }
    case 'Metrics': {
      if (metrics === 'error') return <Empty>Instance metrics are not available.</Empty>;
      if (!metrics) return <Empty>Loading metrics…</Empty>;
      const isWin = d.platform === 'windows';
      const cpuPct = known(metrics.cpu_utilization_pct)
        ? metrics.cpu_utilization_pct
        : isWin && known(metrics.cpu_load)
          ? metrics.cpu_load
          : null;
      const cpuText = !known(metrics.cpu_load)
        ? (cpuPct !== null ? `${cpuPct}%` : '—')
        : isWin
          ? `${metrics.cpu_load}%`
          : `${metrics.cpu_load}${known(metrics.cpu_count) ? ` / ${metrics.cpu_count} cores` : ''}`;
      const memSub =
        known(metrics.mem_used_mb) && known(metrics.mem_total_mb) && metrics.mem_total_mb > 0
          ? `${metrics.mem_used_mb} / ${metrics.mem_total_mb} MiB`
          : undefined;
      const diskSub =
        known(metrics.disk_used_gb) && known(metrics.disk_total_gb) && metrics.disk_total_gb > 0
          ? `${metrics.disk_used_gb} / ${metrics.disk_total_gb} GiB`
          : undefined;
      const netTotal = (metrics.network_in_bytes ?? 0) + (metrics.network_out_bytes ?? 0);
      return (
        <div>
          <MetricBarRow
            label={isWin ? 'CPU' : 'CPU load'}
            valueText={cpuText}
            subText={cpuPct !== null && !isWin ? `${cpuPct}% utilization` : undefined}
            percent={cpuPct}
          />
          <MetricBarRow
            label="Memory"
            valueText={known(metrics.mem_used_pct) ? `${metrics.mem_used_pct}%` : '—'}
            subText={memSub}
            percent={known(metrics.mem_used_pct) ? metrics.mem_used_pct : null}
          />
          <MetricBarRow
            label="Disk"
            valueText={known(metrics.disk_used_pct) ? `${metrics.disk_used_pct}%` : '—'}
            subText={diskSub}
            percent={known(metrics.disk_used_pct) ? metrics.disk_used_pct : null}
          />
          {netTotal > 0 && (
            <div className="flex items-center justify-between px-3 py-2 text-[12px] border-b border-border-2">
              <span className="font-medium text-text-dim">Network I/O</span>
              <span className="font-mono text-text-pri">
                In {formatBytes(metrics.network_in_bytes)} / Out {formatBytes(metrics.network_out_bytes)}
              </span>
            </div>
          )}
          {metrics.uptime && (
            <div className="flex items-center justify-between px-3 py-2 text-[12px]">
              <span className="font-medium text-text-dim">Uptime</span>
              <span className="font-mono text-text-pri">{metrics.uptime}</span>
            </div>
          )}
        </div>
      );
    }
  }
}

function ReadingFrame({ width, min, max, label, onResize, children }: { width: number; min: number; max: number; label: string; onResize: (px: number) => void; children: ReactNode }) {
  const dragging = useRef(false);
  return (
    <div className="relative h-full min-h-0 shrink-0" style={{ width }}>
      <div
        role="separator"
        aria-orientation="vertical"
        aria-label={label}
        aria-valuemin={min}
        aria-valuemax={max}
        aria-valuenow={width}
        tabIndex={0}
        className="absolute left-0 top-0 bottom-0 z-10 w-1.5 cursor-col-resize hover:bg-accent/40"
        onPointerDown={(e) => { dragging.current = true; e.currentTarget.setPointerCapture(e.pointerId); }}
        onPointerMove={(e) => { if (dragging.current) onResize(window.innerWidth - e.clientX); }}
        onPointerUp={() => { dragging.current = false; }}
        onKeyDown={(e) => {
          if (e.key === 'ArrowLeft') onResize(width + 32);
          if (e.key === 'ArrowRight') onResize(width - 32);
        }}
      />
      {children}
    </div>
  );
}

function Empty({ children }: { children: string }) {
  return <p className="px-3 py-2.5 text-[12px] text-text-mut">{children}</p>;
}

function DetailsPane({ instanceId, userMode, scope }: { instanceId: string; userMode: boolean; scope?: { roleID: string; region: string; name: string } }) {
  const closeDetails = useLayoutStore((s) => s.closeDetails);
  const fallbackName = useInstancesStore((s) => {
    for (const a of s.accounts) for (const r of a.regions) for (const g of r.groups) {
      const hit = g.instances.find((i) => i.instance_id === instanceId);
      if (hit) return hit.name;
    }
    return instanceId;
  });
  const [details, setDetails] = useState<InstanceDetails | null>(null);
  const [failed, setFailed] = useState(false);
  const [metrics, setMetrics] = useState<Metrics | null | 'error'>(null);
  const [closed, setClosed] = useState<ReadonlySet<Section>>(() => new Set());
  const [reload, setReload] = useState(0);
  const roleID = scope?.roleID;
  const region = scope?.region;
  const readonly = useAuthStore((s) =>
    Boolean(s.me) &&
    !hasPermission(s.me, 'session:ssh') &&
    !hasPermission(s.me, 'instances:scan') &&
    !hasPermission(s.me, 'topology:deep')
  );

  useEffect(() => {
    let stop = false;
    setDetails(null);
    setFailed(false);
    setMetrics(null);
    if (userMode && (!roleID || !region)) { setFailed(true); return () => { stop = true; }; }
    const path = roleID && region
      ? `/api/aws/instance-details?binding_id=${encodeURIComponent(roleID)}&region=${encodeURIComponent(region)}&instance_id=${encodeURIComponent(instanceId)}`
      : `/instance-details?id=${encodeURIComponent(instanceId)}`;
    void api.get<InstanceDetails>(path).then((r) => {
      if (stop) return;
      if (r.ok) setDetails(r.data);
      else setFailed(true);
    });
    if (!userMode) void api.get<Metrics>(`/instance-metrics?instance_id=${encodeURIComponent(instanceId)}`).then((r) => {
      if (!stop) setMetrics(r.ok ? r.data : 'error');
    });
    return () => { stop = true; };
  }, [instanceId, reload, userMode, roleID, region]);

  useEffect(() => {
    if (!userMode || !roleID || !region) return;
    if (readonly) { setMetrics('error'); return; }
    let stop = false;
    setMetrics(null);
    void api.get<Metrics>(`/api/aws/instance-metrics?binding_id=${encodeURIComponent(roleID)}&region=${encodeURIComponent(region)}&instance_id=${encodeURIComponent(instanceId)}`).then((r) => {
      if (!stop) setMetrics(r.ok ? r.data : 'error');
    });
    return () => { stop = true; };
  }, [userMode, roleID, region, instanceId, reload, readonly]);

  const panelIdPrefix = useId();

  return (
    <aside className="h-full w-full border-l border-border bg-surface flex flex-col min-h-0" aria-label="Instance details">
      <div className="flex items-center gap-2 px-3 h-10 border-b border-border bg-elev shrink-0">
        <span className="text-[10px] font-semibold tracking-wider uppercase text-text-dim">Details</span>
        <span className="text-[12px] font-semibold text-text-pri truncate flex-1">{details?.name || scope?.name || fallbackName}</span>
        <Tooltip label="Reload details" side="bottom">
          <button type="button" onClick={() => setReload((n) => n + 1)} className="h-6 w-6 rounded inline-flex items-center justify-center text-text-dim hover:text-text-pri hover:bg-[var(--surface-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]" aria-label="Reload details">
            <RefreshCw size={12} aria-hidden="true" />
          </button>
        </Tooltip>
        <Tooltip label="Close details" side="bottom">
          <button type="button" onClick={closeDetails} className="h-6 w-6 rounded inline-flex items-center justify-center text-text-dim hover:text-text-pri hover:bg-[var(--surface-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]" aria-label="Close details">
            <X size={14} aria-hidden="true" />
          </button>
        </Tooltip>
      </div>
      <div className="flex-1 overflow-y-auto">
        {!details && !failed && (
          <div className="py-2">
            <p className="px-3 py-2 text-[12px] text-text-mut">Reading {fallbackName} from AWS…</p>
            <SkeletonRow />
            <SkeletonRow />
            <SkeletonRow />
            <SkeletonRow />
            <SkeletonRow />
          </div>
        )}
        {failed && <p className="px-3 py-4 text-[12px] text-danger">AWS did not return details for this instance.</p>}
        {details && (
          <div className="p-3 space-y-3">
            {/* Compact Identity & Status Summary Strip */}
            <div className="rounded-lg border border-border bg-bg/50 px-3 py-2.5 space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-[11px] font-semibold text-text-pri">
                  <CopyValue value={details.instance_id} />
                </span>
                {details.state && (
                  <span className={`px-2 py-0.5 rounded-full border text-[10px] font-semibold uppercase tracking-wide ${stateColor(details.state)}`}>
                    {details.state}
                  </span>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-text-mut">
                {details.platform && <Badge size="sm" variant="default">{details.platform}</Badge>}
                {details.instance_type && <Badge size="sm" variant="default">{details.instance_type}</Badge>}
                {details.availability_zone && <span className="font-mono">{details.availability_zone}</span>}
                {details.private_ip && <span className="font-mono">· {details.private_ip}</span>}
              </div>
            </div>

            {SECTIONS.map((section) => {
              const isOpen = !closed.has(section);
              const panelId = `${panelIdPrefix}-${section.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
              const countBadge = sectionBadge(section, details, metrics);
              return (
                <section
                  key={section}
                  className="rounded-lg border border-border bg-bg/35 overflow-hidden shadow-xs"
                >
                  <button
                    type="button"
                    aria-expanded={isOpen}
                    aria-controls={panelId}
                    onClick={() => setClosed((current) => {
                      const next = new Set(current);
                      if (next.has(section)) next.delete(section);
                      else next.add(section);
                      return next;
                    })}
                    className={`w-full flex items-center justify-between gap-2 px-3 py-2 text-left bg-elev/70 border-b ${
                      isOpen ? 'border-border text-text-pri' : 'border-transparent text-text-mut hover:text-text-pri'
                    } hover:bg-[var(--surface-hover)] focus-visible:outline-none focus-visible:bg-[var(--surface-hover)] transition-colors`}
                  >
                    <span className="flex items-center gap-2 min-w-0">
                      {isOpen ? (
                        <ChevronDown size={13} aria-hidden="true" className="text-text-dim shrink-0" />
                      ) : (
                        <ChevronRight size={13} aria-hidden="true" className="text-text-dim shrink-0" />
                      )}
                      {sectionIcon(section)}
                      <span className="text-[11px] font-semibold tracking-wide uppercase truncate">
                        {section}
                      </span>
                    </span>
                    {countBadge && (
                      <Badge size="sm" variant="default" className="shrink-0">
                        {countBadge}
                      </Badge>
                    )}
                  </button>
                  {isOpen && (
                    <div id={panelId} className="bg-surface/60">
                      <SectionBody section={section} d={details} metrics={metrics} />
                    </div>
                  )}
                </section>
              );
            })}
          </div>
        )}
      </div>
    </aside>
  );
}

/**
 * The reading column beside the work column. It shows either instance details
 * or the AI assistant, never on top of the terminal.
 */
export function ReadingColumn() {
  const detailsInstanceId = useLayoutStore((s) => s.detailsInstanceId);
  const explicitScope = useLayoutStore((s) => s.detailsScope);
  const closeDetails = useLayoutStore((s) => s.closeDetails);
  const showDetails = useLayoutStore((s) => s.showDetails);
  const aiOpen = useAIStore((s) => s.open);
  const canUseAI = useAuthStore((s) => Boolean(s.me) && hasPermission(s.me, 'ai:use'));
  const actor = useAuthStore((s) => s.me);
  const userMode = useAuthStore((s) => s.config?.aws_access_mode === 'user');
  const instanceRoles = useInstancesStore((s) => s.instanceRoles);
  const userRoles = useInstancesStore((s) => s.userRoles);
  const accounts = useInstancesStore((s) => s.accounts);
  const active = useSessionsStore((s) => s.sessions.find((x) => x.id === s.activeId));
  const activeInstanceId = active?.instanceId;
  const previousActive = useRef(active?.id);

  useEffect(() => {
    if (aiOpen && canUseAI) closeDetails();
  }, [aiOpen, canUseAI, closeDetails]);

  useEffect(() => {
    const current = useLayoutStore.getState().detailsInstanceId;
    const changed = previousActive.current !== active?.id;
    previousActive.current = active?.id;
    if (current && activeInstanceId && (current !== activeInstanceId || changed)) showDetails(activeInstanceId);
  }, [active?.id, activeInstanceId, showDetails]);

  const assistantWidth = useLayoutStore((s) => s.assistantWidth);
  const detailsWidth = useLayoutStore((s) => s.detailsWidth);
  const setAssistantWidth = useLayoutStore((s) => s.setAssistantWidth);
  const setDetailsWidth = useLayoutStore((s) => s.setDetailsWidth);

  if (aiOpen && canUseAI) {
    return (
      <ReadingFrame width={assistantWidth} min={320} max={960} label="Resize assistant" onResize={setAssistantWidth}>
        <AIChatPanel />
      </ReadingFrame>
    );
  }
  if (detailsInstanceId) {
    const role = userMode && actor && active?.instanceId === detailsInstanceId ? active.userSSH ?? active.userRDP ?? active.userTopology : undefined;
    const selected = userMode && actor && explicitScope?.userID === actor.user_id && explicitScope.tenantID === actor.tenant_id ? explicitScope : undefined;
    const ownerRole = userMode ? instanceRoles[detailsInstanceId] : undefined;
    const connected = ownerRole ? getAllInstances(accounts).find((i) => i.instance_id === detailsInstanceId) : undefined;
    const scope = selected ?? (role && active ? { ...role, name: active.instanceName } : undefined) ?? (connected && ownerRole ? { roleID: ownerRole, region: connected.aws_region, name: connected.name || connected.instance_id } : undefined);
    if (userMode && (!scope || !userRoles.some(role => role.id === scope.roleID && role.live !== false))) return null;
    return (
      <ReadingFrame width={detailsWidth} min={420} max={1200} label="Resize details" onResize={setDetailsWidth}>
        <DetailsPane key={`${detailsInstanceId}:${userMode ? `${active?.id ?? ''}:${scope?.roleID ?? ''}:${actor?.tenant_id ?? ''}:${actor?.user_id ?? ''}` : ''}`} instanceId={detailsInstanceId} userMode={userMode} scope={scope} />
      </ReadingFrame>
    );
  }
  return null;
}
