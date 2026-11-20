import { useCallback, useEffect, useMemo, useState } from 'react';
import { RefreshCw, Server, Play, Square, Globe, Cpu, Plus, Search, Terminal, Boxes, Database } from 'lucide-react';
import { StatTile } from './StatTile';
import { AccountsBreakdown } from './AccountsBreakdown';
import { Button, Kbd, SkeletonCard } from '@/components/primitives';
import { PlatformIcon } from '@/components/primitives/PlatformIcon';
import type { Platform } from '@/lib/platform';
import { detectPlatform } from '@/lib/platform';
import { api } from '@/lib/api';
import { useInstancesStore } from '@/stores/instances';
import { useLayoutStore } from '@/stores/layout';
import { useAuthStore } from '@/stores/auth';
import { useSettingsStore } from '@/stores/settings';
import { useSessionsStore } from '@/stores/sessions';
import { usePaletteStore } from '@/stores/palette';
import { connectCloud } from '@/lib/connectCloud';
import type { AccountNode } from '@/lib/types';

interface PlatformMix {
  linux?: number;
  rhel?: number;
  ubuntu?: number;
  windows?: number;
  suse?: number;
  [key: string]: number | undefined;
}

export interface AccountRow {
  account_id: string;
  account_alias: string;
  profile?: string;
  total: number;
  running: number;
  stopped: number;
  platforms?: PlatformMix;
}

interface FleetSummary {
  total: number;
  running: number;
  stopped: number;
  platforms: PlatformMix;
  accounts: AccountRow[];
  scan_duration?: string;
}

const FALLBACK: FleetSummary = {
  total: 0, running: 0, stopped: 0, platforms: {}, accounts: [],
};

export const PLATFORM_COLORS: Record<string, string> = {
  rhel: 'var(--danger)',
  windows: 'var(--info)',
  linux: 'var(--success)',
  ubuntu: 'var(--plat-ubuntu)',
  suse: 'var(--chart-6)',
  'amazon-linux': 'var(--chart-3)',
  debian: 'var(--chart-5)',
  centos: 'var(--chart-4)',
  fedora: 'var(--chart-2)',
};

function computeFromAccounts(accounts: AccountNode[]): {
  summary: FleetSummary;
  instanceTypes: Array<{ type: string; count: number }>;
  regions: Array<{ region: string; count: number }>;
} {
  let total = 0;
  let running = 0;
  let stopped = 0;
  const platforms: PlatformMix = {};
  const accountRows: AccountRow[] = [];
  const typeCounts: Record<string, number> = {};
  const regionCounts: Record<string, number> = {};

  for (const a of accounts) {
    let accTotal = 0;
    let accRunning = 0;
    let accStopped = 0;
    const accPlatforms: PlatformMix = {};
    for (const r of a.regions ?? []) {
      let regionTotal = 0;
      for (const g of r.groups ?? []) {
        for (const i of g.instances ?? []) {
          accTotal++;
          total++;
          regionTotal++;
          if (i.state === 'running') {
            accRunning++;
            running++;
          } else if (i.state === 'stopped') {
            accStopped++;
            stopped++;
          }
          const plat = detectPlatform({ Platform: i.platform, PlatformDetails: i.os });
          platforms[plat] = (platforms[plat] ?? 0) + 1;
          accPlatforms[plat] = (accPlatforms[plat] ?? 0) + 1;
          const t = i.instance_type || 'unknown';
          typeCounts[t] = (typeCounts[t] ?? 0) + 1;
        }
      }
      if (regionTotal > 0) {
        regionCounts[r.region] = (regionCounts[r.region] ?? 0) + regionTotal;
      }
    }
    accountRows.push({
      account_id: a.account_id,
      account_alias: a.account_alias || a.profile || a.account_id,
      profile: a.profile,
      total: accTotal,
      running: accRunning,
      stopped: accStopped,
      platforms: accPlatforms,
    });
  }

  return {
    summary: { total, running, stopped, platforms, accounts: accountRows },
    instanceTypes: Object.entries(typeCounts).map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count).slice(0, 10),
    regions: Object.entries(regionCounts).map(([region, count]) => ({ region, count })).sort((a, b) => b.count - a.count),
  };
}

export function FleetDashboard() {
  const [summary, setSummary] = useState<FleetSummary>(FALLBACK);
  const [instanceTypes, setInstanceTypes] = useState<Array<{ type: string; count: number }>>([]);
  const [regions, setRegions] = useState<Array<{ region: string; count: number }>>([]);
  const [loading, setLoading] = useState(false);
  const lastDiscoveryAt = useInstancesStore((s) => s.lastDiscoveryAt);
  const storeAccounts = useInstancesStore((s) => s.accounts);
  const userAWS = useAuthStore((s) => s.config?.aws_access_mode === 'user');
  const enableKubernetes = useSettingsStore((s) => s.enableKubernetes ?? true);
  const enableDatabases = useSettingsStore((s) => s.enableDatabases ?? true);

  const fetchData = useCallback(async () => {
    if (userAWS) {
      const computed = computeFromAccounts(storeAccounts);
      setSummary(computed.summary);
      setInstanceTypes(computed.instanceTypes);
      setRegions(computed.regions);
      return;
    }
    setLoading(true);
    const [sumResult, instResult] = await Promise.all([
      api.get<Partial<FleetSummary>>('/fleet-summary'),
      api.get<{ accounts: Array<{ regions: Array<{ region: string; groups: Array<{ instances: Array<{ instance_type: string; state: string }> }> }> }> }>('/instances'),
    ]);
    let summaryTotal = 0;
    if (sumResult.ok && sumResult.data) {
      const d = sumResult.data;
      summaryTotal = d.total ?? 0;
      setSummary({
        ...FALLBACK,
        ...d,
        accounts: Array.isArray(d.accounts) ? d.accounts : [],
        platforms: d.platforms ?? {},
      });
    }
    if (instResult.ok) {
      const typeCounts: Record<string, number> = {};
      const regionCounts: Record<string, number> = {};
      for (const a of instResult.data.accounts ?? []) {
        for (const r of a.regions ?? []) {
          let regionTotal = 0;
          for (const g of r.groups ?? []) {
            for (const i of g.instances ?? []) {
              const t = i.instance_type || 'unknown';
              typeCounts[t] = (typeCounts[t] ?? 0) + 1;
              regionTotal++;
            }
          }
          regionCounts[r.region] = (regionCounts[r.region] ?? 0) + regionTotal;
        }
      }
      setInstanceTypes(
        Object.entries(typeCounts).map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count).slice(0, 10),
      );
      setRegions(
        Object.entries(regionCounts).map(([region, count]) => ({ region, count })).sort((a, b) => b.count - a.count),
      );
    } else if (summaryTotal === 0 && storeAccounts.length > 0) {
      const computed = computeFromAccounts(storeAccounts);
      setSummary(computed.summary);
      setInstanceTypes(computed.instanceTypes);
      setRegions(computed.regions);
    }
    setLoading(false);
  }, [userAWS, storeAccounts]);

  useEffect(() => { void fetchData(); }, [lastDiscoveryAt, fetchData]);

  const linuxCount = useMemo(() => {
    const p = summary.platforms ?? {};
    return (p.linux ?? 0) + (p.rhel ?? 0) + (p.ubuntu ?? 0) + (p.suse ?? 0);
  }, [summary.platforms]);
  const windowsCount = summary.platforms?.windows ?? 0;

  const platformEntries = useMemo(() =>
    Object.entries(summary.platforms ?? {})
      .filter(([, v]) => typeof v === 'number' && v > 0)
      .map(([name, count]) => ({ name, count: count as number }))
      .sort((a, b) => b.count - a.count),
  [summary.platforms]);

  const sessions = useSessionsStore((s) => s.sessions);
  const favorites = useInstancesStore((s) => s.favorites);
  const favoriteInstances = useMemo(() => {
    if (favorites.length === 0 || storeAccounts.length === 0) return [];
    const favSet = new Set(favorites);
    const hits: Array<{ id: string; name: string; region: string; state: string }> = [];
    for (const a of storeAccounts) {
      for (const r of a.regions) {
        for (const g of r.groups) {
          for (const inst of g.instances) {
            if (favSet.has(inst.instance_id)) {
              hits.push({ id: inst.instance_id, name: inst.name, region: inst.aws_region, state: inst.state });
            }
          }
        }
      }
    }
    return hits.slice(0, 4);
  }, [favorites, storeAccounts]);

  return (
    <div className="p-5 sm:p-6 space-y-5 overflow-y-auto h-full">
      {/* Command Hub Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-wider text-text-dim mb-1">
            Resources · VMs
          </div>
          <h1 className="text-[20px] font-semibold tracking-tight text-text-pri">VM Fleet &amp; Command Hub</h1>
          <p className="text-[12px] text-text-sec mt-0.5">
            {summary.accounts.length} account{summary.accounts.length === 1 ? '' : 's'}
            {summary.scan_duration ? ` · fetched in ${summary.scan_duration}` : ''}
            {' · '}{regions.length} region{regions.length === 1 ? '' : 's'}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {enableKubernetes && (
            <Button
              variant="outline"
              size="sm"
              icon={<Boxes size={13} />}
              onClick={() => useLayoutStore.getState().setView('kubernetes')}
            >
              Kubernetes
            </Button>
          )}
          {enableDatabases && (
            <Button
              variant="outline"
              size="sm"
              icon={<Database size={13} />}
              onClick={() => useLayoutStore.getState().setView('databases')}
            >
              Databases
            </Button>
          )}
          {userAWS && (
            <Button
              variant="primary"
              size="sm"
              icon={<Plus size={13} />}
              onClick={connectCloud}
            >
              Connect account
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            icon={<RefreshCw size={13} className={loading ? 'animate-spin' : ''} />}
            onClick={() => (userAWS ? void useInstancesStore.getState().triggerDiscovery() : void fetchData())}
            disabled={loading}
            aria-label="Refresh"
          >
            Refresh
          </Button>
        </div>
      </div>

      {/* Inline Command Launcher */}
      <button
        type="button"
        onClick={() => usePaletteStore.getState().setOpen(true)}
        className="w-full rounded-[var(--radius-lg)] border border-border bg-surface hover:border-[var(--border-strong)] hover:bg-[var(--surface-hover)] px-3.5 py-2.5 flex items-center justify-between gap-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
      >
        <span className="flex items-center gap-2.5 text-[13px] text-text-mut min-w-0">
          <Search size={14} className="text-accent shrink-0" aria-hidden="true" />
          <span className="truncate">Connect to an instance, Kubernetes cluster, database schema, or command…</span>
        </span>
        <span className="flex items-center gap-1.5 shrink-0">
          <span className="hidden sm:inline px-2 py-0.5 rounded text-[10px] font-medium bg-[var(--accent-dim)] text-accent">SSH · RDP · K8s · SQL</span>
          <Kbd>⌘K</Kbd>
        </span>
      </button>

      {/* Active Sessions & Pinned Favorites Strip */}
      {(sessions.length > 0 || favoriteInstances.length > 0) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {sessions.length > 0 && (
            <div className="rounded-[var(--radius-lg)] border border-border bg-surface p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-text-dim">Active Sessions ({sessions.length})</span>
                <span className="text-[11px] text-accent">Jump back in</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {sessions.slice(0, 4).map((sess) => (
                  <button
                    key={sess.id}
                    type="button"
                    onClick={() => {
                      useSessionsStore.getState().setActive(sess.id);
                      useLayoutStore.getState().setView('session');
                    }}
                    className="inline-flex items-center gap-2 px-2.5 py-1.5 rounded-md border border-border bg-bg hover:border-accent text-[12px] transition-colors"
                  >
                    <span className={`w-1.5 h-1.5 rounded-full ${sess.status === 'error' ? 'bg-danger' : 'bg-success'}`} />
                    <span className="font-medium text-text-pri truncate max-w-[160px]">{sess.instanceName}</span>
                    <span className="font-mono text-[10px] uppercase text-text-dim">{sess.type}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {favoriteInstances.length > 0 && (
            <div className="rounded-[var(--radius-lg)] border border-border bg-surface p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-text-dim">Pinned Favorites</span>
                <span className="text-[11px] text-text-dim">Quick connect</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {favoriteInstances.map((fav) => (
                  <button
                    key={fav.id}
                    type="button"
                    onClick={() => window.dispatchEvent(new CustomEvent('ct:open-ssh', { detail: { instanceId: fav.id, instanceName: fav.name } }))}
                    className="inline-flex items-center gap-2 px-2.5 py-1.5 rounded-md border border-border bg-bg hover:border-accent text-[12px] transition-colors"
                  >
                    <span className={`w-1.5 h-1.5 rounded-full ${fav.state === 'running' ? 'bg-success' : 'bg-text-dim'}`} />
                    <span className="font-medium text-text-pri truncate max-w-[150px]">{fav.name}</span>
                    <span className="font-mono text-[10px] text-text-dim">{fav.region}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* 4-Up Version A KPI Telemetry Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {loading && summary.total === 0 ? (
          <>
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
          </>
        ) : (
          <>
            <StatTile
              label="Running"
              value={summary.total === 0 ? '—' : String(summary.running)}
              delta={summary.total > 0 ? `${Math.round((summary.running / summary.total) * 100)}% of fleet` : undefined}
              accent="success"
              icon={<Play size={14} />}
              sparkline="M2,18 L14,15 L26,14 L38,11 L50,8 L66,5"
            />
            <StatTile
              label="Stopped"
              value={summary.total === 0 ? '—' : String(summary.stopped)}
              delta={summary.total > 0 ? `${Math.round((summary.stopped / summary.total) * 100)}% of fleet` : undefined}
              accent="danger"
              icon={<Square size={14} />}
              sparkline="M2,8 L14,10 L26,9 L38,12 L50,13 L66,15"
            />
            <StatTile
              label="Total"
              value={summary.total === 0 ? '—' : String(summary.total)}
              delta={summary.total > 0 ? `${linuxCount} Linux · ${windowsCount} Windows` : undefined}
              accent="accent"
              icon={<Server size={14} />}
              sparkline="M2,14 L14,12 L26,12 L38,9 L50,7 L66,6"
            />
            <StatTile
              label="Active Sessions"
              value={String(sessions.length)}
              delta={sessions.length > 0 ? 'SSH & RDP tunnels live' : 'Ready for zero-trust connect'}
              accent="info"
              icon={<Terminal size={14} />}
              sparkline="M2,17 L14,14 L26,16 L38,9 L50,11 L66,7"
            />
          </>
        )}
      </div>

      <AccountsBreakdown
        accounts={summary.accounts}
        loading={loading}
        onSelectAccount={(alias) => {
          useInstancesStore.getState().setFilter(alias);
          if (useLayoutStore.getState().sidebarCollapsed) useLayoutStore.getState().toggleSidebar();
        }}
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="bg-surface rounded-[var(--radius-lg)] border border-border overflow-hidden">
          <div className="px-4 py-2.5 border-b border-border flex items-center gap-2">
            <Server size={13} className="text-text-dim" />
            <span className="text-[12px] font-semibold text-text-pri">Platform Distribution</span>
          </div>
          {platformEntries.length === 0 ? (
            <div className="px-4 py-6 text-center text-[12px] text-text-dim">No data</div>
          ) : (
            <div className="p-4 space-y-2.5">
              {platformEntries.map((p) => {
                const pct = summary.total > 0 ? (p.count / summary.total) * 100 : 0;
                return (
                  <div key={p.name} className="flex items-center gap-3 text-[12px]">
                    <span className="w-20 flex items-center gap-1.5 text-text-pri font-semibold uppercase">
                      <PlatformIcon platform={p.name as Platform} size={14} />
                      {p.name}
                    </span>
                    <div className="flex-1 h-2 rounded-full bg-border overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{ width: `${pct}%`, background: PLATFORM_COLORS[p.name] ?? 'var(--text-dim)' }}
                      />
                    </div>
                    <span className="w-8 text-right font-mono tabular-nums text-text-pri font-medium">{p.count}</span>
                    <span className="w-10 text-right text-text-dim">{pct < 1 && pct > 0 ? pct.toFixed(1) : pct.toFixed(0)}%</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="bg-surface rounded-[var(--radius-lg)] border border-border overflow-hidden">
          <div className="px-4 py-2.5 border-b border-border flex items-center gap-2">
            <Globe size={13} className="text-text-dim" />
            <span className="text-[12px] font-semibold text-text-pri">Region Distribution</span>
          </div>
          {regions.length === 0 ? (
            <div className="px-4 py-6 text-center text-[12px] text-text-dim">No data</div>
          ) : (
            <div className="p-4 space-y-2.5">
              {regions.map((r) => {
                const pct = summary.total > 0 ? (r.count / summary.total) * 100 : 0;
                return (
                  <button
                    key={r.region}
                    type="button"
                    onClick={() => {
                      useInstancesStore.getState().setFilter(r.region);
                      if (useLayoutStore.getState().sidebarCollapsed) useLayoutStore.getState().toggleSidebar();
                    }}
                    title={`Filter instances in ${r.region}`}
                    className="w-full flex items-center gap-3 text-[12px] rounded-[var(--radius-sm)] px-1 -mx-1 py-0.5 hover:bg-[var(--surface-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] transition-colors text-left"
                  >
                    <span className="w-24 font-mono text-text-pri font-medium truncate">{r.region}</span>
                    <div className="flex-1 h-2 rounded-full bg-border overflow-hidden">
                      <div className="h-full rounded-full bg-accent transition-all" style={{ width: `${pct}%` }} />
                    </div>
                    <span className="w-8 text-right font-mono tabular-nums text-text-pri font-medium">{r.count}</span>
                    <span className="w-10 text-right text-text-dim">{pct < 1 && pct > 0 ? pct.toFixed(1) : pct.toFixed(0)}%</span>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        <div className="bg-surface rounded-[var(--radius-lg)] border border-border overflow-hidden">
          <div className="px-4 py-2.5 border-b border-border flex items-center gap-2">
            <Cpu size={13} className="text-text-dim" />
            <span className="text-[12px] font-semibold text-text-pri">Top VM Types</span>
            <span className="text-[10px] text-text-dim ml-auto">{instanceTypes.length} shown</span>
          </div>
          {instanceTypes.length === 0 ? (
            <div className="px-4 py-6 text-center text-[12px] text-text-dim">No data</div>
          ) : (
            <div className="divide-y divide-border">
              {instanceTypes.slice(0, 6).map((t) => (
                <div key={t.type} className="flex items-center justify-between px-4 py-2 hover:bg-elev/50 transition-colors">
                  <span className="text-[12px] font-mono text-text-pri">{t.type}</span>
                  <span className="text-[12px] font-mono tabular-nums text-text-mut">{t.count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
