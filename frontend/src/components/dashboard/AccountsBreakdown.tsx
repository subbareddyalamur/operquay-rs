import { useMemo } from 'react';
import { Users } from 'lucide-react';
import { PlatformIcon } from '@/components/primitives/PlatformIcon';
import { EmptyState, SkeletonRow } from '@/components/primitives';
import type { Platform } from '@/lib/platform';
import { PLATFORM_COLORS, type AccountRow } from './FleetDashboard';

interface AccountsBreakdownProps {
  accounts: AccountRow[];
  loading?: boolean;
  onSelectAccount?: (accountAlias: string) => void;
}

const PLATFORM_DISPLAY_ORDER = ['rhel', 'windows', 'linux', 'ubuntu', 'amazon-linux', 'suse', 'debian', 'centos', 'fedora'];

function PlatformBar({ platforms, total }: { platforms: Record<string, number | undefined> | undefined; total: number }) {
  const entries = useMemo(() => {
    if (!platforms || total === 0) return [];
    return Object.entries(platforms)
      .filter(([, v]) => typeof v === 'number' && v > 0)
      .map(([k, v]) => ({ name: k, count: v as number, pct: ((v as number) / total) * 100 }))
      .sort((a, b) => b.count - a.count);
  }, [platforms, total]);

  if (entries.length === 0) return <span className="text-[10px] text-text-dim">—</span>;

  return (
    <div className="flex h-1.5 rounded-full overflow-hidden bg-border w-full max-w-[80px]">
      {entries.map((e) => (
        <div
          key={e.name}
          style={{ width: `${e.pct}%`, background: PLATFORM_COLORS[e.name] ?? 'var(--text-dim)' }}
          title={`${e.name}: ${e.count}`}
        />
      ))}
    </div>
  );
}

export function AccountsBreakdown({ accounts, loading = false, onSelectAccount }: AccountsBreakdownProps) {
  const platformKeys = useMemo(() => {
    const seen = new Set<string>();
    for (const a of accounts) {
      for (const [k, v] of Object.entries(a.platforms ?? {})) {
        if (typeof v === 'number' && v > 0) seen.add(k);
      }
    }
    return PLATFORM_DISPLAY_ORDER.filter((p) => seen.has(p)).concat(
      [...seen].filter((p) => !PLATFORM_DISPLAY_ORDER.includes(p)).sort(),
    );
  }, [accounts]);

  return (
    <div className="bg-surface rounded-[var(--radius-lg)] border border-border overflow-hidden">
      <div className="px-4 py-2.5 border-b border-border flex items-center gap-2">
        <Users size={13} className="text-text-dim" aria-hidden="true" />
        <span className="text-[12px] font-semibold text-text-pri">Accounts</span>
        <span className="text-[10px] text-text-dim ml-auto">
          {accounts.length} account{accounts.length === 1 ? '' : 's'}
        </span>
      </div>
      {loading && accounts.length === 0 ? (
        <div className="py-1">
          <SkeletonRow />
          <SkeletonRow />
          <SkeletonRow />
        </div>
      ) : accounts.length === 0 ? (
        <div className="p-3">
          <EmptyState
            size="sm"
            icon={<Users size={15} aria-hidden="true" />}
            title="No accounts configured"
            description="Add an AWS account in Settings or connect a role to populate your fleet."
          />
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-[12px]">
            <thead>
              <tr className="border-b border-border bg-elev/60 text-[10px] uppercase tracking-wide text-text-dim">
                <th className="px-4 py-2 text-left font-bold">Account</th>
                <th className="px-3 py-2 text-right font-bold w-14">Total</th>
                <th className="px-3 py-2 text-right font-bold w-14">Running</th>
                <th className="px-3 py-2 text-right font-bold w-14">Stopped</th>
                {platformKeys.map((p) => (
                  <th key={p} className="px-2 py-2 text-right font-bold w-12 uppercase">
                    <span className="flex items-center justify-end gap-1">
                      <PlatformIcon platform={p as Platform} size={11} />
                      {p.toUpperCase()}
                    </span>
                  </th>
                ))}
                <th className="px-3 py-2 text-left font-bold w-24">Mix</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {accounts.map((a) => (
                <tr
                  key={a.account_id}
                  onClick={onSelectAccount ? () => onSelectAccount(a.account_alias) : undefined}
                  title={onSelectAccount ? `Filter instances to ${a.account_alias}` : undefined}
                  className={`transition-colors ${onSelectAccount ? 'cursor-pointer hover:bg-[var(--surface-hover)]' : 'hover:bg-elev/50'}`}
                >
                  <td className="px-4 py-1.5">
                    <div className="flex flex-col gap-0.5">
                      <span className="text-text-pri font-semibold text-[12px]">{a.account_alias}</span>
                      <span className="text-[10px] text-text-mut font-mono tracking-wide">{a.account_id}</span>
                    </div>
                  </td>
                  <td className="px-3 py-1.5 text-right text-text-mut font-mono tabular-nums">
                    {a.total}
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono tabular-nums">
                    <span className="text-success font-semibold">{a.running}</span>
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono tabular-nums">
                    <span className="text-danger font-semibold">{a.stopped}</span>
                  </td>
                  {platformKeys.map((p) => (
                    <td key={p} className="px-2 py-1.5 text-right font-mono tabular-nums text-text-mut">
                      {(a.platforms?.[p] ?? 0) > 0 ? (
                        <span style={{ color: PLATFORM_COLORS[p] }} className="font-semibold">
                          {a.platforms?.[p] ?? 0}
                        </span>
                      ) : (
                        <span className="text-text-dim opacity-40">0</span>
                      )}
                    </td>
                  ))}
                  <td className="px-3 py-1.5">
                    <PlatformBar platforms={a.platforms} total={a.total} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
