import { memo, type KeyboardEvent } from 'react';
import { ChevronRight, ChevronDown } from 'lucide-react';
import { useInstancesStore } from '@/stores/instances';
import type { AccountNode } from '@/lib/types';
import { Tooltip } from '@/components/primitives/Tooltip';
import { cloudKey, CloudMark } from './CloudMark';
import { RegionGroup } from './RegionGroup';

export interface AccountGroupProps {
  account: AccountNode;
}

export const AccountGroup = memo(function AccountGroup({ account }: AccountGroupProps) {
  const isOpen = useInstancesStore((s) => !!s.expanded[`account:${account.account_id}`]);
  const toggle = useInstancesStore((s) => s.toggleExpand);

  const allInstances = account.regions.flatMap((r) => r.groups.flatMap((g) => g.instances));
  const runningCount = allInstances.filter((i) => i.state === 'running').length;
  const displayName = account.account_alias || account.profile;

  const handleClick = () => toggle(`account:${account.account_id}`);
  const handleKey = (e: KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      toggle(`account:${account.account_id}`);
    }
  };

  return (
    <div
      className={`account-group rounded-xl border transition-all duration-150 ${
        isOpen
          ? 'border-accent/40 bg-surface/90 shadow-sm'
          : 'border-transparent hover:border-border/60 hover:bg-surface/50'
      }`}
    >
      <Tooltip
        onlyWhenTruncated
        side="right"
        sideOffset={8}
        delay={160}
        content={
          <div className="flex flex-col gap-0.5">
            <span className="text-[12px] font-semibold text-[var(--text-pri)] break-words">{displayName}</span>
            <span className="text-[11px] font-mono text-[var(--accent)]">{account.account_id}</span>
            <span className="text-[11px] font-mono text-[var(--text-dim)]">
              {runningCount} on · {allInstances.length} instances
            </span>
          </div>
        }
      >
        <button
          type="button"
          className="w-full px-2 py-1 rounded-lg text-left flex items-center gap-2 group transition-colors"
          aria-expanded={isOpen}
          onClick={handleClick}
          onKeyDown={handleKey}
        >
          <span className="w-4 h-4 rounded flex items-center justify-center text-text-dim group-hover:text-text-pri shrink-0">
            {isOpen ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          </span>

          <div className="relative shrink-0 flex items-center justify-center">
            <div
              className={`w-5 h-5 rounded-md flex items-center justify-center border ${
                isOpen
                  ? 'bg-accent/15 border-accent/40 text-accent'
                  : runningCount > 0
                    ? 'bg-success/15 border-success/40 text-success'
                    : 'bg-elev border-border text-text-mut'
              }`}
            >
              <CloudMark provider={cloudKey(account.provider)} compact />
            </div>
            {runningCount > 0 && (
              <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-success ring-2 ring-bg" />
            )}
          </div>

          <div className="min-w-0 flex-1">
            <div data-truncate className="text-[12px] font-medium text-text-pri truncate">
              {displayName}
            </div>
            {isOpen && (
              <div data-truncate className="text-[11px] font-mono text-text-dim truncate mt-0.5">
                {account.account_id}
              </div>
            )}
          </div>

          <span
            className={`text-[10px] font-mono px-1.5 py-0.5 rounded border shrink-0 font-medium tabular-nums ${
              isOpen
                ? 'bg-accent/15 border-accent/30 text-accent'
                : runningCount > 0
                  ? 'bg-success/15 border-success/30 text-success'
                  : 'bg-elev border-border text-text-mut'
            }`}
          >
            {runningCount} on
          </span>
        </button>
      </Tooltip>

      {isOpen && (
        <div className="ml-4 pl-2.5 my-1 pb-1.5 border-l border-border/60 space-y-0.5">
          {account.regions.map((r) => (
            <RegionGroup key={r.region} accountId={account.account_id} region={r} />
          ))}
        </div>
      )}
    </div>
  );
});
