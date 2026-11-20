import { memo, type MouseEvent } from 'react';
import { Star, MoreHorizontal } from 'lucide-react';
import { matchField } from '@/lib/filter';
import type { EC2Instance } from '@/lib/types';
import { PlatformIcon } from '@/components/primitives/PlatformIcon';
import { Tooltip } from '@/components/primitives/Tooltip';
import { detectPlatform } from '@/lib/platform';
import { useInstancesStore } from '@/stores/instances';
import { openContextMenu } from './InstanceContextMenu';
import { envTone } from '@/lib/env';
import { useAuthStore, hasPermission } from '@/stores/auth';
import { cloudKey, cloudNames, CloudMark } from './CloudMark';

export interface InstanceRowProps {
  instance: EC2Instance;
  showAccount?: boolean;
  showEnvPill?: boolean;
  provider?: string;
  onActivate?: (inst: EC2Instance) => void;
}

function dotClass(state: string): string {
  if (state === 'running') return 'bg-success';
  if (state === 'stopped') return 'border border-text-dim';
  return 'bg-text-mut';
}

export const InstanceRow = memo(function InstanceRow({
  instance,
  showAccount,
  showEnvPill = true,
  provider,
}: InstanceRowProps) {
  const isFav = useInstancesStore((s) => s.favorites.includes(instance.instance_id));
  const isSelected = useInstancesStore((s) => s.selectedId === instance.instance_id);
  const filter = useInstancesStore((s) => s.filter);
  const matched = filter ? matchField(instance, filter) : null;
  const toggleFav = useInstancesStore((s) => s.toggleFavorite);
  const setSelected = useInstancesStore((s) => s.setSelected);
  const readonly = useAuthStore((s) =>
    Boolean(s.me) && !hasPermission(s.me, 'session:ssh') && !hasPermission(s.me, 'session:rdp')
  );

  const platform = detectPlatform({ Platform: instance.platform, PlatformDetails: instance.os });
  const envRaw = instance.tags?.['Environment'] ?? instance.tags?.['environment'] ?? instance.tag2_value ?? '';
  const fullName = instance.name || instance.instance_id;

  const handleContextMenu = (e: MouseEvent<HTMLDivElement>) => {
    e.preventDefault();
    openContextMenu({ x: e.clientX, y: e.clientY, instance });
  };

  const handleClick = () => {
    setSelected(instance.instance_id);
    if (readonly) {
      window.dispatchEvent(new CustomEvent('ct:show-details', { detail: { instanceId: instance.instance_id } }));
      return;
    }
    window.dispatchEvent(
      new CustomEvent('ct:open-ssh', {
        detail: {
          instanceId: instance.instance_id,
          instanceName: instance.name,
          accountId: instance.account_id,
          region: instance.aws_region,
        },
      }),
    );
  };

  const handleStarClick = (e: MouseEvent<HTMLButtonElement>) => {
    e.stopPropagation();
    toggleFav(instance.instance_id);
  };

  const hoverContent = (
    <div className="flex flex-col gap-0.5 min-w-0">
      <div className="text-[12px] font-semibold text-[var(--text-pri)] break-all">{fullName}</div>
      <div className="flex items-center gap-1.5 text-[11px] font-mono text-[var(--accent)]">
        <span>{instance.instance_id}</span>
        {instance.instance_type && (
          <span className="text-[var(--text-dim)]">· {instance.instance_type}</span>
        )}
      </div>
      <div className="text-[11px] text-[var(--text-dim)] font-mono">
        {instance.state}
        {instance.private_ip ? ` · ${instance.private_ip}` : ''}
        {envRaw ? ` · ${envRaw.toUpperCase()}` : ''}
      </div>
    </div>
  );

  return (
    <Tooltip content={hoverContent} side="right" sideOffset={8} delay={160}>
      <div
        className={`group flex items-center gap-1.5 px-2 py-0.5 rounded text-left text-[12px] cursor-pointer transition-colors focus-visible:outline-2 focus-visible:outline-accent ${
          isSelected
            ? 'bg-accent/15 text-accent font-medium border border-accent/30'
            : 'text-text-mut hover:text-text-pri hover:bg-surface border border-transparent'
        }`}
        onClick={handleClick}
        onContextMenu={handleContextMenu}
        onKeyDown={(e) => {
          if (e.target === e.currentTarget && (e.key === 'Enter' || e.key === ' ')) {
            e.preventDefault();
            handleClick();
          }
        }}
        role="option"
        aria-selected={isSelected}
        tabIndex={0}
      >
        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotClass(instance.state)}`} aria-label={instance.state} />
        <PlatformIcon platform={platform} size={13} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5 min-w-0">
            <span
              data-truncate
              className={`text-[12px] truncate flex-1 min-w-0 ${
                isSelected
                  ? 'text-accent font-medium'
                  : instance.state === 'running'
                    ? 'text-text-pri font-medium'
                    : 'text-text-mut'
              }`}
            >
              {fullName}
            </span>
            {showEnvPill && envRaw && (
              <span className={`font-mono text-[10px] uppercase px-1 py-0.2 rounded border border-border/40 shrink-0 ${envTone(envRaw)}`}>
                {envRaw}
              </span>
            )}
          </div>
          {(showAccount || (matched && matched !== 'name')) && (
            <div className="flex items-center gap-2 text-[10.5px] font-mono text-text-dim min-w-0">
              {matched && matched !== 'name' && <span className="text-accent shrink-0">matched {matched}</span>}
              {showAccount && (
                <span className="flex items-center gap-1 truncate">
                  <CloudMark provider={cloudKey(provider)} compact /> {cloudNames[cloudKey(provider)] || 'Unknown cloud'} · {instance.account_alias}
                </span>
              )}
            </div>
          )}
        </div>

        <button
          type="button"
          className="shrink-0 opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 focus:opacity-100 text-text-dim hover:text-text-pri transition-opacity"
          onClick={(e) => {
            e.stopPropagation();
            const rect = e.currentTarget.getBoundingClientRect();
            openContextMenu({ x: rect.right, y: rect.bottom, instance });
          }}
          aria-label="More actions"
          title="More actions"
        >
          <MoreHorizontal size={13} />
        </button>

        <button
          type="button"
          className={`shrink-0 transition-opacity ${
            isFav ? 'text-warn opacity-100' : 'opacity-0 group-hover:opacity-100 group-focus-within:opacity-100'
          }`}
          onClick={handleStarClick}
          aria-label={isFav ? 'Remove from favorites' : 'Add to favorites'}
        >
          <Star size={11} fill={isFav ? 'currentColor' : 'none'} />
        </button>
      </div>
    </Tooltip>
  );
});
