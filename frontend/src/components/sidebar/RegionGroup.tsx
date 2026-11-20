import { memo, type KeyboardEvent } from 'react';
import { ChevronRight, ChevronDown, Folder } from 'lucide-react';
import { useInstancesStore } from '@/stores/instances';
import type { RegionNode, TagGroup } from '@/lib/types';
import { Tooltip } from '@/components/primitives/Tooltip';
import { VirtualInstanceList } from './VirtualInstanceList';
import { envTone } from '@/lib/env';

function getTagBadgeClass(label: string): string {
  const env = label.split('/').pop()?.trim() ?? label;
  return envTone(env);
}

function getShortTag(label: string): string {
  return label.split('/').pop()?.trim() || label;
}

interface TagSectionProps {
  accountId: string;
  regionKey: string;
  group: TagGroup;
}

const TagSection = memo(function TagSection({ accountId, regionKey, group }: TagSectionProps) {
  const label = [group.tag1, group.tag2].filter(Boolean).join(' / ');
  const expandKey = `tag:${accountId}:${regionKey}:${label}`;
  const isOpen = useInstancesStore((s) => {
    const val = s.expanded[expandKey];
    return val === undefined ? true : !!val;
  });

  if (!label) {
    return <VirtualInstanceList instances={group.instances} />;
  }

  const handleClick = () => {
    useInstancesStore.setState((s) => ({
      expanded: { ...s.expanded, [expandKey]: !isOpen },
    }));
  };
  const handleKey = (e: KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handleClick();
    }
  };

  return (
    <div className="space-y-0.5">
      <button
        type="button"
        className="w-full flex items-center gap-1.5 px-2 py-0.5 rounded hover:bg-surface group/tag text-left"
        onClick={handleClick}
        onKeyDown={handleKey}
        aria-expanded={isOpen}
      >
        {isOpen ? (
          <ChevronDown size={10} className="text-text-dim shrink-0" />
        ) : (
          <ChevronRight size={10} className="text-text-dim shrink-0" />
        )}
        <span
          className={`text-[10.5px] font-medium uppercase tracking-[0.04em] truncate ${getTagBadgeClass(label)}`}
        >
          {label}
        </span>
        <span className="ml-auto text-[10px] font-mono text-text-dim shrink-0">{group.instances.length}</span>
      </button>
      {isOpen && <VirtualInstanceList instances={group.instances} />}
    </div>
  );
});

interface Props {
  accountId: string;
  region: RegionNode;
}

export const RegionGroup = memo(function RegionGroup({ accountId, region }: Props) {
  const isOpen = useInstancesStore((s) => !!s.expanded[`region:${accountId}:${region.region}`]);
  const toggle = useInstancesStore((s) => s.toggleExpand);

  const allInstances = region.groups.flatMap((g) => g.instances);
  const runningCount = allInstances.filter((i) => i.state === 'running').length;

  // V2 Compact Density: fold single tag label onto the region folder row (e.g. "ap-south-1 · PERF")
  const singleGroup = region.groups.length === 1 ? region.groups[0] : null;
  const singleLabel = singleGroup ? [singleGroup.tag1, singleGroup.tag2].filter(Boolean).join(' / ') : '';
  const shortTag = singleLabel ? getShortTag(singleLabel) : '';
  const folderTitle = shortTag ? `${region.region} · ${shortTag}` : region.region;

  const handleClick = () => toggle(`region:${accountId}:${region.region}`);
  const handleKey = (e: KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      toggle(`region:${accountId}:${region.region}`);
    }
  };

  return (
    <div className="space-y-0.5">
      <Tooltip
        onlyWhenTruncated
        side="right"
        sideOffset={8}
        delay={160}
        content={
          <div className="flex flex-col gap-0.5">
            <span className="font-mono text-[12px] font-semibold text-[var(--text-pri)]">{folderTitle}</span>
            {singleLabel && singleLabel !== shortTag && (
              <span className="text-[11px] text-[var(--text-dim)]">{singleLabel}</span>
            )}
            <span className="text-[11px] font-mono text-[var(--text-dim)]">
              {runningCount} on · {allInstances.length} total
            </span>
          </div>
        }
      >
        <button
          type="button"
          className="w-full flex items-center gap-1.5 px-2 py-0.5 rounded-md text-left hover:bg-surface transition-colors text-[12px]"
          aria-expanded={isOpen}
          onClick={handleClick}
          onKeyDown={handleKey}
        >
          <span className="text-text-dim shrink-0">
            {isOpen ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
          </span>
          <Folder size={13} className="shrink-0 text-text-dim opacity-80" aria-hidden="true" />
          <span data-truncate className="flex-1 min-w-0 font-mono text-text-pri truncate">
            {folderTitle}
          </span>
          <span className="text-[10px] text-text-dim font-mono shrink-0 tabular-nums">
            {allInstances.length}
          </span>
        </button>
      </Tooltip>

      {isOpen && (
        <div className="pl-3 pr-1 space-y-0.5 border-l border-border/40 ml-2.5 my-0.5">
          {singleGroup ? (
            <VirtualInstanceList instances={singleGroup.instances} showEnvPill={!shortTag} />
          ) : (
            region.groups.map((group) => {
              const key = `${group.tag1}:${group.tag2}`;
              return (
                <TagSection
                  key={key}
                  accountId={accountId}
                  regionKey={region.region}
                  group={group}
                />
              );
            })
          )}
        </div>
      )}
    </div>
  );
});
