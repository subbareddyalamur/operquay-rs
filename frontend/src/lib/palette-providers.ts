import { createElement, type ReactNode } from 'react';
import type { EC2Instance } from '@/lib/types';
import { PlatformIcon } from '@/components/primitives/PlatformIcon';
import { detectPlatform } from '@/lib/platform';

export type PaletteItemKind = 'instance' | 'command' | 'snippet' | 'session';

export interface PaletteItem {
  id: string;
  kind: PaletteItemKind;
  title: string;
  subtitle?: string;
  icon?: ReactNode;
  kbd?: string;
  action: () => void;
}

export interface PaletteGroup {
  label: string;
  items: PaletteItem[];
}

export interface PaletteContext {
  instances: EC2Instance[];
  favoriteIds: string[];
  recentSessions: Array<{ id: string; instanceName: string; type: string; createdAt: number }>;
  onSSH: (instanceId: string, instanceName: string) => void;
  onRDP: (instanceId: string, instanceName: string) => void;
  onDetails?: (instanceId: string, instanceName: string) => void;
  onSelectSession?: (sessionId: string) => void;
  onOpenSettings: () => void;
  onToggleAI: () => void;
  assistantName: string;
  onCycleTheme: () => void;
  enableKubernetes?: boolean;
  enableDatabases?: boolean;
  onSwitchWorkspace?: (view: 'session' | 'kubernetes' | 'databases') => void;
  onToggleSidebar?: () => void;
  onRefetch?: () => void;
  onOpenAudit?: () => void;
  onOpenRecordings?: () => void;
  onOpenCloudConnections?: () => void;
}

export function buildPaletteGroups(
  query: string,
  ctx: PaletteContext,
): PaletteGroup[] {
  const q = query.trim().toLowerCase();
  const tokens = q.split(/\s+/).filter(Boolean);
  const groups: PaletteGroup[] = [];
  const favSet = new Set(ctx.favoriteIds);

  const instanceItems: PaletteItem[] = ctx.instances
    .filter((inst) => {
      if (tokens.length === 0) return true;
      const tagEntries = inst.tags
        ? Object.entries(inst.tags).flatMap(([k, v]) => [k, v])
        : [];
      const hay = [
        inst.name,
        inst.instance_id,
        inst.private_ip ?? '',
        inst.public_ip ?? '',
        inst.instance_type ?? '',
        inst.account_alias,
        inst.account_id,
        inst.aws_region,
        ...tagEntries,
      ]
        .join(' ')
        .toLowerCase();
      return tokens.every((t) => hay.includes(t));
    })
    .sort((a, b) => Number(favSet.has(b.instance_id)) - Number(favSet.has(a.instance_id)))
    .slice(0, 8)
    .map((inst) => ({
      id: `inst-${inst.instance_id}`,
      kind: 'instance' as PaletteItemKind,
      title: inst.name,
      subtitle: `${favSet.has(inst.instance_id) ? '★ ' : ''}${inst.instance_id} · ${inst.instance_type ?? inst.platform} · ${inst.aws_region} · ${inst.private_ip ?? '—'}`,
      icon: createElement(PlatformIcon, { platform: detectPlatform({ Platform: inst.platform, PlatformDetails: inst.os }), size: 14 }),
      action: () => ctx.onSSH(inst.instance_id, inst.name),
    }));

  if (instanceItems.length > 0) {
    groups.push({ label: 'Instances', items: instanceItems });
  }

  const recentItems: PaletteItem[] = ctx.recentSessions
    .filter((s) => !q || s.instanceName.toLowerCase().includes(q) || s.type.toLowerCase().includes(q))
    .slice(0, 5)
    .map((s) => ({
      id: `recent-${s.id}`,
      kind: 'session' as PaletteItemKind,
      title: s.instanceName,
      subtitle: `Switch to ${(s.type ?? 'ssh').toUpperCase()} session`,
      action: () => ctx.onSelectSession?.(s.id),
    }));

  if (recentItems.length > 0) {
    groups.push({ label: 'Active Sessions', items: recentItems });
  }

  const candidateCommands: Array<PaletteItem & { keywords?: string }> = [
    ...(ctx.onSwitchWorkspace
      ? [
          { id: 'cmd-ws-instances', kind: 'command' as const, title: 'Switch to VMs workspace', subtitle: 'Infrastructure fleet & sessions', keywords: 'workspace vms instances ssh rdp overview ec2', action: () => ctx.onSwitchWorkspace?.('session') },
          ...(ctx.enableKubernetes !== false
            ? [{ id: 'cmd-ws-k8s', kind: 'command' as const, title: 'Switch to Kubernetes workspace', subtitle: 'Clusters, workloads, pods & logs', keywords: 'workspace eks k8s pods', action: () => ctx.onSwitchWorkspace?.('kubernetes') }]
            : []),
          ...(ctx.enableDatabases !== false
            ? [{ id: 'cmd-ws-db', kind: 'command' as const, title: 'Switch to Databases workbench', subtitle: 'SQL IDE, schema explorer & SSM tunnels', keywords: 'workspace db sql dbeaver postgres mysql rds', action: () => ctx.onSwitchWorkspace?.('databases') }]
            : []),
        ]
      : []),
    ...(ctx.onToggleSidebar
      ? [{ id: 'cmd-sidebar', kind: 'command' as const, title: 'Toggle instance sidebar', kbd: '⌘B', keywords: 'hide show panel', action: ctx.onToggleSidebar }]
      : []),
    { id: 'cmd-ai', kind: 'command', title: `Ask ${ctx.assistantName}`, kbd: '⌘/', keywords: 'ai assistant chat', action: ctx.onToggleAI },
    ...(ctx.onRefetch
      ? [{ id: 'cmd-refetch', kind: 'command' as const, title: 'Fetch cloud inventory', subtitle: 'Refresh AWS accounts & instances', keywords: 'refresh sync discover fetch', action: ctx.onRefetch }]
      : []),
    ...(ctx.onOpenCloudConnections
      ? [{ id: 'cmd-clouds', kind: 'command' as const, title: 'Manage cloud connections', subtitle: 'Connect or inspect AWS roles', keywords: 'aws sso roles', action: ctx.onOpenCloudConnections }]
      : []),
    ...(ctx.onOpenAudit
      ? [{ id: 'cmd-audit', kind: 'command' as const, title: 'Open Audit Log', subtitle: 'Security & access audit trail', keywords: 'security events logs', action: ctx.onOpenAudit }]
      : []),
    ...(ctx.onOpenRecordings
      ? [{ id: 'cmd-recordings', kind: 'command' as const, title: 'Open Session Recordings', kbd: '⌘⇧R', subtitle: 'Review recorded SSH, RDP & K8s sessions', keywords: 'video replay', action: ctx.onOpenRecordings }]
      : []),
    { id: 'cmd-settings', kind: 'command', title: 'Open Settings', kbd: '⌘,', keywords: 'preferences config sso users', action: ctx.onOpenSettings },
    { id: 'cmd-theme', kind: 'command', title: 'Switch theme', subtitle: 'Toggle between Dark and Light mode', keywords: 'dark light appearance', action: ctx.onCycleTheme },
  ];

  const commandItems: PaletteItem[] = candidateCommands
    .filter((c) => {
      if (tokens.length === 0) return true;
      const hay = `${c.title} ${c.subtitle ?? ''} ${c.keywords ?? ''}`.toLowerCase();
      return tokens.every((t) => hay.includes(t));
    })
    .map(({ keywords: _k, ...rest }) => rest);

  if (commandItems.length > 0) {
    groups.push({ label: 'Commands', items: commandItems });
  }

  return groups;
}
