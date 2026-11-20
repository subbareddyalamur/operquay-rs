import { useEffect, useState } from 'react';
import { Command, Search, X } from 'lucide-react';
import { type WorkspaceTab } from '../platform/store';

export interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  onNavigate: (tab: WorkspaceTab) => void;
  onToggleTheme: () => void;
}

const COMMANDS: Array<{ id: string; label: string; category: string; action: (props: CommandPaletteProps) => void }> = [
  { id: 'nav-cloud', label: 'Open Cloud Fleet & AWS Workspace', category: 'Navigate', action: (p) => p.onNavigate('cloud') },
  { id: 'nav-term', label: 'Open Pure-Rust WASM Terminal & AI Agent', category: 'Navigate', action: (p) => p.onNavigate('terminal') },
  { id: 'nav-desktop', label: 'Open Remote Desktop Session (RDP / VNC)', category: 'Navigate', action: (p) => p.onNavigate('desktop') },
  { id: 'nav-k8s', label: 'Open Kubernetes Multi-Cluster & Teleport', category: 'Navigate', action: (p) => p.onNavigate('kubernetes') },
  { id: 'nav-db', label: 'Open PostgreSQL Database Explorer', category: 'Navigate', action: (p) => p.onNavigate('databases') },
  { id: 'nav-topo', label: 'Open VPC Network Topology & Reachability Analyzer', category: 'Navigate', action: (p) => p.onNavigate('topology') },
  { id: 'nav-settings', label: 'Open Remote Desktop & Protocol Settings', category: 'Navigate', action: (p) => p.onNavigate('settings') },
  { id: 'nav-audit', label: 'Open Recordings & Audit Ledger', category: 'Navigate', action: (p) => p.onNavigate('audit') },
  { id: 'nav-admin', label: 'Open Enterprise IAM, RBAC & License Console', category: 'Navigate', action: (p) => p.onNavigate('admin') },
  { id: 'theme-toggle', label: 'Toggle Dark / Light Theme', category: 'Appearance', action: (p) => p.onToggleTheme() },
];

export function CommandPalette(props: CommandPaletteProps) {
  const { open, onClose } = props;
  const [query, setQuery] = useState('');

  useEffect(() => {
    if (!open) setQuery('');
  }, [open]);

  if (!open) return null;

  const q = query.trim().toLowerCase();
  const filtered = COMMANDS.filter((c) => !q || c.label.toLowerCase().includes(q) || c.category.toLowerCase().includes(q));

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Global Command Palette"
      className="fixed inset-0 z-50 flex items-start justify-center pt-20 bg-[var(--overlay)] px-4"
    >
      <div className="w-full max-w-lg rounded-[var(--radius-lg)] border border-border bg-surface shadow-[var(--shadow-elev)] overflow-hidden">
        <div className="flex items-center gap-2 px-3.5 py-2.5 border-b border-border bg-elev">
          <Search size={14} className="text-text-dim" aria-hidden="true" />
          <input
            aria-label="Filter commands"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Jump to workspace or action (e.g. Kubernetes, Topology, Theme)..."
            className="flex-1 bg-transparent text-sm text-text-pri focus:outline-none"
          />
          <button
            type="button"
            aria-label="Close Command Palette"
            onClick={onClose}
            className="p-1 rounded-[var(--radius-sm)] text-text-dim hover:text-text-pri"
          >
            <X size={14} aria-hidden="true" />
          </button>
        </div>
        <div className="max-h-72 overflow-y-auto divide-y divide-border">
          {filtered.map((cmd) => (
            <button
              key={cmd.id}
              type="button"
              onClick={() => {
                cmd.action(props);
                onClose();
              }}
              className="w-full px-4 py-2.5 text-left flex items-center justify-between hover:bg-[var(--surface-hover)] text-xs"
            >
              <span className="font-medium text-text-pri inline-flex items-center gap-2">
                <Command size={12} className="text-accent" aria-hidden="true" />
                {cmd.label}
              </span>
              <span className="text-[11px] text-text-dim">{cmd.category}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

