import { Cloud } from 'lucide-react';

export const cloudNames: Record<string, string> = { aws: 'AWS', azure: 'Azure', gcp: 'Google Cloud', alibaba: 'Alibaba Cloud', digitalocean: 'DigitalOcean', hetzner: 'Hetzner' };
const cloudMarks: Record<string, string> = { aws: 'aws', azure: 'A', gcp: 'G', alibaba: '阿', digitalocean: 'DO', hetzner: 'H' };

export function cloudKey(provider?: string): string {
  // Older /instances responses contain only AWS EC2 accounts.
  const key = typeof provider === 'string' ? provider.trim().toLowerCase() || 'aws' : 'aws';
  return cloudNames[key] ? key : 'unknown';
}

export function CloudMark({ provider, compact = false }: { provider: string; compact?: boolean }) {
  return <span aria-hidden="true" className={`flex shrink-0 items-center justify-center rounded bg-accent/15 font-bold text-accent ${compact ? 'h-3.5 w-5 text-[8px]' : 'h-5 w-7 text-[10px]'}`}>{cloudMarks[provider] || <Cloud size={compact ? 11 : 14} />}</span>;
}
