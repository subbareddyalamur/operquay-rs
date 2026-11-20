import type { ArchitectureResource } from './architectureModel';
import { Boxes, MapPin, Network, Shield } from 'lucide-react';
import ec2 from './aws-icons/ec2.svg?raw';
import endpoint from './aws-icons/endpoint.svg?raw';
import igw from './aws-icons/igw.svg?raw';
import lb from './aws-icons/lb.svg?raw';
import nacl from './aws-icons/nacl.svg?raw';
import nat from './aws-icons/nat.svg?raw';
import peering from './aws-icons/peering.svg?raw';
import router from './aws-icons/router.svg?raw';
import tgw from './aws-icons/tgw.svg?raw';
import vpc from './aws-icons/vpc.svg?raw';

const icons: Record<string, string> = { ec2, endpoint, igw, lb, nacl, nat, peering, router, tgw, vpc };

export interface TopologyPalette { background: string; surface: string; text: string; muted: string; border: string; accent: string; info: string; success: string; warning: string }
export const defaultPalette: TopologyPalette = { background: '#0d0f12', surface: '#151821', text: '#e8eaf0', muted: '#a4adbf', border: '#465262', accent: '#a998ff', info: '#8fbaf0', success: '#8bd7b0', warning: '#e3bb78' };

export function TopologyVisual({ resource, width, height, palette, hidden = 0, internal = 0, collapsed = false, expandable = false, risk = false }: {
  resource: ArchitectureResource; width: number; height: number; palette: TopologyPalette; hidden?: number; internal?: number; collapsed?: boolean; expandable?: boolean; risk?: boolean;
}) {
  const group = resource.container || expandable;
  const subnet = resource.kind === 'subnet';
  const color = resource.selected ? palette.accent : subnet ? palette.success : group ? palette.info : palette.warning;
  const title = `${resource.typeLabel}${resource.selected ? ' · Selected' : ''}`;
  const publicIp = risk && resource.kind === 'instance' && Boolean(resource.data['publicIp']);
  const icon = icons[resource.icon]?.match(/<svg[^>]*>([\s\S]*?)<\/svg>/)?.[1];
  const Fallback = resource.icon === 'shield' ? Shield : resource.icon === 'subnet' ? Network : resource.icon === 'zone' ? MapPin : Boxes;
  const letters = Array.from(resource.label);
  const lineLength = Math.max(10, Math.floor((width - 24) / (resource.selected ? 10 : 8)));
  const firstLine = letters.slice(0, lineLength).join('');
  const secondLine = !group ? letters.slice(lineLength, lineLength * 2).join('') + (letters.length > lineLength * 2 ? '…' : '') : '';
  const summary = resource.kind === 'stub' && typeof resource.data['counterparts'] === 'number'
    ? `${resource.data['counterparts']} returned counterparts · expand`
    : `${hidden} resources · ${internal} internal relationships`;
  return <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} xmlns="http://www.w3.org/2000/svg" role="img" aria-label={`${title}: ${resource.label}`}>
    <rect x="1" y="1" width={Math.max(0, width - 2)} height={Math.max(0, height - 2)} rx={group ? 8 : 6} fill={group ? palette.background : palette.surface} fillOpacity={group ? 0.9 : 1} stroke={publicIp ? palette.warning : color} strokeWidth={resource.selected ? 2 : 1.2} strokeDasharray={group ? '6 4' : undefined} />
    <svg x="12" y="8" width={Math.max(0, width - 24)} height={group ? 48 : height - 16} overflow="hidden">
      {icon ? <svg x="0" y="0" width="14" height="14" viewBox="0 0 48 48" dangerouslySetInnerHTML={{ __html: icon }} /> : <Fallback x="0" y="0" size={14} color={color} aria-hidden="true" />}
      <text x="20" y="12" fill={color} fontFamily="sans-serif" fontSize="11" fontWeight="700">{expandable ? (collapsed ? '▸ ' : '▾ ') : ''}{title}</text>
      <text x="0" y={resource.selected ? 38 : 30} fill={palette.text} fontFamily="sans-serif" fontSize={resource.selected ? 20 : 14} fontWeight="600" textLength={resource.selected ? Math.min(width - 24, Array.from(firstLine).length * 11) : undefined} lengthAdjust={resource.selected ? 'spacingAndGlyphs' : undefined}>{firstLine}{group && letters.length > lineLength ? '…' : ''}</text>
      {secondLine && <text x="0" y={resource.selected ? 62 : 46} fill={palette.text} fontFamily="sans-serif" fontSize={resource.selected ? 20 : 14} fontWeight="600" textLength={resource.selected ? Math.min(width - 24, Array.from(secondLine).length * 11) : undefined} lengthAdjust={resource.selected ? 'spacingAndGlyphs' : undefined}>{secondLine}</text>}
      <text x="0" y={resource.selected ? (secondLine ? 84 : 61) : (secondLine ? 62 : 46)} fill={palette.muted} fontFamily="monospace" fontSize={resource.selected ? 12 : 10}>{collapsed ? summary : (resource.subtitle || '')}</text>
      {publicIp && <text x="0" y={resource.selected ? (secondLine ? 101 : 80) : (secondLine ? 71 : 61)} fill={palette.warning} fontFamily="sans-serif" fontSize="10">Public IP present · exposure unverified</text>}
    </svg>
  </svg>;
}
