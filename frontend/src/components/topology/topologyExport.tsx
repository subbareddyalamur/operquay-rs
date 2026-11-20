import { renderToStaticMarkup } from 'react-dom/server';
import type { ArchitectureModel } from './architectureModel';
import type { PositionedNode, RoutedEdge } from './architectureLayout';
import { TopologyVisual, type TopologyPalette } from './TopologyVisual';
import { relationCategory, type VisibleRelation } from './topologyView';

export function pngDimensions(width: number, height: number, scale: number) {
  const w = Math.ceil(width * scale), h = Math.ceil(height * scale);
  if (!Number.isFinite(w) || !Number.isFinite(h) || w <= 0 || h <= 0 || w > 16384 || h > 16384 || w * h > 64_000_000) throw new Error('PNG is too large for safe browser rendering. Choose a smaller scale or collapse groups.');
  return { width: w, height: h };
}

export function topologySvg(model: ArchitectureModel, nodes: PositionedNode[], edges: RoutedEdge[], palette: TopologyPalette, collapsed: Set<string>, hidden: Record<string, number>, internal: Record<string, number>, risk: boolean, query = '') {
  const byId = new Map(nodes.map(node => [node.id, node]));
  const edgesById = new Map(model.edges.map(edge => [edge.id, edge]));
  const position = (node: PositionedNode) => {
    let x = node.position.x, y = node.position.y, parent = node.parentId;
    const seen = new Set([node.id]);
    while (parent) {
      if (seen.has(parent) || !byId.has(parent)) throw new Error('Invalid diagram containment.');
      seen.add(parent);
      const item = byId.get(parent)!;
      x += item.position.x; y += item.position.y; parent = item.parentId;
    }
    return { x, y };
  };
  const placed = nodes.map(node => ({ node, ...position(node) }));
  const points = edges.flatMap(edge => edge.sections.flat());
  if (!placed.length) throw new Error('There are no visible resources to export.');
  const left = Math.min(...placed.map(node => node.x), ...points.map(point => point.x)) - 32;
  const top = Math.min(...placed.map(node => node.y), ...points.map(point => point.y)) - 32;
  const labelEnds = edges.filter(edge => edge.label.includes('relationships')).map(edge => { const section = edge.sections[0]; const point = section?.[Math.floor(section.length / 2)]; return point ? point.x + 4 + edge.label.length * 7 : 0; });
  const right = Math.max(...placed.map(node => node.x + node.node.width), ...points.map(point => point.x), ...labelEnds) + 32;
  const bottom = Math.max(...placed.map(node => node.y + node.node.height), ...points.map(point => point.y)) + 32;
  const width = Math.ceil(right - left), height = Math.ceil(bottom - top);
  const drawNode = ({ node, x, y }: typeof placed[number]) => {
    const resource = model.resources[node.id];
    const text = `${resource.label} ${resource.subtitle ?? ''} ${resource.id} ${resource.typeLabel}`.toLowerCase();
    const opacity = query.trim() && !text.includes(query.trim().toLowerCase()) && !resource.container ? 0.25 : 1;
    return <g key={node.id} transform={`translate(${x} ${y})`} opacity={opacity}><TopologyVisual resource={resource} width={node.width} height={node.height} palette={palette} hidden={hidden[node.id]} internal={internal[node.id]} collapsed={collapsed.has(node.id)} expandable={!!resource.container || collapsed.has(node.id)} risk={risk} /></g>;
  };
  const svg = renderToStaticMarkup(<svg xmlns="http://www.w3.org/2000/svg" width={width} height={height} viewBox={`${left} ${top} ${width} ${height}`}><title>Cloud topology</title><defs>{(['route', 'association', 'custom'] as const).map(category => <marker key={category} id={`arrow-${category}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill={category === 'route' ? palette.info : category === 'custom' ? palette.accent : palette.muted} /></marker>)}</defs><rect x={left} y={top} width={width} height={height} fill={palette.background} />
    {placed.filter(item => model.resources[item.node.id].container).map(drawNode)}
    {edges.map(edge => {
      const section = edge.sections[0], middle = section?.[Math.floor(section.length / 2)];
      const visible = edgesById.get(edge.id) as VisibleRelation | undefined;
      const category = visible?.category ?? relationCategory(model, edge);
      const color = category === 'route' ? palette.info : category === 'custom' ? palette.accent : palette.muted;
      return <g key={edge.id}><title>{edge.label}</title>{edge.sections.map((points, index) => <path key={index} d={points.map((point, i) => `${i ? 'L' : 'M'} ${point.x} ${point.y}`).join(' ')} fill="none" stroke={color} strokeWidth="1.5" strokeDasharray={category === 'route' ? undefined : '5 4'} markerEnd={index === edge.sections.length - 1 ? `url(#arrow-${category})` : undefined} />)}{middle && edge.label.includes('relationships') && <text x={middle.x + 4} y={middle.y - 4} fill={color} fontFamily="sans-serif" fontSize="10" fontWeight="700">{edge.label}</text>}</g>;
    })}
    {placed.filter(item => !model.resources[item.node.id].container).map(drawNode)}
  </svg>);
  return { svg, width, height };
}

export function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = filename; anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function saveTopologyPng(svg: string, width: number, height: number, scale: number) {
  const dimensions = pngDimensions(width, height, scale);
  if (document.fonts) await document.fonts.ready;
  const url = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml;charset=utf-8' }));
  try {
    const image = new Image();
    await new Promise<void>((resolve, reject) => { image.onload = () => resolve(); image.onerror = () => reject(new Error('Could not render the SVG for PNG export.')); image.src = url; });
    const canvas = document.createElement('canvas');
    canvas.width = dimensions.width; canvas.height = dimensions.height;
    const context = canvas.getContext('2d');
    if (!context) throw new Error('Canvas rendering is unavailable.');
    context.drawImage(image, 0, 0, dimensions.width, dimensions.height);
    const blob = await new Promise<Blob | null>(resolve => canvas.toBlob(resolve, 'image/png'));
    if (!blob) throw new Error('The browser could not create the PNG. Try a smaller scale.');
    saveBlob(blob, `topology-${Date.now()}.png`);
  } finally { URL.revokeObjectURL(url); }
}
