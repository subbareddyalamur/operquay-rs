import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Background, BackgroundVariant, BaseEdge, Controls, Handle, MarkerType, Position, ReactFlow, ReactFlowProvider, useNodesInitialized, useNodesState, useReactFlow, type Connection, type Edge, type EdgeProps, type EdgeTypes, type Node, type NodeProps, type NodeTypes } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { TopoNode, VPCTopology } from '@/lib/topology-types';
import { buildAWSArchitecture } from './architectureGraph';
import type { ArchitectureRelation, ArchitectureResource } from './architectureModel';
import { layoutArchitecture, type PositionedNode, type RoutedEdge } from './architectureLayout';
import { inspectArchitectureRouting } from './architectureRouting';
import { manualTopologyRoutes, projectTopology, type RelationshipLayer, type VisibleRelation } from './topologyView';
import { focusedRelationships, topologyOverview } from './topologyOverview';
import { defaultPalette, TopologyVisual, type TopologyPalette } from './TopologyVisual';
import { pngDimensions, saveBlob, saveTopologyPng, topologySvg } from './topologyExport';

interface NodeData extends Record<string, unknown> {
  resource: ArchitectureResource; width: number; height: number; palette: TopologyPalette;
  expandable: boolean; collapsed: boolean; hidden: number; internal: number; risk: boolean;
  edit: boolean;
  toggle: (id: string) => void;
}
interface EdgeData extends Record<string, unknown> { sections: RoutedEdge['sections']; label: string; color: string }

function ResourceCard({ data }: NodeProps) {
  const item = data as NodeData;
  return <div className="relative h-full w-full">
    <TopologyVisual {...item} />
    <Handle type="target" position={Position.Left} style={{ opacity: item.edit ? 1 : 0, background: item.palette.accent }} />
    <Handle type="source" position={Position.Right} style={{ opacity: item.edit ? 1 : 0, background: item.palette.accent }} />
    {item.expandable && <button type="button" className="nodrag absolute left-7 top-1 h-5 w-5 cursor-pointer rounded opacity-0 focus-visible:opacity-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent" aria-label={`${item.collapsed ? 'Expand' : 'Collapse'} ${item.resource.label}`} onClick={event => { event.stopPropagation(); item.toggle(item.resource.id); }} />}
  </div>;
}

function Relationship({ id, data, markerEnd, style }: EdgeProps) {
  const item = data as EdgeData;
  const path = item.sections.map(points => points.map((point, index) => `${index ? 'L' : 'M'} ${point.x} ${point.y}`).join(' ')).join(' ');
  const section = item.sections[0], middle = section?.[Math.floor(section.length / 2)];
  return <g aria-label={item.label}><title>{item.label}</title><BaseEdge id={id} path={path} markerEnd={markerEnd} style={style} />{middle && item.label.includes('relationships') && <text x={middle.x + 4} y={middle.y - 4} fill={item.color} fontSize="10" fontWeight="700">{item.label}</text>}</g>;
}
const nodeTypes: NodeTypes = { topology: ResourceCard };
const edgeTypes: EdgeTypes = { topology: Relationship };

export interface TopologyCanvasProps {
  topology: VPCTopology; instanceId: string;
  onSelectNode?: (node: TopoNode) => void; onRefresh?: () => void; isRefreshing?: boolean;
}

function TopologyCanvasInner({ topology, instanceId, onSelectNode, onRefresh, isRefreshing }: TopologyCanvasProps) {
  const overview = useMemo(() => topologyOverview(buildAWSArchitecture(topology, instanceId), topology, instanceId), [topology, instanceId]);
  const model = overview.model;
  const [collapsed, setCollapsed] = useState(() => new Set(overview.collapsed));
  const [custom, setCustom] = useState<ArchitectureRelation[]>([]);
  const [layer, setLayer] = useState<RelationshipLayer>('focus');
  const [query, setQuery] = useState('');
  const [edit, setEdit] = useState(false), [risk, setRisk] = useState(false), [tags, setTags] = useState(false), [manual, setManual] = useState(false);
  const [scale, setScale] = useState(4), [exportError, setExportError] = useState(''), [exporting, setExporting] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [palette, setPalette] = useState(defaultPalette);
  const [layout, setLayout] = useState<{ nodes: PositionedNode[]; edges: RoutedEdge[] } | null>(null);
  const [layoutError, setLayoutError] = useState('');
  const [bundle, setBundle] = useState<VisibleRelation | null>(null);
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const flow = useReactFlow();
  const nodesReady = useNodesInitialized();
  const pendingFocus = useRef<string | null>(null);
  const initiallyFocused = useRef(false);
  const renderedLayout = useRef<typeof layout>(null);
  const customSequence = useRef(0);
  const container = useRef<HTMLDivElement>(null);
  const missingCustom = useMemo(() => custom.filter(edge => !model.resources[edge.source] || !model.resources[edge.target]), [model, custom]);
  const combined = useMemo(() => ({ ...model, edges: [...model.edges, ...custom.filter(edge => model.resources[edge.source] && model.resources[edge.target])] }), [model, custom]);
  const focusEdges = useMemo(() => focusedRelationships(combined, topology, instanceId, collapsed), [combined, topology, instanceId, collapsed]);
  const view = useMemo(() => projectTopology(combined, collapsed, layer, { aliases: overview.aliases, focusEdges }), [combined, collapsed, layer, overview.aliases, focusEdges]);
  const layoutView = useRef<typeof view | null>(null);
  const currentLayout = layoutView.current === view ? layout : null;

  useEffect(() => {
    setCollapsed(new Set(overview.collapsed));
    setManual(false); setBundle(null); initiallyFocused.current = false;
  }, [overview]);
  useEffect(() => { setCustom([]); }, [instanceId]);
  useEffect(() => {
    const update = () => {
      const style = getComputedStyle(container.current ?? document.documentElement);
      const color = (name: string, fallback: string) => style.getPropertyValue(name).trim() || fallback;
      setPalette({ background: color('--bg', defaultPalette.background), surface: color('--surface', defaultPalette.surface), text: color('--text-pri', defaultPalette.text), muted: color('--text-mut', defaultPalette.muted), border: color('--border', defaultPalette.border), accent: color('--accent', defaultPalette.accent), info: color('--info', defaultPalette.info), success: color('--success', defaultPalette.success), warning: color('--warn', defaultPalette.warning) });
    };
    update();
    const observer = new MutationObserver(update);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme', 'class', 'style'] });
    return () => observer.disconnect();
  }, []);
  useEffect(() => {
    let current = true;
    layoutView.current = null;
    setLayout(null); setLayoutError(''); setManual(false);
    void layoutArchitecture(view).then(result => { if (current) { layoutView.current = view; setLayout(result); } }).catch(() => { if (current) setLayoutError('Could not lay out all relationships. The relationship list remains available.'); });
    return () => { current = false; };
  }, [view]);

  const toggle = useCallback((id: string) => {
    pendingFocus.current = id;
    setCollapsed(previous => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);
  useEffect(() => {
    if (!currentLayout) return;
    const keepPositions = renderedLayout.current === currentLayout;
    renderedLayout.current = currentLayout;
    setNodes(previous => {
      const previousById = new Map(previous.map(node => [node.id, node]));
      return currentLayout.nodes.map(node => {
        const resource = view.resources[node.id];
        const match = `${resource.label} ${resource.subtitle ?? ''} ${resource.id} ${resource.typeLabel}`.toLowerCase().includes(query.trim().toLowerCase());
        return { ...node, extent: node.parentId ? 'parent' as const : undefined, position: keepPositions ? previousById.get(node.id)?.position ?? node.position : node.position, type: 'topology', draggable: edit, selectable: true, data: { resource, width: node.width, height: node.height, palette, expandable: !!combined.resources[node.id]?.container, collapsed: collapsed.has(node.id), hidden: view.hiddenCount[node.id] ?? 0, internal: view.internalCount[node.id] ?? 0, risk, edit, toggle }, style: { width: node.width, height: node.height, opacity: query.trim() && !match && !resource.container ? 0.25 : 1 } };
      });
    });
  }, [currentLayout, view, combined, collapsed, query, edit, risk, palette, toggle, setNodes]);
  useEffect(() => {
    if (!nodesReady || !pendingFocus.current) return;
    const id = pendingFocus.current;
    if (!nodes.some(node => node.id === id)) return;
    pendingFocus.current = null;
    void flow.fitView({ nodes: [{ id }], padding: 1, maxZoom: 1 });
  }, [nodesReady, nodes, flow]);
  useEffect(() => {
    if (!nodesReady || initiallyFocused.current || !currentLayout) return;
    const id = `instance:${instanceId}`;
    if (!nodes.some(node => node.id === id)) return;
    initiallyFocused.current = true;
    void flow.fitView({ padding: 0.1, maxZoom: 1 });
  }, [nodesReady, nodes, flow, currentLayout, instanceId]);

  const positions = useMemo<PositionedNode[]>(() => nodes.map(node => ({ id: node.id, parentId: node.parentId, position: node.position, width: Number(node.width ?? (node.data as NodeData).width), height: Number(node.height ?? (node.data as NodeData).height) })), [nodes]);
  const routes = useMemo(() => !currentLayout ? [] : manual ? manualTopologyRoutes(positions, view.edges) : currentLayout.edges, [currentLayout, manual, positions, view.edges]);
  const routing = useMemo(() => currentLayout ? inspectArchitectureRouting(view, positions, routes) : null, [currentLayout, view, positions, routes]);
  const edges = useMemo<Edge[]>(() => {
    const categories = new Map(view.edges.map(edge => [edge.id, edge.category]));
    return routes.map(route => {
      const category = categories.get(route.id) ?? 'association';
      const color = category === 'route' ? palette.info : category === 'custom' ? palette.accent : palette.muted;
      return { id: route.id, source: route.source, target: route.target, type: 'topology', data: { sections: route.sections, label: route.label, color }, style: { stroke: color, strokeWidth: 1.5, strokeDasharray: category === 'route' ? undefined : '5 4' }, markerEnd: { type: MarkerType.ArrowClosed, color, width: 12, height: 12 }, zIndex: 5 };
    });
  }, [routes, view.edges, palette]);

  const select = (resource: ArchitectureResource) => onSelectNode?.(resource as TopoNode);
  const focus = (id: string) => {
    const resource = combined.resources[id];
    if (!resource) return;
    select(resource);
    const visibleId = overview.aliases.get(id) ?? id;
    pendingFocus.current = visibleId;
    const parent = new Map(combined.nodes.map(node => [node.id, node.parentId]));
    let current = parent.get(visibleId);
    const open = new Set<string>();
    while (current) { open.add(current); current = parent.get(current); }
    if ([...open].some(group => collapsed.has(group))) setCollapsed(previous => new Set([...previous].filter(group => !open.has(group))));
    else if (nodes.some(node => node.id === visibleId)) { pendingFocus.current = null; void flow.fitView({ nodes: [{ id: visibleId }], padding: 1, maxZoom: 1 }); }
  };
  const expandBundle = () => {
    if (!bundle) return;
    const parents = new Map(combined.nodes.map(node => [node.id, node.parentId]));
    const open = new Set<string>();
    for (const edge of bundle.members) for (const id of [edge.source, edge.target]) {
      let parent = parents.get(id);
      while (parent) { open.add(parent); parent = parents.get(parent); }
    }
    setCollapsed(previous => new Set([...previous].filter(id => !open.has(id))));
    setBundle(null);
  };
  const connect = (connection: Connection) => {
    if (!connection.source || !connection.target || connection.source === connection.target) return;
    const id = `custom:${++customSequence.current}`;
    setCustom(previous => [...previous, { id, source: connection.source!, target: connection.target!, label: 'custom' }]);
  };
  const download = async (format: 'png' | 'svg') => {
    setExportError(''); setExporting(true);
    try {
      if (!currentLayout || positions.length !== view.nodes.length || positions.some(node => !view.resources[node.id]) || routes.some(edge => !edge.sections.length)) throw new Error('Wait for all displayed resources and connections to finish rendering.');
      const output = topologySvg(view, positions, routes, palette, collapsed, view.hiddenCount, view.internalCount, risk, query);
      if (format === 'svg') saveBlob(new Blob([output.svg], { type: 'image/svg+xml;charset=utf-8' }), `topology-${Date.now()}.svg`);
      else await saveTopologyPng(output.svg, output.width, output.height, scale);
    } catch (error) { setExportError(error instanceof Error ? error.message : 'Export failed.'); }
    finally { setExporting(false); }
  };
  let dimensions = '';
  if (exportOpen && currentLayout && positions.length === view.nodes.length && positions.length && positions.every(node => view.resources[node.id])) {
    try { const output = topologySvg(view, positions, routes, palette, collapsed, view.hiddenCount, view.internalCount, risk, query); const size = pngDimensions(output.width, output.height, scale); dimensions = `${size.width} × ${size.height} px`; } catch { dimensions = 'PNG too large at this scale'; }
  }
  const buttonClass = 'rounded px-2 py-1.5 text-xs text-text-mut hover:bg-elev focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent disabled:opacity-50';
  return <div ref={container} className="flex h-full min-h-0 flex-col bg-bg">
    <div className="relative z-10 flex flex-wrap items-center gap-2 border-b border-border bg-surface px-3 py-2">
      <input aria-label="Search topology resources" placeholder="Search resources…" value={query} onChange={event => setQuery(event.target.value)} onKeyDown={event => { if (event.key === 'Enter') { const term = query.trim().toLowerCase(); const match = combined.nodes.find(node => term && `${combined.resources[node.id].label} ${combined.resources[node.id].id}`.toLowerCase().includes(term)); if (match) focus(match.id); } }} className="w-44 rounded border border-border bg-elev px-2 py-1.5 text-xs text-text-pri" />
      <button type="button" className={buttonClass} aria-label="Refresh topology" disabled={!onRefresh || isRefreshing} onClick={onRefresh}>Refresh</button>
      <button type="button" className={buttonClass} aria-pressed={edit} onClick={() => setEdit(value => !value)}>{edit ? 'Finish editing' : 'Edit'}</button>
      <button type="button" className={buttonClass} aria-pressed={risk} onClick={() => setRisk(value => !value)}>Risk</button>
      <button type="button" className={buttonClass} aria-pressed={tags} onClick={() => setTags(value => !value)}>Tags</button>
      <button type="button" className={buttonClass} disabled={!currentLayout} onClick={() => void flow.fitView({ padding: 0.12 })}>Fit diagram</button>
      <button type="button" className={buttonClass} disabled={!model.resources[`instance:${instanceId}`]} onClick={() => focus(`instance:${instanceId}`)}>Focus instance</button>
      <label className="text-xs text-text-mut">Relationships <select aria-label="Relationship layer" value={layer} onChange={event => setLayer(event.target.value as RelationshipLayer)} className="rounded border border-border bg-elev p-1 text-text-pri"><option value="focus">Instance focus</option><option value="all">All</option><option value="routes">Routes</option><option value="associations">Associations</option></select></label>
      <details onToggle={event => setExportOpen(event.currentTarget.open)}>
        <summary className={`${buttonClass} cursor-pointer list-none border border-border`}>Export ▾</summary>
        <div className="absolute left-0 right-0 top-full z-50 flex flex-wrap items-center gap-3 border border-border bg-surface p-3 shadow-lg">
          <label className="text-xs text-text-mut">PNG scale <select aria-label="PNG scale" value={scale} onChange={event => setScale(Number(event.target.value))} className="rounded border border-border bg-elev p-1 text-text-pri"><option value={1}>1×</option><option value={2}>2×</option><option value={4}>4×</option></select></label>
          <span className="text-xs text-text-mut">Whole displayed diagram · {dimensions}</span>
          <button type="button" className={buttonClass} disabled={!currentLayout || exporting} onClick={() => void download('png')}>Export PNG</button>
          <button type="button" className={buttonClass} disabled={!currentLayout || exporting} onClick={() => void download('svg')}>Export SVG</button>
        </div>
      </details>
    </div>
    {tags && <div className="border-b border-border bg-surface px-3 py-2 text-xs text-text-mut">Tag grouping is unavailable because this topology response does not include instance tags.</div>}
    {risk && <div className="border-b border-border bg-surface px-3 py-2 text-xs text-text-mut">Public IP highlights are observations, not verified exposure or reachability.</div>}
    {edit && <div className="border-b border-border bg-surface px-3 py-2 text-xs text-text-mut">Drag nodes or connect handles to add a custom relationship. Changing groups or layers restores automatic positions.</div>}
    {exportError && <div role="alert" className="border-b border-border px-3 py-2 text-xs text-danger">{exportError}</div>}
    {missingCustom.length > 0 && <details className="border-b border-border bg-surface px-3 py-2 text-xs text-warn"><summary>{missingCustom.length} custom relationships have unavailable endpoints</summary><ul>{missingCustom.map(edge => <li key={edge.id}>{edge.source} → {edge.target} <button type="button" className="underline" onClick={() => setCustom(previous => previous.filter(item => item.id !== edge.id))}>Remove</button></li>)}</ul></details>}
    <details className="border-b border-border bg-surface px-3 py-1 text-xs text-text-mut"><summary className="cursor-pointer">{view.allEdges.length} relationships in selected layer ({combined.edges.length} total) · {combined.notices.length} notes{routing && (routing.crossingPairs > 0 || routing.cardObstructions > 0 || routing.unrouted > 0 || routing.incomplete) ? ` · ${routing.crossingPairs} crossing pairs · ${routing.cardObstructions} card overlaps · ${routing.unrouted} unrouted${routing.incomplete ? ' · inspection incomplete' : ''}` : ''}</summary>
      <div className="mt-2">Solid: configured route · Dashed: association or custom link</div>
      {routing && <div>Routing: {routing.crossingPairs} crossing/overlapping pairs · {routing.cardObstructions} card overlaps · {routing.unrouted} unrouted{routing.incomplete ? ' · inspection incomplete' : ''}.</div>}
      <ul className="max-h-24 overflow-auto">{combined.notices.map(note => <li key={note}>{note}</li>)}</ul>
      <ul className="mt-2 max-h-32 space-y-1 overflow-auto">{view.allEdges.map(edge => <li key={edge.id}><button type="button" className="hover:underline" onClick={() => focus(edge.source)}>{combined.resources[edge.source]?.label}</button> — {edge.label} → <button type="button" className="hover:underline" onClick={() => focus(edge.target)}>{combined.resources[edge.target]?.label}</button>{edge.id.startsWith('custom:') && <button type="button" className="ml-2 hover:underline" aria-label={`Remove custom relationship ${combined.resources[edge.source]?.label} to ${combined.resources[edge.target]?.label}`} onClick={() => setCustom(previous => previous.filter(item => item.id !== edge.id))}>Remove</button>}</li>)}</ul>
    </details>
    {manual && <div role="status" className="border-b border-border bg-surface px-3 py-1 text-xs text-warn">Manual positions use basic routing; change a group or layer to restore automatic layout.</div>}
    {bundle && <div className="border-b border-border bg-surface px-3 py-2 text-xs text-text-mut"><div>{bundle.members.length} bundled relationships <button type="button" className={buttonClass} onClick={expandBundle}>Expand groups</button><button type="button" className={buttonClass} onClick={() => setBundle(null)}>Close</button></div><ul className="max-h-24 overflow-auto">{bundle.members.map(edge => <li key={edge.id}>{combined.resources[edge.source]?.label} — {edge.label} → {combined.resources[edge.target]?.label}</li>)}</ul></div>}
    <div className={`topology-canvas relative min-h-0 flex-1 ${edit ? 'topology-editing' : ''}`}>
      <style>{`.topology-canvas .react-flow__controls-button { background: var(--surface); border-color: var(--border); fill: var(--text-pri); color: var(--text-pri); } .topology-canvas .react-flow__controls-button:hover { background: var(--elev); } .topology-editing .react-flow__edge { pointer-events: none; }`}</style>
      {layoutError ? <div role="alert" className="p-4 text-danger">{layoutError}</div> : !currentLayout ? <div role="status" className="p-4 text-text-mut">Laying out topology…</div> : <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes} onNodesChange={onNodesChange} onNodeDrag={() => setManual(true)} onNodeClick={(_, node) => select((node.data as NodeData).resource)} onConnect={connect} onEdgeClick={(_, edge) => { const item = view.edges.find(candidate => candidate.id === edge.id); if (item && item.members.length > 1) setBundle(item); }} nodesDraggable={edit} nodesConnectable={edit} fitView fitViewOptions={{ padding: 0.12 }} minZoom={0.04} maxZoom={3} attributionPosition="bottom-right"><Background variant={BackgroundVariant.Dots} gap={20} size={1} color={palette.border} /><Controls showInteractive={false} /></ReactFlow>}
    </div>
  </div>;
}

export function TopologyCanvas(props: TopologyCanvasProps) {
  return <ReactFlowProvider><TopologyCanvasInner {...props} /></ReactFlowProvider>;
}
