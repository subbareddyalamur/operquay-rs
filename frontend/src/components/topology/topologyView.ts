import type { ArchitectureModel, ArchitectureRelation } from './architectureModel';
import type { PositionedNode, RoutedEdge } from './architectureLayout';

export type RelationshipLayer = 'focus' | 'all' | 'routes' | 'associations';
export type RelationCategory = 'route' | 'association' | 'custom';
export interface VisibleRelation extends ArchitectureRelation { members: ArchitectureRelation[]; category: RelationCategory }

export function relationCategory(model: ArchitectureModel, edge: ArchitectureRelation): RelationCategory {
  if (edge.label === 'custom') return 'custom';
  return model.resources[edge.source]?.kind === 'route-table' && edge.label !== 'endpoint association' ? 'route' : 'association';
}

export function projectTopology(model: ArchitectureModel, collapsed: Set<string>, layer: RelationshipLayer, options: { aliases?: Map<string, string>; focusEdges?: Set<string> } = {}) {
  const parents = new Map(model.nodes.map(node => [node.id, node.parentId]));
  const representative = (id: string) => {
    let current = options.aliases?.get(id) ?? id;
    let parent = parents.get(current);
    while (parent) {
      if (collapsed.has(parent)) current = parent;
      parent = parents.get(parent);
    }
    return current;
  };
  const hiddenCount: Record<string, number> = {}, internalCount: Record<string, number> = {};
  const nodes = model.nodes.filter(node => {
    const visible = representative(node.id);
    if (visible !== node.id && !options.aliases?.has(node.id)) hiddenCount[visible] = (hiddenCount[visible] ?? 0) + (model.resources[node.id].container ? 0 : 1);
    return visible === node.id;
  });
  const resources = Object.fromEntries(nodes.map(node => [node.id, { ...model.resources[node.id], container: !!model.resources[node.id].container && !collapsed.has(node.id) }]));
  const allEdges = model.edges.filter(edge => {
    const route = relationCategory(model, edge) === 'route';
    return layer === 'all' || (layer === 'focus' ? (options.focusEdges?.has(edge.id) ?? true) : layer === 'routes' ? route : !route);
  });
  const grouped = new Map<string, VisibleRelation>();
  for (const edge of allEdges) {
    const source = representative(edge.source), target = representative(edge.target);
    const contains = (ancestor: string, child: string) => { let parent = parents.get(child); while (parent) { if (parent === ancestor) return true; parent = parents.get(parent); } return false; };
    if (edge.label === 'located in' && (contains(source, target) || contains(target, source))) { internalCount[source] = (internalCount[source] ?? 0) + 1; continue; }
    if (source === target && (source !== edge.source || target !== edge.target)) { internalCount[source] = (internalCount[source] ?? 0) + 1; continue; }
    const projected = source !== edge.source || target !== edge.target;
    const category = relationCategory(model, edge);
    const key = projected ? JSON.stringify([source, target, category]) : edge.id;
    const existing = grouped.get(key);
    if (existing) existing.members.push(edge);
    else grouped.set(key, { ...edge, id: projected ? `bundle:${key}` : edge.id, source, target, category, members: [edge] });
  }
  const edges = [...grouped.values()].map(edge => ({ ...edge, label: edge.members.length > 1 ? `${edge.members.length} relationships` : edge.label }));
  return { resources, nodes, edges, notices: model.notices, allEdges, hiddenCount, internalCount };
}

export function manualTopologyRoutes(nodes: PositionedNode[], edges: ArchitectureRelation[]): RoutedEdge[] {
  const byId = new Map(nodes.map(node => [node.id, node]));
  const box = (id: string) => {
    const node = byId.get(id);
    if (!node) return null;
    let x = node.position.x, y = node.position.y, parent = node.parentId;
    const seen = new Set([id]);
    while (parent && !seen.has(parent)) {
      seen.add(parent);
      const item = byId.get(parent);
      if (!item) break;
      x += item.position.x; y += item.position.y; parent = item.parentId;
    }
    return { x, y, width: node.width, height: node.height };
  };
  return edges.map(edge => {
    const a = box(edge.source), b = box(edge.target);
    if (!a || !b) return { ...edge, sections: [] };
    if (edge.source === edge.target) {
      const start = { x: a.x + a.width, y: a.y + a.height / 2 }, end = { x: a.x + a.width / 2, y: a.y };
      return { ...edge, sections: [[start, { x: start.x + 30, y: start.y }, { x: start.x + 30, y: end.y - 25 }, { x: end.x, y: end.y - 25 }, end]] };
    }
    const forward = b.x + b.width / 2 >= a.x + a.width / 2;
    const start = { x: forward ? a.x + a.width : a.x, y: a.y + a.height / 2 };
    const end = { x: forward ? b.x : b.x + b.width, y: b.y + b.height / 2 };
    const middle = (start.x + end.x) / 2;
    return { ...edge, sections: [[start, { x: middle, y: start.y }, { x: middle, y: end.y }, end]] };
  });
}
