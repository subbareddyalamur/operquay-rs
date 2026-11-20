import type { ELK, ElkNode, ElkExtendedEdge } from 'elkjs/lib/elk-api';
import type { ArchitectureModel, ArchitectureRelation } from './architectureModel';
import { inspectArchitectureRouting } from './architectureRouting';

export interface PositionedNode { id: string; parentId?: string; position: { x: number; y: number }; width: number; height: number }
export interface RoutedEdge extends ArchitectureRelation { sections: Array<Array<{ x: number; y: number }>> }

let engine: Promise<ELK> | undefined;
function layoutEngine(): Promise<ELK> {
  if (!engine) engine = typeof Worker === 'undefined'
    ? import('elkjs/lib/elk.bundled.js').then(({ default: ELK }) => new ELK())
    : Promise.all([import('elkjs/lib/elk-api.js'), import('elkjs/lib/elk-worker.min.js?worker')])
      .then(([{ default: ELK }, { default: WorkerFactory }]) => new ELK({ workerFactory: () => new WorkerFactory() }));
  return engine;
}

export async function layoutArchitecture(model: ArchitectureModel): Promise<{ nodes: PositionedNode[]; edges: RoutedEdge[] }> {
  const graph: ElkNode = { id: 'root', layoutOptions: {
    'elk.algorithm': 'layered', 'elk.direction': 'RIGHT', 'elk.edgeRouting': 'ORTHOGONAL',
    'elk.hierarchyHandling': 'INCLUDE_CHILDREN', 'elk.json.edgeCoords': 'ROOT',
    'elk.spacing.nodeNode': '48', 'elk.layered.spacing.nodeNodeBetweenLayers': '90',
    'elk.layered.spacing.edgeNodeBetweenLayers': '36', 'elk.spacing.edgeEdge': '18',
    'elk.padding': '[top=30,left=30,bottom=30,right=30]',
  }, children: [], edges: model.edges.map(edge => ({ id: edge.id, sources: [edge.source], targets: [edge.target] })) };
  const groups = new Map<string, ElkNode>();
  for (const item of model.nodes) {
    const resource = model.resources[item.id];
    const node: ElkNode = resource.container
      ? { id: item.id, children: [], layoutOptions: { 'elk.padding': '[top=58,left=26,bottom=26,right=26]', 'elk.spacing.nodeNode': '36' } }
      : { id: item.id, width: resource.selected ? 320 : 236, height: resource.selected ? 130 : 88 };
    if (resource.container) groups.set(item.id, node);
    (item.parentId ? groups.get(item.parentId)?.children : graph.children)?.push(node);
  }
  const run = async (seed: number) => {
    const input = structuredClone(graph);
    input.layoutOptions = { ...input.layoutOptions, 'elk.randomSeed': String(seed) };
    const layout = await (await layoutEngine()).layout(input);
    const nodes: PositionedNode[] = [];
    const visit = (items: ElkNode[], parentId?: string) => {
      for (const node of items) {
        nodes.push({ id: node.id, parentId, position: { x: node.x ?? 0, y: node.y ?? 0 }, width: node.width ?? 0, height: node.height ?? 0 });
        visit(node.children ?? [], node.id);
      }
    };
    visit(layout.children ?? []);
    const routes = new Map((layout.edges as ElkExtendedEdge[] ?? []).map(edge => [edge.id, edge.sections ?? []]));
    const edges = model.edges.map(edge => ({ ...edge, sections: (routes.get(edge.id) ?? []).map(section => [section.startPoint, ...(section.bendPoints ?? []), section.endPoint]) }));
    if (edges.some(edge => edge.sections.length === 0)) throw new Error('Could not route every topology relationship.');
    return { nodes, edges };
  };
  let best = await run(1);
  let diagnostics = inspectArchitectureRouting(model, best.nodes, best.edges);
  // shortcut: retry only modest graphs; move layout scoring to a worker before raising this limit.
  if (model.edges.length <= 100 && model.nodes.length <= 100 && !diagnostics.incomplete) {
    for (const seed of [2, 3]) {
      if (!diagnostics.crossingPairs && !diagnostics.cardObstructions) break;
      try {
        const candidate = await run(seed);
        const next = inspectArchitectureRouting(model, candidate.nodes, candidate.edges);
        if (!next.incomplete && (next.cardObstructions < diagnostics.cardObstructions || (next.cardObstructions === diagnostics.cardObstructions && next.crossingPairs < diagnostics.crossingPairs))) { best = candidate; diagnostics = next; }
      } catch { /* Keep the complete earlier layout. */ }
    }
  }
  return best;
}
