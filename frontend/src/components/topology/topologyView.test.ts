import { describe, expect, it } from 'vitest';
import type { ArchitectureModel } from './architectureModel';
import { projectTopology, manualTopologyRoutes } from './topologyView';

const resource = (id: string, container = false) => ({ id, kind: 'resource', label: id, typeLabel: 'Resource', icon: '', data: {}, container });
const model: ArchitectureModel = {
  resources: { root: resource('root', true), group: resource('group', true), a: resource('a'), b: resource('b'), c: resource('c') },
  nodes: [{ id: 'root' }, { id: 'group', parentId: 'root' }, { id: 'a', parentId: 'group' }, { id: 'b', parentId: 'group' }, { id: 'c', parentId: 'root' }],
  edges: [
    { id: '1', source: 'a', target: 'c', label: 'association' },
    { id: '2', source: 'b', target: 'c', label: 'association' },
    { id: '3', source: 'a', target: 'b', label: 'internal' },
  ], notices: [],
};

describe('topology view projection', () => {
  it('counts collapsed resources, bundles outgoing edges, and retains internal edges for inspection', () => {
    const result = projectTopology(model, new Set(['group']), 'all');
    expect(result.nodes.map(node => node.id)).toEqual(['root', 'group', 'c']);
    expect(result.hiddenCount.group).toBe(2);
    expect(result.edges).toHaveLength(1);
    expect(result.edges[0].members.map(edge => edge.id)).toEqual(['1', '2']);
    expect(result.internalCount.group).toBe(1);
    expect(result.allEdges).toHaveLength(3);
  });
  it('restores individual relationships on expansion', () => {
    const result = projectTopology(model, new Set(), 'all');
    expect(result.nodes).toHaveLength(5);
    expect(result.edges.flatMap(edge => edge.members.map(member => member.id))).toEqual(['1', '2', '3']);
  });
  it('does not merge configured routes with other kinds of relationships', () => {
    const input: ArchitectureModel = { ...model, resources: { ...model.resources, a: { ...model.resources.a, kind: 'route-table' } } };
    const result = projectTopology(input, new Set(['group']), 'all');
    expect(result.edges).toHaveLength(2);
    expect(result.edges.map(edge => edge.category).sort()).toEqual(['association', 'route']);
  });
  it('uses container boundaries as relationship endpoints without losing the underlying resource or connection', () => {
    const result = projectTopology(model, new Set(), 'all', { aliases: new Map([['a', 'group']]) });
    expect(result.nodes.some(node => node.id === 'a')).toBe(false);
    expect(result.edges.some(edge => edge.source === 'group' && edge.target === 'c')).toBe(true);
    expect(result.allEdges.map(edge => edge.id)).toEqual(['1', '2', '3']);
  });
  it('updates orthogonal connection endpoints when edited nodes move', () => {
    const nodes = [
      { id: 'a', position: { x: 0, y: 0 }, width: 20, height: 20 },
      { id: 'c', position: { x: 100, y: 60 }, width: 20, height: 20 },
    ];
    const [route] = manualTopologyRoutes(nodes, [model.edges[0]]);
    expect(route.sections[0][0]).toEqual({ x: 20, y: 10 });
    expect(route.sections[0].at(-1)).toEqual({ x: 100, y: 70 });
    expect(route.sections[0].every((point, index, points) => !index || point.x === points[index - 1].x || point.y === points[index - 1].y)).toBe(true);
  });
});
