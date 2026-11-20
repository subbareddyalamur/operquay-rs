import { describe, expect, it } from 'vitest';
import { inspectArchitectureRouting } from './architectureRouting';
import type { ArchitectureModel } from './architectureModel';
import type { PositionedNode, RoutedEdge } from './architectureLayout';

const model: ArchitectureModel = {
  resources: {
    a: { id: 'a', kind: 'compute', label: 'A', typeLabel: 'A', icon: '', data: {} },
    b: { id: 'b', kind: 'compute', label: 'B', typeLabel: 'B', icon: '', data: {} },
    obstacle: { id: 'obstacle', kind: 'compute', label: 'Obstacle', typeLabel: 'Obstacle', icon: '', data: {} },
    parent: { id: 'parent', kind: 'group', label: 'Parent', typeLabel: 'Group', icon: '', data: {}, container: true },
  },
  nodes: [], edges: [], notices: [],
};
const nodes: PositionedNode[] = [
  { id: 'parent', position: { x: 10, y: 10 }, width: 120, height: 120 },
  { id: 'obstacle', parentId: 'parent', position: { x: 30, y: 30 }, width: 20, height: 20 },
];
const edge = (id: string, points: Array<{ x: number; y: number }>): RoutedEdge => ({ id, source: 'a', target: 'b', label: id, sections: points.length ? [points] : [] });

describe('topology routing diagnostics', () => {
  it('counts crossing and overlapping relationship pairs, and reports lines through resource cards', () => {
    const result = inspectArchitectureRouting(model, nodes, [
      edge('horizontal', [{ x: 0, y: 50 }, { x: 100, y: 50 }]),
      edge('vertical', [{ x: 50, y: 0 }, { x: 50, y: 100 }]),
      edge('overlap', [{ x: 10, y: 50 }, { x: 20, y: 50 }]),
    ]);
    expect(result.crossingPairs).toBe(2);
    expect(result.cardObstructions).toBe(2);
  });

  it('ignores shared endpoints and endpoint cards, but identifies missing geometry', () => {
    const endpoints: PositionedNode[] = [{ id: 'a', position: { x: 0, y: 0 }, width: 20, height: 20 }];
    const result = inspectArchitectureRouting(model, endpoints, [
      edge('one', [{ x: 10, y: 10 }, { x: 40, y: 10 }]),
      edge('two', [{ x: 40, y: 10 }, { x: 40, y: 40 }]),
      edge('missing', []),
    ]);
    expect(result.crossingPairs).toBe(0);
    expect(result.cardObstructions).toBe(0);
    expect(result.unrouted).toBe(1);
  });

  it('checks a 391-relationship synthetic graph without dropping routes', () => {
    const edges = Array.from({ length: 391 }, (_, index) => edge(`edge-${index}`, [{ x: 0, y: index * 10 }, { x: 100, y: index * 10 }]));
    expect(inspectArchitectureRouting(model, [], edges)).toEqual({ crossingPairs: 0, cardObstructions: 0, unrouted: 0, incomplete: false });
  });
});
