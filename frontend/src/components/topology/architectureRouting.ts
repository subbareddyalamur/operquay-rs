import type { ArchitectureModel } from './architectureModel';
import type { PositionedNode, RoutedEdge } from './architectureLayout';

type Point = { x: number; y: number };
type Segment = { a: Point; b: Point };
const epsilon = 0.01;

function intersects(first: Segment, second: Segment): boolean {
  const horizontal = (s: Segment) => Math.abs(s.a.y - s.b.y) < epsilon;
  const within = (value: number, a: number, b: number) => value >= Math.min(a, b) - epsilon && value <= Math.max(a, b) + epsilon;
  const h1 = horizontal(first), h2 = horizontal(second);
  if (h1 === h2) {
    const sameAxis = h1 ? Math.abs(first.a.y - second.a.y) < epsilon : Math.abs(first.a.x - second.a.x) < epsilon;
    const [a, b, c, d] = h1 ? [first.a.x, first.b.x, second.a.x, second.b.x] : [first.a.y, first.b.y, second.a.y, second.b.y];
    return sameAxis && Math.min(Math.max(a, b), Math.max(c, d)) - Math.max(Math.min(a, b), Math.min(c, d)) > epsilon;
  }
  const h = h1 ? first : second, v = h1 ? second : first;
  if (!within(v.a.x, h.a.x, h.b.x) || !within(h.a.y, v.a.y, v.b.y)) return false;
  const hEnd = Math.abs(v.a.x - h.a.x) < epsilon || Math.abs(v.a.x - h.b.x) < epsilon;
  const vEnd = Math.abs(h.a.y - v.a.y) < epsilon || Math.abs(h.a.y - v.b.y) < epsilon;
  return !(hEnd && vEnd);
}

export function inspectArchitectureRouting(model: ArchitectureModel, nodes: PositionedNode[], edges: RoutedEdge[]) {
  const lookup = new Map(nodes.map(node => [node.id, node]));
  const absolute = (node: PositionedNode): Point => {
    let x = node.position.x, y = node.position.y;
    let parent = node.parentId;
    const seen = new Set([node.id]);
    while (parent && !seen.has(parent)) {
      seen.add(parent);
      const item = lookup.get(parent);
      if (!item) break;
      x += item.position.x; y += item.position.y; parent = item.parentId;
    }
    return { x, y };
  };
  const cards = nodes.filter(node => !model.resources[node.id]?.container).map(node => ({ ...node, ...absolute(node) }));
  const segments = edges.map(edge => edge.sections.flatMap(points => points.slice(1).map((point, index) => ({ a: points[index], b: point }))));
  let crossingPairs = 0, cardObstructions = 0, comparisons = 0, incomplete = false;
  // shortcut: bound diagnostic work on very large graphs; move it to a worker before increasing the budget.
  const budget = 2_000_000;
  for (let i = 0; i < edges.length && !incomplete; i++) {
    for (let j = i + 1; j < edges.length; j++) {
      if (++comparisons > budget) { incomplete = true; break; }
      if (segments[i].some(a => segments[j].some(b => intersects(a, b)))) crossingPairs++;
    }
    for (const card of cards) {
      if (incomplete) break;
      if (++comparisons > budget) { incomplete = true; break; }
      if (card.id === edges[i].source || card.id === edges[i].target) continue;
      if (segments[i].some(({ a, b }) => Math.abs(a.x - b.x) < epsilon
        ? a.x > card.x + epsilon && a.x < card.x + card.width - epsilon && Math.max(a.y, b.y) > card.y + epsilon && Math.min(a.y, b.y) < card.y + card.height - epsilon
        : a.y > card.y + epsilon && a.y < card.y + card.height - epsilon && Math.max(a.x, b.x) > card.x + epsilon && Math.min(a.x, b.x) < card.x + card.width - epsilon)) cardObstructions++;
    }
  }
  return { crossingPairs, cardObstructions, unrouted: edges.filter(edge => !edge.sections.length).length, incomplete };
}
