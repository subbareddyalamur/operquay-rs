import { describe, expect, it } from 'vitest';
import { topologySvg, pngDimensions } from './topologyExport';
import { defaultPalette } from './TopologyVisual';
import type { ArchitectureModel } from './architectureModel';

describe('topology exports', () => {
  it('exports vector content, labels and offscreen routed geometry without cropping', () => {
    const model: ArchitectureModel = { resources: { a: { id: 'a', kind: 'instance', label: 'Server & service', typeLabel: 'Instance', icon: '', data: {}, selected: true } }, nodes: [{ id: 'a' }], edges: [], notices: [] };
    const result = topologySvg(model, [{ id: 'a', position: { x: -120, y: 20 }, width: 100, height: 80 }], [{ id: 'edge', source: 'a', target: 'a', label: 'Custom', sections: [[{ x: -120, y: 30 }, { x: 200, y: 30 }]] }], defaultPalette, new Set(), {}, {}, false);
    expect(result.svg).toContain('<svg');
    expect(result.svg).toContain('Server &amp; service');
    expect(result.svg).toContain('<path');
    expect(result.width).toBeGreaterThan(320);
    expect(result.height).toBeGreaterThan(80);
    expect(result.svg).not.toContain('<image');
  });
  it('rejects unsafe PNG sizes instead of silently reducing resolution', () => {
    expect(pngDimensions(100, 50, 4)).toEqual({ width: 400, height: 200 });
    expect(() => pngDimensions(20000, 100, 4)).toThrow(/too large/i);
    expect(() => pngDimensions(0, 1, 4)).toThrow();
  });
  it('wraps a long selected instance name into visible vector text', () => {
    const name = 'SCE-4.5.0.2-genmab9-genmabdev-dev-SAS';
    const model: ArchitectureModel = { resources: { a: { id: 'a', kind: 'instance', label: name, typeLabel: 'Instance', icon: '', data: {}, selected: true } }, nodes: [{ id: 'a' }], edges: [], notices: [] };
    const output = topologySvg(model, [{ id: 'a', position: { x: 0, y: 0 }, width: 320, height: 130 }], [], defaultPalette, new Set(), {}, {}, false);
    expect(output.svg).toContain(`>${name.slice(0, 29)}</text>`);
    expect(output.svg).toContain(`>${name.slice(29)}</text>`);
  });
});
