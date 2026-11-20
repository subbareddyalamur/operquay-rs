import { describe, expect, it } from 'vitest';
import type { VPCTopology } from '@/lib/topology-types';
import { buildAWSArchitecture } from './architectureGraph';
import { projectTopology } from './topologyView';
import { focusedRelationships, topologyOverview } from './topologyOverview';
import { layoutArchitecture } from './architectureLayout';
import { pngDimensions, topologySvg } from './topologyExport';
import { defaultPalette } from './TopologyVisual';

function largeTopology(): VPCTopology {
  const subnets = Array.from({ length: 48 }, (_, i) => ({ id: `subnet-${i}`, name: `Subnet ${i}`, az: `zone-${Math.floor(i / 6)}`, cidr: `10.${i}.0.0/24`, isPublic: false, availableIps: 100, routeTableId: `rt-${i % 24}`, networkAclId: `acl-${i % 24}` }));
  const instances = Array.from({ length: 120 }, (_, i) => ({ id: `i-${i}`, name: `Instance ${i}`, privateIp: `10.0.0.${i + 1}`, publicIp: '', state: 'running', platform: 'linux', instanceType: 'test', subnetId: `subnet-${i % 48}`, securityGroups: [`sg-${i % 80}`, `sg-${(i + 1) % 80}`] }));
  return {
    vpc: { id: 'vpc-main', name: 'Main VPC', cidr: '10.0.0.0/16', isDefault: false }, subnets, instances,
    securityGroups: Array.from({ length: 80 }, (_, i) => ({ id: `sg-${i}`, name: `Security ${i}`, description: '', inboundRules: [{ protocol: 'tcp', fromPort: 443, toPort: 443, source: `sg-${(i + 1) % 80}` }], outboundRules: [] })),
    routeTables: Array.from({ length: 24 }, (_, i) => ({ id: `rt-${i}`, name: `Routes ${i}`, subnetIds: [], isMain: false, routes: [{ destination: '10.2.0.0/16', target: 'tgw-1', targetType: 'tgw', state: 'active' }] })),
    networkAcls: Array.from({ length: 24 }, (_, i) => ({ id: `acl-${i}`, isDefault: false, subnetIds: [], rules: [] })),
    internetGateways: [], natGateways: [],
    tgwAttachments: [{ attachmentId: 'attach-main', tgwId: 'tgw-1', tgwName: 'Hub', resourceType: 'vpc', state: 'available', peerAttachments: Array.from({ length: 8 }, (_, i) => ({ attachmentId: `peer-attach-${i}`, resourceType: 'vpc', resourceId: `vpc-peer-${i}`, state: 'available' })) }],
    fetchedAt: '2026-01-01T00:00:00Z',
  };
}

describe('large topology overview', () => {
  it('opens around the selected subnet instead of rendering hundreds of individual cards', async () => {
    const topology = largeTopology();
    const model = buildAWSArchitecture(topology, 'i-0');
    const overview = topologyOverview(model, topology, 'i-0');
    const options = { aliases: overview.aliases, focusEdges: focusedRelationships(overview.model, topology, 'i-0', overview.collapsed) };
    const view = projectTopology(overview.model, overview.collapsed, 'focus', options);
    expect(model.nodes.length).toBeGreaterThan(300);
    expect(model.edges.length).toBeGreaterThan(400);
    expect(view.nodes.some(node => node.id === 'instance:i-0')).toBe(true);
    expect(view.nodes.length).toBeLessThanOrEqual(35);
    expect(view.nodes.some(node => node.id === 'route:rt-0')).toBe(true);
    expect(view.nodes.some(node => node.id === 'sg:sg-0')).toBe(true);
    expect(view.nodes.some(node => node.id === 'nacl:acl-0')).toBe(true);
    expect(view.nodes.some(node => node.id === 'summary:external:tgw:tgw-1')).toBe(true);
    expect(view.nodes.some(node => node.id === 'tgw:tgw-1' || node.id.startsWith('group:peer:'))).toBe(false);
    expect(view.nodes.some(node => node.id === 'subnet:subnet-0' || node.id === 'vpc:vpc-main')).toBe(false);
    expect(view.edges.length).toBeLessThanOrEqual(12);
    expect(overview.model.edges).toHaveLength(model.edges.length);
    expect(model.nodes.every(node => overview.model.resources[node.id])).toBe(true);
    const openStub = new Set(overview.collapsed); openStub.delete('summary:external:tgw:tgw-1');
    const extended = projectTopology(overview.model, openStub, 'focus', { aliases: overview.aliases, focusEdges: focusedRelationships(overview.model, topology, 'i-0', openStub) });
    expect(extended.nodes.some(node => node.id === 'tgw:tgw-1')).toBe(true);
    expect(extended.nodes.some(node => node.id === 'group:peer:vpc-peer-0')).toBe(true);
    expect(extended.nodes.some(node => node.id.startsWith('peer-subnet:'))).toBe(false);
    const expanded = projectTopology(overview.model, new Set(), 'all', { aliases: overview.aliases });
    expect(expanded.allEdges.map(edge => edge.id).sort()).toEqual(model.edges.map(edge => edge.id).sort());
    const layout = await layoutArchitecture(view);
    expect(layout.nodes.map(node => node.id)).toContain('instance:i-0');
    expect(layout.edges).toHaveLength(view.edges.length);
    const roots = layout.nodes.filter(node => !node.parentId);
    const width = Math.max(...roots.map(node => node.position.x + node.width));
    const height = Math.max(...roots.map(node => node.position.y + node.height));
    expect(height / width, `overview is ${Math.round(width)} × ${Math.round(height)}`).toBeLessThanOrEqual(2);
    const svg = topologySvg(view, layout.nodes, layout.edges, defaultPalette, overview.collapsed, view.hiddenCount, view.internalCount, false);
    expect(() => pngDimensions(svg.width, svg.height, 4)).not.toThrow();
  }, 60_000);
  it('does not hide the selected instance when subnet details are missing', () => {
    const topology = largeTopology();
    topology.subnets = topology.subnets.filter(subnet => subnet.id !== 'subnet-0');
    const model = buildAWSArchitecture(topology, 'i-0');
    const overview = topologyOverview(model, topology, 'i-0');
    const view = projectTopology(overview.model, overview.collapsed, 'all');
    expect(view.nodes.some(node => node.id === 'instance:i-0')).toBe(true);
    expect(view.notices.some(notice => notice.includes('i-0') && notice.includes('subnet'))).toBe(true);
  });
  it('shows a route table and ACL when their subnet associations are returned only on those resources', () => {
    const topology = largeTopology();
    topology.subnets[0] = { ...topology.subnets[0], routeTableId: '', networkAclId: '' };
    topology.routeTables[0] = { ...topology.routeTables[0], subnetIds: ['subnet-0'] };
    topology.networkAcls[0] = { ...topology.networkAcls[0], subnetIds: ['subnet-0'] };
    const model = buildAWSArchitecture(topology, 'i-0');
    const overview = topologyOverview(model, topology, 'i-0');
    const view = projectTopology(overview.model, overview.collapsed, 'focus', { aliases: overview.aliases, focusEdges: focusedRelationships(overview.model, topology, 'i-0', overview.collapsed) });
    expect(view.nodes.some(node => node.id === 'route:rt-0')).toBe(true);
    expect(view.nodes.some(node => node.id === 'nacl:acl-0')).toBe(true);
    expect(view.allEdges.some(edge => edge.source === 'route:rt-0' && edge.target === 'tgw:tgw-1')).toBe(true);
  });
  it('summarizes unassociated peer VPCs without inventing a PrivateLink connection', () => {
    const topology = largeTopology();
    topology.peerVpcDetails = [{ vpcId: 'vpc-unknown', name: 'Unverified peer', cidr: '', connectionType: 'privatelink', subnets: [], instances: [] }];
    const model = buildAWSArchitecture(topology, 'i-0');
    const overview = topologyOverview(model, topology, 'i-0');
    const view = projectTopology(overview.model, overview.collapsed, 'focus', { aliases: overview.aliases, focusEdges: focusedRelationships(overview.model, topology, 'i-0', overview.collapsed) });
    expect(view.nodes.some(node => node.id === 'summary:unmatched-peers')).toBe(true);
    expect(view.nodes.some(node => node.id === 'group:peer:vpc-unknown')).toBe(false);
    expect(view.edges.some(edge => edge.source === 'summary:unmatched-peers' || edge.target === 'summary:unmatched-peers')).toBe(false);
    expect(view.notices.some(note => note.includes('specific endpoint relationship was not returned'))).toBe(true);
  });
  it('keeps many external gateways as bounded expandable stubs', () => {
    const topology = largeTopology();
    topology.tgwAttachments = Array.from({ length: 12 }, (_, i) => ({ attachmentId: `attachment-${i}`, tgwId: `tgw-${i}`, tgwName: `Gateway ${i}`, resourceType: 'vpc', state: 'available', peerAttachments: [] }));
    const model = buildAWSArchitecture(topology, 'i-0');
    const overview = topologyOverview(model, topology, 'i-0');
    const view = projectTopology(overview.model, overview.collapsed, 'focus', { aliases: overview.aliases, focusEdges: focusedRelationships(overview.model, topology, 'i-0', overview.collapsed) });
    expect(view.nodes.filter(node => node.id.startsWith('summary:external:tgw:')).length).toBeLessThanOrEqual(3);
    expect(view.nodes.some(node => node.id === 'summary:other-external-stubs')).toBe(true);
    expect(view.nodes.some(node => node.id === 'summary:external:tgw:tgw-1')).toBe(true);
    const opened = new Set(overview.collapsed); opened.delete('summary:other-external-stubs');
    const expanded = projectTopology(overview.model, opened, 'focus', { aliases: overview.aliases, focusEdges: focusedRelationships(overview.model, topology, 'i-0', opened) });
    expect(expanded.nodes.filter(node => node.id.startsWith('summary:external:tgw:'))).toHaveLength(12);
    expect(expanded.nodes.some(node => node.id.startsWith('tgw:'))).toBe(false);
  });
  it('keeps a crowded selected subnet readable without dropping its instances', () => {
    const topology = largeTopology();
    topology.instances = topology.instances.map(instance => ({ ...instance, subnetId: 'subnet-0' }));
    const overview = topologyOverview(buildAWSArchitecture(topology, 'i-0'), topology, 'i-0');
    const view = projectTopology(overview.model, overview.collapsed, 'focus', { aliases: overview.aliases, focusEdges: focusedRelationships(overview.model, topology, 'i-0', overview.collapsed) });
    expect(view.nodes.some(node => node.id === 'instance:i-0')).toBe(true);
    expect(view.hiddenCount['summary:other-instances']).toBe(119);
    expect(view.nodes.length).toBeLessThanOrEqual(35);
  });
  it('expands an observed VPC peering stub without opening its peer by default', () => {
    const topology = largeTopology();
    topology.vpcPeerings = [{ id: 'pcx-1', status: 'active', requesterVpc: 'vpc-main', requesterCidr: '10.0.0.0/16', accepterVpc: 'vpc-direct', accepterCidr: '10.30.0.0/16', peerVpcName: 'Direct peer' }];
    const model = buildAWSArchitecture(topology, 'i-0');
    const overview = topologyOverview(model, topology, 'i-0');
    const project = (collapsed: Set<string>) => projectTopology(overview.model, collapsed, 'focus', { aliases: overview.aliases, focusEdges: focusedRelationships(overview.model, topology, 'i-0', collapsed) });
    const initial = project(overview.collapsed);
    expect(initial.nodes.some(node => node.id === 'summary:external:peering:pcx-1')).toBe(true);
    expect(initial.nodes.some(node => node.id === 'group:peer:vpc-direct')).toBe(false);
    const opened = new Set(overview.collapsed); opened.delete('summary:external:peering:pcx-1');
    const next = project(opened);
    expect(next.nodes.some(node => node.id === 'peering:pcx-1')).toBe(true);
    expect(next.nodes.some(node => node.id === 'group:peer:vpc-direct')).toBe(true);
    expect(next.notices.some(note => note.includes('vpc-direct') && note.includes('not returned'))).toBe(true);
  });
});
