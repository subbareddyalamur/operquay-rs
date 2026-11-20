import { describe, expect, it } from 'vitest';
import { buildAWSArchitecture } from './architectureGraph';
import { layoutArchitecture } from './architectureLayout';
import { inspectArchitectureRouting } from './architectureRouting';
import type { VPCTopology } from '@/lib/topology-types';

const fixture: VPCTopology = {
  vpc: { id: 'vpc-main', name: 'Main', cidr: '10.0.0.0/16', isDefault: false },
  subnets: [{ id: 'subnet-a', name: 'App', az: 'us-east-1a', cidr: '10.0.1.0/24', isPublic: false, availableIps: 20, routeTableId: 'rtb-a', networkAclId: 'acl-a' }],
  instances: [{ id: 'i-main', name: 'App server', privateIp: '10.0.1.10', publicIp: '', state: 'running', platform: 'linux', instanceType: 't3.small', subnetId: 'subnet-a', securityGroups: ['sg-a'] }],
  securityGroups: [{ id: 'sg-a', name: 'app-sg', description: '', inboundRules: [{ protocol: 'tcp', fromPort: 443, toPort: 443, source: 'sg-lb' }], outboundRules: [] }],
  networkAcls: [{ id: 'acl-a', isDefault: false, subnetIds: ['subnet-a'], rules: [{ ruleNumber: 100, direction: 'inbound', protocol: 'tcp', fromPort: 443, toPort: 443, cidrBlock: '10.0.0.0/16', action: 'allow' }] }],
  routeTables: [{ id: 'rtb-a', name: 'App routes', subnetIds: ['subnet-a'], isMain: false, routes: [{ destination: '10.2.0.0/16', target: 'tgw-1', targetType: 'tgw', state: 'active' }] }],
  internetGateways: [], natGateways: [],
  tgwAttachments: [{ attachmentId: 'tgw-attach-main', tgwId: 'tgw-1', tgwName: 'Hub', resourceType: 'vpc', state: 'available', subnetIds: ['subnet-a'], peerAttachments: [{ attachmentId: 'tgw-attach-peer', resourceType: 'vpc', resourceId: 'vpc-peer', state: 'available' }] }],
  peerVpcDetails: [{ vpcId: 'vpc-peer', name: 'Peer', cidr: '10.2.0.0/16', connectionType: 'tgw', subnets: [{ id: 'subnet-peer', name: 'Peer subnet', az: 'us-east-1b', cidr: '10.2.1.0/24', isPublic: false, availableIps: 20, routeTableId: 'rtb-peer', networkAclId: 'acl-peer' }], instances: [{ id: 'i-peer', name: 'Peer server', privateIp: '10.2.1.10', publicIp: '', state: 'running', platform: 'linux', instanceType: 't3.small', subnetId: 'subnet-peer', securityGroups: ['sg-peer'] }], natGateways: [], securityGroups: [{ id: 'sg-peer', name: 'Peer SG', description: '', inboundRules: [], outboundRules: [] }], networkAcls: [{ id: 'acl-peer', isDefault: false, subnetIds: ['subnet-peer'], rules: [] }], routeTables: [{ id: 'rtb-peer', name: 'Peer routes', subnetIds: ['subnet-peer'], isMain: false, routes: [{ destination: '10.0.0.0/16', target: 'tgw-1', targetType: 'tgw', state: 'active' }] }], loadBalancers: [{ arn: 'arn:peer-lb', name: 'Peer LB', dnsName: '', type: 'network', scheme: 'internal', subnetIds: ['subnet-peer'], securityGroups: ['sg-peer'], listeners: [], targets: [{ targetId: 'i-peer', port: 80, healthState: 'healthy' }] }] }],
  loadBalancers: [{ arn: 'arn:lb', name: 'App LB', dnsName: '', type: 'application', scheme: 'internal', subnetIds: ['subnet-a'], listeners: [{ port: 443, protocol: 'HTTPS' }], targets: [{ targetId: 'i-main', port: 443, healthState: 'healthy' }] }],
  fetchedAt: '2026-01-01T00:00:00Z',
};

describe('reconstructed architecture', () => {
  it('keeps all instances and places NAT gateways in their known subnets', () => {
    const extra = { ...fixture.instances[0], id: 'i-other', name: 'Other' };
    const nat = { id: 'nat-a', name: 'NAT', subnetId: 'subnet-a', publicIp: '', state: 'available' };
    const model = buildAWSArchitecture({ ...fixture, instances: [...fixture.instances, extra], natGateways: [nat] }, 'i-main');
    expect(model.nodes.find(node => node.id === 'instance:i-other')?.parentId).toBe('group:subnet:vpc-main:subnet-a');
    expect(model.nodes.find(node => node.id === 'nat:nat-a')?.parentId).toBe('group:subnet:vpc-main:subnet-a');
    expect(model.edges.some(edge => edge.source === 'instance:i-other' && edge.target === 'sg:sg-a')).toBe(true);
  });

  it('retains orphaned peer instances and warns about unresolved associations', () => {
    const peer = fixture.peerVpcDetails![0];
    const topology = { ...fixture, peerVpcDetails: [{ ...peer, subnets: [] }] };
    const model = buildAWSArchitecture(topology, 'i-main');
    expect(model.nodes.find(node => node.id === 'peer-instance:vpc-peer:i-peer')?.parentId).toBe('group:peer:vpc-peer');
    expect(model.notices.some(note => note.includes('i-peer') && note.includes('subnet'))).toBe(true);
    expect(model.notices.some(note => note.includes('sg-lb') && note.includes('security group rule'))).toBe(true);
  });

  it('keeps distinct transit gateway attachments to the same gateway', () => {
    const first = fixture.tgwAttachments![0];
    const second = { ...first, attachmentId: 'tgw-attach-second', peerAttachments: [] };
    const model = buildAWSArchitecture({ ...fixture, tgwAttachments: [first, second] }, 'i-main');
    expect(model.edges.filter(edge => edge.source === 'vpc:vpc-main' && edge.target === 'tgw:tgw-1')).toHaveLength(2);
  });

  it('retains distinct security-group rules and non-VPC gateway attachments', () => {
    const securityGroups = [fixture.securityGroups[0], { id: 'sg-lb', name: 'LB', description: '', inboundRules: [], outboundRules: [] }];
    securityGroups[0] = { ...securityGroups[0], inboundRules: [...securityGroups[0].inboundRules, { protocol: 'tcp', fromPort: 80, toPort: 80, source: 'sg-lb' }] };
    const attachment = fixture.tgwAttachments![0];
    const topology = { ...fixture, securityGroups, tgwAttachments: [{ ...attachment, peerAttachments: [...attachment.peerAttachments!, { attachmentId: 'attach-vpn', resourceType: 'vpn', resourceId: 'vpn-1', state: 'available' }] }] };
    const model = buildAWSArchitecture(topology, 'i-main');
    expect(model.edges.filter(edge => edge.source === 'sg:sg-lb' && edge.target === 'sg:sg-a')).toHaveLength(2);
    expect(model.resources['tgw-attachment:attach-vpn']?.data['resourceId']).toBe('vpn-1');
    expect(model.edges.some(edge => edge.source === 'tgw:tgw-1' && edge.target === 'tgw-attachment:attach-vpn')).toBe(true);
  });
  it('retains self-referencing security group rules', async () => {
    const sg = { ...fixture.securityGroups[0], inboundRules: [{ protocol: 'tcp', fromPort: 443, toPort: 443, source: 'sg-a' }] };
    const model = buildAWSArchitecture({ ...fixture, securityGroups: [sg] }, 'i-main');
    const rule = model.edges.find(edge => edge.source === 'sg:sg-a' && edge.target === 'sg:sg-a');
    expect(rule).toBeDefined();
    const layout = await layoutArchitecture(model);
    expect(layout.edges.find(edge => edge.id === rule!.id)?.sections.length).toBeGreaterThan(0);
  });

  it('keeps resource boundaries and only records observed associations', () => {
    const model = buildAWSArchitecture(fixture, 'i-main');
    expect(model.resources['instance:i-main']?.kind).toBe('instance');
    expect(model.resources['sg:sg-a']?.kind).toBe('sg');
    expect(model.resources['nacl:acl-a']?.kind).toBe('nacl');
    expect(model.resources['lb:arn:lb']?.kind).toBe('load-balancer');
    expect(model.resources['peer:vpc-peer']?.kind).toBe('peer-vpc');
    expect(model.resources['peer-subnet:vpc-peer:subnet-peer']?.kind).toBe('subnet');
    expect(model.resources['peer-route:vpc-peer:rtb-peer']?.kind).toBe('route-table');
    expect(model.resources['peer-nacl:vpc-peer:acl-peer']?.kind).toBe('nacl');
    expect(model.resources['peer-lb:vpc-peer:arn:peer-lb']?.kind).toBe('load-balancer');
    expect(model.edges.some(e => e.source === 'instance:i-main' && e.target === 'sg:sg-a')).toBe(true);
    expect(model.edges.some(e => e.source === 'route:rtb-a' && e.target === 'tgw:tgw-1')).toBe(true);
    expect(model.edges.some(e => e.source === 'lb:arn:lb' && e.target === 'instance:i-main')).toBe(true);
    expect(model.edges.some(e => e.source === 'peer-route:vpc-peer:rtb-peer' && e.target === 'tgw:tgw-1')).toBe(true);
    expect(model.edges.some(e => e.source === 'peer-lb:vpc-peer:arn:peer-lb' && e.target === 'peer-instance:vpc-peer:i-peer')).toBe(true);
    expect(model.edges.some(e => e.label.includes('reachable'))).toBe(false);
  });

  it('does not invent a gateway connection when the target is unavailable', () => {
    const topology: VPCTopology = { ...fixture, routeTables: [{ ...fixture.routeTables[0], routes: [{ destination: '0.0.0.0/0', target: 'nat-missing', targetType: 'nat', state: 'blackhole' }] }] };
    const model = buildAWSArchitecture(topology, 'i-main');
    expect(model.edges.some(edge => edge.target.includes('nat-missing'))).toBe(false);
    expect(model.notices.some(note => note.includes('nat-missing'))).toBe(true);
  });

  it('shows the selected instance when its subnet details are unavailable', () => {
    const model = buildAWSArchitecture({ ...fixture, subnets: [] }, 'i-main');
    expect(model.nodes.find(node => node.id === 'instance:i-main')?.parentId).toBe('group:vpc:vpc-main');
    expect(model.notices.some(note => note.includes('subnet'))).toBe(true);
    expect(model.edges.some(edge => edge.source === 'instance:i-main' && edge.target === 'sg:sg-a')).toBe(true);
  });

  it('keeps Classic load balancers without ARNs distinct and linked to their instances', () => {
    const classic = { arn: '', id: 'classic:old-app', name: 'old-app', dnsName: '', type: 'classic', scheme: 'internal', subnetIds: ['subnet-a'], listeners: [], targets: [{ targetId: 'i-main', port: 0, healthState: 'InService' }] };
    const model = buildAWSArchitecture({ ...fixture, loadBalancers: [fixture.loadBalancers![0], classic, { ...classic, id: 'classic:second', name: 'second' }] }, 'i-main');
    expect(model.resources['lb:classic:old-app']?.label).toBe('old-app');
    expect(model.resources['lb:classic:second']?.label).toBe('second');
    expect(model.edges.some(edge => edge.source === 'lb:classic:old-app' && edge.target === 'instance:i-main' && edge.label === 'registered target')).toBe(true);
  });

  it('lays out siblings without overlapping and produces orthogonal routed edges', async () => {
    const model = buildAWSArchitecture(fixture, 'i-main');
    const laidOut = await layoutArchitecture(model);
    for (let i = 0; i < laidOut.nodes.length; i++) for (let j = i + 1; j < laidOut.nodes.length; j++) {
      const a = laidOut.nodes[i], b = laidOut.nodes[j];
      if (a.parentId !== b.parentId) continue;
      const overlap = a.position.x < b.position.x + b.width && b.position.x < a.position.x + a.width && a.position.y < b.position.y + b.height && b.position.y < a.position.y + a.height;
      expect(overlap, `${a.id} overlaps ${b.id}`).toBe(false);
    }
    expect(laidOut.edges.length).toBe(model.edges.length);
    for (const edge of laidOut.edges) {
      expect(edge.sections.length).toBeGreaterThan(0);
      for (const points of edge.sections) {
        expect(points.length).toBeGreaterThan(1);
        for (let i = 1; i < points.length; i++) expect(Math.abs(points[i].x - points[i - 1].x) < 0.001 || Math.abs(points[i].y - points[i - 1].y) < 0.001, edge.id).toBe(true);
      }
    }
    const byId = new Map(laidOut.nodes.map(node => [node.id, node]));
    const absolute = (id: string): { x: number; y: number } => {
      const node = byId.get(id)!;
      const parent = node.parentId ? absolute(node.parentId) : { x: 0, y: 0 };
      return { x: node.position.x + parent.x, y: node.position.y + parent.y };
    };
    for (const edge of laidOut.edges) for (const points of edge.sections) for (let i = 1; i < points.length; i++) {
      const a = points[i - 1], b = points[i];
      for (const node of laidOut.nodes) {
        if (model.resources[node.id].container || node.id === edge.source || node.id === edge.target) continue;
        const p = absolute(node.id), epsilon = 0.01;
        const hits = Math.abs(a.x - b.x) < epsilon
          ? a.x > p.x + epsilon && a.x < p.x + node.width - epsilon && Math.max(a.y, b.y) > p.y + epsilon && Math.min(a.y, b.y) < p.y + node.height - epsilon
          : a.y > p.y + epsilon && a.y < p.y + node.height - epsilon && Math.max(a.x, b.x) > p.x + epsilon && Math.min(a.x, b.x) < p.x + node.width - epsilon;
        expect(hits, `${edge.id} crosses ${node.id}`).toBe(false);
      }
    }
  });

  it('layouts are provider-independent', async () => {
    const layout = await layoutArchitecture({ resources: {
      project: { id: 'project', kind: 'project', label: 'Example project', typeLabel: 'Project', icon: 'project', data: {}, container: true },
      vm: { id: 'vm', kind: 'compute', label: 'Example VM', typeLabel: 'Virtual machine', icon: 'compute', data: {} },
      network: { id: 'network', kind: 'network', label: 'Example network', typeLabel: 'Network', icon: 'network', data: {} },
    }, nodes: [{ id: 'project' }, { id: 'vm', parentId: 'project' }, { id: 'network', parentId: 'project' }], edges: [{ id: 'vm-network', source: 'vm', target: 'network', label: 'attached' }], notices: [] });
    expect(layout.nodes.map(node => node.id)).toEqual(['project', 'vm', 'network']);
    expect(layout.edges[0].sections.length).toBeGreaterThan(0);
  });

  it('routes every relationship in a synthetic 391-edge graph', async () => {
    const nodes = Array.from({ length: 24 }, (_, index) => ({ id: `resource-${index}` }));
    const resources = Object.fromEntries(nodes.map(node => [node.id, { id: node.id, kind: 'resource', label: node.id, typeLabel: 'Resource', icon: '', data: {} }]));
    const edges = nodes.flatMap((source, i) => nodes.filter((_, j) => j > i).map(target => ({ id: `${source.id}>${target.id}`, source: source.id, target: target.id, label: 'association' })));
    // Add a second distinct relationship for a subset of pairs.
    edges.push(...edges.slice(0, 115).map(edge => ({ ...edge, id: `${edge.id}:second`, label: 'second association' })));
    expect(edges).toHaveLength(391);
    const layout = await layoutArchitecture({ nodes, resources, edges, notices: [] });
    expect(layout.nodes).toHaveLength(nodes.length);
    expect(layout.edges).toHaveLength(edges.length);
    expect(layout.edges.every(edge => edge.sections.length > 0)).toBe(true);
  }, 60_000);

  it('keeps all 391 links in a nested VPC and availability-zone fixture', async () => {
    const roots = [{ id: 'vpc' }, ...Array.from({ length: 4 }, (_, i) => ({ id: `az-${i}`, parentId: 'vpc' }))];
    const children = Array.from({ length: 40 }, (_, i) => ({ id: `node-${i}`, parentId: `az-${Math.floor(i / 10)}` }));
    const nodes = [...roots, ...children];
    const resources = Object.fromEntries(nodes.map(node => [node.id, { id: node.id, kind: 'resource', label: node.id, typeLabel: 'Resource', icon: '', data: {}, container: roots.some(root => root.id === node.id) }]));
    const edges = children.flatMap((source, i) => children.slice(i + 1).map(target => ({ id: `${source.id}>${target.id}`, source: source.id, target: target.id, label: 'association' }))).slice(0, 391);
    const model = { nodes, resources, edges, notices: [] };
    const layout = await layoutArchitecture(model);
    expect(layout.nodes).toHaveLength(nodes.length);
    expect(layout.edges).toHaveLength(391);
    expect(layout.edges.every(edge => edge.sections.length > 0)).toBe(true);
    const diagnostics = inspectArchitectureRouting(model, layout.nodes, layout.edges);
    expect(diagnostics.incomplete).toBe(false);
    expect(diagnostics.unrouted).toBe(0);
  }, 60_000);
});
