import type { VPCTopology } from '@/lib/topology-types';
import type { ArchitectureModel, ArchitectureResource } from './architectureModel';

function selectedNetwork(topology: VPCTopology, selectedId: string) {
  const instance = (topology.instances ?? []).find(item => item.id === selectedId);
  const subnet = (topology.subnets ?? []).find(item => item.id === instance?.subnetId);
  const routes = (topology.routeTables ?? []).filter(item => subnet && (item.subnetIds ?? []).includes(subnet.id));
  const acls = (topology.networkAcls ?? []).filter(item => subnet && (item.subnetIds ?? []).includes(subnet.id));
  return { instance, subnet, routeId: subnet?.routeTableId || (routes.length === 1 ? routes[0].id : undefined), aclId: subnet?.networkAclId || (acls.length === 1 ? acls[0].id : undefined) };
}

export function topologyOverview(model: ArchitectureModel, topology: VPCTopology, selectedId: string) {
  const primary = `group:vpc:${topology.vpc.id}`;
  const { instance: selected, subnet, routeId: selectedRT, aclId: selectedACL } = selectedNetwork(topology, selectedId);
  const selectedSubnet = subnet ? `group:subnet:${topology.vpc.id}:${subnet.id}` : '';
  const selectedAz = subnet ? `group:az:${topology.vpc.id}:${subnet.az || 'unknown'}` : '';
  const selectedGroups = new Set(selected?.securityGroups ?? []);
  const attachedEndpoints = new Set((topology.vpcEndpoints ?? []).filter(endpoint => (endpoint.subnetIds ?? []).includes(subnet?.id ?? '')).slice(0, 2).map(endpoint => endpoint.id));
  const attachedLBs = new Set((topology.loadBalancers ?? []).filter(lb => (lb.targets ?? []).some(target => target.targetId === selected?.id || (!!selected?.privateIp && target.targetId === selected.privateIp))).slice(0, 2).map(lb => lb.arn || lb.id || lb.name));
  const peerGroups = model.nodes.filter(node => node.id.startsWith('group:peer:')).map(node => node.id);
  const peerGroupSet = new Set(peerGroups);
  const gateways = new Map(model.nodes.filter(node => !node.parentId && (node.id.startsWith('tgw:') || node.id.startsWith('peering:'))).map(node => [node.id, model.resources[node.id]]));
  const selectedTargets = new Set((topology.routeTables ?? []).find(table => table.id === selectedRT)?.routes.map(route => `${route.targetType === 'pcx' ? 'peering' : route.targetType}:${route.target}`) ?? []);
  const orderedGateways = [...gateways.keys()].sort((a, b) => Number(selectedTargets.has(b)) - Number(selectedTargets.has(a)) || a.localeCompare(b));
  const hiddenGateways = new Set(orderedGateways.slice(3));
  const peerGateways = new Map<string, Set<string>>();
  for (const edge of model.edges) {
    if (!gateways.has(edge.source)) continue;
    const target = edge.target.startsWith('peer:') ? `group:peer:${edge.target.slice(5)}` : edge.target.startsWith('tgw-attachment:') ? edge.target : '';
    if (!target) continue;
    const matches = peerGateways.get(target) ?? new Set<string>();
    matches.add(edge.source); peerGateways.set(target, matches);
  }
  const parents = new Map(model.nodes.map(node => [node.id, node.parentId]));
  const grouped = new Map<string, { id: string; label: string; parentId?: string; count: number; stub?: ArchitectureResource }>();
  if (hiddenGateways.size) grouped.set('summary:other-external-stubs', { id: 'summary:other-external-stubs', label: 'Other connections', count: hiddenGateways.size });
  const assignments = new Map<string, string>();
  const assign = (nodeId: string, key: string, label: string, parentId?: string) => {
    const id = `summary:${key}`;
    const group = grouped.get(id) ?? { id, label, parentId, count: 0 };
    group.count++; grouped.set(id, group); assignments.set(nodeId, id);
  };
  const assignService = (nodeId: string, key: string, label: string) => {
    const id = 'summary:other-services';
    const group = grouped.get(id) ?? { id, label: 'Other VPC resources', parentId: primary, count: 0 };
    group.count++; grouped.set(id, group);
    assign(nodeId, key, label, id);
  };
  for (const node of model.nodes) {
    const item = model.resources[node.id];
    if (node.parentId === primary && node.id.startsWith(`group:az:${topology.vpc.id}:`) && node.id !== selectedAz) assign(node.id, 'other-zones', 'Other AZs', primary);
    else if (selectedAz && node.parentId === selectedAz && node.id.startsWith(`group:subnet:${topology.vpc.id}:`) && node.id !== selectedSubnet) assign(node.id, 'other-subnets', 'Other subnets', selectedAz);
    else if (selectedSubnet && node.parentId === selectedSubnet && item.kind === 'instance' && !item.selected) assign(node.id, 'other-instances', 'Other instances', selectedSubnet);
    else if (gateways.has(node.id)) {
      const key = `external:${node.id}`;
      assign(node.id, key, item.label, hiddenGateways.has(node.id) ? 'summary:other-external-stubs' : undefined);
      grouped.get(`summary:${key}`)!.stub = item;
    }
    else if (peerGroupSet.has(node.id) || node.id.startsWith('tgw-attachment:')) {
      const matches = peerGateways.get(node.id);
      if (matches?.size === 1) {
        const gatewayId = [...matches][0], gateway = gateways.get(gatewayId)!;
        const key = `external:${gatewayId}`;
        assign(node.id, key, gateway.label, hiddenGateways.has(gatewayId) ? 'summary:other-external-stubs' : undefined);
        grouped.get(`summary:${key}`)!.stub = gateway;
      } else if (peerGroupSet.has(node.id)) assign(node.id, 'unmatched-peers', 'Other external VPCs');
    }
    else if (node.parentId === primary) {
      const id = String(item.data['id'] ?? '');
      if (item.kind === 'sg' && !selectedGroups.has(id)) assignService(node.id, 'other-sg', 'Other security groups');
      else if (item.kind === 'nacl' && id !== selectedACL) assignService(node.id, 'other-acl', 'Other network ACLs');
      else if (item.kind === 'route-table' && id !== selectedRT) assignService(node.id, 'other-routes', 'Other route tables');
      else if (item.kind === 'igw') assignService(node.id, 'gateways', 'Internet gateways');
      else if (item.kind === 'vpc-endpoint' && !attachedEndpoints.has(id)) assignService(node.id, 'other-endpoints', 'Other VPC endpoints');
      else if (item.kind === 'load-balancer' && !attachedLBs.has(String(item.data['arn'] || item.data['id'] || item.data['name']))) assignService(node.id, 'other-lbs', 'Other load balancers');
    }
  }
  const resources = { ...model.resources };
  const nodes: ArchitectureModel['nodes'] = [];
  const added = new Set<string>();
  const addGroup = (id: string) => {
    if (added.has(id)) return;
    const group = grouped.get(id)!;
    if (group.parentId && grouped.has(group.parentId)) addGroup(group.parentId);
    resources[id] = group.stub
      ? { id, kind: 'stub', label: group.label, typeLabel: `${group.stub.typeLabel} · connections`, icon: group.stub.icon, data: { count: group.count, counterparts: [...peerGateways.values()].filter(matches => matches.has(group.stub!.id)).length }, container: true }
      : { id, kind: 'summary', label: `${group.label} · ${group.count}`, typeLabel: 'Group', icon: '', data: { count: group.count }, container: true } satisfies ArchitectureResource;
    nodes.push({ id, parentId: group.parentId }); added.add(id);
  };
  for (const node of model.nodes) {
    const groupId = assignments.get(node.id);
    if (groupId) addGroup(groupId);
    nodes.push(groupId ? { ...node, parentId: groupId } : node);
  }
  const collapsed = new Set<string>([...grouped.keys(), ...peerGroups]);
  for (const node of nodes) {
    if (node.id.startsWith(`group:az:${topology.vpc.id}:`) && node.id !== selectedAz) collapsed.add(node.id);
    if (node.id.startsWith(`group:subnet:${topology.vpc.id}:`) && node.id !== selectedSubnet) collapsed.add(node.id);
  }
  // The selected subnet must remain visible even when its AZ was not returned.
  let parent = parents.get(`instance:${selectedId}`);
  while (parent) { collapsed.delete(parent); parent = parents.get(parent); }
  const aliases = new Map<string, string>();
  aliases.set(`vpc:${topology.vpc.id}`, primary);
  for (const item of topology.subnets ?? []) aliases.set(`subnet:${item.id}`, `group:subnet:${topology.vpc.id}:${item.id}`);
  for (const peer of topology.peerVpcDetails ?? []) {
    aliases.set(`peer:${peer.vpcId}`, `group:peer:${peer.vpcId}`);
    for (const item of peer.subnets ?? []) aliases.set(`peer-subnet:${peer.vpcId}:${item.id}`, `group:subnet:${peer.vpcId}:${item.id}`);
  }
  for (const peerId of peerGroups) aliases.set(`peer:${peerId.slice('group:peer:'.length)}`, peerId);
  return { model: { ...model, resources, nodes }, collapsed, aliases };
}

export function focusedRelationships(model: ArchitectureModel, topology: VPCTopology, selectedId: string, collapsed: Set<string>) {
  const { instance, subnet, routeId: route } = selectedNetwork(topology, selectedId);
  const selected = `instance:${selectedId}`, subnetId = subnet ? `subnet:${subnet.id}` : '', routeId = route ? `route:${route}` : '';
  const groups = new Set((instance?.securityGroups ?? []).map(id => `sg:${id}`));
  const parents = new Map(model.nodes.map(node => [node.id, node.parentId]));
  const stub = (id: string) => {
    let current: string | undefined = id;
    while (current) { if (current.startsWith('summary:external:')) return current; current = parents.get(current); }
    return undefined;
  };
  return new Set(model.edges.filter(edge => {
    if (edge.label === 'custom' || edge.source === selected || edge.target === selected || edge.source === subnetId || edge.target === subnetId || edge.source === routeId || edge.target === routeId) return true;
    if (groups.has(edge.source) && groups.has(edge.target)) return true;
    if (edge.source === `vpc:${topology.vpc.id}` && stub(edge.target)) return true;
    const sourceStub = stub(edge.source), targetStub = stub(edge.target);
    return !!sourceStub && !collapsed.has(sourceStub) && (sourceStub === targetStub || !!targetStub || edge.target.startsWith('peer:'));
  }).map(edge => edge.id));
}
