import type { TopoNode, VPCTopology, SubnetInfo, TopologyInstance, TopologyLBInfo } from '@/lib/topology-types';
import type { ArchitectureModel, ArchitectureRelation, ArchitectureResource } from './architectureModel';

export function buildAWSArchitecture(topo: VPCTopology, selectedId: string): ArchitectureModel {
  const resources: Record<string, ArchitectureResource> = {};
  const nodes: ArchitectureModel['nodes'] = [];
  const edges: ArchitectureRelation[] = [];
  const edgeIds = new Set<string>();
  const notices: string[] = [];
  const lbKey = (lb: TopologyLBInfo) => lb.arn || lb.id || lb.name;
  const add = (resource: ArchitectureResource, parent?: string) => {
    if (resources[resource.id]) return;
    resources[resource.id] = resource;
    nodes.push({ id: resource.id, parentId: parent });
  };
  const link = (source: string, target: string, label: string) => {
    if (!resources[source] || !resources[target]) {
      notices.push(`Relationship ${source} → ${target} (${label}): resource details were not returned.`);
      return;
    }
    const id = `${source}>${target}:${label}`;
    if (!edgeIds.has(id)) { edgeIds.add(id); edges.push({ id, source, target, label }); }
  };
  const resource = (id: string, kind: TopoNode['kind'], label: string, typeLabel: string, icon: string, data: object, subtitle = '', container = false): ArchitectureResource => ({
    id, kind, label: label || id, typeLabel, icon, data: data as Record<string, unknown>, subtitle, container,
  });

  const primaryGroup = `group:vpc:${topo.vpc.id}`;
  add(resource(primaryGroup, 'vpc', topo.vpc.name || topo.vpc.id, 'VPC', 'vpc', topo.vpc, topo.vpc.cidr, true));
  const primaryAnchor = `vpc:${topo.vpc.id}`;
  add(resource(primaryAnchor, 'vpc', topo.vpc.name || topo.vpc.id, 'VPC network', 'vpc', topo.vpc, topo.vpc.id), primaryGroup);

  const addSubnets = (vpcId: string, groupId: string, subnets: SubnetInfo[], instances: TopologyInstance[], peer: boolean) => {
    for (const subnet of subnets) {
      const azId = `group:az:${vpcId}:${subnet.az || 'unknown'}`;
      add(resource(azId, 'az', subnet.az || 'Availability zone unavailable', 'Availability zone', 'zone', {}, '', true), groupId);
      const subnetGroup = `group:subnet:${vpcId}:${subnet.id}`;
      add(resource(subnetGroup, 'subnet', subnet.name || subnet.id, 'Subnet', 'subnet', subnet, subnet.cidr, true), azId);
      const subnetId = peer ? `peer-subnet:${vpcId}:${subnet.id}` : `subnet:${subnet.id}`;
      add(resource(subnetId, 'subnet', subnet.name || subnet.id, 'Subnet', 'subnet', subnet, subnet.id), subnetGroup);
      for (const instance of instances.filter(item => item.subnetId === subnet.id)) {
        const node = resource(peer ? `peer-instance:${vpcId}:${instance.id}` : `instance:${instance.id}`, 'instance', instance.name || instance.id, 'EC2 instance', 'ec2', instance, `${instance.id}${instance.privateIp ? ` · ${instance.privateIp}` : ''}`);
        node.selected = !peer && instance.id === selectedId;
        add(node, subnetGroup);
      }
    }
    for (const instance of instances.filter(item => !subnets.some(subnet => subnet.id === item.subnetId))) {
      const node = resource(peer ? `peer-instance:${vpcId}:${instance.id}` : `instance:${instance.id}`, 'instance', instance.name || instance.id, 'EC2 instance', 'ec2', instance, `${instance.id}${instance.privateIp ? ` · ${instance.privateIp}` : ''}`);
      node.selected = !peer && instance.id === selectedId;
      add(node, groupId);
      notices.push(`Instance ${instance.id}: subnet details were not returned.`);
    }
  };
  addSubnets(topo.vpc.id, primaryGroup, topo.subnets ?? [], topo.instances ?? [], false);
  if (!(topo.instances ?? []).some(instance => instance.id === selectedId)) notices.push('The selected instance is not present in this topology response.');

  for (const sg of topo.securityGroups ?? []) add(resource(`sg:${sg.id}`, 'sg', sg.name || sg.id, 'Security group', 'shield', sg, sg.id), primaryGroup);
  for (const acl of topo.networkAcls ?? []) add(resource(`nacl:${acl.id}`, 'nacl', acl.id, 'Network ACL', 'nacl', acl, acl.isDefault ? 'Default ACL' : ''), primaryGroup);
  for (const rt of topo.routeTables ?? []) add(resource(`route:${rt.id}`, 'route-table', rt.name || rt.id, 'Route table', 'router', rt, rt.id), primaryGroup);
  for (const igw of topo.internetGateways ?? []) add(resource(`igw:${igw.id}`, 'igw', igw.name || igw.id, 'Internet gateway', 'igw', igw, igw.id), primaryGroup);
  for (const nat of topo.natGateways ?? []) {
    const subnet = `group:subnet:${topo.vpc.id}:${nat.subnetId}`;
    add(resource(`nat:${nat.id}`, 'nat', nat.name || nat.id, 'NAT gateway', 'nat', nat, nat.id), resources[subnet] ? subnet : primaryGroup);
    if (!resources[subnet]) notices.push(`NAT gateway ${nat.id}: subnet details were not returned.`);
  }
  for (const endpoint of topo.vpcEndpoints ?? []) add(resource(`endpoint:${endpoint.id}`, 'vpc-endpoint', endpoint.serviceName || endpoint.id, 'VPC endpoint', 'endpoint', { ...endpoint, endpointId: endpoint.id }, endpoint.id), primaryGroup);
  for (const lb of topo.loadBalancers ?? []) add(resource(`lb:${lbKey(lb)}`, 'load-balancer', lb.name || lbKey(lb), `${lb.type || 'Elastic'} load balancer`, 'lb', lb, lb.scheme), primaryGroup);
  for (const attachment of topo.tgwAttachments ?? []) {
    add(resource(`tgw:${attachment.tgwId}`, 'tgw', attachment.tgwName || attachment.tgwId, 'Transit gateway', 'tgw', { ...attachment, attachmentId: attachment.attachmentId }, attachment.tgwId));
    link(primaryAnchor, `tgw:${attachment.tgwId}`, `attachment ${attachment.attachmentId} · ${attachment.state || 'unknown'}`);
  }

  const peers = new Map((topo.peerVpcDetails ?? []).map(peer => [peer.vpcId, peer]));
  for (const peering of topo.vpcPeerings ?? []) {
    const isRequester = peering.requesterVpc === topo.vpc.id;
    if (!isRequester && peering.accepterVpc !== topo.vpc.id) continue;
    const id = isRequester ? peering.accepterVpc : peering.requesterVpc;
    if (id && !peers.has(id)) peers.set(id, { vpcId: id, name: peering.peerVpcName || '', cidr: isRequester ? peering.accepterCidr : peering.requesterCidr, accountId: peering.peerAccountId, region: peering.peerRegion, connectionType: 'peering', subnets: [], instances: [] });
  }
  for (const attachment of topo.tgwAttachments ?? []) for (const peer of attachment.peerAttachments ?? []) {
    if (peer.resourceType === 'vpc' && peer.resourceId && !peers.has(peer.resourceId)) peers.set(peer.resourceId, { vpcId: peer.resourceId, name: peer.resourceName || '', cidr: peer.resourceCidr || '', accountId: peer.accountId, connectionType: 'tgw', subnets: [], instances: [] });
  }
  for (const peer of peers.values()) {
    const peerGroup = `group:peer:${peer.vpcId}`;
    const peerData = { ...peer, peerAccountId: peer.accountId, peerRegion: peer.region };
    add(resource(peerGroup, 'peer-vpc', peer.name || peer.vpcId, 'Connected VPC', 'vpc', peerData, peer.cidr, true));
    add(resource(`peer:${peer.vpcId}`, 'peer-vpc', peer.name || peer.vpcId, 'Connected VPC', 'vpc', peerData, peer.vpcId), peerGroup);
    addSubnets(peer.vpcId, peerGroup, peer.subnets ?? [], peer.instances ?? [], true);
    for (const nat of peer.natGateways ?? []) {
      const subnet = `group:subnet:${peer.vpcId}:${nat.subnetId}`;
      add(resource(`peer-nat:${peer.vpcId}:${nat.id}`, 'nat', nat.name || nat.id, 'NAT gateway', 'nat', nat, nat.id), resources[subnet] ? subnet : peerGroup);
      if (!resources[subnet]) notices.push(`NAT gateway ${nat.id}: subnet details were not returned.`);
    }
    for (const igw of peer.internetGateways ?? []) add(resource(`peer-igw:${peer.vpcId}:${igw.id}`, 'igw', igw.name || igw.id, 'Internet gateway', 'igw', igw, igw.id), peerGroup);
    for (const endpoint of peer.vpcEndpoints ?? []) add(resource(`peer-endpoint:${peer.vpcId}:${endpoint.id}`, 'vpc-endpoint', endpoint.serviceName || endpoint.id, 'VPC endpoint', 'endpoint', { ...endpoint, endpointId: endpoint.id }, endpoint.id), peerGroup);
    for (const sg of peer.securityGroups ?? []) add(resource(`peer-sg:${peer.vpcId}:${sg.id}`, 'sg', sg.name || sg.id, 'Security group', 'shield', sg, sg.id), peerGroup);
    for (const acl of peer.networkAcls ?? []) add(resource(`peer-nacl:${peer.vpcId}:${acl.id}`, 'nacl', acl.id, 'Network ACL', 'nacl', acl, acl.isDefault ? 'Default ACL' : ''), peerGroup);
    for (const rt of peer.routeTables ?? []) add(resource(`peer-route:${peer.vpcId}:${rt.id}`, 'route-table', rt.name || rt.id, 'Route table', 'router', rt, rt.id), peerGroup);
    for (const lb of peer.loadBalancers ?? []) add(resource(`peer-lb:${peer.vpcId}:${lbKey(lb)}`, 'load-balancer', lb.name || lbKey(lb), `${lb.type || 'Elastic'} load balancer`, 'lb', lb, lb.scheme), peerGroup);
    if (!(peer.subnets ?? []).length) notices.push(`Connected VPC ${peer.vpcId}: subnet details were not returned.`);
    if (peer.connectionType === 'privatelink') notices.push(`Connected VPC ${peer.vpcId}: the specific endpoint relationship was not returned.`);
  }
  for (const peering of topo.vpcPeerings ?? []) {
    const peerId = peering.requesterVpc === topo.vpc.id ? peering.accepterVpc : peering.accepterVpc === topo.vpc.id ? peering.requesterVpc : '';
    if (!peerId) continue;
    const id = `peering:${peering.id}`;
    add(resource(id, 'peer-vpc', peering.id, 'VPC peering', 'peering', { ...peering, vpcId: peerId }, peering.status));
    link(primaryAnchor, id, `peering ${peering.status || 'unknown'}`);
    link(id, `peer:${peerId}`, 'peer');
  }
  for (const attachment of topo.tgwAttachments ?? []) for (const peer of attachment.peerAttachments ?? []) {
    if (peer.resourceType === 'vpc') link(`tgw:${attachment.tgwId}`, `peer:${peer.resourceId}`, `attachment ${peer.attachmentId} · ${peer.state || 'unknown'}`);
    else {
      const id = `tgw-attachment:${peer.attachmentId}`;
      add(resource(id, 'target', peer.resourceName || peer.resourceId || peer.attachmentId, `${peer.resourceType || 'Unknown'} attachment`, 'tgw', peer, peer.state));
      link(`tgw:${attachment.tgwId}`, id, `attachment ${peer.attachmentId} · ${peer.state || 'unknown'}`);
    }
  }
  const securityGroupId = (id: string, fallback: string) => {
    const matches = Object.values(resources).filter(item => item.kind === 'sg' && item.data['id'] === id);
    return matches.length === 1 ? matches[0].id : fallback;
  };
  const securityRules = (groups: NonNullable<VPCTopology['securityGroups']>, key: (id: string) => string) => {
    for (const sg of groups) {
      for (const [index, rule] of (sg.inboundRules ?? []).entries()) if (rule.source.startsWith('sg-')) link(securityGroupId(rule.source, key(rule.source)), key(sg.id), `inbound security group rule ${index + 1} · ${rule.protocol} ${rule.fromPort}–${rule.toPort}`);
      for (const [index, rule] of (sg.outboundRules ?? []).entries()) if (rule.source.startsWith('sg-')) link(key(sg.id), securityGroupId(rule.source, key(rule.source)), `outbound security group rule ${index + 1} · ${rule.protocol} ${rule.fromPort}–${rule.toPort}`);
    }
  };
  for (const peer of peers.values()) {
    for (const subnet of peer.subnets ?? []) {
      if (subnet.routeTableId) link(`peer-subnet:${peer.vpcId}:${subnet.id}`, `peer-route:${peer.vpcId}:${subnet.routeTableId}`, 'route table');
      if (subnet.networkAclId) link(`peer-subnet:${peer.vpcId}:${subnet.id}`, `peer-nacl:${peer.vpcId}:${subnet.networkAclId}`, 'network ACL');
    }
    for (const instance of peer.instances ?? []) for (const sg of instance.securityGroups ?? []) link(`peer-instance:${peer.vpcId}:${instance.id}`, `peer-sg:${peer.vpcId}:${sg}`, 'security group');
    securityRules(peer.securityGroups ?? [], id => `peer-sg:${peer.vpcId}:${id}`);
    for (const rt of peer.routeTables ?? []) for (const subnet of rt.subnetIds ?? []) link(`peer-subnet:${peer.vpcId}:${subnet}`, `peer-route:${peer.vpcId}:${rt.id}`, 'route table');
    for (const acl of peer.networkAcls ?? []) for (const subnet of acl.subnetIds ?? []) link(`peer-subnet:${peer.vpcId}:${subnet}`, `peer-nacl:${peer.vpcId}:${acl.id}`, 'network ACL');
    for (const lb of peer.loadBalancers ?? []) {
      const lbId = `peer-lb:${peer.vpcId}:${lbKey(lb)}`;
      for (const id of lb.subnetIds ?? []) link(`peer-subnet:${peer.vpcId}:${id}`, lbId, 'load balancer subnet');
      for (const sg of lb.securityGroups ?? []) link(lbId, `peer-sg:${peer.vpcId}:${sg}`, 'security group');
      for (const target of lb.targets ?? []) {
        if (!target.targetId) { notices.push(`A target of ${lb.name || lb.arn} has no returned identifier.`); continue; }
        const instance = (peer.instances ?? []).find(item => item.id === target.targetId || (item.privateIp && item.privateIp === target.targetId));
        if (instance) link(lbId, `peer-instance:${peer.vpcId}:${instance.id}`, `registered target${target.port ? ` :${target.port}` : ''}`);
        else {
          const targetId = `peer-target:${peer.vpcId}:${target.targetId}:${target.port}`;
          add(resource(targetId, 'target', target.targetId, 'Registered target', 'ec2', target, `${target.port ? `Port ${target.port} · ` : ''}${target.healthState || 'unknown'}`), `group:peer:${peer.vpcId}`);
          link(lbId, targetId, 'registered target');
        }
      }
    }
    for (const nat of peer.natGateways ?? []) if (nat.subnetId) link(`peer-subnet:${peer.vpcId}:${nat.subnetId}`, `peer-nat:${peer.vpcId}:${nat.id}`, 'located in');
    for (const endpoint of peer.vpcEndpoints ?? []) {
      for (const id of endpoint.subnetIds ?? []) link(`peer-subnet:${peer.vpcId}:${id}`, `peer-endpoint:${peer.vpcId}:${endpoint.id}`, 'endpoint');
      for (const id of endpoint.routeTableIds ?? []) link(`peer-route:${peer.vpcId}:${id}`, `peer-endpoint:${peer.vpcId}:${endpoint.id}`, 'endpoint association');
    }
    for (const rt of peer.routeTables ?? []) for (const route of rt.routes ?? []) {
      const target = route.targetType === 'nat' ? `peer-nat:${peer.vpcId}:${route.target}` : route.targetType === 'igw' ? `peer-igw:${peer.vpcId}:${route.target}` : route.targetType === 'vpce' ? `peer-endpoint:${peer.vpcId}:${route.target}` : route.targetType === 'tgw' ? `tgw:${route.target}` : route.targetType === 'pcx' ? `peering:${route.target}` : '';
      if (target && resources[target]) link(`peer-route:${peer.vpcId}:${rt.id}`, target, `${route.destination} · ${route.state || 'unknown'}`);
      else if (route.target && route.targetType !== 'local') notices.push(`Route ${rt.id} → ${route.target}: target details were not returned.`);
    }
  }

  for (const subnet of topo.subnets ?? []) {
    if (subnet.routeTableId) link(`subnet:${subnet.id}`, `route:${subnet.routeTableId}`, 'route table');
    if (subnet.networkAclId) link(`subnet:${subnet.id}`, `nacl:${subnet.networkAclId}`, 'network ACL');
  }
  for (const instance of topo.instances ?? []) for (const sg of instance.securityGroups ?? []) link(`instance:${instance.id}`, `sg:${sg}`, 'security group');
  securityRules(topo.securityGroups ?? [], id => `sg:${id}`);
  for (const rt of topo.routeTables ?? []) for (const subnet of rt.subnetIds ?? []) link(`subnet:${subnet}`, `route:${rt.id}`, 'route table');
  for (const acl of topo.networkAcls ?? []) for (const subnet of acl.subnetIds ?? []) link(`subnet:${subnet}`, `nacl:${acl.id}`, 'network ACL');
  for (const nat of topo.natGateways ?? []) if (nat.subnetId) link(`subnet:${nat.subnetId}`, `nat:${nat.id}`, 'located in');
  for (const endpoint of topo.vpcEndpoints ?? []) {
    for (const id of endpoint.subnetIds ?? []) link(`subnet:${id}`, `endpoint:${endpoint.id}`, 'endpoint');
    for (const id of endpoint.routeTableIds ?? []) link(`route:${id}`, `endpoint:${endpoint.id}`, 'endpoint association');
  }
  for (const lb of topo.loadBalancers ?? []) {
    const lbId = `lb:${lbKey(lb)}`;
    for (const id of lb.subnetIds ?? []) link(`subnet:${id}`, lbId, 'load balancer subnet');
    for (const sg of lb.securityGroups ?? []) link(lbId, `sg:${sg}`, 'security group');
    for (const target of lb.targets ?? []) {
      if (!target.targetId) { notices.push(`A target of ${lb.name || lb.arn} has no returned identifier.`); continue; }
      const instance = (topo.instances ?? []).find(item => item.id === target.targetId || (item.privateIp && item.privateIp === target.targetId));
      if (instance) link(lbId, `instance:${instance.id}`, `registered target${target.port ? ` :${target.port}` : ''}`);
      else {
        const targetId = `target:${target.targetId}:${target.port}`;
        add(resource(targetId, 'target', target.targetId, 'Registered target', 'ec2', target, `${target.port ? `Port ${target.port} · ` : ''}${target.healthState || 'unknown'}`), primaryGroup);
        link(lbId, targetId, 'registered target');
      }
    }
  }
  for (const rt of topo.routeTables ?? []) for (const route of rt.routes ?? []) {
    const prefix: Record<string, string> = { igw: 'igw', nat: 'nat', tgw: 'tgw', pcx: 'peering', vpce: 'endpoint' };
    const target = prefix[route.targetType] ? `${prefix[route.targetType]}:${route.target}` : '';
    if (target && resources[target]) link(`route:${rt.id}`, target, `${route.destination} · ${route.state || 'unknown'}`);
    else if (route.target && route.targetType !== 'local') notices.push(`Route ${rt.id} → ${route.target}: target details were not returned.`);
  }
  return { nodes, resources, edges, notices: [...new Set(notices)] };
}
