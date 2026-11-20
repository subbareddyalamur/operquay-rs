export const cloudNames = { aws: 'AWS', azure: 'Azure', gcp: 'Google Cloud', alibaba: 'Alibaba Cloud', digitalocean: 'DigitalOcean', hetzner: 'Hetzner', mixed: 'Mixed clouds', unknown: 'Hosting unknown' }

const schemes = { aws: 'aws', azure: 'azure', gce: 'gcp', alicloud: 'alibaba', digitalocean: 'digitalocean', hcloud: 'hetzner' }

export function nodeHosting(nodes) {
  if (!Array.isArray(nodes) || !nodes.length) return null
  const clouds = new Set()
  let unknown = false
  for (const node of nodes) {
    const scheme = typeof node?.spec?.providerID === 'string' ? node.spec.providerID.match(/^([a-z0-9]+):\/\//i)?.[1]?.toLowerCase() : ''
    const cloud = schemes[scheme]
    if (cloud) clouds.add(cloud)
    else unknown = true
  }
  if (!clouds.size) return null
  return { cloud: clouds.size === 1 ? [...clouds][0] : 'mixed', partial: unknown }
}

export function clusterHosting(info) {
  if (info?.source === 'aws') return { cloud: 'aws', detail: 'EKS · AWS discovery' }
  const hosting = info?.nodeHosting
  if (hosting && cloudNames[hosting.cloud]) return { cloud: hosting.cloud, detail: `${cloudNames[hosting.cloud]} worker nodes · ${hosting.partial ? 'partial; ' : ''}control plane unknown` }
  if (info?.source === 'kubeconfig' && /^arn:(aws|aws-us-gov|aws-cn):eks:[a-z0-9-]+:\d{12}:cluster\/[A-Za-z0-9_-]+$/.test(info.name || '')) return { cloud: 'aws', detail: 'EKS identifier · unverified kubeconfig' }
  return { cloud: 'unknown', detail: 'Hosting unknown' }
}
