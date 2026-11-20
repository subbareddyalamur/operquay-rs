export function decodeSecret(value) {
  if (typeof value !== 'string') return { text: '', kind: 'invalid' }
  try {
    const binary = atob(value)
    const bytes = Uint8Array.from(binary, char => char.charCodeAt(0))
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)) return { text: value, kind: 'binary' }
    return { text, kind: 'text' }
  } catch {
    try { atob(value); return { text: value, kind: 'binary' } } catch { return { text: '', kind: 'invalid' } }
  }
}

export function podSecretReferences(spec = {}) {
  const refs = new Map()
  const add = (name, keys, source) => {
    if (typeof name !== 'string' || !name) return
    const ref = refs.get(name) || { name, all: false, keys: new Set(), sources: new Set(), invalid: name.length > 253 || !/^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$/.test(name) }
    if (keys === null) ref.all = true
    else keys.forEach(key => ref.keys.add(typeof key === 'string' ? key : ''))
    ref.sources.add(source); refs.set(name, ref)
  }
  for (const container of [...(spec.containers || []), ...(spec.initContainers || []), ...(spec.ephemeralContainers || [])]) {
    for (const env of container.env || []) if (env.valueFrom?.secretKeyRef) add(env.valueFrom.secretKeyRef.name, [env.valueFrom.secretKeyRef.key], 'environment')
    for (const env of container.envFrom || []) if (env.secretRef) add(env.secretRef.name, null, 'environment')
  }
  for (const volume of spec.volumes || []) {
    if (volume.secret) add(volume.secret.secretName, volume.secret.items?.length ? volume.secret.items.map(item => item.key) : null, 'volume')
    for (const source of volume.projected?.sources || []) if (source.secret) add(source.secret.name, source.secret.items?.length ? source.secret.items.map(item => item.key) : null, 'projected volume')
    if (volume.csi?.nodePublishSecretRef) add(volume.csi.nodePublishSecretRef.name, null, 'CSI volume')
  }
  for (const pull of spec.imagePullSecrets || []) add(pull.name, null, 'image pull')
  return [...refs.values()]
}
