import React, { useState, useEffect, useMemo } from 'react'
import { stringify } from 'yaml'
import Prism from 'prismjs'
import 'prismjs/components/prism-yaml'
import { useApi } from './useApi.js'
import { editableResource } from './resourceView.js'
import { decodeSecret, podSecretReferences } from './secretView.js'

function Row({ label, children }) {
  return <div className="detail-row"><dt>{label}</dt><dd>{children ?? '—'}</dd></div>
}

function MapDetails({ label, values }) {
  const entries = Object.entries(values || {})
  return <Row label={label}>{entries.length ? <details><summary>{entries.length} {label.toLowerCase()}</summary>{entries.map(([key, value]) => <div key={key}>{key}: {String(value)}</div>)}</details> : '—'}</Row>
}

function renderTokens(tokens) {
  return tokens.map((token, index) => typeof token === 'string' ? token : <span className={`yaml-token yaml-${token.type}`} key={index}>{Array.isArray(token.content) ? renderTokens(token.content) : token.content}</span>)
}

function SecretValue({ value }) {
  const decoded = decodeSecret(value)
  if (decoded.kind === 'invalid') return <span className="secret-unavailable">Invalid base64 value</span>
  if (decoded.kind === 'binary') return <div><span className="secret-unavailable">Binary (base64)</span><pre className="secret-value">{decoded.text}</pre></div>
  return decoded.text === '' ? <span className="secret-unavailable">Empty value</span> : <pre className="secret-value">{decoded.text}</pre>
}

const secretMap = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {}

export default function DetailPanel({ clusterId, resource, onOpenLogs, onOpenExec, onEdit, metrics, canRevealSecrets = false }) {
  const [data, setData] = useState(null)
  const [view, setView] = useState('properties')
  const [copied, setCopied] = useState(false)
  const [revealSecrets, setRevealSecrets] = useState(false)
  const [podSecrets, setPodSecrets] = useState({})
  const api = useApi()
  const isPod = resource?.kind === 'Pod' && resource?.resource === 'pods' && !resource?.group
  const isSecret = resource?.kind === 'Secret' && resource?.resource === 'secrets' && !resource?.group
  const secretRefs = useMemo(() => isPod && data && !data.error ? podSecretReferences(data.spec || {}) : [], [isPod, data])

  useEffect(() => {
    if (!clusterId || !resource) { setData(null); return }
    let cancelled = false
    setData(null); setView('properties'); setRevealSecrets(false); setPodSecrets({})
    api.get(`/api/k8s/resource/${resource.resource}/${resource.name}`, { cluster: clusterId, group: resource.group, version: resource.version, namespace: resource.namespace })
      .then(r => r.json()).then(value => { if (!cancelled) setData(value) })
      .catch(err => { if (!cancelled) setData({ error: err.message }) })
    return () => { cancelled = true }
  }, [clusterId, resource])

  useEffect(() => {
    if (!isPod || !revealSecrets || !canRevealSecrets || !resource || !secretRefs.length) return
    const controller = new AbortController()
    setPodSecrets({})
    const load = async ref => {
      if (ref.invalid) return { error: 'Invalid Secret name' }
      if (!resource.namespace) return { error: 'Pod namespace unavailable' }
      try {
        const url = new URL(`/api/k8s/resource/secrets/${encodeURIComponent(ref.name)}`, window.location.origin)
        for (const [key, value] of Object.entries({ cluster: clusterId, group: '', version: 'v1', namespace: resource.namespace })) url.searchParams.set(key, value)
        const response = await fetch(url.toString(), { cache: 'no-store', signal: controller.signal })
        if (!response.ok) return { error: response.status === 403 ? 'Permission denied' : response.status === 404 ? 'Secret not found' : `Unavailable (HTTP ${response.status})` }
        const secret = await response.json()
        if (secret?.kind !== 'Secret' || secret.metadata?.name !== ref.name || secret.metadata?.namespace !== resource.namespace || (secret.data != null && (typeof secret.data !== 'object' || Array.isArray(secret.data)))) return { error: 'Secret response was invalid' }
        const values = secret.data || {}
        return { data: ref.all ? values : Object.fromEntries([...ref.keys].filter(key => Object.prototype.hasOwnProperty.call(values, key)).map(key => [key, values[key]])) }
      } catch { return { error: 'Secret unavailable' } }
    }
    const run = async () => {
      // shortcut: load four Secrets at a time; use a cancellable work queue if this needs streaming at larger scale.
      for (let offset = 0; offset < secretRefs.length && !controller.signal.aborted; offset += 4) {
        const batch = secretRefs.slice(offset, offset + 4)
        const results = await Promise.all(batch.map(load))
        if (controller.signal.aborted) return
        setPodSecrets(previous => ({ ...previous, ...Object.fromEntries(batch.map((ref, index) => [ref.name, results[index]])) }))
      }
    }
    void run()
    return () => controller.abort()
  }, [clusterId, resource, isPod, revealSecrets, canRevealSecrets, secretRefs])

  const definition = useMemo(() => {
    if (!data || data.error) return ''
    let obj = editableResource(data)
    if (isSecret && (!revealSecrets || !canRevealSecrets)) {
      obj = { ...obj }
      for (const field of ['data', 'stringData']) if (obj[field] != null) {
        const values = secretMap(obj[field])
        obj[field] = values === obj[field] ? Object.fromEntries(Object.keys(values).map(key => [key, '[hidden]'])) : '[hidden]'
      }
      if (obj.metadata?.annotations) obj.metadata = { ...obj.metadata, annotations: Object.fromEntries(Object.keys(secretMap(obj.metadata.annotations)).map(key => [key, '[hidden]'])) }
    }
    return stringify(obj)
  }, [data, isSecret, revealSecrets, canRevealSecrets])
  // shortcut: skip highlighting definitions over 256k characters; use incremental rendering for larger resources.
  const highlighted = useMemo(() => definition.length <= 256000 ? renderTokens(Prism.tokenize(definition, Prism.languages.yaml)) : definition, [definition])
  if (!resource) return <div className="detail-panel"><div className="detail-empty">Select a resource to view its details</div></div>
  const meta = data?.metadata || {}
  const spec = data?.spec || {}
  const status = data?.status || {}
  const secretValues = { ...secretMap(data?.data), ...secretMap(data?.stringData) }
  const malformedSecret = isSecret && ['data', 'stringData'].some(field => data?.[field] != null && data[field] !== secretMap(data[field]))
  const target = { namespace: resource.namespace, name: resource.name, uid: resource.uid, containers: resource.containers?.length ? resource.containers : spec.containers?.map(c => c.name) || [], shellContainers: resource.shellContainers?.length ? resource.shellContainers : [...(spec.containers || []), ...(spec.initContainers || [])].map(c => c.name) }
  const controller = meta.ownerReferences?.find(owner => owner.controller) || meta.ownerReferences?.[0]

  return <div className="detail-panel">
    <div className="detail-header">
      <div className="detail-title"><span className="detail-kind">{resource.kind}</span><span className="detail-name">{resource.name}</span>{resource.namespace && <span className="detail-ns">{resource.namespace}</span>}</div>
      <div className="detail-actions">
        <div className="detail-tabs"><button className={`detail-tab ${view === 'properties' ? 'active' : ''}`} onClick={() => setView('properties')}>Details</button><button className={`detail-tab ${view === 'definition' ? 'active' : ''}`} onClick={() => setView('definition')}>Definition</button></div>
        {isPod && (onOpenLogs || onOpenExec) && <div className="pod-action-buttons">{onOpenLogs && <button className="pod-action-btn logs" onClick={() => onOpenLogs(target)}>Logs</button>}{onOpenExec && <button className="pod-action-btn exec" onClick={() => onOpenExec(target)}>Exec</button>}</div>}
        <button className="copy-btn" disabled={!onEdit || !data || !!data.error || (isSecret && (!revealSecrets || !canRevealSecrets))} onClick={onEdit}>Edit</button>
        {view === 'definition' && <button className="copy-btn" disabled={!definition || (isSecret && (!revealSecrets || !canRevealSecrets))} onClick={async () => { try { await navigator.clipboard.writeText(definition); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { setCopied(false) } }}>{copied ? 'Copied' : 'Copy YAML'}</button>}
      </div>
    </div>
    {!data ? <div className="detail-empty">Loading details…</div> : data.error ? <div className="lens-error" role="alert">{data.error}</div> : view === 'definition' ? <>{isSecret && <p className="lens-metrics-note">{revealSecrets && canRevealSecrets ? 'This YAML contains base64-encoded Secret values; base64 is not encryption.' : 'Secret values are hidden. Reveal them in Details to view or copy the original YAML.'}</p>}{definition.length > 256000 && <p className="lens-metrics-note">Large definition shown without syntax highlighting.</p>}<pre className="detail-code"><code>{highlighted}</code></pre></> : <div className="detail-properties">
      <section><h2>Properties</h2><dl>
        <Row label="Created">{meta.creationTimestamp || '—'}</Row><Row label="Name">{meta.name || resource.name}</Row>{resource.namespace && <Row label="Namespace">{resource.namespace}</Row>}
        <MapDetails label="Labels" values={meta.labels} />{isSecret && (!revealSecrets || !canRevealSecrets) && Object.keys(meta.annotations || {}).length ? <Row label="Annotations">Hidden until values are revealed</Row> : <MapDetails label="Annotations" values={meta.annotations} />}
        {controller && <Row label="Controlled by">{controller.kind}/{controller.name}</Row>}
        {status.phase && <Row label="Status">{status.phase}</Row>}
        {isPod && <><Row label="Node">{spec.nodeName}</Row><Row label="Pod IP">{status.podIP}</Row><Row label="Service account">{spec.serviceAccountName}</Row><Row label="QoS class">{status.qosClass}</Row><Row label="Conditions">{status.conditions?.filter(c => c.status === 'True').map(c => c.type).join(', ') || '—'}</Row></>}
      </dl></section>
      {isSecret && <section><div className="secret-heading"><h2>Secret data</h2>{canRevealSecrets && <button className="copy-btn" aria-pressed={revealSecrets} onClick={() => setRevealSecrets(value => !value)}>{revealSecrets ? 'Hide all values' : 'Show all values'}</button>}</div>
        {malformedSecret && <p className="secret-unavailable">Invalid Secret data</p>}{Object.keys(secretValues).length ? <dl>{Object.entries(secretValues).map(([key, value]) => <Row key={key} label={key}>{revealSecrets && canRevealSecrets ? Object.prototype.hasOwnProperty.call(secretMap(data.stringData), key) ? typeof value === 'string' ? <pre className="secret-value">{value}</pre> : <span className="secret-unavailable">Invalid text value</span> : <SecretValue value={value} /> : <span aria-label="Hidden value">••••••••</span>}</Row>)}</dl> : !malformedSecret && <p>No Secret data returned.</p>}
      </section>}
      {isPod && <><section><h2>Metrics</h2><p>{metrics ? `Current CPU: ${metrics.cpu_millicores}m · Memory: ${(metrics.memory_bytes / 1048576).toFixed(1)} MiB (Metrics Server)` : 'Current metrics unavailable. Historical metrics require a configured metrics source.'}</p></section>
        <section><h2>Pod volumes</h2>{spec.volumes?.length ? <dl>{spec.volumes.map(v => <Row key={v.name} label={v.name}>{Object.keys(v).filter(k => k !== 'name').join(', ') || '—'}</Row>)}</dl> : <p>No volumes listed.</p>}</section>
        <section><div className="secret-heading"><h2>Referenced Secrets</h2>{canRevealSecrets && secretRefs.length > 0 && <button className="copy-btn" aria-pressed={revealSecrets} onClick={() => { setRevealSecrets(value => !value); if (revealSecrets) setPodSecrets({}) }}>{revealSecrets ? 'Hide all values' : 'Show all values'}</button>}</div>
          <p>Current Secret contents may differ from values in a running container. Reading a Secret requires access to the whole Secret; only referenced keys are displayed. Service-account tokens and external secret stores are not shown.</p>
          {!canRevealSecrets ? <p>Secret values are unavailable for your role.</p> : !secretRefs.length ? <p>No explicit Secret references in this Pod.</p> : secretRefs.map(ref => {
            const result = Object.prototype.hasOwnProperty.call(podSecrets, ref.name) ? podSecrets[ref.name] : null
            const values = result?.data || {}
            const keys = ref.all ? Object.keys(values) : [...ref.keys]
            return <div className="secret-reference" key={ref.name}><h3>{ref.name}</h3><p>{[...ref.sources].join(' · ')}</p>
              {!revealSecrets ? <p>Values hidden</p> : !result ? <p role="status">Loading Secret…</p> : result.error ? <p className="secret-unavailable" role="status">{result.error}</p> : !keys.length ? <p>No Secret data returned.</p> : <dl>{keys.map(key => <Row key={key} label={key || 'Unknown key'}>{!key ? <span className="secret-unavailable">Key name unavailable</span> : Object.prototype.hasOwnProperty.call(values, key) ? <SecretValue value={values[key]} /> : <span className="secret-unavailable">Key not found</span>}</Row>)}</dl>}
            </div>
          })}
        </section>
        <section><h2>Containers</h2>{(spec.containers || []).map(c => { const current = status.containerStatuses?.find(s => s.name === c.name); return <div key={c.name}><h3>{c.name}</h3><dl><Row label="Status">{current ? (current.ready ? 'Ready' : 'Not ready') : '—'}</Row><Row label="Image">{c.image}</Row><Row label="Image pull policy">{c.imagePullPolicy}</Row><Row label="Ports">{c.ports?.map(p => `${p.name ? p.name + ': ' : ''}${p.containerPort}/${p.protocol || 'TCP'}`).join(', ') || '—'}</Row><Row label="Requests">{c.resources?.requests ? Object.entries(c.resources.requests).map(([k, v]) => `${k}: ${v}`).join(', ') : '—'}</Row><Row label="Limits">{c.resources?.limits ? Object.entries(c.resources.limits).map(([k, v]) => `${k}: ${v}`).join(', ') : '—'}</Row><Row label="Environment">{c.env?.length ? `${c.env.length} variables (values hidden)` : '—'}</Row><Row label="Mounts">{c.volumeMounts?.map(m => `${m.name}: ${m.mountPath}`).join(', ') || '—'}</Row></dl></div> })}</section>
        <section><h2>Events</h2><p>Open Events in the navigator to inspect available events for this resource.</p></section></>}
    </div>}
  </div>
}
