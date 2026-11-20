import React, { useEffect, useId, useMemo, useRef, useState } from 'react'
import { useApi } from './useApi.js'
import ResizableHeader from './ResizableHeader.jsx'

const groupings = { 'Namespace': 'namespace', 'Workload / controller': 'workload', 'Pod': 'pod', 'Node allocation': 'node', 'Label': 'label', 'Persistent-volume assets': 'volumes', 'Node assets': 'node-assets' }
const fields = ['cpuCost', 'ramCost', 'pvCost', 'networkCost', 'totalCost']
const number = value => {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—'
  if (value && Math.abs(value) < 0.0001) return value.toExponential(3)
  return value.toFixed(value && Math.abs(value) < 0.01 ? 4 : 2)
}

function CostTrend({ series }) {
  const values = series.map(point => point.total).filter(value => typeof value === 'number' && Number.isFinite(value))
  if (!values.length) return <p>No time-series values were returned by the source.</p>
  const low = Math.min(0, ...values), high = Math.max(0, ...values), span = high - low || 1
  const zero = 144 - (0 - low) / span * 128
  const bar = 690 / series.length
  const width = Math.max(1, Math.min(42, bar - 4))
  return <><svg className="cost-chart" viewBox="0 0 720 160" role="img" aria-label="Cost returned per time interval; unavailable intervals are omitted">
    <line x1="20" x2="710" y1={zero} y2={zero} className="cost-chart-axis" />
    {series.map((point, index) => {
      if (typeof point.total !== 'number' || !Number.isFinite(point.total)) return null
      const y = 144 - (point.total - low) / span * 128
      return <rect key={index} x={20 + index * bar + (bar - width) / 2} y={Math.min(y, zero)} width={width} height={Math.max(1, Math.abs(zero - y))} className="cost-chart-bar"><title>{point.name}: {number(point.total)}</title></rect>
    })}
  </svg><div className="cost-chart-labels"><span>{series[0]?.name}</span><span>{series[series.length - 1]?.name}</span></div><details className="cost-periods"><summary>View interval values</summary>{series.map((point, index) => <div key={index}>{point.name}: {number(point.total)}</div>)}</details></>
}

export default function CostPanel({ clusterId, namespaces = [] }) {
  const api = useApi(), ids = useId()
  const [sources, setSources] = useState([]), [source, setSource] = useState(null)
  const [discovering, setDiscovering] = useState(true), [discoveryError, setDiscoveryError] = useState('')
  const [sourceNamespace, setSourceNamespace] = useState(''), [service, setService] = useState('')
  const [window, setWindow] = useState('7d'), [start, setStart] = useState(''), [end, setEnd] = useState('')
  const [groupInput, setGroupInput] = useState('Namespace'), [labelKey, setLabelKey] = useState(''), [labelValue, setLabelValue] = useState(''), [search, setSearch] = useState('')
  const [data, setData] = useState(null), [query, setQuery] = useState(null), [busy, setBusy] = useState(false), [error, setError] = useState(''), [widths, setWidths] = useState({})
  const discoveryRequest = useRef(0), costRequest = useRef(0)
  const group = groupings[Object.keys(groupings).find(name => name.toLowerCase() === groupInput.trim().toLowerCase())]

  const load = async (chosen, filters) => {
    const generation = ++costRequest.current
    setBusy(true); setError(''); setData(null); setSearch('')
    try {
      const assetView = filters.group === 'volumes' || filters.group === 'node-assets'
      const params = { cluster: clusterId, namespace: chosen.namespace, service: chosen.service, port: chosen.port, api: chosen.api, view: assetView ? 'assets' : 'allocation', window: filters.window, aggregate: filters.group }
      if (filters.window === 'custom') { params.start = filters.start; params.end = filters.end }
      if (!assetView) { params.label_key = filters.labelKey; params.label_value = filters.labelValue }
      const result = await api.get('/api/k8s/cost', params).then(r => r.json())
      if (generation === costRequest.current) { setData(result); setQuery(filters) }
    } catch (err) { if (generation === costRequest.current) setError(err.message) }
    finally { if (generation === costRequest.current) setBusy(false) }
  }

  const discover = async (namespace = '', exact = '') => {
    const generation = ++discoveryRequest.current
    costRequest.current++; setBusy(false); setData(null); setSource(null); setSources([]); setDiscovering(true); setDiscoveryError(''); setError('')
    try {
      const result = await api.get('/api/k8s/cost/sources', { cluster: clusterId, namespace: namespace.trim(), service: exact.trim() }).then(r => r.json())
      if (generation !== discoveryRequest.current) return
      setSources(result.sources || [])
      if (result.truncated) setDiscoveryError('Discovery reached its scan limit; additional cost sources may exist. Search a specific namespace below.')
      if (result.sources?.length === 1) {
        const chosen = result.sources[0]; setSource(chosen)
        await load(chosen, { group: 'namespace', window: '7d', labelKey: '', labelValue: '' })
        if (generation === discoveryRequest.current) { setGroupInput('Namespace'); setWindow('7d'); setLabelKey(''); setLabelValue('') }
      } else if (!result.sources?.length && !result.truncated) setDiscoveryError('No verified OpenCost or Kubecost API was found. Check permissions or search its namespace below.')
    } catch (err) { if (generation === discoveryRequest.current) setDiscoveryError(err.message) }
    finally { if (generation === discoveryRequest.current) setDiscovering(false) }
  }
  useEffect(() => { discover(); return () => { discoveryRequest.current++; costRequest.current++ } }, [clusterId])

  const submit = e => {
    e.preventDefault()
    if (!group) { setError('Choose a listed grouping.'); return }
    if (window === 'custom' && (!start || !end || start > end)) { setError('Choose a valid UTC date range.'); return }
    load(source, { group, window, start, end, labelKey: labelKey.trim(), labelValue: labelValue.trim() })
  }
  const results = useMemo(() => {
    if (!data || !query) return { rows: [], series: [] }
    if (data.view === 'assets') {
      const rows = Object.entries(data.data).map(([key, asset]) => ({ key, ...asset }))
        .filter(a => query.group === 'volumes' ? a.type === 'Disk' && a.volumeName : a.type === 'Node')
        .filter(a => !query.labelValue || a.labels?.[query.labelKey] === query.labelValue)
        .map(a => ({ name: a.volumeName || a.properties?.name || a.key, cluster: a.properties?.cluster || '—', namespace: a.claimNamespace || '—', totalCost: a.totalCost, source: a.type }))
      return { rows, series: [] }
    }
    const totals = new Map()
    const series = data.data.map((set, index) => {
      const records = Object.entries(set || {})
      let sum = 0, complete = records.length > 0
      records.forEach(([key, item]) => {
        const previous = totals.get(key) || { name: item.name || key, cpuCost: 0, ramCost: 0, pvCost: 0, networkCost: 0, totalCost: 0, missing: {} }
        for (const field of fields) { if (typeof item[field] === 'number' && Number.isFinite(item[field])) previous[field] += item[field]; else previous.missing[field] = true }
        totals.set(key, previous)
        if (typeof item.totalCost === 'number' && Number.isFinite(item.totalCost)) sum += item.totalCost; else complete = false
      })
      return { name: records[0]?.[1]?.start || `Interval ${index + 1}`, total: complete ? sum : null }
    })
    return { rows: [...totals.values()].map(row => { for (const field of Object.keys(row.missing)) row[field] = null; return row }), series }
  }, [data, query])
  const rows = results.rows.filter(row => `${row.name} ${row.cluster || ''} ${row.namespace || ''}`.toLowerCase().includes(search.toLowerCase())).sort((a, b) => (b.totalCost ?? -Infinity) - (a.totalCost ?? -Infinity))
  const coverage = data?.coverage
  const missingIntervals = data?.view === 'allocation' && (!coverage || !Number.isInteger(coverage.expected_intervals) || !Number.isInteger(coverage.returned_intervals) || !Number.isInteger(coverage.empty_intervals) || coverage.expected_intervals < 1 || coverage.returned_intervals !== data.data.length || coverage.returned_intervals < coverage.expected_intervals || coverage.empty_intervals !== 0)
  const totalFor = field => !missingIntervals && rows.length && rows.every(row => typeof row[field] === 'number' && Number.isFinite(row[field])) ? rows.reduce((sum, row) => sum + row[field], 0) : null
  const labels = data ? (data.view === 'assets' ? Object.values(data.data) : data.data.flatMap(set => Object.values(set))).map(item => item.labels || item.properties?.labels || {}) : []
  const labelKeys = [...new Set(labels.flatMap(item => Object.keys(item)))].sort()
  const labelValues = [...new Set(labels.map(item => item[labelKey]).filter(value => typeof value === 'string'))].sort()
  const header = label => <ResizableHeader key={label} label={label} width={widths[label]} onResize={width => setWidths(current => ({ ...current, [label]: width }))} onBatchResize={updates => setWidths(current => ({ ...current, ...updates }))} />
  const chooseSource = index => {
    const selected = sources[Number(index)]
    if (!selected) return
    setSource(selected); load(selected, { group: 'namespace', window: '7d', labelKey: '', labelValue: '' }); setGroupInput('Namespace'); setWindow('7d'); setLabelKey(''); setLabelValue('')
  }
  return <section className="cost-panel">
    <div className="cost-title"><div><h1>Cost Monitoring</h1><p>Allocation and assets from your cluster’s cost source</p></div><button onClick={() => discover()} disabled={discovering}>{discovering ? 'Finding source…' : 'Refresh sources'}</button></div>
    {discovering && <p role="status"><span className="connect-spinner" aria-hidden="true" /> Finding and verifying cost services…</p>}
    {discoveryError && <p className="lens-error" role="alert">{discoveryError}</p>}
    {!source && !discovering && sources.length === 0 && <div className="cost-empty"><strong>Connect a cost source to see the dashboard</strong><p>No costs are estimated by Operquay. An accessible OpenCost or Kubecost allocation API is required.</p></div>}
    {sources.length > 1 && <label className="cost-source-choice">Choose a verified API <select aria-label="Cost source" value={source ? String(sources.indexOf(source)) : ''} onChange={e => chooseSource(e.target.value)}><option value="" disabled>Select a source</option>{sources.map((item, index) => <option value={index} key={`${item.namespace}/${item.service}/${item.port}/${item.api}`}>{item.namespace}/{item.service} ({item.api === 'model' ? 'Kubecost frontend' : 'direct API'})</option>)}</select></label>}
    <details className="cost-discovery"><summary>Find a source in a specific namespace</summary><p>Use this when cluster-wide service discovery is restricted or the service has a custom name.</p><div><label>Namespace<input aria-label="Cost source namespace" list={`${ids}-namespaces`} value={sourceNamespace} onChange={e => setSourceNamespace(e.target.value)} /><datalist id={`${ids}-namespaces`}>{namespaces.map(name => <option key={name} value={name} />)}</datalist></label><label>Service name (optional)<input aria-label="Cost source service" value={service} onChange={e => setService(e.target.value)} /></label><button disabled={discovering || !sourceNamespace.trim()} onClick={() => discover(sourceNamespace, service)}>Find source</button></div></details>
    {source && <>
      <div className="cost-source-strip"><span>Verified API: <strong>{source.namespace}/{source.service}</strong></span></div>
      <form className="cost-form" onSubmit={submit}>
        <label>Time window<select aria-label="Cost time window" value={window} onChange={e => setWindow(e.target.value)}><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option><option value="90d">Last 90 days</option><option value="365d">Last 365 days</option><option value="1096d">Last 1096 days (~3 years)</option><option value="custom">Custom dates (UTC)</option></select></label>
        {window === 'custom' && <><label>From (UTC)<input aria-label="Cost start date" type="date" required value={start} onChange={e => setStart(e.target.value)} /></label><label>Through (UTC)<input aria-label="Cost end date" type="date" required value={end} onChange={e => setEnd(e.target.value)} /></label></>}
        <label>Group by<input aria-label="Cost grouping" list={`${ids}-groups`} required value={groupInput} placeholder="Search grouping" onChange={e => setGroupInput(e.target.value)} /><datalist id={`${ids}-groups`}>{Object.keys(groupings).map(name => <option key={name} value={name} />)}</datalist></label>
        <label>Label key<input aria-label="Cost label key" list={`${ids}-keys`} value={labelKey} onChange={e => setLabelKey(e.target.value)} placeholder="Optional key" required={group === 'label' || !!labelValue} /><datalist id={`${ids}-keys`}>{labelKeys.map(key => <option key={key} value={key} />)}</datalist></label>
        <label>Label value<input aria-label="Cost label value" list={`${ids}-values`} value={labelValue} onChange={e => setLabelValue(e.target.value)} placeholder="Optional exact value" /><datalist id={`${ids}-values`}>{labelValues.map(value => <option key={value} value={value} />)}</datalist></label>
        <button type="submit" disabled={busy}>{busy ? 'Loading…' : 'Apply filters'}</button>
      </form>
      {window === 'custom' && <p className="cost-source">Dates are inclusive UTC calendar dates, up to 1096 days. Today ends at the time of the query.</p>}
      {busy && <p role="status">Loading cost data…</p>}{error && <p className="lens-error" role="alert">{error}</p>}
      {data && <>
        <div className="cost-notice">Allocation values are estimates, not necessarily your cloud bill. This source may include multiple clusters. Source coverage is not independently verified; missing periods and historical retention may make totals incomplete. Source currency is not supplied by this API.</div>
        {missingIntervals && <div className="cost-notice" role="status">The source returned fewer intervals than requested, empty intervals, or unavailable coverage information. Summary totals are hidden; the table and chart show only returned data.</div>}
        <div className="cost-summary"><div><span>Displayed total</span><strong>{number(totalFor('totalCost'))}</strong><small>Listed rows · source currency</small></div>{data.view === 'allocation' ? <><div><span>CPU</span><strong>{number(totalFor('cpuCost'))}</strong><small>Listed allocations</small></div><div><span>Memory</span><strong>{number(totalFor('ramCost'))}</strong><small>Listed allocations</small></div><div><span>Persistent volumes</span><strong>{number(totalFor('pvCost'))}</strong><small>Listed allocations</small></div><div><span>Network</span><strong>{number(totalFor('networkCost'))}</strong><small>Listed allocations</small></div></> : <div><span>Rows</span><strong>{rows.length}</strong><small>Returned assets</small></div>}</div>
        {results.series.length > 0 && <div className="cost-series"><h2>Cost over time</h2><p>Source query total per interval; table search does not change this chart.</p><CostTrend series={results.series} /></div>}
        <div className="cost-table-heading"><div><h2>{data.view === 'assets' ? 'Assets' : 'Allocation breakdown'}</h2><p>{rows.length} displayed · idle is shown separately, not redistributed</p></div><label>Search rows<input aria-label="Search cost rows" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search by name" /></label></div>
        <div className="lens-table-wrap"><table className="lens-table cost-table"><thead><tr>{header('Name')}{data.view === 'assets' ? <>{header('Cluster')}{header('Namespace')}{header('Type')}</> : <>{header('CPU')}{header('Memory')}{header('Persistent volumes')}{header('Network')}</>}{header('Total')}</tr></thead><tbody>{rows.map((row, i) => <tr key={i}><td title={row.name}>{row.name}</td>{data.view === 'assets' ? <><td title={row.cluster || '—'}>{row.cluster}</td><td title={row.namespace || '—'}>{row.namespace}</td><td title={row.source || '—'}>{row.source}</td></> : <><td title={number(row.cpuCost)}>{number(row.cpuCost)}</td><td title={number(row.ramCost)}>{number(row.ramCost)}</td><td title={number(row.pvCost)}>{number(row.pvCost)}</td><td title={number(row.networkCost)}>{number(row.networkCost)}</td></>}<td title={number(row.totalCost)}>{number(row.totalCost)}</td></tr>)}</tbody></table></div>
        {!rows.length && <p>No matching cost data returned. Check the source, filters and retained coverage.</p>}
        <p className="cost-source">Window: {data.window} · Label suggestions are limited to returned data. ReplicaSets owned by Deployments may be attributed to the Deployment by the source.</p>
      </>}
    </>}
  </section>
}
