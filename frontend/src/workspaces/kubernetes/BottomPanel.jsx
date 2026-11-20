import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useApi } from './useApi.js'
import { watchTheme } from '@/lib/xterm-themes'
import { createTerminalAdapter, normalizeTerminalEngine } from '@/lib/terminal-engine'
import { WorkspaceTab } from '@/components/primitives/WorkspaceTabs'

function readTerminalSettings() {
  let settings = {}
  try { settings = JSON.parse(localStorage.getItem('ct-settings') || '{}')?.state || {} } catch { /* Use the default appearance. */ }
  const fontFamily = typeof settings.fontFamily === 'string' ? settings.fontFamily : 'JetBrains Mono'
  const fontSize = typeof settings.fontSize === 'number' ? Math.max(10, Math.min(22, settings.fontSize)) : 13
  const scrollbackLines = typeof settings.scrollbackLines === 'number' ? Math.max(1000, Math.min(100000, settings.scrollbackLines)) : 10000
  const terminalEngine = normalizeTerminalEngine(settings.terminalEngine)
  return { fontFamily, fontSize, scrollbackLines, terminalEngine }
}

function logHue(namespace, name, pods) { const index = Math.max(0, pods.findIndex(p => p.namespace === namespace && p.name === name)); return (index * 137.508) % 360 }

function ShellTerminal({ clusterId, shell, active }) {
  const [status, setStatus] = useState('')
  const termRef = useRef(null)
  const adapterRef = useRef(null)
  useEffect(() => {
    let adapter, activeEngine, ws, observer
    let cancelled = false
    let received = false
    let swapGen = 0

    const sendSize = () => {
      if (ws?.readyState === WebSocket.OPEN && adapter) {
        ws.send(JSON.stringify({ type: 'resize', cols: adapter.cols, rows: adapter.rows }))
      }
    }

    const mountAdapter = async (engine, settings) => {
      if (!termRef.current || cancelled) return null
      let next = null
      next = createTerminalAdapter({
        engine,
        container: termRef.current,
        fontFamily: settings.fontFamily,
        fontSize: settings.fontSize,
        scrollbackLines: settings.scrollbackLines,
        onData: data => {
          if (!cancelled && adapter === next && ws?.readyState === WebSocket.OPEN) {
            ws.send(new TextEncoder().encode(data))
          }
        },
        onResize: () => {
          if (!cancelled && adapter === next) sendSize()
        },
      })
      adapter = next
      adapterRef.current = next
      activeEngine = engine
      await next.init()
      if (cancelled || adapter !== next) {
        next.dispose()
        if (adapterRef.current === next) adapterRef.current = null
        return null
      }
      if (termRef.current?.clientWidth && termRef.current?.clientHeight) next.fit()
      sendSize()
      return next
    }

    const syncAppearance = () => {
      if (!adapter || cancelled) return
      const settings = readTerminalSettings()
      if (settings.terminalEngine !== activeEngine) {
        const gen = ++swapGen
        const prev = adapter
        void (async () => {
          const snapshot = await prev.serializeAsync()
          if (cancelled || swapGen !== gen || !termRef.current) return
          prev.dispose()
          if (adapter === prev) adapter = null
          termRef.current.replaceChildren()
          const next = await mountAdapter(settings.terminalEngine, settings)
          if (!next || cancelled || swapGen !== gen) return
          if (snapshot) next.write(snapshot)
          sendSize()
        })()
        return
      }
      adapter.setAppearance(settings.fontFamily, settings.fontSize)
      adapter.setScrollbackLines(settings.scrollbackLines)
      adapter.setTheme()
      if (termRef.current?.clientWidth && termRef.current?.clientHeight) adapter.fit()
    }

    const syncTheme = () => {
      adapter?.setTheme()
    }

    setStatus('Opening connection')
    const init = async () => {
      if (cancelled || !termRef.current) return
      const settings = readTerminalSettings()
      const mounted = await mountAdapter(settings.terminalEngine, settings)
      if (!mounted || cancelled || !termRef.current) return
      const api = useApi()
      ws = api.ws(shell.mode === 'attach' ? '/ws/k8s/attach' : '/ws/k8s/exec', {
        cluster: clusterId, namespace: shell.pod.namespace, pod: shell.pod.name, container: shell.container,
        command: shell.mode === 'exec' ? '/bin/sh' : null, uid: shell.mode === 'attach' ? shell.pod.uid : null, protocol: 'resize-v1'
      })
      observer = new ResizeObserver(() => {
        if (termRef.current?.clientWidth && termRef.current?.clientHeight) adapter?.fit()
      })
      observer.observe(termRef.current)
      ws.onopen = () => {
        setStatus('Waiting for shell output')
        if (termRef.current?.clientWidth && termRef.current?.clientHeight) adapter?.fit()
        sendSize()
        if (active) adapter?.focus()
      }
      ws.onmessage = e => { received = true; setStatus(''); adapter?.write(e.data) }
      ws.onerror = () => { setStatus('Connection failed or was rejected; check your session and permissions.'); adapter?.write('\r\n\x1b[31m[Connection Error]\x1b[0m\r\n') }
      ws.onclose = e => { setStatus(received ? `Session closed (code ${e.code}).` : `Connection closed before any shell output (code ${e.code}). Check the container shell and access.`); adapter?.write('\r\n\x1b[33m[Session Closed]\x1b[0m\r\n') }
    }
    window.addEventListener('storage', syncAppearance)
    const stopWatching = watchTheme(syncTheme)
    init().catch(err => { if (!cancelled) setStatus(`Could not open terminal: ${err.message}`) })
    return () => {
      cancelled = true
      swapGen += 1
      window.removeEventListener('storage', syncAppearance)
      stopWatching()
      observer?.disconnect()
      if (ws) { ws.onopen = null; ws.onmessage = null; ws.onerror = null; ws.onclose = null; ws.close() }
      adapter?.dispose()
      adapter = null
      adapterRef.current = null
    }
  }, [clusterId, shell.pod, shell.container, shell.mode])

  useEffect(() => {
    if (!active || !adapterRef.current) return
    const id = requestAnimationFrame(() => {
      if (termRef.current?.clientWidth && termRef.current?.clientHeight) adapterRef.current?.fit()
      adapterRef.current?.focus()
    })
    return () => cancelAnimationFrame(id)
  }, [active])

  return (
    <div
      className="shell-terminal"
      style={{ display: active ? 'flex' : 'none' }}
      hidden={!active}
    >
      {status && (
        <div className="exec-status" role="status">
          {(status === 'Opening connection' || status === 'Waiting for shell output') && (
            <span className="connect-spinner" aria-hidden="true" />
          )}{' '}
          {status}
        </div>
      )}
      <div className="exec-terminal" ref={termRef} />
    </div>
  )
}

export default function BottomPanel({ clusterId, pod, pods, tab, onTabChange, shells, onCloseShell, onOpenExec, onChangeShellContainer, height, onHeightChange, canExec }) {
  const [logs, setLogs] = useState([])
  const [logFilter, setLogFilter] = useState('')
  const [timestamps, setTimestamps] = useState(true)
  const [autoScroll, setAutoScroll] = useState(true)
  const [selectedContainer, setSelectedContainer] = useState('')
  const [loadingPast, setLoadingPast] = useState(false)
  const [hasReachedBeginning, setHasReachedBeginning] = useState(false)
  const currentTailLines = useRef(100)
  const logRef = useRef(null)
  const logSockets = useRef([])
  const dragRef = useRef(null)
  const api = useApi()
  const logContainer = pods?.length > 1 ? '' : selectedContainer

  // Cleanup websockets on unmount
  useEffect(() => () => {
    logSockets.current.forEach(ws => ws.close())
  }, [])

  // Set default container
  useEffect(() => {
    setSelectedContainer(pod?.containers?.[0] || '')
    setHasReachedBeginning(false)
    currentTailLines.current = 100
  }, [pod])

  // Logs streaming
  useEffect(() => {
    logSockets.current.forEach(ws => ws.close())
    setHasReachedBeginning(false)
    currentTailLines.current = 100
    if (!clusterId || !pod || tab !== 'logs') return

    const targets = (pods?.length ? pods : [pod]).flatMap(p => {
      const containers = pods?.length > 1 ? p.containers : [logContainer]
      return (containers || []).filter(Boolean).map(container => ({ pod: p, container }))
    })
    if (!targets.length) { setLogs([]); return }

    setLogs([])
    // shortcut: cap concurrent log streams at 100; split selections when workloads exceed this limit.
    if (targets.length > 100) { setLogs([{ pod: '', container: '', text: 'Select at most 100 pod/container streams at a time.', error: true }]); return }
    let active = true
    const sockets = targets.map(target => {
      const ws = api.ws('/ws/k8s/logs', { cluster: clusterId, namespace: target.pod.namespace, pod: target.pod.name, uid: target.pod.uid || null, container: target.container, follow: 'true', tailLines: '100' })
      const add = (text, error = false) => {
        if (!active) return
        setLogs(prev => [...prev, { namespace: target.pod.namespace, pod: target.pod.name, container: target.container, text, error }].slice(-25000))
      }
      ws.onmessage = e => {
        try { const msg = JSON.parse(e.data); if (msg.log != null) add(msg.log); if (msg.error) add(msg.error, true) }
        catch { add('Invalid log message received.', true) }
      }
      ws.onerror = () => add('Log connection failed.', true)
      return ws
    })
    logSockets.current = sockets
    return () => { active = false; sockets.forEach(ws => ws.close()) }
  }, [clusterId, pod, pods, tab, logContainer])

  // Auto-scroll logs
  useEffect(() => {
    if (autoScroll && logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight
    }
  }, [logs, autoScroll])

  // Fetch past logs on demand when scrolling up
  const fetchPastLogs = useCallback(async () => {
    if (loadingPast || hasReachedBeginning || !clusterId || !pod || tab !== 'logs') return
    const targets = (pods?.length ? pods : [pod]).flatMap(p => {
      const containers = pods?.length > 1 ? p.containers : [logContainer]
      return (containers || []).filter(Boolean).map(container => ({ pod: p, container }))
    })
    if (!targets.length) return

    setLoadingPast(true)
    const prevScrollHeight = logRef.current?.scrollHeight || 0
    const prevScrollTop = logRef.current?.scrollTop || 0

    const nextTail = currentTailLines.current + 300
    currentTailLines.current = nextTail

    try {
      let reachedStart = false

      const results = await Promise.all(targets.map(async target => {
        try {
          const res = await api.get('/api/k8s/logs', {
            cluster: clusterId,
            namespace: target.pod.namespace,
            pod: target.pod.name,
            uid: target.pod.uid || null,
            container: target.container,
            tailLines: String(nextTail),
          })
          const lines = await res.json()
          return { target, lines: Array.isArray(lines) ? lines : [] }
        } catch {
          return { target, lines: [] }
        }
      }))

      let addedAny = false
      setLogs(prev => {
        const existingByTarget = new Map()
        for (const l of prev) {
          const key = `${l.namespace}/${l.pod}/${l.container}`
          if (!existingByTarget.has(key)) existingByTarget.set(key, new Set())
          existingByTarget.get(key).add(l.text)
        }

        const newPastLines = []
        for (const { target, lines } of results) {
          const key = `${target.pod.namespace}/${target.pod.name}/${target.container}`
          const existingSet = existingByTarget.get(key) || new Set()
          if (lines.length < nextTail) {
            reachedStart = true
          }
          let targetNewCount = 0
          for (const text of lines) {
            if (!existingSet.has(text)) {
              newPastLines.push({
                namespace: target.pod.namespace,
                pod: target.pod.name,
                container: target.container,
                text,
                error: false,
              })
              targetNewCount++
            }
          }
          if (targetNewCount === 0 && lines.length > 0) {
            reachedStart = true
          }
        }

        if (newPastLines.length > 0) {
          addedAny = true
          return [...newPastLines, ...prev]
        }
        if (!addedAny) {
          reachedStart = true
        }
        return prev
      })

      if (reachedStart) {
        setHasReachedBeginning(true)
      }

      // Preserve viewport scroll position
      requestAnimationFrame(() => {
        if (logRef.current) {
          const newScrollHeight = logRef.current.scrollHeight
          logRef.current.scrollTop = newScrollHeight - prevScrollHeight + prevScrollTop
        }
      })
    } catch {
      // Ignore background fetch error
    } finally {
      setLoadingPast(false)
    }
  }, [loadingPast, hasReachedBeginning, clusterId, pod, pods, tab, logContainer, api])

  // Handle log scroll (detect scroll up to top to trigger loading past logs, and pause autoScroll)
  const handleLogScroll = useCallback(() => {
    if (!logRef.current) return
    const { scrollTop, scrollHeight, clientHeight } = logRef.current
    const atBottom = scrollHeight - scrollTop - clientHeight < 30
    if (autoScroll && !atBottom) {
      setAutoScroll(false)
    }
    if (scrollTop <= 15 && !loadingPast && !hasReachedBeginning && logs.length > 0) {
      fetchPastLogs()
    }
  }, [autoScroll, loadingPast, hasReachedBeginning, logs.length, fetchPastLogs])

  // Drag resize
  const handleDragStart = useCallback((e) => {
    e.preventDefault()
    dragRef.current = { startY: e.clientY, startHeight: height }
    const onMove = (me) => {
      const delta = dragRef.current.startY - me.clientY
      onHeightChange(Math.max(100, Math.min(window.innerHeight - 200, dragRef.current.startHeight + delta)))
    }
    const onUp = () => {
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', onUp)
    }
    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', onUp)
  }, [height, onHeightChange])
  const handleResizeKey = useCallback(e => {
    if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown') return
    e.preventDefault()
    onHeightChange(Math.max(100, Math.min(window.innerHeight - 200, height + (e.key === 'ArrowUp' ? 20 : -20))))
  }, [height, onHeightChange])
  const handleProps = { role: 'separator', 'aria-label': 'Resize terminal panel', 'aria-orientation': 'horizontal', 'aria-valuemin': 100, 'aria-valuemax': Math.max(100, window.innerHeight - 200), 'aria-valuenow': height, tabIndex: 0, onMouseDown: handleDragStart, onKeyDown: handleResizeKey }

  const visibleLogs = timestamps ? logs : logs.map(l => ({ ...l, text: l.text.replace(/^\d{4}-\d\d-\d\dT\S+\s+/, '') }))
  const displayLogs = logFilter ? visibleLogs.filter(l => `${l.namespace || ''} ${l.pod} ${l.container} ${l.text}`.toLowerCase().includes(logFilter.toLowerCase())) : visibleLogs

  if (!pod) {
    return (
      <div className="bottom-panel" style={{ height }}>
        <div className="drag-handle" {...handleProps} />
        <div className="bottom-empty">Select a pod to view logs or exec</div>
      </div>
    )
  }

  return (
    <div className="bottom-panel" style={{ height }}>
      <div className="drag-handle" {...handleProps} />
      <div className="bottom-header">
        <div className="bottom-tabs">
          <button className={`bottom-tab ${tab === 'logs' ? 'active' : ''}`} onClick={() => onTabChange('logs')}>
            Logs
          </button>
          <button className="bottom-tab" disabled={!canExec} onClick={onOpenExec}>
            Exec
          </button>
          <div role="tablist" aria-label="Pod shells" className="shell-tabs">
            {shells.map(shell => {
              const label = `${shell.pod.name} / ${shell.container}${shell.mode === 'attach' ? ' (attach)' : ''}`
              return (
                <WorkspaceTab
                  key={shell.id}
                  mode="trigger-tab"
                  size="sm"
                  className="shell-tab"
                  active={tab === shell.id}
                  label={label}
                  title={label}
                  onSelect={() => onTabChange(shell.id)}
                  onClose={() => onCloseShell(shell.id)}
                  closeLabel={`Close ${shell.pod.name} / ${shell.container} shell`}
                />
              )
            })}
          </div>
        </div>

        {tab === 'logs' && (!pods || pods.length <= 1) && pod.containers?.length > 1 && (
          <select
            className="container-select"
            value={selectedContainer}
            onChange={e => setSelectedContainer(e.target.value)}
          >
            {pod.containers.map(c => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        )}
        {shells.find(s => s.id === tab && s.mode === 'attach' && s.pod.containers.length > 1) && <select className="container-select" aria-label="Attach container" value={shells.find(s => s.id === tab).container} onChange={e => onChangeShellContainer(tab, e.target.value)}>{shells.find(s => s.id === tab).pod.containers.map(c => <option key={c}>{c}</option>)}</select>}

        {tab === 'logs' && (
          <div className="log-controls">
            <input
              className="log-filter"
              aria-label="Search logs"
              placeholder="Search logs..."
              value={logFilter}
              onChange={e => setLogFilter(e.target.value)}
            />
            {logFilter && <span className="log-match-count">{displayLogs.length} matches</span>}
            <label className="log-toggle">
              <input type="checkbox" checked={timestamps} onChange={e => setTimestamps(e.target.checked)} />
              Timestamps
            </label>
            <label className="log-toggle">
              <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} />
              Auto-scroll
            </label>
          </div>
        )}
      </div>

      {tab === 'logs' && (
        <div className="log-viewer" ref={logRef} onScroll={handleLogScroll}>
          {hasReachedBeginning && (
            <div className="log-history-status log-history-beginning" role="status">
              ● Beginning of container log reached
            </div>
          )}
          {loadingPast && (
            <div className="log-history-status" role="status">
              <span className="connect-spinner" aria-hidden="true" /> Loading earlier logs…
            </div>
          )}
          {!hasReachedBeginning && !loadingPast && logs.length > 0 && (
            <button type="button" className="log-load-more" onClick={fetchPastLogs}>
              ↑ Scroll up or click to load more past logs
            </button>
          )}
          {displayLogs.map((line, i) => (
            <div key={i} className="log-line">{line.pod && <span className="log-source" style={{ '--log-hue': logHue(line.namespace, line.pod, pods?.length ? pods : [pod]) }}>[{line.namespace}/{line.pod}{(pods?.length > 1 && line.container) ? '/' + line.container : ''}] </span>}<span className={line.error ? 'log-error' : undefined}>{line.text}</span></div>
          ))}
          {displayLogs.length === 0 && <div className="log-empty">{logFilter ? 'No matching log lines.' : 'Waiting for logs...'}</div>}
        </div>
      )}

      {shells.map(shell => <ShellTerminal key={shell.id} clusterId={clusterId} shell={shell} active={tab === shell.id} />)}
    </div>
  )
}
