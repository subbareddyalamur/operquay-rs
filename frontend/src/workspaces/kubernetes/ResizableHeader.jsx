import React, { useEffect, useRef, useState } from 'react'

const MIN_COL_WIDTH = 42

/**
 * @param {{
 *   label: string,
 *   width?: string | number,
 *   onResize: (width: string | number) => void,
 *   onBatchResize?: (updates: Record<string, string>) => void,
 * }} props
 */
export default function ResizableHeader({ label, width, onResize, onBatchResize }) {
  const header = useRef(null)
  const drag = useRef(null)
  const [actualWidth, setActualWidth] = useState(0)
  const [dragging, setDragging] = useState(false)
  const clamp = value => Math.max(MIN_COL_WIDTH, Math.min(800, value))

  useEffect(() => {
    if (typeof ResizeObserver === 'undefined' || !header.current) return undefined
    const observer = new ResizeObserver(entries => setActualWidth(Math.round(entries[0].contentRect.width)))
    observer.observe(header.current)
    return () => observer.disconnect()
  }, [])

  useEffect(() => {
    return () => {
      if (drag.current) {
        document.body.style.cursor = drag.current.prevCursor
        document.body.style.userSelect = drag.current.prevUserSelect
      }
    }
  }, [])

  const finishDrag = () => {
    if (!drag.current) return
    document.body.style.cursor = drag.current.prevCursor
    document.body.style.userSelect = drag.current.prevUserSelect
    drag.current = null
    setDragging(false)
  }

  return (
    <th ref={header} data-col-label={label} style={width ? { width } : undefined} title={label}>
      <span className="lens-th-label" title={label}>{label}</span>
      <span
        className={`lens-resizer${dragging ? ' dragging' : ''}`}
        role="separator"
        aria-label={`Resize ${label}`}
        aria-orientation="vertical"
        aria-valuemin={0}
        aria-valuemax={800}
        aria-valuenow={Math.min(800, actualWidth)}
        tabIndex={0}
        onPointerDown={e => {
          if (!Number.isFinite(e.clientX)) return
          e.preventDefault()
          const th = header.current
          if (!th) return
          const tr = th.closest('tr')
          const table = th.closest('table')
          const tableWidth = table?.getBoundingClientRect().width || 0
          const allThs = tr ? Array.from(tr.children).filter(el => el.tagName === 'TH') : [th]
          const resizableThs = allThs.filter(el => el.hasAttribute('data-col-label'))
          const idx = resizableThs.indexOf(th)
          const startWidths = resizableThs.map(el => el.getBoundingClientRect().width)

          // Lock non-resizable fixed columns (checkbox / actions) to current pixel width
          for (const sibling of allThs) {
            if (!sibling.hasAttribute('data-col-label')) {
              const px = sibling.getBoundingClientRect().width
              if (px > 0) sibling.style.width = `${Math.round(px)}px`
            }
          }

          drag.current = {
            x: e.clientX,
            width: th.getBoundingClientRect().width,
            tableWidth,
            resizableThs,
            idx,
            startWidths,
            prevCursor: document.body.style.cursor,
            prevUserSelect: document.body.style.userSelect,
          }
          setDragging(true)
          document.body.style.cursor = 'col-resize'
          document.body.style.userSelect = 'none'
          try {
            e.currentTarget.setPointerCapture(e.pointerId)
          } catch {
            // Synthetic pointer events in JSDOM may not have an active pointerId
          }
        }}
        onPointerMove={e => {
          if (!drag.current || !Number.isFinite(e.clientX)) return
          const { x, width: startW, tableWidth, resizableThs, idx, startWidths } = drag.current
          const rawDx = e.clientX - x

          if (resizableThs.length > 1 && idx >= 0 && tableWidth > 0 && startWidths.every(w => w > 0)) {
            if (idx >= resizableThs.length - 1) return
            const nextWidths = [...startWidths]
            const leftIdx = idx
            const rightIdx = idx + 1

            if (rawDx >= 0) {
              let remaining = rawDx
              let gained = 0
              for (let k = rightIdx; k < nextWidths.length && remaining > 0; k++) {
                const spare = Math.max(0, nextWidths[k] - MIN_COL_WIDTH)
                const take = Math.min(spare, remaining)
                nextWidths[k] -= take
                gained += take
                remaining -= take
              }
              nextWidths[leftIdx] += gained
            } else {
              const maxShrink = Math.max(0, startWidths[leftIdx] - MIN_COL_WIDTH)
              const delta = Math.max(rawDx, -maxShrink)
              nextWidths[leftIdx] += delta
              nextWidths[rightIdx] -= delta
            }

            const batchUpdates = {}
            for (let k = 0; k < resizableThs.length; k++) {
              const pct = `${((nextWidths[k] / tableWidth) * 100).toFixed(4)}%`
              resizableThs[k].style.width = pct
              const colLabel = resizableThs[k].getAttribute('data-col-label')
              if (colLabel) batchUpdates[colLabel] = pct
            }
            if (onBatchResize) onBatchResize(batchUpdates)
            else if (batchUpdates[label]) onResize(batchUpdates[label])
          } else {
            onResize(clamp(Math.round(startW + rawDx)))
          }
        }}
        onPointerUp={finishDrag}
        onPointerCancel={finishDrag}
        onKeyDown={e => {
          if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return
          e.preventDefault()
          const th = header.current
          if (!th) return
          const tr = th.closest('tr')
          const table = th.closest('table')
          const tableWidth = table?.getBoundingClientRect().width || 0
          const resizableThs = tr ? Array.from(tr.children).filter(el => el.hasAttribute('data-col-label')) : [th]
          const idx = resizableThs.indexOf(th)
          const widths = resizableThs.map(el => el.getBoundingClientRect().width)
          const step = e.key === 'ArrowRight' ? 10 : -10

          if (resizableThs.length > 1 && idx >= 0 && idx < resizableThs.length - 1 && tableWidth > 0 && widths.every(w => w > 0)) {
            const nextWidths = [...widths]
            if (step > 0) {
              const spare = Math.max(0, nextWidths[idx + 1] - MIN_COL_WIDTH)
              const take = Math.min(spare, step)
              nextWidths[idx] += take
              nextWidths[idx + 1] -= take
            } else {
              const shrink = Math.min(Math.max(0, nextWidths[idx] - MIN_COL_WIDTH), -step)
              nextWidths[idx] -= shrink
              nextWidths[idx + 1] += shrink
            }
            const batchUpdates = {}
            for (let k = 0; k < resizableThs.length; k++) {
              const pct = `${((nextWidths[k] / tableWidth) * 100).toFixed(4)}%`
              const colLabel = resizableThs[k].getAttribute('data-col-label')
              if (colLabel) batchUpdates[colLabel] = pct
            }
            if (onBatchResize) onBatchResize(batchUpdates)
            else if (batchUpdates[label]) onResize(batchUpdates[label])
          } else {
            onResize(clamp(Math.round(th.getBoundingClientRect().width + step)))
          }
        }}
      />
    </th>
  )
}
