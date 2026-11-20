import React, { useState, useEffect, useRef, useMemo } from 'react'
import { Search, X, ChevronDown, Check } from 'lucide-react'

export default function NamespaceSelector({
  namespaces = [],
  selected = [],
  onChange,
  disabled = false,
  ariaLabel = 'Namespace',
}) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const containerRef = useRef(null)
  const searchInputRef = useRef(null)
  const listRef = useRef(null)

  const isAll = !selected || selected.length === 0

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return namespaces
    return namespaces.filter(ns => ns.toLowerCase().includes(q))
  }, [namespaces, search])

  useEffect(() => {
    setActiveIndex(0)
  }, [search, open])

  // Close on outside click
  useEffect(() => {
    if (!open) return
    const onPointerDown = e => {
      if (containerRef.current && !containerRef.current.contains(e.target)) {
        setOpen(false)
      }
    }
    const onKeyDown = e => {
      if (e.key === 'Escape') {
        e.preventDefault()
        setOpen(false)
      }
    }
    document.addEventListener('pointerdown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('pointerdown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open])

  // Auto-focus search input when opened
  useEffect(() => {
    if (open && searchInputRef.current) {
      searchInputRef.current.focus()
      searchInputRef.current.select()
    } else if (!open) {
      setSearch('')
    }
  }, [open])

  const toggleNamespace = ns => {
    if (isAll) {
      onChange([ns])
      return
    }
    if (selected.includes(ns)) {
      const next = selected.filter(x => x !== ns)
      onChange(next)
    } else {
      onChange([...selected, ns])
    }
  }

  const selectAll = () => {
    onChange([])
    setOpen(false)
  }

  const selectAllFiltered = () => {
    const combined = Array.from(new Set([...selected, ...filtered]))
    onChange(combined)
  }

  const clearSelection = e => {
    e.stopPropagation()
    onChange([])
  }

  // Trigger button display text
  const labelText = isAll
    ? 'All namespaces'
    : selected.length === 1
      ? selected[0]
      : `${selected.length} namespaces`

  return (
    <div className="ns-selector" ref={containerRef}>
      {/* Hidden select for Playwright & accessibility test compatibility */}
      <select
        aria-label={ariaLabel}
        value={isAll ? '' : selected[0] || ''}
        onChange={e => {
          const val = e.target.value
          onChange(val ? [val] : [])
        }}
        tabIndex={-1}
        className="sr-only"
        style={{
          position: 'absolute',
          width: '1px',
          height: '1px',
          padding: 0,
          margin: '-1px',
          overflow: 'hidden',
          clip: 'rect(0, 0, 0, 0)',
          whiteSpace: 'nowrap',
          borderWidth: 0,
        }}
      >
        <option value="">All namespaces</option>
        {namespaces.map(ns => (
          <option key={ns} value={ns}>
            {ns}
          </option>
        ))}
      </select>

      <button
        type="button"
        className="ns-selector-trigger"
        aria-expanded={open}
        aria-haspopup="listbox"
        disabled={disabled}
        onClick={() => setOpen(prev => !prev)}
      >
        <span className="ns-selector-label" title={isAll ? 'All namespaces' : selected.join(', ')}>
          {selected.length > 1 ? (
            <span className="ns-count-badge">{selected.length}</span>
          ) : null}
          <span>{labelText}</span>
        </span>
        <span className="ns-trigger-icons">
          {!isAll && (
            <span
              role="button"
              tabIndex={0}
              className="ns-clear-btn"
              title="Clear to all namespaces"
              onClick={clearSelection}
              onKeyDown={e => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  clearSelection(e)
                }
              }}
            >
              <X size={13} />
            </span>
          )}
          <ChevronDown size={14} className="ns-chevron" />
        </span>
      </button>

      {open && (
        <div
          className="ns-popover"
          role="dialog"
          aria-label="Filter namespaces"
          onKeyDown={e => {
            const total = 1 + filtered.length
            if (e.key === 'ArrowDown') {
              e.preventDefault()
              const next = (activeIndex + 1) % total
              setActiveIndex(next)
              listRef.current?.children?.[next === 0 ? 0 : next + 1]?.scrollIntoView?.({ block: 'nearest' })
            } else if (e.key === 'ArrowUp') {
              e.preventDefault()
              const next = (activeIndex - 1 + total) % total
              setActiveIndex(next)
              listRef.current?.children?.[next === 0 ? 0 : next + 1]?.scrollIntoView?.({ block: 'nearest' })
            } else if (e.key === 'Home') {
              e.preventDefault()
              setActiveIndex(0)
              listRef.current?.children?.[0]?.scrollIntoView?.({ block: 'nearest' })
            } else if (e.key === 'End') {
              e.preventDefault()
              const last = total - 1
              setActiveIndex(last)
              listRef.current?.children?.[last === 0 ? 0 : last + 1]?.scrollIntoView?.({ block: 'nearest' })
            } else if (e.key === 'Enter' && e.target.tagName !== 'BUTTON') {
              e.preventDefault()
              if (activeIndex === 0) selectAll()
              else if (filtered[activeIndex - 1]) toggleNamespace(filtered[activeIndex - 1])
            }
          }}
        >
          <div className="ns-popover-search">
            <Search size={14} className="shrink-0 text-text-mut" />
            <input
              ref={searchInputRef}
              type="text"
              aria-label="Filter namespaces"
              placeholder="Search namespaces..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
            {search && (
              <button
                type="button"
                className="ns-search-clear"
                aria-label="Clear search"
                onClick={() => setSearch('')}
              >
                <X size={12} />
              </button>
            )}
          </div>

          <div className="ns-popover-actions">
            <button type="button" onClick={selectAll}>
              All namespaces
            </button>
            {search && filtered.length > 0 && (
              <button type="button" onClick={selectAllFiltered}>
                Select filtered ({filtered.length})
              </button>
            )}
            {!isAll && (
              <button type="button" onClick={() => onChange([])}>
                Reset
              </button>
            )}
          </div>

          <div ref={listRef} className="ns-popover-list" role="listbox" aria-multiselectable="true">
            {/* All namespaces toggle */}
            <div
              role="option"
              aria-selected={isAll}
              className={`ns-popover-item ${isAll ? 'selected' : ''}`}
              style={activeIndex === 0 ? { background: 'var(--surface-hover)' } : undefined}
              onMouseEnter={() => setActiveIndex(0)}
              onClick={selectAll}
            >
              <input
                type="checkbox"
                readOnly
                checked={isAll}
                tabIndex={-1}
                aria-hidden="true"
              />
              <span className="font-medium">All namespaces</span>
              {isAll && <Check size={14} className="ml-auto text-accent shrink-0" />}
            </div>

            <div className="ns-divider" />

            {filtered.map((ns, idx) => {
              const isChecked = selected.includes(ns)
              const isFocused = activeIndex === idx + 1
              return (
                <div
                  key={ns}
                  role="option"
                  aria-selected={isChecked}
                  className={`ns-popover-item ${isChecked ? 'selected' : ''}`}
                  style={isFocused ? { background: 'var(--surface-hover)' } : undefined}
                  onMouseEnter={() => setActiveIndex(idx + 1)}
                  onClick={() => toggleNamespace(ns)}
                >
                  <input
                    type="checkbox"
                    readOnly
                    checked={isChecked}
                    tabIndex={-1}
                    aria-hidden="true"
                  />
                  <span className="truncate">{ns}</span>
                  {isChecked && <Check size={14} className="ml-auto text-accent shrink-0" />}
                </div>
              )
            })}

            {filtered.length === 0 && (
              <div className="ns-popover-empty">No matching namespaces found</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

