import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  Database,
  KeyRound,
  Layers,
  LayoutDashboard,
  Loader2,
  Pencil,
  Plug,
  Plus,
  Power,
  Table2,
  Trash2,
} from 'lucide-react';
import { Button, Tooltip } from '@/components/primitives';

export type DbEngine = 'postgres' | 'clickhouse' | 'duckdb' | 'mysql' | 'redis';

export interface ColumnDef {
  name: string;
  type: string;
  pk?: boolean;
  nullable?: boolean;
}

export interface TableDef {
  name: string;
  schema: string;
  estimatedRows: number;
  sizeBytes?: number;
  sizePretty?: string;
  columns: ColumnDef[];
  rows?: Array<Record<string, string | number | boolean | null>>;
}

export interface DbConnection {
  id: string;
  name: string;
  engine: DbEngine;
  host: string;
  port: number;
  database: string;
  databases?: string[];
  username?: string;
  password?: string;
  ssl?: boolean;
  tunnel?: string;
  sslMode?: string;
  status: 'connected' | 'disconnected' | 'connecting' | 'error';
  lastError?: string;
  liveBackend?: boolean;
  tables: TableDef[];
}

export const ENGINE_META: Record<string, { label: string; short: string; badge: 'info' | 'warn' | 'success'; defaultPort: number }> = {
  postgres: { label: 'PostgreSQL', short: 'PG', badge: 'info', defaultPort: 5432 },
  clickhouse: { label: 'ClickHouse', short: 'CH', badge: 'warn', defaultPort: 8123 },
  duckdb: { label: 'DuckDB', short: 'DK', badge: 'info', defaultPort: 1294 },
  mysql: { label: 'MySQL', short: 'MY', badge: 'warn', defaultPort: 3306 },
  redis: { label: 'Redis', short: 'RD', badge: 'success', defaultPort: 6379 },
};

export function connectionDotClass(status: DbConnection['status']): string {
  switch (status) {
    case 'connected':
      return 'bg-success';
    case 'connecting':
      return 'bg-warn animate-pulse';
    case 'error':
      return 'bg-danger';
    default:
      return 'bg-text-dim/50';
  }
}

export interface DatabaseTreeProps {
  connections: DbConnection[];
  selectedConnectionId?: string | null;
  activeTable?: { connectionId?: string; schema?: string; name?: string } | null;
  filterText?: string;
  expandSignal?: { expanded: boolean; version: number };
  onSelectConnection?: (conn: DbConnection) => void;
  onConnect?: (conn: DbConnection) => void;
  onDisconnect?: (conn: DbConnection) => void;
  onEdit?: (conn: DbConnection) => void;
  onRemove?: (conn: DbConnection) => void;
  onOpenTable?: (conn: DbConnection, table: TableDef) => void;
  onOpenAddModal?: () => void;
  className?: string;
}

export function DatabaseTree({
  connections,
  selectedConnectionId,
  activeTable,
  filterText = '',
  expandSignal,
  onSelectConnection,
  onConnect,
  onDisconnect,
  onEdit,
  onRemove,
  onOpenTable,
  onOpenAddModal,
  className = '',
}: DatabaseTreeProps) {
  const [expandedConnIds, setExpandedConnIds] = useState<Record<string, boolean>>(() => {
    const initial: Record<string, boolean> = {};
    if (connections[0]) initial[connections[0].id] = true;
    return initial;
  });

  const [expandedTreeNodes, setExpandedTreeNodes] = useState<Record<string, boolean>>({});
  const [selectedSchemaByConn, setSelectedSchemaByConn] = useState<Record<string, string>>({});

  useEffect(() => {
    if (!expandSignal || expandSignal.version === 0) return;
    if (expandSignal.expanded) {
      setExpandedConnIds(Object.fromEntries(connections.map((c) => [c.id, true])));
    } else {
      setExpandedConnIds({});
    }
  }, [expandSignal, connections]);

  const isTreeNodeExpanded = useCallback(
    (key: string, defaultOpen = true) => expandedTreeNodes[key] ?? defaultOpen,
    [expandedTreeNodes],
  );

  const toggleTreeNode = useCallback((key: string, defaultOpen = true) => {
    setExpandedTreeNodes((prev) => {
      const current = prev[key] ?? defaultOpen;
      return { ...prev, [key]: !current };
    });
  }, []);

  const normalizedFilter = filterText.trim().toLowerCase();

  const filteredConnections = useMemo(() => {
    if (!normalizedFilter) return connections;
    return connections.filter((c) => {
      if (c.name.toLowerCase().includes(normalizedFilter)) return true;
      if (c.database.toLowerCase().includes(normalizedFilter)) return true;
      if (c.host.toLowerCase().includes(normalizedFilter)) return true;
      return c.tables?.some((t) => t.name.toLowerCase().includes(normalizedFilter) || t.schema.toLowerCase().includes(normalizedFilter));
    });
  }, [connections, normalizedFilter]);

  if (filteredConnections.length === 0) {
    return (
      <div className={`rounded-xl border border-dashed border-border bg-surface/50 p-4 text-center space-y-2.5 ${className}`}>
        <div className="w-8 h-8 rounded-full bg-surface border border-border flex items-center justify-center mx-auto text-text-dim">
          <Database size={16} />
        </div>
        <p className="text-[12px] font-medium text-text-pri">
          {connections.length === 0 ? 'No database connections configured yet' : 'No matching database connections'}
        </p>
        <p className="text-[11px] text-text-dim leading-relaxed">
          {connections.length === 0
            ? 'Add a PostgreSQL, MySQL, ClickHouse, or Redis endpoint to browse schemas and run queries.'
            : 'Try a different search query or clear the filter.'}
        </p>
        {onOpenAddModal && connections.length === 0 && (
          <Button
            size="sm"
            variant="primary"
            className="h-7 text-[11px] px-2.5 mx-auto"
            onClick={onOpenAddModal}
          >
            <Plus size={12} />
            Add Database Connection
          </Button>
        )}
      </div>
    );
  }

  return (
    <div role="tree" aria-label="Database Explorer Tree" className={`space-y-1.5 ${className}`}>
      <div className="px-1.5 py-0.5 flex items-center gap-1.5 text-[10.5px] font-semibold text-text-dim uppercase tracking-wider">
        <Layers size={11} className="opacity-70" />
        <span>Endpoints</span>
        <span className="text-text-mut font-normal">({filteredConnections.length})</span>
      </div>

      {filteredConnections.map((conn) => {
        const hasMatchingTables = Boolean(
          normalizedFilter &&
            conn.tables?.some(
              (t) => t.name.toLowerCase().includes(normalizedFilter) || t.schema.toLowerCase().includes(normalizedFilter),
            ),
        );
        const isExpanded = hasMatchingTables || (expandedConnIds[conn.id] ?? (selectedConnectionId === conn.id));
        const isSelectedConn = selectedConnectionId === conn.id;
        const isConnected = conn.status === 'connected';
        const engine = ENGINE_META[conn.engine] || {
          label: conn.engine,
          short: conn.engine.slice(0, 2).toUpperCase(),
          badge: 'info',
          defaultPort: 5432,
        };
        const tunnelLabel = conn.tunnel || `${conn.host}:${conn.port}/${conn.database}`;

        return (
          <div
            key={conn.id}
            className={`rounded-xl border transition-all duration-150 ${
              isSelectedConn || isExpanded
                ? 'border-accent/40 bg-surface/90 shadow-sm'
                : 'border-transparent hover:border-border/60 hover:bg-surface/50'
            }`}
          >
            {/* V2 Compact Connection Card Header + Inline Quick Actions */}
            <div className="flex items-center gap-1 pr-1.5">
              <Tooltip
                onlyWhenTruncated
                side="right"
                sideOffset={8}
                delay={160}
                content={
                  <div className="flex flex-col gap-0.5">
                    <span className="text-[12px] font-semibold text-[var(--text-pri)] break-all">{conn.name}</span>
                    <span className="text-[11px] font-mono text-[var(--accent)] break-all">{tunnelLabel}</span>
                    <span className="text-[11px] font-mono text-[var(--text-dim)]">
                      {engine.label} · {conn.status}
                    </span>
                  </div>
                }
              >
                <button
                  type="button"
                  aria-expanded={isExpanded}
                  onClick={() => {
                    setExpandedConnIds((prev) => ({ ...prev, [conn.id]: !isExpanded }));
                    onSelectConnection?.(conn);
                  }}
                  className="flex-1 min-w-0 px-2 py-1 rounded-lg text-left flex items-center gap-2 group transition-colors cursor-pointer"
                >
                  <span className="w-4 h-4 rounded flex items-center justify-center text-text-dim group-hover:text-text-pri shrink-0">
                    {isExpanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                  </span>

                  <div className="relative shrink-0 flex items-center justify-center">
                    <div
                      className={`w-5 h-5 rounded-md flex items-center justify-center border ${
                        isConnected
                          ? 'bg-success/15 border-success/40 text-success'
                          : isSelectedConn
                            ? 'bg-accent/15 border-accent/40 text-accent'
                            : 'bg-elev border-border text-text-mut'
                      }`}
                    >
                      <Database size={12} />
                    </div>
                    {isConnected && (
                      <span
                        className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-success ring-2 ring-bg"
                        aria-hidden="true"
                      />
                    )}
                  </div>

                  <div className="min-w-0 flex-1">
                    <div data-truncate className="text-[12px] font-medium text-text-pri truncate">
                      {conn.name}
                    </div>
                    {isExpanded && (
                      <div data-truncate className="text-[11px] font-mono text-text-dim truncate mt-0.5">
                        {tunnelLabel}
                      </div>
                    )}
                  </div>
                </button>
              </Tooltip>

              {/* Compact inline actions + Engine pill */}
              <div className="flex items-center gap-0.5 shrink-0">
                {onConnect && (
                  <Tooltip
                    label={
                      conn.status === 'connecting'
                        ? 'Connecting…'
                        : isConnected && conn.liveBackend
                          ? 'Reconnect'
                          : 'Connect'
                    }
                    side="top"
                    delay={160}
                  >
                    <button
                      type="button"
                      disabled={conn.status === 'connecting'}
                      aria-label={
                        conn.status === 'connecting'
                          ? 'Connecting'
                          : isConnected && conn.liveBackend
                            ? 'Reconnect'
                            : 'Connect'
                      }
                      onClick={(e) => {
                        e.stopPropagation();
                        onConnect(conn);
                      }}
                      className="w-5 h-5 rounded flex items-center justify-center text-accent hover:bg-elev cursor-pointer disabled:opacity-60"
                    >
                      {conn.status === 'connecting' ? (
                        <Loader2 size={11} className="animate-spin" />
                      ) : (
                        <Plug size={11} />
                      )}
                    </button>
                  </Tooltip>
                )}
                {isConnected && onDisconnect && (
                  <Tooltip label="Disconnect" side="top" delay={160}>
                    <button
                      type="button"
                      aria-label="Disconnect"
                      onClick={(e) => {
                        e.stopPropagation();
                        onDisconnect(conn);
                      }}
                      className="w-5 h-5 rounded flex items-center justify-center text-text-dim hover:text-text-pri hover:bg-elev cursor-pointer"
                    >
                      <Power size={11} />
                    </button>
                  </Tooltip>
                )}
                {onEdit && (
                  <Tooltip label="Edit connection" side="top" delay={160}>
                    <button
                      type="button"
                      aria-label="Edit"
                      onClick={(e) => {
                        e.stopPropagation();
                        onEdit(conn);
                      }}
                      className="w-5 h-5 rounded flex items-center justify-center text-text-dim hover:text-text-pri hover:bg-elev cursor-pointer"
                    >
                      <Pencil size={11} />
                    </button>
                  </Tooltip>
                )}
                {onRemove && (
                  <Tooltip label="Remove connection" side="top" delay={160}>
                    <button
                      type="button"
                      aria-label="Remove"
                      onClick={(e) => {
                        e.stopPropagation();
                        onRemove(conn);
                      }}
                      className="w-5 h-5 rounded flex items-center justify-center text-text-dim hover:text-danger hover:bg-elev cursor-pointer"
                    >
                      <Trash2 size={11} />
                    </button>
                  </Tooltip>
                )}
                <Tooltip label={engine.label} side="top" delay={160}>
                  <span
                    aria-label={engine.label}
                    className={`ml-0.5 text-[10px] font-mono px-1.5 py-0.5 rounded border font-medium shrink-0 ${
                      isConnected
                        ? 'bg-success/15 border-success/30 text-success'
                        : 'bg-accent/15 border-accent/30 text-accent'
                    }`}
                  >
                    {engine.short}
                  </span>
                </Tooltip>
              </div>
            </div>

            {/* Expanded connection body — V2 K8s-style 2-level rail */}
            {isExpanded && (
              <div className="ml-4 pl-2.5 my-1 pb-1.5 border-l border-border/60 space-y-0.5">
                {conn.lastError && (
                  <div
                    role="alert"
                    className="rounded-[var(--radius-sm)] border border-danger/40 bg-danger/10 px-2 py-1 text-[10.5px] text-danger break-words"
                  >
                    {conn.lastError}
                  </div>
                )}

                {(isConnected || (conn.tables && conn.tables.length > 0)) && (() => {
                  const schemaGroups = new Map<string, TableDef[]>();
                  for (const tbl of conn.tables || []) {
                    const sch = tbl.schema || 'public';
                    const list = schemaGroups.get(sch);
                    if (list) list.push(tbl);
                    else schemaGroups.set(sch, [tbl]);
                  }
                  if (schemaGroups.size === 0) {
                    schemaGroups.set('public', []);
                  }

                  const schemaNames = Array.from(schemaGroups.keys());
                  const activeSchemaName =
                    selectedSchemaByConn[conn.id] && schemaGroups.has(selectedSchemaByConn[conn.id])
                      ? selectedSchemaByConn[conn.id]
                      : schemaNames[0];
                  const rawSchemaTables = schemaGroups.get(activeSchemaName) ?? [];
                  const schemaTables = normalizedFilter
                    ? rawSchemaTables.filter(
                        (t) =>
                          t.name.toLowerCase().includes(normalizedFilter) ||
                          t.schema.toLowerCase().includes(normalizedFilter),
                      )
                    : rawSchemaTables;

                  const tablesKey = `${conn.id}:tables:${activeSchemaName}`;
                  const tablesOpen = hasMatchingTables || isTreeNodeExpanded(tablesKey, true);
                  const dbList = Array.from(new Set([...(conn.databases ?? []), conn.database].filter(Boolean)));

                  return (
                    <div role="group" aria-label={`${conn.name} schema tree`} className="space-y-0.5 text-[12px] select-none">
                      {/* Top Standalone item: Overview (shows active database) */}
                      <Tooltip
                        onlyWhenTruncated
                        side="right"
                        sideOffset={8}
                        delay={160}
                        content={`Database: ${conn.database}${dbList.length > 1 ? ` (${dbList.length} databases)` : ''}`}
                      >
                        <button
                          type="button"
                          onClick={() => onSelectConnection?.(conn)}
                          className="w-full flex items-center gap-2 px-2 py-0.5 rounded-md text-left text-[12px] text-text-mut hover:text-text-pri hover:bg-surface border border-transparent cursor-pointer"
                        >
                          <LayoutDashboard size={13} className="shrink-0 opacity-80" />
                          <span className="truncate flex-1">Overview</span>
                          <span data-truncate className="text-[10.5px] font-mono text-text-dim truncate max-w-[100px]">
                            {conn.database}
                          </span>
                        </button>
                      </Tooltip>

                      {/* Schema Selector Pill */}
                      <div className="flex items-center justify-between gap-2 px-2 py-0.5 rounded-md bg-bg/70 border border-border/70 text-[11.5px]">
                        <span className="flex items-center gap-1.5 text-text-mut shrink-0">
                          <Layers size={12} className="text-info opacity-80" aria-hidden="true" />
                          <span>Schema</span>
                        </span>
                        {schemaNames.length > 1 ? (
                          <select
                            aria-label="Select schema"
                            value={activeSchemaName}
                            onChange={(e) =>
                              setSelectedSchemaByConn((prev) => ({ ...prev, [conn.id]: e.target.value }))
                            }
                            className="bg-transparent font-mono text-[11px] text-accent focus:outline-none cursor-pointer truncate max-w-[130px]"
                          >
                            {schemaNames.map((sch) => (
                              <option key={sch} value={sch}>
                                {sch} ({schemaGroups.get(sch)?.length ?? 0})
                              </option>
                            ))}
                          </select>
                        ) : (
                          <span className="font-mono text-[11px] text-accent truncate">
                            {activeSchemaName}
                          </span>
                        )}
                      </div>

                      {/* Category: Tables (K8s Workloads style) */}
                      <div className="space-y-0.5">
                        <button
                          type="button"
                          role="treeitem"
                          aria-expanded={tablesOpen}
                          onClick={() => toggleTreeNode(tablesKey, true)}
                          className="w-full px-2 py-0.5 flex items-center gap-1.5 text-left text-text-pri hover:bg-surface rounded-md text-[12px] cursor-pointer"
                        >
                          <span className="text-text-dim shrink-0">
                            {tablesOpen ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
                          </span>
                          <Table2 size={13} className="text-accent shrink-0 opacity-80" aria-hidden="true" />
                          <span className="truncate font-medium flex-1">Tables</span>
                          <span className="text-[10px] font-mono text-text-dim shrink-0">
                            {schemaTables.length}
                          </span>
                        </button>

                        {tablesOpen && (
                          <div className="pl-3 pr-1 space-y-0.5 border-l border-border/40 ml-2.5 my-0.5">
                            {schemaTables.length === 0 ? (
                              <div className="px-2 py-1 text-[11px] text-text-dim">No tables</div>
                            ) : (
                              schemaTables.map((tbl) => {
                                const colKey = `${conn.id}:table:${tbl.schema}.${tbl.name}`;
                                const colsOpen = isTreeNodeExpanded(colKey, false);
                                const isActiveTbl =
                                  activeTable?.connectionId === conn.id &&
                                  activeTable?.name?.toLowerCase() === tbl.name.toLowerCase() &&
                                  (!activeTable?.schema ||
                                    activeTable.schema.toLowerCase() === tbl.schema.toLowerCase());

                                return (
                                  <div key={`${tbl.schema}.${tbl.name}`}>
                                    <div
                                      className={`flex items-center gap-1 rounded px-1.5 py-0.5 text-[12px] transition-colors ${
                                        isActiveTbl
                                          ? 'bg-accent/15 text-accent font-medium border border-accent/30'
                                          : 'text-text-mut hover:text-text-pri hover:bg-surface border border-transparent'
                                      }`}
                                    >
                                      <button
                                        type="button"
                                        aria-label={`Toggle columns for ${tbl.name}`}
                                        aria-expanded={colsOpen}
                                        onClick={() => toggleTreeNode(colKey, false)}
                                        className="p-0.5 text-text-dim hover:text-text-pri cursor-pointer shrink-0"
                                      >
                                        {colsOpen ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
                                      </button>
                                      <Tooltip
                                        onlyWhenTruncated
                                        side="right"
                                        sideOffset={8}
                                        delay={160}
                                        content={
                                          <div className="flex flex-col gap-0.5">
                                            <span className="font-mono text-[12px] font-semibold text-[var(--text-pri)] break-all">
                                              {tbl.schema}.{tbl.name}
                                            </span>
                                            <span className="text-[11px] font-mono text-[var(--text-dim)]">
                                              {tbl.sizePretty ? `${tbl.sizePretty} · ` : ''}
                                              {tbl.estimatedRows.toLocaleString()} est. rows · {tbl.columns.length} cols
                                            </span>
                                          </div>
                                        }
                                      >
                                        <button
                                          type="button"
                                          onClick={() => onOpenTable?.(conn, tbl)}
                                          className="flex-1 py-0.5 flex items-center gap-1.5 text-left text-[12px] cursor-pointer min-w-0"
                                        >
                                          <span
                                            data-truncate
                                            className={`truncate flex-1 ${isActiveTbl ? 'text-accent font-medium' : 'text-text-pri'}`}
                                          >
                                            {tbl.name}
                                          </span>
                                          {tbl.sizePretty && (
                                            <span className="ml-auto text-[10px] font-mono px-1.5 py-0.2 rounded border border-border bg-surface text-text-dim font-medium shrink-0 inline-flex items-center justify-center">
                                              {tbl.sizePretty}
                                            </span>
                                          )}
                                        </button>
                                      </Tooltip>
                                    </div>

                                    {colsOpen && (
                                      <ul className="ml-4 mt-0.5 space-y-0.5 border-l border-border/70 pl-2 pb-1">
                                        {tbl.columns.map((col) => (
                                          <Tooltip
                                            key={col.name}
                                            onlyWhenTruncated
                                            side="right"
                                            sideOffset={8}
                                            delay={160}
                                            content={`${col.name} (${col.type})`}
                                          >
                                            <li className="flex items-center justify-between gap-2 text-[11px] py-0.5 pr-1">
                                              <span data-truncate className="flex items-center gap-1 font-mono text-text-sec truncate min-w-0">
                                                {col.pk && (
                                                  <KeyRound size={10} className="text-warn shrink-0" aria-hidden="true" />
                                                )}
                                                <span className="truncate">{col.name}</span>
                                              </span>
                                              <span data-truncate className="text-[10px] font-mono text-text-dim shrink-0 max-w-[80px] truncate">
                                                {col.type}
                                              </span>
                                            </li>
                                          </Tooltip>
                                        ))}
                                      </ul>
                                    )}
                                  </div>
                                );
                              })
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })()}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

