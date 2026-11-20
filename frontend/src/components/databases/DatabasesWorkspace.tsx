import { useCallback, useEffect, useMemo, useState, type KeyboardEvent } from 'react';
import {
  AlertCircle,
  Check,
  Clock,
  Copy,
  Database,
  Download,
  FileCode2,
  GitBranch,
  Loader2,
  Lock,
  LockOpen,
  PanelLeftClose,
  PanelLeftOpen,
  PanelRightClose,
  PanelRightOpen,
  Pencil,
  Play,
  Plug,
  Plus,
  Power,
  RefreshCw,
  RotateCcw,
  Search,
  Sparkles,
} from 'lucide-react';
import { Badge, Button, Dialog, Input, Select } from '@/components/primitives';
import { WorkspaceTab, WorkspaceTabBar } from '@/components/primitives/WorkspaceTabs';
import { api } from '@/lib/api';
import { useToastStore } from '@/stores/toast';
import {
  DatabaseTree,
  type DbEngine,
  type ColumnDef,
  type TableDef,
  type DbConnection,
  ENGINE_META,
  connectionDotClass,
} from './DatabaseTree';

export type { DbEngine, ColumnDef, TableDef, DbConnection };

type ResultTab = 'results' | 'explain' | 'history' | 'schema';

interface QueryWorksheet {
  id: string;
  title: string;
  connectionId: string;
  sql: string;
}

interface HistoryEntry {
  id: string;
  connectionName: string;
  sql: string;
  durationMs: number;
  rowsReturned: number;
  status: 'ok' | 'blocked' | 'error';
  executedAt: string;
}

interface ExecutionResult {
  columns: string[];
  rows: Array<Record<string, string | number | boolean | null>>;
  durationMs: number;
  tableUsed: TableDef | null;
  error?: string;
  blockedByGuard?: boolean;
  notice?: string;
}

const STORAGE_KEY = 'operquay.db.customConnections.v1';
const SESSION_SECRETS_KEY = 'operquay.db.sessionSecrets.v1';

const BUILTIN_CONNECTIONS: DbConnection[] = [];

const EMPTY_RESULT: ExecutionResult = {
  columns: [],
  rows: [],
  durationMs: 0,
  tableUsed: null,
};

function loadSessionSecrets(): Record<string, string> {
  try {
    const raw = window.sessionStorage?.getItem(SESSION_SECRETS_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, string>) : {};
  } catch {
    return {};
  }
}

function saveSessionSecrets(items: DbConnection[]): void {
  try {
    if (!window.sessionStorage) return;
    const secrets: Record<string, string> = {};
    for (const item of items) {
      if (item.password) {
        secrets[item.id] = item.password;
      }
    }
    window.sessionStorage.setItem(SESSION_SECRETS_KEY, JSON.stringify(secrets));
  } catch {
    // Ignore storage errors in restricted environments.
  }
}

function loadCustomConnections(): DbConnection[] {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    const secrets = loadSessionSecrets();
    return parsed.map((item) => ({
      ...item,
      password: item?.id && secrets[item.id] ? secrets[item.id] : undefined,
      status: item?.status === 'standby' || !item?.status ? 'disconnected' : item.status,
    })) as DbConnection[];
  } catch {
    return [];
  }
}

function saveCustomConnections(items: DbConnection[]): void {
  saveSessionSecrets(items);
  try {
    const sanitized = items.map(({ password: _password, ...rest }) => rest);
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(sanitized));
    window.dispatchEvent(new CustomEvent('operquay:db-connections-changed'));
  } catch {
    // Ignore storage quota errors in ephemeral contexts.
  }
}

function resolveTableUsedFromSQL(
  sql: string,
  tables: TableDef[],
  fallback: TableDef | null,
): TableDef | null {
  const match = sql.match(
    /\bFROM\s+(?:(?:"([^"]+)"|`([^`]+)`|([a-zA-Z0-9_]+))\.)?(?:"([^"]+)"|`([^`]+)`|([a-zA-Z0-9_]+))/i,
  );
  if (!match) return fallback;
  const schemaPart = (match[1] ?? match[2] ?? match[3] ?? '').toLowerCase();
  const tablePart = (match[4] ?? match[5] ?? match[6] ?? '').toLowerCase();
  if (!tablePart) return fallback;
  const exact = tables.find(
    (t) =>
      t.name.toLowerCase() === tablePart &&
      (!schemaPart || t.schema.toLowerCase() === schemaPart),
  );
  return exact ?? fallback;
}

function formatSqlQuery(raw: string): string {
  return raw
    .trim()
    .replace(/\b(select|from|where|order by|group by|limit|and|or|desc|asc|show tables|describe)\b/gi, (m) => m.toUpperCase())
    .replace(/\s+(FROM|WHERE|ORDER BY|GROUP BY|LIMIT)\b/g, '\n$1');
}

type CellValue = string | number | boolean | null;

function formatCellValue(v: CellValue | undefined): string {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  return String(v);
}

function formatEditableCellValue(v: CellValue | undefined): string {
  if (v === null || v === undefined) return '';
  return String(v);
}

function parseEditedCellValue(raw: string, original: CellValue | undefined): CellValue {
  const trimmed = raw.trim();
  if (raw === 'NULL') return null;
  if (raw === '') return original === null || original === undefined ? null : '';
  if (typeof original === 'number') {
    const parsed = Number(raw);
    return Number.isFinite(parsed) && trimmed !== '' ? parsed : raw;
  }
  if (typeof original === 'boolean') {
    if (trimmed.toLowerCase() === 'true') return true;
    if (trimmed.toLowerCase() === 'false') return false;
  }
  return raw;
}

function getEffectiveValue(
  pendingEdits: Record<number, Record<string, CellValue>>,
  origIdx: number,
  col: string,
  baseVal: CellValue | undefined,
): CellValue {
  const rowEdits = pendingEdits[origIdx];
  if (rowEdits && Object.prototype.hasOwnProperty.call(rowEdits, col)) {
    return rowEdits[col];
  }
  return baseVal ?? null;
}

function isCellDirty(
  pendingEdits: Record<number, Record<string, CellValue>>,
  origIdx: number,
  col: string,
  baseVal: CellValue | undefined,
): boolean {
  const rowEdits = pendingEdits[origIdx];
  if (!rowEdits || !Object.prototype.hasOwnProperty.call(rowEdits, col)) return false;
  return rowEdits[col] !== (baseVal ?? null);
}

function executeSimulatedQuery(conn: DbConnection | undefined, sql: string): ExecutionResult {
  const start = performance.now();
  const trimmed = sql.trim().replace(/;+\s*$/, '');
  if (!trimmed) {
    return { columns: [], rows: [], durationMs: 0, tableUsed: null, error: 'Enter a SQL statement to execute.' };
  }

  const normalized = trimmed.replace(/\s+/g, ' ');
  const upper = normalized.toUpperCase();

  if (/^(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|GRANT|REVOKE)\b/i.test(normalized)) {
    return {
      columns: [],
      rows: [],
      durationMs: Math.max(1, Math.round(performance.now() - start)),
      tableUsed: null,
      blockedByGuard: true,
      error: 'Write statement blocked by Read-Only Guard. Disable Read-Only Guard in the toolbar to run write statements.',
    };
  }

  if (!conn) {
    return {
      columns: [],
      rows: [],
      durationMs: 1,
      tableUsed: null,
      error: 'No database connection selected. Add a database connection to execute queries.',
    };
  }

  if (/^SHOW TABLES\b/i.test(normalized)) {
    const cols = ['schema', 'table_name', 'estimated_rows', 'columns'];
    const rows = conn.tables.map((t) => ({
      schema: t.schema,
      table_name: t.name,
      estimated_rows: t.estimatedRows,
      columns: t.columns.length,
    }));
    return { columns: cols, rows, durationMs: 6, tableUsed: conn.tables[0] ?? null };
  }

  const descMatch = normalized.match(/^(?:DESCRIBE|DESC)\s+([a-zA-Z0-9_."`]+)/i);
  if (descMatch) {
    const targetName = descMatch[1].replace(/["`]/g, '').split('.').pop()?.toLowerCase() ?? '';
    const table = conn.tables.find((t) => t.name.toLowerCase() === targetName);
    if (!table) {
      return { columns: [], rows: [], durationMs: 4, tableUsed: null, error: `Relation "${targetName}" does not exist on ${conn.name}.` };
    }
    return {
      columns: ['column_name', 'data_type', 'primary_key'],
      rows: table.columns.map((c) => ({ column_name: c.name, data_type: c.type, primary_key: Boolean(c.pk) })),
      durationMs: 5,
      tableUsed: table,
    };
  }

  if (!upper.startsWith('SELECT ')) {
    return {
      columns: [],
      rows: [],
      durationMs: 3,
      tableUsed: null,
      error: 'SQL engine supports SELECT, SHOW TABLES, and DESCRIBE <table> statements.',
    };
  }

  if (!/\bFROM\b/i.test(normalized)) {
    const expr = normalized.slice(7).trim();
    return {
      columns: ['result'],
      rows: [{ result: expr }],
      durationMs: 3,
      tableUsed: null,
    };
  }

  const fromMatch = normalized.match(/\bFROM\s+([a-zA-Z0-9_."`]+)/i);
  const rawTableName = fromMatch?.[1]?.replace(/["`]/g, '').split('.').pop()?.toLowerCase();
  const table = rawTableName
    ? conn.tables.find((t) => t.name.toLowerCase() === rawTableName)
    : conn.tables[0];

  if (!table) {
    return {
      columns: [],
      rows: [],
      durationMs: 5,
      tableUsed: null,
      error: conn.tables.length > 0
        ? `Table "${rawTableName}" not found in ${conn.name}. Available tables: ${conn.tables.map((t) => t.name).join(', ')}`
        : `No introspected tables cached for "${conn.name}". Run SELECT 1; or connect an SSM tunnel for live schema discovery.`,
    };
  }

  let rows = [...(table.rows ?? [])];

  const whereMatch = normalized.match(/\bWHERE\s+(.+?)(?=\s+\b(?:ORDER BY|GROUP BY|LIMIT)\b|$)/i);
  if (whereMatch) {
    const cond = whereMatch[1].trim();
    const numCond = cond.match(/^([a-zA-Z0-9_]+)\s*(>=|<=|>|<|=)\s*(\d+(?:\.\d+)?)$/);
    const strCond = cond.match(/^([a-zA-Z0-9_]+)\s*=\s*['"]([^'"]*)['"]$/);
    const likeCond = cond.match(/^([a-zA-Z0-9_]+)\s+ILIKE\s+['"]([^'"]*)['"]$/i) || cond.match(/^([a-zA-Z0-9_]+)\s+LIKE\s+['"]([^'"]*)['"]$/i);

    if (numCond) {
      const [, col, op, valStr] = numCond;
      const rhs = Number(valStr);
      rows = rows.filter((r) => {
        const lhs = Number(r[col]);
        if (Number.isNaN(lhs)) return false;
        if (op === '>') return lhs > rhs;
        if (op === '<') return lhs < rhs;
        if (op === '>=') return lhs >= rhs;
        if (op === '<=') return lhs <= rhs;
        return lhs === rhs;
      });
    } else if (strCond) {
      const [, col, val] = strCond;
      rows = rows.filter((r) => String(r[col] ?? '').toLowerCase() === val.toLowerCase());
    } else if (likeCond) {
      const [, col, pattern] = likeCond;
      const needle = pattern.replace(/%/g, '').toLowerCase();
      rows = rows.filter((r) => String(r[col] ?? '').toLowerCase().includes(needle));
    }
  }

  const orderMatch = normalized.match(/\bORDER\s+BY\s+([a-zA-Z0-9_]+)(?:\s+(ASC|DESC))?/i);
  if (orderMatch) {
    const [, col, dirRaw] = orderMatch;
    const desc = (dirRaw || 'ASC').toUpperCase() === 'DESC';
    rows.sort((a, b) => {
      const av = a[col];
      const bv = b[col];
      if (typeof av === 'number' && typeof bv === 'number') return desc ? bv - av : av - bv;
      return desc ? String(bv ?? '').localeCompare(String(av ?? '')) : String(av ?? '').localeCompare(String(bv ?? ''));
    });
  }

  const limitMatch = normalized.match(/\bLIMIT\s+(\d+)/i);
  if (limitMatch) {
    rows = rows.slice(0, Math.max(0, Number(limitMatch[1])));
  }

  const selectClause = normalized.slice(7, normalized.search(/\bFROM\b/i)).trim();
  const allCols = table.columns.map((c) => c.name);
  const selectedCols =
    selectClause === '*' || !selectClause
      ? allCols
      : selectClause
          .split(',')
          .map((c) => c.trim().split(/\s+as\s+/i)[0].trim())
          .filter((c) => allCols.includes(c));

  const columns = selectedCols.length > 0 ? selectedCols : allCols;
  const elapsed = Math.max(4, Math.round(performance.now() - start) + 11);

  return {
    columns,
    rows,
    durationMs: elapsed,
    tableUsed: table,
    notice: undefined,
  };
}

export function DatabasesWorkspace({
  initialConnections = BUILTIN_CONNECTIONS,
  defaultShowExplorer = true,
}: {
  initialConnections?: DbConnection[];
  defaultShowExplorer?: boolean;
}) {
  const pushToast = useToastStore((s) => s.push);
  const [customConnections, setCustomConnections] = useState<DbConnection[]>(() => loadCustomConnections());
  const allConnections = useMemo(() => [...initialConnections, ...customConnections], [initialConnections, customConnections]);

  const [worksheets, setWorksheets] = useState<QueryWorksheet[]>(() => [
    {
      id: 'ws-1',
      title: 'query_1.sql',
      connectionId: initialConnections[0]?.id ?? loadCustomConnections()[0]?.id ?? '',
      sql: initialConnections[0]?.tables[0] ? `SELECT *\nFROM ${initialConnections[0].tables[0].name}\nLIMIT 25;` : 'SELECT 1;',
    },
  ]);
  const [activeWorksheetId, setActiveWorksheetId] = useState<string>('ws-1');
  const [readOnlyGuard, setReadOnlyGuard] = useState<boolean>(true);
  const [showExplorer, setShowExplorer] = useState<boolean>(defaultShowExplorer);
  const [showInspector, setShowInspector] = useState<boolean>(true);
  const [resultTab, setResultTab] = useState<ResultTab>('results');
  const [resultFilter, setResultFilter] = useState<string>('');
  const [sortCol, setSortCol] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [selectedRowIdx, setSelectedRowIdx] = useState<number>(0);
  const [pendingEdits, setPendingEdits] = useState<Record<number, Record<string, CellValue>>>({});
  const [pendingNewRows, setPendingNewRows] = useState<Array<Record<string, CellValue>>>([]);
  const [editingCell, setEditingCell] = useState<{ origIdx: number; col: string } | null>(null);
  const [isSavingEdits, setIsSavingEdits] = useState(false);

  const activeWorksheet = useMemo(
    () => worksheets.find((w) => w.id === activeWorksheetId) ?? worksheets[0],
    [worksheets, activeWorksheetId],
  );
  const activeConnection = useMemo(
    () => allConnections.find((c) => c.id === activeWorksheet.connectionId) ?? allConnections[0],
    [allConnections, activeWorksheet.connectionId],
  );

  const [lastResult, setLastResult] = useState<ExecutionResult>(() =>
    initialConnections[0]?.tables[0]
      ? executeSimulatedQuery(initialConnections[0], `SELECT * FROM ${initialConnections[0].tables[0].name} LIMIT 25;`)
      : EMPTY_RESULT,
  );
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  const [newConnOpen, setNewConnOpen] = useState(false);
  const [editingConnId, setEditingConnId] = useState<string | null>(null);
  const [newName, setNewName] = useState('');
  const [newEngine, setNewEngine] = useState<DbEngine>('postgres');
  const [newHost, setNewHost] = useState('');
  const [newPort, setNewPort] = useState('5432');
  const [newDatabase, setNewDatabase] = useState('');
  const [newUser, setNewUser] = useState('postgres');
  const [newPassword, setNewPassword] = useState('');
  const [newSslEnabled, setNewSslEnabled] = useState<'true' | 'false'>('true');
  const [newSslMode, setNewSslMode] = useState('require');
  const [testConnState, setTestConnState] = useState<{ status: 'idle' | 'testing' | 'ok' | 'error'; message?: string }>({
    status: 'idle',
  });
  const [isRunningQuery, setIsRunningQuery] = useState(false);

  useEffect(() => {
    saveCustomConnections(customConnections);
  }, [customConnections]);

  const updateWorksheet = useCallback((patch: Partial<QueryWorksheet>) => {
    setWorksheets((prev) => prev.map((w) => (w.id === activeWorksheet.id ? { ...w, ...patch } : w)));
  }, [activeWorksheet.id]);

  const updateCustomConnection = useCallback((connId: string, patch: Partial<DbConnection>) => {
    setCustomConnections((prev) => prev.map((c) => (c.id === connId ? { ...c, ...patch } : c)));
  }, []);

  const buildConnPayload = useCallback((c: Pick<DbConnection, 'engine' | 'host' | 'port' | 'database' | 'username' | 'password' | 'ssl' | 'sslMode'>) => ({
    engine: c.engine,
    host: c.host,
    port: c.port,
    database: c.database,
    username: c.username,
    password: c.password ?? '',
    ssl: c.ssl ?? c.sslMode !== 'disable',
    ssl_mode: c.sslMode || 'require',
  }), []);

  const connectToDatabase = useCallback(
    async (conn: DbConnection) => {
      updateCustomConnection(conn.id, { status: 'connecting', lastError: undefined });
      const res = await api.post<{
        connected: boolean;
        database: string;
        databases?: string[];
        host: string;
        port: number;
        tables: TableDef[];
      }>('/api/db/connect', buildConnPayload(conn));

      if (res.ok) {
        const tables = Array.isArray(res.data.tables) ? res.data.tables : [];
        const databases =
          Array.isArray(res.data.databases) && res.data.databases.length > 0
            ? res.data.databases
            : [conn.database];
        updateCustomConnection(conn.id, {
          status: 'connected',
          liveBackend: true,
          lastError: undefined,
          databases,
          tables,
        });
        const firstTable = tables[0];
        if (firstTable) {
          if (firstTable.rows && firstTable.rows.length > 0) {
            setLastResult({
              columns: firstTable.columns.map((c) => c.name),
              rows: firstTable.rows,
              durationMs: 12,
              tableUsed: firstTable,
            });
            setSelectedRowIdx(0);
            setPendingEdits({});
            setPendingNewRows([]);
            setEditingCell(null);
            setResultTab('results');
          }
          if (activeWorksheet.connectionId === conn.id && (!activeWorksheet.sql.trim() || activeWorksheet.sql.trim() === 'SELECT 1;')) {
            updateWorksheet({
              sql: `SELECT ${firstTable.columns.map((c) => `"${c.name}"`).join(', ')}\nFROM "${firstTable.schema}"."${firstTable.name}"\nLIMIT 25;`,
            });
          }
        }

        pushToast({
          variant: 'success',
          title: `Connected to "${conn.name}"`,
          description: `${tables.length} table${tables.length === 1 ? '' : 's'} discovered`,
          duration: 3000,
        });
        return;
      }

      if (res.error.status === 0) {
        updateCustomConnection(conn.id, {
          status: 'connected',
          liveBackend: false,
          lastError: undefined,
        });

        pushToast({
          variant: 'success',
          title: `Connection "${conn.name}" saved`,
          duration: 3000,
        });
        return;
      }

      updateCustomConnection(conn.id, {
        status: 'error',
        liveBackend: false,
        lastError: res.error.message,
      });
      pushToast({
        variant: 'danger',
        title: `Failed to connect to "${conn.name}"`,
        description: res.error.message,
        duration: 4500,
      });
    },
    [activeWorksheet.connectionId, activeWorksheet.sql, buildConnPayload, pushToast, updateCustomConnection, updateWorksheet],
  );

  const handleDisconnect = useCallback(
    (conn: DbConnection) => {
      updateCustomConnection(conn.id, {
        status: 'disconnected',
        liveBackend: false,
        lastError: undefined,
      });
      pushToast({
        variant: 'info',
        title: `Disconnected "${conn.name}"`,
        duration: 2500,
      });
    },
    [pushToast, updateCustomConnection],
  );

  const openNewConnectionModal = useCallback(() => {
    setEditingConnId(null);
    setNewName('');
    setNewEngine('postgres');
    setNewHost('');
    setNewPort(String(ENGINE_META.postgres.defaultPort));
    setNewDatabase('');
    setNewUser('postgres');
    setNewPassword('');
    setNewSslEnabled('true');
    setNewSslMode('require');
    setTestConnState({ status: 'idle' });
    setNewConnOpen(true);
  }, []);

  const openEditConnectionModal = useCallback((conn: DbConnection) => {
    setEditingConnId(conn.id);
    setNewName(conn.name);
    setNewEngine(conn.engine);
    setNewHost(conn.host);
    setNewPort(String(conn.port));
    setNewDatabase(conn.database);
    setNewUser(conn.username ?? '');
    setNewPassword(conn.password ?? '');
    const sslEnabled = conn.ssl ?? conn.sslMode !== 'disable';
    setNewSslEnabled(sslEnabled ? 'true' : 'false');
    setNewSslMode(sslEnabled ? conn.sslMode || 'require' : 'disable');
    setTestConnState({ status: 'idle' });
    setNewConnOpen(true);
  }, []);

  const handleTestConnection = useCallback(async () => {
    const portNum = Number(newPort) || ENGINE_META[newEngine].defaultPort;
    const hostVal = newHost.trim() || '127.0.0.1';
    const sslEnabled = newSslEnabled === 'true';
    const resolvedSslMode = sslEnabled ? newSslMode : 'disable';
    setTestConnState({ status: 'testing', message: 'Testing connection...' });
    const res = await api.post<{ connected: boolean; tables: TableDef[] }>(
      '/api/db/connect',
      buildConnPayload({
        engine: newEngine,
        host: hostVal,
        port: portNum,
        database: newDatabase.trim() || 'app_db',
        username: newUser.trim() || 'postgres',
        password: newPassword,
        ssl: sslEnabled,
        sslMode: resolvedSslMode,
      }),
    );
    if (res.ok) {
      const count = Array.isArray(res.data.tables) ? res.data.tables.length : 0;
      setTestConnState({
        status: 'ok',
        message: `Connection succeeded (${count} table${count === 1 ? '' : 's'} discovered).`,
      });
      return;
    }
    setTestConnState({
      status: 'error',
      message: res.error.status === 0 ? 'Backend API unavailable in offline mode.' : res.error.message,
    });
  }, [buildConnPayload, newDatabase, newEngine, newHost, newPassword, newPort, newSslEnabled, newSslMode, newUser]);

  const executeLiveQuery = useCallback(
    async (conn: DbConnection, sqlToRun: string, explicitTableUsed?: TableDef | null) => {
      setIsRunningQuery(true);
      const res = await api.post<{
        columns: string[];
        rows: Array<Record<string, CellValue>>;
        duration_ms: number;
      }>('/api/db/query', {
        connection: buildConnPayload(conn),
        sql: sqlToRun,
        read_only: readOnlyGuard,
      });
      setIsRunningQuery(false);

      if (res.ok) {
        const resolvedTable =
          explicitTableUsed !== undefined
            ? explicitTableUsed
            : resolveTableUsedFromSQL(sqlToRun, conn.tables, null);
        const nextResult: ExecutionResult = {
          columns: res.data.columns ?? [],
          rows: res.data.rows ?? [],
          durationMs: res.data.duration_ms ?? 1,
          tableUsed: resolvedTable,
        };
        if (/\b(?:UPDATE|INSERT|DELETE|ALTER|DROP)\b/i.test(sqlToRun) && /\b(?:users)\b/i.test(sqlToRun)) {
          window.dispatchEvent(new CustomEvent('operquay:users-changed'));
        }
        setLastResult(nextResult);
        setSelectedRowIdx(0);
        setSortCol(null);
        setPendingEdits({});
        setPendingNewRows([]);
        setEditingCell(null);
        setResultTab('results');
        setHistory((prev) => [
          {
            id: `h-${Date.now()}-${prev.length}`,
            connectionName: conn.name,
            sql: sqlToRun.trim(),
            durationMs: nextResult.durationMs,
            rowsReturned: nextResult.rows.length,
            status: 'ok',
            executedAt: new Date().toLocaleTimeString(),
          },
          ...prev.slice(0, 29),
        ]);
        return;
      }

      const blocked = res.error.message.toLowerCase().includes('read-only guard');
      const errRes: ExecutionResult = {
        columns: [],
        rows: [],
        durationMs: 1,
        tableUsed: null,
        error: res.error.message,
        blockedByGuard: blocked,
      };
      setLastResult(errRes);
      setPendingEdits({});
      setPendingNewRows([]);
      setEditingCell(null);
      setResultTab('results');
      setHistory((prev) => [
        {
          id: `h-${Date.now()}-${prev.length}`,
          connectionName: conn.name,
          sql: sqlToRun.trim(),
          durationMs: 1,
          rowsReturned: 0,
          status: blocked ? 'blocked' : 'error',
          executedAt: new Date().toLocaleTimeString(),
        },
        ...prev.slice(0, 29),
      ]);
    },
    [buildConnPayload, readOnlyGuard],
  );

  const runQuery = useCallback(
    (overrideSql?: string, overrideConn?: DbConnection, explicitTableUsed?: TableDef | null) => {
      const conn = overrideConn ?? activeConnection;
      const sqlToRun = overrideSql ?? activeWorksheet.sql;

      if (conn?.liveBackend) {
        void executeLiveQuery(conn, sqlToRun, explicitTableUsed);
        return;
      }

      let res: ExecutionResult;
      if (!readOnlyGuard && conn && /^(INSERT|UPDATE|DELETE)\b/i.test(sqlToRun.trim())) {
        res = {
          columns: ['status', 'affected_rows', 'connection'],
          rows: [{ status: 'committed (sandbox preview)', affected_rows: 1, connection: conn.name }],
          durationMs: 14,
          tableUsed: conn.tables[0] ?? null,
        };
      } else {
        res = executeSimulatedQuery(conn, sqlToRun);
      }

      setLastResult(res);
      setSelectedRowIdx(0);
      setSortCol(null);
      setPendingEdits({});
      setPendingNewRows([]);
      setEditingCell(null);
      setResultTab('results');
      setHistory((prev) => [
        {
          id: `h-${Date.now()}-${prev.length}`,
          connectionName: conn?.name ?? 'No connection',
          sql: sqlToRun.trim(),
          durationMs: res.durationMs,
          rowsReturned: res.rows.length,
          status: res.blockedByGuard ? 'blocked' : res.error ? 'error' : 'ok',
          executedAt: new Date().toLocaleTimeString(),
        },
        ...prev.slice(0, 29),
      ]);
    },
    [activeConnection, activeWorksheet.sql, executeLiveQuery, readOnlyGuard],
  );

  const handleOpenTable = useCallback((conn: DbConnection, table: TableDef) => {
    const tableRef = conn.liveBackend ? `"${table.schema}"."${table.name}"` : table.name;
    const colList = conn.liveBackend ? table.columns.map((c) => `"${c.name}"`).join(', ') : table.columns.map((c) => c.name).join(', ');
    const nextSql = `SELECT ${colList}\nFROM ${tableRef}\nLIMIT 25;`;
    updateWorksheet({ connectionId: conn.id, sql: nextSql });
    runQuery(nextSql, conn, table);
    window.dispatchEvent(
      new CustomEvent('operquay:db-active-table-changed', {
        detail: { connectionId: conn.id, schema: table.schema, name: table.name },
      }),
    );
  }, [runQuery, updateWorksheet]);

  useEffect(() => {
    const onOpenAdd = () => openNewConnectionModal();
    const onSelectConn = (ev: Event) => {
      const id = (ev as CustomEvent<{ id?: string }>).detail?.id;
      if (id) {
        updateWorksheet({ connectionId: id });
      }
    };
    const onConnectEvt = (ev: Event) => {
      const id = (ev as CustomEvent<{ id?: string }>).detail?.id;
      if (!id) return;
      const target = allConnections.find((c) => c.id === id);
      if (target) {
        void connectToDatabase(target);
      }
    };
    const onDisconnectEvt = (ev: Event) => {
      const id = (ev as CustomEvent<{ id?: string }>).detail?.id;
      if (!id) return;
      const target = allConnections.find((c) => c.id === id);
      if (target) {
        handleDisconnect(target);
      }
    };
    const onOpenEditEvt = (ev: Event) => {
      const id = (ev as CustomEvent<{ id?: string }>).detail?.id;
      if (!id) return;
      const target = allConnections.find((c) => c.id === id);
      if (target) {
        openEditConnectionModal(target);
      }
    };
    const onRemoveEvt = (ev: Event) => {
      const id = (ev as CustomEvent<{ id?: string }>).detail?.id;
      if (!id) return;
      setCustomConnections((prev) => prev.filter((c) => c.id !== id));
    };
    const onOpenTableEvt = (ev: Event) => {
      const detail = (ev as CustomEvent<{ connectionId: string; schema: string; name: string }>).detail;
      if (!detail) return;
      const conn = allConnections.find((c) => c.id === detail.connectionId);
      if (!conn) return;
      const tbl = conn.tables?.find(
        (t) =>
          t.name.toLowerCase() === detail.name.toLowerCase() &&
          (!detail.schema || t.schema.toLowerCase() === detail.schema.toLowerCase()),
      );
      if (tbl) {
        handleOpenTable(conn, tbl);
      }
    };

    window.addEventListener('operquay:db-open-add-modal', onOpenAdd);
    window.addEventListener('operquay:db-select-connection', onSelectConn);
    window.addEventListener('operquay:db-connect', onConnectEvt);
    window.addEventListener('operquay:db-disconnect', onDisconnectEvt);
    window.addEventListener('operquay:db-open-edit-modal', onOpenEditEvt);
    window.addEventListener('operquay:db-remove-connection', onRemoveEvt);
    window.addEventListener('operquay:db-open-table', onOpenTableEvt);
    return () => {
      window.removeEventListener('operquay:db-open-add-modal', onOpenAdd);
      window.removeEventListener('operquay:db-select-connection', onSelectConn);
      window.removeEventListener('operquay:db-connect', onConnectEvt);
      window.removeEventListener('operquay:db-disconnect', onDisconnectEvt);
      window.removeEventListener('operquay:db-open-edit-modal', onOpenEditEvt);
      window.removeEventListener('operquay:db-remove-connection', onRemoveEvt);
      window.removeEventListener('operquay:db-open-table', onOpenTableEvt);
    };
  }, [allConnections, connectToDatabase, handleDisconnect, handleOpenTable, openEditConnectionModal, openNewConnectionModal, updateWorksheet]);


  const handleAddWorksheet = () => {
    const nextNum = worksheets.length + 1;
    const id = `ws-${Date.now()}`;
    setWorksheets((prev) => [
      ...prev,
      {
        id,
        title: `query_${nextNum}.sql`,
        connectionId: activeConnection?.id ?? '',
        sql: activeConnection?.tables[0] ? `SELECT *\nFROM ${activeConnection.tables[0].name}\nLIMIT 25;` : 'SELECT 1;',
      },
    ]);
    setActiveWorksheetId(id);
  };

  const handleCloseWorksheet = (id: string) => {
    if (worksheets.length <= 1) return;
    const remaining = worksheets.filter((w) => w.id !== id);
    setWorksheets(remaining);
    if (activeWorksheetId === id) {
      setActiveWorksheetId(remaining[remaining.length - 1].id);
    }
  };

  const handleSaveConnection = () => {
    const cleanName = newName.trim() || `custom-${newEngine}-${customConnections.length + 1}`;
    const portNum = Number(newPort) || ENGINE_META[newEngine].defaultPort;
    const hostVal = newHost.trim() || '127.0.0.1';
    const sslEnabled = newSslEnabled === 'true';
    const resolvedSslMode = sslEnabled ? newSslMode : 'disable';
    const existing = editingConnId ? customConnections.find((c) => c.id === editingConnId) : undefined;
    const savedConn: DbConnection = {
      id: editingConnId ?? `custom-${Date.now()}`,
      name: cleanName,
      engine: newEngine,
      host: hostVal,
      port: portNum,
      database: newDatabase.trim() || 'app_db',
      username: newUser.trim() || 'postgres',
      password: newPassword,
      ssl: sslEnabled,
      tunnel: `${hostVal}:${portNum} · SSL: ${sslEnabled ? `true (${resolvedSslMode})` : 'false'}`,
      sslMode: resolvedSslMode,
      status: 'connecting',
      lastError: undefined,
      liveBackend: existing?.liveBackend,
      tables: existing?.tables ?? [],
    };
    setCustomConnections((prev) =>
      editingConnId ? prev.map((c) => (c.id === editingConnId ? savedConn : c)) : [...prev, savedConn],
    );
    updateWorksheet({ connectionId: savedConn.id });
    setNewConnOpen(false);
    setEditingConnId(null);
    setNewName('');
    setNewHost('');
    setNewDatabase('');
    setNewPassword('');
    setTestConnState({ status: 'idle' });
    void connectToDatabase(savedConn);
  };

  const indexedCombinedRows = useMemo(
    () => [
      ...lastResult.rows.map((row, origIdx) => ({ row, origIdx, isNew: false })),
      ...pendingNewRows.map((row, j) => ({ row, origIdx: lastResult.rows.length + j, isNew: true })),
    ],
    [lastResult.rows, pendingNewRows],
  );

  const dirtyChangeCount = useMemo(() => {
    let count = pendingNewRows.length;
    for (const [key, cols] of Object.entries(pendingEdits)) {
      const idx = Number(key);
      if (idx < lastResult.rows.length) {
        count += Object.keys(cols).length;
      }
    }
    return count;
  }, [pendingEdits, pendingNewRows.length, lastResult.rows.length]);

  const stageCellEdit = useCallback(
    (origIdx: number, col: string, rawValue: string, baseVal: CellValue | undefined) => {
      const nextVal = parseEditedCellValue(rawValue, baseVal);
      setPendingEdits((prev) => {
        const existingRowEdits = { ...(prev[origIdx] ?? {}) };
        if (origIdx < lastResult.rows.length && nextVal === (baseVal ?? null)) {
          delete existingRowEdits[col];
        } else {
          existingRowEdits[col] = nextVal;
        }
        if (Object.keys(existingRowEdits).length === 0) {
          const copy = { ...prev };
          delete copy[origIdx];
          return copy;
        }
        return { ...prev, [origIdx]: existingRowEdits };
      });
    },
    [lastResult.rows.length],
  );

  const handleSaveEdits = async () => {
    if (dirtyChangeCount === 0 || isSavingEdits) return;
    const savedCount = dirtyChangeCount;
    const nextRows = indexedCombinedRows.map((entry) => ({
      ...entry.row,
      ...(pendingEdits[entry.origIdx] ?? {}),
    }));

    if (activeConnection?.liveBackend) {
      const targetTable =
        lastResult.tableUsed ??
        resolveTableUsedFromSQL(activeWorksheet.sql, activeConnection.tables, null);
      if (!targetTable) {
        pushToast({
          variant: 'danger',
          title: 'Cannot commit edits',
          description: 'Run a single-table SELECT query first so the target table is known.',
          duration: 4500,
        });
        return;
      }

      const updates = Object.entries(pendingEdits)
        .map(([k, changes]) => ({ idx: Number(k), changes }))
        .filter(({ idx, changes }) => idx < lastResult.rows.length && Object.keys(changes).length > 0)
        .map(({ idx, changes }) => ({
          original: lastResult.rows[idx],
          changes,
        }));

      const inserts = pendingNewRows.map((row, j) => ({
        ...row,
        ...(pendingEdits[lastResult.rows.length + j] ?? {}),
      }));

      setIsSavingEdits(true);
      try {
        const res = await api.post<{
          committed: boolean;
          updated: number;
          inserted: number;
          duration_ms: number;
        }>('/api/db/mutate', {
          connection: buildConnPayload(activeConnection),
          schema: targetTable.schema || 'public',
          table: targetTable.name,
          primary_keys: targetTable.columns.filter((c) => c.pk).map((c) => c.name),
          updates,
          inserts,
        });

        if (!res.ok) {
          pushToast({
            variant: 'danger',
            title: 'Failed to commit changes',
            description: res.error.message,
            duration: 5000,
          });
          return;
        }

        setLastResult((prev) => ({
          ...prev,
          rows: nextRows,
        }));

        setCustomConnections((prev) =>
          prev.map((conn) =>
            conn.id === activeConnection.id
              ? {
                  ...conn,
                  tables: conn.tables.map((t) =>
                    t.schema === targetTable.schema && t.name === targetTable.name
                      ? { ...t, rows: nextRows, estimatedRows: Math.max(t.estimatedRows, nextRows.length) }
                      : t,
                  ),
                }
              : conn,
          ),
        );

        setPendingEdits({});
        setPendingNewRows([]);
        setEditingCell(null);

        const refreshSql = /^\s*(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|GRANT|REVOKE|MERGE|COPY)\b/i.test(
          activeWorksheet.sql.trim(),
        )
          ? `SELECT * FROM "${targetTable.schema || 'public'}"."${targetTable.name}" LIMIT 25;`
          : activeWorksheet.sql;

        if (refreshSql.trim()) {
          await executeLiveQuery(activeConnection, refreshSql, targetTable);
        }

        setHistory((prev) => [
          {
            id: `h-${Date.now()}-${prev.length}`,
            connectionName: activeConnection.name,
            sql: `-- Committed ${savedCount} change${savedCount === 1 ? '' : 's'} to "${targetTable.schema || 'public'}"."${targetTable.name}"`,
            durationMs: res.data.duration_ms ?? 4,
            rowsReturned: nextRows.length,
            status: 'ok',
            executedAt: new Date().toLocaleTimeString(),
          },
          ...prev.slice(0, 29),
        ]);

        if (targetTable.name.toLowerCase() === 'users') {
          window.dispatchEvent(new CustomEvent('operquay:users-changed'));
        }

        pushToast({
          variant: 'success',
          title: `Committed ${savedCount} change${savedCount === 1 ? '' : 's'} to ${targetTable.schema}.${targetTable.name}`,
          duration: 3000,
        });
      } finally {
        setIsSavingEdits(false);
      }
      return;
    }

    setLastResult((prev) => ({
      ...prev,
      rows: nextRows,
    }));

    if (lastResult.tableUsed && activeConnection) {
      const targetTableName = lastResult.tableUsed.name;
      setCustomConnections((prev) =>
        prev.map((conn) =>
          conn.id === activeConnection.id
            ? {
                ...conn,
                tables: conn.tables.map((t) =>
                  t.name === targetTableName ? { ...t, rows: nextRows, estimatedRows: nextRows.length } : t,
                ),
              }
            : conn,
        ),
      );
    }

    setHistory((prev) => [
      {
        id: `h-${Date.now()}-${prev.length}`,
        connectionName: activeConnection?.name ?? 'Local Grid',
        sql: `-- Saved ${savedCount} inline/inspector change${savedCount === 1 ? '' : 's'}`,
        durationMs: 4,
        rowsReturned: nextRows.length,
        status: 'ok',
        executedAt: new Date().toLocaleTimeString(),
      },
      ...prev.slice(0, 29),
    ]);

    setPendingEdits({});
    setPendingNewRows([]);
    setEditingCell(null);
    pushToast({
      variant: 'success',
      title: `Saved ${savedCount} change${savedCount === 1 ? '' : 's'}`,
      duration: 2500,
    });
  };

  const handleCancelEdits = () => {
    if (dirtyChangeCount === 0) return;
    setPendingEdits({});
    setPendingNewRows([]);
    setEditingCell(null);
    if (selectedRowIdx >= lastResult.rows.length) {
      setSelectedRowIdx(Math.max(0, lastResult.rows.length - 1));
    }
    pushToast({ variant: 'info', title: 'Discarded uncommitted edits', duration: 2000 });
  };

  const handleRefreshResults = () => {
    setPendingEdits({});
    setPendingNewRows([]);
    setEditingCell(null);
    runQuery();
  };

  const handleAddRow = () => {
    const cols = lastResult.columns.length > 0 ? lastResult.columns : ['id', 'name', 'value'];
    const blankRow: Record<string, CellValue> = {};
    for (const c of cols) blankRow[c] = null;
    const newOrigIdx = lastResult.rows.length + pendingNewRows.length;

    if (lastResult.columns.length === 0) {
      setLastResult((prev) => ({
        ...prev,
        columns: cols,
        error: undefined,
        blockedByGuard: false,
      }));
    }

    setPendingNewRows((prev) => [...prev, blankRow]);
    setResultFilter('');
    setSortCol(null);
    setResultTab('results');
    setSelectedRowIdx(newOrigIdx);
    setEditingCell({ origIdx: newOrigIdx, col: cols[0] });
  };

  const filteredAndSortedEntries = useMemo(() => {
    const q = resultFilter.trim().toLowerCase();
    const list = !q
      ? indexedCombinedRows
      : indexedCombinedRows.filter((entry) =>
          lastResult.columns.some((c) =>
            formatCellValue(getEffectiveValue(pendingEdits, entry.origIdx, c, entry.row[c])).toLowerCase().includes(q),
          ),
        );
    if (!sortCol) return list;
    return [...list].sort((a, b) => {
      const av = getEffectiveValue(pendingEdits, a.origIdx, sortCol, a.row[sortCol]);
      const bv = getEffectiveValue(pendingEdits, b.origIdx, sortCol, b.row[sortCol]);
      if (typeof av === 'number' && typeof bv === 'number') return sortDir === 'asc' ? av - bv : bv - av;
      const cmp = formatCellValue(av).localeCompare(formatCellValue(bv));
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }, [indexedCombinedRows, pendingEdits, lastResult.columns, resultFilter, sortCol, sortDir]);

  const filteredAndSortedRows = useMemo(
    () =>
      filteredAndSortedEntries.map((entry) => ({
        ...entry.row,
        ...(pendingEdits[entry.origIdx] ?? {}),
      })),
    [filteredAndSortedEntries, pendingEdits],
  );

  const selectedEntry = filteredAndSortedEntries[selectedRowIdx] ?? filteredAndSortedEntries[0] ?? null;
  const selectedRow = useMemo(
    () =>
      selectedEntry
        ? {
            ...selectedEntry.row,
            ...(pendingEdits[selectedEntry.origIdx] ?? {}),
          }
        : null,
    [selectedEntry, pendingEdits],
  );
  const inspectorTable = lastResult.tableUsed ?? activeConnection?.tables[0] ?? null;

  const handleExport = (format: 'csv' | 'json') => {
    if (filteredAndSortedRows.length === 0) return;
    const content =
      format === 'json'
        ? JSON.stringify(filteredAndSortedRows, null, 2)
        : [
            lastResult.columns.join(','),
            ...filteredAndSortedRows.map((row) =>
              lastResult.columns.map((c) => JSON.stringify(row[c] ?? '')).join(','),
            ),
          ].join('\n');
    const blob = new Blob([content], { type: format === 'json' ? 'application/json' : 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeWorksheet.title.replace(/\.sql$/, '')}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyText = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      pushToast({ variant: 'info', title: `${label} copied`, duration: 2000 });
    } catch {
      pushToast({ variant: 'danger', title: 'Clipboard unavailable', duration: 2500 });
    }
  };

  const handleEditorKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      runQuery();
    } else if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === 'f') {
      e.preventDefault();
      updateWorksheet({ sql: formatSqlQuery(activeWorksheet.sql) });
    }
  };

  const lineCount = Math.max(1, activeWorksheet.sql.split('\n').length);

  return (
    <div className="h-full w-full flex bg-bg text-text-pri overflow-hidden">
      {/* Left Pane: Database Connections & Schema Navigator */}
      {showExplorer && (
        <aside
          aria-label="Database explorer"
          className="w-[295px] shrink-0 border-r border-border bg-surface flex flex-col min-h-0"
        >
          <div className="h-10 px-3 border-b border-border flex items-center justify-between gap-2 shrink-0">
            <div className="flex items-center gap-2 min-w-0">
              <Database size={14} className="text-accent shrink-0" aria-hidden="true" />
              <span className="text-[12px] font-semibold tracking-tight truncate">Database Explorer</span>
            </div>
            <div className="flex items-center gap-1">
              <Button
                type="button"
                variant="outline"
                size="xs"
                icon={<Plus size={11} />}
                onClick={openNewConnectionModal}
                aria-label="New database connection"
              >
                New
              </Button>
              <button
                type="button"
                onClick={() => setShowExplorer(false)}
                aria-label="Hide database explorer"
                className="h-6 w-6 inline-flex items-center justify-center rounded text-text-dim hover:text-text-pri hover:bg-elev cursor-pointer"
              >
                <PanelLeftClose size={13} />
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-2">
            <DatabaseTree
              connections={allConnections}
              selectedConnectionId={activeConnection?.id}
              activeTable={
                lastResult.tableUsed
                  ? {
                      connectionId: activeConnection?.id,
                      schema: lastResult.tableUsed.schema,
                      name: lastResult.tableUsed.name,
                    }
                  : null
              }
              onSelectConnection={(conn) => {
                updateWorksheet({ connectionId: conn.id });
              }}
              onConnect={(conn) => void connectToDatabase(conn)}
              onDisconnect={(conn) => handleDisconnect(conn)}
              onEdit={(conn) => openEditConnectionModal(conn)}
              onRemove={(conn) => setCustomConnections((prev) => prev.filter((c) => c.id !== conn.id))}
              onOpenTable={(conn, tbl) => handleOpenTable(conn, tbl)}
              onOpenAddModal={openNewConnectionModal}
            />
          </div>
        </aside>
      )}

      {/* Center Pane: Query Tabs + SQL Editor + Results / Explain / History */}
      <div className="flex-1 min-w-0 flex flex-col min-h-0">
        {/* Worksheet Tabs */}
        <div className="flex items-center border-b border-border bg-surface/80 shrink-0 pr-2">
          {!showExplorer && (
            <button
              type="button"
              onClick={() => setShowExplorer(true)}
              aria-label="Show database explorer"
              className="h-9 px-2.5 border-r border-border text-text-dim hover:text-text-pri hover:bg-elev cursor-pointer"
            >
              <PanelLeftOpen size={14} />
            </button>
          )}
          <WorkspaceTabBar className="flex-1 min-w-0 overflow-x-auto">
            {worksheets.map((ws) => (
              <WorkspaceTab
                key={ws.id}
                mode="split-button"
                active={ws.id === activeWorksheet.id}
                icon={<FileCode2 size={13} className="text-accent" />}
                label={ws.title}
                onSelect={() => setActiveWorksheetId(ws.id)}
                onClose={worksheets.length > 1 ? () => handleCloseWorksheet(ws.id) : undefined}
                closeLabel={`Close ${ws.title}`}
              />
            ))}
          </WorkspaceTabBar>
          <Button
            type="button"
            variant="ghost"
            size="xs"
            icon={<Plus size={12} />}
            onClick={handleAddWorksheet}
            aria-label="New SQL worksheet"
          >
            New Tab
          </Button>
          {!showInspector && (
            <button
              type="button"
              onClick={() => setShowInspector(true)}
              aria-label="Show row inspector"
              className="ml-1 h-7 px-2 rounded border border-border text-text-dim hover:text-text-pri hover:bg-elev cursor-pointer"
            >
              <PanelRightOpen size={13} />
            </button>
          )}
        </div>

        {/* Execution Toolbar */}
        <div className="px-3 py-2 border-b border-border bg-elev/50 flex flex-wrap items-center gap-2 shrink-0">
          <Select
            aria-label="Active database connection"
            className="w-auto min-w-[180px] h-8 text-[12px]"
            value={activeConnection?.id ?? ''}
            disabled={allConnections.length === 0}
            onChange={(e) => updateWorksheet({ connectionId: e.target.value })}
          >
            {allConnections.length === 0 ? (
              <option value="">No connection selected</option>
            ) : (
              allConnections.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} ({c.database})
                </option>
              ))
            )}
          </Select>

          {activeConnection ? (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="hidden md:inline-flex items-center gap-1.5 px-2 py-1 rounded bg-surface border border-border text-[11px] font-mono text-text-dim">
                <span className={`h-1.5 w-1.5 rounded-full ${connectionDotClass(activeConnection.status)}`} aria-hidden="true" />
                {activeConnection.host}:{activeConnection.port}
              </span>
              {activeConnection.id.startsWith('custom-') && (
                <>
                  {activeConnection.status === 'connected' && activeConnection.liveBackend ? (
                    <>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        className="h-8 text-[11px] px-2.5"
                        icon={<RefreshCw size={12} />}
                        onClick={() => void connectToDatabase(activeConnection)}
                      >
                        Reconnect
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        className="h-8 text-[11px] px-2.5"
                        icon={<Power size={12} />}
                        onClick={() => handleDisconnect(activeConnection)}
                      >
                        Disconnect
                      </Button>
                    </>
                  ) : (
                    <Button
                      type="button"
                      size="sm"
                      variant="primary"
                      className="h-8 text-[11px] px-2.5"
                      disabled={activeConnection.status === 'connecting'}
                      icon={
                        activeConnection.status === 'connecting' ? (
                          <Loader2 size={12} className="animate-spin" />
                        ) : (
                          <Plug size={12} />
                        )
                      }
                      onClick={() => void connectToDatabase(activeConnection)}
                    >
                      {activeConnection.status === 'connecting' ? 'Connecting…' : 'Connect'}
                    </Button>
                  )}
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    className="h-8 text-[11px] px-2"
                    icon={<Pencil size={12} />}
                    onClick={() => openEditConnectionModal(activeConnection)}
                    aria-label="Edit active connection"
                  >
                    Edit
                  </Button>
                </>
              )}
            </div>
          ) : (
            <Button
              size="sm"
              variant="secondary"
              className="h-8 text-[11px] px-2.5"
              onClick={openNewConnectionModal}
            >
              <Plus size={12} />
              Add Connection
            </Button>
          )}

          <div className="ml-auto flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              aria-pressed={readOnlyGuard}
              onClick={() => setReadOnlyGuard((v) => !v)}
              className={`inline-flex items-center gap-1.5 h-8 px-2.5 rounded-[var(--radius)] border text-[11px] font-medium transition-colors cursor-pointer ${
                readOnlyGuard
                  ? 'bg-success/10 border-success/30 text-success'
                  : 'bg-warn/15 border-warn/40 text-warn'
              }`}
            >
              {readOnlyGuard ? <Lock size={12} aria-hidden="true" /> : <LockOpen size={12} aria-hidden="true" />}
              Read-Only Guard {readOnlyGuard ? 'On' : 'Off'}
            </button>

            <Button
              type="button"
              variant="outline"
              size="sm"
              icon={<Sparkles size={12} />}
              onClick={() => updateWorksheet({ sql: formatSqlQuery(activeWorksheet.sql) })}
            >
              Format SQL
            </Button>

            <Button
              type="button"
              variant="outline"
              size="sm"
              icon={<GitBranch size={12} />}
              onClick={() => setResultTab('explain')}
            >
              Explain
            </Button>

            <Button
              type="button"
              variant="primary"
              size="sm"
              disabled={isRunningQuery}
              icon={isRunningQuery ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
              onClick={() => runQuery()}
            >
              {isRunningQuery ? 'Running…' : 'Run Query'}
            </Button>
          </div>
        </div>

        {/* SQL Editor Pane */}
        <div className="h-[190px] border-b border-border bg-[var(--canvas,var(--bg))] flex overflow-hidden shrink-0">
          <div
            aria-hidden="true"
            className="w-10 py-3 pr-2 text-right select-none font-mono text-[12px] leading-[1.55] text-text-dim border-r border-border/60 bg-surface/40 shrink-0"
          >
            {Array.from({ length: lineCount }, (_, idx) => (
              <div key={idx}>{idx + 1}</div>
            ))}
          </div>
          <textarea
            aria-label="SQL query editor"
            spellCheck={false}
            value={activeWorksheet.sql}
            onChange={(e) => updateWorksheet({ sql: e.target.value })}
            onKeyDown={handleEditorKeyDown}
            className="flex-1 resize-none bg-transparent px-3 py-3 font-mono text-[13px] leading-[1.55] text-text-pri focus:outline-none"
            placeholder="SELECT * FROM orders LIMIT 25;"
          />
        </div>

        {/* Output / Results Section */}
        <div className="flex-1 min-h-0 flex flex-col bg-bg">
          <div className="px-3 py-1.5 border-b border-border bg-surface/60 flex flex-wrap items-center gap-2 shrink-0">
            <div className="flex items-center gap-1" role="tablist" aria-label="Query output tabs">
              {([
                ['results', `Results (${filteredAndSortedRows.length})`],
                ['explain', 'Explain Plan'],
                ['history', `History (${history.length})`],
                ['schema', 'Schema Columns'],
              ] as Array<[ResultTab, string]>).map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  aria-selected={resultTab === id}
                  onClick={() => setResultTab(id)}
                  className={`px-2.5 py-1 rounded-[var(--radius-sm)] text-[11px] font-medium transition-colors cursor-pointer ${
                    resultTab === id
                      ? 'bg-[var(--accent-soft)] text-accent border border-[var(--accent-border)]'
                      : 'text-text-sec hover:text-text-pri hover:bg-elev border border-transparent'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            {resultTab === 'results' && !lastResult.error && (
              <div className="ml-auto flex flex-wrap items-center gap-1.5">
                {dirtyChangeCount > 0 && (
                  <Badge variant="warn">
                    {dirtyChangeCount} unsaved
                  </Badge>
                )}
                <Button
                  type="button"
                  variant={dirtyChangeCount > 0 ? 'primary' : 'outline'}
                  size="xs"
                  icon={<Check size={11} />}
                  disabled={dirtyChangeCount === 0 || isSavingEdits}
                  onClick={() => void handleSaveEdits()}
                  title="Save pending edits"
                >
                  Save
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="xs"
                  icon={<RotateCcw size={11} />}
                  disabled={dirtyChangeCount === 0}
                  onClick={handleCancelEdits}
                  title="Cancel uncommitted edits"
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="xs"
                  icon={<RefreshCw size={11} />}
                  onClick={handleRefreshResults}
                  title="Refresh query results"
                >
                  Refresh
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="xs"
                  icon={<Plus size={11} />}
                  onClick={handleAddRow}
                  title="Add new row"
                >
                  Add Row
                </Button>
                <div className="w-40">
                  <Input
                    icon={<Search size={11} />}
                    placeholder="Filter result rows…"
                    aria-label="Filter result rows"
                    value={resultFilter}
                    onChange={(e) => setResultFilter(e.target.value)}
                    className="h-7 text-[11px]"
                  />
                </div>
                <span className="text-[11px] font-mono text-text-dim tabular-nums">
                  {lastResult.durationMs} ms
                </span>
                <Button type="button" variant="outline" size="xs" icon={<Download size={11} />} onClick={() => handleExport('csv')}>
                  CSV
                </Button>
                <Button type="button" variant="outline" size="xs" icon={<Download size={11} />} onClick={() => handleExport('json')}>
                  JSON
                </Button>
              </div>
            )}
          </div>

          <div className="flex-1 min-h-0 overflow-auto p-3">
            {resultTab === 'results' && (
              <>
                {lastResult.error ? (
                  <div
                    role="alert"
                    className={`rounded-[var(--radius)] border px-4 py-3 text-[13px] ${
                      lastResult.blockedByGuard
                        ? 'border-warn/40 bg-warn/10 text-warn'
                        : 'border-danger/40 bg-danger/10 text-danger'
                    }`}
                  >
                    {lastResult.error}
                  </div>
                ) : (
                  <div className="rounded-[var(--radius)] border border-border bg-surface overflow-x-auto">
                    <table className="w-full text-[12px] border-collapse">
                      <thead className="bg-elev">
                        <tr className="border-b border-border text-left text-[11px] uppercase tracking-wider text-text-dim">
                          <th className="px-3 py-2 w-10 font-mono">#</th>
                          {lastResult.columns.map((col) => (
                            <th key={col} className="px-3 py-2 font-mono font-medium">
                              <button
                                type="button"
                                onClick={() => {
                                  if (sortCol === col) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
                                  else {
                                    setSortCol(col);
                                    setSortDir('asc');
                                  }
                                }}
                                className="hover:text-text-pri cursor-pointer flex items-center gap-1"
                              >
                                <span>{col}</span>
                                {sortCol === col && <span className="text-accent">{sortDir === 'asc' ? '↑' : '↓'}</span>}
                              </button>
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border/70">
                        {filteredAndSortedEntries.length === 0 ? (
                          <tr>
                            <td colSpan={Math.max(1, lastResult.columns.length) + 1} className="px-4 py-8 text-center text-text-dim">
                              Query returned 0 rows. Click Refresh to re-run or Add Row to insert data.
                            </td>
                          </tr>
                        ) : (
                          filteredAndSortedEntries.map((entry, idx) => (
                            <tr
                              key={entry.origIdx}
                              onClick={() => setSelectedRowIdx(idx)}
                              className={`cursor-pointer transition-colors ${
                                idx === selectedRowIdx ? 'bg-[var(--accent-soft)]/50' : 'hover:bg-elev/60'
                              }`}
                            >
                              <td className="px-3 py-2 font-mono text-[11px] text-text-dim whitespace-nowrap">
                                {entry.isNew ? `*${idx + 1}` : idx + 1}
                              </td>
                              {lastResult.columns.map((col) => {
                                const baseVal = entry.row[col];
                                const effectiveVal = getEffectiveValue(pendingEdits, entry.origIdx, col, baseVal);
                                const dirty = entry.isNew || isCellDirty(pendingEdits, entry.origIdx, col, baseVal);
                                const isEditing = editingCell?.origIdx === entry.origIdx && editingCell?.col === col;
                                const displayVal = formatCellValue(effectiveVal);
                                return (
                                  <td
                                    key={col}
                                    title={displayVal}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setSelectedRowIdx(idx);
                                      setEditingCell({ origIdx: entry.origIdx, col });
                                    }}
                                    onDoubleClick={(e) => {
                                      e.stopPropagation();
                                      setSelectedRowIdx(idx);
                                      setEditingCell({ origIdx: entry.origIdx, col });
                                    }}
                                    className={`px-3 py-1.5 font-mono whitespace-nowrap max-w-[260px] truncate transition-colors ${
                                      dirty ? 'bg-warn/15 text-warn font-medium' : 'text-text-pri'
                                    }`}
                                  >
                                    {isEditing ? (
                                      <input
                                        autoFocus
                                        type="text"
                                        aria-label={`Inline edit ${col} row ${idx + 1}`}
                                        value={formatEditableCellValue(effectiveVal)}
                                        placeholder="NULL"
                                        onClick={(e) => e.stopPropagation()}
                                        onChange={(e) => stageCellEdit(entry.origIdx, col, e.target.value, baseVal)}
                                        onBlur={() => setEditingCell(null)}
                                        onKeyDown={(e) => {
                                          if (e.key === 'Enter') {
                                            e.preventDefault();
                                            setEditingCell(null);
                                          } else if (e.key === 'Escape') {
                                            e.preventDefault();
                                            stageCellEdit(entry.origIdx, col, formatEditableCellValue(baseVal), baseVal);
                                            setEditingCell(null);
                                          }
                                        }}
                                        className="w-full min-w-[90px] rounded border border-accent bg-bg px-1.5 py-0.5 font-mono text-[12px] text-text-pri focus:outline-none"
                                      />
                                    ) : (
                                      <span className="block truncate">{displayVal}</span>
                                    )}
                                  </td>
                                );
                              })}
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}

            {resultTab === 'explain' && (
              <div className="rounded-[var(--radius-lg)] border border-border bg-surface p-4 space-y-3 font-mono text-[12px]">
                <div className="flex items-center justify-between border-b border-border pb-2">
                  <span className="font-semibold text-text-pri">
                    Execution Plan ({activeConnection ? ENGINE_META[activeConnection.engine].label : 'SQL Engine'})
                  </span>
                  <span className="text-accent">Total estimated cost: 0.43..18.92</span>
                </div>
                <div className="space-y-2 text-text-sec">
                  <div className="rounded border border-border bg-elev px-3 py-2">
                    <span className="text-accent font-semibold">Limit</span> (cost=0.43..14.12 rows={Math.max(1, filteredAndSortedRows.length)} width=96)
                  </div>
                  <div className="ml-6 rounded border border-border bg-elev/70 px-3 py-2">
                    <span className="text-info font-semibold">Sort</span> (Key: primary sort expression · Method: quicksort Memory: 25kB)
                  </div>
                  <div className="ml-12 rounded border border-border bg-elev/40 px-3 py-2">
                    <span className="text-success font-semibold">Index Scan</span> on {inspectorTable ? `${inspectorTable.schema}.${inspectorTable.name}` : 'table'} (actual time=0.028..{Math.max(0.4, lastResult.durationMs / 10).toFixed(2)} ms rows={filteredAndSortedRows.length} loops=1)
                  </div>
                </div>
              </div>
            )}

            {resultTab === 'history' && (
              <div className="space-y-2">
                {history.map((item) => (
                  <div
                    key={item.id}
                    className="rounded-[var(--radius)] border border-border bg-surface p-3 flex items-start justify-between gap-3"
                  >
                    <div className="min-w-0 flex-1 space-y-1">
                      <div className="flex items-center gap-2 text-[11px]">
                        <Clock size={11} className="text-text-dim" />
                        <span className="text-text-sec font-medium">{item.connectionName}</span>
                        <span className="text-text-dim">{item.executedAt}</span>
                        <Badge variant={item.status === 'ok' ? 'success' : item.status === 'blocked' ? 'warn' : 'danger'}>
                          {item.status === 'ok' ? `${item.rowsReturned} rows · ${item.durationMs}ms` : item.status}
                        </Badge>
                      </div>
                      <pre className="font-mono text-[11px] text-text-pri whitespace-pre-wrap break-all">{item.sql}</pre>
                    </div>
                    <Button
                      type="button"
                      variant="outline"
                      size="xs"
                      onClick={() => updateWorksheet({ sql: item.sql })}
                    >
                      Load SQL
                    </Button>
                  </div>
                ))}
              </div>
            )}

            {resultTab === 'schema' && inspectorTable && (
              <div className="rounded-[var(--radius)] border border-border bg-surface overflow-x-auto">
                <table className="w-full text-[12px]">
                  <thead className="bg-elev border-b border-border text-[11px] uppercase tracking-wider text-text-dim">
                    <tr>
                      <th className="px-3 py-2 text-left font-medium">Column</th>
                      <th className="px-3 py-2 text-left font-medium">Type</th>
                      <th className="px-3 py-2 text-left font-medium">Constraint</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/70">
                    {inspectorTable.columns.map((c) => (
                      <tr key={c.name}>
                        <td className="px-3 py-2 font-mono text-text-pri">{c.name}</td>
                        <td className="px-3 py-2 font-mono text-text-sec">{c.type}</td>
                        <td className="px-3 py-2">
                          {c.pk ? <Badge variant="warn">PRIMARY KEY</Badge> : <span className="text-text-dim">—</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Right Pane: Row & JSON Inspector */}
      {showInspector && (
        <aside
          aria-label="Row inspector"
          className="w-[300px] shrink-0 border-l border-border bg-surface flex flex-col min-h-0"
        >
          <div className="h-10 px-3 border-b border-border flex items-center justify-between gap-2 shrink-0">
            <span className="text-[12px] font-semibold text-text-pri">Row Inspector</span>
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={handleRefreshResults}
                aria-label="Refresh inspector grid"
                title="Refresh query results"
                className="h-6 w-6 inline-flex items-center justify-center rounded text-text-dim hover:text-text-pri hover:bg-elev cursor-pointer"
              >
                <RefreshCw size={12} />
              </button>
              {selectedRow && (
                <Button
                  type="button"
                  variant="ghost"
                  size="xs"
                  icon={<Copy size={11} />}
                  onClick={() => void handleCopyText(JSON.stringify(selectedRow, null, 2), 'Row JSON')}
                >
                  JSON
                </Button>
              )}
              <button
                type="button"
                onClick={() => setShowInspector(false)}
                aria-label="Hide row inspector"
                className="h-6 w-6 inline-flex items-center justify-center rounded text-text-dim hover:text-text-pri hover:bg-elev cursor-pointer"
              >
                <PanelRightClose size={13} />
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-3 space-y-2.5 text-[12px]">
            {!selectedRow || !selectedEntry ? (
              <p className="text-text-dim text-center py-6">Select a result row to inspect and edit its fields or JSON payload.</p>
            ) : (
              <>
                <div className="space-y-1.5">
                  {lastResult.columns.map((col) => {
                    const baseVal = selectedEntry.row[col];
                    const effectiveVal = getEffectiveValue(pendingEdits, selectedEntry.origIdx, col, baseVal);
                    const dirty = selectedEntry.isNew || isCellDirty(pendingEdits, selectedEntry.origIdx, col, baseVal);
                    const copyVal = formatCellValue(effectiveVal);
                    return (
                      <div
                        key={col}
                        className={`rounded-[var(--radius-sm)] border px-2.5 py-1.5 transition-colors ${
                          dirty ? 'border-warn/50 bg-warn/10' : 'border-border/70 bg-elev/50'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 mb-1">
                          <label
                            htmlFor={`inspector-field-${col}`}
                            className="text-[10px] font-semibold uppercase tracking-wider text-text-dim font-mono flex items-center gap-1.5"
                          >
                            <span>{col}</span>
                            {dirty && <span className="text-warn lowercase font-normal">modified</span>}
                          </label>
                          <button
                            type="button"
                            onClick={() => void handleCopyText(copyVal, col)}
                            aria-label={`Copy ${col}`}
                            className="text-text-dim hover:text-accent cursor-pointer"
                          >
                            <Copy size={10} />
                          </button>
                        </div>
                        <input
                          id={`inspector-field-${col}`}
                          type="text"
                          aria-label={`Edit ${col}`}
                          value={formatEditableCellValue(effectiveVal)}
                          placeholder="NULL"
                          onChange={(e) => stageCellEdit(selectedEntry.origIdx, col, e.target.value, baseVal)}
                          className="w-full rounded border border-border bg-bg px-2 py-1 font-mono text-[12px] text-text-pri focus:border-accent focus:outline-none"
                        />
                      </div>
                    );
                  })}
                </div>
                <div className="rounded-[var(--radius-sm)] border border-border bg-[var(--canvas,var(--bg))] p-2.5">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-text-dim mb-1.5">Raw JSON</div>
                  <pre className="font-mono text-[11px] text-text-sec whitespace-pre-wrap break-all">
                    {JSON.stringify(selectedRow, null, 2)}
                  </pre>
                </div>
              </>
            )}
          </div>

          {selectedEntry && (
            <div className="px-3 py-2 border-t border-border bg-elev/40 flex items-center justify-between gap-2 shrink-0">
              <span className="text-[11px] text-text-dim">
                {dirtyChangeCount > 0 ? `${dirtyChangeCount} pending edit${dirtyChangeCount === 1 ? '' : 's'}` : 'No unsaved edits'}
              </span>
              <div className="flex items-center gap-1.5">
                <Button
                  type="button"
                  variant="outline"
                  size="xs"
                  icon={<RotateCcw size={11} />}
                  disabled={dirtyChangeCount === 0}
                  onClick={handleCancelEdits}
                  aria-label="Cancel inspector edits"
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant={dirtyChangeCount > 0 ? 'primary' : 'outline'}
                  size="xs"
                  icon={<Check size={11} />}
                  disabled={dirtyChangeCount === 0 || isSavingEdits}
                  onClick={() => void handleSaveEdits()}
                  aria-label="Save inspector edits"
                >
                  Save
                </Button>
              </div>
            </div>
          )}
        </aside>
      )}

      {/* Add / Edit Connection Modal */}
      <Dialog
        open={newConnOpen}
        onOpenChange={(open) => {
          setNewConnOpen(open);
          if (!open) {
            setEditingConnId(null);
            setNewPassword('');
            setTestConnState({ status: 'idle' });
          }
        }}
        title={editingConnId ? 'Edit Database Connection' : 'Add Database Connection'}
        description="Configure host, database, user credentials, and SSL settings for your database connection."
        size="md"
        footer={
          <>
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={testConnState.status === 'testing'}
              icon={testConnState.status === 'testing' ? <Loader2 size={12} className="animate-spin" /> : <Plug size={12} />}
              onClick={() => void handleTestConnection()}
            >
              Test Connection
            </Button>
            <div className="flex-1" />
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                setNewConnOpen(false);
                setEditingConnId(null);
                setNewPassword('');
                setTestConnState({ status: 'idle' });
              }}
            >
              Cancel
            </Button>
            <Button type="button" variant="primary" size="sm" onClick={handleSaveConnection}>
              {editingConnId ? 'Save & Reconnect' : 'Save Connection'}
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-sm">
          <div>
            <label htmlFor="db-conn-name" className="block text-xs font-medium text-text-sec mb-1">
              Connection label
            </label>
            <Input
              id="db-conn-name"
              placeholder="e.g. billing-read-replica"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label htmlFor="db-conn-engine" className="block text-xs font-medium text-text-sec mb-1">
                Engine
              </label>
              <Select
                id="db-conn-engine"
                value={newEngine}
                onChange={(e) => {
                  const eng = e.target.value as DbEngine;
                  setNewEngine(eng);
                  setNewPort(String(ENGINE_META[eng].defaultPort));
                  if (eng === 'duckdb') {
                    if (!newHost || newHost === 'localhost') setNewHost('embedded');
                    if (!newDatabase || newDatabase === 'app_db') setNewDatabase('analytics');
                    setNewUser('');
                  } else if (eng === 'clickhouse') {
                    if (newHost === 'embedded') setNewHost('localhost');
                    if (!newDatabase || newDatabase === 'app_db') setNewDatabase('default');
                    if (!newUser || newUser === 'postgres') setNewUser('default');
                  } else if (eng === 'mysql') {
                    if (newHost === 'embedded') setNewHost('localhost');
                    if (!newUser || newUser === 'postgres') setNewUser('root');
                  } else if (eng === 'redis') {
                    if (newHost === 'embedded') setNewHost('localhost');
                    setNewDatabase('0');
                    setNewUser('');
                  } else {
                    if (newHost === 'embedded') setNewHost('localhost');
                    if (!newUser) setNewUser('postgres');
                  }
                }}
              >
                <option value="postgres">PostgreSQL</option>
                <option value="clickhouse">ClickHouse</option>
                <option value="duckdb">DuckDB (Embedded / HTTP)</option>
                <option value="mysql">MySQL</option>
                <option value="redis">Redis</option>
              </Select>
            </div>
            <div>
              <label htmlFor="db-conn-port" className="block text-xs font-medium text-text-sec mb-1">
                Port
              </label>
              <Input id="db-conn-port" value={newPort} onChange={(e) => setNewPort(e.target.value)} />
            </div>
          </div>
          <div>
            <label htmlFor="db-conn-host" className="block text-xs font-medium text-text-sec mb-1">
              Hostname / Endpoint
            </label>
            <Input
              id="db-conn-host"
              placeholder="db-cluster.internal.us-east-1.rds"
              value={newHost}
              onChange={(e) => setNewHost(e.target.value)}
            />
          </div>
          <div>
            <label htmlFor="db-conn-db" className="block text-xs font-medium text-text-sec mb-1">
              Database
            </label>
            <Input id="db-conn-db" placeholder="orders_prod" value={newDatabase} onChange={(e) => setNewDatabase(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label htmlFor="db-conn-user" className="block text-xs font-medium text-text-sec mb-1">
                Username
              </label>
              <Input id="db-conn-user" placeholder="postgres" value={newUser} onChange={(e) => setNewUser(e.target.value)} />
            </div>
            <div>
              <label htmlFor="db-conn-password" className="block text-xs font-medium text-text-sec mb-1">
                Password
              </label>
              <Input
                id="db-conn-password"
                type="password"
                autoComplete="new-password"
                placeholder="Enter password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label htmlFor="db-conn-ssl" className="block text-xs font-medium text-text-sec mb-1">
                Use SSL
              </label>
              <Select
                id="db-conn-ssl"
                value={newSslEnabled}
                onChange={(e) => {
                  const next = e.target.value as 'true' | 'false';
                  setNewSslEnabled(next);
                  if (next === 'false') {
                    setNewSslMode('disable');
                  } else if (newSslMode === 'disable') {
                    setNewSslMode('require');
                  }
                }}
              >
                <option value="true">true</option>
                <option value="false">false</option>
              </Select>
            </div>
            <div>
              <label htmlFor="db-conn-ssl-mode" className="block text-xs font-medium text-text-sec mb-1">
                SSL Mode
              </label>
              <Select
                id="db-conn-ssl-mode"
                value={newSslEnabled === 'false' ? 'disable' : newSslMode}
                disabled={newSslEnabled === 'false'}
                onChange={(e) => setNewSslMode(e.target.value)}
              >
                <option value="require">require</option>
                <option value="verify-ca">verify-ca</option>
                <option value="verify-full">verify-full</option>
                <option value="prefer">prefer</option>
                <option value="allow">allow</option>
                <option value="disable">disable</option>
              </Select>
            </div>
          </div>
          {testConnState.status !== 'idle' && (
            <div
              role="status"
              className={`rounded-[var(--radius)] border px-3 py-2 text-xs flex items-center gap-2 ${
                testConnState.status === 'ok'
                  ? 'border-success/40 bg-success/10 text-success'
                  : testConnState.status === 'error'
                    ? 'border-danger/40 bg-danger/10 text-danger'
                    : 'border-border bg-elev text-text-sec'
              }`}
            >
              {testConnState.status === 'ok' && <Check size={14} className="shrink-0" aria-hidden="true" />}
              {testConnState.status === 'error' && <AlertCircle size={14} className="shrink-0" aria-hidden="true" />}
              {testConnState.status === 'testing' && <Loader2 size={14} className="animate-spin shrink-0" aria-hidden="true" />}
              <span>{testConnState.message}</span>
            </div>
          )}
        </div>
      </Dialog>
    </div>
  );
}
