import { useState } from 'react';
import { Database, Lock, Play, ShieldAlert } from 'lucide-react';
import { Badge, Button, Card } from '@/design-system/primitives';
import { apiJson } from '../platform/api';

export function DatabaseExplorerWorkspace() {
  const [host, setHost] = useState('127.0.0.1');
  const [port, setPort] = useState(5432);
  const [database, setDatabase] = useState('operquay');
  const [username, setUsername] = useState('operquay');
  const [password, setPassword] = useState('');
  const [sslMode, setSslMode] = useState('require');
  const [connId, setConnId] = useState('');
  const [tables, setTables] = useState<Array<{ name: string; schema: string; sizePretty: string }>>([]);
  const [sql, setSql] = useState('SELECT id, email, role FROM users LIMIT 25;');
  const [allowMutate, setAllowMutate] = useState(false);
  const [resultRows, setResultRows] = useState<Array<Record<string, unknown>>>([]);
  const [buckets, setBuckets] = useState<Record<string, Record<string, string>> | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const connectPg = async () => {
    setErr(null);
    try {
      const res = await apiJson<{ connection_id: string; tables: typeof tables }>('/api/db/connect', {
        method: 'POST',
        body: JSON.stringify({ engine: 'postgres', host, port: Number(port), database, username, password, ssl_mode: sslMode }),
      });
      setConnId(res.connection_id);
      setTables(res.tables);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'PostgreSQL connection failed');
    }
  };

  const runSql = async () => {
    setErr(null);
    try {
      const endpoint = allowMutate ? '/api/db/mutate' : '/api/db/query';
      const res = await apiJson<{ rows: Array<Record<string, unknown>> }>(endpoint, {
        method: 'POST',
        body: JSON.stringify({ connection_id: connId, sql }),
      });
      setResultRows(res.rows ?? []);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'SQL execution rejected');
    }
  };

  const loadSuggestDb = async () => {
    const res = await apiJson<{ buckets: Record<string, Record<string, string>> }>('/db-viewer');
    setBuckets(res.buckets);
  };

  return (
    <div className="max-w-6xl mx-auto px-6 py-6 space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-4">
        <div>
          <h1 className="text-[20px] font-semibold text-text-pri tracking-[-0.02em]">
            TLS PostgreSQL Explorer &amp; Suggest Bucket Inspector
          </h1>
          <p className="mt-1 text-xs text-text-mut">
            Default `sslmode=require` Postgres workspace with read-only SQL guardrail and AES-256-GCM Suggest bucket browser.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void loadSuggestDb()}>
          Inspect Suggest Buckets (`/db-viewer`)
        </Button>
      </div>

      {err && (
        <div role="alert" className="px-4 py-2.5 rounded-[var(--radius-sm)] border border-border bg-[var(--danger-dim)] text-xs text-danger">
          {err}
        </div>
      )}

      <Card className="p-4 grid grid-cols-2 md:grid-cols-7 gap-2 text-xs items-end">
        <div>
          <label htmlFor="db-host" className="block text-[11px] text-text-dim mb-1">Host</label>
          <input id="db-host" value={host} onChange={(e) => setHost(e.target.value)} className="w-full h-8 px-2 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri" />
        </div>
        <div>
          <label htmlFor="db-port" className="block text-[11px] text-text-dim mb-1">Port</label>
          <input id="db-port" type="number" value={port} onChange={(e) => setPort(Number(e.target.value))} className="w-full h-8 px-2 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri" />
        </div>
        <div>
          <label htmlFor="db-name" className="block text-[11px] text-text-dim mb-1">Database</label>
          <input id="db-name" value={database} onChange={(e) => setDatabase(e.target.value)} className="w-full h-8 px-2 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri" />
        </div>
        <div>
          <label htmlFor="db-user" className="block text-[11px] text-text-dim mb-1">User</label>
          <input id="db-user" value={username} onChange={(e) => setUsername(e.target.value)} className="w-full h-8 px-2 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri" />
        </div>
        <div>
          <label htmlFor="db-pw" className="block text-[11px] text-text-dim mb-1">Password</label>
          <input id="db-pw" type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="w-full h-8 px-2 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri" />
        </div>
        <div>
          <label htmlFor="db-ssl" className="block text-[11px] text-text-dim mb-1">SSL Mode</label>
          <select id="db-ssl" value={sslMode} onChange={(e) => setSslMode(e.target.value)} className="w-full h-8 px-2 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri">
            <option value="require">require</option>
            <option value="verify-full">verify-full</option>
            <option value="disable">disable</option>
          </select>
        </div>
        <Button size="sm" onClick={() => void connectPg()} icon={<Lock size={12} aria-hidden="true" />}>Connect</Button>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 text-xs">
        <Card className="lg:col-span-4 p-4 space-y-2">
          <div className="flex items-center gap-2 font-semibold text-text-pri">
            <Database size={14} className="text-accent" aria-hidden="true" />
            Tables ({tables.length})
          </div>
          {tables.map((t) => (
            <div key={`${t.schema}.${t.name}`} className="py-1.5 border-b border-border flex justify-between">
              <span className="font-mono text-text-pri">{t.schema}.{t.name}</span>
              <span className="text-text-dim">{t.sizePretty}</span>
            </div>
          ))}
        </Card>

        <Card className="lg:col-span-8 p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <label htmlFor="sql-editor" className="font-semibold text-text-pri">SQL Console</label>
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-1.5 text-text-mut cursor-pointer">
                <input type="checkbox" checked={allowMutate} onChange={(e) => setAllowMutate(e.target.checked)} />
                <ShieldAlert size={12} className="text-warn" aria-hidden="true" />
                Enable Write (`/api/db/mutate`)
              </label>
              <Button size="xs" disabled={!connId} onClick={() => void runSql()} icon={<Play size={11} aria-hidden="true" />}>
                Run SQL
              </Button>
            </div>
          </div>
          <textarea
            id="sql-editor"
            rows={4}
            value={sql}
            onChange={(e) => setSql(e.target.value)}
            className="w-full p-2.5 rounded-[var(--radius-sm)] border border-border bg-elev font-mono text-text-pri"
          />
          {resultRows.length > 0 && (
            <pre className="p-3 rounded-[var(--radius-sm)] bg-elev border border-border overflow-x-auto text-[11px] font-mono text-text-mut">
              {JSON.stringify(resultRows, null, 2)}
            </pre>
          )}
        </Card>
      </div>

      {buckets && (
        <Card className="p-4 space-y-2 text-xs">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-text-pri">Suggest AES-256-GCM Decrypted Buckets</span>
            <Badge tone="accent">{Object.keys(buckets).length} buckets</Badge>
          </div>
          <pre className="p-3 rounded-[var(--radius-sm)] bg-elev border border-border overflow-x-auto text-[11px] font-mono text-text-mut">
            {JSON.stringify(buckets, null, 2)}
          </pre>
        </Card>
      )}
    </div>
  );
}

