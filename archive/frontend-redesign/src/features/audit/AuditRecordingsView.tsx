import { useCallback, useEffect, useState } from 'react';
import { Download, FileVideo, Play, RefreshCw, ShieldCheck } from 'lucide-react';
import { Badge, Button, Card } from '@/design-system/primitives';
import {
  fetchAuditEvents,
  fetchRecordings,
  type AuditEvent,
  type RecordingEntry,
} from '../sessions/launchApi';
import { GuacRecordingPlayer } from './GuacRecordingPlayer';

export function AuditRecordingsView() {
  const [recordings, setRecordings] = useState<RecordingEntry[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [playingId, setPlayingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const [recs, evs] = await Promise.all([fetchRecordings(), fetchAuditEvents()]);
      setRecordings(recs);
      setEvents(evs);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Unable to load audit records');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  return (
    <div className="max-w-6xl mx-auto px-6 py-6 space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h1 className="text-[20px] font-semibold text-text-pri tracking-[-0.02em]">
            Fail-Closed Session Recordings &amp; Audit Ledger
          </h1>
          <p className="mt-1 text-xs text-text-mut">
            SHA-256 tamper-evident Guacamole captures with pure-Rust ISO-BMFF MP4 container export and OpenTelemetry trace linkage.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <a
            href="/api/audit/export?format=csv"
            download="operquay-audit.csv"
            className="h-8 px-3 rounded-[var(--radius-sm)] border border-border bg-surface text-xs font-medium text-text-pri hover:bg-surface-hover inline-flex items-center gap-1.5"
          >
            <Download size={13} aria-hidden="true" />
            Export CSV
          </a>
          <a
            href="/api/audit/export?format=json"
            download="operquay-audit.json"
            className="h-8 px-3 rounded-[var(--radius-sm)] border border-border bg-surface text-xs font-medium text-text-pri hover:bg-surface-hover inline-flex items-center gap-1.5"
          >
            <Download size={13} aria-hidden="true" />
            Export JSON
          </a>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void reload()}
            loading={loading}
            icon={<RefreshCw size={14} aria-hidden="true" />}
          >
            Refresh Ledger
          </Button>
        </div>
      </div>

      {errorMsg && (
        <div
          role="alert"
          className="px-4 py-3 rounded-[var(--radius-md)] border border-border bg-[var(--danger-dim)] text-xs text-danger"
        >
          {errorMsg}
        </div>
      )}

      {playingId && (
        <GuacRecordingPlayer recordingId={playingId} onClose={() => setPlayingId(null)} />
      )}

      <Card className="p-5 space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <FileVideo size={16} className="text-accent" aria-hidden="true" />
            <h2 className="text-[15px] font-semibold text-text-pri">Recorded Sessions</h2>
          </div>
          <Badge tone="neutral">{recordings.length} total</Badge>
        </div>

        {recordings.length === 0 ? (
          <p className="text-xs text-text-dim py-4">
            No closed or active session recordings yet. Connect an RDP or VNC session to capture fail-closed frames.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-border text-text-dim">
                  <th className="py-2 pr-3 font-medium">Session</th>
                  <th className="py-2 pr-3 font-medium">Target</th>
                  <th className="py-2 pr-3 font-medium">Metrics</th>
                  <th className="py-2 pr-3 font-medium">SHA-256 Digest</th>
                  <th className="py-2 pr-3 font-medium">Policy</th>
                  <th className="py-2 font-medium text-right">Artifacts</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {recordings.map((rec) => (
                  <tr key={rec.id} className="hover:bg-[var(--surface-hover)]/40">
                    <td className="py-2.5 pr-3 tabular-mono text-text-pri">
                      <div>{rec.id.slice(0, 8)}...</div>
                      <div className="text-[11px] text-text-dim uppercase">{rec.protocol}</div>
                    </td>
                    <td className="py-2.5 pr-3 text-text-pri">{rec.target_host || 'demo'}</td>
                    <td className="py-2.5 pr-3 tabular-mono text-text-mut">
                      {rec.frame_count} frames · {rec.bytes_written} B
                    </td>
                    <td className="py-2.5 pr-3 tabular-mono text-text-dim">
                      {rec.sha256_hex ? `${rec.sha256_hex.slice(0, 16)}...` : 'active'}
                    </td>
                    <td className="py-2.5 pr-3">
                      <Badge tone={rec.status === 'completed' ? 'success' : 'warn'}>
                        {rec.fail_closed ? 'fail-closed' : 'best-effort'} · {rec.status}
                      </Badge>
                    </td>
                    <td className="py-2.5 text-right whitespace-nowrap space-x-2">
                      <button
                        type="button"
                        onClick={() => setPlayingId(rec.id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri hover:bg-[var(--surface-hover)]"
                      >
                        <Play size={12} aria-hidden="true" />
                        Replay
                      </button>
                      <a
                        href={`/api/v1/recordings/${encodeURIComponent(rec.id)}/guac`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri hover:bg-[var(--surface-hover)]"
                      >
                        <Download size={12} aria-hidden="true" />
                        .guac
                      </a>
                      <a
                        href={`/api/v1/recordings/${encodeURIComponent(rec.id)}/export-mp4`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-[var(--radius-sm)] border border-[var(--accent-border)] bg-[var(--accent-dim)] text-accent hover:opacity-90"
                      >
                        <Download size={12} aria-hidden="true" />
                        Export MP4
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card className="p-5 space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ShieldCheck size={16} className="text-accent" aria-hidden="true" />
            <h2 className="text-[15px] font-semibold text-text-pri">Trace-Linked Audit Log</h2>
          </div>
          <Badge tone="neutral">{events.length} events</Badge>
        </div>

        {events.length === 0 ? (
          <p className="text-xs text-text-dim py-4">No audit events captured yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-border text-text-dim">
                  <th className="py-2 pr-3 font-medium">Action</th>
                  <th className="py-2 pr-3 font-medium">Target</th>
                  <th className="py-2 pr-3 font-medium">Detail</th>
                  <th className="py-2 font-medium text-right">OTel Trace</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {events.slice(0, 25).map((ev) => (
                  <tr key={ev.id}>
                    <td className="py-2 pr-3 font-medium text-text-pri">
                      <Badge tone={ev.action.includes('abort') || ev.action.includes('error') ? 'danger' : 'info'}>
                        {ev.action}
                      </Badge>
                    </td>
                    <td className="py-2 pr-3 text-text-mut">
                      {ev.protocol.toUpperCase()} · {ev.target_host}
                    </td>
                    <td className="py-2 pr-3 text-text-dim">{ev.detail}</td>
                    <td className="py-2 text-right tabular-mono text-text-dim">
                      {ev.trace_id.slice(0, 16)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
