export type LaunchMode = 'demo' | 'direct_tcp' | 'ssm_tunnel';

export interface LaunchSessionPayload {
  protocol: 'rdp' | 'vnc';
  launch_mode: LaunchMode;
  target_host?: string;
  target_port?: number;
  username?: string;
  password?: string;
  width?: number;
  height?: number;
  keyboard_layout?: string;
  transport_mode?: string;
  expected_cert_sha256_hex?: string;
}

export interface LaunchSessionResponse {
  ticket: string;
  session_id: string;
  ws_url: string;
  protocol: 'rdp' | 'vnc';
  launch_mode: LaunchMode;
  expires_in_secs: number;
  trace_id: string;
}

export interface RecordingEntry {
  id: string;
  tenant_id: string;
  protocol: string;
  target_host: string;
  format: string;
  started_at_ms: number;
  bytes_written: number;
  frame_count: number;
  sha256_hex: string;
  fail_closed: boolean;
  status: string;
}

export interface AuditEvent {
  id: string;
  ts_ms: number;
  tenant_id: string;
  trace_id: string;
  session_id: string;
  action: string;
  protocol: string;
  target_host: string;
  detail: string;
  recording_id: string | null;
}

export async function issueSessionTicket(
  payload: LaunchSessionPayload,
): Promise<LaunchSessionResponse> {
  const res = await fetch('/api/v1/sessions/launch', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const body = (await res.json()) as LaunchSessionResponse & { error?: string };
  if (!res.ok) {
    throw new Error(body.error ?? `Launch ticket rejected (HTTP ${res.status})`);
  }
  return body;
}

export async function fetchRecordings(): Promise<RecordingEntry[]> {
  const res = await fetch('/api/v1/recordings');
  if (!res.ok) {
    throw new Error(`Failed to fetch recordings (HTTP ${res.status})`);
  }
  const body = (await res.json()) as { recordings: RecordingEntry[] };
  return body.recordings;
}

export async function fetchAuditEvents(): Promise<AuditEvent[]> {
  const res = await fetch('/api/v1/audit');
  if (!res.ok) {
    throw new Error(`Failed to fetch audit log (HTTP ${res.status})`);
  }
  const body = (await res.json()) as { events: AuditEvent[] };
  return body.events;
}

