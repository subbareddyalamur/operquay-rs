import { useState } from 'react';
import { Button, Input } from '@/components/primitives';
import { api } from '@/lib/api';
import { canSendCredentials } from '@/lib/credentialTransport';
import { useAuthStore } from '@/stores/auth';

export function OwnPasswordForm() {
  const me = useAuthStore(s => s.me);
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  if (!me || me.method === 'sso') return null;
  const submit = async () => {
    setError('');
    if (!canSendCredentials('/api/auth/password')) { setError('HTTPS is required to change the password.'); return; }
    setBusy(true);
    const result = await api.post('/api/auth/password', { current_password: current, new_password: next });
    setBusy(false);
    if (!result.ok) {
      setError(result.error.status === 401 ? 'Current password was not accepted.' : result.error.status === 400 ? 'Password must be between 12 and 72 bytes.' : result.error.status === 429 ? 'Too many attempts. Try again later.' : 'Could not change the password.');
      return;
    }
    setCurrent(''); setNext(''); setConfirm('');
    useAuthStore.setState({ me: null, expired: true, signInOpen: true });
  };
  return (
    <form
      className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs"
      onSubmit={e => { e.preventDefault(); void submit(); }}
    >
      <div className="px-5 py-4 border-b border-border flex items-start justify-between gap-4">
        <div>
          <h3 className="text-[14px] font-semibold text-text-pri">Change password</h3>
          <p className="text-[13px] text-text-mut mt-0.5">
            Changing your password signs out existing password sessions.
          </p>
        </div>
      </div>
      <div className="px-5 py-4 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
            <span>Current password</span>
            <Input
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={e => setCurrent(e.target.value)}
            />
          </label>
          <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
            <span>New password</span>
            <Input
              type="password"
              autoComplete="new-password"
              value={next}
              onChange={e => setNext(e.target.value)}
            />
          </label>
          <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
            <span>Confirm new password</span>
            <Input
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={e => setConfirm(e.target.value)}
            />
          </label>
        </div>
        {next && confirm && next !== confirm && (
          <p className="text-[12px] text-danger">New password and confirmation do not match.</p>
        )}
        {error && <p role="alert" className="text-[12px] text-danger">{error}</p>}
      </div>
      <div className="px-5 py-3 bg-bg/60 border-t border-border flex items-center justify-between gap-3">
        <span className="text-[12px] text-text-dim">Minimum 12 characters required.</span>
        <Button
          type="submit"
          variant="primary"
          size="sm"
          loading={busy}
          disabled={busy || !current || !next || next !== confirm}
        >
          Change password
        </Button>
      </div>
    </form>
  );
}
