import { useEffect, useState, type ReactNode } from 'react';
import { useAuthStore } from '@/stores/auth';
import { OperquayMark } from '@/components/brand/OperquayMark';
import { Button } from '@/components/primitives';
import { OwnPasswordForm } from '@/components/settings/OwnPasswordForm';

function readAuthError(): string | null {
  const params = new URLSearchParams(window.location.search);
  const err = params.get('auth_error');
  if (err) {
    params.delete('auth_error');
    const q = params.toString();
    window.history.replaceState(null, '', window.location.pathname + (q ? `?${q}` : ''));
  }
  return err;
}

/** Full-page sign-in. SSO is the main path; a password form serves local or break-glass accounts. */
export function SignInPage({ onClose }: { onClose?: () => void }) {
  const config = useAuthStore((s) => s.config);
  const expired = useAuthStore((s) => s.expired);
  const signIn = useAuthStore((s) => s.signIn);
  const mfaChallenge = useAuthStore((s) => s.mfaChallenge);
  const completeMfaLogin = useAuthStore((s) => s.completeMfaLogin);
  const clearMfaChallenge = useAuthStore((s) => s.clearMfaChallenge);
  const [error, setError] = useState<string | null>(null);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [showLocal, setShowLocal] = useState(false);

  useEffect(() => {
    const err = readAuthError();
    if (err) setError(err);
  }, []);

  const providers = config?.sso.providers ?? [];
  const version = config?.version || 'unknown';
  const revision = config?.revision?.match(/^([a-f0-9]{7,})(-dirty)?$/i);
  const ssoOn = providers.length > 0;
  const local = config?.local ?? 'all';
  const localVisible = local !== 'off' && (!ssoOn || showLocal);
  const routable = providers.some((p) => (p.domains ?? []).length > 0);
  const [workEmail, setWorkEmail] = useState('');

  const startSSO = (id: string) => {
    window.location.assign(`/api/auth/sso/${encodeURIComponent(id)}/start`);
  };

  const routeByEmail = () => {
    const domain = workEmail.trim().toLowerCase().split('@')[1] ?? '';
    const match = providers.find((p) => (p.domains ?? []).some((d) => d.replace(/^@/, '').toLowerCase() === domain));
    if (match) {
      startSSO(match.id);
    } else {
      setError(domain ? `No sign-in provider is set up for ${domain}. Choose one below or ask your administrator.` : 'Enter your work email.');
    }
  };

  const submit = async () => {
    setBusy(true);
    setError(null);
    const err = await signIn(email, password);
    setBusy(false);
    if (err) setError(err);
  };

  const submitMfa = async () => {
    setBusy(true);
    setError(null);
    const err = await completeMfaLogin(mfaCode, useRecovery);
    setBusy(false);
    if (err) setError(err);
  };

  const field = 'w-full h-10 px-3 rounded-md bg-bg border border-border text-[14px] text-text-pri placeholder:text-text-dim hover:border-text-dim focus:outline-none focus:border-accent focus:ring-2 focus:ring-[var(--accent-dim)]';

  if (mfaChallenge) {
    return (
      <div className="fixed inset-0 z-[9500] bg-bg flex overflow-y-auto p-6">
        <div className="m-auto w-full max-w-[400px] space-y-6">
          <div className="flex items-center gap-2.5">
            <OperquayMark size={26} />
            <span className="text-[19px] font-semibold text-text-pri">Operquay</span>
          </div>
          <div className="bg-surface border border-border rounded-[var(--radius-lg)] shadow-[var(--shadow-sm)] p-7 space-y-5">
            <div className="space-y-1">
              <h1 className="text-[20px] font-semibold text-text-pri">Two-factor verification</h1>
              <p className="text-[13px] text-text-mut">
                Enter the verification code for <span className="text-text-pri font-medium">{mfaChallenge.email}</span>.
              </p>
            </div>
            {error && <p role="alert" className="text-[13px] text-danger bg-[color-mix(in_srgb,var(--danger)_10%,transparent)] border border-danger/30 rounded-md px-3 py-2 leading-relaxed">{error}</p>}
            <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); void submitMfa(); }}>
              <label className="block space-y-1">
                <span className="text-[13px] font-medium text-text-pri">
                  {useRecovery ? 'Recovery code' : 'Authenticator code'}
                </span>
                <input
                  className={`${field} font-mono`}
                  inputMode={useRecovery ? 'text' : 'numeric'}
                  autoComplete="one-time-code"
                  autoFocus
                  placeholder={useRecovery ? 'XXXX-XXXX' : '000000'}
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                />
              </label>
              <Button type="submit" size="lg" fullWidth disabled={busy || !mfaCode.trim()} loading={busy}>
                {busy ? 'Verifying…' : 'Verify code'}
              </Button>
            </form>
            <div className="flex items-center justify-between text-[13px]">
              <button
                type="button"
                onClick={() => { setUseRecovery((v) => !v); setMfaCode(''); setError(null); }}
                className="text-accent hover:underline"
              >
                {useRecovery ? 'Use authenticator code instead' : 'Use a recovery code'}
              </button>
              <button
                type="button"
                onClick={() => { clearMfaChallenge(); setMfaCode(''); setError(null); }}
                className="text-text-mut hover:text-text-pri"
              >
                Back to sign in
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  let body: ReactNode = null;
  if (localVisible) {
    body = (
      <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); void submit(); }}>
        {ssoOn && (
          <p className="text-[13px] text-warn bg-warn-ink border border-warn/30 rounded-md px-3 py-2 leading-relaxed">
            {local === 'all' ? 'Local password sign-in is enabled.' : config?.local_user_opt_in_allowed ? 'Local administrators and accounts explicitly enabled by an administrator can sign in here.' : 'Only local administrators can sign in here under the current deployment policy.'}
          </p>
        )}
        <label className="block space-y-1">
          <span className="text-[13px] font-medium text-text-pri">Email</span>
          <input className={field} autoComplete="username" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label className="block space-y-1">
          <span className="text-[13px] font-medium text-text-pri">Password</span>
          <input className={field} type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <Button type="submit" size="lg" fullWidth disabled={busy || !email || !password} loading={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </Button>
      </form>
    );
  }

  return (
    <div className="fixed inset-0 z-[9500] bg-bg flex overflow-y-auto p-6">
      <div className="m-auto w-full max-w-[400px] space-y-6">
        <div className="flex items-center gap-2.5">
          <OperquayMark size={26} />
          <span className="text-[19px] font-semibold text-text-pri">Operquay</span>
        </div>
        <div className="bg-surface border border-border rounded-[var(--radius-lg)] shadow-[var(--shadow-sm)] p-7 space-y-5">
          <div className="space-y-1">
            <h1 className="text-[20px] font-semibold text-text-pri">Sign in</h1>
            {expired && <p className="text-[13px] text-text-mut">Your session ended. Sign in again to continue.</p>}
          </div>
          {error && <p role="alert" className="text-[13px] text-danger bg-[color-mix(in_srgb,var(--danger)_10%,transparent)] border border-danger/30 rounded-md px-3 py-2 leading-relaxed">{error}</p>}
          {ssoOn && routable && (
            <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); routeByEmail(); }}>
              <input
                className={field}
                type="email"
                autoComplete="email"
                placeholder="you@company.com"
                aria-label="Work email"
                value={workEmail}
                onChange={(e) => setWorkEmail(e.target.value)}
              />
              <Button type="submit" size="lg" className="shrink-0">
                Continue
              </Button>
            </form>
          )}
          {ssoOn && (
            <div className="space-y-2">
              {routable && <div className="text-[12px] text-text-dim text-center">or choose your provider</div>}
              {providers.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => startSSO(p.id)}
                  className="w-full h-10 rounded-md border border-border bg-surface text-[14px] font-medium text-text-pri hover:bg-elev hover:border-text-dim transition-colors flex items-center justify-center gap-2"
                >
                  Continue with {p.label}
                  <span className="text-[11px] font-mono text-text-dim uppercase">{p.type}</span>
                </button>
              ))}
            </div>
          )}
          {body}
          {config && !ssoOn && (
            <button type="button" disabled className="w-full h-10 rounded-md border border-dashed border-border text-[14px] text-text-mut cursor-not-allowed">
              Single sign-on (not configured)
            </button>
          )}
          {ssoOn && local !== 'off' && !showLocal && (
            <button type="button" onClick={() => setShowLocal(true)} className="w-full text-center text-[13px] text-accent hover:underline">
              {local === 'all' || config?.local_user_opt_in_allowed ? 'Sign in with a local account' : 'Break-glass administrator'}
            </button>
          )}
          {onClose && (
            <button type="button" onClick={onClose} className="w-full text-center text-[13px] text-text-mut hover:text-text-pri">
              Cancel
            </button>
          )}
        </div>
        {config && <footer className="pt-24 text-[12px] text-text-dim text-center font-mono">
          <span>{version === 'unknown' || version.startsWith('v') ? version : `v${version}`}:{revision ? revision[1].slice(0, 7) : 'unknown'}</span>
          {revision?.[2] && <span className="ml-2" title="Build includes uncommitted changes">dirty</span>}
        </footer>}
      </div>
    </div>
  );
}

/** Holds the desk until the server says who you are, and requires sign-in when the deployment does. */
export function AuthGate({ children }: { children: ReactNode }) {
  const ready = useAuthStore((s) => s.ready);
  const config = useAuthStore((s) => s.config);
  const me = useAuthStore((s) => s.me);
  const signInOpen = useAuthStore((s) => s.signInOpen);
  const setSignInOpen = useAuthStore((s) => s.setSignInOpen);
  const load = useAuthStore((s) => s.load);
  const signOut = useAuthStore((s) => s.signOut);

  useEffect(() => {
    void load();
  }, [load]);

  if (!ready) return null;
  if (config?.required && !me) return <SignInPage />;
  if (me?.must_change_password) {
    return (
      <div className="fixed inset-0 z-[9500] bg-bg flex overflow-y-auto p-6">
        <div className="m-auto w-full max-w-[540px] space-y-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <OperquayMark size={26} />
              <span className="text-[19px] font-semibold text-text-pri">Operquay</span>
            </div>
            <button type="button" onClick={() => void signOut()} className="text-[13px] text-text-mut hover:text-text-pri">
              Sign out
            </button>
          </div>
          <div className="bg-surface border border-border rounded-[var(--radius-lg)] shadow-[var(--shadow-sm)] p-6 space-y-4">
            <div className="space-y-1">
              <h1 className="text-[19px] font-semibold text-text-pri">Password rotation required</h1>
              <p className="text-[13px] text-text-mut">
                For security compliance, set a new password of at least 12 characters before continuing.
              </p>
            </div>
            <OwnPasswordForm />
          </div>
        </div>
      </div>
    );
  }
  return (
    <>
      {children}
      {signInOpen && <SignInPage onClose={() => setSignInOpen(false)} />}
    </>
  );
}
