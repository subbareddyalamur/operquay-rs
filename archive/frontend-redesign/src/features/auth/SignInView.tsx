import { useState, type FormEvent } from 'react';
import { KeyRound, Lock, ShieldCheck } from 'lucide-react';
import { Badge, Button, Card } from '@/design-system/primitives';
import { apiJson, type SsoProviderPublic } from '../platform/api';

export interface SignInViewProps {
  tenantId: string;
  providers: SsoProviderPublic[];
  onSignedIn: () => Promise<void>;
  onCancel?: () => void;
}

export function SignInView({ tenantId, providers, onSignedIn, onCancel }: SignInViewProps) {
  const [email, setEmail] = useState('admin@local');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await apiJson('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
      await onSignedIn();
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Sign-in failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg px-4 py-8">
      <Card elevated className="w-full max-w-md p-6 space-y-5">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <span className="h-8 w-8 rounded-[var(--radius-sm)] bg-accent text-accent-fg inline-flex items-center justify-center font-bold text-sm">
              OQ
            </span>
            <div>
              <h1 className="text-[18px] font-semibold text-text-pri tracking-tight">
                Sign in to Operquay
              </h1>
              <p className="text-xs text-text-mut">
                Enterprise Single-Binary Cloud &amp; Remote Desktop Gateway
              </p>
            </div>
          </div>
          <Badge tone="accent">{tenantId}</Badge>
        </div>

        {err && (
          <div
            role="alert"
            className="px-3.5 py-2.5 rounded-[var(--radius-sm)] border border-border bg-[var(--danger-dim)] text-xs text-danger"
          >
            {err}
          </div>
        )}

        <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="signin-email" className="block text-xs font-medium text-text-mut">
              Work Email or Username
            </label>
            <input
              id="signin-email"
              type="text"
              required
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full h-9 px-3 rounded-[var(--radius-sm)] border border-border bg-elev text-sm text-text-pri focus:outline-none focus:ring-2 focus:ring-accent"
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="signin-password" className="block text-xs font-medium text-text-mut">
              Password
            </label>
            <input
              id="signin-password"
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full h-9 px-3 rounded-[var(--radius-sm)] border border-border bg-elev text-sm text-text-pri focus:outline-none focus:ring-2 focus:ring-accent"
            />
          </div>

          <div className="flex items-center gap-2">
            <Button
              type="submit"
              className="flex-1"
              loading={busy}
              icon={<Lock size={14} aria-hidden="true" />}
            >
              Sign In
            </Button>
            {onCancel && (
              <Button variant="outline" onClick={onCancel}>
                Cancel
              </Button>
            )}
          </div>
        </form>

        {providers.length > 0 && (
          <div className="pt-3 border-t border-border space-y-2">
            <p className="text-xs font-medium text-text-dim flex items-center gap-1.5">
              <KeyRound size={12} aria-hidden="true" /> Single Sign-On ({providers.length})
            </p>
            <div className="grid grid-cols-1 gap-2">
              {providers.map((p) => (
                <a
                  key={p.id}
                  href={`/api/auth/sso/${encodeURIComponent(p.id)}/start`}
                  className="h-9 px-3 rounded-[var(--radius-sm)] border border-border bg-elev hover:bg-[var(--surface-hover)] text-xs font-medium text-text-pri inline-flex items-center justify-center gap-2 transition-colors"
                >
                  <ShieldCheck size={14} className="text-accent" aria-hidden="true" />
                  Continue with {p.label || p.provider_type.toUpperCase()}
                </a>
              ))}
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

