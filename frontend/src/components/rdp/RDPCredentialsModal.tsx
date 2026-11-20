import { useState, useCallback } from 'react';
import { Eye, EyeOff } from 'lucide-react';
import { Dialog } from '@/components/primitives/Dialog';
import { Button } from '@/components/primitives/Button';
import { Input } from '@/components/primitives/Input';
import { canSendCredentials } from '@/lib/credentialTransport';
import type { Instance } from '@/stores/instances';

const SECURITY_OPTIONS = [
  { value: 'any', label: 'Security: Auto (any)' },
  { value: 'nla', label: 'Security: NLA' },
  { value: 'tls', label: 'Security: TLS' },
  { value: 'rdp', label: 'Security: RDP' },
] as const;

type SecurityType = (typeof SECURITY_OPTIONS)[number]['value'];

export interface RDPCredentials {
  username: string;
  password: string;
  security: SecurityType;
}

export interface RDPCredentialsModalProps {
  open: boolean;
  instance: Pick<Instance, 'name'>;
  reconnect?: boolean;
  onSubmit: (creds: RDPCredentials) => void;
  onCancel: () => void;
}

export function RDPCredentialsModal({ open, instance, reconnect = false, onSubmit, onCancel }: RDPCredentialsModalProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [security, setSecurity] = useState<SecurityType>('any');
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      if (!canSendCredentials('/start-guacamole-rdp')) {
        setError('HTTPS is required for RDP credentials. Open Operquay at its HTTPS address.');
        return;
      }
      if (!username.trim()) {
        setError('Username is required');
        return;
      }
      if (!password) {
        setError('Password is required');
        return;
      }
      setError(null);
      onSubmit({
        username: username.trim(),
        password,
        security,
      });
      setPassword('');
    },
    [username, password, security, onSubmit],
  );

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => { if (!o) onCancel(); }}
      title={`${reconnect ? 'Reconnect to' : 'Connect to'} ${instance.name}`}
      size="sm"
      footer={
        <>
          <Button variant="outline" size="sm" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="primary" size="sm" type="submit" form="rdp-creds-form">
            {reconnect ? 'Reconnect' : 'Connect'}
          </Button>
        </>
      }
    >
      <form id="rdp-creds-form" onSubmit={handleSubmit} className="flex flex-col gap-4">
        <div className="flex flex-col gap-1">
          <label htmlFor="rdp-username" className="text-[12px] text-text-dim font-medium">
            Username
          </label>
          <Input
            id="rdp-username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            placeholder="DOMAIN\username or username"
          />
        </div>

        <div className="flex flex-col gap-1">
          <label htmlFor="rdp-password" className="text-[12px] text-text-dim font-medium">
            Password
          </label>
          <Input
            id="rdp-password"
            type={showPassword ? 'text' : 'password'}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            placeholder="Password"
            disabled={false}
            rightIcon={
              <button
                type="button"
                className="pointer-events-auto text-text-dim hover:text-text-pri transition-colors"
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                onClick={() => setShowPassword((v) => !v)}
              >
                {showPassword ? <EyeOff size={13} /> : <Eye size={13} />}
              </button>
            }
          />
        </div>

        <div className="flex flex-col gap-1">
          <label htmlFor="rdp-security" className="text-[12px] text-text-dim font-medium">
            Security
          </label>
          <select
            id="rdp-security"
            value={security}
            onChange={(e) => setSecurity(e.target.value as SecurityType)}
            className="w-full px-3 py-2 rounded-md border border-border bg-elev text-text-pri text-[12px] font-medium outline-none focus:border-accent/50 transition-colors"
          >
            {SECURITY_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

        {error && <p className="text-[12px] text-danger">{error}</p>}

      </form>
    </Dialog>
  );
}

RDPCredentialsModal.displayName = 'RDPCredentialsModal';
