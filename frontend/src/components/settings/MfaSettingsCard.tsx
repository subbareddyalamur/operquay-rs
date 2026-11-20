import { useCallback, useEffect, useState } from 'react';
import { Button, Input } from '@/components/primitives';
import { api } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';

interface PasskeySummary {
  id: string;
  label: string;
  alg: number;
  created_at: number;
}

interface MfaStatus {
  mfa_enabled: boolean;
  totp_enabled: boolean;
  recovery_codes_remaining: number;
  passkeys: PasskeySummary[];
}

interface TotpSetupPayload {
  secret: string;
  otpauth_url: string;
}

interface TotpVerifyResponse {
  enabled: boolean;
  recovery_codes: string[];
}

function toBase64Url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(b64u: string): ArrayBuffer {
  const pad = b64u.length % 4 === 0 ? '' : '='.repeat(4 - (b64u.length % 4));
  const raw = atob(b64u.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    out[i] = raw.charCodeAt(i);
  }
  return out.buffer;
}

export function MfaSettingsCard() {
  const me = useAuthStore((s) => s.me);
  const loadAuth = useAuthStore((s) => s.load);
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [setup, setSetup] = useState<TotpSetupPayload | null>(null);
  const [verifyCode, setVerifyCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [copiedRecovery, setCopiedRecovery] = useState(false);
  const [disableOpen, setDisableOpen] = useState(false);
  const [disablePw, setDisablePw] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [passkeyLabel, setPasskeyLabel] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const refresh = useCallback(async () => {
    const res = await api.get<MfaStatus>('/api/auth/mfa/status');
    if (res.ok) {
      setStatus(res.data);
    }
  }, []);

  useEffect(() => {
    if (me && me.method !== 'sso') {
      void refresh();
    }
  }, [me, refresh]);

  if (!me || me.method === 'sso') return null;

  const webauthnSupported =
    typeof window !== 'undefined' &&
    'PublicKeyCredential' in window &&
    Boolean(navigator.credentials?.create);

  const beginTotp = async () => {
    setError('');
    setBusy(true);
    const res = await api.post<TotpSetupPayload>('/api/auth/mfa/totp/setup');
    setBusy(false);
    if (!res.ok) {
      setError('Could not start authenticator setup.');
      return;
    }
    setSetup(res.data);
    setVerifyCode('');
    setRecoveryCodes(null);
  };

  const confirmTotp = async () => {
    setError('');
    setBusy(true);
    const res = await api.post<TotpVerifyResponse>('/api/auth/mfa/totp/verify', {
      code: verifyCode.trim(),
    });
    setBusy(false);
    if (!res.ok) {
      setError('Verification code did not match. Check the 6-digit code and try again.');
      return;
    }
    setSetup(null);
    setVerifyCode('');
    setRecoveryCodes(res.data.recovery_codes);
    setCopiedRecovery(false);
    await refresh();
    await loadAuth();
  };

  const disableTotp = async () => {
    setError('');
    setBusy(true);
    const res = await api.post('/api/auth/mfa/totp/disable', {
      current_password: disablePw,
      code: disableCode.trim(),
    });
    setBusy(false);
    if (!res.ok) {
      setError(
        res.error.status === 401
          ? 'Current password or MFA code was rejected.'
          : 'Could not disable two-factor authentication.',
      );
      return;
    }
    setDisableOpen(false);
    setDisablePw('');
    setDisableCode('');
    setRecoveryCodes(null);
    await refresh();
    await loadAuth();
  };

  const registerPasskey = async () => {
    if (!webauthnSupported) return;
    setError('');
    setBusy(true);
    const startRes = await api.post<{
      challenge: string;
      rp: { id: string; name: string };
      user: { id: string; name: string; displayName: string };
      pubKeyCredParams: PublicKeyCredentialParameters[];
      timeout: number;
      authenticatorSelection?: AuthenticatorSelectionCriteria;
    }>('/api/auth/mfa/webauthn/register/start');
    if (!startRes.ok) {
      setBusy(false);
      setError('Could not initiate passkey registration.');
      return;
    }
    try {
      const opts = startRes.data;
      const cred = (await navigator.credentials.create({
        publicKey: {
          challenge: fromBase64Url(opts.challenge),
          rp: opts.rp,
          user: {
            id: fromBase64Url(opts.user.id),
            name: opts.user.name,
            displayName: opts.user.displayName,
          },
          pubKeyCredParams: opts.pubKeyCredParams,
          timeout: opts.timeout,
          authenticatorSelection: opts.authenticatorSelection,
        },
      })) as PublicKeyCredential | null;
      if (!cred) {
        setBusy(false);
        setError('Passkey creation was cancelled.');
        return;
      }
      const resp = cred.response as AuthenticatorAttestationResponse;
      const spki = typeof resp.getPublicKey === 'function' ? resp.getPublicKey() : null;
      const alg = typeof resp.getPublicKeyAlgorithm === 'function' ? resp.getPublicKeyAlgorithm() : -7;
      if (!spki) {
        setBusy(false);
        setError('This browser did not expose the passkey SPKI public key.');
        return;
      }
      const fin = await api.post('/api/auth/mfa/webauthn/register/finish', {
        credential_id: toBase64Url(cred.rawId),
        label: passkeyLabel.trim() || 'Passkey',
        public_key_spki_b64: toBase64Url(spki),
        alg,
        client_data_b64: toBase64Url(resp.clientDataJSON),
      });
      setBusy(false);
      if (!fin.ok) {
        setError('Failed to save passkey on server.');
        return;
      }
      setPasskeyLabel('');
      await refresh();
      await loadAuth();
    } catch {
      setBusy(false);
      setError('Passkey enrollment failed or was cancelled.');
    }
  };

  const removePasskey = async (id: string) => {
    setError('');
    setBusy(true);
    const res = await api.delete(`/api/auth/mfa/webauthn/${encodeURIComponent(id)}`);
    setBusy(false);
    if (!res.ok) {
      setError('Could not remove passkey.');
      return;
    }
    await refresh();
    await loadAuth();
  };

  const copyRecoveryCodes = async () => {
    if (!recoveryCodes) return;
    await navigator.clipboard?.writeText(recoveryCodes.join('\n')).catch(() => {});
    setCopiedRecovery(true);
  };

  const totpEnabled = Boolean(status?.totp_enabled);

  return (
    <div className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs">
      <div className="px-5 py-4 border-b border-border flex items-start justify-between gap-4">
        <div>
          <h3 className="text-[14px] font-semibold text-text-pri">Two-factor authentication (MFA)</h3>
          <p className="text-[13px] text-text-mut mt-0.5">
            Protect local password access with an authenticator app (TOTP), single-use recovery codes, or WebAuthn passkeys.
          </p>
        </div>
        {status && (
          <span
            className={`px-2 py-0.5 rounded text-[11px] font-medium ${
              status.mfa_enabled
                ? 'bg-success/15 text-success border border-success/30'
                : 'bg-elev text-text-mut border border-border'
            }`}
          >
            {status.mfa_enabled ? 'Enabled' : 'Not configured'}
          </span>
        )}
      </div>

      <div className="px-5 py-4 space-y-4">
        {error && (
          <p role="alert" className="text-[12px] text-danger">
            {error}
          </p>
        )}

        {recoveryCodes && (
          <div className="rounded-md border border-warn/40 bg-warn-ink/40 p-4 space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <p className="text-[13px] font-semibold text-text-pri">
                Save your single-use recovery codes
              </p>
              <Button type="button" variant="outline" size="sm" onClick={() => void copyRecoveryCodes()}>
                {copiedRecovery ? 'Copied' : 'Copy all'}
              </Button>
            </div>
            <p className="text-[12px] text-text-mut">
              Each code can sign in once if your authenticator device is unavailable. Store them securely offline.
            </p>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[12px] text-text-pri">
              {recoveryCodes.map((rc) => (
                <code key={rc} className="px-2 py-1 rounded bg-bg border border-border text-center">
                  {rc}
                </code>
              ))}
            </div>
          </div>
        )}

        {!setup && !totpEnabled && (
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-[13px] font-medium text-text-pri">Authenticator app (TOTP)</p>
              <p className="text-[12px] text-text-mut">Requires a 6-digit rotating code on sign-in.</p>
            </div>
            <Button type="button" variant="primary" size="sm" loading={busy} onClick={() => void beginTotp()}>
              Set up authenticator app
            </Button>
          </div>
        )}

        {setup && (
          <div className="rounded-md border border-border bg-bg p-4 space-y-3">
            <div className="space-y-1">
              <p className="text-[13px] font-semibold text-text-pri">Enroll authenticator app</p>
              <p className="text-[12px] text-text-mut">
                Add this Base32 key to 1Password, Google Authenticator, or Yubico Authenticator, then enter the 6-digit code below.
              </p>
            </div>
            <div className="space-y-1.5 text-[12px]">
              <div className="text-text-mut">Setup key</div>
              <code className="block px-3 py-2 rounded bg-surface border border-border font-mono text-text-pri break-all">
                {setup.secret}
              </code>
              <div className="text-[11px] text-text-dim break-all font-mono">{setup.otpauth_url}</div>
            </div>
            <div className="flex flex-wrap items-end gap-2">
              <label className="block space-y-1 text-[12px] font-medium text-text-mut">
                <span>Verification code</span>
                <Input
                  type="text"
                  inputMode="numeric"
                  aria-label="Verification code"
                  placeholder="123456"
                  value={verifyCode}
                  onChange={(e) => setVerifyCode(e.target.value)}
                  className="font-mono w-40"
                />
              </label>
              <Button
                type="button"
                variant="primary"
                size="sm"
                loading={busy}
                disabled={busy || verifyCode.trim().length < 6}
                onClick={() => void confirmTotp()}
              >
                Verify & enable
              </Button>
              <Button type="button" variant="outline" size="sm" onClick={() => { setSetup(null); setVerifyCode(''); }}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        {totpEnabled && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-[13px] font-medium text-text-pri">Authenticator app active</p>
                <p className="text-[12px] text-text-mut">
                  {status?.recovery_codes_remaining ?? 0} recovery codes remaining.
                </p>
              </div>
              {!disableOpen && (
                <Button type="button" variant="outline" size="sm" onClick={() => setDisableOpen(true)}>
                  Disable authenticator
                </Button>
              )}
            </div>
            {disableOpen && (
              <div className="rounded-md border border-border bg-bg p-3.5 space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <label className="block space-y-1 text-[12px] font-medium text-text-mut">
                    <span>Current password</span>
                    <Input
                      type="password"
                      autoComplete="current-password"
                      value={disablePw}
                      onChange={(e) => setDisablePw(e.target.value)}
                    />
                  </label>
                  <label className="block space-y-1 text-[12px] font-medium text-text-mut">
                    <span>Authenticator or recovery code</span>
                    <Input
                      type="text"
                      value={disableCode}
                      onChange={(e) => setDisableCode(e.target.value)}
                      className="font-mono"
                    />
                  </label>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    type="button"
                    variant="danger"
                    size="sm"
                    loading={busy}
                    disabled={busy || !disablePw || !disableCode.trim()}
                    onClick={() => void disableTotp()}
                  >
                    Confirm disable
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => { setDisableOpen(false); setDisablePw(''); setDisableCode(''); }}
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            )}
          </div>
        )}

        {webauthnSupported && (
          <div className="pt-3 border-t border-border space-y-2.5">
            <div className="flex flex-wrap items-end justify-between gap-2">
              <div>
                <p className="text-[13px] font-medium text-text-pri">WebAuthn / FIDO2 Passkeys</p>
                <p className="text-[12px] text-text-mut">Hardware security keys or platform biometrics.</p>
              </div>
              <div className="flex items-center gap-2">
                <Input
                  type="text"
                  placeholder="Key label (e.g. YubiKey)"
                  value={passkeyLabel}
                  onChange={(e) => setPasskeyLabel(e.target.value)}
                  className="w-44"
                />
                <Button type="button" variant="outline" size="sm" loading={busy} onClick={() => void registerPasskey()}>
                  Add passkey
                </Button>
              </div>
            </div>
            {status && status.passkeys.length > 0 && (
              <div className="divide-y divide-border rounded border border-border bg-bg">
                {status.passkeys.map((pk) => (
                  <div key={pk.id} className="px-3 py-2 flex items-center justify-between gap-2 text-[12px]">
                    <span className="font-medium text-text-pri">{pk.label}</span>
                    <button
                      type="button"
                      onClick={() => void removePasskey(pk.id)}
                      className="text-danger hover:underline cursor-pointer"
                    >
                      Remove
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
