import { Activity, LogIn } from 'lucide-react';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';

import { ApiError } from '../api/client';
import { useAuth, useAuthStore } from '../auth/AuthContext';
import { beginLogin, safeReturnTo } from '../auth/oidc';
import { Button, ErrorMessage, TextField } from '../components/ui';
import { getConfig } from '../config';

function loginErrorMessage(err: unknown): unknown {
  if (err instanceof ApiError && err.status === 401 && err.code === 'tenant_required') {
    return new ApiError({
      status: 401,
      code: err.code,
      message: 'This account exists in several tenants. Enter the tenant and sign in again.',
      requestId: err.requestId,
    });
  }
  if (err instanceof ApiError && err.status === 401) {
    return new ApiError({
      status: 401,
      code: err.code,
      message: 'Sign-in failed. Check your email and password. Accounts registered in several tenants must also give the tenant.',
      requestId: err.requestId,
    });
  }
  if (err instanceof ApiError && err.status === 429) {
    const wait = err.retryAfter ? ` Try again in ${err.retryAfter} seconds.` : ' Try again shortly.';
    return new ApiError({ status: 429, code: err.code, message: `Too many sign-in attempts.${wait}`, requestId: err.requestId });
  }
  return err;
}

export default function LoginPage() {
  const { status } = useAuth();
  const store = useAuthStore();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const location = useLocation();
  const oidc = getConfig().oidc;
  const from = safeReturnTo((location.state as { from?: string } | null)?.from);
  const expired = status === 'expired' || new URLSearchParams(location.search).get('reason') === 'expired';

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [tenant, setTenant] = useState('');
  const [busy, setBusy] = useState(false);
  const [ssoBusy, setSsoBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const emailRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    emailRef.current?.focus();
  }, []);

  if (status === 'authenticated') return <Navigate to={from} replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await store.login(email.trim(), password, tenant.trim() || null);
      setPassword('');
      // Nothing cached for a previous session may render for this one.
      queryClient.clear();
      navigate(from, { replace: true });
    } catch (err) {
      setError(loginErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const sso = async () => {
    if (!oidc) return;
    setError(null);
    setSsoBusy(true);
    try {
      window.location.assign(await beginLogin(oidc, from));
    } catch (err) {
      setError(err);
      setSsoBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4 py-10">
      <main className="w-full max-w-sm">
        <div className="mb-6 flex items-center justify-center gap-2">
          <Activity className="h-7 w-7 text-sky-400" aria-hidden="true" />
          <span className="text-xl font-semibold text-white">LG-SOTF</span>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-6 shadow-xl">
          <h1 className="mb-1 text-lg font-semibold text-white">Sign in</h1>
          <p className="mb-5 text-sm text-slate-300">Security alert triage console</p>
          {expired && (
            <p role="status" className="mb-4 rounded-md border border-amber-700 bg-amber-950 px-3 py-2 text-sm text-amber-100">
              Your session has expired or was ended. Sign in again to continue.
            </p>
          )}
          {error !== null && (
            <div className="mb-4">
              <ErrorMessage error={error} compact />
            </div>
          )}
          <form onSubmit={submit} className="space-y-4" noValidate={false}>
            <TextField
              ref={emailRef}
              label="Email"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <TextField
              label="Password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <TextField
              label="Tenant (optional)"
              hint="Only needed when your email is registered in more than one tenant."
              autoComplete="organization"
              value={tenant}
              onChange={(e) => setTenant(e.target.value)}
            />
            <Button type="submit" variant="primary" className="w-full" busy={busy} icon={<LogIn className="h-4 w-4" aria-hidden="true" />}>
              Sign in
            </Button>
          </form>
          {oidc && (
            <>
              <div className="my-5 flex items-center gap-3 text-xs text-slate-400" aria-hidden="true">
                <span className="h-px flex-1 bg-slate-700" />
                or
                <span className="h-px flex-1 bg-slate-700" />
              </div>
              <Button className="w-full" onClick={sso} busy={ssoBusy}>
                {oidc.label}
              </Button>
            </>
          )}
        </div>
      </main>
    </div>
  );
}
