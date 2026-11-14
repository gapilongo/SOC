import { Activity, LogIn, ShieldCheck } from 'lucide-react';
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';

import { ApiError } from '../api/client';
import type { MfaEnrollOut } from '../api/types';
import { useAuth, useAuthStore } from '../auth/AuthContext';
import { forgetCachedData } from '../auth/cacheBinding';
import { beginLogin, safeReturnTo } from '../auth/oidc';
import type { EnrollmentResult, MfaChallenge } from '../auth/store';
import { CodeField, EnrollmentDetails, RecoveryCodes } from '../components/Mfa';
import { Button, ErrorMessage, LoadingState, TextField } from '../components/ui';
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
  return rateLimitMessage(err);
}

function rateLimitMessage(err: unknown): unknown {
  if (err instanceof ApiError && err.status === 429) {
    const wait = err.retryAfter ? ` Try again in ${err.retryAfter} seconds.` : ' Try again shortly.';
    return new ApiError({ status: 429, code: err.code, message: `Too many sign-in attempts.${wait}`, requestId: err.requestId });
  }
  return err;
}

/** True when the challenge is gone (expired, spent, password changed): the user must start over. */
function challengeExpired(err: unknown): boolean {
  return err instanceof ApiError && err.code === 'invalid_mfa_token';
}

function codeErrorMessage(err: unknown): unknown {
  if (err instanceof ApiError && err.code === 'invalid_mfa_code') {
    return new ApiError({
      status: err.status,
      code: err.code,
      message: 'That code is not valid. Each code works once: wait for the next code in your app, or use a recovery code. Repeated failures lock the account.',
      requestId: err.requestId,
    });
  }
  return rateLimitMessage(err);
}

function Shell({ title, subtitle, children }: { title: string; subtitle: ReactNode; children: ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-4 py-10">
      <main className="w-full max-w-md">
        <div className="mb-6 flex items-center justify-center gap-2">
          <Activity className="h-7 w-7 text-link" aria-hidden="true" />
          <span className="text-xl font-semibold text-fg">LG-SOTF</span>
        </div>
        <div className="rounded-card border border-subtle bg-raised p-6 shadow-xl">
          <h1 className="mb-1 text-lg font-semibold text-fg">{title}</h1>
          <div className="mb-5 text-sm text-secondary">{subtitle}</div>
          {children}
        </div>
      </main>
    </div>
  );
}

function MfaStep({ challenge, onDone, onRestart }: { challenge: MfaChallenge; onDone: () => void; onRestart: (expired: boolean) => void }) {
  const store = useAuthStore();
  const [code, setCode] = useState('');
  const [recovery, setRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [remaining, setRemaining] = useState<number | null>(null);
  const codeRef = useRef<HTMLInputElement>(null);
  const canRecover = challenge.methods.includes('recovery_code');

  useEffect(() => {
    codeRef.current?.focus();
  }, [recovery]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const out = await store.completeMfa(challenge, code.trim());
      if (out.recoveryCodesRemaining !== null) {
        setRemaining(out.recoveryCodesRemaining);
        return;
      }
      onDone();
    } catch (err) {
      if (challengeExpired(err)) {
        onRestart(true);
        return;
      }
      setCode('');
      setError(codeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  if (remaining !== null) {
    return (
      <Shell title="Signed in with a recovery code" subtitle="That recovery code is now used up.">
        <p role="status" className="mb-4 rounded-control border border-warn/60 bg-tint-warn px-3 py-2 text-sm text-warn-fg">
          {remaining === 0
            ? 'You have no recovery codes left. Generate new ones under Account security now.'
            : `You have ${remaining} recovery code${remaining === 1 ? '' : 's'} left. If you lost your authenticator, set up a new one under Account security.`}
        </p>
        <Button variant="primary" className="w-full" onClick={onDone}>
          Continue
        </Button>
      </Shell>
    );
  }

  return (
    <Shell title="Two-step verification" subtitle={recovery ? 'Enter one of your recovery codes.' : 'Enter the code from your authenticator app.'}>
      {error !== null && (
        <div className="mb-4">
          <ErrorMessage error={error} compact />
        </div>
      )}
      <form onSubmit={submit} className="space-y-4">
        <CodeField ref={codeRef} value={code} onChange={setCode} recovery={recovery} />
        <Button type="submit" variant="primary" className="w-full" busy={busy} icon={<ShieldCheck className="h-4 w-4" aria-hidden="true" />}>
          Verify
        </Button>
      </form>
      <div className="mt-4 flex flex-wrap justify-between gap-2 text-sm">
        {canRecover && (
          <button
            type="button"
            className="text-link underline hover:text-link"
            onClick={() => {
              setRecovery(!recovery);
              setCode('');
              setError(null);
            }}
          >
            {recovery ? 'Use an authenticator code' : 'Use a recovery code'}
          </button>
        )}
        <button type="button" className="text-secondary underline hover:text-fg" onClick={() => onRestart(false)}>
          Start over
        </button>
      </div>
    </Shell>
  );
}

function EnrollStep({ challenge, onDone, onRestart }: { challenge: MfaChallenge; onDone: () => void; onRestart: (expired: boolean) => void }) {
  const store = useAuthStore();
  const [enrollment, setEnrollment] = useState<MfaEnrollOut | null>(null);
  const [result, setResult] = useState<EnrollmentResult | null>(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const started = useRef(false);

  useEffect(() => {
    // Once per challenge (StrictMode runs effects twice in development).
    if (started.current) return;
    started.current = true;
    store.beginEnrollment(challenge).then(setEnrollment, (err: unknown) => {
      if (challengeExpired(err)) onRestart(true);
      else setError(rateLimitMessage(err));
    });
  }, [store, challenge, onRestart]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      setResult(await store.completeEnrollment(challenge, code.trim()));
    } catch (err) {
      if (challengeExpired(err)) {
        onRestart(true);
        return;
      }
      setCode('');
      setError(codeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  if (result) {
    return (
      <Shell title="Two-step verification is on" subtitle="From now on you sign in with your password and a code from your app.">
        <RecoveryCodes codes={result.recoveryCodes} />
        <Button
          variant="primary"
          className="mt-5 w-full"
          onClick={() => {
            result.finish();
            onDone();
          }}
        >
          I have saved my recovery codes
        </Button>
      </Shell>
    );
  }

  return (
    <Shell
      title="Set up two-step verification"
      subtitle="Your organisation requires an authenticator app for this account. You can use nothing else until it is set up."
    >
      {error !== null && (
        <div className="mb-4">
          <ErrorMessage error={error} compact />
        </div>
      )}
      {!enrollment && error === null && <LoadingState label="Preparing enrollment" />}
      {enrollment && (
        <form onSubmit={submit} className="space-y-5">
          <EnrollmentDetails enrollment={enrollment} />
          <CodeField value={code} onChange={setCode} />
          <Button type="submit" variant="primary" className="w-full" busy={busy} icon={<ShieldCheck className="h-4 w-4" aria-hidden="true" />}>
            Turn on and sign in
          </Button>
        </form>
      )}
      <div className="mt-4 text-sm">
        <button type="button" className="text-secondary underline hover:text-fg" onClick={() => onRestart(false)}>
          Start over
        </button>
      </div>
    </Shell>
  );
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
  // Memory only; never stored. It is not a session.
  const [challenge, setChallenge] = useState<MfaChallenge | null>(null);
  const [stepExpired, setStepExpired] = useState(false);
  const emailRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!challenge) emailRef.current?.focus();
  }, [challenge]);

  if (status === 'authenticated' && !challenge) return <Navigate to={from} replace />;

  const enter = () => {
    // Nothing cached for a previous session may render for this one.
    forgetCachedData(queryClient, true);
    setChallenge(null);
    navigate(from, { replace: true });
  };

  const restart = (wasExpired: boolean) => {
    setChallenge(null);
    setPassword('');
    setStepExpired(wasExpired);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setStepExpired(false);
    setBusy(true);
    try {
      const result = await store.login(email.trim(), password, tenant.trim() || null);
      setPassword('');
      if (result.status === 'mfa') {
        setChallenge(result.challenge);
        return;
      }
      enter();
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

  if (challenge) {
    return challenge.enrollmentRequired ? (
      <EnrollStep challenge={challenge} onDone={enter} onRestart={restart} />
    ) : (
      <MfaStep challenge={challenge} onDone={enter} onRestart={restart} />
    );
  }

  return (
    <Shell title="Sign in" subtitle="Security alert triage console">
      {expired && (
        <p role="status" className="mb-4 rounded-control border border-warn/60 bg-tint-warn px-3 py-2 text-sm text-warn-fg">
          Your session has expired or was ended. Sign in again to continue.
        </p>
      )}
      {stepExpired && (
        <p role="status" className="mb-4 rounded-control border border-warn/60 bg-tint-warn px-3 py-2 text-sm text-warn-fg">
          The verification step expired. Sign in again.
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
          <div className="my-5 flex items-center gap-3 text-xs text-muted" aria-hidden="true">
            <span className="h-px flex-1 bg-selected" />
            or
            <span className="h-px flex-1 bg-selected" />
          </div>
          <Button className="w-full" onClick={sso} busy={ssoBusy}>
            {oidc.label}
          </Button>
        </>
      )}
    </Shell>
  );
}
