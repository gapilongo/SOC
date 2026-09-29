import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { useAuthStore } from '../auth/AuthContext';
import { completeLogin } from '../auth/oidc';
import { ErrorMessage, LoadingState } from '../components/ui';
import { getConfig } from '../config';
import type { AuthStore } from '../auth/store';

// The authorization code can be redeemed once; guard against effects running twice.
let inflight: { url: string; promise: Promise<string> } | null = null;

function redeem(store: AuthStore, url: string): Promise<string> {
  // A second effect run (React StrictMode) sees the cleaned URL: reuse the first redemption.
  if (inflight && (inflight.url === url || !/[?&](code|error)=/.test(url))) return inflight.promise;
  const oidc = getConfig().oidc;
  const promise = (async () => {
    if (!oidc) throw new Error('Single sign-on is not configured.');
    const result = await completeLogin(oidc, url);
    await store.acceptOidc(result.token, result.expiresIn, result.refreshToken);
    return result.returnTo;
  })();
  inflight = { url, promise };
  return promise;
}

export default function OidcCallbackPage() {
  const store = useAuthStore();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    const url = window.location.href;
    // Remove the code and state from the address bar and history straight away.
    window.history.replaceState(null, '', window.location.pathname);
    redeem(store, url).then(
      (returnTo) => {
        // Nothing cached for a previous session may render for this one.
        queryClient.clear();
        navigate(returnTo, { replace: true });
      },
      (err: unknown) => {
        setError(err);
        // Fall back to the cookie session (if any) so the rest of the app is usable.
        void store.init();
      },
    );
  }, [store, navigate, queryClient]);

  return (
    <main className="mx-auto max-w-md px-4 py-16">
      <h1 className="mb-4 text-lg font-semibold text-white">Completing single sign-on</h1>
      {error ? (
        <div className="space-y-4">
          <ErrorMessage error={error} />
          <Link to="/login" className="text-sm text-sky-300 underline hover:text-sky-200">
            Back to sign in
          </Link>
        </div>
      ) : (
        <LoadingState label="Signing you in" />
      )}
    </main>
  );
}
