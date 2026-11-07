import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { Link, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { fakeApi, renderWithSession, signedInSession } from '../test/helpers';
import { ErrorBoundary, isChunkLoadError, PageFallback } from './ErrorBoundary';
import { Layout } from './Layout';

let failure: Error | null = null;

function Crashy({ label }: { label: string }) {
  if (failure) throw failure;
  return <h1>{label}</h1>;
}

/** React rethrows render errors in development; jsdom would report each one as uncaught. */
const quiet = (e: ErrorEvent) => e.preventDefault();

beforeEach(() => {
  failure = null;
  // React logs caught render errors; the boundary logs them too.
  vi.spyOn(console, 'error').mockImplementation(() => undefined);
  window.addEventListener('error', quiet);
});

afterEach(() => {
  failure = null;
  window.removeEventListener('error', quiet);
});

describe('isChunkLoadError', () => {
  it.each([
    'Failed to fetch dynamically imported module: https://soc.example/assets/AlertsPage-1a2b.js',
    'error loading dynamically imported module: https://soc.example/assets/AlertsPage-1a2b.js',
    'Importing a module script failed.',
    'Unable to preload CSS for /assets/AlertsPage-1a2b.css',
  ])('recognises %s', (message) => {
    expect(isChunkLoadError(new TypeError(message))).toBe(true);
  });

  it.each([new Error('Cannot read properties of undefined'), null, 'text', { message: 42 }])('ignores %s', (error) => {
    expect(isChunkLoadError(error)).toBe(false);
  });

  it('recognises an error reported through vite:preloadError', () => {
    const error = new Error('opaque');
    expect(isChunkLoadError(error)).toBe(false);
    window.dispatchEvent(Object.assign(new Event('vite:preloadError', { cancelable: true }), { payload: error }));
    expect(isChunkLoadError(error)).toBe(true);
  });
});

describe('ErrorBoundary', () => {
  it('shows the full-page message by default and logs the error', () => {
    failure = new Error('boom');
    render(
      <ErrorBoundary>
        <Crashy label="Page" />
      </ErrorBoundary>,
    );
    expect(screen.getByRole('alert')).toHaveTextContent('Something went wrong');
    expect(screen.getByRole('button', { name: 'Reload' })).toBeInTheDocument();
    expect(console.error).toHaveBeenCalledWith('Unhandled UI error', failure, expect.anything());
  });

  it('asks to reload when the app was updated under the tab', () => {
    failure = new TypeError('Failed to fetch dynamically imported module: /assets/x.js');
    render(
      <ErrorBoundary>
        <Crashy label="Page" />
      </ErrorBoundary>,
    );
    expect(screen.getByRole('heading', { name: 'A new version is available' })).toBeInTheDocument();
  });

  it('retries with the page fallback and clears the error when the reset key changes', async () => {
    failure = new Error('boom');
    function Harness() {
      const [key, setKey] = useState(1);
      return (
        <>
          <button type="button" onClick={() => setKey((k) => k + 1)}>
            next
          </button>
          <ErrorBoundary resetKey={key} fallback={PageFallback}>
            <Crashy label={`Page ${key}`} />
          </ErrorBoundary>
        </>
      );
    }
    render(<Harness />);
    expect(screen.getByRole('heading', { name: 'This page hit an unexpected error' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(screen.getByRole('heading', { name: 'This page hit an unexpected error' })).toBeInTheDocument();
    failure = null;
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(screen.getByRole('heading', { name: 'Page 1' })).toBeInTheDocument();

    failure = new Error('boom again');
    await userEvent.click(screen.getByRole('button', { name: 'next' }));
    expect(screen.getByRole('alert')).toBeInTheDocument();
    failure = null;
    await userEvent.click(screen.getByRole('button', { name: 'next' }));
    expect(screen.getByRole('heading', { name: 'Page 3' })).toBeInTheDocument();
  });

  it('page fallback asks to reload on a chunk-load error', () => {
    failure = new TypeError('Importing a module script failed.');
    render(
      <ErrorBoundary fallback={PageFallback}>
        <Crashy label="Page" />
      </ErrorBoundary>,
    );
    expect(screen.getByRole('heading', { name: 'A new version is available' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Try again' })).not.toBeInTheDocument();
  });
});

describe('per-route boundary in the shell', () => {
  it('keeps the navigation and sign-out when a page crashes, and recovers on navigation', async () => {
    const user = userEvent.setup();
    const { api } = fakeApi((_m, path) => (path === '/auth/me' ? { kind: 'user', tenant_id: 'acme', home_tenant_id: 'acme' } : new Promise(() => undefined)));
    const session = await signedInSession(api);
    failure = new Error('boom');
    renderWithSession(
      <Routes>
        <Route element={<Layout />}>
          <Route path="/alerts" element={<Crashy label="Alerts" />} />
          <Route
            path="/"
            element={
              <>
                <h1>Dashboard</h1>
                <Link to="/alerts">alerts</Link>
              </>
            }
          />
        </Route>
      </Routes>,
      session,
      { route: '/alerts' },
    );
    expect(screen.getByRole('heading', { name: 'This page hit an unexpected error' })).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Main' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Account: / })).toBeInTheDocument();

    failure = null;
    await user.click(screen.getAllByRole('link', { name: 'Overview' })[0]);
    expect(await screen.findByRole('heading', { name: 'Dashboard' })).toBeInTheDocument();
    await user.click(screen.getByRole('link', { name: 'alerts' }));
    expect(await screen.findByRole('heading', { name: 'Alerts', level: 1 })).toBeInTheDocument();
  });
});
