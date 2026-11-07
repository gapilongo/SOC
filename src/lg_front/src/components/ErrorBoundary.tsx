import { Component, type ErrorInfo, type ReactNode } from 'react';

import { Button } from './ui';

/**
 * Messages a browser gives when a lazily loaded chunk cannot be fetched,
 * usually because a deploy replaced the hashed files this tab still refers to.
 */
const CHUNK_LOAD_ERROR = [
  /Failed to fetch dynamically imported module/i, // Chrome, Edge
  /error loading dynamically imported module/i, // Firefox
  /Importing a module script failed/i, // Safari
  /Unable to preload CSS/i, // Vite's CSS preload helper
  /Loading (CSS )?chunk [\w-]+ failed/i, // older bundlers
];

/** Errors seen through Vite's `vite:preloadError` event (a failed preload of a route's dependencies). */
const preloadErrors = new WeakSet<object>();
if (typeof window !== 'undefined') {
  window.addEventListener('vite:preloadError', (event) => {
    const payload = (event as Event & { payload?: unknown }).payload;
    if (payload && typeof payload === 'object') preloadErrors.add(payload);
  });
}

/** True when `error` means the app was updated under this tab: reloading loads the new version. */
export function isChunkLoadError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  if (preloadErrors.has(error)) return true;
  const message = (error as { message?: unknown }).message;
  return typeof message === 'string' && CHUNK_LOAD_ERROR.some((re) => re.test(message));
}

export interface FallbackProps {
  error: Error;
  /** Render the children again (after the cause went away, or to retry). */
  reset: () => void;
}

interface Props {
  children: ReactNode;
  /** When this value changes (for example the route), a shown error is cleared. */
  resetKey?: unknown;
  /** What to show instead of the children; the default is a full-page message. */
  fallback?: (props: FallbackProps) => ReactNode;
}

interface State {
  error: Error | null;
  resetKey: unknown;
}

function reload(): void {
  window.location.reload();
}

/** "A new version is available": a chunk of the old version could not be loaded. */
export function NewVersionMessage({ className = 'mx-auto max-w-lg px-4 py-16 text-center' }: { className?: string }) {
  return (
    <div role="alert" className={className}>
      <h1 className="text-lg font-semibold text-fg">A new version is available</h1>
      <p className="mt-2 text-sm text-secondary">LG-SOTF was updated while this tab was open. Reload to continue; your session is restored automatically.</p>
      <Button variant="primary" className="mt-4" onClick={reload}>
        Reload
      </Button>
    </div>
  );
}

/** Full-page fallback for the outermost boundary. */
function AppFallback({ error }: FallbackProps) {
  if (isChunkLoadError(error)) return <NewVersionMessage />;
  return (
    <div role="alert" className="mx-auto max-w-lg px-4 py-16 text-center">
      <h1 className="text-lg font-semibold text-fg">Something went wrong</h1>
      <p className="mt-2 text-sm text-secondary">The page hit an unexpected error. Reloading usually fixes it; your session is restored automatically.</p>
      <Button variant="primary" className="mt-4" onClick={reload}>
        Reload
      </Button>
    </div>
  );
}

/** Fallback inside the app shell: the page failed, the navigation and sign-out still work. */
export function PageFallback({ error, reset }: FallbackProps) {
  if (isChunkLoadError(error)) return <NewVersionMessage className="py-16 text-center" />;
  return (
    <div role="alert" className="py-16 text-center">
      <h1 className="text-lg font-semibold text-fg">This page hit an unexpected error</h1>
      <p className="mt-2 text-sm text-secondary">Try again, or open another page from the menu. Reloading usually fixes it.</p>
      <div className="mt-4 flex justify-center gap-2">
        <Button variant="primary" onClick={reset}>
          Try again
        </Button>
        <Button onClick={reload}>Reload</Button>
      </div>
    </div>
  );
}

/**
 * Catches rendering errors below it. The app has one around everything (a
 * last resort) and one around each page inside the shell, reset when the
 * route changes, so a page crash keeps the sidebar, header and sign-out.
 */
export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null, resetKey: this.props.resetKey };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  static getDerivedStateFromProps(props: Props, state: State): Partial<State> | null {
    // A new resetKey (the user navigated away) clears the error.
    if (Object.is(props.resetKey, state.resetKey)) return null;
    return { resetKey: props.resetKey, error: null };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('Unhandled UI error', error, info.componentStack);
  }

  reset = () => this.setState({ error: null });

  override render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    const Fallback = this.props.fallback ?? AppFallback;
    return Fallback({ error, reset: this.reset });
  }
}
