import { AlertTriangle, X } from 'lucide-react';
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';

import { describeError } from '../api/client';

interface Toast {
  id: number;
  tone: 'success' | 'error' | 'info';
  message: string;
  requestId?: string | null;
}

interface ToastApi {
  success(message: string): void;
  info(message: string): void;
  error(error: unknown, prefix?: string): void;
}

const ToastContext = createContext<ToastApi | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const next = useRef(1);

  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);

  const push = useCallback(
    (toast: Omit<Toast, 'id'>) => {
      const id = next.current++;
      // A repeat of a visible toast replaces it (fresh timer) instead of stacking: repeated clicks
      // that fail the same way show one notice.
      const same = (x: Toast) => x.tone === toast.tone && x.message === toast.message;
      setToasts((t) => [...t.filter((x) => !same(x)).slice(-4), { ...toast, id }]);
      setTimeout(() => dismiss(id), toast.tone === 'error' ? 12_000 : 5_000);
    },
    [dismiss],
  );

  const api = useMemo<ToastApi>(
    () => ({
      success: (message) => push({ tone: 'success', message }),
      info: (message) => push({ tone: 'info', message }),
      error: (error, prefix) => {
        const d = describeError(error);
        push({ tone: 'error', message: prefix ? `${prefix}: ${d.message}` : d.message, requestId: d.requestId });
      },
    }),
    [push],
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="pointer-events-none fixed inset-x-3 bottom-5 z-[60] mx-auto flex max-w-sm flex-col gap-2">
        <div aria-live="polite" role="status" className="flex flex-col gap-2">
          {toasts
            .filter((t) => t.tone !== 'error')
            .map((t) => (
              <ToastView key={t.id} toast={t} onDismiss={dismiss} />
            ))}
        </div>
        <div aria-live="assertive" role="alert" className="flex flex-col gap-2">
          {toasts
            .filter((t) => t.tone === 'error')
            .map((t) => (
              <ToastView key={t.id} toast={t} onDismiss={dismiss} />
            ))}
        </div>
      </div>
    </ToastContext.Provider>
  );
}

function ToastView({ toast, onDismiss }: { toast: Toast; onDismiss: (id: number) => void }) {
  return (
    // One look for every toast: the sheet inverted. An error says so with its mark and stays longer.
    <div data-tone={toast.tone} className="pointer-events-auto flex items-start gap-2 rounded-control bg-fg px-3 py-2 text-ctl text-canvas shadow-popover">
      {toast.tone === 'error' && <AlertTriangle className="mt-0.5 h-4 w-4 flex-none" strokeWidth={1.5} aria-hidden="true" />}
      <div className="min-w-0 flex-1">
        <p>{toast.message}</p>
        {toast.requestId && <p className="mt-0.5 font-mono text-xs">Request ID: {toast.requestId}</p>}
      </div>
      <button
        type="button"
        onClick={() => onDismiss(toast.id)}
        aria-label="Dismiss notification"
        className="rounded p-0.5 hover:bg-canvas/20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-canvas"
      >
        <X className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />
      </button>
    </div>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('ToastProvider is missing');
  return ctx;
}
