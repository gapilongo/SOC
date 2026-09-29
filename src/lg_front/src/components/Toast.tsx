import { X } from 'lucide-react';
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';

import { describeError } from '../api/client';
import { cx } from './ui';

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
      setToasts((t) => [...t.slice(-4), { ...toast, id }]);
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
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2">
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
    <div
      className={cx(
        'pointer-events-auto flex items-start gap-2 rounded-md border px-3 py-2 text-sm shadow-lg',
        toast.tone === 'error' && 'border-red-700 bg-red-950 text-red-50',
        toast.tone === 'success' && 'border-emerald-700 bg-emerald-950 text-emerald-50',
        toast.tone === 'info' && 'border-slate-600 bg-slate-800 text-slate-50',
      )}
    >
      <div className="min-w-0 flex-1">
        <p>{toast.message}</p>
        {toast.requestId && <p className="mt-0.5 font-mono text-xs opacity-80">Request ID: {toast.requestId}</p>}
      </div>
      <button
        type="button"
        onClick={() => onDismiss(toast.id)}
        aria-label="Dismiss notification"
        className="rounded p-0.5 hover:bg-white/10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400"
      >
        <X className="h-4 w-4" aria-hidden="true" />
      </button>
    </div>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('ToastProvider is missing');
  return ctx;
}
