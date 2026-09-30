/**
 * Building blocks for TOTP MFA screens (sign-in step, forced enrollment,
 * account security): the QR code, the manual-entry secret, the code input and
 * the one-time recovery-code list.
 */

import { Copy, Download } from 'lucide-react';
import { forwardRef, useState } from 'react';

import type { MfaEnrollOut } from '../api/types';
import { useToast } from './Toast';
import { Button, TextField } from './ui';

const QUIET_ZONE = 4;

/** Rows of '1'/'0' modules (from the API) drawn as one SVG path; no image or canvas needed. */
export function QrCode({ rows, label, size = 192 }: { rows: string[]; label: string; size?: number }) {
  const n = rows.length;
  const dim = n + QUIET_ZONE * 2;
  let d = '';
  rows.forEach((row, y) => {
    for (let x = 0; x < row.length; x++) {
      if (row[x] === '1') d += `M${x + QUIET_ZONE} ${y + QUIET_ZONE}h1v1h-1z`;
    }
  });
  return (
    <svg
      role="img"
      aria-label={label}
      width={size}
      height={size}
      viewBox={`0 0 ${dim} ${dim}`}
      shapeRendering="crispEdges"
      className="rounded bg-white"
      data-testid="mfa-qr"
    >
      <rect width={dim} height={dim} fill="#ffffff" />
      <path d={d} fill="#000000" />
    </svg>
  );
}

/** The base32 secret in groups of four for manual entry. */
export function formatSecret(secret: string): string {
  return secret.replace(/(.{4})/g, '$1 ').trim();
}

export function EnrollmentDetails({ enrollment }: { enrollment: MfaEnrollOut }) {
  return (
    <div className="space-y-4">
      <ol className="list-decimal space-y-1 pl-5 text-sm text-slate-300">
        <li>Open an authenticator app (for example Microsoft Authenticator, Google Authenticator, 1Password or FreeOTP).</li>
        <li>Scan the QR code, or enter the key below by hand (time-based, 6 digits, 30 seconds).</li>
        <li>Enter the 6-digit code the app shows to finish.</li>
      </ol>
      <div className="flex flex-wrap items-start gap-4">
        {enrollment.qr && enrollment.qr.length > 0 ? (
          <QrCode rows={enrollment.qr} label="QR code for your authenticator app" />
        ) : (
          <p className="max-w-xs text-sm text-slate-300">A QR code is not available for this account; enter the key by hand.</p>
        )}
        <div className="min-w-0 flex-1 space-y-2">
          <p className="text-xs font-medium text-slate-300">Setup key</p>
          <p className="break-all rounded-md border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm tracking-wider text-slate-100" data-testid="mfa-secret">
            {formatSecret(enrollment.secret)}
          </p>
          <p className="text-xs text-slate-400">
            On a phone, <a href={enrollment.otpauth_uri} className="text-sky-300 underline">open this link in your authenticator app</a>.
            The key is shown only now.
          </p>
        </div>
      </div>
    </div>
  );
}

type CodeFieldProps = {
  value: string;
  onChange: (value: string) => void;
  recovery?: boolean;
  label?: string;
  disabled?: boolean;
};

/** A one-time-code input (numeric keypad on phones, autofill from the OS); recovery codes are text. */
export const CodeField = forwardRef<HTMLInputElement, CodeFieldProps>(function CodeField(
  { value, onChange, recovery = false, label, disabled },
  ref,
) {
  return (
    <TextField
      ref={ref}
      label={label ?? (recovery ? 'Recovery code' : 'Authentication code')}
      hint={recovery ? 'One of the codes you saved when you set up MFA, e.g. abcde-12345. Each works once.' : 'The 6-digit code from your authenticator app.'}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      autoComplete="one-time-code"
      inputMode={recovery ? 'text' : 'numeric'}
      pattern={recovery ? undefined : '[0-9 ]{6,7}'}
      maxLength={recovery ? 16 : 7}
      spellCheck={false}
      autoCapitalize="off"
      required
      disabled={disabled}
      className="font-mono tracking-widest"
    />
  );
});

export function downloadText(filename: string, text: string): void {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

/** Recovery codes shown once, with copy and download. */
export function RecoveryCodes({ codes, account }: { codes: string[]; account?: string | null }) {
  const toast = useToast();
  const [copied, setCopied] = useState(false);
  const text = [
    `LG-SOTF recovery codes${account ? ` for ${account}` : ''}`,
    `Generated ${new Date().toISOString()}. Each code works once.`,
    '',
    ...codes,
    '',
  ].join('\n');
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(codes.join('\n'));
      setCopied(true);
      toast.success('Recovery codes copied to the clipboard.');
    } catch {
      toast.info('Copy failed; select the codes and copy them manually.');
    }
  };
  return (
    <div className="space-y-3">
      <p className="text-sm text-amber-200">
        Save these recovery codes somewhere safe (a password manager). Each signs you in once if you lose your authenticator. They are not shown again.
      </p>
      <ul className="grid grid-cols-2 gap-2 rounded-md border border-slate-700 bg-slate-950 p-3 font-mono text-sm text-slate-100" aria-label="Recovery codes" data-testid="recovery-codes">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" onClick={() => void copy()} icon={<Copy className="h-3.5 w-3.5" aria-hidden="true" />}>
          {copied ? 'Copied' : 'Copy codes'}
        </Button>
        <Button size="sm" onClick={() => downloadText('lg-sotf-recovery-codes.txt', text)} icon={<Download className="h-3.5 w-3.5" aria-hidden="true" />}>
          Download
        </Button>
      </div>
    </div>
  );
}
