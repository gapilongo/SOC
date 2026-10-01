import type { MicrosoftCapabilityCheck, MicrosoftPermissionCheck, MicrosoftTestReport as Report } from '../../api/types';
import { Badge, type Tone } from '../../components/Badge';
import { formatDateTime, humanize } from '../../lib/format';

const CAPABILITY_TONE: Record<string, Tone> = {
  ok: 'good',
  unverified: 'info',
  missing_permission: 'critical',
  not_licensed: 'warn',
  unsupported_cloud: 'neutral',
  error: 'critical',
  not_enabled: 'neutral',
};
const PERMISSION_TONE: Record<string, Tone> = { granted: 'good', missing: 'critical', unknown: 'warn' };
const TOKEN_TONE: Record<string, Tone> = { ok: 'good', failed: 'critical', not_needed: 'neutral' };
const API_LABELS: Record<string, string> = { graph: 'Microsoft Graph', defender: 'Defender for Endpoint' };

function Permission({ check }: { check: MicrosoftPermissionCheck }) {
  const via = check.via === 'token' ? '' : ` (${humanize(check.via)})`;
  return (
    <li className="flex flex-wrap items-center gap-1.5 text-xs" title={check.guidance || undefined}>
      <Badge tone={check.warning ? 'warn' : (PERMISSION_TONE[check.status] ?? 'neutral')}>{check.status}</Badge>
      <code className="text-slate-200">{check.role}</code>
      <span className="text-slate-400">
        {check.api}
        {via}
        {!check.required ? ', not required with these options' : ''}
      </span>
      {check.warning && <span className="basis-full text-amber-200">{check.warning}</span>}
    </li>
  );
}

/** Whether an enabled capability lacks an application permission its token should carry (consent to fix). */
function consentMissing(report: Report): boolean {
  return Object.values(report.capabilities ?? {}).some(
    (c) => c.enabled && c.permissions.some((p) => p.via === 'token' && p.status === 'missing' && p.required),
  );
}

function CapabilityRow({ name, check }: { name: string; check: MicrosoftCapabilityCheck }) {
  return (
    <tr className="border-b border-slate-800/70 align-top">
      <th scope="row" className="px-3 py-2 text-left font-medium text-slate-100">
        {name}
        <div className="text-xs font-normal text-slate-400">{check.enabled ? (check.live ? 'enabled, live' : 'enabled, rehearsal') : 'not enabled'}</div>
      </th>
      <td className="px-3 py-2">
        <Badge tone={CAPABILITY_TONE[check.status] ?? 'neutral'}>{humanize(check.status)}</Badge>
        {check.detail && <p className="mt-1 text-xs text-slate-400">{check.detail}</p>}
      </td>
      <td className="px-3 py-2">
        <ul className="space-y-1">
          {check.permissions.map((p) => (
            <Permission key={`${p.via}:${p.api}:${p.role}`} check={p} />
          ))}
        </ul>
      </td>
      <td className="px-3 py-2 text-xs text-slate-300">
        {check.checks.length === 0
          ? '-'
          : check.checks.map((c, i) => (
              <p key={i}>
                <Badge tone={c.status === 'ok' ? 'good' : c.status === 'skipped' ? 'neutral' : 'critical'}>{c.status}</Badge> {c.name}
                {c.detail ? `: ${c.detail}` : ''}
              </p>
            ))}
      </td>
    </tr>
  );
}

/** The Microsoft connection test: token panel, certificate, and the capability x permission matrix. */
export function MicrosoftTestReport({ report }: { report: Report }) {
  const capabilities = Object.entries(report.capabilities ?? {});
  const noRoles = consentMissing(report) ? 'none (admin consent missing?)' : 'none';
  return (
    <div className="space-y-4 text-sm">
      <p>
        <Badge tone={report.ok ? 'good' : 'critical'}>{report.ok ? 'ok' : 'problems found'}</Badge>{' '}
        <span className="text-slate-300">Only sign-in requests and read-only calls were made.</span>
      </p>
      <section aria-label="Tokens">
        <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">Tokens</h4>
        <ul className="space-y-2">
          {Object.entries(report.tokens ?? {}).map(([api, token]) => (
            <li key={api} className="rounded-md border border-slate-800 p-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-slate-100">{API_LABELS[api] ?? api}</span>
                <Badge tone={TOKEN_TONE[token.status] ?? 'neutral'}>{humanize(token.status)}</Badge>
                {token.error && <span className="text-red-200">{humanize(token.error)}</span>}
                {token.aadsts ? <span className="text-xs text-slate-400">AADSTS{token.aadsts}</span> : null}
              </div>
              {token.hint && <p className="mt-1 text-xs text-amber-200">{token.hint}</p>}
              {token.roles && (
                <p className="mt-1 text-xs text-slate-400">
                  Roles in the token: {token.roles.length ? token.roles.join(', ') : noRoles}
                </p>
              )}
            </li>
          ))}
        </ul>
      </section>
      {report.certificate && (
        <p className="text-xs text-slate-300">
          Certificate {report.certificate.thumbprint_sha1} expires {formatDateTime(report.certificate.not_after)} (
          {report.certificate.days_left} days).
        </p>
      )}
      {capabilities.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left text-sm">
            <caption className="sr-only">Capabilities and permissions</caption>
            <thead className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th scope="col" className="px-3 py-2">Capability</th>
                <th scope="col" className="px-3 py-2">Status</th>
                <th scope="col" className="px-3 py-2">Permissions</th>
                <th scope="col" className="px-3 py-2">Checks</th>
              </tr>
            </thead>
            <tbody>
              {capabilities.map(([name, check]) => (
                <CapabilityRow key={name} name={name} check={check} />
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-slate-400">No capability is installed yet.</p>
      )}
    </div>
  );
}
