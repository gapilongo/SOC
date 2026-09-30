import type { JsonObject } from '../../api/types';
import { Badge, type Tone } from '../../components/Badge';
import { DefinitionList } from '../../components/ui';

/** The parsed facts of a reported email (``CanonicalAlert.email``, written by the email normalizer). */
export interface EmailSection {
  message_id?: string | null;
  subject?: string;
  date?: string | null;
  from?: { address?: string; display_name?: string; domain?: string | null };
  reply_to?: string[];
  return_path?: string | null;
  recipients?: string[];
  recipient_count?: number;
  auth?: JsonObject[];
  relay_ip?: string | null;
  relay_host?: string | null;
  urls?: Array<{ url?: string; display?: string; host?: string; mismatch?: boolean; mismatch_text_host?: string; ip_host?: boolean; shortener?: boolean; punycode?: boolean; source?: string }>;
  url_count?: number;
  attachments?: Array<{ filename?: string; declared_type?: string; sniffed_type?: string; size?: number; sha256?: string; risks?: string[] }>;
  attachment_count?: number;
  reporter?: string | null;
  reporter_source?: string | null;
  credential_wording?: string[];
  parse_error?: string;
}

function obj(value: unknown): JsonObject | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as JsonObject) : null;
}

/** The email section of a normalized alert, or null for alerts that are not emails. */
export function emailSection(normalized: JsonObject | null | undefined): EmailSection | null {
  const section = obj(normalized?.email);
  return section ? (section as unknown as EmailSection) : null;
}

function siteOf(domain: string): string {
  const labels = domain.toLowerCase().split('.').filter(Boolean);
  return labels.slice(-2).join('.');
}

function domainOf(address: string | null | undefined): string {
  return address && address.includes('@') ? address.split('@').pop() ?? '' : '';
}

/** Reply-To addresses on another site than the sender (where answers to the message would go). */
export function replyToMismatch(section: EmailSection): string[] {
  const from = section.from?.domain ?? domainOf(section.from?.address);
  if (!from) return [];
  return (section.reply_to ?? []).filter((a) => domainOf(a) && siteOf(domainOf(a)) !== siteOf(from));
}

const VERDICT_TONE: Record<string, Tone> = { pass: 'good', fail: 'bad', softfail: 'warn', hardfail: 'bad', none: 'neutral', neutral: 'neutral' };

function AuthBadges({ result }: { result: JsonObject | undefined }) {
  if (!result) return <span className="text-slate-400">No Authentication-Results header</span>;
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      {(['spf', 'dkim', 'dmarc'] as const).map((method) => {
        const verdict = typeof result[method] === 'string' ? (result[method] as string) : 'missing';
        return (
          <Badge key={method} tone={VERDICT_TONE[verdict] ?? 'warn'}>
            {method.toUpperCase()} {verdict}
          </Badge>
        );
      })}
      {typeof result.authserv_id === 'string' && <span className="text-xs text-slate-400">by {result.authserv_id}</span>}
    </span>
  );
}

function formatBytes(size: number | undefined): string {
  if (typeof size !== 'number') return '-';
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

export function EmailPanel({ section, phishing }: { section: EmailSection; phishing?: JsonObject | null }) {
  const sender = section.from ?? {};
  const mismatched = replyToMismatch(section);
  const urls = section.urls ?? [];
  const attachments = section.attachments ?? [];
  const lookalikes = Array.isArray(phishing?.lookalikes) ? (phishing?.lookalikes as string[]) : [];
  const impersonation = typeof phishing?.impersonation === 'string' ? phishing.impersonation : null;
  return (
    <div className="space-y-4 text-sm">
      {section.parse_error && (
        <p className="rounded border border-amber-700 bg-amber-950 px-3 py-2 text-amber-100">
          The reported message could not be analysed: {section.parse_error}
        </p>
      )}
      <DefinitionList
        items={[
          [
            'Sender',
            <span key="sender" className="break-all">
              {sender.display_name ? `"${sender.display_name}" ` : ''}
              <code className="text-xs">{sender.address || 'unknown'}</code>
            </span>,
          ],
          [
            'Reply-To',
            section.reply_to && section.reply_to.length ? (
              <span key="reply" className="flex flex-wrap items-center gap-1.5 break-all">
                {section.reply_to.map((a) => (
                  <code key={a} className="text-xs">
                    {a}
                  </code>
                ))}
                {mismatched.length > 0 && <Badge tone="bad">differs from sender</Badge>}
              </span>
            ) : (
              '-'
            ),
          ],
          ['Return-Path', section.return_path ? <code key="rp" className="break-all text-xs">{section.return_path}</code> : '-'],
          ['Authentication', <AuthBadges key="auth" result={section.auth?.[0]} />],
          ['Relay', section.relay_ip ? `${section.relay_ip}${section.relay_host ? ` (${section.relay_host})` : ''}` : '-'],
          ['Subject', section.subject || '(no subject)'],
          ['Recipients', typeof section.recipient_count === 'number' ? String(section.recipient_count) : '-'],
          ['Reported by', section.reporter ? `${section.reporter}${section.reporter_source === 'param' ? ' (stated by the API client)' : ''}` : '-'],
          ['Message-ID', section.message_id ? <code key="mid" className="break-all text-xs">{section.message_id}</code> : '-'],
        ]}
      />
      {(lookalikes.length > 0 || impersonation) && (
        <ul className="list-disc space-y-1 pl-5 text-orange-200">
          {impersonation && <li>Impersonation: {impersonation}</li>}
          {lookalikes.map((l) => (
            <li key={l}>Lookalike domain: {l}</li>
          ))}
        </ul>
      )}
      {section.credential_wording && section.credential_wording.length > 0 && (
        <p className="text-slate-300">
          <span className="text-slate-400">Credential-harvest wording: </span>
          {section.credential_wording.map((w) => w.replace(/_/g, ' ')).join(', ')}
        </p>
      )}
      <section>
        <h4 className="mb-1 font-medium text-slate-100">
          Links ({typeof section.url_count === 'number' ? section.url_count : urls.length})
        </h4>
        {urls.length === 0 ? (
          <p className="text-slate-400">No links.</p>
        ) : (
          <ul className="space-y-1.5">
            {urls.map((u, i) => (
              <li key={`${u.url ?? ''}-${i}`} className="flex flex-wrap items-center gap-1.5">
                <code className="max-w-full break-all rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-100" title="Defanged: not clickable">
                  {u.display ?? u.url}
                </code>
                {u.mismatch && <Badge tone="bad">text shows {u.mismatch_text_host ?? 'another domain'}</Badge>}
                {u.ip_host && <Badge tone="bad">raw IP</Badge>}
                {u.shortener && <Badge tone="warn">shortener</Badge>}
                {u.punycode && <Badge tone="warn">punycode</Badge>}
                {u.source && u.source !== 'body' && <Badge>{u.source.replace(/_/g, ' ')}</Badge>}
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <h4 className="mb-1 font-medium text-slate-100">
          Attachments ({typeof section.attachment_count === 'number' ? section.attachment_count : attachments.length})
        </h4>
        {attachments.length === 0 ? (
          <p className="text-slate-400">No attachments.</p>
        ) : (
          <ul className="space-y-2">
            {attachments.map((a, i) => (
              <li key={`${a.sha256 ?? ''}-${i}`}>
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="break-all font-medium text-slate-100">{a.filename || '(unnamed)'}</span>
                  <span className="text-xs text-slate-400">
                    {a.sniffed_type ?? 'unknown'} content, declared {a.declared_type ?? '-'}, {formatBytes(a.size)}
                  </span>
                  {(a.risks ?? []).map((r) => (
                    <Badge key={r} tone="bad">
                      {r.replace(/_/g, ' ')}
                    </Badge>
                  ))}
                </div>
                {a.sha256 && <code className="block break-all text-xs text-slate-300">SHA-256 {a.sha256}</code>}
              </li>
            ))}
          </ul>
        )}
        <p className="mt-1 text-xs text-slate-400">Attachments are hashed and inspected, never stored.</p>
      </section>
    </div>
  );
}
