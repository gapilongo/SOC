/**
 * Readers for what the workflow writes into `alert.summary`, for the list
 * rows and the alert panel. The summary is free-form JSON that grew over
 * releases, so every reader tolerates absent or malformed parts.
 *
 * Keys read here (see src/lg_sotf/core/nodes.py): `analysis` (verdict,
 * conclusion, `simulated_evidence`, `tools[].simulated`), `verdict` and
 * `dry_run` / `simulated_evidence` written at close, and `escalation_id`.
 */

import { finite, text } from '../../api/fields';
import type { AlertDetailOut, AlertOut, FindingOut, JsonObject } from '../../api/types';
import { asObjectOrNull } from '../../../../lib/json';

type Rec = Record<string, unknown>;

function records(value: unknown): Rec[] {
  return Array.isArray(value) ? value.map(asObjectOrNull).filter((r): r is Rec => r !== null) : [];
}

/** The AI's verdict (the analysis while open, the disposition once closed) and the triage confidence (0-100). */
export function aiVerdict(alert: Pick<AlertOut, 'summary' | 'disposition' | 'confidence'>): { verdict: string | null; confidence: number | null } {
  const summary = asObjectOrNull(alert.summary);
  const analysis = asObjectOrNull(summary?.analysis);
  const verdict = text(analysis?.verdict) ?? text(summary?.verdict) ?? text(alert.disposition);
  const confidence = finite(alert.confidence);
  return { verdict, confidence: confidence === null ? null : Math.round(confidence) };
}

/** The escalation this alert raised (or was attached to), from the summary; null when none. */
export function escalationIdOf(alert: Pick<AlertOut, 'summary'>): string | null {
  return text(asObjectOrNull(alert.summary)?.escalation_id);
}

export interface EvidenceFlags {
  /** Some evidence came from a simulated provider (a test fixture), not a live lookup. */
  simulated: boolean;
  /** The providers that were simulated, when the data names them. */
  simulatedSources: string[];
  /** Response actions ran as a dry run: recorded, nothing changed in the tenant's systems. */
  dryRun: boolean;
}

/**
 * Whether the evidence or the response of this alert was not real. Every
 * place the workflow has recorded it counts: the close summary, the analysis
 * digest, each lookup (`tools[].simulated`) and the finding data.
 */
export function evidenceFlags(alert: Pick<AlertDetailOut, 'summary' | 'findings'>): EvidenceFlags {
  const summary = asObjectOrNull(alert.summary);
  const analysis = asObjectOrNull(summary?.analysis);
  const sources = new Set<string>();
  for (const tool of records(analysis?.tools)) {
    if (tool.simulated !== true) continue;
    const named = text(tool.source) ?? text(tool.provider);
    if (named) sources.add(named);
    for (const result of records(tool.results)) {
      const source = text(result.source);
      if (source) sources.add(source);
    }
  }
  const findings: FindingOut[] = Array.isArray(alert.findings) ? alert.findings : [];
  for (const f of findings) {
    if (asObjectOrNull(f?.data)?.simulated === true && text(f.source)) sources.add(f.source);
  }
  const simulated = summary?.simulated_evidence === true || analysis?.simulated_evidence === true || sources.size > 0;
  return { simulated, simulatedSources: [...sources].sort(), dryRun: summary?.dry_run === true };
}

/** A finding was served from a simulated provider. */
export function isSimulatedFinding(f: FindingOut): boolean {
  return asObjectOrNull(f.data as JsonObject | undefined)?.simulated === true;
}

const STATUS_WORDS: Record<string, string> = {
  new: 'New',
  queued: 'Queued',
  processing: 'Processing',
  waiting_human: 'Waiting for an analyst',
  waiting_approval: 'Waiting for approval',
  closed: 'Closed',
  failed: 'Failed',
};

/** The alert status in words ("Waiting for an analyst"). */
export function statusWords(status: string): string {
  return STATUS_WORDS[status] ?? status.replace(/_/g, ' ');
}

const STATUS_SHORT: Record<string, string> = {
  waiting_human: 'Needs analyst',
  waiting_approval: 'Awaiting approval',
};

/** The status for a table cell: the view tab's words where the full ones are long ("Needs analyst"). */
export function statusShort(status: string): string {
  return STATUS_SHORT[status] ?? statusWords(status);
}

const KIND_WORDS: Record<string, string> = { ip: 'IP', url: 'URL', email: 'E-mail', hash: 'File hash' };

/** An entity or lookup kind in words ("IP", "Domain"). */
export function kindWords(kind: string): string {
  return KIND_WORDS[kind] ?? kind.charAt(0).toUpperCase() + kind.slice(1).replace(/_/g, ' ');
}

/** The finding's origin in words. */
export function originWords(origin: FindingOut['origin']): string {
  return origin === 'history' ? 'Your history' : 'Threat intel';
}
