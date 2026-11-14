import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { CaseAlertOut, CaseClosedByOut } from '../../api/types';
import { DECIDED_CASE, OPEN_CASE } from '../../../../test/caseReadModels';
import { AlertWhy, ClosedBy, CloserMark, auditWords, closerKind, closerLabel, closerOf, decisionWords, tierWords } from '.';

const alertOf = (id: string, model = OPEN_CASE): CaseAlertOut => model.alerts.find((a) => a.id === id) as CaseAlertOut;
const LINKED = alertOf('alr-48212');
const AUDITED = alertOf('alr-48190');
const ANALYST = alertOf('alr-47702');
const RULE = alertOf('alr-48226');
const CACHED = alertOf('alr-48231');
const THREAT = alertOf('alr-48213');
const WAITING = alertOf('alr-48214');
const RUNNING = alertOf('alr-48247');
const REOPENED = alertOf('alr-48212', DECIDED_CASE);

const closedBy = (overrides: Partial<CaseClosedByOut>): CaseClosedByOut => ({ ...(LINKED.closed_by as CaseClosedByOut), ...overrides });
const withheld: CaseAlertOut = {
  ...LINKED,
  role: 'withheld',
  hidden_for_blind_audit: true,
  closed_by: null,
  category: null,
  disposition: null,
  link: null,
  blind_audit: { state: 'pending', label: null, agrees: null, labelled_at: null },
};

const show = (ui: React.ReactElement) => render(<MemoryRouter>{ui}</MemoryRouter>);

describe('closerKind: the one mark of an alert', () => {
  it('names who closed a closed alert, from the close and the alert’s category', () => {
    expect(closerKind(LINKED)).toBe('ai_audit');
    expect(closerKind({ ...LINKED, category: 'ai_closed_evidence' })).toBe('ai_evidence');
    expect(closerKind({ ...LINKED, category: null })).toBe('ai');
    expect(closerKind(ANALYST)).toBe('analyst');
    expect(closerKind(RULE)).toBe('suppression_rule');
    expect(closerKind(CACHED)).toBe('cached_verdict');
    // Closed with no recorded closer, or by one a newer API names.
    expect(closerKind({ ...LINKED, closed_by: null })).toBe('closed');
    expect(closerOf(closedBy({ kind: 'closer_of_a_newer_release' }), null)).toBe('closed');
  });

  it('says where an alert stands while it is not closed, and withholds a blind-audit sample', () => {
    expect(closerKind(THREAT)).toBe('needs_decision');
    expect(closerKind({ ...THREAT, category: 'needs_review' })).toBe('needs_review');
    expect(closerKind(WAITING)).toBe('waiting_approval');
    expect(closerKind(RUNNING)).toBe('investigating');
    expect(closerKind(withheld)).toBe('withheld');
  });

  it('has words for every kind, and the mark carries them', () => {
    expect(closerLabel('ai_audit')).toBe("AI, on the model's word");
    const { container } = render(<CloserMark kind="suppression_rule" />);
    expect(container.querySelector('[data-closer="suppression_rule"]')).toHaveTextContent('Suppression rule');
    expect(container.querySelector('svg')).toHaveAttribute('aria-hidden', 'true');
  });
});

describe('the words of a close', () => {
  it('puts a decision, a tier and an audit result in words, and guesses none it does not know', () => {
    expect(decisionWords('benign_positive')).toBe('benign, expected here');
    expect(decisionWords('decision_of_a_newer_release')).toBe('decision of a newer release');
    expect(tierWords('auto_full_audit')).toMatch(/every such close is audited/);
    expect(tierWords('off')).toMatch(/not allowed/);
    expect(tierWords('tier_of_a_newer_release')).toBeNull();
    expect(tierWords(null)).toBeNull();
    expect(auditWords({ state: 'not_sampled', label: null, agrees: null })).toBeNull();
    expect(auditWords({ state: 'pending', label: null, agrees: null })).toBe('Blind audit: waits for its label');
    expect(auditWords({ state: 'labelled', label: 'benign', agrees: true })).toBe('Blind audit: labelled benign, agrees with the AI');
    expect(auditWords({ state: 'labelled', label: 'malicious', agrees: false })).toBe('Blind audit: labelled malicious, disagrees with the AI');
    expect(auditWords({ state: 'labelled', label: 'unsure', agrees: null })).toBe('Blind audit: labelled unsure');
    expect(auditWords({ state: 'labelled', label: null, agrees: null })).toBeNull();
  });
});

describe('ClosedBy', () => {
  it('an AI close on the model’s word: the mark, when, the Linked tag and the audit result', () => {
    const { container } = show(<ClosedBy alert={AUDITED} />);
    expect(container.querySelector('[data-closed-by]')).toHaveAttribute('data-closed-by', 'ai_audit');
    expect(screen.getByText("AI, on the model's word")).toBeInTheDocument();
    expect(screen.getByText(/^Closed /)).toBeInTheDocument();
    expect(screen.getByText('Linked')).toBeInTheDocument();
    expect(screen.getByText('Blind audit: labelled benign, agrees with the AI')).toBeInTheDocument();
  });

  it('an analyst close names the analyst: "you", the e-mail, a short id, or only "an analyst"', () => {
    const { rerender } = show(<ClosedBy alert={ANALYST} userId={ANALYST.closed_by?.analyst?.user_id} />);
    expect(screen.getByText(/· by you$/)).toBeInTheDocument();
    const again = (alert: CaseAlertOut) =>
      rerender(
        <MemoryRouter>
          <ClosedBy alert={alert} userId="someone-else" />
        </MemoryRouter>,
      );
    again(ANALYST);
    expect(screen.getByText(/· by ines\.moreau@brightwater\.example$/)).toBeInTheDocument();
    again({ ...ANALYST, closed_by: closedBy({ kind: 'analyst', analyst: { user_id: '5b0c7a52-6f0e-4c58', email: null } }) });
    expect(screen.getByText(/· by 5b0c7a52\.\.\.$/)).toBeInTheDocument();
    again({ ...ANALYST, closed_by: closedBy({ kind: 'analyst', analyst: null }) });
    expect(screen.getByText(/· by an analyst$/)).toBeInTheDocument();
  });

  it('a suppression rule is named as data, and an earlier verdict links to the alert that was decided', () => {
    show(<ClosedBy alert={RULE} />);
    expect(screen.getByText('rule “Defender definition updates”')).toBeInTheDocument();
    show(<ClosedBy alert={CACHED} />);
    expect(screen.getByRole('link', { name: 'alr-46011' })).toHaveAttribute('href', '/alerts/alr-46011');
  });

  it('an open alert shows where it stands and no close line; a reopened one says so', () => {
    const { container } = show(<ClosedBy alert={THREAT} />);
    expect(screen.getByText('Needs a decision: likely malicious')).toBeInTheDocument();
    expect(container).not.toHaveTextContent('Closed');
    show(<ClosedBy alert={REOPENED} />);
    expect(screen.getByText('Reopened')).toBeInTheDocument();
    expect(screen.getByText('Being investigated')).toBeInTheDocument();
  });

  it('a blind-audit sample shows that it is closed and nothing of who closed it', () => {
    const { container } = show(<ClosedBy alert={withheld} />);
    expect(screen.getByText('Withheld for the blind audit')).toBeInTheDocument();
    expect(container).not.toHaveTextContent('AI');
    expect(container).not.toHaveTextContent('Linked');
    expect(container).not.toHaveTextContent('Blind audit:');
  });
});

describe('AlertWhy', () => {
  const why = (alert: CaseAlertOut, caseId = OPEN_CASE.id) => show(<AlertWhy alert={alert} caseId={caseId} />).container;

  it('an AI close: the rule of the decision policy in the read model’s words, and the closure tier', () => {
    const cell = why(LINKED);
    expect(cell).toHaveTextContent(LINKED.closed_by?.policy?.sentence as string);
    expect(cell).toHaveTextContent('Closure tier when it was decided: the AI may close on the model’s word, and every such close is audited.');
    // Without a recorded rule the close reason is the sentence, and an unknown tier is not put in words.
    const bare = why({ ...LINKED, closed_by: closedBy({ policy: null, tier: null }) });
    expect(bare).toHaveTextContent(LINKED.closed_by?.reason.sentence as string);
    expect(bare).not.toHaveTextContent('Closure tier');
  });

  it('an analyst close: the decision, the note as the analyst wrote it, or the case that has it', () => {
    const elsewhere = why(ANALYST);
    expect(elsewhere).toHaveTextContent('An analyst decided it is real activity that is expected here. Decision: benign, expected here.');
    expect(within(elsewhere).getByRole('link', { name: 'another case' })).toHaveAttribute('href', '/cases/esc-2207');
    const threat = alertOf('alr-48213', DECIDED_CASE);
    const here = why(threat, DECIDED_CASE.id);
    expect(here.querySelector('q')).toHaveTextContent('The dump is visible in the process tree. Isolating the host.');
    expect(within(here).queryByRole('link')).toBeNull();
    // Decided on this case without a note: no quote, and no link to "another" case.
    const silent = why({ ...threat, closed_by: closedBy({ ...(threat.closed_by as CaseClosedByOut), notes: null }) }, DECIDED_CASE.id);
    expect(silent.querySelector('q')).toBeNull();
    expect(within(silent).queryByRole('link')).toBeNull();
  });

  it('an open alert: why it is with a person; a reopened one: what reopened it; a running one: nothing yet', () => {
    expect(why(THREAT)).toHaveTextContent('No automatic rule applies to this alert, so a person decides.');
    expect(why(REOPENED, DECIDED_CASE.id)).toHaveTextContent(/^A person confirmed a related threat/);
    expect(why(RUNNING)).toHaveTextContent('No decision yet: the investigation is still running.');
    expect(why({ ...LINKED, closed_by: null })).toHaveTextContent('The reason of this close is not recorded.');
  });

  it('a blind-audit sample: the reason is withheld with the verdict', () => {
    const cell = why(withheld);
    expect(cell).toHaveTextContent('This alert waits for its blind-audit label.');
    expect(cell).not.toHaveTextContent('model');
  });
});
