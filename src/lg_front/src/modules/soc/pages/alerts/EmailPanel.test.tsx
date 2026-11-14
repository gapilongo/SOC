import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { EmailPanel, emailSection, replyToMismatch, type EmailSection } from './EmailPanel';

const SECTION: EmailSection = {
  message_id: '<m1@examp1e.test>',
  subject: 'Verify your account',
  from: { address: 'it@examp1e.test', display_name: 'IT Support', domain: 'examp1e.test' },
  reply_to: ['collect@attacker.test'],
  return_path: null,
  recipient_count: 1,
  auth: [{ authserv_id: 'mx.example.com', spf: 'fail', dkim: 'pass', dmarc: 'fail' }],
  relay_ip: '203.0.113.7',
  urls: [
    { url: 'http://198.51.100.9/login', display: 'hxxp://198[.]51[.]100[.]9/login', mismatch: true, mismatch_text_host: 'login.example.com', ip_host: true },
    { url: 'https://login.example.com', display: 'hxxps://login[.]example[.]com', mismatch: false, display_only: true },
  ],
  url_count: 2,
  attachments: [{ filename: 'page.htm', sniffed_type: 'html', declared_type: 'text/html', size: 2048, sha256: 'a'.repeat(64), risks: ['html'] }],
  attachment_count: 1,
  reporter: 'bob@example.com',
  reporter_source: 'envelope',
  credential_wording: ['verify_account'],
};

describe('EmailPanel', () => {
  it('shows sender, authentication, defanged links with mismatch flags, attachment hashes and the reporter', () => {
    render(<EmailPanel section={SECTION} phishing={{ lookalikes: ['examp1e.test spells example.com with look-alike characters'] }} />);
    expect(screen.getByText('it@examp1e.test')).toBeTruthy();
    expect(screen.getByText('differs from sender')).toBeTruthy();
    expect(screen.getByText('SPF fail')).toBeTruthy();
    expect(screen.getByText('DKIM pass')).toBeTruthy();
    expect(screen.getByText('DMARC fail')).toBeTruthy();
    expect(screen.getByText('hxxp://198[.]51[.]100[.]9/login')).toBeTruthy();
    expect(screen.getByText('text shows login.example.com')).toBeTruthy();
    expect(screen.getByText('raw IP')).toBeTruthy();
    // The URL the deceiving link shows is listed, flagged as link text only.
    expect(screen.getByText('hxxps://login[.]example[.]com')).toBeTruthy();
    expect(screen.getAllByText('link text only')).toHaveLength(1);
    expect(screen.getByText(`SHA-256 ${'a'.repeat(64)}`)).toBeTruthy();
    expect(screen.getByText('bob@example.com')).toBeTruthy();
    expect(screen.getByText(/Lookalike domain: examp1e.test/)).toBeTruthy();
    // Links are never rendered as anchors.
    expect(document.querySelectorAll('a').length).toBe(0);
  });

  it('reads the section from a normalized alert and flags only Reply-To on another site', () => {
    expect(emailSection({ email: { subject: 'x' } })?.subject).toBe('x');
    expect(emailSection({ title: 'not an email' })).toBeNull();
    expect(replyToMismatch(SECTION)).toEqual(['collect@attacker.test']);
    expect(replyToMismatch({ ...SECTION, reply_to: ['help@mail.examp1e.test'] })).toEqual([]);
  });

  it('explains a message that could not be analysed', () => {
    render(<EmailPanel section={{ parse_error: 'message is larger than 10485760 bytes', reporter: 'bob@example.com' }} />);
    expect(screen.getByText(/could not be analysed: message is larger/)).toBeTruthy();
    expect(screen.getByText('No links.')).toBeTruthy();
  });
});
