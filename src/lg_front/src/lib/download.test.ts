import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { csvFilename, downloadCsv } from './csv';
import { downloadBlob, downloadText, fileStamp, openHtmlBlob, safeFilename } from './download';

/** Every helper builds an object URL, clicks a hidden link (or opens a tab) and revokes the URL later. */
describe('download helpers', () => {
  let created: Blob[];
  let clicked: HTMLAnchorElement[];
  const revoke = vi.fn();

  beforeEach(() => {
    vi.useFakeTimers();
    created = [];
    clicked = [];
    revoke.mockReset();
    URL.createObjectURL = vi.fn((b: Blob | MediaSource) => {
      created.push(b as Blob);
      return `blob:test/${created.length}`;
    });
    URL.revokeObjectURL = revoke;
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push(this);
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  function expectRevokedAfter(ms: number, url: string): void {
    vi.advanceTimersByTime(ms - 1);
    expect(revoke).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(revoke).toHaveBeenCalledWith(url);
  }

  it('safeFilename keeps only portable characters', () => {
    expect(safeFilename('report 2026/09:30 ü.pdf')).toBe('report_2026_09_30__.pdf');
  });

  it('fileStamp is a compact UTC stamp', () => {
    expect(fileStamp(new Date('2026-09-30T10:15:00.123Z'))).toBe('20260930T101500Z');
  });

  it('downloadBlob clicks a detached link with a safe name and revokes the URL', () => {
    downloadBlob('pack/alert 1.zip', new Blob(['x']));
    expect(clicked).toHaveLength(1);
    expect(clicked[0].download).toBe('pack_alert_1.zip');
    expect(clicked[0].rel).toBe('noopener');
    expect(clicked[0].isConnected).toBe(false);
    expectRevokedAfter(1_000, 'blob:test/1');
  });

  it('openHtmlBlob opens HTML in a new tab and coerces other types to text/html', () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    openHtmlBlob(new Blob(['<p>hi</p>'], { type: 'application/octet-stream' }));
    expect(created[0].type).toBe('text/html');
    expect(open).toHaveBeenCalledWith('blob:test/1', '_blank', 'noopener');
    expectRevokedAfter(60_000, 'blob:test/1');
  });

  it('openHtmlBlob keeps a blob that is already HTML', () => {
    vi.spyOn(window, 'open').mockReturnValue(null);
    const html = new Blob(['<p>hi</p>'], { type: 'text/html;charset=utf-8' });
    openHtmlBlob(html);
    expect(created[0]).toBe(html);
  });

  it('downloadCsv adds a BOM and a safe filename', () => {
    downloadCsv('alerts list.csv', 'a,b\r\n');
    expect(created[0].type).toBe('text/csv;charset=utf-8');
    expect(created[0].size).toBe(3 + 'a,b\r\n'.length); // UTF-8 BOM is 3 bytes
    expect(clicked[0].download).toBe('alerts_list.csv');
    expectRevokedAfter(1_000, 'blob:test/1');
  });

  it('csvFilename stamps the prefix in UTC', () => {
    expect(csvFilename('alerts', new Date('2026-09-30T10:15:00.123Z'))).toBe('alerts-2026-09-30T101500Z.csv');
  });

  it('downloadText adds a BOM only for CSV', () => {
    downloadText('r.csv', 'x', 'text/csv');
    downloadText('r.json', 'x', 'application/json');
    expect(created[0].size).toBe(4);
    expect(created[1].size).toBe(1);
    expect(created[1].type).toBe('application/json');
    expect(clicked.map((a) => a.download)).toEqual(['r.csv', 'r.json']);
    vi.advanceTimersByTime(1_000);
    expect(revoke).toHaveBeenCalledTimes(2);
  });

  it('downloadText defaults to UTF-8 plain text and sanitises the filename', () => {
    downloadText('recovery codes.txt', 'abcd-efgh\n');
    expect(created[0].type).toBe('text/plain;charset=utf-8');
    expect(created[0].size).toBe('abcd-efgh\n'.length); // no byte-order mark
    expect(clicked[0].download).toBe('recovery_codes.txt');
    expectRevokedAfter(1_000, 'blob:test/1');
  });
});
