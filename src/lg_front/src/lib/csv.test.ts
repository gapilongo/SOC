import { describe, expect, it } from 'vitest';

import { escapeCsvCell, toCsv } from './csv';

describe('CSV export', () => {
  it('quotes separators, quotes and line breaks (RFC 4180)', () => {
    expect(escapeCsvCell('plain')).toBe('plain');
    expect(escapeCsvCell('a,b')).toBe('"a,b"');
    expect(escapeCsvCell('say "hi"')).toBe('"say ""hi"""');
    expect(escapeCsvCell('line1\nline2')).toBe('"line1\nline2"');
    expect(escapeCsvCell('cr\rhere')).toBe('"cr\rhere"');
  });

  it('neutralises spreadsheet formulas in text cells', () => {
    expect(escapeCsvCell('=HYPERLINK("http://evil","x")')).toBe(`"'=HYPERLINK(""http://evil"",""x"")"`);
    expect(escapeCsvCell('+1+1')).toBe("'+1+1");
    expect(escapeCsvCell('-2+3')).toBe("'-2+3");
    expect(escapeCsvCell('@SUM(A1)')).toBe("'@SUM(A1)");
    expect(escapeCsvCell('\tcmd')).toBe("'\tcmd");
    expect(escapeCsvCell('  =cmd|calc')).toBe("'  =cmd|calc");
    expect(escapeCsvCell('a=b')).toBe('a=b');
  });

  it('writes numbers, booleans, empty values and objects safely', () => {
    expect(escapeCsvCell(-5)).toBe('-5');
    expect(escapeCsvCell(3.5)).toBe('3.5');
    expect(escapeCsvCell(Number.NaN)).toBe('');
    expect(escapeCsvCell(true)).toBe('true');
    expect(escapeCsvCell(null)).toBe('');
    expect(escapeCsvCell(undefined)).toBe('');
    expect(escapeCsvCell({ a: 1, b: 'x' })).toBe('"{""a"":1,""b"":""x""}"');
  });

  it('builds a document with a header row and CRLF line endings', () => {
    const rows = [
      { id: 'a1', title: 'Brute force, admin', score: 80 },
      { id: 'a2', title: '=cmd', score: null },
    ];
    const csv = toCsv(
      [
        { header: 'id', value: (r: (typeof rows)[number]) => r.id },
        { header: 'title', value: (r: (typeof rows)[number]) => r.title },
        { header: 'score', value: (r: (typeof rows)[number]) => r.score },
      ],
      rows,
    );
    expect(csv).toBe('id,title,score\r\na1,"Brute force, admin",80\r\na2,\'=cmd,\r\n');
  });
});
