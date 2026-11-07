/**
 * File downloads: the one place that creates object URLs (ESLint bans `URL.createObjectURL`
 * elsewhere), so every download gets the same safe filename and URL revocation.
 */

/** Keep only characters that are safe in a filename on every platform. */
export function safeFilename(name: string): string {
  return name.replace(/[^A-Za-z0-9._-]/g, '_');
}

export function downloadBlob(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = safeFilename(filename);
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

/**
 * Save `text` as a file. CSV (`text/csv…`) gets a UTF-8 byte-order mark so spreadsheet apps
 * detect the encoding; every other type is written as is.
 */
export function downloadText(filename: string, text: string, type = 'text/plain;charset=utf-8'): void {
  const parts = type.startsWith('text/csv') ? ['\uFEFF', text] : [text];
  downloadBlob(filename, new Blob(parts, { type }));
}

/**
 * Open an HTML document (a Blob of API output) in a new tab. The document is
 * rendered as its own page, never injected into the app; the object URL is
 * revoked once the tab has had time to load it.
 */
export function openHtmlBlob(blob: Blob): void {
  const html = blob.type.startsWith('text/html') ? blob : new Blob([blob], { type: 'text/html' });
  const url = URL.createObjectURL(html);
  window.open(url, '_blank', 'noopener');
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

/** `20260930T101500Z`-style UTC stamp for filenames. */
export function fileStamp(now: Date = new Date()): string {
  return now.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
}
