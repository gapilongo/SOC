/**
 * Narrowing helpers for loosely typed JSON (alert summaries, integration configs, settings documents).
 *
 * The API returns open `JsonObject` documents; these helpers read nested objects without a cast at
 * every call site. A "JSON object" is a non-null, non-array object.
 */
import type { JsonObject } from '../api/types';

export function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** `value` when it is a JSON object, otherwise an empty object (safe to spread or index). */
export function asObject(value: unknown): JsonObject {
  return isJsonObject(value) ? value : {};
}

/** `value` when it is a JSON object, otherwise `null` (for "is the section present" checks). */
export function asObjectOrNull(value: unknown): JsonObject | null {
  return isJsonObject(value) ? value : null;
}

/**
 * Parse a textarea of JSON that must be an object. Invalid JSON raises the parser's `SyntaxError`
 * (its position helps the user); valid JSON that is not an object raises
 * `"<what> must be a JSON object."`.
 */
export function parseJsonObject(text: string, what: string): JsonObject {
  const parsed = JSON.parse(text) as unknown;
  if (!isJsonObject(parsed)) throw new Error(`${what} must be a JSON object.`);
  return parsed;
}
