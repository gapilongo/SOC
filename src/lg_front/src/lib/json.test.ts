import { describe, expect, it } from 'vitest';

import { asObject, asObjectOrNull, isJsonObject, parseJsonObject } from './json';

const CASES: Array<[string, unknown, boolean]> = [
  ['an object', { a: 1 }, true],
  ['an empty object', {}, true],
  ['null', null, false],
  ['undefined', undefined, false],
  ['an array', [1, 2], false],
  ['a string', 'x', false],
  ['a number', 0, false],
  ['a boolean', true, false],
];

describe('json helpers', () => {
  it.each(CASES)('isJsonObject(%s) is %s', (_name, value, expected) => {
    expect(isJsonObject(value)).toBe(expected);
  });

  it.each(CASES)('asObject(%s) returns the object itself or {}', (_name, value, isObject) => {
    if (isObject) expect(asObject(value)).toBe(value);
    else expect(asObject(value)).toEqual({});
  });

  it.each(CASES)('asObjectOrNull(%s) returns the object itself or null', (_name, value, isObject) => {
    expect(asObjectOrNull(value)).toBe(isObject ? value : null);
  });

  it('asObject chains through missing levels', () => {
    expect(asObject(asObject({ a: { b: 1 } }).a).b).toBe(1);
    expect(asObject(asObject(undefined).a).b).toBeUndefined();
  });

  it.each([
    ['{"a": 1}', { a: 1 }],
    ['  {}  ', {}],
    ['{"nested": {"x": [1]}}', { nested: { x: [1] } }],
  ])('parseJsonObject(%s) parses an object', (text, expected) => {
    expect(parseJsonObject(text, 'Config')).toEqual(expected);
  });

  it.each(['[1]', 'null', '"text"', '42', 'true'])('parseJsonObject(%s) refuses a non-object with the exact message', (text) => {
    expect(() => parseJsonObject(text, 'Additional configuration')).toThrow(
      new Error('Additional configuration must be a JSON object.'),
    );
  });

  it('parseJsonObject keeps the parser error for invalid JSON', () => {
    expect(() => parseJsonObject('{nope', 'Config')).toThrow(SyntaxError);
  });
});
