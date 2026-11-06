#!/usr/bin/env node
// Coverage floors for the web app (roadmap FE1): fail when an area drops below its floor.
//
// Reads the json-summary report that `vitest run --coverage` writes (coverage/coverage-summary.json)
// and compares each area in coverage-floors.json with its floors. Floors only go up: when an area is
// comfortably above a floor, the output says so and the floor should be raised in the same PR.
// Lowering a floor needs code-owner review (.github/CODEOWNERS), like scripts/ci/coverage_floors.py.
//
//     node scripts/coverage-floors.mjs [coverage/coverage-summary.json]

import { readFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const METRICS = ['statements', 'branches', 'functions', 'lines'];
const RAISE_HINT_MARGIN = 2.0;

/** Sum the per-file counters of every file under `prefix` ('' = the whole app). */
export function areaCoverage(summary, prefix) {
  const totals = Object.fromEntries(METRICS.map((m) => [m, { covered: 0, total: 0 }]));
  let files = 0;
  for (const [name, data] of Object.entries(summary)) {
    if (name === 'total') continue;
    const rel = relative(ROOT, name).split('\\').join('/');
    if (!rel.startsWith(prefix)) continue;
    files += 1;
    for (const m of METRICS) {
      totals[m].covered += data[m].covered;
      totals[m].total += data[m].total;
    }
  }
  const pct = Object.fromEntries(
    METRICS.map((m) => [m, totals[m].total ? (100 * totals[m].covered) / totals[m].total : 100]),
  );
  return { pct, files };
}

/** Check every floor; returns the output lines and whether any floor failed. */
export function checkFloors(summary, floors) {
  const lines = [];
  let failed = false;
  for (const [area, areaFloors] of Object.entries(floors)) {
    if (area.startsWith('$')) continue; // "$comment"
    const prefix = area === 'all' ? '' : area;
    const { pct, files } = areaCoverage(summary, prefix);
    if (files === 0) {
      lines.push(`FAIL ${area}: no files in the report (was the folder moved? update coverage-floors.json)`);
      failed = true;
      continue;
    }
    for (const [metric, floor] of Object.entries(areaFloors)) {
      const value = pct[metric];
      const label = `${area} ${metric}`;
      if (value === undefined) {
        lines.push(`FAIL ${label}: unknown metric`);
        failed = true;
      } else if (value < floor) {
        lines.push(`FAIL ${label}: ${value.toFixed(2)}% is below its floor ${floor.toFixed(1)}%`);
        failed = true;
      } else if (value >= floor + RAISE_HINT_MARGIN) {
        lines.push(`ok   ${label}: ${value.toFixed(2)}% (floor ${floor.toFixed(1)}%; raise it to ${(value - 1).toFixed(1)})`);
      } else {
        lines.push(`ok   ${label}: ${value.toFixed(2)}% (floor ${floor.toFixed(1)}%)`);
      }
    }
  }
  return { lines, failed };
}

function main(argv) {
  const report = resolve(ROOT, argv[0] ?? 'coverage/coverage-summary.json');
  const summary = JSON.parse(readFileSync(report, 'utf8'));
  const floors = JSON.parse(readFileSync(resolve(ROOT, 'coverage-floors.json'), 'utf8'));
  const { lines, failed } = checkFloors(summary, floors);
  for (const line of lines) console.log(line);
  return failed ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv.slice(2)));
}
