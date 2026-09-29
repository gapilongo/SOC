import { useQuery } from '@tanstack/react-query';
import { Download } from 'lucide-react';
import { useMemo, useState } from 'react';

import { endpoints } from '../api/endpoints';
import type { UsageDayOut } from '../api/types';
import { useApi } from '../auth/AuthContext';
import { Button, Card, EmptyState, ErrorMessage, LoadingState, PageHeader, TextField } from '../components/ui';
import { csvFilename, downloadCsv, toCsv, type CsvColumn } from '../lib/csv';
import { formatInt, formatUsd } from '../lib/format';

function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}

export interface DayTotal {
  day: string;
  cost: number;
  calls: number;
  tokens: number;
}

/** Sum usage rows per day (every model and agent), filling days without usage with zero. */
export function dailyTotals(rows: UsageDayOut[], from: string, to: string): DayTotal[] {
  const map = new Map<string, DayTotal>();
  const start = new Date(`${from}T00:00:00Z`);
  const end = new Date(`${to}T00:00:00Z`);
  for (let d = start; d <= end && map.size < 400; d = new Date(d.getTime() + 86_400_000)) {
    map.set(isoDay(d), { day: isoDay(d), cost: 0, calls: 0, tokens: 0 });
  }
  for (const r of rows) {
    const day = r.day.slice(0, 10);
    const t = map.get(day) ?? { day, cost: 0, calls: 0, tokens: 0 };
    t.cost += Number(r.cost_usd) || 0;
    t.calls += r.calls;
    t.tokens += r.input_tokens + r.output_tokens;
    map.set(day, t);
  }
  return [...map.values()].sort((a, b) => a.day.localeCompare(b.day));
}

/** Single-series daily cost bars with a hover/focus tooltip; the table below carries the same data. */
function CostChart({ days }: { days: DayTotal[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const width = 800;
  const height = 220;
  const pad = { l: 56, r: 8, t: 12, b: 28 };
  const max = Math.max(0.01, ...days.map((d) => d.cost));
  const plotW = width - pad.l - pad.r;
  const plotH = height - pad.t - pad.b;
  const step = plotW / Math.max(1, days.length);
  const barW = Math.max(1, step - 2);
  const ticks = [0, 0.5, 1].map((f) => f * max);
  const labelEvery = Math.ceil(days.length / 8);
  const active = hover !== null ? days[hover] : null;
  return (
    <figure>
      <svg viewBox={`0 0 ${width} ${height}`} className="h-auto w-full" role="img" aria-label={`Daily LLM cost, ${days.length} days, peak ${formatUsd(max)}`}>
        {ticks.map((t) => {
          const y = pad.t + plotH - (t / max) * plotH;
          return (
            <g key={t}>
              <line x1={pad.l} x2={width - pad.r} y1={y} y2={y} stroke="#334155" strokeWidth={1} />
              <text x={pad.l - 6} y={y + 4} textAnchor="end" fontSize={11} fill="#94a3b8">
                {formatUsd(t)}
              </text>
            </g>
          );
        })}
        {days.map((d, i) => {
          const h = (d.cost / max) * plotH;
          const x = pad.l + i * step + 1;
          return (
            <g key={d.day}>
              <rect
                x={x}
                y={pad.t + plotH - h}
                width={barW}
                height={Math.max(0, h)}
                rx={Math.min(4, barW / 2)}
                fill={hover === i ? '#7dd3fc' : '#0ea5e9'}
              />
              <rect
                x={pad.l + i * step}
                y={pad.t}
                width={step}
                height={plotH}
                fill="transparent"
                onMouseEnter={() => setHover(i)}
                onMouseLeave={() => setHover(null)}
              />
              {i % labelEvery === 0 && (
                <text x={x + barW / 2} y={height - 8} textAnchor="middle" fontSize={11} fill="#94a3b8">
                  {d.day.slice(5)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <figcaption className="mt-1 min-h-[1.25rem] text-xs text-slate-300" aria-live="polite">
        {active ? `${active.day}: ${formatUsd(active.cost)}, ${formatInt(active.calls)} calls, ${formatInt(active.tokens)} tokens` : 'Hover a bar for the day total. The table below lists every row.'}
      </figcaption>
    </figure>
  );
}

const CSV: CsvColumn<UsageDayOut>[] = [
  { header: 'day', value: (r) => r.day },
  { header: 'model', value: (r) => r.model },
  { header: 'agent', value: (r) => r.agent },
  { header: 'calls', value: (r) => r.calls },
  { header: 'input_tokens', value: (r) => r.input_tokens },
  { header: 'output_tokens', value: (r) => r.output_tokens },
  { header: 'cache_read_tokens', value: (r) => r.cache_read_tokens },
  { header: 'cache_write_tokens', value: (r) => r.cache_write_tokens },
  { header: 'cost_usd', value: (r) => Number(r.cost_usd) },
  { header: 'refusals', value: (r) => r.refusals },
  { header: 'errors', value: (r) => r.errors },
];

export default function UsagePage() {
  const api = useApi();
  const today = new Date();
  const [from, setFrom] = useState(isoDay(new Date(today.getTime() - 29 * 86_400_000)));
  const [to, setTo] = useState(isoDay(today));
  const q = useQuery({
    queryKey: ['usage', from, to],
    queryFn: ({ signal }) => endpoints.llmUsage(api, from, to, signal),
    enabled: Boolean(from && to && from <= to),
  });
  const days = useMemo(() => (q.data ? dailyTotals(q.data.days, from, to) : []), [q.data, from, to]);
  return (
    <>
      <PageHeader
        title="LLM usage"
        description="Model calls, tokens and cost for this tenant by day, model and agent."
        actions={
          <Button onClick={() => q.data && downloadCsv(csvFilename('llm-usage'), toCsv(CSV, q.data.days))} disabled={!q.data?.days.length} icon={<Download className="h-4 w-4" aria-hidden="true" />}>
            Export CSV
          </Button>
        }
      />
      <div className="mb-4 flex flex-wrap gap-3">
        <TextField label="From" type="date" value={from} max={to} onChange={(e) => setFrom(e.target.value)} />
        <TextField label="To" type="date" value={to} min={from} onChange={(e) => setTo(e.target.value)} />
      </div>
      {q.isPending && q.fetchStatus !== 'idle' && <LoadingState label="Loading usage" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {q.data && (
        <div className="space-y-5">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {[
              ['Total cost', formatUsd(q.data.total_cost_usd)],
              ['Calls', formatInt(q.data.total_calls)],
              ['Input tokens', formatInt(q.data.total_input_tokens)],
              ['Output tokens', formatInt(q.data.total_output_tokens)],
            ].map(([label, value]) => (
              <div key={label} className="rounded-lg border border-slate-800 bg-slate-900 p-4">
                <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
                <div className="mt-1 text-2xl font-semibold tabular-nums text-white">{value}</div>
              </div>
            ))}
          </div>
          <Card title="Daily cost (USD)">{days.length ? <CostChart days={days} /> : <EmptyState title="No days in range" />}</Card>
          <Card title="Usage by day, model and agent">
            {q.data.days.length === 0 ? (
              <EmptyState title="No LLM usage in this range" />
            ) : (
              <div className="max-h-[28rem] overflow-auto">
                <table className="w-full min-w-[720px] text-left text-sm">
                  <caption className="sr-only">LLM usage rows</caption>
                  <thead className="sticky top-0 bg-slate-900 text-xs uppercase tracking-wide text-slate-400">
                    <tr>
                      <th scope="col" className="py-2 pr-3">Day</th>
                      <th scope="col" className="py-2 pr-3">Model</th>
                      <th scope="col" className="py-2 pr-3">Agent</th>
                      <th scope="col" className="py-2 pr-3 text-right">Calls</th>
                      <th scope="col" className="py-2 pr-3 text-right">Tokens in / out</th>
                      <th scope="col" className="py-2 pr-3 text-right">Refusals / errors</th>
                      <th scope="col" className="py-2 text-right">Cost</th>
                    </tr>
                  </thead>
                  <tbody>
                    {q.data.days.map((r) => (
                      <tr key={`${r.day}-${r.model}-${r.agent}`} className="border-t border-slate-800 tabular-nums">
                        <td className="py-1.5 pr-3 text-slate-200">{r.day}</td>
                        <td className="py-1.5 pr-3 text-slate-200">{r.model}</td>
                        <td className="py-1.5 pr-3 text-slate-300">{r.agent}</td>
                        <td className="py-1.5 pr-3 text-right">{formatInt(r.calls)}</td>
                        <td className="py-1.5 pr-3 text-right">
                          {formatInt(r.input_tokens)} / {formatInt(r.output_tokens)}
                        </td>
                        <td className="py-1.5 pr-3 text-right">
                          {formatInt(r.refusals)} / {formatInt(r.errors)}
                        </td>
                        <td className="py-1.5 text-right">{formatUsd(r.cost_usd)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
