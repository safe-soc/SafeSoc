/**
 * SafeSOC — Severity Distribution Chart
 * Renders GET /api/v1/alerts/summary's severity breakdown — a backend
 * aggregation over the SAME tenant+time-window population the
 * dashboard's "Total Alerts" KPI counts, not a client-side tally of a
 * single fetched page of documents (that page is capped at 500 by
 * GET /api/v1/alerts' `size` limit, which silently undercounted once
 * total alerts exceeded it).
 */

import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';
import Spinner from '../Spinner';
import { SEVERITIES, type AlertSeveritySummary } from '../../lib/types';
import ChartCard from './ChartCard';

const COLORS: Record<string, string> = {
  low: '#94a3b8',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
};

export default function SeverityDistributionChart({ summary }: { summary: AlertSeveritySummary | null }) {
  const total = summary?.total ?? 0;
  const bySeverity = summary?.by_severity ?? {};

  // Preserve the low->critical ordering regardless of bucket order returned
  // by the backend; only include severities actually present in the window.
  const counts = SEVERITIES.map((severity) => ({
    name: severity,
    value: bySeverity[severity] ?? 0,
  })).filter((entry) => entry.value > 0);

  // Buckets not recognized as one of the 4 known severities (shouldn't
  // occur — NormalizedLog validation rejects anything else at ingestion —
  // but surfaced rather than silently dropped if it ever does).
  const unknownCount = Object.entries(bySeverity)
    .filter(([key]) => !SEVERITIES.includes(key as (typeof SEVERITIES)[number]))
    .reduce((sum, [, value]) => sum + (value ?? 0), 0);

  return (
    <ChartCard title="Severity Distribution" subtitle={`${total} alert${total === 1 ? '' : 's'} in window`}>
      {summary === null ? (
        <div className="flex h-56 items-center justify-center">
          <Spinner className="h-5 w-5 text-slate-600" />
        </div>
      ) : counts.length === 0 ? (
        <div className="flex h-56 items-center justify-center text-sm text-slate-500">No alerts in this window.</div>
      ) : (
        <div className="flex items-center gap-4">
          <ResponsiveContainer width="55%" height={200}>
            <PieChart>
              <Pie data={counts} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2}>
                {counts.map((entry) => (
                  <Cell key={entry.name} fill={COLORS[entry.name]} stroke="#0f172a" strokeWidth={2} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: '#cbd5e1' }}
              />
            </PieChart>
          </ResponsiveContainer>
          <ul className="flex-1 space-y-2">
            {counts.map((entry) => (
              <li key={entry.name} className="flex items-center justify-between text-sm">
                <span className="flex items-center gap-2 capitalize text-slate-300">
                  <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: COLORS[entry.name] }} />
                  {entry.name}
                </span>
                <span className="font-medium tabular-nums text-slate-100">
                  {entry.value} <span className="text-slate-500">({Math.round((entry.value / total) * 100)}%)</span>
                </span>
              </li>
            ))}
            {unknownCount > 0 && (
              <li className="flex items-center justify-between text-sm">
                <span className="flex items-center gap-2 capitalize text-slate-400">
                  <span className="h-2.5 w-2.5 rounded-full bg-slate-600" />
                  Unrecognized
                </span>
                <span className="font-medium tabular-nums text-slate-100">{unknownCount}</span>
              </li>
            )}
          </ul>
        </div>
      )}
    </ChartCard>
  );
}
