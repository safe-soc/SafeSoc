/**
 * SafeSOC — Threat Analytics Dashboard (SS-112)
 * Renders GET /api/v1/threat-analytics' rollup: current vs. previous
 * window counts per correlation-pattern category, with MITRE ATT&CK
 * annotation. Visual language matches Dashboard.tsx's existing
 * charts/widgets (ChartCard shell, same color palette).
 */

import { useEffect, useState } from 'react';
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import Layout from '../components/Layout';
import PageHeader from '../components/PageHeader';
import ChartCard from '../components/dashboard/ChartCard';
import { titleCase } from '../lib/format';
import { api } from '../lib/api';
import type { CategoryTrend, ThreatAnalyticsResponse } from '../lib/types';

const WINDOW_OPTIONS = [7, 14, 30, 90];

const selectClasses =
  'rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500';

function formatChangePct(trend: CategoryTrend): string {
  if (trend.change_pct === null) return trend.current_count > 0 ? 'new' : '—';
  const sign = trend.change_pct > 0 ? '+' : '';
  return `${sign}${trend.change_pct}%`;
}

function changeTone(trend: CategoryTrend): string {
  if (trend.change_pct === null) return trend.current_count > 0 ? 'text-blue-400' : 'text-slate-500';
  if (trend.change_pct > 0) return 'text-red-400';
  if (trend.change_pct < 0) return 'text-green-400';
  return 'text-slate-400';
}

export default function ThreatAnalytics() {
  const [windowDays, setWindowDays] = useState(7);
  const [data, setData] = useState<ThreatAnalyticsResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    api
      .get<ThreatAnalyticsResponse>('/api/v1/threat-analytics', { params: { window_days: windowDays } })
      .then((response) => {
        if (!cancelled) setData(response.data);
      })
      .catch(() => {
        if (!cancelled) setError('Failed to load threat analytics.');
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [windowDays]);

  const chartData = (data?.trends ?? []).map((trend) => ({
    name: titleCase(trend.category),
    Current: trend.current_count,
    Previous: trend.previous_count,
  }));

  return (
    <Layout>
      <PageHeader
        title="Threat Analytics"
        description="Correlation-pattern trends across your tenant's detected incidents."
        actions={
          <label className="flex items-center gap-2 text-sm text-slate-400">
            Window
            <select
              value={windowDays}
              onChange={(e) => setWindowDays(Number(e.target.value))}
              className={selectClasses}
            >
              {WINDOW_OPTIONS.map((days) => (
                <option key={days} value={days}>
                  {days} days
                </option>
              ))}
            </select>
          </label>
        }
      />

      {error && <p className="mt-4 text-sm text-red-400">{error}</p>}

      <section className="mt-6">
        <ChartCard
          title="Detected Pattern Trends"
          subtitle={`Current vs. previous ${windowDays}-day window`}
        >
          {isLoading ? (
            <div className="flex h-56 items-center justify-center text-sm text-slate-500">Loading…</div>
          ) : chartData.length === 0 ? (
            <div className="flex h-56 items-center justify-center text-sm text-slate-500">
              No detected patterns in either window.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={chartData} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 12 }} axisLine={{ stroke: '#1e293b' }} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: '#64748b', fontSize: 12 }} axisLine={false} tickLine={false} width={32} />
                <Tooltip
                  contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: '#cbd5e1' }}
                />
                <Legend wrapperStyle={{ fontSize: 12, color: '#94a3b8' }} />
                <Bar dataKey="Previous" fill="#334155" radius={[4, 4, 0, 0]} />
                <Bar dataKey="Current" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>
      </section>

      <section className="mt-4 overflow-hidden rounded-xl border border-slate-800">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-3 font-medium">Category</th>
                <th className="px-4 py-3 font-medium">MITRE Tactic</th>
                <th className="px-4 py-3 font-medium">Techniques</th>
                <th className="px-4 py-3 font-medium">Current</th>
                <th className="px-4 py-3 font-medium">Previous</th>
                <th className="px-4 py-3 font-medium">Change</th>
              </tr>
            </thead>
            <tbody>
              {!isLoading && (data?.trends.length ?? 0) === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-sm text-slate-500">
                    No detected patterns in either window.
                  </td>
                </tr>
              ) : (
                (data?.trends ?? []).map((trend) => (
                  <tr key={trend.category} className="border-t border-slate-800/70">
                    <td className="px-4 py-2.5 text-slate-200">{titleCase(trend.category)}</td>
                    <td className="px-4 py-2.5 text-slate-400">{trend.mitre_tactic}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-slate-500">{trend.mitre_technique_ids.join(', ')}</td>
                    <td className="px-4 py-2.5 tabular-nums text-slate-200">{trend.current_count}</td>
                    <td className="px-4 py-2.5 tabular-nums text-slate-400">{trend.previous_count}</td>
                    <td className={`px-4 py-2.5 tabular-nums font-medium ${changeTone(trend)}`}>{formatChangePct(trend)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </Layout>
  );
}
