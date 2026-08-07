/**
 * SafeSOC — Severity Distribution Chart
 * Client-side grouping of the Dashboard's alert fetch by severity —
 * same 4-tier vocabulary as LevelBadge, same colors for consistency.
 */

import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';
import { SEVERITIES, type Alert } from '../../lib/types';
import ChartCard from './ChartCard';

const COLORS: Record<string, string> = {
  low: '#94a3b8',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
};

export default function SeverityDistributionChart({ alerts }: { alerts: Alert[] }) {
  const counts = SEVERITIES.map((severity) => ({
    name: severity,
    value: alerts.filter((a) => a.severity === severity).length,
  })).filter((entry) => entry.value > 0);

  const total = alerts.length;

  return (
    <ChartCard title="Severity Distribution" subtitle={`${total} alert${total === 1 ? '' : 's'} in window`}>
      {counts.length === 0 ? (
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
          </ul>
        </div>
      )}
    </ChartCard>
  );
}
