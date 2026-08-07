/**
 * SafeSOC — Alerts Over Time Chart
 * Client-side bucketing of the Dashboard's own alert fetch
 * (GET /api/v1/alerts, no dedicated aggregation endpoint exists) into
 * one count per day within the fetched window.
 */

import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { Alert } from '../../lib/types';
import ChartCard from './ChartCard';

function bucketByDay(alerts: Alert[], days: number): { date: string; label: string; count: number }[] {
  const buckets = new Map<string, number>();
  const now = new Date();

  for (let i = days - 1; i >= 0; i--) {
    const day = new Date(now);
    day.setDate(day.getDate() - i);
    buckets.set(day.toISOString().slice(0, 10), 0);
  }

  for (const alert of alerts) {
    const key = alert.timestamp.slice(0, 10);
    if (buckets.has(key)) {
      buckets.set(key, (buckets.get(key) ?? 0) + 1);
    }
  }

  return Array.from(buckets.entries()).map(([date, count]) => ({
    date,
    label: new Date(date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
    count,
  }));
}

export default function AlertsOverTimeChart({ alerts, days }: { alerts: Alert[]; days: number }) {
  const data = bucketByDay(alerts, days);
  const isEmpty = data.every((d) => d.count === 0);

  return (
    <ChartCard title="Alerts Over Time" subtitle={`Last ${days} days`}>
      {isEmpty ? (
        <div className="flex h-56 items-center justify-center text-sm text-slate-500">No alerts in this window.</div>
      ) : (
        <ResponsiveContainer width="100%" height={224}>
          <AreaChart data={data} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="alertsFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.35} />
                <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
            <XAxis dataKey="label" tick={{ fill: '#64748b', fontSize: 12 }} axisLine={{ stroke: '#1e293b' }} tickLine={false} />
            <YAxis allowDecimals={false} tick={{ fill: '#64748b', fontSize: 12 }} axisLine={false} tickLine={false} width={32} />
            <Tooltip
              contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, fontSize: 12 }}
              labelStyle={{ color: '#cbd5e1' }}
              itemStyle={{ color: '#93c5fd' }}
            />
            <Area type="monotone" dataKey="count" name="Alerts" stroke="#3b82f6" strokeWidth={2} fill="url(#alertsFill)" />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </ChartCard>
  );
}
