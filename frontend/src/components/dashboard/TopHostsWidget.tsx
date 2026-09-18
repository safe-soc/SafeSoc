/**
 * SafeSOC — Top Affected Hosts Widget
 * Client-side grouping of the Dashboard's alert fetch by host_id —
 * simple proportional bar list rather than a full chart, since host
 * IDs are arbitrary-length labels that don't lay out well on an axis.
 */

import { Link } from 'react-router-dom';
import type { Alert } from '../../lib/types';
import ChartCard from './ChartCard';
import EmptyState from '../EmptyState';

export default function TopHostsWidget({ alerts }: { alerts: Alert[] }) {
  const counts = new Map<string, number>();
  for (const alert of alerts) {
    counts.set(alert.host_id, (counts.get(alert.host_id) ?? 0) + 1);
  }
  const top = Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  const max = top[0]?.[1] ?? 1;

  return (
    <ChartCard title="Top Affected Hosts" subtitle="By alert volume in window">
      {top.length === 0 ? (
        <EmptyState title="No host activity yet" description="Hosts will appear here once alerts start arriving." />
      ) : (
        <ul className="space-y-3">
          {top.map(([hostId, count]) => (
            <li key={hostId}>
              <div className="mb-1 flex items-center justify-between text-sm">
                <Link
                  to={`/endpoints/${encodeURIComponent(hostId)}`}
                  className="font-mono text-slate-200 hover:text-blue-400 hover:underline"
                >
                  {hostId}
                </Link>
                <span className="tabular-nums text-slate-400">{count}</span>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full rounded-full bg-blue-500"
                  style={{ width: `${Math.max(4, (count / max) * 100)}%` }}
                />
              </div>
            </li>
          ))}
        </ul>
      )}
    </ChartCard>
  );
}
