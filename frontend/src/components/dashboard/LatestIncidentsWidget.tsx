/**
 * SafeSOC — Latest Incidents Widget
 * GET /api/v1/incidents, no status filter, size=5 — newest first
 * (server default), reusing the same resource the Incidents page uses.
 */

import { Link } from 'react-router-dom';
import type { Incident } from '../../lib/types';
import { formatRelativeTime } from '../../lib/format';
import StatusBadge from '../StatusBadge';
import EmptyState from '../EmptyState';
import ChartCard from './ChartCard';

export default function LatestIncidentsWidget({ incidents, isLoading }: { incidents: Incident[]; isLoading: boolean }) {
  return (
    <ChartCard title="Latest Incidents" subtitle="Most recently created or updated">
      {isLoading ? (
        <ul className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <li key={i} className="h-10 animate-pulse rounded bg-slate-800/60" />
          ))}
        </ul>
      ) : incidents.length === 0 ? (
        <EmptyState title="No incidents yet" description="Detected attack chains and manually created incidents will show up here." />
      ) : (
        <ul className="divide-y divide-slate-800/70">
          {incidents.map((incident) => (
            <li key={incident.id}>
              <Link
                to={`/incidents/${incident.id}`}
                className="flex items-center justify-between gap-3 py-2.5 first:pt-0 last:pb-0 hover:opacity-80"
              >
                <div className="min-w-0">
                  <p className="truncate font-mono text-sm text-slate-200">{incident.id.slice(0, 8)}</p>
                  <p className="text-xs text-slate-500">
                    {incident.alert_ids.length} alert{incident.alert_ids.length === 1 ? '' : 's'} ·{' '}
                    {formatRelativeTime(incident.updated_at)}
                  </p>
                </div>
                <StatusBadge status={incident.status} />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </ChartCard>
  );
}
