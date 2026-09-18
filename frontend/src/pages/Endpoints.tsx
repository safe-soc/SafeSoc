/**
 * SafeSOC — Endpoint Risk Dashboard View (SS-060)
 * Backed by GET /api/v1/endpoints (SS-034). Each row drills down to a
 * dedicated endpoint detail/investigation page (EndpointDetail.tsx),
 * which itself links onward to the same host-filtered Alerts view
 * (SS-059) this used to link to directly.
 *
 * GET /api/v1/endpoints has no host_os field — the small OS icon per
 * row is a best-effort lookup against recently-seen alerts for that
 * host (lib/alertLookup.ts), not a real endpoint property; a host with
 * no matching alert in the lookup window just shows a generic icon.
 */

import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import Layout from '../components/Layout';
import PageHeader from '../components/PageHeader';
import LevelBadge from '../components/LevelBadge';
import EmptyState from '../components/EmptyState';
import TableSkeleton from '../components/TableSkeleton';
import OsIcon from '../components/OsIcon';
import { EndpointIcon, SortIcon } from '../components/icons';
import { api } from '../lib/api';
import { fetchAlertLookup } from '../lib/alertLookup';
import { formatDateTime } from '../lib/format';
import type { Endpoint } from '../lib/types';

type SortKey = 'risk_score' | 'host_id' | 'updated_at';

const RISK_BAR_COLOR: Record<string, string> = {
  low: 'bg-slate-500',
  medium: 'bg-yellow-500',
  high: 'bg-orange-500',
  critical: 'bg-red-500',
};

export default function Endpoints() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [osByHost, setOsByHost] = useState<Map<string, string>>(new Map());
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>('risk_score');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');

  useEffect(() => {
    let cancelled = false;
    api
      .get<Endpoint[]>('/api/v1/endpoints')
      .then((response) => {
        if (!cancelled) setEndpoints(response.data);
      })
      .catch(() => {
        if (!cancelled) setError('Failed to load endpoints.');
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    // Best-effort only — a failure here just means OS icons stay generic.
    fetchAlertLookup()
      .then((lookup) => {
        if (!cancelled) setOsByHost(lookup.osForHost);
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
    };
  }, []);

  const sorted = useMemo(() => {
    const copy = [...endpoints];
    copy.sort((a, b) => {
      let result = 0;
      if (sortKey === 'host_id') result = a.host_id.localeCompare(b.host_id);
      else if (sortKey === 'updated_at') result = a.updated_at.localeCompare(b.updated_at);
      else result = a.risk_score - b.risk_score;
      return sortDirection === 'asc' ? result : -result;
    });
    return copy;
  }, [endpoints, sortKey, sortDirection]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDirection('desc');
    }
  };

  const highRiskCount = endpoints.filter((e) => e.risk_level === 'high' || e.risk_level === 'critical').length;

  const SortableHeader = ({ label, sortKeyName }: { label: string; sortKeyName: SortKey }) => (
    <th className="px-4 py-3 font-medium">
      <button
        type="button"
        onClick={() => toggleSort(sortKeyName)}
        className="flex items-center gap-1 transition-colors hover:text-slate-200"
      >
        {label}
        <SortIcon direction={sortKey === sortKeyName ? sortDirection : 'none'} className="h-3.5 w-3.5" />
      </button>
    </th>
  );

  return (
    <Layout>
      <PageHeader
        title="Endpoints"
        description={`Known hosts, sorted by risk score.${
          highRiskCount > 0 ? ` ${highRiskCount} at high or critical risk.` : ''
        } Click a host to investigate it.`}
      />

      {error && <p className="mt-4 text-sm text-red-400">{error}</p>}

      <div className="mt-4 overflow-hidden rounded-xl border border-slate-800">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <SortableHeader label="Host" sortKeyName="host_id" />
                <SortableHeader label="Risk Score" sortKeyName="risk_score" />
                <th className="px-4 py-3 font-medium">Risk Level</th>
                <SortableHeader label="Last Updated" sortKeyName="updated_at" />
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <TableSkeleton rows={8} columns={4} />
              ) : sorted.length === 0 ? (
                <tr>
                  <td colSpan={4}>
                    <EmptyState
                      icon={<EndpointIcon className="h-10 w-10 text-slate-700" />}
                      title="No endpoints have been scored yet"
                      description="Endpoints appear here once the risk scoring task has evaluated their alert history."
                    />
                  </td>
                </tr>
              ) : (
                sorted.map((endpoint) => (
                  <tr key={endpoint.id} className="border-t border-slate-800/70 transition-colors hover:bg-slate-900/50">
                    <td className="px-4 py-3">
                      <Link
                        to={`/endpoints/${encodeURIComponent(endpoint.host_id)}`}
                        className="inline-flex items-center gap-2 font-mono text-slate-200 hover:text-blue-400 hover:underline"
                      >
                        <OsIcon os={osByHost.get(endpoint.host_id)} />
                        {endpoint.host_id}
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-24 overflow-hidden rounded-full bg-slate-800">
                          <div
                            className={`h-full rounded-full ${RISK_BAR_COLOR[endpoint.risk_level] ?? 'bg-slate-500'}`}
                            style={{ width: `${Math.min(100, Math.max(2, endpoint.risk_score))}%` }}
                          />
                        </div>
                        <span className="w-8 tabular-nums text-slate-300">{endpoint.risk_score}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <LevelBadge level={endpoint.risk_level} />
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-slate-400">{formatDateTime(endpoint.updated_at)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </Layout>
  );
}
