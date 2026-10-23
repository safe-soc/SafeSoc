/**
 * SafeSOC — Incident List View (SS-061)
 * Backed by GET /api/v1/incidents (SS-036). Each row links to
 * IncidentDetail for transitions, alert linking, and notes.
 */

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import Layout from '../components/Layout';
import PageHeader from '../components/PageHeader';
import LevelBadge from '../components/LevelBadge';
import StatusBadge from '../components/StatusBadge';
import EmptyState from '../components/EmptyState';
import TableSkeleton from '../components/TableSkeleton';
import { ChevronLeftIcon, ChevronRightIcon, IncidentIcon } from '../components/icons';
import { api } from '../lib/api';
import { categoryLabel, hostsLabel } from '../lib/format';
import Timestamp from '../components/Timestamp';
import type { Incident, IncidentListResponse, IncidentStatus } from '../lib/types';

const STATUSES: IncidentStatus[] = ['open', 'investigating', 'resolved', 'false_positive'];
const PAGE_SIZE = 50;
const COLUMN_COUNT = 9;

export default function Incidents() {
  const [status, setStatus] = useState('');
  const [page, setPage] = useState(1);

  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    const params: Record<string, string | number> = { page, size: PAGE_SIZE };
    if (status) params.status = status;

    api
      .get<IncidentListResponse>('/api/v1/incidents', { params })
      .then((response) => {
        if (cancelled) return;
        setIncidents(response.data.incidents);
        setTotal(response.data.total);
        setPages(response.data.pages);
      })
      .catch(() => {
        if (!cancelled) setError('Failed to load incidents.');
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [status, page]);

  const rangeStart = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const rangeEnd = Math.min(page * PAGE_SIZE, total);

  return (
    <Layout>
      <PageHeader title="Incidents" description="Auto-detected attack chains and manually opened investigations." />

      <div className="mt-4 flex flex-wrap items-center gap-2">
        {['', ...STATUSES].map((s) => (
          <button
            key={s || 'all'}
            type="button"
            onClick={() => {
              setStatus(s);
              setPage(1);
            }}
            className={`rounded-full px-3 py-1.5 text-sm font-medium capitalize transition-colors ${
              status === s
                ? 'bg-blue-600 text-white'
                : 'border border-slate-800 bg-slate-900 text-slate-400 hover:border-slate-700 hover:text-slate-200'
            }`}
          >
            {s ? s.replace('_', ' ') : 'All statuses'}
          </button>
        ))}
      </div>

      {error && <p className="mt-4 text-sm text-red-400">{error}</p>}

      <div className="mt-4 overflow-hidden rounded-xl border border-slate-800">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-3 font-medium">Incident</th>
                <th className="px-4 py-3 font-medium">Title / Category</th>
                <th className="px-4 py-3 font-medium">Host</th>
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Confidence</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Alerts</th>
                <th className="px-4 py-3 font-medium">Created</th>
                <th className="px-4 py-3 font-medium">Updated</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <TableSkeleton rows={8} columns={COLUMN_COUNT} />
              ) : incidents.length === 0 ? (
                <tr>
                  <td colSpan={COLUMN_COUNT}>
                    <EmptyState
                      icon={<IncidentIcon className="h-10 w-10 text-slate-700" />}
                      title="No incidents match these filters"
                      description="Incidents are created automatically when the correlation engine detects an attack chain, or manually by an analyst."
                    />
                  </td>
                </tr>
              ) : (
                incidents.map((incident) => (
                  <tr key={incident.id} className="border-t border-slate-800/70 transition-colors hover:bg-slate-900/50">
                    <td className="px-4 py-3">
                      <Link to={`/incidents/${incident.id}`} className="font-mono text-blue-400 hover:underline">
                        {incident.id.slice(0, 8)}
                      </Link>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-slate-200">{categoryLabel(incident.category)}</td>
                    <td
                      className="whitespace-nowrap px-4 py-3 font-mono text-xs text-slate-300"
                      title={incident.hosts.length > 1 ? incident.hosts.join(', ') : undefined}
                    >
                      {hostsLabel(incident.hosts)}
                    </td>
                    <td className="px-4 py-3">
                      {incident.severity ? <LevelBadge level={incident.severity} /> : <span className="text-slate-600">—</span>}
                    </td>
                    <td className="px-4 py-3 tabular-nums text-slate-300">
                      {incident.confidence === null ? (
                        <span className="text-slate-600">—</span>
                      ) : (
                        `${Math.round(incident.confidence * 100)}%`
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={incident.status} />
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 tabular-nums text-slate-300">
                      {incident.alert_ids.length} alert{incident.alert_ids.length === 1 ? '' : 's'}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-slate-400">
                      <Timestamp iso={incident.created_at} format="relative" />
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-slate-400">
                      <Timestamp iso={incident.updated_at} format="relative" />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm text-slate-400">
        <span>
          {total === 0 ? '0 incidents' : `Showing ${rangeStart}–${rangeEnd} of ${total} incident${total === 1 ? '' : 's'}`}
        </span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={page <= 1}
            onClick={() => setPage((p) => p - 1)}
            className="flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900 px-3 py-1.5 transition-colors hover:border-slate-700 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ChevronLeftIcon className="h-4 w-4" />
            Previous
          </button>
          <span className="tabular-nums">
            Page {page} of {pages || 1}
          </span>
          <button
            type="button"
            disabled={page >= pages}
            onClick={() => setPage((p) => p + 1)}
            className="flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900 px-3 py-1.5 transition-colors hover:border-slate-700 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Next
            <ChevronRightIcon className="h-4 w-4" />
          </button>
        </div>
      </div>
    </Layout>
  );
}
