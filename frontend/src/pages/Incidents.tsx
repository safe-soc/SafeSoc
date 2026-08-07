/**
 * SafeSOC — Incident List View (SS-061)
 * Backed by GET /api/v1/incidents (SS-036). Each row links to
 * IncidentDetail for transitions, alert linking, and notes.
 */

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import Layout from '../components/Layout';
import StatusBadge from '../components/StatusBadge';
import { api } from '../lib/api';
import type { Incident, IncidentListResponse, IncidentStatus } from '../lib/types';

const STATUSES: IncidentStatus[] = ['open', 'investigating', 'resolved', 'false_positive'];
const PAGE_SIZE = 50;

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

  return (
    <Layout>
      <h1 className="text-xl font-semibold">Incidents</h1>

      <div className="mt-4 flex gap-3">
        <select
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(1);
          }}
          className="rounded border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm text-slate-100"
        >
          <option value="">All statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>

      {error && <p className="mt-4 text-sm text-red-400">{error}</p>}

      <div className="mt-4 overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-3 py-2">Incident</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Alerts</th>
              <th className="px-3 py-2">Created</th>
              <th className="px-3 py-2">Updated</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-slate-500">
                  Loading…
                </td>
              </tr>
            ) : incidents.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-slate-500">
                  No incidents match these filters.
                </td>
              </tr>
            ) : (
              incidents.map((incident) => (
                <tr key={incident.id} className="border-t border-slate-800 hover:bg-slate-900/60">
                  <td className="px-3 py-2">
                    <Link to={`/incidents/${incident.id}`} className="font-mono text-blue-400 hover:underline">
                      {incident.id.slice(0, 8)}
                    </Link>
                  </td>
                  <td className="px-3 py-2">
                    <StatusBadge status={incident.status} />
                  </td>
                  <td className="px-3 py-2 text-slate-300">{incident.alert_ids.length}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-slate-300">
                    {new Date(incident.created_at).toLocaleString()}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-slate-300">
                    {new Date(incident.updated_at).toLocaleString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="mt-4 flex items-center justify-between text-sm text-slate-400">
        <span>{total} total incident(s)</span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={page <= 1}
            onClick={() => setPage((p) => p - 1)}
            className="rounded bg-slate-800 px-3 py-1.5 disabled:opacity-40"
          >
            Previous
          </button>
          <span>
            Page {page} of {pages || 1}
          </span>
          <button
            type="button"
            disabled={page >= pages}
            onClick={() => setPage((p) => p + 1)}
            className="rounded bg-slate-800 px-3 py-1.5 disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </div>
    </Layout>
  );
}
