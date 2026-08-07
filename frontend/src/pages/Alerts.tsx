/**
 * SafeSOC — Alert Queue View (SS-059)
 * Paginated, filterable list backed by GET /api/v1/alerts, exposing
 * every filter the backend already supports (severity, log_type,
 * source, host, timerange) — not a subset (AC).
 */

import { useEffect, useState } from 'react';
import Layout from '../components/Layout';
import LevelBadge from '../components/LevelBadge';
import { api } from '../lib/api';
import { LOG_SOURCES, LOG_TYPES, SEVERITIES, type Alert, type AlertSearchResponse } from '../lib/types';

const PAGE_SIZE = 50;

export default function Alerts() {
  const [severity, setSeverity] = useState('');
  const [logType, setLogType] = useState('');
  const [source, setSource] = useState('');
  const [hostId, setHostId] = useState('');
  const [timerangeHours, setTimerangeHours] = useState(24);
  const [page, setPage] = useState(1);

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    const params: Record<string, string | number> = { page, size: PAGE_SIZE, timerange_hours: timerangeHours };
    if (severity) params.severity = severity;
    if (logType) params.log_type = logType;
    if (source) params.source = source;
    if (hostId) params.host_id = hostId;

    api
      .get<AlertSearchResponse>('/api/v1/alerts', { params })
      .then((response) => {
        if (cancelled) return;
        setAlerts(response.data.alerts);
        setTotal(response.data.total);
        setPages(response.data.pages);
      })
      .catch(() => {
        if (!cancelled) setError('Failed to load alerts.');
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [severity, logType, source, hostId, timerangeHours, page]);

  const resetToFirstPage = (setter: (value: string) => void) => (value: string) => {
    setter(value);
    setPage(1);
  };

  return (
    <Layout>
      <h1 className="text-xl font-semibold">Alerts</h1>

      <div className="mt-4 flex flex-wrap gap-3">
        <select
          value={severity}
          onChange={(e) => resetToFirstPage(setSeverity)(e.target.value)}
          className="rounded border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm text-slate-100"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>

        <select
          value={logType}
          onChange={(e) => resetToFirstPage(setLogType)(e.target.value)}
          className="rounded border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm text-slate-100"
        >
          <option value="">All log types</option>
          {LOG_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>

        <select
          value={source}
          onChange={(e) => resetToFirstPage(setSource)(e.target.value)}
          className="rounded border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm text-slate-100"
        >
          <option value="">All sources</option>
          {LOG_SOURCES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>

        <input
          type="text"
          placeholder="Host ID"
          value={hostId}
          onChange={(e) => resetToFirstPage(setHostId)(e.target.value)}
          className="rounded border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm text-slate-100"
        />

        <label className="flex items-center gap-2 text-sm text-slate-300">
          Last
          <input
            type="number"
            min={1}
            max={720}
            value={timerangeHours}
            onChange={(e) => {
              setTimerangeHours(Number(e.target.value) || 1);
              setPage(1);
            }}
            className="w-20 rounded border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm text-slate-100"
          />
          hours
        </label>
      </div>

      {error && <p className="mt-4 text-sm text-red-400">{error}</p>}

      <div className="mt-4 overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-3 py-2">Timestamp</th>
              <th className="px-3 py-2">Severity</th>
              <th className="px-3 py-2">Host</th>
              <th className="px-3 py-2">Source</th>
              <th className="px-3 py-2">Log Type</th>
              <th className="px-3 py-2">Action</th>
              <th className="px-3 py-2">Description</th>
              <th className="px-3 py-2">User</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={8} className="px-3 py-6 text-center text-slate-500">
                  Loading…
                </td>
              </tr>
            ) : alerts.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-3 py-6 text-center text-slate-500">
                  No alerts match these filters.
                </td>
              </tr>
            ) : (
              alerts.map((alert) => (
                <tr key={alert.alert_id} className="border-t border-slate-800">
                  <td className="whitespace-nowrap px-3 py-2 text-slate-300">
                    {new Date(alert.timestamp).toLocaleString()}
                  </td>
                  <td className="px-3 py-2">
                    <LevelBadge level={alert.severity} />
                  </td>
                  <td className="px-3 py-2 font-mono text-slate-300">{alert.host_id}</td>
                  <td className="px-3 py-2 text-slate-300">{alert.source}</td>
                  <td className="px-3 py-2 text-slate-300">{alert.log_type}</td>
                  <td className="px-3 py-2 text-slate-300">{alert.action}</td>
                  <td className="px-3 py-2 text-slate-300">{alert.description}</td>
                  <td className="px-3 py-2 text-slate-300">{alert.user}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="mt-4 flex items-center justify-between text-sm text-slate-400">
        <span>{total} total alert(s)</span>
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
