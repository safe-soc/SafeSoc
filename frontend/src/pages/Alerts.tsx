/**
 * SafeSOC — Alert Queue View (SS-059)
 * Paginated, filterable list backed by GET /api/v1/alerts, exposing
 * every filter the backend already supports (severity, log_type,
 * source, host, timerange) — not a subset (AC).
 *
 * The quick-search box is a client-side filter over the currently
 * loaded page only — the backend's alert search has no free-text
 * query parameter wired to this router (only the structured filters
 * below), so "search" here narrows what's already on screen rather
 * than querying the server, and is labeled that way in the UI.
 */

import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import Layout from '../components/Layout';
import PageHeader from '../components/PageHeader';
import LevelBadge from '../components/LevelBadge';
import EmptyState from '../components/EmptyState';
import TableSkeleton from '../components/TableSkeleton';
import { AlertIcon, ChevronLeftIcon, ChevronRightIcon, SearchIcon } from '../components/icons';
import { api } from '../lib/api';
import { formatDateTime } from '../lib/format';
import { LOG_SOURCES, LOG_TYPES, SEVERITIES, type Alert, type AlertAnnotation, type AlertSearchResponse } from '../lib/types';

const PAGE_SIZE = 50;

const selectClasses =
  'rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500';

export default function Alerts() {
  // Pre-fills the host filter when arriving from an Endpoints drill-down
  // link (SS-060, /alerts?host_id=...) — read once on mount, not kept
  // in sync afterward, since this is a starting filter, not a two-way
  // URL-state binding the rest of this page doesn't otherwise have.
  const [searchParams] = useSearchParams();

  const [severity, setSeverity] = useState('');
  const [logType, setLogType] = useState('');
  const [source, setSource] = useState('');
  const [hostId, setHostId] = useState(() => searchParams.get('host_id') ?? '');
  const [timerangeHours, setTimerangeHours] = useState(24);
  const [page, setPage] = useState(1);
  const [quickSearch, setQuickSearch] = useState('');

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [triageAlertId, setTriageAlertId] = useState<string | null>(null);

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

  const visibleAlerts = useMemo(() => {
    const needle = quickSearch.trim().toLowerCase();
    if (!needle) return alerts;
    return alerts.filter((alert) =>
      [alert.host_id, alert.action, alert.description, alert.user].some((field) =>
        field?.toLowerCase().includes(needle),
      ),
    );
  }, [alerts, quickSearch]);

  const handleTriage = async (alertId: string, action: 'acknowledge' | 'dismiss') => {
    setTriageAlertId(alertId);
    try {
      const response = await api.post<AlertAnnotation>(`/api/v1/alerts/${alertId}/${action}`);
      setAlerts((prev) =>
        prev.map((alert) =>
          alert.alert_id === alertId
            ? { ...alert, acknowledged: response.data.acknowledged, dismissed: response.data.dismissed }
            : alert,
        ),
      );
    } catch {
      setError(`Failed to ${action} that alert.`);
    } finally {
      setTriageAlertId(null);
    }
  };

  const resetToFirstPage = (setter: (value: string) => void) => (value: string) => {
    setter(value);
    setPage(1);
  };

  const hasActiveFilters = Boolean(severity || logType || source || hostId);
  const rangeStart = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const rangeEnd = Math.min(page * PAGE_SIZE, total);

  return (
    <Layout>
      <PageHeader title="Alerts" description="Every normalized log accepted into SafeSOC, filterable by severity, type, source, and host." />

      <div className="sticky top-[57px] z-10 -mx-6 mt-4 border-y border-slate-800/80 bg-slate-950/95 px-6 py-3 backdrop-blur">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <SearchIcon className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Quick search (this page)…"
              value={quickSearch}
              onChange={(e) => setQuickSearch(e.target.value)}
              className="w-56 rounded-lg border border-slate-700 bg-slate-800 py-1.5 pl-8 pr-2.5 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>

          <div className="h-5 w-px bg-slate-800" />

          <select value={severity} onChange={(e) => resetToFirstPage(setSeverity)(e.target.value)} className={selectClasses}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>

          <select value={logType} onChange={(e) => resetToFirstPage(setLogType)(e.target.value)} className={selectClasses}>
            <option value="">All log types</option>
            {LOG_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>

          <select value={source} onChange={(e) => resetToFirstPage(setSource)(e.target.value)} className={selectClasses}>
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
            className="w-32 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />

          <label className="flex items-center gap-2 text-sm text-slate-400">
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
              className="w-16 rounded-lg border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
            hours
          </label>

          {hasActiveFilters && (
            <button
              type="button"
              onClick={() => {
                setSeverity('');
                setLogType('');
                setSource('');
                setHostId('');
                setPage(1);
              }}
              className="text-sm text-slate-500 hover:text-slate-300"
            >
              Clear filters
            </button>
          )}
        </div>
      </div>

      {error && <p className="mt-4 text-sm text-red-400">{error}</p>}

      <div className="mt-4 overflow-hidden rounded-xl border border-slate-800">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-3 font-medium">Timestamp</th>
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Host</th>
                <th className="px-4 py-3 font-medium">Source</th>
                <th className="px-4 py-3 font-medium">Log Type</th>
                <th className="px-4 py-3 font-medium">Action</th>
                <th className="px-4 py-3 font-medium">Description</th>
                <th className="px-4 py-3 font-medium">User</th>
                <th className="px-4 py-3 font-medium">Triage</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <TableSkeleton rows={10} columns={9} />
              ) : visibleAlerts.length === 0 ? (
                <tr>
                  <td colSpan={9}>
                    <EmptyState
                      icon={<AlertIcon className="h-10 w-10 text-slate-700" />}
                      title={quickSearch ? 'No alerts match your search' : 'No alerts match these filters'}
                      description={
                        quickSearch
                          ? 'Try a different term, or clear the quick search box.'
                          : 'Try widening the time range or clearing a filter.'
                      }
                    />
                  </td>
                </tr>
              ) : (
                visibleAlerts.map((alert) => (
                  <tr key={alert.alert_id} className="border-t border-slate-800/70 transition-colors hover:bg-slate-900/50">
                    <td className="whitespace-nowrap px-4 py-2.5 text-slate-400" title={alert.timestamp}>
                      {formatDateTime(alert.timestamp)}
                    </td>
                    <td className="px-4 py-2.5">
                      <LevelBadge level={alert.severity} />
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 font-mono text-slate-300">{alert.host_id}</td>
                    <td className="px-4 py-2.5 text-slate-400">{alert.source}</td>
                    <td className="px-4 py-2.5 text-slate-400">{alert.log_type}</td>
                    <td className="px-4 py-2.5 text-slate-300">{alert.action}</td>
                    <td className="max-w-md truncate px-4 py-2.5 text-slate-300" title={alert.description}>
                      {alert.description}
                    </td>
                    <td className="px-4 py-2.5 text-slate-400">{alert.user}</td>
                    <td className="whitespace-nowrap px-4 py-2.5">
                      {alert.dismissed ? (
                        <span className="text-xs text-slate-500">Dismissed</span>
                      ) : alert.acknowledged ? (
                        <span className="text-xs text-green-400">Acknowledged</span>
                      ) : (
                        <div className="flex gap-2">
                          <button
                            type="button"
                            disabled={triageAlertId === alert.alert_id}
                            onClick={() => handleTriage(alert.alert_id, 'acknowledge')}
                            className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
                          >
                            Acknowledge
                          </button>
                          <button
                            type="button"
                            disabled={triageAlertId === alert.alert_id}
                            onClick={() => handleTriage(alert.alert_id, 'dismiss')}
                            className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-500 transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
                          >
                            Dismiss
                          </button>
                        </div>
                      )}
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
          {total === 0 ? '0 alerts' : `Showing ${rangeStart}–${rangeEnd} of ${total} alert${total === 1 ? '' : 's'}`}
        </span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={page <= 1}
            onClick={() => setPage((p) => p - 1)}
            className="flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900 px-3 py-1.5 transition-colors hover:border-slate-700 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-slate-800 disabled:hover:bg-slate-900"
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
            className="flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900 px-3 py-1.5 transition-colors hover:border-slate-700 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-slate-800 disabled:hover:bg-slate-900"
          >
            Next
            <ChevronRightIcon className="h-4 w-4" />
          </button>
        </div>
      </div>
    </Layout>
  );
}
