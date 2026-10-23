/**
 * SafeSOC — Alert Queue View (SS-059)
 * Paginated, filterable list backed by GET /api/v1/alerts, exposing
 * every filter the backend already supports (severity, log_type,
 * source, host, timerange) — not a subset (AC).
 *
 * The search box is a real server-side search: it sends `q` (debounced
 * 300 ms) to GET /api/v1/alerts, which matches it case-insensitively
 * against host, user, action, description, source/destination IP, rule
 * id and MITRE technique, combined with every other filter — so
 * pagination and the total reflect the search, not just this page.
 *
 * Triage: Acknowledge, or Dismiss with a reason (a note is required for
 * "Other"); a dismissed alert shows its reason and can be restored with
 * Undo. The Triage filter (untriaged / acknowledged / dismissed) is also
 * applied server-side.
 */

import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import Layout from '../components/Layout';
import PageHeader from '../components/PageHeader';
import LevelBadge from '../components/LevelBadge';
import EmptyState from '../components/EmptyState';
import TableSkeleton from '../components/TableSkeleton';
import { AlertIcon, ChevronLeftIcon, ChevronRightIcon, SearchIcon } from '../components/icons';
import { api } from '../lib/api';
import { dismissReasonLabel } from '../lib/format';
import Timestamp from '../components/Timestamp';
import {
  DISMISS_REASONS,
  LOG_SOURCES,
  LOG_TYPES,
  SEVERITIES,
  TRIAGE_STATUSES,
  type Alert,
  type AlertAnnotation,
  type AlertSearchResponse,
  type DismissReason,
} from '../lib/types';

const PAGE_SIZE = 50;
const SEARCH_DEBOUNCE_MS = 300;
const DISMISS_NOTE_MAX_LENGTH = 500;

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
  const [triage, setTriage] = useState('');
  const [timerangeHours, setTimerangeHours] = useState(24);
  const [page, setPage] = useState(1);
  // What's typed vs. what's been sent: `q` only follows `searchInput`
  // after a 300 ms pause, so each keystroke doesn't fire a request.
  const [searchInput, setSearchInput] = useState('');
  const [q, setQ] = useState('');

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [triageAlertId, setTriageAlertId] = useState<string | null>(null);

  useEffect(() => {
    const next = searchInput.trim();
    if (next === q) return;
    const timer = setTimeout(() => {
      setQ(next);
      setPage(1);
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [searchInput, q]);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    const params: Record<string, string | number> = { page, size: PAGE_SIZE, timerange_hours: timerangeHours };
    if (severity) params.severity = severity;
    if (logType) params.log_type = logType;
    if (source) params.source = source;
    if (hostId) params.host_id = hostId;
    if (triage) params.triage = triage;
    if (q) params.q = q;

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
  }, [severity, logType, source, hostId, triage, q, timerangeHours, page]);

  const handleTriage = async (
    alertId: string,
    action: 'acknowledge' | 'dismiss' | 'restore',
    body?: { reason: DismissReason; note?: string },
  ): Promise<boolean> => {
    setTriageAlertId(alertId);
    try {
      const response = await api.post<AlertAnnotation>(`/api/v1/alerts/${alertId}/${action}`, body);
      const { acknowledged, dismissed, dismiss_reason, dismiss_note } = response.data;
      setAlerts((prev) =>
        prev.map((alert) =>
          alert.alert_id === alertId ? { ...alert, acknowledged, dismissed, dismiss_reason, dismiss_note } : alert,
        ),
      );
      return true;
    } catch {
      setError(`Failed to ${action} that alert.`);
      return false;
    } finally {
      setTriageAlertId(null);
    }
  };

  const resetToFirstPage = (setter: (value: string) => void) => (value: string) => {
    setter(value);
    setPage(1);
  };

  const hasActiveFilters = Boolean(severity || logType || source || hostId || triage || searchInput);
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
              type="search"
              aria-label="Search alerts"
              placeholder="Search alerts (host, user, IP, action…)"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              maxLength={200}
              className="w-72 max-w-full rounded-lg border border-slate-700 bg-slate-800 py-1.5 pl-8 pr-2.5 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
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

          <select
            aria-label="Triage status"
            value={triage}
            onChange={(e) => resetToFirstPage(setTriage)(e.target.value)}
            className={selectClasses}
          >
            <option value="">All triage</option>
            {TRIAGE_STATUSES.map((t) => (
              <option key={t} value={t}>
                {t.charAt(0).toUpperCase() + t.slice(1)}
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
                setTriage('');
                setSearchInput('');
                setQ('');
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
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={9}>
                    <EmptyState
                      icon={<AlertIcon className="h-10 w-10 text-slate-700" />}
                      title={q ? 'No alerts match your search' : 'No alerts match these filters'}
                      description={
                        q
                          ? 'Try a different term, widen the time range, or clear the search.'
                          : 'Try widening the time range or clearing a filter.'
                      }
                    />
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => (
                  <tr key={alert.alert_id} className="border-t border-slate-800/70 transition-colors hover:bg-slate-900/50">
                    <td className="whitespace-nowrap px-4 py-2.5 text-slate-400">
                      <Timestamp iso={alert.timestamp} />
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
                    <td className="whitespace-nowrap px-4 py-2.5 align-top">
                      <TriageCell
                        alert={alert}
                        isBusy={triageAlertId === alert.alert_id}
                        onAcknowledge={() => handleTriage(alert.alert_id, 'acknowledge')}
                        onDismiss={(reason, note) => handleTriage(alert.alert_id, 'dismiss', { reason, note })}
                        onRestore={() => handleTriage(alert.alert_id, 'restore')}
                      />
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

const triageButtonClasses =
  'rounded-md border border-slate-700 px-2 py-1 text-xs transition-colors hover:bg-slate-800 focus:outline-none focus-visible:ring-1 focus-visible:ring-blue-500 disabled:cursor-not-allowed disabled:opacity-40';

/**
 * One row's triage controls. Dismiss opens an inline reason picker in
 * the cell itself (not an absolutely positioned popover, which the
 * table's overflow container would clip on the last rows). Radios and
 * real buttons keep it keyboard-operable; Escape cancels and returns
 * focus to the Dismiss button.
 */
function TriageCell({
  alert,
  isBusy,
  onAcknowledge,
  onDismiss,
  onRestore,
}: {
  alert: Alert;
  isBusy: boolean;
  onAcknowledge: () => void;
  onDismiss: (reason: DismissReason, note?: string) => Promise<boolean>;
  onRestore: () => void;
}) {
  const [isPicking, setIsPicking] = useState(false);
  const [reason, setReason] = useState<DismissReason>('false_positive');
  const [note, setNote] = useState('');
  const dismissButtonRef = useRef<HTMLButtonElement>(null);

  const trimmedNote = note.trim();
  const canConfirm = !isBusy && (reason !== 'other' || trimmedNote.length > 0);

  const reset = () => {
    setIsPicking(false);
    setReason('false_positive');
    setNote('');
  };

  const cancel = () => {
    reset();
    requestAnimationFrame(() => dismissButtonRef.current?.focus());
  };

  const confirm = async () => {
    if (!canConfirm) return;
    if (await onDismiss(reason, trimmedNote || undefined)) reset();
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLFieldSetElement>) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      cancel();
    }
  };

  if (alert.dismissed) {
    const label = alert.dismiss_reason ? dismissReasonLabel(alert.dismiss_reason) : null;
    return (
      <div className="flex items-center gap-2">
        <span className="text-xs text-slate-500" title={alert.dismiss_note ?? undefined}>
          Dismissed{label ? ` · ${label}` : ''}
        </span>
        <button type="button" disabled={isBusy} onClick={onRestore} className={`${triageButtonClasses} text-slate-300`}>
          Undo
        </button>
      </div>
    );
  }

  if (alert.acknowledged) {
    return <span className="text-xs text-green-400">Acknowledged</span>;
  }

  if (isPicking) {
    return (
      <fieldset
        onKeyDown={handleKeyDown}
        className="w-56 space-y-2 whitespace-normal rounded-lg border border-slate-700 bg-slate-900 p-2.5"
      >
        <legend className="sr-only">Dismiss reason</legend>
        <p className="text-xs font-medium text-slate-300">Dismiss as…</p>
        {DISMISS_REASONS.map((value, index) => (
          <label key={value} className="flex cursor-pointer items-center gap-2 text-xs text-slate-300">
            <input
              type="radio"
              name={`dismiss-reason-${alert.alert_id}`}
              value={value}
              checked={reason === value}
              onChange={() => setReason(value)}
              autoFocus={index === 0}
              className="accent-blue-500"
            />
            {dismissReasonLabel(value)}
          </label>
        ))}
        {reason === 'other' && (
          <input
            type="text"
            aria-label="Dismiss note"
            placeholder="Note (required)"
            value={note}
            maxLength={DISMISS_NOTE_MAX_LENGTH}
            onChange={(e) => setNote(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                void confirm();
              }
            }}
            className="w-full rounded-md border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button type="button" onClick={cancel} className={`${triageButtonClasses} text-slate-400`}>
            Cancel
          </button>
          <button
            type="button"
            disabled={!canConfirm}
            onClick={() => void confirm()}
            className={`${triageButtonClasses} border-slate-600 bg-slate-800 text-slate-100`}
          >
            {isBusy ? 'Dismissing…' : 'Dismiss'}
          </button>
        </div>
      </fieldset>
    );
  }

  return (
    <div className="flex gap-2">
      <button type="button" disabled={isBusy} onClick={onAcknowledge} className={`${triageButtonClasses} text-slate-300`}>
        Acknowledge
      </button>
      <button
        ref={dismissButtonRef}
        type="button"
        disabled={isBusy}
        aria-haspopup="true"
        onClick={() => setIsPicking(true)}
        className={`${triageButtonClasses} text-slate-500`}
      >
        Dismiss…
      </button>
    </div>
  );
}
