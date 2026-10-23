/**
 * SafeSOC — Incident Investigation Timeline (SS-099)
 * Renders GET /api/v1/incidents/{id}/timeline's chronological merge of
 * linked alerts, audit-log activity, and notes as one narrative feed,
 * oldest first (the order the backend already returns them in).
 *
 * Noise is collapsed for display only (lib/timelineGroups.ts): repeated
 * adjacent alerts/audit rows fold into one row, and each SOAR action's
 * lifecycle becomes one row with its final state. Every folded entry is
 * one click away, and nothing is removed from the backend audit log.
 * A filter (All / Attack / Analyst / Automation) narrows the feed; its
 * choice is remembered per browser.
 */

import { useState } from 'react';
import LevelBadge from './LevelBadge';
import MitreBadge from './MitreBadge';
import Timestamp from './Timestamp';
import { formatDateTime, formatTimeRange, formatUtcTooltip, parseTimestamp } from '../lib/format';
import {
  TIMELINE_FILTERS,
  describeAuditEntry,
  filterTimelineRows,
  groupTimelineEntries,
  type TimelineCategory,
  type TimelineFilter,
  type TimelineRow,
} from '../lib/timelineGroups';
import type { Alert, TimelineEntry } from '../lib/types';

const FILTER_STORAGE_KEY = 'safesoc.incidentTimeline.filter';

const FILTER_LABELS: Record<TimelineFilter, string> = {
  all: 'All',
  attack: 'Attack',
  analyst: 'Analyst',
  automation: 'Automation',
};

const DOT_COLORS: Record<TimelineCategory, string> = {
  attack: 'bg-orange-500',
  analyst: 'bg-blue-500',
  automation: 'bg-slate-600',
};

function readStoredFilter(): TimelineFilter {
  try {
    const stored = window.localStorage.getItem(FILTER_STORAGE_KEY);
    return TIMELINE_FILTERS.includes(stored as TimelineFilter) ? (stored as TimelineFilter) : 'all';
  } catch {
    return 'all';
  }
}

function storeFilter(filter: TimelineFilter): void {
  try {
    window.localStorage.setItem(FILTER_STORAGE_KEY, filter);
  } catch {
    // Storage blocked (private mode, policy) — the choice just isn't remembered.
  }
}

function sameSecond(a: string, b: string): boolean {
  const start = parseTimestamp(a);
  const end = parseTimestamp(b);
  return !!start && !!end && Math.floor(start.getTime() / 1000) === Math.floor(end.getTime() / 1000);
}

/**
 * "14:16:16 IST · 21 minutes ago" for one entry (or a group within one
 * second), "16:33:29–16:35:31 IST · 21 minutes ago" for a group. The
 * tooltip gives the exact local and UTC times of both ends.
 */
function RowTime({ entries }: { entries: TimelineEntry[] }) {
  const first = entries[0].timestamp;
  const last = entries[entries.length - 1].timestamp;
  return (
    <p className="mt-1.5 text-xs text-slate-500">
      {sameSecond(first, last) || !parseTimestamp(last) ? (
        <Timestamp iso={first} format="time" />
      ) : (
        <span title={`${formatDateTime(first)} – ${formatDateTime(last)}\n${formatUtcTooltip(first)} – ${formatUtcTooltip(last)}`}>
          {formatTimeRange(first, last)}
        </span>
      )}
      {' · '}
      <Timestamp iso={last} format="relative" />
    </p>
  );
}

function ExpandToggle({ expanded, controls, onToggle, count }: { expanded: boolean; controls: string; onToggle: () => void; count: number }) {
  return (
    <button
      type="button"
      aria-expanded={expanded}
      aria-controls={controls}
      onClick={onToggle}
      className="text-xs text-blue-400 hover:underline focus:outline-none focus-visible:ring-1 focus-visible:ring-blue-500"
    >
      {expanded ? 'Hide' : `Show ${count}`}
    </button>
  );
}

function AlertRow({ row, expanded, onToggle }: { row: TimelineRow; expanded: boolean; onToggle: () => void }) {
  const alerts = row.entries.map((entry) => entry.data as unknown as Alert);
  const first = alerts[0];
  const withMitre = alerts.find((alert) => alert.mitre_technique);
  const users = [...new Set(alerts.map((alert) => alert.user).filter((user) => user && user !== 'unknown'))];
  const listId = `${row.key}-alerts`;

  return (
    <>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <LevelBadge level={first.severity} />
        {alerts.length > 1 ? (
          <span className="text-slate-300">
            {alerts.length} × {first.action}
          </span>
        ) : null}
        <span className="font-mono text-slate-300">{first.host_id}</span>
        {alerts.length === 1 && <span className="text-slate-500">{first.action}</span>}
        <MitreBadge technique={withMitre?.mitre_technique ?? null} tactic={withMitre?.mitre_tactic ?? null} />
        {alerts.length > 1 && <ExpandToggle expanded={expanded} controls={listId} onToggle={onToggle} count={alerts.length} />}
      </div>
      {alerts.length > 1 && users.length > 0 && <p className="mt-1 text-xs text-slate-500">users: {users.join(', ')}</p>}
      <RowTime entries={row.entries} />
      {alerts.length > 1 && expanded && (
        <ul id={listId} className="mt-2 space-y-1 border-l border-slate-800 pl-3">
          {alerts.map((alert, index) => (
            <li key={alert.alert_id ?? `${row.key}-${index}`} className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <Timestamp iso={alert.timestamp} format="time" className="tabular-nums text-slate-500" />
              {alert.user && <span>{alert.user}</span>}
              <span className="truncate text-slate-500">{alert.description}</span>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

function SoarLifecycleRow({
  row,
  expanded,
  onToggle,
}: {
  row: Extract<TimelineRow, { kind: 'soar_lifecycle' }>;
  expanded: boolean;
  onToggle: () => void;
}) {
  const listId = `${row.key}-steps`;
  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-slate-400" title={row.detail ?? undefined}>
          {row.text}
        </p>
        <ExpandToggle expanded={expanded} controls={listId} onToggle={onToggle} count={row.entries.length} />
      </div>
      <RowTime entries={row.entries} />
      {expanded && (
        <ul id={listId} className="mt-2 space-y-1 border-l border-slate-800 pl-3">
          {row.entries.map((entry, index) => (
            <li key={`${row.key}-${index}`} className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
              <Timestamp iso={entry.timestamp} format="time" className="tabular-nums" />
              <span>{describeAuditEntry(entry.data)}</span>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

export default function IncidentTimeline({ entries }: { entries: TimelineEntry[] }) {
  const [filter, setFilter] = useState<TimelineFilter>(readStoredFilter);
  // Every group starts collapsed; a key is only here once the analyst
  // expands that row, and leaves again when they collapse it.
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());

  if (entries.length === 0) {
    return <p className="text-sm text-slate-500">Nothing to show yet — alerts, activity, and notes will appear here as they happen.</p>;
  }

  const rows = filterTimelineRows(groupTimelineEntries(entries), filter);

  const toggle = (key: string) =>
    setExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const chooseFilter = (next: TimelineFilter) => {
    setFilter(next);
    storeFilter(next);
  };

  return (
    <div>
      <div role="group" aria-label="Filter timeline" className="mb-3 flex flex-wrap gap-1.5">
        {TIMELINE_FILTERS.map((option) => (
          <button
            key={option}
            type="button"
            aria-pressed={filter === option}
            onClick={() => chooseFilter(option)}
            className={`rounded-full px-2.5 py-0.5 text-xs font-medium transition-colors focus:outline-none focus-visible:ring-1 focus-visible:ring-blue-500 ${
              filter === option
                ? 'bg-blue-600 text-white'
                : 'border border-slate-800 bg-slate-900 text-slate-400 hover:border-slate-700 hover:text-slate-200'
            }`}
          >
            {FILTER_LABELS[option]}
          </button>
        ))}
      </div>

      {rows.length === 0 ? (
        <p className="text-sm text-slate-500">Nothing in this view — try another filter.</p>
      ) : (
        <ol className="space-y-0">
          {rows.map((row, index) => {
            const isAutomation = row.category === 'automation';
            const isExpanded = expanded.has(row.key);
            return (
              <li key={row.key} className={`relative flex gap-3 last:pb-0 ${isAutomation ? 'pb-2' : 'pb-4'}`}>
                <div className="flex flex-col items-center">
                  <span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${DOT_COLORS[row.category]}`} />
                  {index < rows.length - 1 && <span className="mt-1 w-px flex-1 bg-slate-800" />}
                </div>
                <div
                  className={`flex-1 rounded-lg border ${
                    isAutomation ? 'border-slate-800/50 bg-slate-950/30 px-3 py-2' : 'border-slate-800/80 bg-slate-950/50 p-3'
                  }`}
                >
                  {row.kind === 'alert' && <AlertRow row={row} expanded={isExpanded} onToggle={() => toggle(row.key)} />}

                  {row.kind === 'soar_lifecycle' && (
                    <SoarLifecycleRow row={row} expanded={isExpanded} onToggle={() => toggle(row.key)} />
                  )}

                  {row.kind === 'audit' && (
                    <>
                      <div className="flex flex-wrap items-center gap-2">
                        <p className={isAutomation ? 'text-xs text-slate-400' : 'text-sm text-slate-200'}>
                          {row.text}
                          {row.entries.length > 1 && <span className="text-slate-500"> (×{row.entries.length})</span>}
                        </p>
                        {row.entries.length > 1 && (
                          <ExpandToggle
                            expanded={isExpanded}
                            controls={`${row.key}-entries`}
                            onToggle={() => toggle(row.key)}
                            count={row.entries.length}
                          />
                        )}
                      </div>
                      <RowTime entries={row.entries} />
                      {row.entries.length > 1 && isExpanded && (
                        <ul id={`${row.key}-entries`} className="mt-2 space-y-1 border-l border-slate-800 pl-3">
                          {row.entries.map((entry, entryIndex) => (
                            <li key={`${row.key}-${entryIndex}`} className="text-xs text-slate-500">
                              <Timestamp iso={entry.timestamp} format="time" className="tabular-nums" />
                            </li>
                          ))}
                        </ul>
                      )}
                    </>
                  )}

                  {row.kind === 'note' && (
                    <>
                      <p className="text-sm text-slate-200">{String(row.entries[0].data.body ?? '')}</p>
                      <RowTime entries={row.entries} />
                    </>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}
