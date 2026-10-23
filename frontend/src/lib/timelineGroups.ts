/**
 * SafeSOC — Incident Timeline Grouping
 * Pure display logic for components/IncidentTimeline.tsx: turns the
 * backend's flat, chronological entry list into rows, collapsing noise
 * without hiding anything (every collapsed entry stays reachable behind
 * the row's expand toggle, and the backend audit log is untouched).
 *
 * 1. SOAR action lifecycles: the started / succeeded / verified events
 *    of one action collapse into ONE row showing its final state, placed
 *    where the lifecycle began. Those three events carry no action_id in
 *    their audit details (services/soar_execution.py::_emit records only
 *    action_type/incident_id/result), so they're matched by action_type
 *    (+ playbook_id when present). A new "started" for the same type
 *    opens a new lifecycle. A later soar.action.failed or
 *    verification_failed for that type marks the lifecycle failed.
 *    Triggered, awaiting_approval, approved, rejected, failed, skipped
 *    and verification_failed always stay their own rows.
 * 2. Consecutive repeats: adjacent alerts with the same action, host and
 *    severity, and adjacent audit rows with the same description, fold
 *    into one row. Only adjacent ones: a different entry in between
 *    always breaks the group, so chronological order is preserved.
 *    Notes never fold.
 *
 * Kept free of React and of runtime imports so it can be exercised
 * directly (see the verification notes in the commit that added it).
 */

import type { TimelineEntry } from './types';

export type TimelineCategory = 'attack' | 'analyst' | 'automation';
export type TimelineFilter = 'all' | TimelineCategory;
export const TIMELINE_FILTERS: TimelineFilter[] = ['all', 'attack', 'analyst', 'automation'];

interface RowBase {
  /** Stable, unique React key derived from the row's first entry — never the row index alone. */
  key: string;
  category: TimelineCategory;
  /** The entries this row stands for, oldest first (always at least one). */
  entries: TimelineEntry[];
}

export type TimelineRow =
  | (RowBase & { kind: 'alert' })
  | (RowBase & { kind: 'audit'; text: string })
  | (RowBase & { kind: 'soar_lifecycle'; text: string; detail: string | null })
  | (RowBase & { kind: 'note' });

const AUDIT_ACTION_LABELS: Record<string, string> = {
  'incident.created': 'Incident created',
  'incident.merged': 'Incident merged with a new detection',
  'incident.status_transitioned': 'Status changed',
  'incident.assigned': 'Assigned',
  'incident.alert_linked': 'Alert linked',
  'incident.note_added': 'Note added',
  'incident.tagged': 'Tags updated',
  // SOAR lifecycle (Phase 3.5) — the backend decides which of these
  // reach the timeline (services/incident_timeline.py); this only
  // decides how they read.
  'soar.playbook.triggered': 'SOAR playbook triggered',
  'soar.playbook_run.cancelled': 'SOAR playbook cancelled',
  'soar.action.skipped': 'SOAR action skipped',
  'soar.action.awaiting_approval': 'SOAR action awaiting approval',
  'soar.action.approved': 'SOAR action approved',
  'soar.action.rejected': 'SOAR action rejected',
  'soar.action.started': 'SOAR action started',
  'soar.action.succeeded': 'SOAR action succeeded',
  'soar.action.failed': 'SOAR action failed',
  'soar.action.verified': 'SOAR action verified',
  'soar.action.verification_failed': 'SOAR action could not be verified',
};

// Why a SOAR action never ran. Mirrors services/soar.py's own
// _SKIP_* reasons — worth spelling out rather than showing the raw
// enum, since "we did nothing here" needs to explain itself.
const SOAR_SKIP_REASONS: Record<string, string> = {
  required_evidence_unavailable: 'this incident carries no such evidence',
  parameter_validation_failed: 'its parameters failed validation',
};

const LIFECYCLE_ACTIONS = new Set(['soar.action.started', 'soar.action.succeeded', 'soar.action.verified']);
const LIFECYCLE_FAILURE_ACTIONS = new Set(['soar.action.failed', 'soar.action.verification_failed']);

function auditAction(entry: TimelineEntry): string {
  return typeof entry.data.action === 'string' ? entry.data.action : 'unknown';
}

function auditDetails(entry: TimelineEntry): Record<string, unknown> {
  const details = entry.data.details;
  return details && typeof details === 'object' ? (details as Record<string, unknown>) : {};
}

function str(value: unknown): string {
  return value === undefined || value === null ? '' : String(value);
}

export function describeAuditEntry(data: Record<string, unknown>): string {
  const action = typeof data.action === 'string' ? data.action : 'unknown';
  const label = AUDIT_ACTION_LABELS[action] ?? action;
  const details = (data.details ?? {}) as Record<string, unknown>;
  if (action === 'incident.status_transitioned' && details.from_status && details.to_status) {
    return `${label}: ${details.from_status} → ${details.to_status}`;
  }
  if (action === 'soar.playbook.triggered' && details.playbook_id) {
    return `${label}: ${details.playbook_id}`;
  }
  if (action === 'soar.action.skipped' && details.action_type) {
    const reason = typeof details.reason === 'string' ? SOAR_SKIP_REASONS[details.reason] ?? details.reason : null;
    return reason ? `${label}: ${details.action_type} — ${reason}` : `${label}: ${details.action_type}`;
  }
  if (action.startsWith('soar.action.') && details.action_type) {
    return `${label}: ${details.action_type}`;
  }
  return label;
}

export function entryCategory(entry: TimelineEntry): TimelineCategory {
  if (entry.type === 'alert') return 'attack';
  if (entry.type === 'note') return 'analyst';
  const action = auditAction(entry);
  if (action.startsWith('soar.') || action === 'incident.merged') return 'automation';
  // Created by the correlation engine (no actor) vs. opened by an analyst.
  if (action === 'incident.created') return entry.data.actor_user_id ? 'analyst' : 'automation';
  return 'analyst';
}

function lifecycleKey(entry: TimelineEntry): string {
  const details = auditDetails(entry);
  if (details.action_id) return `id:${str(details.action_id)}`;
  return `type:${str(details.action_type)}|${str(details.playbook_id)}`;
}

/** A short reason for a "succeeded but skipped" result, plus the full message for the tooltip. */
function skippedReason(result: Record<string, unknown>): { short: string; full: string | null } {
  const message = typeof result.message === 'string' ? result.message : null;
  if (message && /no threat-intel provider/i.test(message)) return { short: 'no provider', full: message };
  if (message && /is not an IP/i.test(message)) return { short: 'not an IP', full: message };
  return { short: 'nothing to act on', full: message };
}

interface Lifecycle {
  key: string;
  entries: TimelineEntry[];
  hasStarted: boolean;
  closed: boolean;
  failed: boolean;
}

function lifecycleRow(lifecycle: Lifecycle, firstIndex: number): TimelineRow {
  const actionType = str(auditDetails(lifecycle.entries[0]).action_type) || 'action';
  const last = lifecycle.entries[lifecycle.entries.length - 1];
  const lastAction = auditAction(last);
  let state = 'running';
  let detail: string | null = null;
  if (lifecycle.failed) {
    state = 'failed';
  } else if (lifecycle.entries.some((entry) => auditAction(entry) === 'soar.action.verified')) {
    state = 'succeeded · verified';
  } else if (lastAction === 'soar.action.succeeded') {
    const result = auditDetails(last).result;
    if (result && typeof result === 'object' && (result as Record<string, unknown>).skipped) {
      const reason = skippedReason(result as Record<string, unknown>);
      state = `succeeded (skipped: ${reason.short})`;
      detail = reason.full;
    } else {
      state = 'succeeded';
    }
  }
  return {
    kind: 'soar_lifecycle',
    key: `soar:${lifecycle.key}:${lifecycle.entries[0].timestamp}:${firstIndex}`,
    category: 'automation',
    entries: lifecycle.entries,
    text: `SOAR: ${actionType} — ${state}`,
    detail,
  };
}

type Item = { entry: TimelineEntry; index: number } | { lifecycle: Lifecycle; index: number };

function alertSignature(entry: TimelineEntry): string {
  return [str(entry.data.action), str(entry.data.host_id), str(entry.data.severity)].join('\u0000');
}

export function groupTimelineEntries(entries: TimelineEntry[]): TimelineRow[] {
  // Pass 1: pull each SOAR action's lifecycle events into one item,
  // positioned at the first of them.
  const items: Item[] = [];
  const openLifecycles = new Map<string, Lifecycle>();
  entries.forEach((entry, index) => {
    if (entry.type === 'audit') {
      const action = auditAction(entry);
      if (LIFECYCLE_ACTIONS.has(action)) {
        const key = lifecycleKey(entry);
        let lifecycle = openLifecycles.get(key);
        const startsAnother = action === 'soar.action.started' && lifecycle?.hasStarted;
        if (!lifecycle || lifecycle.closed || startsAnother) {
          lifecycle = { key, entries: [], hasStarted: false, closed: false, failed: false };
          openLifecycles.set(key, lifecycle);
          items.push({ lifecycle, index });
        }
        lifecycle.entries.push(entry);
        if (action === 'soar.action.started') lifecycle.hasStarted = true;
        if (action === 'soar.action.verified') lifecycle.closed = true;
        return;
      }
      if (LIFECYCLE_FAILURE_ACTIONS.has(action)) {
        const lifecycle = openLifecycles.get(lifecycleKey(entry));
        if (lifecycle && !lifecycle.closed) lifecycle.failed = true;
      }
    }
    items.push({ entry, index });
  });

  // Pass 2: fold adjacent repeats.
  const rows: TimelineRow[] = [];
  for (const item of items) {
    if ('lifecycle' in item) {
      rows.push(lifecycleRow(item.lifecycle, item.index));
      continue;
    }
    const { entry, index } = item;
    const previous = rows[rows.length - 1];

    if (entry.type === 'alert') {
      if (previous?.kind === 'alert' && alertSignature(previous.entries[0]) === alertSignature(entry)) {
        previous.entries.push(entry);
      } else {
        rows.push({
          kind: 'alert',
          key: `alert:${str(entry.data.alert_id) || `${entry.timestamp}:${index}`}`,
          category: 'attack',
          entries: [entry],
        });
      }
    } else if (entry.type === 'audit') {
      const text = describeAuditEntry(entry.data);
      if (previous?.kind === 'audit' && previous.text === text) {
        previous.entries.push(entry);
      } else {
        rows.push({
          kind: 'audit',
          key: `audit:${auditAction(entry)}:${entry.timestamp}:${index}`,
          category: entryCategory(entry),
          entries: [entry],
          text,
        });
      }
    } else {
      rows.push({
        kind: 'note',
        key: `note:${str(entry.data.id) || `${entry.timestamp}:${index}`}`,
        category: 'analyst',
        entries: [entry],
      });
    }
  }
  return rows;
}

export function filterTimelineRows(rows: TimelineRow[], filter: TimelineFilter): TimelineRow[] {
  return filter === 'all' ? rows : rows.filter((row) => row.category === filter);
}
