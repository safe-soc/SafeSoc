/**
 * SafeSOC — Incident Investigation Timeline (SS-099)
 * Renders GET /api/v1/incidents/{id}/timeline's chronological merge of
 * linked alerts, audit-log activity, and notes as one narrative feed —
 * type-specific rendering per entry, oldest first (the order the
 * backend already returns them in).
 */

import LevelBadge from './LevelBadge';
import MitreBadge from './MitreBadge';
import { formatDateTime, formatRelativeTime } from '../lib/format';
import type { Alert, TimelineEntry } from '../lib/types';

const AUDIT_ACTION_LABELS: Record<string, string> = {
  'incident.created': 'Incident created',
  'incident.merged': 'Incident merged with a new detection',
  'incident.status_transitioned': 'Status changed',
  'incident.assigned': 'Assigned',
  'incident.alert_linked': 'Alert linked',
  'incident.note_added': 'Note added',
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

function describeAuditEntry(data: Record<string, unknown>): string {
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

function EntryDot({ type }: { type: TimelineEntry['type'] }) {
  const colors: Record<TimelineEntry['type'], string> = {
    alert: 'bg-orange-500',
    audit: 'bg-blue-500',
    note: 'bg-slate-400',
  };
  return <span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${colors[type]}`} />;
}

export default function IncidentTimeline({ entries }: { entries: TimelineEntry[] }) {
  if (entries.length === 0) {
    return <p className="text-sm text-slate-500">Nothing to show yet — alerts, activity, and notes will appear here as they happen.</p>;
  }

  return (
    <ol className="space-y-0">
      {entries.map((entry, index) => {
        const key = `${entry.type}-${entry.timestamp}-${index}`;
        return (
          <li key={key} className="relative flex gap-3 pb-4 last:pb-0">
            <div className="flex flex-col items-center">
              <EntryDot type={entry.type} />
              {index < entries.length - 1 && <span className="mt-1 w-px flex-1 bg-slate-800" />}
            </div>
            <div className="flex-1 rounded-lg border border-slate-800/80 bg-slate-950/50 p-3">
              {entry.type === 'alert' && (() => {
                const alert = entry.data as unknown as Alert;
                return (
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <LevelBadge level={alert.severity} />
                    <span className="font-mono text-slate-300">{alert.host_id}</span>
                    <span className="text-slate-500">{alert.action}</span>
                    <MitreBadge technique={alert.mitre_technique ?? null} tactic={alert.mitre_tactic ?? null} />
                  </div>
                );
              })()}

              {entry.type === 'audit' && (
                <p className="text-sm text-slate-200">{describeAuditEntry(entry.data)}</p>
              )}

              {entry.type === 'note' && (
                <p className="text-sm text-slate-200">{String(entry.data.body ?? '')}</p>
              )}

              <p className="mt-1.5 text-xs text-slate-500" title={formatDateTime(entry.timestamp)}>
                {formatRelativeTime(entry.timestamp)}
              </p>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
