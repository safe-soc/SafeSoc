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
};

function describeAuditEntry(data: Record<string, unknown>): string {
  const action = typeof data.action === 'string' ? data.action : 'unknown';
  const label = AUDIT_ACTION_LABELS[action] ?? action;
  const details = (data.details ?? {}) as Record<string, unknown>;
  if (action === 'incident.status_transitioned' && details.from_status && details.to_status) {
    return `${label}: ${details.from_status} → ${details.to_status}`;
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
