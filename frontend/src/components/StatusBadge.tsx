/**
 * SafeSOC — Incident Status Badge
 * Distinct from LevelBadge (severity/risk) — incident status is a
 * different vocabulary (open/investigating/resolved/false_positive).
 */

import type { IncidentStatus } from '../lib/types';

const COLORS: Record<IncidentStatus, string> = {
  open: 'bg-blue-600/80 text-blue-50',
  investigating: 'bg-yellow-600/80 text-yellow-50',
  resolved: 'bg-green-600/80 text-green-50',
  false_positive: 'bg-slate-600 text-slate-100',
};

const LABELS: Record<IncidentStatus, string> = {
  open: 'Open',
  investigating: 'Investigating',
  resolved: 'Resolved',
  false_positive: 'False Positive',
};

export default function StatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${COLORS[status]}`}>
      {LABELS[status]}
    </span>
  );
}
