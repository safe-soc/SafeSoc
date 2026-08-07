/**
 * SafeSOC — Incident Status Badge
 * Distinct from LevelBadge (severity/risk) — incident status is a
 * different vocabulary (open/investigating/resolved/false_positive).
 */

import type { IncidentStatus } from '../lib/types';

const STYLES: Record<IncidentStatus, string> = {
  open: 'bg-blue-500/10 text-blue-300 ring-1 ring-inset ring-blue-500/30',
  investigating: 'bg-yellow-500/10 text-yellow-300 ring-1 ring-inset ring-yellow-500/30',
  resolved: 'bg-green-500/10 text-green-300 ring-1 ring-inset ring-green-500/30',
  false_positive: 'bg-slate-800 text-slate-400 ring-1 ring-inset ring-slate-700',
};

const DOT: Record<IncidentStatus, string> = {
  open: 'bg-blue-400',
  investigating: 'bg-yellow-400',
  resolved: 'bg-green-400',
  false_positive: 'bg-slate-500',
};

const LABELS: Record<IncidentStatus, string> = {
  open: 'Open',
  investigating: 'Investigating',
  resolved: 'Resolved',
  false_positive: 'False Positive',
};

export default function StatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${STYLES[status]}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${DOT[status]} ${status === 'investigating' ? 'animate-pulse' : ''}`} />
      {LABELS[status]}
    </span>
  );
}
