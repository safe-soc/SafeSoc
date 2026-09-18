/**
 * SafeSOC — SOAR Status Badge
 * Shared between SoarPlaybookRun.status and SoarActionExecution.status
 * (services/soar.py's two separate but overlapping state machines) —
 * both vocabularies fit one color map since a run's states are a
 * subset in spirit of an action's (pending/running≈executing/awaiting
 * approval/completed≈succeeded/failed/cancelled≈rejected).
 */

const STYLES: Record<string, string> = {
  pending: 'bg-slate-800 text-slate-300 ring-1 ring-inset ring-slate-700',
  running: 'bg-blue-500/10 text-blue-300 ring-1 ring-inset ring-blue-500/30',
  executing: 'bg-blue-500/10 text-blue-300 ring-1 ring-inset ring-blue-500/30',
  awaiting_approval: 'bg-amber-500/10 text-amber-300 ring-1 ring-inset ring-amber-500/30',
  approved: 'bg-blue-500/10 text-blue-300 ring-1 ring-inset ring-blue-500/30',
  succeeded: 'bg-green-500/10 text-green-300 ring-1 ring-inset ring-green-500/30',
  completed: 'bg-green-500/10 text-green-300 ring-1 ring-inset ring-green-500/30',
  failed: 'bg-red-500/15 text-red-300 ring-1 ring-inset ring-red-500/40',
  rejected: 'bg-red-500/10 text-red-300 ring-1 ring-inset ring-red-500/30',
  cancelled: 'bg-slate-800 text-slate-400 ring-1 ring-inset ring-slate-700',
};

const DOT: Record<string, string> = {
  pending: 'bg-slate-400',
  running: 'bg-blue-400',
  executing: 'bg-blue-400',
  awaiting_approval: 'bg-amber-400',
  approved: 'bg-blue-400',
  succeeded: 'bg-green-400',
  completed: 'bg-green-400',
  failed: 'bg-red-400',
  rejected: 'bg-red-400',
  cancelled: 'bg-slate-500',
};

const PULSE = new Set(['running', 'executing', 'awaiting_approval']);

export default function SoarStatusBadge({ status }: { status: string }) {
  const classes = STYLES[status] ?? STYLES.pending;
  const dot = DOT[status] ?? DOT.pending;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${classes}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${dot} ${PULSE.has(status) ? 'animate-pulse' : ''}`} />
      {status.replace(/_/g, ' ')}
    </span>
  );
}
