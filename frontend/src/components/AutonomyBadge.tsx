/**
 * SafeSOC — Autonomy Badge
 * The one distinction the Phase 3 spec calls out explicitly: an
 * AUTOMATIC action ran without a human in the loop; an
 * APPROVAL_REQUIRED action never executes until an analyst approves
 * it. Rendered next to every action so that distinction is visible at
 * a glance, not just inferable from status.
 */

import type { AutonomyClass } from '../lib/types';

export default function AutonomyBadge({ autonomyClass }: { autonomyClass: AutonomyClass }) {
  if (autonomyClass === 'automatic') {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-slate-800 px-2.5 py-0.5 text-xs font-medium text-slate-300 ring-1 ring-inset ring-slate-700">
        Automatic Response
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-purple-500/10 px-2.5 py-0.5 text-xs font-medium text-purple-300 ring-1 ring-inset ring-purple-500/30">
      Human Approval Required
    </span>
  );
}
