/**
 * SafeSOC — Compliance Status Badge
 * Renders ONLY the four approved phrasings for ComplianceStatus. Must
 * never render "compliant"/"non-compliant"/"legally compliant" in any
 * form — SafeSOC telemetry is evidence, never a legal-compliance
 * determination. See docs/compliance.md.
 */

import type { ComplianceStatus } from '../lib/types';

const COMPLIANCE_STATUS_LABELS: Record<ComplianceStatus, string> = {
  evidence_available: 'Evidence available',
  partially_supported: 'Control appears supported',
  gap: 'Evidence gap',
  not_assessable: 'Not assessable from SafeSOC telemetry',
};

const STYLES: Record<ComplianceStatus, string> = {
  evidence_available: 'bg-green-500/10 text-green-300 ring-1 ring-inset ring-green-500/30',
  partially_supported: 'bg-blue-500/10 text-blue-300 ring-1 ring-inset ring-blue-500/30',
  gap: 'bg-amber-500/10 text-amber-300 ring-1 ring-inset ring-amber-500/30',
  not_assessable: 'bg-slate-800 text-slate-400 ring-1 ring-inset ring-slate-700',
};

const DOT: Record<ComplianceStatus, string> = {
  evidence_available: 'bg-green-400',
  partially_supported: 'bg-blue-400',
  gap: 'bg-amber-400',
  not_assessable: 'bg-slate-500',
};

export default function ComplianceStatusBadge({ status }: { status: ComplianceStatus }) {
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-0.5 text-xs font-medium ${STYLES[status]}`}>
      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${DOT[status]}`} />
      {COMPLIANCE_STATUS_LABELS[status]}
    </span>
  );
}
