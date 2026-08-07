/**
 * SafeSOC — KPI Card
 * A single top-line metric for the Dashboard's summary row. `tone`
 * tints the accent/icon only — the card itself stays neutral so a row
 * of four doesn't turn into a wall of color.
 */

import type { ReactNode } from 'react';
import Spinner from './Spinner';

type Tone = 'default' | 'warning' | 'danger' | 'info';

const TONE_CLASSES: Record<Tone, string> = {
  default: 'text-slate-300 bg-slate-800',
  info: 'text-blue-300 bg-blue-500/10',
  warning: 'text-amber-300 bg-amber-500/10',
  danger: 'text-red-300 bg-red-500/10',
};

export default function KpiCard({
  label,
  value,
  icon,
  tone = 'default',
  isLoading = false,
  hint,
}: {
  label: string;
  value: number | string;
  icon: ReactNode;
  tone?: Tone;
  isLoading?: boolean;
  hint?: string;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm shadow-black/20 transition-colors hover:border-slate-700">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
          <div className="mt-2 flex items-center gap-2">
            {isLoading ? (
              <Spinner className="h-5 w-5 text-slate-600" />
            ) : (
              <p className="text-3xl font-semibold tabular-nums text-slate-50">{value}</p>
            )}
          </div>
          {hint && <p className="mt-1 text-xs text-slate-500">{hint}</p>}
        </div>
        <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${TONE_CLASSES[tone]}`}>
          {icon}
        </span>
      </div>
    </div>
  );
}
