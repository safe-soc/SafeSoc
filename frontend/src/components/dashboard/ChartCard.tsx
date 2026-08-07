/**
 * SafeSOC — Chart Card
 * Shared card chrome (title, optional subtitle/actions) for every
 * Dashboard chart/widget, so the grid stays visually consistent.
 */

import type { ReactNode } from 'react';

export default function ChartCard({
  title,
  subtitle,
  children,
  className = '',
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm shadow-black/20 ${className}`}>
      <div className="mb-4">
        <h2 className="text-sm font-semibold text-slate-200">{title}</h2>
        {subtitle && <p className="text-xs text-slate-500">{subtitle}</p>}
      </div>
      {children}
    </div>
  );
}
