/**
 * SafeSOC — Investigation Evidence Panel (SS-083)
 * Renders the raw structured data behind an assistant answer
 * (InvestigateResponse.data), collapsed by default. Every MCP tool's
 * output is just an object whose values are either scalars or arrays
 * of objects, so one generic renderer covers both list-shaped outputs
 * (e.g. { total, alerts: [...] }) and snapshot outputs (e.g.
 * { host_id, risk_score, recent_alerts: [...] }) without per-tool code.
 */

import { useState } from 'react';
import { ChevronRightIcon } from './icons';

interface EvidencePanelProps {
  data: Record<string, unknown>;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function formatScalar(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function EvidenceList({ items }: { items: unknown[] }) {
  if (items.length === 0) {
    return <p className="text-xs text-slate-500">No items.</p>;
  }

  const rows = items.map((item) => (isPlainObject(item) ? item : { value: item }));
  const columns = Array.from(new Set(rows.flatMap((row) => Object.keys(row)))).slice(0, 6);

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead>
          <tr className="text-slate-500">
            {columns.map((col) => (
              <th key={col} className="whitespace-nowrap px-2 py-1 font-medium">
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index} className="border-t border-slate-800/60">
              {columns.map((col) => (
                <td key={col} className="max-w-[16rem] truncate whitespace-nowrap px-2 py-1 text-slate-300">
                  {formatScalar(row[col])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function EvidencePanel({ data }: EvidencePanelProps) {
  const [isOpen, setIsOpen] = useState(false);
  const entries = Object.entries(data);

  if (entries.length === 0) {
    return null;
  }

  return (
    <div className="mt-1 w-full max-w-full rounded-lg border border-slate-800 bg-slate-900/60">
      <button
        type="button"
        onClick={() => setIsOpen((prev) => !prev)}
        className="flex w-full items-center gap-1.5 px-2.5 py-1.5 text-left text-xs text-slate-400 hover:text-slate-200"
      >
        <ChevronRightIcon className={`h-3.5 w-3.5 transition-transform ${isOpen ? 'rotate-90' : ''}`} />
        Evidence
      </button>
      {isOpen && (
        <div className="space-y-2 border-t border-slate-800 px-2.5 py-2">
          {entries.map(([key, value]) => (
            <div key={key}>
              <p className="mb-1 text-[11px] font-medium uppercase tracking-wide text-slate-500">
                {key.replace(/_/g, ' ')}
              </p>
              {Array.isArray(value) ? (
                <EvidenceList items={value} />
              ) : (
                <p className="text-xs text-slate-300">{formatScalar(value)}</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
