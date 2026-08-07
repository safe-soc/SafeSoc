/**
 * SafeSOC — Level Badge
 * Color-coded low/medium/high/critical badge — shared between alert
 * severity (SS-059) and endpoint risk level (SS-060, same 4-tier
 * vocabulary in the backend's Severity/RiskLevel enums).
 */

const STYLES: Record<string, string> = {
  low: 'bg-slate-800 text-slate-300 ring-1 ring-inset ring-slate-700',
  medium: 'bg-yellow-500/10 text-yellow-300 ring-1 ring-inset ring-yellow-500/30',
  high: 'bg-orange-500/10 text-orange-300 ring-1 ring-inset ring-orange-500/30',
  critical: 'bg-red-500/15 text-red-300 ring-1 ring-inset ring-red-500/40',
};

const DOT: Record<string, string> = {
  low: 'bg-slate-400',
  medium: 'bg-yellow-400',
  high: 'bg-orange-400',
  critical: 'bg-red-400',
};

export default function LevelBadge({ level }: { level: string }) {
  const classes = STYLES[level] ?? STYLES.low;
  const dot = DOT[level] ?? DOT.low;
  const isCritical = level === 'critical';

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${classes}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${dot} ${isCritical ? 'animate-pulse' : ''}`} />
      {level}
    </span>
  );
}
