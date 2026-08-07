/**
 * SafeSOC — Level Badge
 * Color-coded low/medium/high/critical badge — shared between alert
 * severity (SS-059) and endpoint risk level (SS-060, same 4-tier
 * vocabulary in the backend's Severity/RiskLevel enums).
 */

const COLORS: Record<string, string> = {
  low: 'bg-slate-700 text-slate-200',
  medium: 'bg-yellow-600/80 text-yellow-50',
  high: 'bg-orange-600/80 text-orange-50',
  critical: 'bg-red-600/90 text-red-50',
};

export default function LevelBadge({ level }: { level: string }) {
  const classes = COLORS[level] ?? 'bg-slate-700 text-slate-200';
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium capitalize ${classes}`}>{level}</span>
  );
}
