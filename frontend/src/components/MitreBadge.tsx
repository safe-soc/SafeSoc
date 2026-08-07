/**
 * SafeSOC — MITRE ATT&CK Badge
 * Renders a technique/tactic pair resolved via lib/alertLookup.ts's
 * best-effort alert lookup. Nothing is invented — a caller that
 * couldn't resolve MITRE data for a given alert simply doesn't render
 * this badge for it.
 */

export default function MitreBadge({ technique, tactic }: { technique: string | null; tactic: string | null }) {
  if (!technique && !tactic) return null;

  return (
    <span
      className="inline-flex items-center gap-1 rounded border border-purple-700/50 bg-purple-900/30 px-2 py-0.5 text-xs font-medium text-purple-300"
      title={tactic ?? undefined}
    >
      <svg viewBox="0 0 24 24" className="h-3 w-3" fill="none" aria-hidden="true">
        <path d="M12 2 3 6v6c0 5 4 8.5 9 10 5-1.5 9-5 9-10V6l-9-4z" stroke="currentColor" strokeWidth="1.4" />
      </svg>
      {technique ?? tactic}
    </span>
  );
}
