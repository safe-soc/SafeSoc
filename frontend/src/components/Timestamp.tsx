/**
 * SafeSOC — Timestamp
 * Renders one time in the app-wide convention (lib/format.ts): local
 * time with its zone, and a tooltip with the UTC equivalent, so an
 * analyst can line it up with AI answers and raw logs (both UTC).
 *
 *   datetime  "22 Oct 2026, 14:16:16 IST"  tooltip: UTC
 *   time      "14:16:16 IST"               tooltip: local date+time, then UTC
 *   relative  "21 minutes ago"             tooltip: local date+time, then UTC
 *
 * A missing or unparseable value renders "—", never "Invalid Date".
 */

import {
  formatDateTime,
  formatRelativeTime,
  formatTime,
  formatUtcTooltip,
  parseTimestamp,
  relativeTimeTooltip,
} from '../lib/format';

export type TimestampFormat = 'datetime' | 'time' | 'relative';

export default function Timestamp({
  iso,
  format = 'datetime',
  className,
}: {
  iso: string | null | undefined;
  format?: TimestampFormat;
  className?: string;
}) {
  if (!parseTimestamp(iso)) {
    return <span className={className}>—</span>;
  }

  const text = format === 'relative' ? formatRelativeTime(iso) : format === 'time' ? formatTime(iso) : formatDateTime(iso);
  const title = format === 'datetime' ? formatUtcTooltip(iso) : relativeTimeTooltip(iso);

  return (
    <time dateTime={iso ?? undefined} title={title} className={className}>
      {text}
    </time>
  );
}
