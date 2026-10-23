/**
 * SafeSOC — Formatting Helpers
 * Small, dependency-free formatters shared across pages/widgets.
 *
 * Time convention: every time on screen is the viewer's LOCAL time with
 * its zone shown ("22 Oct 2026, 14:16:16 IST"). The tooltip adds the UTC
 * time ("2026-10-22 08:46:16 UTC") so analysts can match AI answers and
 * raw logs, which use UTC. Use components/Timestamp.tsx to render one;
 * it wires up the text and tooltip together. A missing or unparseable
 * timestamp renders "—", never "Invalid Date".
 */

import type { CorrelationPattern, DismissReason, Incident } from './types';

const PLACEHOLDER = '—';

/** A Date for a usable timestamp, or null for empty/invalid input. */
export function parseTimestamp(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? null : date;
}

// Day/month/time come from a fixed locale so the layout is always
// "22 Oct 2026, 14:16:16", whatever the browser's language.
const DATE_TIME_FORMAT = new Intl.DateTimeFormat('en-GB', {
  day: '2-digit',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
});
const TIME_FORMAT = new Intl.DateTimeFormat('en-GB', {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
});

// The zone label must not depend on the browser's language: an en-US
// browser in India gets "GMT+5:30" from Intl, not "IST". So the label
// comes from the IANA zone itself. Zones with daylight saving list
// [standard offset (minutes east of UTC), standard name, summer name];
// the date's actual offset picks between them.
const ZONE_ABBREVIATIONS: Record<string, string | [number, string, string]> = {
  'Asia/Kolkata': 'IST',
  'Asia/Calcutta': 'IST',
  UTC: 'UTC',
  'Etc/UTC': 'UTC',
  'Europe/London': [0, 'GMT', 'BST'],
  'America/New_York': [-300, 'EST', 'EDT'],
  'America/Los_Angeles': [-480, 'PST', 'PDT'],
  'Europe/Berlin': [60, 'CET', 'CEST'],
  'Asia/Singapore': 'SGT',
  'Asia/Dubai': 'GST',
};

const VIEWER_TIME_ZONE = (() => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone ?? '';
  } catch {
    return '';
  }
})();

/** "UTC+05:30" / "UTC-04:00" / "UTC" for an offset in minutes east of UTC — never "GMT+5:30". */
export function formatUtcOffset(offsetMinutes: number): string {
  if (offsetMinutes === 0) return 'UTC';
  const sign = offsetMinutes > 0 ? '+' : '-';
  const abs = Math.abs(offsetMinutes);
  const hours = String(Math.floor(abs / 60)).padStart(2, '0');
  const minutes = String(abs % 60).padStart(2, '0');
  return `UTC${sign}${hours}:${minutes}`;
}

/**
 * The zone label for an IANA zone at a given offset (minutes east of
 * UTC): a known abbreviation ("IST", "EDT"…), else "UTC+05:30" style.
 * Pure, so it can be checked for any zone regardless of the machine's.
 */
export function zoneLabel(timeZone: string, offsetMinutes: number): string {
  const known = ZONE_ABBREVIATIONS[timeZone];
  if (typeof known === 'string') return known;
  if (known) {
    const [standardOffset, standardName, summerName] = known;
    if (offsetMinutes === standardOffset) return standardName;
    if (offsetMinutes === standardOffset + 60) return summerName;
  }
  return formatUtcOffset(offsetMinutes);
}

function zoneName(date: Date): string {
  // getTimezoneOffset is minutes WEST of UTC, in the viewer's zone at that date.
  return zoneLabel(VIEWER_TIME_ZONE, -date.getTimezoneOffset());
}

/** Local date and time with the zone, e.g. "22 Oct 2026, 14:16:16 IST". */
export function formatDateTime(iso: string | null | undefined): string {
  const date = parseTimestamp(iso);
  if (!date) return PLACEHOLDER;
  return `${DATE_TIME_FORMAT.format(date)} ${zoneName(date)}`;
}

/** Local time only with the zone, e.g. "14:16:16 IST" — for compact rows and ranges. */
export function formatTime(iso: string | null | undefined): string {
  const date = parseTimestamp(iso);
  if (!date) return PLACEHOLDER;
  return `${TIME_FORMAT.format(date)} ${zoneName(date)}`;
}

/**
 * A time range with the zone once, at the end: "16:33:29–16:35:31 IST".
 * Collapses to a single time when both ends fall in the same second. If
 * the zone label changes inside the range (a DST switch), both ends
 * keep their own label so neither time is misread.
 */
export function formatTimeRange(startIso: string | null | undefined, endIso: string | null | undefined): string {
  const start = parseTimestamp(startIso);
  const end = parseTimestamp(endIso);
  if (!start || !end) return formatTime(start ? startIso : endIso);
  if (Math.floor(start.getTime() / 1000) === Math.floor(end.getTime() / 1000)) return formatTime(startIso);
  const startZone = zoneName(start);
  const endZone = zoneName(end);
  if (startZone !== endZone) return `${formatTime(startIso)}–${formatTime(endIso)}`;
  return `${TIME_FORMAT.format(start)}–${TIME_FORMAT.format(end)} ${endZone}`;
}

/** The same instant in UTC, e.g. "2026-10-22 08:46:16 UTC" — the tooltip next to any local time. */
export function formatUtcTooltip(iso: string | null | undefined): string {
  const date = parseTimestamp(iso);
  if (!date) return PLACEHOLDER;
  return `${date.toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}

/** Tooltip for a relative time ("21 minutes ago"): the local time, then UTC, on two lines. */
export function relativeTimeTooltip(iso: string | null | undefined): string {
  if (!parseTimestamp(iso)) return PLACEHOLDER;
  return `${formatDateTime(iso)}\n${formatUtcTooltip(iso)}`;
}

export function formatRelativeTime(iso: string | null | undefined): string {
  const date = parseTimestamp(iso);
  if (!date) return PLACEHOLDER;
  const deltaMs = Date.now() - date.getTime();
  const deltaSeconds = Math.round(deltaMs / 1000);

  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['year', 60 * 60 * 24 * 365],
    ['month', 60 * 60 * 24 * 30],
    ['day', 60 * 60 * 24],
    ['hour', 60 * 60],
    ['minute', 60],
  ];

  for (const [unit, secondsInUnit] of units) {
    if (Math.abs(deltaSeconds) >= secondsInUnit) {
      const value = Math.round(deltaSeconds / secondsInUnit);
      return new Intl.RelativeTimeFormat('en', { numeric: 'auto' }).format(-value, unit);
    }
  }
  return deltaSeconds <= 5 ? 'just now' : `${deltaSeconds}s ago`;
}

export function formatCompactNumber(value: number): string {
  return new Intl.NumberFormat('en', { notation: 'compact' }).format(value);
}

export function titleCase(value: string): string {
  return value.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

const CATEGORY_LABELS: Record<CorrelationPattern, string> = {
  credential_brute_force: 'Credential brute force',
  successful_compromise: 'Successful compromise',
  recon_to_exploitation: 'Recon to exploitation',
  privilege_escalation: 'Privilege escalation',
  data_exfiltration: 'Data exfiltration',
  lateral_movement: 'Lateral movement',
};

/** Human label for an incident's detected chain; a null category means it was opened manually. */
export function categoryLabel(category: CorrelationPattern | null): string {
  if (category === null) return 'Manual incident';
  return CATEGORY_LABELS[category] ?? titleCase(category);
}

/** First (most-alerted) host, plus " +N" for the rest; "—" when none. */
export function hostsLabel(hosts: string[]): string {
  if (hosts.length === 0) return '—';
  return hosts.length === 1 ? hosts[0] : `${hosts[0]} +${hosts.length - 1}`;
}

/** Readable incident title, e.g. "Successful compromise on UBUNTU-WEB-01"; just the category when no host resolved. */
export function incidentTitle(incident: Pick<Incident, 'category' | 'hosts'>): string {
  const category = categoryLabel(incident.category);
  return incident.hosts.length > 0 ? `${category} on ${hostsLabel(incident.hosts)}` : category;
}

const DISMISS_REASON_LABELS: Record<DismissReason, string> = {
  false_positive: 'False positive',
  expected_activity: 'Expected activity',
  duplicate: 'Duplicate',
  other: 'Other',
};

export function dismissReasonLabel(reason: DismissReason): string {
  return DISMISS_REASON_LABELS[reason] ?? titleCase(reason);
}
