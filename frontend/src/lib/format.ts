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
// "22 Oct 2026, 14:16:16". The zone name comes from the viewer's own
// locale, the one most likely to have an abbreviation for their zone:
// en-IN says "IST" where en-GB only has "GMT+5:30".
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
const ZONE_FORMAT = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' });

function zoneName(date: Date): string {
  return ZONE_FORMAT.formatToParts(date).find((part) => part.type === 'timeZoneName')?.value ?? '';
}

/** Local date and time with the zone, e.g. "22 Oct 2026, 14:16:16 IST". */
export function formatDateTime(iso: string | null | undefined): string {
  const date = parseTimestamp(iso);
  if (!date) return PLACEHOLDER;
  return `${DATE_TIME_FORMAT.format(date)} ${zoneName(date)}`.trim();
}

/** Local time only with the zone, e.g. "14:16:16 IST" — for compact rows and ranges. */
export function formatTime(iso: string | null | undefined): string {
  const date = parseTimestamp(iso);
  if (!date) return PLACEHOLDER;
  return `${TIME_FORMAT.format(date)} ${zoneName(date)}`.trim();
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
