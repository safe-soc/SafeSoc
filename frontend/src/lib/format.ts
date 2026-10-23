/**
 * SafeSOC — Formatting Helpers
 * Small, dependency-free formatters shared across pages/widgets.
 */

import type { CorrelationPattern, DismissReason, Incident } from './types';

export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString();
}

export function formatRelativeTime(iso: string): string {
  const deltaMs = Date.now() - new Date(iso).getTime();
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
