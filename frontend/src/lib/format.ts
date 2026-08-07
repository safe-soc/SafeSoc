/**
 * SafeSOC — Formatting Helpers
 * Small, dependency-free formatters shared across pages/widgets.
 */

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
