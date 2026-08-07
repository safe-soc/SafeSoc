/**
 * SafeSOC — OS Icon
 * GET /api/v1/endpoints has no host_os field (see lib/alertLookup.ts
 * for why) — callers pass whatever they resolved best-effort from
 * recent alerts, or omit it, in which case a neutral device icon is
 * shown rather than guessing.
 */

function WindowsGlyph() {
  return (
    <svg viewBox="0 0 24 24" fill="none" className="h-4 w-4" aria-hidden="true">
      <path d="M3 5.5 10.5 4.4v7.1H3zM11.5 4.3 21 3v8.5h-9.5zM3 12.5h7.5v7.1L3 18.5zM11.5 12.5H21V21l-9.5-1.3z" fill="currentColor" />
    </svg>
  );
}

function LinuxGlyph() {
  return (
    <svg viewBox="0 0 24 24" fill="none" className="h-4 w-4" aria-hidden="true">
      <circle cx="12" cy="9" r="4" fill="currentColor" opacity="0.9" />
      <path d="M8 13c-1.5 2-2 4.5-1.5 7h11c.5-2.5 0-5-1.5-7" stroke="currentColor" strokeWidth="1.4" fill="none" />
    </svg>
  );
}

function GenericDeviceGlyph() {
  return (
    <svg viewBox="0 0 24 24" fill="none" className="h-4 w-4" aria-hidden="true">
      <rect x="4" y="4" width="16" height="11" rx="1.5" stroke="currentColor" strokeWidth="1.4" />
      <path d="M9 19h6M12 15v4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  );
}

export default function OsIcon({ os, className = 'text-slate-500' }: { os?: string | null; className?: string }) {
  const normalized = (os ?? '').toLowerCase();
  let glyph = <GenericDeviceGlyph />;
  let label = 'Unknown OS';

  if (normalized.includes('win')) {
    glyph = <WindowsGlyph />;
    label = 'Windows';
  } else if (normalized.includes('linux') || normalized.includes('ubuntu') || normalized.includes('debian')) {
    glyph = <LinuxGlyph />;
    label = 'Linux';
  } else if (normalized.includes('mac') || normalized.includes('darwin') || normalized.includes('osx')) {
    glyph = <GenericDeviceGlyph />;
    label = 'macOS';
  }

  return (
    <span className={`inline-flex items-center ${className}`} title={label} aria-label={label}>
      {glyph}
    </span>
  );
}
