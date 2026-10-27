/**
 * SafeSOC — IP Threat Intel Card
 * Right-side slide-over showing everything ti_cache holds for one IP:
 * the combined verdict plus VirusTotal's and AbuseIPDB's own details,
 * as plain label/value rows. Deliberately text-only — no scores drawn
 * as rings/bars/gauges, no provider branding. Rows with no value are
 * omitted rather than shown as blanks.
 */

import { useEffect, type ReactNode } from 'react';
import Timestamp from './Timestamp';
import type { AbuseIPDetails, IPThreatIntel, VTIPDetails } from '../lib/types';

type Row = [label: string, value: ReactNode];

function hasValue(value: ReactNode): boolean {
  return value !== null && value !== undefined && value !== '' && value !== false;
}

function Section({ title, rows, link }: { title: string; rows: Row[]; link: { href: string; label: string } }) {
  const visible = rows.filter(([, value]) => hasValue(value));
  return (
    <section className="border-t border-slate-800 pt-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">{title}</h3>
      <dl className="mt-2 space-y-2 text-sm">
        {visible.map(([label, value]) => (
          <div key={label} className="grid grid-cols-[8.5rem_1fr] gap-3">
            <dt className="text-slate-500">{label}</dt>
            <dd className="min-w-0 break-words text-slate-300">{value}</dd>
          </div>
        ))}
      </dl>
      <a href={link.href} target="_blank" rel="noopener noreferrer" className="mt-3 inline-block text-sm text-blue-400 hover:underline">
        {link.label} ↗
      </a>
    </section>
  );
}

function NoData({ provider }: { provider: string }) {
  return (
    <section className="border-t border-slate-800 pt-4">
      <p className="text-sm text-slate-500">{provider}: no data for this IP</p>
    </section>
  );
}

function DateWithRelative({ iso }: { iso: string | null }) {
  if (!iso) return null;
  return (
    <>
      <Timestamp iso={iso} /> (<Timestamp iso={iso} format="relative" />)
    </>
  );
}

function yesNo(value: boolean | null | undefined): string | null {
  return value === null || value === undefined ? null : value ? 'Yes' : 'No';
}

function vtRows(vt: VTIPDetails): Row[] {
  const owner = [vt.asn != null ? `AS${vt.asn}` : null, vt.as_owner].filter(Boolean).join(' — ');
  return [
    ['Detections', `${vt.malicious} malicious, ${vt.suspicious} suspicious, ${vt.harmless} harmless, ${vt.undetected} undetected (of ${vt.total})`],
    ['Community score', vt.reputation != null ? String(vt.reputation) : null],
    ['ASN / Owner', owner || null],
    ['Network', vt.network],
    ['Country', vt.country],
    ['Last analysis', vt.last_analysis_date ? <DateWithRelative iso={vt.last_analysis_date} /> : null],
    ['Tags', vt.tags.length ? vt.tags.join(', ') : null],
    [
      'Flagged by',
      vt.flagged_by.length === 0 ? (
        'None'
      ) : (
        <ul className="space-y-0.5">
          {vt.flagged_by.map((f) => (
            <li key={f.engine} className={f.category === 'malicious' ? 'text-red-400' : undefined}>
              {f.engine} — {f.category}
              {f.result ? ` (${f.result})` : ''}
            </li>
          ))}
        </ul>
      ),
    ],
  ];
}

function abuseRows(abuse: AbuseIPDetails): Row[] {
  return [
    ['Abuse confidence', `${abuse.confidence}%`],
    [
      'Reports',
      `${abuse.total_reports} in the last ${abuse.max_age_days} days from ${abuse.num_distinct_users} distinct reporter${abuse.num_distinct_users === 1 ? '' : 's'}`,
    ],
    ['Last reported', abuse.last_reported_at ? <DateWithRelative iso={abuse.last_reported_at} /> : null],
    ['ISP', abuse.isp],
    ['Usage type', abuse.usage_type],
    ['Domain', abuse.domain],
    ['Country', abuse.country_code],
    ['Hostnames', abuse.hostnames.length ? abuse.hostnames.join(', ') : null],
    ['Tor exit node', yesNo(abuse.is_tor)],
    ['Whitelisted', yesNo(abuse.is_whitelisted)],
  ];
}

export default function IpIntelCard({ ip, intel, onClose }: { ip: string; intel: IPThreatIntel; onClose: () => void }) {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  const encoded = encodeURIComponent(ip);

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-label={`Threat intel for ${ip}`}>
      <div className="absolute inset-0 bg-slate-950/70" onClick={onClose} aria-hidden="true" />
      <aside className="relative flex h-full w-full max-w-md flex-col border-l border-slate-800 bg-slate-900 shadow-xl">
        <header className="flex items-start justify-between gap-3 px-5 py-4">
          <div className="min-w-0">
            <p className="break-all font-mono text-base text-slate-100">{ip}</p>
            <p className="mt-1 text-sm">
              {intel.is_malicious ? <span className="font-medium text-red-400">Malicious</span> : <span className="text-slate-300">Clean</span>}
              {intel.checked_at && (
                <span className="text-slate-500">
                  {' · Checked '}
                  <Timestamp iso={intel.checked_at} format="relative" /> (cached)
                </span>
              )}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            autoFocus
            className="rounded-md px-2 py-1 text-sm text-slate-400 hover:bg-slate-800 hover:text-slate-200 focus:outline-none focus-visible:ring-1 focus-visible:ring-blue-500"
          >
            Close
          </button>
        </header>
        <div className="flex-1 space-y-4 overflow-y-auto px-5 pb-6">
          {intel.vt ? (
            <Section
              title="VirusTotal"
              rows={vtRows(intel.vt)}
              link={{ href: `https://www.virustotal.com/gui/ip-address/${encoded}`, label: 'Open on VirusTotal' }}
            />
          ) : (
            <NoData provider="VirusTotal" />
          )}
          {intel.abuse ? (
            <Section
              title="AbuseIPDB"
              rows={abuseRows(intel.abuse)}
              link={{ href: `https://www.abuseipdb.com/check/${encoded}`, label: 'Open on AbuseIPDB' }}
            />
          ) : (
            <NoData provider="AbuseIPDB" />
          )}
        </div>
      </aside>
    </div>
  );
}
