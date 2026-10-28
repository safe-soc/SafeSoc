/**
 * SafeSOC — IP Threat Intel Card
 * Right-side slide-over showing everything ti_cache holds for one IP:
 * the combined verdict plus VirusTotal's and AbuseIPDB's own details,
 * as plain label/value rows. Deliberately text-only — no scores drawn
 * as rings/bars/gauges, no provider branding. Rows with no value are
 * omitted rather than shown as blanks.
 *
 * Refresh queues a forced re-lookup in the worker (POST .../refresh),
 * then polls the incident's evidence until this IP's checked_at moves.
 * Nothing is updated optimistically — the card only changes once the
 * evidence endpoint reports the new lookup.
 */

import axios from 'axios';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import Timestamp from './Timestamp';
import { api } from '../lib/api';
import { useAuth } from '../hooks/useAuth';
import type { AbuseIPDetails, IncidentEvidence, IPThreatIntel, TIDetailStatus, VTIPDetails } from '../lib/types';

const POLL_INTERVAL_MS = 3000;
const POLL_TIMEOUT_MS = 90_000;
const REFRESH_ROLES = ['analyst', 'admin'];

type Row = [label: string, value: ReactNode];

type RefreshState =
  | { phase: 'idle' }
  | { phase: 'refreshing' }
  | { phase: 'message'; text: string; isError: boolean };

function hasValue(value: ReactNode): boolean {
  return value !== null && value !== undefined && value !== '' && value !== false;
}

function apiErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const data = error.response?.data as { error?: unknown; detail?: unknown } | undefined;
    if (typeof data?.error === 'string') return data.error;
    if (typeof data?.detail === 'string') return data.detail;
  }
  return 'Could not start a refresh.';
}

function isNewer(next: string | null | undefined, previous: string | null): boolean {
  if (!next) return false;
  if (!previous) return true;
  return Date.parse(next) > Date.parse(previous);
}

function RefreshButton({ onClick, disabled }: { onClick: () => void; disabled: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="text-sm text-blue-400 hover:underline focus:outline-none focus-visible:ring-1 focus-visible:ring-blue-500 disabled:cursor-not-allowed disabled:text-slate-500 disabled:no-underline"
    >
      Refresh
    </button>
  );
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

function ProviderNotice({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="border-t border-slate-800 pt-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">{title}</h3>
      <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-slate-500">{children}</div>
    </section>
  );
}

function ProviderSection({
  provider,
  status,
  details,
  link,
  refreshButton,
}: {
  provider: string;
  status: TIDetailStatus;
  details: Row[] | null;
  link: { href: string; label: string };
  refreshButton: ReactNode;
}) {
  if (status === 'ok' && details) return <Section title={provider} rows={details} link={link} />;
  if (status === 'not_found') {
    return (
      <ProviderNotice title={provider}>
        <span>{provider}: not seen before (no report)</span>
      </ProviderNotice>
    );
  }
  if (status === 'legacy') {
    return (
      <ProviderNotice title={provider}>
        <span>Cached before details were collected.</span>
        {refreshButton}
      </ProviderNotice>
    );
  }
  return (
    <ProviderNotice title={provider}>
      <span>Not checked by {provider} (no API key or lookup failed).</span>
    </ProviderNotice>
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

export default function IpIntelCard({
  ip,
  intel,
  isPublic,
  incidentId,
  onEvidenceChange,
  onClose,
  allowRefresh = true,
}: {
  ip: string;
  intel: IPThreatIntel;
  isPublic: boolean;
  // Refresh is incident-scoped: without an incident (e.g. the Alerts
  // page's details row) pass allowRefresh={false} and omit these two.
  incidentId?: string;
  onEvidenceChange?: (evidence: IncidentEvidence) => void;
  onClose: () => void;
  allowRefresh?: boolean;
}) {
  const { claims } = useAuth();
  const [refresh, setRefresh] = useState<RefreshState>({ phase: 'idle' });
  // Cleared on unmount so a poll in flight never updates a closed card.
  const pollTimer = useRef<number | null>(null);
  const isMounted = useRef(true);

  useEffect(() => {
    isMounted.current = true;
    return () => {
      isMounted.current = false;
      if (pollTimer.current !== null) window.clearTimeout(pollTimer.current);
    };
  }, []);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  const canRefresh =
    allowRefresh && Boolean(incidentId && onEvidenceChange) && isPublic && REFRESH_ROLES.includes(claims?.role ?? '');
  const isRefreshing = refresh.phase === 'refreshing';

  const poll = (baseline: string | null, deadline: number) => {
    pollTimer.current = window.setTimeout(async () => {
      if (!isMounted.current) return;
      try {
        const response = await api.get<IncidentEvidence>(`/api/v1/incidents/${incidentId}/evidence`);
        if (!isMounted.current) return;
        const entity = response.data.ips.find((candidate) => candidate.ip === ip);
        if (isNewer(entity?.ti?.checked_at, baseline)) {
          onEvidenceChange?.(response.data);
          setRefresh({ phase: 'idle' });
          return;
        }
      } catch {
        // A failed poll is retried on the next tick until the deadline.
      }
      if (Date.now() >= deadline) {
        setRefresh({ phase: 'message', text: 'Still refreshing — check back shortly.', isError: false });
        return;
      }
      poll(baseline, deadline);
    }, POLL_INTERVAL_MS);
  };

  const startRefresh = async () => {
    if (isRefreshing) return;
    const baseline = intel.checked_at;
    setRefresh({ phase: 'refreshing' });
    try {
      await api.post(`/api/v1/incidents/${incidentId}/evidence/ips/${encodeURIComponent(ip)}/refresh`);
    } catch (error) {
      if (isMounted.current) setRefresh({ phase: 'message', text: apiErrorMessage(error), isError: true });
      return;
    }
    poll(baseline, Date.now() + POLL_TIMEOUT_MS);
  };

  const refreshButton = canRefresh ? <RefreshButton onClick={() => void startRefresh()} disabled={isRefreshing} /> : null;
  const encoded = encodeURIComponent(ip);

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-label={`Threat intel for ${ip}`}>
      <div className="absolute inset-0 bg-slate-950/70" onClick={onClose} aria-hidden="true" />
      <aside className="relative flex h-full w-full max-w-md flex-col border-l border-slate-800 bg-slate-900 shadow-xl">
        <header className="px-5 py-4">
          <div className="flex items-start justify-between gap-3">
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
            <div className="flex shrink-0 items-center gap-3">
              {refreshButton}
              <button
                type="button"
                onClick={onClose}
                autoFocus
                className="rounded-md px-2 py-1 text-sm text-slate-400 hover:bg-slate-800 hover:text-slate-200 focus:outline-none focus-visible:ring-1 focus-visible:ring-blue-500"
              >
                Close
              </button>
            </div>
          </div>
          {refresh.phase === 'refreshing' && (
            <p className="mt-2 text-xs text-slate-400" role="status">
              Refreshing… (VirusTotal allows 4 lookups/min, this can take up to a minute)
            </p>
          )}
          {refresh.phase === 'message' && (
            <p className={`mt-2 text-xs ${refresh.isError ? 'text-amber-400' : 'text-slate-400'}`} role="status">
              {refresh.text}
            </p>
          )}
        </header>
        <div className="flex-1 space-y-4 overflow-y-auto px-5 pb-6">
          <ProviderSection
            provider="VirusTotal"
            status={intel.vt_status}
            details={intel.vt ? vtRows(intel.vt) : null}
            link={{ href: `https://www.virustotal.com/gui/ip-address/${encoded}`, label: 'Open on VirusTotal' }}
            refreshButton={refreshButton}
          />
          <ProviderSection
            provider="AbuseIPDB"
            status={intel.abuse_status}
            details={intel.abuse ? abuseRows(intel.abuse) : null}
            link={{ href: `https://www.abuseipdb.com/check/${encoded}`, label: 'Open on AbuseIPDB' }}
            refreshButton={refreshButton}
          />
        </div>
      </aside>
    </div>
  );
}
