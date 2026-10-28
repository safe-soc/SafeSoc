/**
 * SafeSOC — Alert Details
 * The Alerts page's expandable row: one alert's full context from
 * GET /api/v1/alerts/{id}/context, grouped into label/value sections.
 * Empty values are hidden, and any document field not placed in a
 * named group lands under "Other fields" so nothing is silently dropped.
 */

import { useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import IpIntelCard from './IpIntelCard';
import LevelBadge from './LevelBadge';
import MitreBadge from './MitreBadge';
import StatusBadge from './StatusBadge';
import Timestamp from './Timestamp';
import { dismissReasonLabel, incidentTitle, ipOwnerSummary, VT_NOT_FOUND_LABEL, vtNotFound } from '../lib/format';
import type { AlertContext, AlertDocument } from '../lib/types';

type Row = [label: string, value: ReactNode];

// Fields rendered in a named group, or deliberately left out (tenant_id
// is the caller's own tenant; ti_result is what Threat intel shows) —
// the rest of the document goes to "Other fields".
const SHOWN_FIELDS = new Set([
  'alert_id', 'tenant_id', 'timestamp', 'ingested_at', 'source', 'log_type', 'action', 'rule_id', 'severity', 'description',
  'host_id', 'host_ip', 'host_os', 'user', 'source_ip', 'source_port', 'destination_ip', 'destination_port', 'protocol',
  'process_name', 'process_id', 'parent_process', 'command_line', 'file_path', 'file_hash', 'file_size',
  'mitre_technique', 'mitre_tactic', 'risk_score', 'anomaly_score', 'ti_enriched', 'ti_result',
  'acknowledged', 'dismissed', 'dismiss_reason', 'dismiss_note', 'raw_log',
]);

function isEmpty(value: unknown): boolean {
  return value === null || value === undefined || value === '' || (Array.isArray(value) && value.length === 0);
}

function Mono({ children }: { children: ReactNode }) {
  return <span className="break-all font-mono text-xs text-slate-300">{children}</span>;
}

function Group({ title, rows }: { title: string; rows: Row[] }) {
  const visible = rows.filter(([, value]) => !isEmpty(value) && value !== false);
  if (visible.length === 0) return null;
  return (
    <div>
      <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">{title}</h4>
      <dl className="mt-1.5 space-y-1 text-sm">
        {visible.map(([label, value]) => (
          <div key={label} className="grid grid-cols-[8rem_1fr] gap-3">
            <dt className="text-slate-500">{label}</dt>
            <dd className="min-w-0 whitespace-pre-wrap text-slate-300 [overflow-wrap:anywhere]">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function present<T>(value: T | null | undefined, render: (v: T) => ReactNode = (v) => String(v)): ReactNode {
  return isEmpty(value) ? null : render(value as T);
}

const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;

function formatOther(value: unknown): ReactNode {
  if (typeof value === 'object') {
    return (
      <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded border border-slate-800 bg-slate-950 p-2 font-mono text-xs text-slate-300">
        {JSON.stringify(value, null, 2)}
      </pre>
    );
  }
  if (typeof value === 'string' && ISO_TIMESTAMP.test(value)) return <Timestamp iso={value} />;
  return String(value);
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard unavailable (insecure context / denied) — nothing to report beyond not showing "Copied".
    }
  };

  return (
    <button type="button" onClick={() => void copy()} className="text-xs text-blue-400 hover:underline">
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}

function RawLog({ raw }: { raw: string | null | undefined }) {
  const [open, setOpen] = useState(false);

  const trimmed = (raw ?? '').trim();
  const isEmptyLog = trimmed === '' || trimmed === '{}';
  let pretty = trimmed;
  if (!isEmptyLog) {
    try {
      pretty = JSON.stringify(JSON.parse(trimmed), null, 2);
    } catch {
      pretty = raw ?? '';
    }
  }

  return (
    <div>
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          className="text-xs font-semibold uppercase tracking-wide text-slate-500 hover:text-slate-300"
        >
          {open ? '▾' : '▸'} Raw log
        </button>
        {open && !isEmptyLog && <CopyButton text={pretty} />}
      </div>
      {open &&
        (isEmptyLog ? (
          <p className="mt-1.5 text-sm text-slate-500">No raw log captured (synthetic event)</p>
        ) : (
          <pre className="mt-1.5 max-h-80 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-xs text-slate-300">
            {pretty}
          </pre>
        ))}
    </div>
  );
}

export default function AlertDetails({ context }: { context: AlertContext }) {
  const { alert, incident, ip_intel } = context;
  const [intelIp, setIntelIp] = useState<string | null>(null);
  const openIntel = intelIp ? ip_intel[intelIp] : undefined;

  const otherRows: Row[] = Object.entries(alert as AlertDocument)
    .filter(([key, value]) => !SHOWN_FIELDS.has(key) && !isEmpty(value))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => [key, formatOther(value)]);

  const ipEntries = Object.entries(ip_intel);

  return (
    <div className="grid grid-cols-1 gap-x-8 gap-y-4 px-4 py-4 lg:grid-cols-2">
      <Group
        title="Event"
        rows={[
          [
            'Alert ID',
            present(alert.alert_id, (v) => (
              <span className="inline-flex flex-wrap items-center gap-2">
                <Mono>{v}</Mono>
                <CopyButton text={v} />
              </span>
            )),
          ],
          [
            'Time',
            <>
              <Timestamp iso={alert.timestamp} /> (<Timestamp iso={alert.timestamp} format="relative" />)
            </>,
          ],
          ['Ingested', present(alert.ingested_at, (v) => <Timestamp iso={v} />)],
          ['Source', present(alert.source)],
          ['Log type', present(alert.log_type)],
          ['Action', present(alert.action)],
          ['Rule', present(alert.rule_id, (v) => <Mono>{v}</Mono>)],
          ['Severity', <LevelBadge key="sev" level={alert.severity} />],
          ['Description', present(alert.description)],
        ]}
      />

      <Group
        title="Entities"
        rows={[
          ['Host', present(alert.host_id, (v) => <Mono>{v}</Mono>)],
          ['Host IP', present(alert.host_ip, (v) => <Mono>{v}</Mono>)],
          ['Host OS', present(alert.host_os)],
          ['User', present(alert.user)],
          ['Source IP', present(alert.source_ip, (v) => <Mono>{v}</Mono>)],
          ['Source port', present(alert.source_port)],
          ['Destination IP', present(alert.destination_ip, (v) => <Mono>{v}</Mono>)],
          ['Destination port', present(alert.destination_port)],
          ['Protocol', present(alert.protocol)],
          ['Process', present(alert.process_name)],
          ['Process ID', present(alert.process_id)],
          ['Parent process', present(alert.parent_process)],
          ['Command line', present(alert.command_line, (v) => <Mono>{v}</Mono>)],
          ['File path', present(alert.file_path, (v) => <Mono>{v}</Mono>)],
          ['File hash', present(alert.file_hash, (v) => <Mono>{v}</Mono>)],
          ['File size', present(alert.file_size)],
        ]}
      />

      <Group
        title="Detection"
        rows={[
          [
            'MITRE',
            alert.mitre_technique || alert.mitre_tactic ? (
              <span className="inline-flex flex-wrap items-center gap-2">
                <MitreBadge technique={alert.mitre_technique ?? null} tactic={alert.mitre_tactic ?? null} />
                {alert.mitre_technique && alert.mitre_tactic && <span className="text-slate-400">{alert.mitre_tactic}</span>}
              </span>
            ) : incident ? (
              <span className="text-slate-500">none on this event (see linked incident)</span>
            ) : null,
          ],
          ['Risk score', present(alert.risk_score)],
          ['Anomaly score', present(alert.anomaly_score, (v) => v.toFixed(2))],
          ['TI enriched', alert.ti_enriched == null ? null : alert.ti_enriched ? 'Yes' : 'No'],
        ]}
      />

      <div className="space-y-4">
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Threat intel</h4>
          {ipEntries.length === 0 ? (
            <p className="mt-1.5 text-sm text-slate-500">No IPs on this alert.</p>
          ) : (
            <ul className="mt-1.5 space-y-1 text-sm">
              {ipEntries.map(([ip, entry]) => (
                <li key={ip} className="flex flex-wrap items-center gap-2">
                  <Mono>{ip}</Mono>
                  {entry.ti ? (
                    <>
                      <span className="text-slate-500">·</span>
                      {entry.ti.is_malicious ? <span className="text-red-400">Malicious</span> : <span className="text-slate-300">Clean</span>}
                      {ipOwnerSummary(entry.ti) && <span className="text-xs text-slate-500">· {ipOwnerSummary(entry.ti)}</span>}
                      {vtNotFound(entry.ti) && <span className="text-xs text-slate-500">· {VT_NOT_FOUND_LABEL}</span>}
                      <button type="button" onClick={() => setIntelIp(ip)} className="text-xs text-blue-400 hover:underline">
                        View threat intel
                      </button>
                    </>
                  ) : (
                    <span className="text-xs text-slate-600">
                      {entry.is_public ? 'Not checked' : 'Private/reserved — not looked up'}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Incident</h4>
          {incident ? (
            <p className="mt-1.5 flex flex-wrap items-center gap-2 text-sm">
              <span className="text-slate-500">Part of incident:</span>
              <Link to={`/incidents/${incident.id}`} className="text-blue-400 hover:underline">
                {incidentTitle(incident)}
              </Link>
              <StatusBadge status={incident.status} />
            </p>
          ) : (
            <p className="mt-1.5 text-sm text-slate-500">Not part of an incident</p>
          )}
        </div>

        {alert.dismissed && (
          <Group
            title="Triage"
            rows={[
              ['Dismissed as', alert.dismiss_reason ? dismissReasonLabel(alert.dismiss_reason) : 'Dismissed'],
              ['Note', present(alert.dismiss_note)],
            ]}
          />
        )}
      </div>

      {otherRows.length > 0 && (
        <div className="lg:col-span-2">
          <Group title="Other fields" rows={otherRows} />
        </div>
      )}

      <div className="lg:col-span-2">
        <RawLog raw={alert.raw_log} />
      </div>

      {intelIp && openIntel?.ti && (
        <IpIntelCard ip={intelIp} intel={openIntel.ti} isPublic={openIntel.is_public} allowRefresh={false} onClose={() => setIntelIp(null)} />
      )}
    </div>
  );
}
