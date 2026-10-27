/**
 * SafeSOC — Incident Evidence Explorer (SS-101)
 * Renders GET /api/v1/incidents/{id}/evidence's distinct entities
 * (hosts/IPs/users/cloud resources) with their risk/TI annotations —
 * a structured "who/what was involved" view, not just a raw alert
 * list. Every annotation is best-effort: an unannotated entity shows
 * a neutral "not yet scored"/"not checked" state, never an error.
 */

import { useState } from 'react';
import IpIntelCard from './IpIntelCard';
import LevelBadge from './LevelBadge';
import type { IncidentEvidence, IPEntity } from '../lib/types';

function EmptyRow({ label }: { label: string }) {
  return <p className="text-sm text-slate-500">{label}</p>;
}

/** "{country} · {owner}" from whichever provider supplied each part; null if neither did. */
function ipContext(ip: IPEntity): string | null {
  if (!ip.ti) return null;
  const country = ip.ti.vt?.country || ip.ti.abuse?.country_code;
  const owner = ip.ti.vt?.as_owner || ip.ti.abuse?.isp;
  return [country, owner].filter(Boolean).join(' · ') || null;
}

export default function EvidenceExplorer({ evidence }: { evidence: IncidentEvidence }) {
  const [intelIp, setIntelIp] = useState<IPEntity | null>(null);
  const hasAnything =
    evidence.hosts.length > 0 ||
    evidence.ips.length > 0 ||
    evidence.users.length > 0 ||
    evidence.cloud_resources.length > 0;

  if (!hasAnything) {
    return <p className="text-sm text-slate-500">No entities could be extracted from this incident's linked alerts yet.</p>;
  }

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
      <div>
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Hosts ({evidence.hosts.length})</h3>
        {evidence.hosts.length === 0 ? (
          <EmptyRow label="None involved." />
        ) : (
          <ul className="mt-2 space-y-1.5">
            {evidence.hosts.map((host) => (
              <li key={host.host_id} className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-800/80 bg-slate-950/50 px-3 py-2 text-sm">
                <span className="font-mono text-slate-300">{host.host_id}</span>
                {host.host_os && <span className="text-xs text-slate-500">{host.host_os}</span>}
                {host.risk_level != null ? (
                  <LevelBadge level={host.risk_level} />
                ) : (
                  <span className="text-xs text-slate-600">Not yet scored</span>
                )}
                {host.has_anomalous_activity && (
                  <span className="rounded-full bg-purple-500/15 px-2 py-0.5 text-xs font-medium text-purple-300 ring-1 ring-inset ring-purple-500/40">
                    Anomalous
                  </span>
                )}
                <span className="ml-auto text-xs text-slate-600">{host.alert_count} alert{host.alert_count === 1 ? '' : 's'}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">IP Addresses ({evidence.ips.length})</h3>
        {evidence.ips.length === 0 ? (
          <EmptyRow label="None involved." />
        ) : (
          <ul className="mt-2 space-y-1.5">
            {evidence.ips.map((ip) => (
              <li key={ip.ip} className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-800/80 bg-slate-950/50 px-3 py-2 text-sm">
                <span className="font-mono text-slate-300">{ip.ip}</span>
                <span className="text-xs text-slate-500">{ip.roles.join(', ')}</span>
                {ip.is_malicious === true && (
                  <span className="rounded-full bg-red-500/15 px-2 py-0.5 text-xs font-medium text-red-300 ring-1 ring-inset ring-red-500/40">Malicious</span>
                )}
                {ip.is_malicious === false && (
                  <span className="rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-400">Clean</span>
                )}
                {(ip.is_malicious === null || ip.is_malicious === undefined) && (
                  <span className="text-xs text-slate-600">
                    {ip.is_public === false ? 'Private/reserved — not looked up' : 'Not checked'}
                  </span>
                )}
                {ipContext(ip) && <span className="text-xs text-slate-500">{ipContext(ip)}</span>}
                {ip.ti && (
                  <button
                    type="button"
                    onClick={() => setIntelIp(ip)}
                    className="text-xs text-blue-400 hover:underline focus:outline-none focus-visible:ring-1 focus-visible:ring-blue-500"
                  >
                    View threat intel
                  </button>
                )}
                <span className="ml-auto text-xs text-slate-600">{ip.alert_count} alert{ip.alert_count === 1 ? '' : 's'}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Users ({evidence.users.length})</h3>
        {evidence.users.length === 0 ? (
          <EmptyRow label="None involved." />
        ) : (
          <ul className="mt-2 space-y-1.5">
            {evidence.users.map((user) => (
              <li key={user.user} className="flex items-center gap-2 rounded-lg border border-slate-800/80 bg-slate-950/50 px-3 py-2 text-sm">
                <span className="text-slate-300">{user.user}</span>
                <span className="ml-auto text-xs text-slate-600">{user.alert_count} alert{user.alert_count === 1 ? '' : 's'}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Cloud Resources ({evidence.cloud_resources.length})</h3>
        {evidence.cloud_resources.length === 0 ? (
          <EmptyRow label="None involved." />
        ) : (
          <ul className="mt-2 space-y-1.5">
            {evidence.cloud_resources.map((resource) => (
              <li key={resource.resource_id} className="flex items-center gap-2 rounded-lg border border-slate-800/80 bg-slate-950/50 px-3 py-2 text-sm">
                <span className="font-mono text-slate-300">{resource.resource_id}</span>
                <span className="ml-auto text-xs text-slate-600">{resource.alert_count} alert{resource.alert_count === 1 ? '' : 's'}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {intelIp?.ti && <IpIntelCard ip={intelIp.ip} intel={intelIp.ti} onClose={() => setIntelIp(null)} />}
    </div>
  );
}
