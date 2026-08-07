/**
 * SafeSOC — Endpoint Risk Dashboard View (SS-060)
 * Backed by GET /api/v1/endpoints (SS-034), already sorted by risk
 * score descending server-side. Each row drills down to that
 * endpoint's recent alerts by reusing the Alerts view (SS-059) with
 * its host filter pre-applied, rather than building a second alert
 * list.
 */

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import Layout from '../components/Layout';
import LevelBadge from '../components/LevelBadge';
import { api } from '../lib/api';
import type { Severity } from '../lib/types';

interface Endpoint {
  id: string;
  tenant_id: string;
  host_id: string;
  risk_score: number;
  risk_level: Severity;
  updated_at: string;
}

export default function Endpoints() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .get<Endpoint[]>('/api/v1/endpoints')
      .then((response) => {
        if (!cancelled) setEndpoints(response.data);
      })
      .catch(() => {
        if (!cancelled) setError('Failed to load endpoints.');
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <Layout>
      <h1 className="text-xl font-semibold">Endpoints</h1>
      <p className="mt-1 text-sm text-slate-400">Known hosts, sorted by risk score. Click a host for its recent alerts.</p>

      {error && <p className="mt-4 text-sm text-red-400">{error}</p>}

      <div className="mt-4 overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-3 py-2">Host</th>
              <th className="px-3 py-2">Risk Score</th>
              <th className="px-3 py-2">Risk Level</th>
              <th className="px-3 py-2">Last Updated</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={4} className="px-3 py-6 text-center text-slate-500">
                  Loading…
                </td>
              </tr>
            ) : endpoints.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-3 py-6 text-center text-slate-500">
                  No endpoints have been scored yet.
                </td>
              </tr>
            ) : (
              endpoints.map((endpoint) => (
                <tr key={endpoint.id} className="border-t border-slate-800 hover:bg-slate-900/60">
                  <td className="px-3 py-2">
                    <Link
                      to={`/alerts?host_id=${encodeURIComponent(endpoint.host_id)}`}
                      className="font-mono text-blue-400 hover:underline"
                    >
                      {endpoint.host_id}
                    </Link>
                  </td>
                  <td className="px-3 py-2 text-slate-300">{endpoint.risk_score}</td>
                  <td className="px-3 py-2">
                    <LevelBadge level={endpoint.risk_level} />
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-slate-300">
                    {new Date(endpoint.updated_at).toLocaleString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}
