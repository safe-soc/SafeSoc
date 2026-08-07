/**
 * SafeSOC — Best-Effort Alert Lookup
 * GET /api/v1/endpoints has no host_os field, and GET /api/v1/incidents
 * has no MITRE fields — both live on the Alert resource instead
 * (host_os, mitre_technique/mitre_tactic). Rather than inventing a new
 * backend endpoint, pages that want this data fetch a recent window of
 * alerts (the existing GET /api/v1/alerts, maxed out at size=500 /
 * timerange_hours=720) and look values up by host_id or alert_id from
 * that batch. This is inherently best-effort — an alert outside the
 * fetched window simply won't resolve — so every caller must treat a
 * miss as "unknown", never an error.
 */

import { api } from './api';
import type { Alert } from './types';

export interface AlertLookup {
  /** Most recently seen host_os for a given host_id, if any alert in the fetched window mentioned it. */
  osForHost: Map<string, string>;
  /** MITRE technique/tactic for a given alert_id, if that alert was in the fetched window. */
  mitreForAlert: Map<string, { technique: string | null; tactic: string | null }>;
  /** Every fetched alert, for callers that want to derive their own aggregates. */
  alerts: Alert[];
}

export async function fetchAlertLookup(timerangeHours = 720): Promise<AlertLookup> {
  const response = await api.get<{ alerts: Alert[] }>('/api/v1/alerts', {
    params: { timerange_hours: timerangeHours, size: 500 },
  });

  const osForHost = new Map<string, string>();
  const mitreForAlert = new Map<string, { technique: string | null; tactic: string | null }>();

  for (const alert of response.data.alerts) {
    if (alert.host_os && !osForHost.has(alert.host_id)) {
      osForHost.set(alert.host_id, alert.host_os);
    }
    if (alert.mitre_technique || alert.mitre_tactic) {
      mitreForAlert.set(alert.alert_id, {
        technique: alert.mitre_technique ?? null,
        tactic: alert.mitre_tactic ?? null,
      });
    }
  }

  return { osForHost, mitreForAlert, alerts: response.data.alerts };
}
