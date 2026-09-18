/**
 * SafeSOC — SOAR Display Labels
 * Small, purely presentational lookups shared by SoarResponsePanel and
 * SoarActionApprovalDialog. "Expected simulated impact" describes what
 * SafeSOC's own simulated adapters (adapters/soar/*.py) actually do —
 * never a claim about a real external system, and always framed as
 * simulated. Every affected value here is fixed, tiny, and reviewable;
 * nothing is inferred or fabricated at runtime.
 */

import type { SoarActionExecution, SoarActionType } from './types';

const ACTION_TYPE_LABELS: Record<SoarActionType, string> = {
  collect_additional_evidence: 'Collect Additional Evidence',
  create_investigation_action: 'Create Investigation Action',
  enrich_indicator: 'Enrich Indicator',
  add_incident_note: 'Add Incident Note',
  increase_incident_priority: 'Increase Incident Priority',
  isolate_endpoint: 'Isolate Endpoint',
  disable_account: 'Disable Account',
  block_indicator: 'Block Indicator',
  terminate_process: 'Terminate Process',
  revoke_credentials: 'Revoke Credentials',
};

export function formatActionType(actionType: SoarActionType): string {
  return ACTION_TYPE_LABELS[actionType] ?? actionType;
}

const SIMULATED_IMPACT: Record<SoarActionType, string> = {
  collect_additional_evidence: 'Gathers additional evidence for this incident from existing SafeSOC data — no external system is touched.',
  create_investigation_action: 'Adds an open action item to this incident\'s investigation session.',
  enrich_indicator: 'Looks up this indicator against SafeSOC\'s existing threat-intel cache/clients.',
  add_incident_note: 'Adds an automated note to this incident\'s timeline.',
  increase_incident_priority: 'Not currently implemented as a working action handler.',
  isolate_endpoint: 'The simulated EDR (SimulatedEDR) marks this endpoint as isolated in SafeSOC\'s own simulated environment — no real endpoint agent, firewall, or network device is contacted.',
  disable_account: 'The simulated Identity Provider (SimulatedIdentityProvider) marks this account as disabled in SafeSOC\'s own simulated environment — no real directory or IdP is contacted.',
  block_indicator: 'The simulated Firewall (SimulatedFirewall) marks this indicator as blocked in SafeSOC\'s own simulated environment — no real firewall or network appliance is contacted.',
  terminate_process: 'The simulated EDR (SimulatedEDR) marks this process as terminated in SafeSOC\'s own simulated environment — no real endpoint agent is contacted.',
  revoke_credentials: 'The simulated Identity Provider (SimulatedIdentityProvider) marks this account\'s credentials as revoked in SafeSOC\'s own simulated environment — no real directory or IdP is contacted.',
};

export function describeSimulatedImpact(actionType: SoarActionType): string {
  return SIMULATED_IMPACT[actionType] ?? 'No simulated-impact description is available for this action type.';
}

const TARGET_PARAMETER_KEYS = ['host_id', 'user', 'indicator', 'process', 'description', 'note'] as const;

/** Best-effort human-readable target, drawn only from this action's own already-validated parameters — never fabricated. */
export function describeTarget(action: SoarActionExecution): string | null {
  for (const key of TARGET_PARAMETER_KEYS) {
    const value = action.parameters[key];
    if (typeof value === 'string' && value.trim()) {
      return value;
    }
  }
  return null;
}
