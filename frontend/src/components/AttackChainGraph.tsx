/**
 * SafeSOC — Attack-Chain Graph View (SS-105)
 * Renders GET /api/v1/incidents/{id}/graph's node/edge data as a
 * simple, time-ordered relationship sequence — not a force-directed
 * graph layout. No graph-rendering library exists in this frontend
 * today (only in the separate CloudLens stack), so v1 deliberately
 * scopes to this lower-risk view per the issue's own recommendation,
 * rather than adding a new dependency.
 */

import MitreBadge from './MitreBadge';
import { formatDateTime, formatRelativeTime } from '../lib/format';
import type { GraphNode, GraphNodeType, IncidentGraph } from '../lib/types';

const NODE_TYPE_STYLES: Record<GraphNodeType, string> = {
  host: 'bg-blue-500/15 text-blue-300 ring-1 ring-inset ring-blue-500/40',
  ip: 'bg-orange-500/15 text-orange-300 ring-1 ring-inset ring-orange-500/40',
  user: 'bg-purple-500/15 text-purple-300 ring-1 ring-inset ring-purple-500/40',
  cloud_resource: 'bg-green-500/15 text-green-300 ring-1 ring-inset ring-green-500/40',
};

function NodeChip({ node }: { node: GraphNode }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${NODE_TYPE_STYLES[node.type]}`}>
      {node.label}
    </span>
  );
}

export default function AttackChainGraph({ graph }: { graph: IncidentGraph }) {
  if (graph.nodes.length === 0) {
    return <p className="text-sm text-slate-500">No relationships could be derived from this incident's linked alerts yet.</p>;
  }

  const nodesById = new Map(graph.nodes.map((node) => [node.id, node]));

  if (graph.edges.length === 0) {
    return (
      <div>
        <p className="text-sm text-slate-500">No connecting activity between entities yet. Involved entities:</p>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {graph.nodes.map((node) => (
            <NodeChip key={node.id} node={node} />
          ))}
        </div>
      </div>
    );
  }

  return (
    <ol className="space-y-0">
      {graph.edges.map((edge, index) => {
        const source = nodesById.get(edge.source);
        const target = nodesById.get(edge.target);
        return (
          <li key={`${edge.alert_id}-${edge.source}-${edge.target}-${index}`} className="relative flex gap-3 pb-4 last:pb-0">
            <div className="flex flex-col items-center">
              <span className="mt-1 h-2 w-2 shrink-0 rounded-full bg-slate-400" />
              {index < graph.edges.length - 1 && <span className="mt-1 w-px flex-1 bg-slate-800" />}
            </div>
            <div className="flex-1 rounded-lg border border-slate-800/80 bg-slate-950/50 p-3">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                {source ? <NodeChip node={source} /> : <span className="font-mono text-slate-400">{edge.source}</span>}
                <span className="text-slate-600">→</span>
                {target ? <NodeChip node={target} /> : <span className="font-mono text-slate-400">{edge.target}</span>}
                <MitreBadge technique={edge.mitre_technique ?? null} tactic={edge.mitre_tactic ?? null} />
              </div>
              <p className="mt-1.5 text-xs text-slate-500" title={formatDateTime(edge.timestamp)}>
                {formatRelativeTime(edge.timestamp)}
              </p>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
