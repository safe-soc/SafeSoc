/**
 * SafeSOC — Attack-Chain Graph View
 * A real node-link visualization of GET /api/v1/incidents/{id}/graph's
 * data (nodes = evidence entities, edges = alerts connecting them),
 * replacing the plain edge-by-edge list AttackChainGraph.tsx rendered
 * as the ONLY representation. Nodes/edges are exactly what the backend
 * returned — nothing here invents a relationship or entity; parallel
 * edges (the same entity pair linked by several alerts) are grouped
 * for rendering only, with every underlying alert id and MITRE
 * technique preserved on the group (lib/graphLayout.ts).
 *
 * No graph-rendering library exists in this frontend (see package.json)
 * — this is a small, self-contained SVG renderer rather than a new
 * dependency, matching AttackChainGraph.tsx's own original reasoning
 * for staying dependency-free.
 */

import { useMemo, useRef, useState, type PointerEvent as ReactPointerEvent, type WheelEvent as ReactWheelEvent } from 'react';
import { computeForceLayout, groupParallelEdges, type GroupedEdge } from '../lib/graphLayout';
import { formatDateTime, formatRelativeTime } from '../lib/format';
import type { GraphNode, GraphNodeType, IncidentGraph } from '../lib/types';

const VIEW_WIDTH = 760;
const VIEW_HEIGHT = 380;
const MIN_SCALE = 0.5;
const MAX_SCALE = 2.5;

const NODE_VISUAL: Record<GraphNodeType, { fill: string; stroke: string; shape: 'circle' | 'diamond' | 'square'; label: string }> = {
  host: { fill: '#3b82f6', stroke: '#93c5fd', shape: 'circle', label: 'Host' },
  ip: { fill: '#f97316', stroke: '#fdba74', shape: 'diamond', label: 'IP address' },
  user: { fill: '#a855f7', stroke: '#d8b4fe', shape: 'circle', label: 'User' },
  cloud_resource: { fill: '#22c55e', stroke: '#86efac', shape: 'square', label: 'Cloud resource' },
};

const NODE_RADIUS = 16;

function NodeShape({ type, x, y, isSelected }: { type: GraphNodeType; x: number; y: number; isSelected: boolean }) {
  const visual = NODE_VISUAL[type];
  const ringProps = isSelected ? { stroke: '#e2e8f0', strokeWidth: 2.5 } : { stroke: visual.stroke, strokeWidth: 1.5 };

  if (visual.shape === 'diamond') {
    const half = NODE_RADIUS;
    return (
      <rect
        x={x - half}
        y={y - half}
        width={half * 2}
        height={half * 2}
        fill={visual.fill}
        transform={`rotate(45 ${x} ${y})`}
        {...ringProps}
      />
    );
  }
  if (visual.shape === 'square') {
    return <rect x={x - NODE_RADIUS} y={y - NODE_RADIUS} width={NODE_RADIUS * 2} height={NODE_RADIUS * 2} rx={4} fill={visual.fill} {...ringProps} />;
  }
  return <circle cx={x} cy={y} r={NODE_RADIUS} fill={visual.fill} {...ringProps} />;
}

type Selection = { kind: 'node'; node: GraphNode } | { kind: 'edge'; edge: GroupedEdge; sourceLabel: string; targetLabel: string };

export default function AttackChainGraphView({ graph }: { graph: IncidentGraph }) {
  const [transform, setTransform] = useState({ x: 0, y: 0, scale: 1 });
  const [selection, setSelection] = useState<Selection | null>(null);
  const dragState = useRef<{ startX: number; startY: number; originX: number; originY: number } | null>(null);

  const nodesById = useMemo(() => new Map(graph.nodes.map((node) => [node.id, node])), [graph.nodes]);
  const nodeIds = useMemo(() => graph.nodes.map((n) => n.id), [graph.nodes]);
  const groupedEdges = useMemo(() => groupParallelEdges(graph.edges), [graph.edges]);
  const positions = useMemo(
    () => computeForceLayout(nodeIds, groupedEdges, VIEW_WIDTH, VIEW_HEIGHT),
    [nodeIds, groupedEdges],
  );

  const handleWheel = (event: ReactWheelEvent<SVGSVGElement>) => {
    event.preventDefault();
    setTransform((prev) => {
      const delta = event.deltaY > 0 ? -0.1 : 0.1;
      const scale = Math.min(Math.max(prev.scale + delta, MIN_SCALE), MAX_SCALE);
      return { ...prev, scale };
    });
  };

  const handlePointerDown = (event: ReactPointerEvent<SVGSVGElement>) => {
    dragState.current = { startX: event.clientX, startY: event.clientY, originX: transform.x, originY: transform.y };
    event.currentTarget.setPointerCapture(event.pointerId);
  };

  const handlePointerMove = (event: ReactPointerEvent<SVGSVGElement>) => {
    if (!dragState.current) return;
    const dx = event.clientX - dragState.current.startX;
    const dy = event.clientY - dragState.current.startY;
    setTransform((prev) => ({ ...prev, x: dragState.current!.originX + dx, y: dragState.current!.originY + dy }));
  };

  const handlePointerUp = (event: ReactPointerEvent<SVGSVGElement>) => {
    dragState.current = null;
    event.currentTarget.releasePointerCapture(event.pointerId);
  };

  const resetView = () => setTransform({ x: 0, y: 0, scale: 1 });

  if (graph.nodes.length === 0) {
    return <p className="text-sm text-slate-500">No relationships could be derived from this incident's linked alerts yet.</p>;
  }

  return (
    <div>
      <div className="flex items-center justify-between gap-2">
        <div className="flex flex-wrap gap-3">
          {(Object.entries(NODE_VISUAL) as [GraphNodeType, (typeof NODE_VISUAL)[GraphNodeType]][]).map(([type, visual]) => (
            <span key={type} className="flex items-center gap-1.5 text-xs text-slate-400">
              <span
                className="inline-block h-2.5 w-2.5 shrink-0"
                style={{
                  backgroundColor: visual.fill,
                  borderRadius: visual.shape === 'circle' ? '9999px' : visual.shape === 'square' ? '2px' : 0,
                  transform: visual.shape === 'diamond' ? 'rotate(45deg)' : undefined,
                }}
              />
              {visual.label}
            </span>
          ))}
        </div>
        <button
          type="button"
          onClick={resetView}
          className="shrink-0 rounded-md border border-slate-700 px-2 py-1 text-[11px] text-slate-400 hover:border-slate-600 hover:text-slate-200"
        >
          Reset view
        </button>
      </div>

      <svg
        viewBox={`0 0 ${VIEW_WIDTH} ${VIEW_HEIGHT}`}
        className="mt-2 h-[380px] w-full touch-none rounded-lg border border-slate-800 bg-slate-950/50"
        onWheel={handleWheel}
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerLeave={handlePointerUp}
        style={{ cursor: dragState.current ? 'grabbing' : 'grab' }}
      >
        <g transform={`translate(${transform.x} ${transform.y}) scale(${transform.scale})`}>
          {groupedEdges.map((edge) => {
            const source = positions.get(edge.source);
            const target = positions.get(edge.target);
            const sourceNode = nodesById.get(edge.source);
            const targetNode = nodesById.get(edge.target);
            if (!source || !target || !sourceNode || !targetNode) return null;
            const midX = (source.x + target.x) / 2;
            const midY = (source.y + target.y) / 2;
            const hasMitre = edge.mitre.length > 0;

            return (
              <g
                key={`${edge.source}|${edge.target}`}
                className="cursor-pointer"
                onClick={() =>
                  setSelection({ kind: 'edge', edge, sourceLabel: sourceNode.label, targetLabel: targetNode.label })
                }
              >
                <line
                  x1={source.x}
                  y1={source.y}
                  x2={target.x}
                  y2={target.y}
                  stroke={hasMitre ? '#c084fc' : '#475569'}
                  strokeWidth={hasMitre ? 2 : 1.5}
                />
                <title>
                  {`${sourceNode.label} ↔ ${targetNode.label} — ${edge.count} alert${edge.count === 1 ? '' : 's'}` +
                    (hasMitre ? ` — ${edge.mitre.map((m) => m.technique).join(', ')}` : '') +
                    ` — latest ${formatDateTime(edge.latestTimestamp)}`}
                </title>
                {edge.count > 1 && (
                  <>
                    <circle cx={midX} cy={midY} r={9} fill="#1e293b" stroke="#475569" strokeWidth={1} />
                    <text x={midX} y={midY + 3.5} textAnchor="middle" fontSize={10} fill="#cbd5e1">
                      {edge.count}
                    </text>
                  </>
                )}
              </g>
            );
          })}

          {graph.nodes.map((node) => {
            const pos = positions.get(node.id);
            if (!pos) return null;
            const isSelected = selection?.kind === 'node' && selection.node.id === node.id;
            return (
              <g key={node.id} className="cursor-pointer" onClick={() => setSelection({ kind: 'node', node })}>
                <NodeShape type={node.type} x={pos.x} y={pos.y} isSelected={isSelected} />
                <title>{`${node.label} (${NODE_VISUAL[node.type].label})`}</title>
                <text x={pos.x} y={pos.y + NODE_RADIUS + 13} textAnchor="middle" fontSize={10.5} fill="#cbd5e1">
                  {node.label.length > 18 ? `${node.label.slice(0, 16)}…` : node.label}
                </text>
              </g>
            );
          })}
        </g>
      </svg>

      {selection && (
        <div className="mt-2 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-xs">
          {selection.kind === 'node' ? (
            <>
              <p className="font-medium text-slate-200">{selection.node.label}</p>
              <p className="mt-0.5 text-slate-500">{NODE_VISUAL[selection.node.type].label}</p>
            </>
          ) : (
            <>
              <p className="font-medium text-slate-200">
                {selection.sourceLabel} <span className="text-slate-600">↔</span> {selection.targetLabel}
              </p>
              <p className="mt-0.5 text-slate-500">
                {selection.edge.count} connecting alert{selection.edge.count === 1 ? '' : 's'} · latest{' '}
                {formatRelativeTime(selection.edge.latestTimestamp)}
              </p>
              {selection.edge.mitre.length > 0 && (
                <p className="mt-1 flex flex-wrap gap-1">
                  {selection.edge.mitre.map((m) => (
                    <span key={m.technique} className="rounded border border-purple-700/50 bg-purple-900/30 px-1.5 py-0.5 text-purple-300">
                      {m.technique}
                      {m.tactic ? ` · ${m.tactic}` : ''}
                    </span>
                  ))}
                </p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
