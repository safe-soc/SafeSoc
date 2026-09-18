/**
 * SafeSOC — Attack-Chain Graph Layout
 * Pure, dependency-free helpers for AttackChainGraphView: a small
 * force-directed layout (repulsion + spring attraction + centering,
 * run for a fixed number of iterations) and parallel-edge grouping.
 * No graph-rendering library exists in this frontend (package.json has
 * none) — this is deliberately small enough not to need one for the
 * incident-sized graphs (a handful to a few dozen entities) this
 * renders.
 */

import type { GraphEdge } from './types';

export interface LayoutPoint {
  x: number;
  y: number;
}

/** Small deterministic string hash (not cryptographic) — seeds each node's initial angle from its id. */
function hashString(value: string): number {
  let hash = 0;
  for (let i = 0; i < value.length; i++) {
    hash = (hash * 31 + value.charCodeAt(i)) | 0;
  }
  return Math.abs(hash);
}

/**
 * Force-directed layout for a relationship graph. Deterministic: the
 * same (nodeIds, edges) always produces the same positions, since
 * initial placement is seeded from each node id's hash rather than
 * Math.random() — so the graph doesn't jitter between renders/reloads,
 * and this function is a plain, testable pure function.
 */
export function computeForceLayout(
  nodeIds: string[],
  edges: { source: string; target: string }[],
  width: number,
  height: number,
): Map<string, LayoutPoint> {
  const positions = new Map<string, LayoutPoint>();
  const n = nodeIds.length;
  if (n === 0) return positions;

  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.max(Math.min(width, height) / 3, 1);

  nodeIds.forEach((id) => {
    const angle = (hashString(id) % 360) * (Math.PI / 180);
    positions.set(id, {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
    });
  });

  if (n <= 1) return positions;

  const REPULSION = 6000;
  const SPRING_LENGTH = 140;
  const SPRING_STRENGTH = 0.02;
  const CENTER_STRENGTH = 0.01;
  const DAMPING = 0.85;
  const ITERATIONS = 220;
  const MARGIN = 44;

  const velocities = new Map<string, LayoutPoint>(nodeIds.map((id) => [id, { x: 0, y: 0 }]));
  const relevantEdges = edges.filter((e) => positions.has(e.source) && positions.has(e.target));

  for (let iter = 0; iter < ITERATIONS; iter++) {
    const forces = new Map<string, LayoutPoint>(nodeIds.map((id) => [id, { x: 0, y: 0 }]));

    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const a = nodeIds[i];
        const b = nodeIds[j];
        const pa = positions.get(a)!;
        const pb = positions.get(b)!;
        let dx = pa.x - pb.x;
        let dy = pa.y - pb.y;
        let distSq = dx * dx + dy * dy;
        if (distSq < 1) {
          // Deterministic tie-break for exactly-coincident points (rare: distinct id
          // hashes landing on the same angle) rather than leaving them stacked forever.
          dx = (hashString(a + b) % 10) - 5 || 1;
          dy = (hashString(b + a) % 10) - 5 || 1;
          distSq = dx * dx + dy * dy;
        }
        const dist = Math.sqrt(distSq);
        const force = REPULSION / distSq;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        forces.get(a)!.x += fx;
        forces.get(a)!.y += fy;
        forces.get(b)!.x -= fx;
        forces.get(b)!.y -= fy;
      }
    }

    for (const edge of relevantEdges) {
      const pa = positions.get(edge.source)!;
      const pb = positions.get(edge.target)!;
      const dx = pb.x - pa.x;
      const dy = pb.y - pa.y;
      const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
      const force = (dist - SPRING_LENGTH) * SPRING_STRENGTH;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      forces.get(edge.source)!.x += fx;
      forces.get(edge.source)!.y += fy;
      forces.get(edge.target)!.x -= fx;
      forces.get(edge.target)!.y -= fy;
    }

    for (const id of nodeIds) {
      const p = positions.get(id)!;
      forces.get(id)!.x += (centerX - p.x) * CENTER_STRENGTH;
      forces.get(id)!.y += (centerY - p.y) * CENTER_STRENGTH;
    }

    for (const id of nodeIds) {
      const v = velocities.get(id)!;
      const f = forces.get(id)!;
      v.x = (v.x + f.x) * DAMPING;
      v.y = (v.y + f.y) * DAMPING;
      const p = positions.get(id)!;
      p.x = Math.min(Math.max(p.x + v.x, MARGIN), width - MARGIN);
      p.y = Math.min(Math.max(p.y + v.y, MARGIN), height - MARGIN);
    }
  }

  return positions;
}

export interface GroupedEdge {
  source: string;
  target: string;
  count: number;
  latestTimestamp: string;
  mitre: { technique: string; tactic: string | null }[];
  alertIds: string[];
}

/**
 * Collapses parallel edges (the same unordered entity pair, connected
 * by more than one alert — e.g. the same host+user pair recurring
 * across several failed logins) into one grouped edge for rendering,
 * so the graph draws one line per relationship instead of visually
 * overlapping duplicate lines. Nothing is discarded: `count`,
 * `alertIds`, and every distinct MITRE technique/tactic pair from the
 * underlying edges are preserved on the group.
 */
export function groupParallelEdges(edges: GraphEdge[]): GroupedEdge[] {
  const groups = new Map<string, GroupedEdge>();

  for (const edge of edges) {
    const key = [edge.source, edge.target].sort().join('|');
    let group = groups.get(key);
    if (!group) {
      group = { source: edge.source, target: edge.target, count: 0, latestTimestamp: edge.timestamp, mitre: [], alertIds: [] };
      groups.set(key, group);
    }
    group.count += 1;
    if (edge.timestamp > group.latestTimestamp) group.latestTimestamp = edge.timestamp;
    if (!group.alertIds.includes(edge.alert_id)) group.alertIds.push(edge.alert_id);
    if (edge.mitre_technique && !group.mitre.some((m) => m.technique === edge.mitre_technique)) {
      group.mitre.push({ technique: edge.mitre_technique, tactic: edge.mitre_tactic ?? null });
    }
  }

  return Array.from(groups.values());
}
