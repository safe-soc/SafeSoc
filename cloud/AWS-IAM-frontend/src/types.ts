// Matches the Django 'FindingSerializer' output
export interface APIFinding {
  id: number;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  affected_resource: string;
  remediation: string;
}

// Matches the Django 'GraphNodeSerializer' output
export interface APIGraphNode {
  id: number;
  node_id: string;
  label: string;
  type: 'USER' | 'GROUP' | 'ROLE' | 'POLICY' | 'UNKNOWN'; // Added UNKNOWN for external nodes
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

// Matches the Django 'GraphEdgeSerializer' output
export interface APIGraphEdge {
  id: number;
  source: string;
  target: string;
  label: string;
}

// Matches the Django 'ScanSerializer' output EXACTLY
export interface APIScanResult {
  id: number;
  account_id: string;
  account_alias: string;
  scan_time: string;
  risk_score: number;
  
  // Flat fields (No 'stats' object)
  total_users: number;
  total_roles: number;
  total_policies: number;
  critical_count: number;
  high_count: number;
  medium_count: number;

  findings: APIFinding[];
  graph_data: {
    nodes: APIGraphNode[];
    edges: APIGraphEdge[];
  };
}