export interface Position {
  x: number;
  y: number;
}

export interface Node {
  id: string;
  label: string;
  type: 'USER' | 'GROUP' | 'ROLE' | 'POLICY';
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  position: Position;
}

export interface Edge {
  id: string;
  source: string;
  target: string;
  label: string;
}

export interface Risk {
  id: string;
  category: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  title: string;
  description: string;
  affected_resource: string;
  remediation: string;
}

export interface MockData {
  summary: {
    account_id: string;
    account_alias: string;
    scan_time: string;
    risk_score: number;
    stats: {
      users: number;
      roles: number;
      policies: number;
      critical_risks: number;
      high_risks: number;
      medium_risks: number;
    };
  };
  graph_data: {
    nodes: Node[];
    edges: Edge[];
  };
  risks: Risk[];
}

export const mockData: MockData = {
  summary: {
    account_id: "123456789012",
    account_alias: "dev-environment",
    scan_time: "2025-10-27T10:30:00Z",
    risk_score: 65,
    stats: {
      users: 12,
      roles: 34,
      policies: 45,
      critical_risks: 4,
      high_risks: 5,
      medium_risks: 8
    }
  },
  graph_data: {
    nodes: [
      { id: "user-dave", label: "Dave (Dev)", type: "USER", risk: "HIGH", position: { x: 0, y: 0 } },
      { id: "group-admins", label: "Admin Group", type: "GROUP", risk: "CRITICAL", position: { x: 200, y: 0 } },
      { id: "role-deployment", label: "DeploymentRole", type: "ROLE", risk: "MEDIUM", position: { x: 200, y: 150 } },
      { id: "policy-admin", label: "AdministratorAccess", type: "POLICY", risk: "CRITICAL", position: { x: 400, y: 75 } },
      { id: "role-ec2", label: "EC2-S3-Access", type: "ROLE", risk: "LOW", position: { x: 0, y: 150 } }
    ],
    edges: [
      { id: "e1", source: "user-dave", target: "group-admins", label: "MEMBER_OF" },
      { id: "e2", source: "group-admins", target: "policy-admin", label: "HAS_POLICY" },
      { id: "e3", source: "user-dave", target: "role-deployment", label: "CAN_ASSUME" },
      { id: "e4", source: "role-deployment", target: "policy-admin", label: "ATTACHED_TO" }
    ]
  },
  risks: [
    {
      id: "R-001",
      category: "Privilege Escalation",
      severity: "CRITICAL",
      title: "Indirect Admin Access",
      description: "User 'Dave' can assume 'DeploymentRole', which has full AdministratorAccess.",
      affected_resource: "user-dave",
      remediation: "Remove sts:AssumeRole permission from Dave's inline policy."
    },
    {
      id: "R-002",
      category: "Misconfiguration",
      severity: "CRITICAL",
      title: "Publicly Assumable Role",
      description: "The Trust Policy for 'DeploymentRole' allows access from '*' (Any AWS Account).",
      affected_resource: "role-deployment",
      remediation: "Update the Trust Policy to specify a Principal AWS Account ID."
    },
    {
      id: "R-003",
      category: "Excessive Permissions",
      severity: "HIGH",
      title: "Full Wildcard Permissions",
      description: "Policy contains 'Action': '*' and 'Resource': '*'. This grants full control.",
      affected_resource: "policy-unsafe-dev",
      remediation: "Scope down permissions to specific services and resources."
    },
    {
      id: "R-004",
      category: "Security Hygiene",
      severity: "HIGH",
      title: "MFA Not Enabled on Admin",
      description: "User 'Admin-Sarah' has full access privileges but Multi-Factor Authentication is disabled.",
      affected_resource: "user-sarah",
      remediation: "Enforce MFA via IAM Policy Condition 'aws:MultiFactorAuthPresent'."
    },
    {
      id: "R-005",
      category: "Security Hygiene",
      severity: "MEDIUM",
      title: "Unused Access Keys",
      description: "Access Key AKIAXYZ... for user 'BackupBot' has not been used in >90 days.",
      affected_resource: "user-backupbot",
      remediation: "Rotate or delete the inactive access key to prevent credential leakage."
    }
  ]
};
