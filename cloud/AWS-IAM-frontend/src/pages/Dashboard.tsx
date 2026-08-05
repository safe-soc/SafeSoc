import { useScan } from '../context/ScanContext';
import { Users, Shield, FileText, AlertTriangle, TrendingUp } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';

const Dashboard = () => {
  const { scanData, loading } = useScan();

  if (loading) return <div className="text-white p-10">Loading Dashboard...</div>;
  if (!scanData) return <div className="text-white p-10">No scan data available. Go to Connect Account.</div>;

  // --- FIXED DATA MAPPING HERE ---
  // We read directly from the flat API fields (total_users, etc.)
  const { 
    risk_score, 
    account_alias, 
    account_id, 
    scan_time,
    total_users,
    total_roles,
    total_policies,
    critical_count,
    high_count,
    medium_count
  } = scanData;

  const getRiskLevel = (score: number) => {
    // High Score = BAD (Red)
    if (score >= 80) return { text: 'Critical', color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20' };
    if (score >= 50) return { text: 'High', color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20' };
    if (score >= 20) return { text: 'Medium', color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20' };
    // Low Score = GOOD (Green)
    return { text: 'Low', color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20' };
  };

  const riskLevel = getRiskLevel(risk_score);

  const gaugeData = [
    { 
      name: 'Score', 
      value: risk_score, 
      // Color logic flipped: High score gets Red
      color: risk_score >= 80 ? '#ef4444' : risk_score >= 50 ? '#f97316' : risk_score >= 20 ? '#eab308' : '#10b981' 
    },
    { name: 'Remaining', value: 100 - risk_score, color: '#1e293b' },
  ];

  const trendData = [
    { day: 'Mon', score: 58 },
    { day: 'Tue', score: 62 },
    { day: 'Wed', score: 60 },
    { day: 'Thu', score: 63 },
    { day: 'Fri', score: risk_score },
  ];

  // --- FIXED STAT CARDS ---
  const statCards = [
    { label: 'Total Users', value: total_users, icon: Users, color: 'cyan' },
    { label: 'Total Roles', value: total_roles, icon: Shield, color: 'blue' },
    { label: 'Total Policies', value: total_policies, icon: FileText, color: 'slate' },
    { label: 'Critical Risks', value: critical_count, icon: AlertTriangle, color: 'red' },
    { label: 'High Risks', value: high_count, icon: AlertTriangle, color: 'orange' },
    { label: 'Medium Risks', value: medium_count, icon: AlertTriangle, color: 'yellow' },
  ];

  const getColorClasses = (color: string) => {
    const colors: Record<string, { text: string; bg: string; border: string }> = {
      cyan: { text: 'text-cyan-400', bg: 'bg-cyan-500/10', border: 'border-cyan-500/20' },
      blue: { text: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20' },
      slate: { text: 'text-slate-400', bg: 'bg-slate-500/10', border: 'border-slate-500/20' },
      red: { text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20' },
      orange: { text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20' },
      yellow: { text: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20' },
    };
    return colors[color] || colors.slate;
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Security Dashboard</h1>
        <div className="flex items-center gap-4 text-sm text-slate-400">
          <span>Account: {account_alias || "N/A"}</span>
          <span>•</span>
          <span>ID: {account_id}</span>
          <span>•</span>
          <span>Last Scan: {new Date(scan_time).toLocaleString()}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className={`lg:col-span-1 bg-slate-900 border ${riskLevel.border} rounded-xl p-8 shadow-xl`}>
          <div className="text-center">
            <h2 className="text-lg font-semibold text-slate-300 mb-6">Overall Risk Score</h2>
            <div className="relative inline-block">
              <ResponsiveContainer width={200} height={200}>
                <PieChart>
                  <Pie
                    data={gaugeData}
                    cx="50%"
                    cy="50%"
                    startAngle={180}
                    endAngle={0}
                    innerRadius={60}
                    outerRadius={90}
                    paddingAngle={0}
                    dataKey="value"
                  >
                    {gaugeData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex items-center justify-center pt-8">
                <div>
                  <div className={`text-5xl font-bold ${riskLevel.color}`}>{risk_score}</div>
                  <div className="text-sm text-slate-400 mt-1">/ 100</div>
                </div>
              </div>
            </div>
            <div className={`mt-6 inline-flex items-center gap-2 px-4 py-2 ${riskLevel.bg} ${riskLevel.border} border rounded-lg`}>
              <div className={`w-2 h-2 rounded-full ${riskLevel.color.replace('text-', 'bg-')}`} />
              <span className={`font-semibold ${riskLevel.color}`}>{riskLevel.text}</span>
            </div>
            <p className="text-xs text-slate-500 mt-4">
              Lower score indicates better security posture
            </p>
          </div>
        </div>

        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-8 shadow-xl">
          <div className="flex items-center gap-3 mb-6">
            <TrendingUp className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-semibold text-white">Risk Score Trend</h2>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="day" stroke="#64748b" />
              <YAxis domain={[0, 100]} stroke="#64748b" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  color: '#fff',
                }}
              />
              <Line type="monotone" dataKey="score" stroke="#22d3ee" strokeWidth={3} dot={{ fill: '#22d3ee', r: 5 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div>
        <h2 className="text-xl font-semibold text-white mb-4">Statistics Overview</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {statCards.map((card) => {
            const Icon = card.icon;
            const colors = getColorClasses(card.color);
            return (
              <div
                key={card.label}
                className={`bg-slate-900 border ${colors.border} rounded-xl p-6 shadow-lg hover:shadow-xl transition-shadow`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-slate-400 mb-1">{card.label}</p>
                    <p className={`text-3xl font-bold ${colors.text}`}>{card.value}</p>
                  </div>
                  <div className={`${colors.bg} p-4 rounded-xl border ${colors.border}`}>
                    <Icon className={`w-6 h-6 ${colors.text}`} />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;