import { useState } from 'react';
import { useScan } from '../context/ScanContext'; // Import Context
import { ChevronDown, ChevronUp, Filter, AlertCircle, XCircle, AlertTriangle } from 'lucide-react';

const RiskFindings = () => {
  const { scanData } = useScan(); // Get Real Data
  
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set()); // ID is now number in API
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');

  if (!scanData) return <div className="text-white p-10">No findings data available.</div>;

  const findings = scanData.findings; // Use API findings

  const toggleRow = (id: number) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedRows(newExpanded);
  };

  const getSeverityConfig = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', icon: XCircle };
      case 'HIGH':
        return { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20', icon: AlertCircle };
      case 'MEDIUM':
        return { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', icon: AlertTriangle };
      default:
        return { color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20', icon: AlertCircle };
    }
  };

  const filteredRisks = findings.filter((risk) => {
    const severityMatch = severityFilter === 'ALL' || risk.severity === severityFilter;
    const categoryMatch = categoryFilter === 'ALL' || risk.category === categoryFilter;
    return severityMatch && categoryMatch;
  });

  const categories = ['ALL', ...Array.from(new Set(findings.map((r) => r.category)))];
  const severities = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Risk Findings</h1>
        <p className="text-slate-400">Review and remediate security misconfigurations and risks</p>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex items-center gap-3 mb-4">
          <Filter className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-semibold text-white">Filters</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-2">Severity</label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              {severities.map((sev) => <option key={sev} value={sev}>{sev}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-2">Category</label>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              {categories.map((cat) => <option key={cat} value={cat}>{cat}</option>)}
            </select>
          </div>
        </div>

        <div className="mt-4 flex items-center gap-2 text-sm text-slate-400">
          <span>Showing {filteredRisks.length} of {findings.length} findings</span>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-800/50 border-b border-slate-800">
              <tr>
                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Severity</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Category</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Issue</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Affected Resource</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {filteredRisks.map((risk) => {
                const severityConfig = getSeverityConfig(risk.severity);
                const Icon = severityConfig.icon;
                const isExpanded = expandedRows.has(risk.id);

                return (
                  <>
                    <tr key={risk.id} className="hover:bg-slate-800/50 transition-colors cursor-pointer" onClick={() => toggleRow(risk.id)}>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border ${severityConfig.bg} ${severityConfig.border}`}>
                          <Icon className={`w-4 h-4 ${severityConfig.color}`} />
                          <span className={`text-sm font-semibold ${severityConfig.color}`}>{risk.severity}</span>
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-300">{risk.category}</td>
                      <td className="px-6 py-4">
                        <div className="text-sm font-medium text-white">{risk.title}</div>
                        <div className="text-xs text-slate-400 mt-0.5">ID: {risk.id}</div>
                      </td>
                      <td className="px-6 py-4">
                        <code className="text-sm text-cyan-400 bg-cyan-500/10 px-2 py-1 rounded">{risk.affected_resource}</code>
                      </td>
                      <td className="px-6 py-4">
                        <button className="flex items-center gap-2 text-sm text-cyan-400 hover:text-cyan-300 transition-colors">
                          {isExpanded ? <><ChevronUp className="w-4 h-4" />Hide Details</> : <><ChevronDown className="w-4 h-4" />View Details</>}
                        </button>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr key={`${risk.id}-details`} className="bg-slate-800/30">
                        <td colSpan={5} className="px-6 py-6">
                          <div className="space-y-4">
                            <div>
                              <h3 className="text-sm font-semibold text-white mb-2">Description</h3>
                              <p className="text-sm text-slate-300 leading-relaxed">{risk.description}</p>
                            </div>
                            <div className="border-t border-slate-700 pt-4">
                              <h3 className="text-sm font-semibold text-white mb-2">Remediation</h3>
                              <p className="text-sm text-slate-300 leading-relaxed">{risk.remediation}</p>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                );
              })}
            </tbody>
          </table>
        </div>
        {filteredRisks.length === 0 && (
          <div className="text-center py-12">
            <AlertCircle className="w-12 h-12 text-slate-600 mx-auto mb-4" />
            <p className="text-slate-400">No risks found matching the current filters</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default RiskFindings;