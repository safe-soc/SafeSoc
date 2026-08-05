import { Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, Network, AlertTriangle, Link2, Settings, Shield } from 'lucide-react';

const Sidebar = () => {
  const location = useLocation();

  const navItems = [
    { path: '/', icon: Link2, label: 'Connect Account' },
    { path: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
    { path: '/graph-explorer', icon: Network, label: 'Graph Explorer' },
    { path: '/risk-findings', icon: AlertTriangle, label: 'Risk Findings' },
    { path: '/settings', icon: Settings, label: 'Settings' },
  ];

  return (
    <div className="w-64 bg-slate-900 border-r border-slate-800 h-screen fixed left-0 top-0 flex flex-col">
      <div className="p-6 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-cyan-400" />
          <div>
            <h1 className="text-xl font-bold text-white">AWS IAM</h1>
            <p className="text-xs text-slate-400">Risk Analyzer</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-4">
        <ul className="space-y-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            return (
              <li key={item.path}>
                <Link
                  to={item.path}
                  className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                      : 'text-slate-400 hover:bg-slate-800 hover:text-white'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  <span className="font-medium">{item.label}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="p-4 border-t border-slate-800">
        <div className="px-4 py-3 bg-slate-800/50 rounded-lg">
          <p className="text-xs text-slate-500 uppercase tracking-wide">Status</p>
          <div className="flex items-center gap-2 mt-1">
            <div className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
            <span className="text-sm text-slate-300">System Online</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
