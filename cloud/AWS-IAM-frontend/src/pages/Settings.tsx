import { useScan } from '../context/ScanContext'; // Import Context
import { Settings as SettingsIcon, Bell, Shield, Database, Trash2 } from 'lucide-react';

const Settings = () => {
  const { scanData } = useScan(); // Get Real Data

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Settings</h1>
        <p className="text-slate-400">
          Configure your AWS IAM Risk Analyzer preferences
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Notifications Panel */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
          <div className="flex items-center gap-3 mb-6">
            <Bell className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-semibold text-white">Notifications</h2>
          </div>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-white">Email Alerts</p>
                <p className="text-xs text-slate-400">Receive email notifications for critical findings</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" className="sr-only peer" defaultChecked />
                <div className="w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-cyan-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500"></div>
              </label>
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-white">Daily Reports</p>
                <p className="text-xs text-slate-400">Get a daily summary of your security posture</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" className="sr-only peer" />
                <div className="w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-cyan-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500"></div>
              </label>
            </div>
          </div>
        </div>

        {/* Scan Preferences Panel */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
          <div className="flex items-center gap-3 mb-6">
            <Shield className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-semibold text-white">Scan Preferences</h2>
          </div>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-white mb-2">Scan Frequency</label>
              <select className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500">
                <option>Every 6 hours</option>
                <option>Every 12 hours</option>
                <option>Daily</option>
                <option>Weekly</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-white mb-2">Risk Threshold</label>
              <select className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500">
                <option>All Risks</option>
                <option>Medium and Above</option>
                <option>High and Critical Only</option>
                <option>Critical Only</option>
              </select>
            </div>
          </div>
        </div>

        {/* Connected Account Panel (DYNAMIC NOW) */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
          <div className="flex items-center gap-3 mb-6">
            <Database className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-semibold text-white">Connected Account</h2>
          </div>

          <div className="space-y-4">
            <div className="bg-slate-800 rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-slate-400">Account ID</span>
                <span className="text-sm font-mono text-white">
                  {scanData ? scanData.account_id : "Not Connected"}
                </span>
              </div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-slate-400">Alias</span>
                <span className="text-sm font-mono text-white">
                  {scanData ? (scanData.account_alias || "N/A") : "-"}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-400">Status</span>
                <span className="inline-flex items-center gap-2 text-sm">
                  <div className={`w-2 h-2 rounded-full ${scanData ? 'bg-emerald-400' : 'bg-red-400'}`} />
                  <span className={`${scanData ? 'text-emerald-400' : 'text-red-400'} font-medium`}>
                    {scanData ? 'Connected' : 'Disconnected'}
                  </span>
                </span>
              </div>
            </div>

            <button className="w-full bg-slate-800 hover:bg-slate-700 text-white font-medium py-2.5 rounded-lg transition-colors">
              Rotate Credentials
            </button>
          </div>
        </div>

        {/* Danger Zone */}
        <div className="bg-slate-900 border border-red-500/20 rounded-xl p-6 shadow-xl">
          <div className="flex items-center gap-3 mb-6">
            <Trash2 className="w-5 h-5 text-red-400" />
            <h2 className="text-lg font-semibold text-white">Danger Zone</h2>
          </div>
          <div className="space-y-4">
            <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
              <p className="text-sm text-slate-300 mb-3">
                Disconnecting your account will stop all scans and remove stored data.
              </p>
              <button 
                onClick={() => window.location.href = '/'} 
                className="w-full bg-red-600 hover:bg-red-700 text-white font-medium py-2.5 rounded-lg transition-colors"
              >
                Disconnect Account
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Advanced Options Panel */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex items-center gap-3 mb-6">
          <SettingsIcon className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-semibold text-white">Advanced Options</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-white">Enable Debug Mode</p>
              <p className="text-xs text-slate-400">Show detailed scan information</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" className="sr-only peer" />
              <div className="w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-cyan-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500"></div>
            </label>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-white">Auto-Remediation</p>
              <p className="text-xs text-slate-400">Automatically fix low-risk issues</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" className="sr-only peer" />
              <div className="w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-cyan-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500"></div>
            </label>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;