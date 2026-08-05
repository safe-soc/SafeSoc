import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Key, Lock, Loader2, AlertCircle } from 'lucide-react';
import { useScan } from '../context/ScanContext'; // Import our new Context

const ConnectAccount = () => {
  const navigate = useNavigate();
  const { startScan } = useScan(); // Get the startScan function
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [credentials, setCredentials] = useState({
    accessKeyId: '',
    secretAccessKey: '',
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      // Call the Real API
      await startScan(credentials.accessKeyId, credentials.secretAccessKey);
      // If successful, redirect
      navigate('/dashboard');
    } catch (err) {
      console.error("Scan Failed:", err);
      // Error is already handled in Context, but we can set local state if needed
      setError("Connection failed. Check your keys or backend server.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-8">
      <div className="max-w-2xl w-full">
        {/* ... Header Section (Same as before) ... */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-cyan-500/10 rounded-2xl mb-6 border border-cyan-500/20">
            <Shield className="w-10 h-10 text-cyan-400" />
          </div>
          <h1 className="text-4xl font-bold text-white mb-3">AWS IAM Risk Analyzer</h1>
          <p className="text-slate-400 text-lg">Connect your AWS account to begin security analysis</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 shadow-2xl">
          {/* ... Secure Connection Header (Same) ... */}
          
          {/* Error Message Alert */}
          {error && (
             <div className="mb-6 bg-red-500/10 border border-red-500/20 rounded-lg p-4 flex items-center gap-3">
               <AlertCircle className="w-5 h-5 text-red-400" />
               <p className="text-sm text-red-300">{error}</p>
             </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Inputs (Same as before) */}
            <div>
              <label htmlFor="accessKeyId" className="block text-sm font-medium text-slate-300 mb-2">AWS Access Key ID</label>
              <div className="relative">
                <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
                <input
                  type="text"
                  id="accessKeyId"
                  value={credentials.accessKeyId}
                  onChange={(e) => setCredentials({ ...credentials, accessKeyId: e.target.value })}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-11 pr-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-all"
                  placeholder="AKIA..."
                  required
                />
              </div>
            </div>

            <div>
              <label htmlFor="secretAccessKey" className="block text-sm font-medium text-slate-300 mb-2">AWS Secret Access Key</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
                <input
                  type="password"
                  id="secretAccessKey"
                  value={credentials.secretAccessKey}
                  onChange={(e) => setCredentials({ ...credentials, secretAccessKey: e.target.value })}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-11 pr-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-all"
                  placeholder="wJalr..."
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-600 hover:to-blue-700 text-white font-semibold py-3 px-6 rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Scanning Cloud Environment...
                </>
              ) : (
                <>
                  <Shield className="w-5 h-5" />
                  Start Security Scan
                </>
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default ConnectAccount;