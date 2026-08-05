import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';
import { APIScanResult } from '../types';

interface ScanContextType {
  scanData: APIScanResult | null;
  loading: boolean;
  error: string | null;
  startScan: (accessKey: string, secretKey: string) => Promise<void>;
  refreshHistory: () => Promise<void>;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);

export const ScanProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [scanData, setScanData] = useState<APIScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Function to run a NEW scan (POST)
  const startScan = async (accessKey: string, secretKey: string) => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post('http://127.0.0.1:8000/api/scan/', {
        access_key: accessKey,
        secret_key: secretKey
      });
      setScanData(response.data);
    } catch (err) {
      console.error(err);
      const message = axios.isAxiosError(err) ? err.response?.data?.error : undefined;
      setError(message || "Failed to connect to scanner engine.");
      throw err; // Re-throw to handle UI redirects
    } finally {
      setLoading(false);
    }
  };

  // Function to load recent history (GET)
  const refreshHistory = async () => {
    setLoading(true);
    try {
      const response = await axios.get('http://127.0.0.1:8000/api/history/');
      if (response.data && response.data.length > 0) {
        setScanData(response.data[0]); // Load the most recent scan
      }
    } catch {
      console.error("No history found or backend offline");
    } finally {
      setLoading(false);
    }
  };

  // Load history on startup
  useEffect(() => {
    refreshHistory();
  }, []);

  return (
    <ScanContext.Provider value={{ scanData, loading, error, startScan, refreshHistory }}>
      {children}
    </ScanContext.Provider>
  );
};

export const useScan = () => {
  const context = useContext(ScanContext);
  if (context === undefined) {
    throw new Error('useScan must be used within a ScanProvider');
  }
  return context;
};