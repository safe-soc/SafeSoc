import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ScanProvider } from './context/ScanContext';
import Layout from './components/Layout';
import ConnectAccount from './pages/ConnectAccount';
import Dashboard from './pages/Dashboard';
import GraphExplorer from './pages/GraphExplorer';
import RiskFindings from './pages/RiskFindings';
import Settings from './pages/Settings';

function App() {
  return (
    <ScanProvider>
      <Router>
        <Routes>
          <Route path="/" element={<ConnectAccount />} />
          <Route path="/dashboard" element={<Layout><Dashboard /></Layout>} />
          <Route path="/graph-explorer" element={<Layout><GraphExplorer /></Layout>} />
          <Route path="/risk-findings" element={<Layout><RiskFindings /></Layout>} />
          <Route path="/settings" element={<Layout><Settings /></Layout>} />
        </Routes>
      </Router>
    </ScanProvider>
  );
}

export default App;