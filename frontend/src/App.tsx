import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Alerts from './pages/Alerts';
import Compliance from './pages/Compliance';
import ComplianceRequirementDetail from './pages/ComplianceRequirementDetail';
import Dashboard from './pages/Dashboard';
import EndpointDetail from './pages/EndpointDetail';
import Endpoints from './pages/Endpoints';
import IncidentDetail from './pages/IncidentDetail';
import Incidents from './pages/Incidents';
import Investigate from './pages/Investigate';
import Login from './pages/Login';
import Soar from './pages/Soar';
import ThreatAnalytics from './pages/ThreatAnalytics';

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<ProtectedRoute />}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/endpoints" element={<Endpoints />} />
            <Route path="/endpoints/:hostId" element={<EndpointDetail />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:incidentId" element={<IncidentDetail />} />
            <Route path="/soar" element={<Soar />} />
            <Route path="/investigate" element={<Investigate />} />
            <Route path="/threat-analytics" element={<ThreatAnalytics />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/compliance/:requirementId" element={<ComplianceRequirementDetail />} />
          </Route>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
