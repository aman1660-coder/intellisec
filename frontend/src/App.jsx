import { Navigate, Route, Routes } from "react-router-dom";
import AppLayout from "./layouts/AppLayout";
import { useAuth } from "./context/AuthContext";
import Landing from "./pages/Landing";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import NewScan from "./pages/NewScan";
import ScanResults from "./pages/ScanResults";
import FindingsExplorer from "./pages/FindingsExplorer";
import AttackPathExplorer from "./pages/AttackPathExplorer";
import ComplianceDashboard from "./pages/ComplianceDashboard";
import PQCReadiness from "./pages/PQCReadiness";
import ScanHistory from "./pages/ScanHistory";
import ScanComparison from "./pages/ScanComparison";
import ResearchNovelty from "./pages/ResearchNovelty";
import CaseStudy from "./pages/CaseStudy";
import Profile from "./pages/Profile";
import NotFound from "./pages/NotFound";

function Protected({ children }) {
  const { isAuthenticated, loading } = useAuth();
  if (loading) return <div className="min-h-screen bg-ink p-8 text-slate-300">Loading IntelliSec...</div>;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/case-study" element={<CaseStudy />} />
      <Route
        path="/app"
        element={
          <Protected>
            <AppLayout />
          </Protected>
        }
      >
        <Route index element={<Navigate to="/app/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="new-scan" element={<NewScan />} />
        <Route path="scans/:scanId" element={<ScanResults />} />
        <Route path="findings" element={<FindingsExplorer />} />
        <Route path="attack-paths" element={<AttackPathExplorer />} />
        <Route path="compliance" element={<ComplianceDashboard />} />
        <Route path="pqc" element={<PQCReadiness />} />
        <Route path="history" element={<ScanHistory />} />
        <Route path="compare" element={<ScanComparison />} />
        <Route path="research" element={<ResearchNovelty />} />
        <Route path="profile" element={<Profile />} />
      </Route>
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
