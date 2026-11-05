import { Navigate, Route, Routes } from "react-router-dom";
import { Guard } from "./components/Shell";
import Agents from "./pages/Agents";
import Audit from "./pages/Audit";
import Decisions from "./pages/Decisions";
import Evaluations from "./pages/Evaluations";
import Improvement from "./pages/Improvement";
import Integrations from "./pages/Integrations";
import Landing from "./pages/Landing";
import Login from "./pages/Login";
import Monitoring from "./pages/Monitoring";
import Overview from "./pages/Overview";
import Policies from "./pages/Policies";
import Register from "./pages/Register";
import SettingsPage from "./pages/SettingsPage";
import Threats from "./pages/Threats";

export default function App() {
  return <Routes>
    <Route path="/" element={<Landing />} />
    <Route path="/login" element={<Login />} />
    <Route path="/register" element={<Register />} />
    <Route path="/app" element={<Guard><Overview /></Guard>} />
    <Route path="/app/agents" element={<Guard><Agents /></Guard>} />
    <Route path="/app/monitoring" element={<Guard><Monitoring /></Guard>} />
    <Route path="/app/threats" element={<Guard><Threats /></Guard>} />
    <Route path="/app/evaluations" element={<Guard><Evaluations /></Guard>} />
    <Route path="/app/decisions" element={<Guard><Decisions /></Guard>} />
    <Route path="/app/policies" element={<Guard><Policies /></Guard>} />
    <Route path="/app/improvement" element={<Guard><Improvement /></Guard>} />
    <Route path="/app/audit" element={<Guard><Audit /></Guard>} />
    <Route path="/app/integrations" element={<Guard><Integrations /></Guard>} />
    <Route path="/app/settings" element={<Guard><SettingsPage /></Guard>} />
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>;
}
