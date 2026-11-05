import { Suspense, lazy, type ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { Guard } from "./components/Shell";
import { PageSkeleton } from "./components/skeletons";
import Landing from "./pages/Landing";
import Login from "./pages/Login";
import Register from "./pages/Register";

const Overview = lazy(() => import("./pages/Overview"));
const Agents = lazy(() => import("./pages/Agents"));
const Monitoring = lazy(() => import("./pages/Monitoring"));
const Threats = lazy(() => import("./pages/Threats"));
const Evaluations = lazy(() => import("./pages/Evaluations"));
const Decisions = lazy(() => import("./pages/Decisions"));
const Policies = lazy(() => import("./pages/Policies"));
const Improvement = lazy(() => import("./pages/Improvement"));
const Audit = lazy(() => import("./pages/Audit"));
const Integrations = lazy(() => import("./pages/Integrations"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));

function LazyPage({ children }: { children: ReactNode }) {
  return <Suspense fallback={<PageSkeleton />}>{children}</Suspense>;
}

export default function App() {
  return <Routes>
    <Route path="/" element={<Landing />} />
    <Route path="/login" element={<Login />} />
    <Route path="/register" element={<Register />} />
    <Route path="/app" element={<Guard><LazyPage><Overview /></LazyPage></Guard>} />
    <Route path="/app/agents" element={<Guard><LazyPage><Agents /></LazyPage></Guard>} />
    <Route path="/app/monitoring" element={<Guard><LazyPage><Monitoring /></LazyPage></Guard>} />
    <Route path="/app/threats" element={<Guard><LazyPage><Threats /></LazyPage></Guard>} />
    <Route path="/app/evaluations" element={<Guard><LazyPage><Evaluations /></LazyPage></Guard>} />
    <Route path="/app/decisions" element={<Guard><LazyPage><Decisions /></LazyPage></Guard>} />
    <Route path="/app/policies" element={<Guard><LazyPage><Policies /></LazyPage></Guard>} />
    <Route path="/app/improvement" element={<Guard><LazyPage><Improvement /></LazyPage></Guard>} />
    <Route path="/app/audit" element={<Guard><LazyPage><Audit /></LazyPage></Guard>} />
    <Route path="/app/integrations" element={<Guard><LazyPage><Integrations /></LazyPage></Guard>} />
    <Route path="/app/settings" element={<Guard><LazyPage><SettingsPage /></LazyPage></Guard>} />
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>;
}
