import React, { lazy, Suspense } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { AuthLayout } from "./layouts/AuthLayout";
import { ProtectedLayout } from "./layouts/ProtectedLayout";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Skeleton } from "./components/ui/Skeleton";

// Dynamic Named Imports with Code-Splitting
const RoleSelectionPage = lazy(() => import("./pages/Login/RoleSelectionPage").then(m => ({ default: m.RoleSelectionPage })));
const LoginPage = lazy(() => import("./pages/Login/LoginPage").then(m => ({ default: m.LoginPage })));
const DashboardPage = lazy(() => import("./pages/Dashboard/DashboardPage").then(m => ({ default: m.DashboardPage })));
const FindingsPage = lazy(() => import("./pages/Findings/FindingsPage").then(m => ({ default: m.FindingsPage })));
const EndpointDetailsPage = lazy(() => import("./pages/EndpointDetails/EndpointDetailsPage").then(m => ({ default: m.EndpointDetailsPage })));
const AttackGraphPage = lazy(() => import("./pages/AttackGraph/AttackGraphPage").then(m => ({ default: m.AttackGraphPage })));
const CopilotPage = lazy(() => import("./pages/Copilot/CopilotPage").then(m => ({ default: m.CopilotPage })));
const ApprovalQueuePage = lazy(() => import("./pages/ApprovalQueue/ApprovalQueuePage").then(m => ({ default: m.ApprovalQueuePage })));
const ReportsPage = lazy(() => import("./pages/Reports/ReportsPage").then(m => ({ default: m.ReportsPage })));
const SettingsPage = lazy(() => import("./pages/Settings/SettingsPage").then(m => ({ default: m.SettingsPage })));
const EndpointsPage = lazy(() => import("./pages/Endpoints/EndpointsPage").then(m => ({ default: m.EndpointsPage })));
const NotFoundPage = lazy(() => import("./pages/NotFound/NotFoundPage").then(m => ({ default: m.NotFoundPage })));
const MaintenancePage = lazy(() => import("./pages/Maintenance/MaintenancePage").then(m => ({ default: m.MaintenancePage })));

import { motion } from "framer-motion";

const LoadingFallback = () => (
  <motion.div 
    initial={{ opacity: 0 }}
    animate={{ opacity: 1 }}
    transition={{ duration: 0.25 }}
    className="p-6 space-y-6"
  >
    <div className="space-y-2">
      <Skeleton className="h-6 w-48 rounded" />
      <Skeleton className="h-4 w-72 rounded" />
    </div>
    <Skeleton className="h-[300px] w-full rounded-md" />
  </motion.div>
);

export function App() {
  return (
    <ErrorBoundary>
      <Router>
        <Suspense fallback={<LoadingFallback />}>
          <Routes>
            {/* Public Authentication sector */}
            <Route element={<AuthLayout />}>
              <Route path="/login" element={<RoleSelectionPage />} />
              <Route path="/admin-login" element={<LoginPage title="Administrator Login" subtitle="Full system access" role="admin" accentColor="blue" redirectPath="/" />} />
              <Route path="/analyst-login" element={<LoginPage title="Security Analyst Login" subtitle="Threat investigation workspace" role="analyst" accentColor="purple" redirectPath="/" />} />
            </Route>

            {/* Secured Console Operation sectors */}
            <Route element={<ProtectedLayout />}>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/findings" element={<FindingsPage />} />
              <Route path="/endpoints" element={<EndpointsPage />} />
              <Route path="/endpoints/:id" element={<EndpointDetailsPage />} />
              <Route path="/graph" element={<AttackGraphPage />} />
              <Route path="/copilot" element={<CopilotPage />} />
              <Route path="/approvals" element={<ApprovalQueuePage />} />
              <Route path="/reports" element={<ReportsPage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Route>

            {/* Maintenance route */}
            <Route path="/maintenance" element={<MaintenancePage />} />

            {/* Wildcard 404 Route */}
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </Suspense>
      </Router>
    </ErrorBoundary>
  );
}

export default App;
