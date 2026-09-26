import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { lazy, Suspense, useEffect } from "react";
import { BrowserRouter, Navigate, Route, Routes, useParams } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { ErrorState, Spinner } from "./components/ui";
import { api } from "./lib/api";
import { ComponentsPage } from "./pages/ComponentsPage";
import { ExtensionsPage } from "./pages/ExtensionsPage";
const FindingDetailPage = lazy(() => import("./pages/FindingDetailPage").then((module) => ({ default: module.FindingDetailPage })));
import { FindingsPage } from "./pages/FindingsPage";
import { OverviewPage } from "./pages/OverviewPage";
import { RulesPage } from "./pages/RulesPage";
import { SarifPage } from "./pages/SarifPage";
import { ScanDiffPage } from "./pages/ScanDiffPage";
import { ScannersPage } from "./pages/ScannersPage";
import { ScansPage } from "./pages/ScansPage";
import { SettingsPage } from "./pages/SettingsPage";
import { WelcomePage } from "./pages/WelcomePage";
import { useAppStore } from "./stores/app";
import { useQuery } from "@tanstack/react-query";

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 5_000, refetchOnWindowFocus: false } } });

export default function App() {
  const theme = useAppStore((state) => state.theme);
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => { const resolved = theme === "system" ? (media.matches ? "dark" : "light") : theme; document.documentElement.dataset.theme = resolved; };
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [theme]);
  return <QueryClientProvider client={queryClient}><Tooltip.Provider delayDuration={350}><BrowserRouter><Routes><Route path="/" element={<WelcomePage />} /><Route path="/workspace/:projectId" element={<WorkspaceLayout />}><Route index element={<Navigate to="overview" replace />} /><Route path="overview" element={<OverviewPage />} /><Route path="findings" element={<FindingsPage />} /><Route path="findings/:findingId" element={<Suspense fallback={<div className="page-loading"><Spinner label="Loading debugger…" /></div>}><FindingDetailPage /></Suspense>} /><Route path="scans" element={<ScansPage />} /><Route path="scans/:runId/diff" element={<ScanDiffPage />} /><Route path="scanners" element={<ScannersPage />} /><Route path="rules" element={<RulesPage />} /><Route path="sarif" element={<SarifPage />} /><Route path="settings" element={<SettingsPage />} /><Route path="components" element={<ComponentsPage />} /><Route path="extensions" element={<ExtensionsPage />} /></Route><Route path="*" element={<Navigate to="/" replace />} /></Routes></BrowserRouter></Tooltip.Provider></QueryClientProvider>;
}

function WorkspaceLayout() {
  const { projectId } = useParams();
  const setActiveProject = useAppStore((state) => state.setActiveProject);
  const project = useQuery({ queryKey: ["project", projectId], queryFn: () => api.getProject(projectId!), enabled: Boolean(projectId) });
  useEffect(() => { if (project.data) setActiveProject(project.data.id); }, [project.data, setActiveProject]);
  if (project.isLoading) return <div className="full-page-loading"><Spinner label="Opening workspace…" /></div>;
  if (project.error || !project.data) return <div className="full-page-loading"><ErrorState error={project.error ?? "Workspace not found"} /></div>;
  return <AppShell project={project.data} />;
}
