import { useQuery } from "@tanstack/react-query";
import { Activity, Boxes, ChevronLeft, ChevronRight, FileSearch, GitBranch, LayoutDashboard, ListChecks, Menu, Moon, Radar, ScrollText, Search, Settings, ShieldCheck, Sun, TerminalSquare } from "lucide-react";
import { FormEvent, useState } from "react";
import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { shortenCommit } from "../lib/utils";
import { useAppStore, type Theme } from "../stores/app";
import type { Project } from "../types/domain";
import { CommandPalette } from "./CommandPalette";
import { IconButton, Tooltip } from "./ui";

const navItems = [
  { label: "Overview", icon: LayoutDashboard, path: "overview" },
  { label: "Findings", icon: ListChecks, path: "findings" },
  { label: "Scans", icon: Radar, path: "scans" },
  { label: "Scanners", icon: ShieldCheck, path: "scanners" },
  { label: "Rules", icon: ScrollText, path: "rules" },
  { label: "SARIF", icon: FileSearch, path: "sarif" },
  { label: "Extensions", icon: Boxes, path: "extensions" },
  { label: "Settings", icon: Settings, path: "settings" },
];

export function AppShell({ project }: { project: Project }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const sidebarCollapsed = useAppStore((state) => state.sidebarCollapsed);
  const toggleSidebar = useAppStore((state) => state.toggleSidebar);
  const theme = useAppStore((state) => state.theme);
  const setTheme = useAppStore((state) => state.setTheme);
  const setCommandOpen = useAppStore((state) => state.setCommandOpen);
  const dashboard = useQuery({ queryKey: ["dashboard", project.id], queryFn: () => api.dashboard(project.id) });
  const submitSearch = (event: FormEvent) => { event.preventDefault(); if (search.trim()) navigate("/workspace/" + project.id + "/findings?q=" + encodeURIComponent(search.trim())); };
  const cycleTheme = () => { const order: Theme[] = ["dark", "light", "system"]; const index = order.indexOf(theme); setTheme(order[(index + 1) % order.length]); };
  return <div className="app-shell"><header className="titlebar"><div className="titlebar-project"><IconButton label="Toggle sidebar" onClick={toggleSidebar}><Menu size={16} /></IconButton><Link to={"/workspace/" + project.id + "/overview"} className="brand-mark"><TerminalSquare size={17} /></Link><div className="project-identity"><strong>{project.name}</strong><span><GitBranch size={12} />{project.branch ?? "folder"} · {shortenCommit(project.commitHash)}</span></div></div><form className="global-search" onSubmit={submitSearch}><Search size={14} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search findings, rules, files…" /><kbd>Ctrl K</kbd></form><div className="titlebar-actions"><span className="preview-badge">Preview</span><Tooltip content={"Theme: " + theme}><button className="icon-button" onClick={cycleTheme} aria-label="Change theme">{theme === "light" ? <Sun size={16} /> : <Moon size={16} />}</button></Tooltip><button className="button button-primary" onClick={() => navigate("/workspace/" + project.id + "/scanners")}><Activity size={15} />Scan</button></div></header><div className={"workspace-layout " + (sidebarCollapsed ? "sidebar-collapsed" : "")}><aside className="sidebar"><nav>{navItems.map((item) => <Link key={item.path} to={"/workspace/" + project.id + "/" + item.path} className={location.pathname.includes("/" + item.path) ? "active" : ""} title={item.label}><item.icon size={17} /><span>{item.label}</span></Link>)}</nav><div className="sidebar-footer"><IconButton label="Collapse sidebar" onClick={toggleSidebar}>{sidebarCollapsed ? <ChevronRight size={15} /> : <ChevronLeft size={15} />}</IconButton><span>Local-first</span></div></aside><main className="main-content"><Outlet context={project} /></main></div><footer className="statusbar"><span><GitBranch size={12} />{project.branch ?? "folder"} · {shortenCommit(project.commitHash)}</span><span>{dashboard.data?.scannerCount ?? 0} scanners</span><span>{dashboard.data?.totalFindings ?? 0} findings</span><span className="status-local">● Local</span><span className="status-spacer" />{dashboard.data?.lastScan?.status === "running" ? <span className="scan-running">Scanning…</span> : <span>v0.1.0-preview</span>}</footer><CommandPalette project={project} /><button className="sr-only" onClick={() => setCommandOpen(true)}>Open command palette</button></div>;
}
