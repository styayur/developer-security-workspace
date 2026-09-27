import * as Dialog from "@radix-ui/react-dialog";
import { useQuery } from "@tanstack/react-query";
import { Boxes, FileSearch, FolderKanban, LayoutDashboard, ListChecks, Radar, ScrollText, Search, Settings, ShieldCheck, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { useAppStore } from "../stores/app";
import type { FindingFilters, Project } from "../types/domain";
import { Input } from "./ui";

export function CommandPalette({ project }: { project: Project }) {
  const open = useAppStore((state) => state.commandOpen);
  const setOpen = useAppStore((state) => state.setCommandOpen);
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const commands = useMemo(() => [
    { label: "Overview", hint: "Project summary", icon: LayoutDashboard, path: "/workspace/" + project.id + "/overview" },
    { label: "Findings", hint: "Search and triage findings", icon: ListChecks, path: "/workspace/" + project.id + "/findings" },
    { label: "Scan history", hint: "Runs and logs", icon: Radar, path: "/workspace/" + project.id + "/scans" },
    { label: "Scanners", hint: "Configure and run providers", icon: ShieldCheck, path: "/workspace/" + project.id + "/scanners" },
    { label: "Rules", hint: "Inspect normalized rules", icon: ScrollText, path: "/workspace/" + project.id + "/rules" },
    { label: "SARIF", hint: "Import and export", icon: FileSearch, path: "/workspace/" + project.id + "/sarif" },
    { label: "Extensions", hint: "Manifest architecture", icon: Boxes, path: "/workspace/" + project.id + "/extensions" },
    { label: "Components & licenses", hint: "Third-party inventory", icon: FolderKanban, path: "/workspace/" + project.id + "/components" },
    { label: "Settings", hint: "Theme and privacy", icon: Settings, path: "/workspace/" + project.id + "/settings" },
  ], [project.id]);
  const filters: FindingFilters = { projectId: project.id, search: query, severities: [], scanners: [], categories: [], statuses: [] };
  const findings = useQuery({ queryKey: ["command-findings", project.id, query], queryFn: () => api.findingPage(filters, 0, 8), enabled: open && query.trim().length > 1 });
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setOpen(true); }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [setOpen]);
  const select = (path: string) => { setOpen(false); setQuery(""); navigate(path); };
  const filteredCommands = commands.filter((command) => command.label.toLowerCase().includes(query.toLowerCase()));
  return <Dialog.Root open={open} onOpenChange={setOpen}><Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><Dialog.Content className="command-dialog"><Dialog.Title className="sr-only">Command palette</Dialog.Title><div className="command-input"><Search size={17} /><Input autoFocus value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search commands and findings…" /><Dialog.Close className="icon-button" aria-label="Close command palette"><X size={16} /></Dialog.Close></div><div className="command-results">{filteredCommands.map((command) => <button key={command.path} className="command-item" onClick={() => select(command.path)}><command.icon size={16} /><span><strong>{command.label}</strong><small>{command.hint}</small></span></button>)}{query.trim().length > 1 ? <div className="command-section"><span className="command-section-label">Findings</span>{findings.data?.items.map((finding) => <button key={finding.id} className="command-item" onClick={() => select("/workspace/" + project.id + "/findings/" + finding.id)}><span className={"command-severity severity-" + finding.severity}>●</span><span><strong>{finding.title}</strong><small>{finding.filePath}:{finding.startLine}</small></span></button>)}{findings.data?.total === 0 ? <p className="command-empty">No matching findings.</p> : null}</div> : null}</div></Dialog.Content></Dialog.Portal></Dialog.Root>;
}
