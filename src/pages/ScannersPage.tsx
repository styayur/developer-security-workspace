import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, CheckCircle2, Clipboard, ExternalLink, FolderSearch, Play, RefreshCw, Settings2, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useNavigate, useOutletContext } from "react-router-dom";
import { api, onScanCompleted, onScanProgress, openExternal, pickExecutable } from "../lib/api";
import { errorMessage } from "../lib/utils";
import type { Project, ScannerCapabilities, ScannerInstallation, ScanProgressEvent } from "../types/domain";
import { Badge, Button, EmptyState, ErrorState, Input, Panel, Spinner } from "../components/ui";

type ScannerDraft = { executablePath?: string; config: Record<string, unknown> };

export function ScannersPage() {
  const project = useOutletContext<Project>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const installed = useQuery({ queryKey: ["scanners", project.id], queryFn: () => api.listScanners(project.id) });
  const [selected, setSelected] = useState<string[]>([]);
  const [drafts, setDrafts] = useState<Record<string, ScannerDraft>>({});
  const [mode, setMode] = useState<"full" | "changed">("full");
  const [activeRunId, setActiveRunId] = useState<string>();
  const [progress, setProgress] = useState<Record<string, ScanProgressEvent>>({});
  const [notice, setNotice] = useState<string>();
  useEffect(() => { if (installed.data) setDrafts((current) => Object.fromEntries(installed.data!.map((item) => [item.id, current[item.id] ?? { executablePath: item.configuredPath ?? item.executable, config: {} }]))); }, [installed.data]);
  useEffect(() => {
    const cleanups: Array<() => void> = [];
    onScanProgress((event) => setProgress((current) => ({ ...current, [event.scannerId]: event }))).then((cleanup) => cleanups.push(cleanup));
    onScanCompleted((run) => { setActiveRunId(undefined); setProgress({}); queryClient.invalidateQueries({ queryKey: ["scan-runs", project.id] }); setNotice("Scan " + run.status + " · " + run.findingCount + " findings"); }).then((cleanup) => cleanups.push(cleanup));
    return () => cleanups.forEach((cleanup) => cleanup());
  }, [project.id, queryClient]);
  const save = useMutation({ mutationFn: ({ id, draft }: { id: string; draft: ScannerDraft }) => api.configureScanner(project.id, id, draft.executablePath, draft.config), onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["scanners", project.id] }); setNotice("Scanner configuration saved."); } });
  const start = useMutation({ mutationFn: () => api.startScan({ projectId: project.id, scannerIds: selected, workspaceRoot: project.path, mode, scannerConfigs: Object.fromEntries(selected.map((id) => [id, drafts[id]?.config ?? {}])) }), onSuccess: (run) => { setActiveRunId(run.id); setNotice("Scan started. Progress is coming from the Rust runtime."); queryClient.invalidateQueries({ queryKey: ["scan-runs", project.id] }); } });
  const cancel = useMutation({ mutationFn: () => api.cancelScan(activeRunId!), onSuccess: () => setNotice("Cancellation requested.") });
  const installedSelected = useMemo(() => installed.data?.filter((scanner) => scanner.installed && selected.includes(scanner.id)) ?? [], [installed.data, selected]);
  const toggle = (id: string) => setSelected((current) => current.includes(id) ? current.filter((value) => value !== id) : [...current, id]);
  const locate = async (scanner: ScannerInstallation) => { const path = await pickExecutable(); if (!path) return; const draft = { ...(drafts[scanner.id] ?? { config: {} }), executablePath: path }; setDrafts((current) => ({ ...current, [scanner.id]: draft })); save.mutate({ id: scanner.id, draft }); };
  if (installed.isLoading) return <div className="page-loading"><Spinner label="Detecting scanner binaries…" /></div>;
  if (installed.error) return <ErrorState error={installed.error} />;
  return (
    <div className="page scanners-page">
      <header className="page-header"><div><span className="eyebrow">Scanner orchestrator</span><h1>Run Security Scan</h1><p>Only installed, locally detected tools can run. No scanner binary is downloaded automatically.</p></div><Button variant="ghost" onClick={() => installed.refetch()}><RefreshCw size={14} />Recheck</Button></header>
      {notice ? <div className="inline-notice"><CheckCircle2 size={15} />{notice}</div> : null}
      <div className="scanner-grid">{installed.data?.map((scanner) => { const draft = drafts[scanner.id] ?? { config: {} }; const checked = selected.includes(scanner.id); return <Panel key={scanner.id} className={"scanner-card " + (checked ? "selected" : "")}>
        <div className="scanner-card-header"><label className="scanner-check"><input type="checkbox" checked={checked} disabled={!scanner.installed} onChange={() => toggle(scanner.id)} /><span><strong>{scanner.displayName}</strong><small>{scanner.description}</small></span></label><Badge tone={scanner.installed ? "success" : "muted"}>{scanner.installed ? "Installed" : "Not installed"}</Badge></div>
        <div className="scanner-facts"><div><span>Version</span><strong>{scanner.version ?? "—"}</strong></div><div><span>Path</span><strong className="path-value" title={draft.executablePath ?? scanner.executable}>{draft.executablePath ?? scanner.executable ?? "Not found"}</strong></div><div><span>License</span><strong>{scanner.license}</strong></div></div>
        <CapabilityRow capabilities={scanner.capabilities} />
        {scanner.id === "semgrep" ? <div className="scanner-config"><label><span>Rule source</span><Input value={String(draft.config.config ?? "p/default")} onChange={(event) => setDrafts((current) => ({ ...current, [scanner.id]: { ...draft, config: { ...draft.config, config: event.target.value } } }))} placeholder="Local path, directory, or registry identifier" /></label><label><span>Additional structured args</span><Input value={(draft.config.extraArgs as string[] | undefined)?.join(" ") ?? ""} onChange={(event) => setDrafts((current) => ({ ...current, [scanner.id]: { ...draft, config: { ...draft.config, extraArgs: event.target.value.split(/\s+/).filter(Boolean) } } }))} placeholder="--timeout 30" /></label><p>Semgrep engine and Semgrep-maintained rules are separate license objects.</p></div> : null}
        {scanner.id === "trivy" ? <div className="scanner-config"><span>Scan categories</span><div className="check-row">{[["vuln", "Vulnerability"], ["misconfig", "Misconfiguration"], ["secret", "Secret"], ["license", "License"]].map(([value, label]) => <label key={value}><input type="checkbox" checked={(draft.config.scanners as string[] | undefined)?.includes(value) ?? ["vuln", "misconfig", "secret", "license"].includes(value)} onChange={(event) => { const current = (draft.config.scanners as string[] | undefined) ?? ["vuln", "misconfig", "secret", "license"]; const next = event.target.checked ? [...new Set([...current, value])] : current.filter((item) => item !== value); setDrafts((state) => ({ ...state, [scanner.id]: { ...draft, config: { ...draft.config, scanners: next } } })); }} />{label}</label>)}</div></div> : null}
        {scanner.id === "trufflehog" ? <div className="scanner-config"><label className="inline-check"><input type="checkbox" checked={Boolean(draft.config.verifiedOnly)} onChange={(event) => setDrafts((current) => ({ ...current, [scanner.id]: { ...draft, config: { ...draft.config, verifiedOnly: event.target.checked } } }))} />Only show verified credentials from this adapter</label><p>Raw candidate secret values are not shown or persisted by the compatibility adapter.</p></div> : null}
        <div className="scanner-actions"><Button onClick={() => save.mutate({ id: scanner.id, draft })}><Settings2 size={14} />Save config</Button>{scanner.installed ? <Button variant="ghost" onClick={() => locate(scanner)}><FolderSearch size={14} />Locate binary</Button> : <Button variant="ghost" onClick={() => navigator.clipboard.writeText(scanner.installCommand)}><Clipboard size={14} />Copy install command</Button>}<Button variant="ghost" onClick={() => openExternal(scanner.projectUrl)}><ExternalLink size={14} />Project</Button></div>
      </Panel>; })}</div>
      <Panel className="scan-launch-panel"><div><span className="eyebrow">Target</span><h2>{project.name}</h2><p>{project.path}</p></div><div className="scan-mode"><span>Mode</span><button className={mode === "full" ? "active" : ""} onClick={() => setMode("full")}>Full</button><button className={mode === "changed" ? "active" : ""} onClick={() => setMode("changed")}>Changed Files</button></div><div className="launch-actions">{activeRunId ? <Button variant="danger" onClick={() => cancel.mutate()}><Ban size={15} />Cancel scan</Button> : <Button variant="primary" disabled={!installedSelected.length || start.isPending} onClick={() => start.mutate()}><Play size={15} />{start.isPending ? "Starting…" : "Start Scan"}</Button>}<span>{installedSelected.length} scanner(s) selected</span></div>{start.error ? <div className="inline-error">{errorMessage(start.error)}</div> : null}{Object.keys(progress).length ? <div className="launch-progress">{Object.values(progress).map((event) => <div key={event.scannerId}><strong>{event.scannerName}</strong><span>{event.status}</span><progress value={event.status === "completed" ? 100 : 55} max={100} /><small>{event.message}</small></div>)}</div> : null}</Panel>
      {!installed.data?.some((scanner) => scanner.installed) ? <EmptyState icon={<ShieldAlert size={24} />} title="No supported scanner detected" description="Use each provider’s official setup command, then Recheck. Demo and SARIF import remain available without scanner binaries." action={<Button onClick={() => navigate("/workspace/" + project.id + "/sarif")}>Open SARIF tools</Button>} /> : null}
    </div>
  );
}

function CapabilityRow({ capabilities }: { capabilities: ScannerCapabilities }) { const labels: Array<[keyof ScannerCapabilities, string]> = [["sast", "SAST"], ["secrets", "Secrets"], ["sca", "SCA"], ["iac", "IaC"], ["container", "Container"], ["licenses", "Licenses"]]; return <div className="capability-row">{labels.filter(([key]) => capabilities[key]).map(([key, label]) => <span key={key}>{label}</span>)}</div>; }
