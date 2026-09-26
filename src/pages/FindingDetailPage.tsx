import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import "../lib/monaco";
import { ArrowLeft, ArrowRight, Check, Copy, FileCode2, FolderOpen, Info, ListTree, ScrollText, ShieldAlert, Sparkles, Wrench, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useOutletContext, useParams } from "react-router-dom";
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";
import { api, revealPath } from "../lib/api";
import { flattenTraceSteps } from "../lib/filters";
import { cn } from "../lib/utils";
import { useAppStore } from "../stores/app";
import type { FindingLocation, FindingStatus, Project } from "../types/domain";
import { JsonViewer } from "../components/JsonViewer";
import { MonacoSource } from "../components/MonacoSource";
import { Button, EmptyState, ErrorState, IconButton, SeverityBadge, Spinner, StatusBadge } from "../components/ui";
import * as Tabs from "@radix-ui/react-tabs";

export function FindingDetailPage() {
  const project = useOutletContext<Project>();
  const { findingId } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const theme = useAppStore((state) => state.theme);
  const [activeLocation, setActiveLocation] = useState<FindingLocation>();
  const [activeTab, setActiveTab] = useState("overview");
  const [note, setNote] = useState("");
  const [fullRaw, setFullRaw] = useState<Record<string, unknown>>();
  const detail = useQuery({ queryKey: ["finding", findingId], queryFn: () => api.getFinding(findingId!), enabled: Boolean(findingId) });
  const all = useQuery({ queryKey: ["findings", project.id, "navigation"], queryFn: () => api.listFindings({ projectId: project.id, severities: [], scanners: [], categories: [], statuses: [] }) });
  const finding = detail.data;
  useEffect(() => { if (finding) { setActiveLocation(finding.location); setNote(finding.triageNote ?? ""); } }, [finding]);
  const source = useQuery({ queryKey: ["source", project.id, activeLocation?.filePath], queryFn: () => api.readSource(project.id, activeLocation!.filePath), enabled: Boolean(activeLocation?.filePath && activeLocation.filePath !== "unknown") });
  const steps = useMemo(() => finding ? flattenTraceSteps(finding) : [], [finding]);
  const currentIndex = all.data?.findIndex((item) => item.id === findingId) ?? -1;
  const previous = currentIndex > 0 ? all.data?.[currentIndex - 1] : undefined;
  const next = currentIndex >= 0 && all.data && currentIndex < all.data.length - 1 ? all.data[currentIndex + 1] : undefined;
  const triage = useMutation({ mutationFn: ({ status, value }: { status: FindingStatus; value?: string }) => api.updateTriage(finding!.id, status, value ?? note), onSuccess: (updated) => { queryClient.setQueryData(["finding", updated.id], updated); queryClient.invalidateQueries({ queryKey: ["findings", project.id] }); } });
  const copy = (value: string) => navigator.clipboard.writeText(value);
  if (detail.isLoading) return <div className="page-loading"><Spinner label="Loading finding…" /></div>;
  if (detail.error || !finding) return <ErrorState error={detail.error ?? "Finding not found"} />;
  const filePath = activeLocation?.filePath ?? finding.location.filePath;
  const currentLocation: FindingLocation = activeLocation ?? finding.location;
  const line = currentLocation.region.startLine;
  return (
    <div className="finding-debugger">
      <header className="debugger-toolbar">
        <div className="debugger-nav"><Link className="icon-button" to={"/workspace/" + project.id + "/findings"} aria-label="Back to findings"><ArrowLeft size={16} /></Link><IconButton label="Previous finding" disabled={!previous} onClick={() => previous && navigate("/workspace/" + project.id + "/findings/" + previous.id)}><ArrowLeft size={15} /></IconButton><span className="finding-counter">{currentIndex >= 0 ? currentIndex + 1 : 1} / {all.data?.length ?? 1}</span><IconButton label="Next finding" disabled={!next} onClick={() => next && navigate("/workspace/" + project.id + "/findings/" + next.id)}><ArrowRight size={15} /></IconButton></div>
        <div className="debugger-file"><FileCode2 size={15} /><span>{filePath}</span><strong>:{line}</strong></div>
        <div className="debugger-actions"><Button variant="ghost" onClick={() => copy(filePath)}><Copy size={14} />Copy path</Button><Button variant="ghost" onClick={() => copy(finding.ruleId)}><Copy size={14} />Copy rule</Button><Button variant="ghost" onClick={() => copy(finding.title + "\n" + finding.message + "\n" + filePath + ":" + line)}><Copy size={14} />Copy summary</Button><Button variant="ghost" onClick={() => currentLocation.absolutePath && revealPath(currentLocation.absolutePath)}><FolderOpen size={14} />Open file</Button></div>
      </header>
      <PanelGroup direction="horizontal" autoSaveId="dsw-finding-debugger" className="debugger-workbench">
        <Panel defaultSize={62} minSize={35}>
          <div className="source-pane"><div className="source-breadcrumb"><span>{project.name}</span><span>/</span>{filePath.split("/").map((part, index, parts) => <span key={part + index}>{part}{index < parts.length - 1 ? " /" : ""}</span>)}</div>{source.error ? <EmptyState title="Source unavailable" description={source.error instanceof Error ? source.error.message : String(source.error)} /> : <MonacoSource source={source.data} location={currentLocation} theme={theme === "light" ? "vs" : "vs-dark"} />}</div>
        </Panel>
        <PanelResizeHandle className="resize-handle" />
        <Panel defaultSize={38} minSize={28}>
          <aside className="inspector-pane">
            <div className="inspector-summary"><div className="inspector-title-row"><SeverityBadge severity={finding.severity} /><StatusBadge status={finding.status} /></div><h2>{finding.title}</h2><p>{finding.message}</p><div className="inspector-rule">{finding.scannerName} · {finding.ruleId}</div></div>
            <Tabs.Root value={activeTab} onValueChange={setActiveTab} className="inspector-tabs"><Tabs.List className="tabs-list"><Tabs.Trigger value="overview"><Info size={13} />Overview</Tabs.Trigger><Tabs.Trigger value="trace"><ListTree size={13} />Trace</Tabs.Trigger><Tabs.Trigger value="rule"><ScrollText size={13} />Rule</Tabs.Trigger><Tabs.Trigger value="fix"><Wrench size={13} />Fix</Tabs.Trigger><Tabs.Trigger value="raw"><ShieldAlert size={13} />Raw</Tabs.Trigger></Tabs.List>
              <Tabs.Content value="overview" className="tab-content"><Metadata label="CWE" value={finding.cwe.join(", ") || "Not provided"} /><Metadata label="Location" value={filePath + ":" + line} /><Metadata label="Fingerprint" value={finding.workspaceFingerprint.slice(0, 18) + "…"} mono /><div className="triage-block"><h3>Triage</h3><div className="triage-actions"><Button onClick={() => triage.mutate({ status: "confirmed" })}><Check size={14} />Confirm</Button><Button onClick={() => triage.mutate({ status: "false_positive" })}><XCircle size={14} />False positive</Button><Button onClick={() => triage.mutate({ status: "accepted_risk" })}>Accept risk</Button><Button variant="ghost" onClick={() => triage.mutate({ status: "ignored" })}>Ignore</Button><Button variant="ghost" onClick={() => triage.mutate({ status: "reopened" })}>Reopen</Button></div><textarea value={note} onChange={(event) => setNote(event.target.value)} placeholder="Add triage note…" /><Button onClick={() => triage.mutate({ status: finding.status })} disabled={triage.isPending}>Save note</Button></div></Tabs.Content>
              <Tabs.Content value="trace" className="tab-content">{steps.length ? <><div className="trace-steps">{steps.map((step) => <button key={step.index} className={cn("trace-step", currentLocation.region.startLine === step.location.region.startLine && currentLocation.filePath === step.location.filePath && "active")} onClick={() => { setActiveLocation(step.location) }}><span className="trace-index">{step.index}</span><span className="trace-node" /><span><strong>{step.label}</strong><small>{step.message ?? step.location.filePath + ":" + step.location.region.startLine}</small></span></button>)}</div><div className="trace-controls"><Button variant="ghost" disabled={!steps.length} onClick={() => { const index = Math.max(0, steps.findIndex((step) => step.location.filePath === currentLocation.filePath && step.location.region.startLine === currentLocation.region.startLine) - 1); setActiveLocation(steps[index].location); }}><ArrowLeft size={14} />Previous step</Button><span>Trace Player</span><Button variant="ghost" onClick={() => { const current = steps.findIndex((step) => step.location.filePath === currentLocation.filePath && step.location.region.startLine === currentLocation.region.startLine); const index = Math.min(steps.length - 1, current + 1); setActiveLocation(steps[index].location); }}>Next step<ArrowRight size={14} /></Button></div></> : <EmptyState icon={<ListTree size={21} />} title="No execution/data-flow trace" description="No execution/data-flow trace was provided by this scanner." />}</Tabs.Content>
              <Tabs.Content value="rule" className="tab-content"><Metadata label="Rule" value={finding.ruleId} mono /><Metadata label="Scanner" value={finding.scannerName} /><Metadata label="Severity" value={finding.severity.toUpperCase()} /><Metadata label="CWE" value={finding.cwe.join(", ") || "Not provided"} /><Metadata label="Taxa" value={finding.taxa.map((taxon) => taxon.id).join(", ") || "Not provided"} /><p className="muted-copy">Only scanner-provided rule metadata is shown. Missing fields are not inferred.</p></Tabs.Content>
              <Tabs.Content value="fix" className="tab-content">{finding.fixes.length ? finding.fixes.map((fix, index) => <div key={index} className="fix-card"><strong>{fix.description ?? "Scanner-provided fix"}</strong>{fix.replacements.map((replacement, replacementIndex) => <pre key={replacementIndex}>{replacement.filePath + ":" + replacement.deletedRegion.startLine + "\n" + (replacement.insertedContent ?? "No replacement content")}</pre>)}</div>) : <EmptyState icon={<Wrench size={20} />} title="No fix provided" description="This scanner result did not include a SARIF fix." />}</Tabs.Content>
              <Tabs.Content value="raw" className="tab-content raw-tab"><div className="raw-actions"><Button variant="ghost" onClick={async () => setFullRaw(await api.fullSarif(finding.scanRunId))}><Sparkles size={14} />Open full SARIF run</Button></div><JsonViewer value={fullRaw ?? finding.rawSarif} /></Tabs.Content>
            </Tabs.Root>
          </aside>
        </Panel>
      </PanelGroup>
    </div>
  );
}

function Metadata({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) { return <div className="metadata-row"><span>{label}</span><strong className={mono ? "font-mono" : undefined}>{value}</strong></div>; }
