import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, ChevronDown, GitCommitHorizontal, ListFilter, Radar, Terminal } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useOutletContext, useSearchParams } from "react-router-dom";
import { api, onScanCompleted, onScanProgress } from "../lib/api";
import { formatDuration, formatTimestamp, shortenCommit } from "../lib/utils";
import type { Project, ScanProgressEvent } from "../types/domain";
import { Badge, Button, EmptyState, ErrorState, Panel, Spinner } from "../components/ui";

export function ScansPage() {
  const project = useOutletContext<Project>();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const [progress, setProgress] = useState<Record<string, ScanProgressEvent>>({});
  const runs = useQuery({ queryKey: ["scan-runs", project.id, 100], queryFn: () => api.listScanRuns(project.id, 100) });
  const selectedId = params.get("run") ?? runs.data?.[0]?.id;
  const selected = runs.data?.find((run) => run.id === selectedId) ?? runs.data?.[0];
  const cancel = useMutation({ mutationFn: api.cancelScan, onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scan-runs", project.id] }) });
  useEffect(() => {
    const cleanups: Array<() => void> = [];
    onScanProgress((event) => setProgress((current) => ({ ...current, [event.scannerId]: event }))).then((cleanup) => cleanups.push(cleanup));
    onScanCompleted(() => { setProgress({}); queryClient.invalidateQueries({ queryKey: ["scan-runs", project.id] }); }).then((cleanup) => cleanups.push(cleanup));
    return () => cleanups.forEach((cleanup) => cleanup());
  }, [project.id, queryClient]);
  if (runs.isLoading) return <div className="page-loading"><Spinner label="Loading scan history…" /></div>;
  if (runs.error) return <ErrorState error={runs.error} />;
  return <div className="page scans-page"><header className="page-header"><div><span className="eyebrow">Runtime history</span><h1>Scan runs</h1><p>Reopen results, inspect logs, cancel active work, and compare fingerprints across runs.</p></div><Link className="button button-primary" to={"/workspace/" + project.id + "/scanners"}><Radar size={15} />New scan</Link></header>{!runs.data?.length ? <EmptyState icon={<Radar size={24} />} title="No scan runs" description="Scanner executions, imports, and demo data all appear here." action={<Link className="button button-primary" to={"/workspace/" + project.id + "/scanners"}>Configure scanners</Link>} /> : <div className="scans-layout"><Panel className="scan-history"><div className="scan-history-header"><span>Started</span><span>Revision</span><span>Result</span></div>{runs.data.map((run, index) => <button key={run.id} className={"scan-history-row " + (selected?.id === run.id ? "active" : "")} onClick={() => setParams({ run: run.id })}><div><strong>{formatTimestamp(run.startedAt)}</strong><small>{run.source.replaceAll("_", " ")}</small></div><div className="mono"><GitCommitHorizontal size={13} />{shortenCommit(run.gitCommit)}</div><div><Badge tone={run.status === "completed" ? "success" : run.status === "failed" ? "danger" : "warning"}>{run.status}</Badge><small>{run.findingCount} findings · {formatDuration(run.durationMs)}</small></div>{index < runs.data.length - 1 && runs.data[index + 1] ? <span className="scan-diff-hint">compare</span> : null}</button>)}</Panel>{selected ? <Panel className="scan-detail"><div className="panel-header"><div><h2>Run {selected.id.slice(0, 8)}</h2><p>{formatTimestamp(selected.startedAt)} · {selected.gitBranch ?? "folder"} · {shortenCommit(selected.gitCommit)}</p></div><div className="panel-actions">{selected.status === "running" ? <Button variant="danger" onClick={() => cancel.mutate(selected.id)}><Ban size={14} />Cancel</Button> : null}<Link className="button button-secondary" to={"/workspace/" + project.id + "/scans/" + selected.id + "/diff"}><ListFilter size={14} />View diff</Link></div></div><div className="scanner-run-list">{selected.scanners.length ? selected.scanners.map((scanner) => <details key={scanner.id} className="scanner-run"><summary><span className={"scan-dot status-" + scanner.status} /><strong>{scanner.scannerName}</strong><Badge tone={scanner.status === "completed" ? "success" : scanner.status === "failed" ? "danger" : "warning"}>{scanner.status}</Badge><span>{scanner.version ?? "version unknown"}</span><span>{formatDuration(scanner.durationMs)}</span><progress max={100} value={scanner.status === "running" ? 65 : scanner.status === "completed" ? 100 : 0} /></summary><div className="scanner-logs"><div className="log-heading"><Terminal size={13} />Logs · {scanner.logs.length} entries</div>{scanner.error ? <div className="scanner-error">{scanner.error}</div> : null}{scanner.logs.map((entry, index) => <div className="log-line" key={entry.timestamp + index}><span>{entry.stream}</span><code>{entry.message}</code></div>)}</div></details>) : <EmptyState icon={<Radar size={20} />} title="No scanner records" description="This run did not persist scanner-level results." />}</div>{Object.keys(progress).length ? <div className="live-progress"><ChevronDown size={14} /><strong>Live scan events</strong>{Object.values(progress).map((event) => <div key={event.scannerId}><span>{event.scannerName}</span><progress max={100} value={event.status === "completed" ? 100 : 60} /><small>{event.message}</small></div>)}</div> : null}</Panel> : null}</div>}</div>;
}
