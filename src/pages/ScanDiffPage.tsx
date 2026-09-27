import { useQuery } from "@tanstack/react-query";
import { GitCompareArrows } from "lucide-react";
import { useState } from "react";
import { Link, useOutletContext, useParams } from "react-router-dom";
import { api } from "../lib/api";
import type { Project } from "../types/domain";
import { FindingRow } from "../components/FindingRow";
import { Button, EmptyState, ErrorState, Spinner } from "../components/ui";

export function ScanDiffPage() {
  const project = useOutletContext<Project>();
  const { runId } = useParams();
  const [tab, setTab] = useState<"new" | "fixed" | "existing" | "changed" | "reopened">("new");
  const [offset, setOffset] = useState(0);
  const diff = useQuery({ queryKey: ["scan-diff", project.id, runId, offset], queryFn: () => api.scanDiff(project.id, runId!, undefined, offset, 100), enabled: Boolean(runId) });
  if (diff.isLoading) return <div className="page-loading"><Spinner label="Comparing finding identities…" /></div>;
  if (diff.error) return <ErrorState error={diff.error} />;
  if (!diff.data) return <div className="page"><EmptyState icon={<GitCompareArrows size={25} />} title="No previous scan to compare" description="Complete or import a second scan run in this workspace to calculate New, Existing, and Fixed findings." action={<Link className="button button-secondary" to={"/workspace/" + project.id + "/scans"}>Back to scan history</Link>} /></div>;
  const data = diff.data;
  const rows = data[tab];
  return <div className="page diff-page"><header className="page-header"><div><span className="eyebrow">Finding identity diff</span><h1>Scan comparison</h1><p>Native, exact, source context and symbol evidence explain correspondence across scans.</p></div><Link className="button button-ghost" to={"/workspace/" + project.id + "/scans?run=" + data.currentRunId}>Open run</Link></header><div className="diff-summary">{(["new", "existing", "fixed", "reopened", "changed"] as const).map((value) => <button key={value} className={tab === value ? "active" : ""} onClick={() => { setTab(value); setOffset(0); }}><span>{data[`${value}Count`]}</span>{value}</button>)}</div><div className="trace-controls"><Button disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 100))}>Previous page</Button><span>{offset + 1}–{offset + rows.length} / {data[`${tab}Count`]}</span><Button disabled={offset + 100 >= data[`${tab}Count`]} onClick={() => setOffset(offset + 100)}>Next page</Button></div>{rows.length ? <div className="diff-list">{rows.map((finding) => <FindingRow key={finding.id} finding={finding} projectId={project.id} compact />)}</div> : <EmptyState icon={<GitCompareArrows size={22} />} title={"No " + tab + " findings"} description="The selected comparison bucket is empty." />}</div>;
}
