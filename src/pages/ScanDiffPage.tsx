import { useQuery } from "@tanstack/react-query";
import { GitCompareArrows } from "lucide-react";
import { useState } from "react";
import { Link, useOutletContext, useParams } from "react-router-dom";
import { api } from "../lib/api";
import type { Project } from "../types/domain";
import { FindingRow } from "../components/FindingRow";
import { EmptyState, ErrorState, Spinner } from "../components/ui";

export function ScanDiffPage() {
  const project = useOutletContext<Project>();
  const { runId } = useParams();
  const [tab, setTab] = useState<"new" | "fixed" | "existing">("new");
  const diff = useQuery({ queryKey: ["scan-diff", project.id, runId], queryFn: () => api.scanDiff(project.id, runId!), enabled: Boolean(runId) });
  if (diff.isLoading) return <div className="page-loading"><Spinner label="Comparing workspace fingerprints…" /></div>;
  if (diff.error) return <ErrorState error={diff.error} />;
  if (!diff.data) return <div className="page"><EmptyState icon={<GitCompareArrows size={25} />} title="No previous scan to compare" description="Complete or import a second scan run in this workspace to calculate New, Existing, and Fixed findings." action={<Link className="button button-secondary" to={"/workspace/" + project.id + "/scans"}>Back to scan history</Link>} /></div>;
  const data = diff.data;
  const rows = data[tab];
  return <div className="page diff-page"><header className="page-header"><div><span className="eyebrow">Workspace fingerprint diff</span><h1>Scan comparison</h1><p>Fingerprint matching avoids treating a moved line as a new finding.</p></div><Link className="button button-ghost" to={"/workspace/" + project.id + "/scans?run=" + data.currentRunId}>Open run</Link></header><div className="diff-summary"><button className={tab === "new" ? "active" : ""} onClick={() => setTab("new")}><span>+ {data.newCount}</span>New</button><button className={tab === "fixed" ? "active" : ""} onClick={() => setTab("fixed")}><span>- {data.fixedCount}</span>Fixed</button><button className={tab === "existing" ? "active" : ""} onClick={() => setTab("existing")}><span>= {data.existingCount}</span>Existing</button></div>{rows.length ? <div className="diff-list">{rows.map((finding) => <FindingRow key={finding.id} finding={finding} projectId={project.id} compact />)}</div> : <EmptyState icon={<GitCompareArrows size={22} />} title={"No " + tab + " findings"} description="The selected comparison bucket is empty." />}</div>;
}
