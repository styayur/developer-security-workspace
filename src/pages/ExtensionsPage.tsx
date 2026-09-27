import { useMutation, useQuery } from "@tanstack/react-query";
import { Boxes, LockKeyhole } from "lucide-react";
import { useState } from "react";
import { useNavigate, useOutletContext } from "react-router-dom";
import { api } from "../lib/api";
import type { ExtensionManifest, Project } from "../types/domain";
import { Badge, Button, ErrorState, Panel, Spinner } from "../components/ui";

export function ExtensionsPage() {
  const project = useOutletContext<Project>();
  const navigate = useNavigate();
  const extensions = useQuery({ queryKey: ["extensions"], queryFn: api.listExtensions });
  const [approved, setApproved] = useState<Record<string, string>>({});
  const run = useMutation({ mutationFn: (extension: ExtensionManifest) => api.startScan({ projectId: project.id, workspaceRoot: project.path, mode: "full", scannerIds: [extension.id], scannerConfigs: { [extension.id]: { approvalDigest: approved[extension.id] } } }), onSuccess: () => navigate(`/workspace/${project.id}/scans`) });
  if (extensions.isLoading) return <div className="page-loading"><Spinner /></div>;
  if (extensions.error) return <ErrorState error={extensions.error} />;
  return <div className="page"><header className="page-header"><div><span className="eyebrow">Declarative scanners v1</span><h1>Extensions</h1><p>Review a manifest and installed executable, then run it through the scanner pipeline.</p></div><Button onClick={() => extensions.refetch()}>Recheck</Button></header>
    <div className="extension-safety"><LockKeyhole size={17} /><span>Runtime v1 supports the reviewed offline Gitleaks profile. Permissions describe the invocation; external binaries run with your OS privileges. Install only binaries you trust.</span></div>
    {run.error && <ErrorState error={run.error} />}
    <div className="extension-grid">{extensions.data?.map((extension) => <Panel key={extension.id} className="extension-card">
      <div><Boxes size={18} /><div><strong>{extension.name}</strong><small>{extension.id}</small></div><Badge tone="muted">Third-party · untrusted</Badge></div>
      <dl><dt>Version</dt><dd>{extension.version}</dd><dt>Executable</dt><dd className="mono">{extension.resolvedExecutable ?? `${extension.scanner.executable} (not installed)`}</dd><dt>Arguments</dt><dd className="mono">{extension.scan.args.join(" ")}</dd><dt>Workspace</dt><dd>Read: {String(extension.permissions.workspaceRead)} · Write: {String(extension.permissions.workspaceWrite)}</dd><dt>Network declaration</dt><dd>{extension.permissions.network ? "Requested" : "None"}</dd><dt>Output</dt><dd>{extension.output.format} / {extension.output.source}</dd><dt>Timeout</dt><dd>{extension.scan.timeoutSeconds}s</dd><dt>License</dt><dd>{extension.license.spdx} · {extension.license.bundled ? "bundled" : "external"}</dd><dt>Approval digest</dt><dd className="mono">{extension.approvalDigest.slice(0, 20)}…</dd></dl>
      <div className="capability-row">{Object.entries(extension.capabilities).filter(([,value]) => value).map(([key]) => <span key={key}>{key}</span>)}</div>
      {extension.runnable ? <><label><input type="checkbox" checked={approved[extension.id] === extension.approvalDigest} onChange={(event) => setApproved((current) => ({ ...current, [extension.id]: event.target.checked ? extension.approvalDigest : "" }))} />I approve this manifest and installed binary for this workspace.</label><Button disabled={!extension.resolvedExecutable || approved[extension.id] !== extension.approvalDigest || run.isPending} onClick={() => run.mutate(extension)}>Run extension</Button></> : <p>This manifest is metadata only: its execution profile is not supported by runtime v1.</p>}
    </Panel>)}</div>
  </div>;
}
