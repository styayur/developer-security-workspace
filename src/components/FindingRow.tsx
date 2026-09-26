import { ChevronRight } from "lucide-react";
import { Link } from "react-router-dom";
import { severityLabel, severityMarker, statusLabel } from "../lib/filters";
import type { FindingListItem } from "../types/domain";
import { cn } from "../lib/utils";

export function FindingRow({ finding, projectId, compact = false }: { finding: FindingListItem; projectId: string; compact?: boolean }) {
  return <Link to={"/workspace/" + projectId + "/findings/" + finding.id} className={cn("finding-row", compact && "finding-row-compact")}><span className={cn("finding-marker", "severity-" + finding.severity)} aria-label={severityLabel(finding.severity)}>{severityMarker(finding.severity)}</span><div className="finding-row-main"><div className="finding-row-title"><strong>{finding.title}</strong><span className="finding-scanner">{finding.scannerName}</span></div><p>{finding.message}</p><div className="finding-row-meta"><span>{finding.filePath}:{finding.startLine}</span><span>{finding.cwe.join(" · ") || "No CWE"}</span><span>{statusLabel(finding.status)}</span></div></div><ChevronRight size={15} /></Link>;
}
