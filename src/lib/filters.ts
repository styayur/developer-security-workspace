import type { Finding, FindingFilters, FindingListItem, FindingStatus, Severity, TraceStep } from "../types/domain";
export const emptyFilters = (projectId: string): FindingFilters => ({ projectId, severities: [], scanners: [], categories: [], statuses: [] });
export function severityLabel(severity: Severity) { return severity.toUpperCase(); }
export function severityMarker(severity: Severity) { return { critical: "●", high: "▲", medium: "◆", low: "•", info: "·" }[severity]; }
export function statusLabel(status: FindingStatus) { return status.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }
export function filterFindings(findings: FindingListItem[], filters: FindingFilters) {
  const query = filters.search?.trim().toLowerCase();
  return findings.filter((finding) => {
    if (filters.severities.length && !filters.severities.includes(finding.severity)) return false;
    if (filters.scanners.length && !filters.scanners.includes(finding.scannerId)) return false;
    if (filters.categories.length && !filters.categories.includes(finding.category)) return false;
    if (filters.statuses.length && !filters.statuses.includes(finding.status)) return false;
    if (filters.filePath && !finding.filePath.toLowerCase().includes(filters.filePath.toLowerCase())) return false;
    if (filters.cwe && !finding.cwe.some((cwe) => cwe.toLowerCase().includes(filters.cwe!.toLowerCase()))) return false;
    if (filters.ruleId && !finding.ruleId.toLowerCase().includes(filters.ruleId.toLowerCase())) return false;
    if (query) {
      const haystack = [finding.title, finding.message, finding.ruleId, finding.filePath, finding.scannerName, ...finding.cwe].join(" ").toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  });
}
export function flattenTraceSteps(finding: Pick<Finding, "codeFlows">): TraceStep[] { return finding.codeFlows.flatMap((flow) => flow.threadFlows.flatMap((thread) => thread.steps)); }
