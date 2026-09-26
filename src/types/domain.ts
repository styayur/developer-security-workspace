export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingCategory = "sast" | "secrets" | "sca" | "iac" | "container" | "license" | "misconfiguration" | "unknown";
export type FindingStatus = "new" | "existing" | "fixed" | "confirmed" | "false_positive" | "accepted_risk" | "ignored" | "reopened";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled" | "partial";
export type ScannerRunStatus = "queued" | "running" | "completed" | "failed" | "cancelled" | "skipped";

export interface Project { id: string; name: string; path: string; isGit: boolean; branch?: string; commitHash?: string; primaryLanguage: string; fileCount: number; lastOpenedAt: string; createdAt: string; }
export interface RecentProject { id: string; name: string; path: string; primaryLanguage: string; lastOpenedAt: string; }
export interface Region { startLine: number; startColumn: number; endLine: number; endColumn: number; snippet?: string; }
export interface FindingLocation { filePath: string; absolutePath?: string; message?: string; region: Region; logicalLocations: string[]; }
export interface TraceStep { index: number; label: string; message?: string; location: FindingLocation; nestingLevel: number; }
export interface ThreadFlow { id?: string; message?: string; steps: TraceStep[]; }
export interface CodeFlow { message?: string; threadFlows: ThreadFlow[]; }
export interface FixReplacement { filePath: string; deletedRegion: Region; insertedContent?: string; }
export interface Fix { description?: string; replacements: FixReplacement[]; }
export interface Taxonomy { id: string; name?: string; shortDescription?: string; }
export interface Finding {
  id: string; scanRunId: string; projectId: string; scannerId: string; scannerName: string; ruleId: string; title: string; message: string;
  severity: Severity; category: FindingCategory; location: FindingLocation; relatedLocations: FindingLocation[]; codeFlows: CodeFlow[];
  fixes: Fix[]; taxa: Taxonomy[]; cwe: string[]; status: FindingStatus; triageNote?: string; nativeFingerprint?: string;
  workspaceFingerprint: string; rawSarif: Record<string, unknown>;
}
export interface FindingListItem {
  id: string; scanRunId: string; scannerId: string; scannerName: string; ruleId: string; title: string; message: string;
  severity: Severity; category: FindingCategory; filePath: string; startLine: number; cwe: string[]; status: FindingStatus;
  triageNote?: string; workspaceFingerprint: string;
}
export interface FindingFilters {
  projectId?: string; scanRunId?: string; search?: string; severities: Severity[]; scanners: string[]; categories: FindingCategory[];
  statuses: FindingStatus[]; filePath?: string; cwe?: string; ruleId?: string; diffClass?: string;
}
export interface LogEntry { timestamp: string; stream: string; message: string; }
export interface ScannerRun {
  id: string; scanRunId: string; scannerId: string; scannerName: string; status: ScannerRunStatus; version?: string; startedAt: string;
  finishedAt?: string; durationMs?: number; error?: string; logs: LogEntry[];
}
export interface ScanRun {
  id: string; projectId: string; startedAt: string; finishedAt?: string; gitBranch?: string; gitCommit?: string; status: ScanStatus;
  scanners: ScannerRun[]; findingCount: number; durationMs?: number; source: string;
}
export interface ScannerCapabilities { sast: boolean; secrets: boolean; sca: boolean; iac: boolean; container: boolean; licenses: boolean; vulnerabilities: boolean; misconfiguration: boolean; }
export interface ScannerInstallation {
  id: string; displayName: string; installed: boolean; executable?: string; version?: string; capabilities: ScannerCapabilities; license: string;
  projectUrl: string; installCommand: string; description: string; configuredPath?: string; detectionError?: string;
}
export interface ScannerConfig { scannerId: string; executablePath?: string; config: Record<string, unknown>; updatedAt: string; }
export interface ScanRequest {
  projectId: string; scannerIds: string[]; workspaceRoot: string; mode: "full" | "changed"; scannerConfigs: Record<string, Record<string, unknown>>;
  changedFiles?: string[];
}
export interface SeverityCounts { critical: number; high: number; medium: number; low: number; info: number; }
export interface DashboardSummary {
  project: Project; lastScan?: ScanRun; totalFindings: number; newFindings: number; existingFindings: number; fixedFindings: number;
  severity: SeverityCounts; categories: Record<string, number>; scannerCount: number;
}
export interface ScanDiff {
  currentRunId: string; previousRunId: string; new: FindingListItem[]; fixed: FindingListItem[]; existing: FindingListItem[];
  newCount: number; fixedCount: number; existingCount: number;
}
export interface Rule { id: string; name?: string; scannerId: string; description?: string; help?: string; helpUri?: string; severity: Severity; cwe: string[]; tags: string[]; }
export interface SourceFile { path: string; absolutePath: string; language: string; content: string; size: number; truncated: boolean; }
export interface ImportResult { scanRun: ScanRun; importedFindings: number; warnings: string[]; }
export interface ComponentInfo { name: string; version: string; license: string; purpose: string; url: string; }
export interface ExtensionManifest {
  schemaVersion: number; id: string; name: string; version: string; scanner: { executable: string }; output: { format: string };
  capabilities: ScannerCapabilities; license: { spdx: string; bundled: boolean }; trusted: boolean; sourcePath?: string;
}
export interface ScanProgressEvent {
  scanRunId: string; scannerId: string; scannerName: string; status: ScannerRunStatus; message: string; elapsedMs: number; findingCount: number;
}
