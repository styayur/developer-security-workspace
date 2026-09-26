import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import { openPath, openUrl } from "@tauri-apps/plugin-opener";
import type { ComponentInfo, DashboardSummary, ExtensionManifest, Finding, FindingFilters, FindingListItem, ImportResult, LogEntry, Project, RecentProject, Rule, ScanDiff, ScanProgressEvent, ScanRequest, ScanRun, ScannerConfig, ScannerInstallation, SourceFile } from "../types/domain";

export const isDesktopRuntime = () => "__TAURI_INTERNALS__" in window;
export const api = {
  openProject: (path: string) => invoke<Project>("open_project", { path }),
  getProject: (projectId: string) => invoke<Project>("get_project", { projectId }),
  recentProjects: (limit = 12) => invoke<RecentProject[]>("recent_projects", { limit }),
  readSource: (projectId: string, path: string) => invoke<SourceFile>("read_source", { projectId, path }),
  listFindings: (filters: FindingFilters) => invoke<FindingListItem[]>("list_findings", { filters }),
  getFinding: (findingId: string) => invoke<Finding>("get_finding", { findingId }),
  updateTriage: (findingId: string, status: string, note?: string) => invoke<Finding>("update_triage", { update: { findingId, status, note } }),
  dashboard: (projectId: string) => invoke<DashboardSummary>("dashboard", { projectId }),
  listRules: (projectId: string) => invoke<Rule[]>("list_rules", { projectId }),
  listScanRuns: (projectId: string, limit = 100) => invoke<ScanRun[]>("list_scan_runs", { projectId, limit }),
  getScanRun: (scanRunId: string) => invoke<ScanRun>("get_scan_run", { scanRunId }),
  scanDiff: (projectId: string, currentRunId: string, previousRunId?: string) => invoke<ScanDiff | null>("scan_diff", { projectId, currentRunId, previousRunId }),
  importSarif: (path: string, projectId?: string, workspaceRoot?: string) => invoke<ImportResult>("import_sarif", { path, projectId, workspaceRoot }),
  openDemoWorkspace: () => invoke<ImportResult>("open_demo_workspace"),
  exportSarif: (projectId: string, destination: string) => invoke<string>("export_sarif", { projectId, destination }),
  fullSarif: (scanRunId: string) => invoke<Record<string, unknown>>("full_sarif", { scanRunId }),
  listScanners: (projectId?: string) => invoke<ScannerInstallation[]>("list_scanners", { projectId }),
  configureScanner: (projectId: string, scannerId: string, executablePath?: string, config: Record<string, unknown> = {}) => invoke<ScannerConfig>("configure_scanner", { projectId, scannerId, executablePath, config }),
  clearScannerConfig: (projectId: string, scannerId: string) => invoke<ScannerConfig>("clear_scanner_config", { projectId, scannerId }),
  startScan: (request: ScanRequest) => invoke<ScanRun>("start_scan", { request }),
  cancelScan: (scanRunId: string) => invoke<void>("cancel_scan", { scanRunId }),
  getSetting: <T = unknown>(key: string) => invoke<T | null>("get_setting", { key }),
  setSetting: (key: string, value: unknown) => invoke<void>("set_setting", { setting: { key, value } }),
  listComponents: () => invoke<ComponentInfo[]>("list_components"),
  listExtensions: () => invoke<ExtensionManifest[]>("list_extensions"),
  verifyCodeql: (runtimePath: string) => invoke<{ path: string; version: string }>("verify_codeql", { runtimePath }),
};
export async function pickDirectory(): Promise<string | null> { const result = await open({ directory: true, multiple: false, title: "Open repository or folder" }); return typeof result === "string" ? result : null; }
export async function pickSarifFile(): Promise<string | null> { const result = await open({ multiple: false, title: "Import SARIF", filters: [{ name: "SARIF", extensions: ["sarif", "json"] }] }); return typeof result === "string" ? result : null; }
export async function pickExecutable(): Promise<string | null> { const result = await open({ multiple: false, title: "Locate scanner executable", filters: [{ name: "Executable", extensions: ["exe"] }] }); return typeof result === "string" ? result : null; }
export async function pickSarifDestination(defaultPath = "findings.sarif"): Promise<string | null> { return save({ title: "Export SARIF", defaultPath, filters: [{ name: "SARIF", extensions: ["sarif"] }] }); }
export async function revealPath(path: string) { await openPath(path); }
export async function openExternal(url: string) { await openUrl(url); }
export function onScanProgress(handler: (event: ScanProgressEvent) => void): Promise<UnlistenFn> { return listen<ScanProgressEvent>("scan://progress", (event) => handler(event.payload)); }
export function onScanLog(handler: (payload: { scanRunId: string; scannerId: string; entry: LogEntry }) => void): Promise<UnlistenFn> { return listen<{ scanRunId: string; scannerId: string; entry: LogEntry }>("scan://log", (event) => handler(event.payload)); }
export function onScanCompleted(handler: (run: ScanRun) => void): Promise<UnlistenFn> { return listen<ScanRun>("scan://completed", (event) => handler(event.payload)); }
