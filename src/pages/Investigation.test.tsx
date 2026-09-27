import { Provider as TooltipProvider } from "@radix-ui/react-tooltip";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Outlet, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../lib/api";
import { FindingsPage } from "./FindingsPage";
import { FindingDetailPage } from "./FindingDetailPage";
import { ScanDiffPage } from "./ScanDiffPage";
import type { Finding, FindingListItem, Project, ScanDiff } from "../types/domain";

vi.mock("../lib/monaco", () => ({}));
vi.mock("../components/MonacoSource", () => ({ MonacoSource: () => <div>Source editor</div> }));
vi.mock("@tanstack/react-virtual", () => ({ useVirtualizer: ({ count }: { count: number }) => ({ getTotalSize: () => count * 78, getVirtualItems: () => Array.from({ length: count }, (_, index) => ({ index, start: index * 78 })) }) }));

const project: Project = { id: "p", name: "Project", path: "/workspace", isGit: false, primaryLanguage: "TypeScript", fileCount: 1, lastOpenedAt: "now", createdAt: "now" };
const row: FindingListItem = { id: "f", scanRunId: "s", scannerId: "test", scannerName: "Test", ruleId: "sql", title: "SQL injection", message: "Untrusted input reaches query", severity: "high", category: "sast", filePath: "src/a.ts", startLine: 5, cwe: ["CWE-89"], status: "new", workspaceFingerprint: "hash" };
const finding: Finding = { ...row, projectId: "p", location: { filePath: row.filePath, logicalLocations: [], region: { startLine: 5, endLine: 5, startColumn: 1, endColumn: 10 } }, relatedLocations: [], codeFlows: [], fixes: [], taxa: [], rawSarif: {}, fingerprints: { exact: "hash" }, lifecycle: { identityId: "identity", firstSeen: "now", lastSeen: "now", occurrenceCount: 1, state: "new" }, provenance: { scannerId: "test", scannerName: "Test", adapterVersion: "1", sourceFormat: "sarif", securityIrVersion: 1, source: "imported", scanRunId: "s" } };

function mount(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><TooltipProvider><MemoryRouter initialEntries={[path]}><Routes><Route path="/workspace/p" element={<Outlet context={project} />}><Route path="findings" element={<FindingsPage />} /><Route path="findings/:findingId" element={<FindingDetailPage />} /><Route path="scans/:runId/diff" element={<ScanDiffPage />} /></Route></Routes></MemoryRouter></TooltipProvider></QueryClientProvider>);
}
afterEach(() => vi.restoreAllMocks());

describe("investigation workflow", () => {
  it("loads a bounded list then opens detail and saves triage", async () => {
    vi.spyOn(api, "findingPage").mockResolvedValue({ items: [row], total: 1, offset: 0, limit: 100 });
    vi.spyOn(api, "findingScanners").mockResolvedValue(["test"]);
    vi.spyOn(api, "getFinding").mockResolvedValue(finding);
    vi.spyOn(api, "findingNavigation").mockResolvedValue({ total: 1, position: 1 });
    vi.spyOn(api, "readSource").mockResolvedValue({ path: row.filePath, absolutePath: "/workspace/src/a.ts", content: "query(input)", language: "typescript", size: 12, truncated: false });
    const triage = vi.spyOn(api, "updateTriage").mockResolvedValue({ ...finding, status: "confirmed" });
    const user = userEvent.setup(); mount("/workspace/p/findings");
    await user.click(await screen.findByRole("link", { name: /SQL injection/ }));
    expect(await screen.findByRole("heading", { name: "SQL injection" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(triage).toHaveBeenCalledWith("f", "confirmed", ""));
    expect(api.findingPage).toHaveBeenCalledWith(expect.objectContaining({ projectId: "p" }), 0, 100);
  });
  it("filters the comparison into Changed and Reopened buckets", async () => {
    const diff: ScanDiff = { currentRunId: "s", previousRunId: "old", new: [], fixed: [], existing: [], changed: [row], reopened: [], newCount: 0, fixedCount: 0, existingCount: 0, changedCount: 1, reopenedCount: 0, offset: 0, limit: 100 };
    vi.spyOn(api, "scanDiff").mockResolvedValue(diff);
    const user = userEvent.setup(); mount("/workspace/p/scans/s/diff");
    await user.click(await screen.findByRole("button", { name: /changed/ }));
    expect(screen.getByRole("link", { name: /SQL injection/ })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /reopened/ }));
    expect(screen.queryByRole("link", { name: /SQL injection/ })).not.toBeInTheDocument();
    expect(screen.getByText("No reopened findings")).toBeInTheDocument();
  });
});
