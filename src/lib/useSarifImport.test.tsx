import { act, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { useSarifImport } from "./useSarifImport";
const mocks = vi.hoisted(() => ({
  pick: vi.fn(), prepare: vi.fn(), cancel: vi.fn(), run: vi.fn(), listen: vi.fn(), unlisten: vi.fn(),
}));
vi.mock("./api", () => ({ api: { prepareImport: mocks.prepare, cancelImport: mocks.cancel, importSarif: mocks.run }, pickSarifFile: mocks.pick }));
vi.mock("@tauri-apps/api/event", () => ({ listen: mocks.listen }));
function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={new QueryClient({ defaultOptions: { mutations: { retry: false } } })}>{children}</QueryClientProvider>;
}
beforeEach(() => {
  vi.resetAllMocks(); mocks.pick.mockResolvedValue("report.sarif"); mocks.prepare.mockResolvedValue("id");
  mocks.cancel.mockResolvedValue(undefined); mocks.listen.mockResolvedValue(mocks.unlisten);
});
it("filters progress by import id, cancels the active worker, and removes the listener", async () => {
  let reject!: (e: Error) => void;
  mocks.run.mockImplementation(() => new Promise((_, no) => { reject = no; }));
  const success = vi.fn();
  const { result } = renderHook(() => useSarifImport(success), { wrapper });
  act(() => result.current.mutate());
  await waitFor(() => expect(mocks.run).toHaveBeenCalled());
  const event = mocks.listen.mock.calls[0][1];
  act(() => event({ payload: { importId: "other", phase: "completed", processed: 999 } }));
  expect(result.current.progress?.processed).toBe(0);
  act(() => event({ payload: { importId: "id", phase: "committing", processed: 256 } }));
  expect(result.current.progress?.processed).toBe(256);
  await act(() => result.current.cancel());
  expect(mocks.cancel).toHaveBeenCalledWith("id");
  act(() => reject(new Error("Import cancelled")));
  await waitFor(() => expect(result.current.isError).toBe(true));
  expect(success).not.toHaveBeenCalled();
  expect(mocks.unlisten).toHaveBeenCalledOnce();
  expect(result.current.progress).toBeUndefined();
});
it("does not allocate a cancellation token if the event listener fails", async () => {
  mocks.listen.mockRejectedValue(new Error("Unavailable"));
  const { result } = renderHook(() => useSarifImport(vi.fn()), { wrapper });
  act(() => result.current.mutate());
  await waitFor(() => expect(result.current.isError).toBe(true));
  expect(mocks.prepare).not.toHaveBeenCalled();
  expect(mocks.run).not.toHaveBeenCalled();
});
