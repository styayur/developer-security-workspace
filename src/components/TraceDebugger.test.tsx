import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { TraceDebugger } from "./TraceDebugger";
import type { CodeFlow, TraceStep } from "../types/domain";

const step = (index: number, filePath: string, kind: TraceStep["kind"]): TraceStep => ({ index, label: kind, kind, nestingLevel: 0, location: { filePath, logicalLocations: [], region: { startLine: index, endLine: index, startColumn: 1, endColumn: 10 } } });
const flows: CodeFlow[] = [{ threadFlows: [{ id: "primary", steps: [step(1, "input.ts", "source"), step(2, "sink.ts", "sink")] }, { id: "separate", steps: [step(1, "other.ts", "unknown")] }] }];

describe("trace debugger", () => {
  it("links cross-file steps, previous/next, and keyboard navigation", async () => {
    const user = userEvent.setup(); const onSelect = vi.fn();
    render(<TraceDebugger flows={flows} onSelect={onSelect} />);
    expect(screen.getByText("Step 1 / 2")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Previous step/ })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: /Next step/ }));
    expect(onSelect.mock.lastCall?.[0].filePath).toBe("sink.ts");
    expect(screen.getByText("Step 2 / 2")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Previous step/ }));
    expect(onSelect.mock.lastCall?.[0].filePath).toBe("input.ts");
    screen.getByRole("region", { name: "Trace debugger" }).focus();
    await user.keyboard("{ArrowRight}");
    expect(onSelect.mock.lastCall?.[0].filePath).toBe("sink.ts");
    expect(screen.getByRole("button", { name: /Next step/ })).toBeDisabled();
  });
  it("keeps independent thread flows separate, with neutral Unknown labels", async () => {
    const user = userEvent.setup(); const onSelect = vi.fn();
    render(<TraceDebugger flows={flows} onSelect={onSelect} />);
    await user.selectOptions(screen.getByRole("combobox", { name: "Thread flow" }), "1");
    expect(screen.getByText("Step 1 / 1")).toBeInTheDocument();
    expect(screen.queryByText("Sink")).not.toBeInTheDocument();
    expect(screen.getByText("Unknown")).toBeInTheDocument();
    expect(onSelect.mock.lastCall?.[0].filePath).toBe("other.ts");
  });
});
