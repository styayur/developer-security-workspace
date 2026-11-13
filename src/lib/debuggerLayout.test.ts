import { describe, expect, it } from "vitest";
import { createDebuggerLayoutStorage, DEBUGGER_LAYOUT_KEY } from "./debuggerLayout";

const legacyKey = "react-resizable-panels:dsw-finding-debugger";
const constraints = [{ defaultSize: 62, minSize: 35 }, { defaultSize: 38, minSize: 28 }].map(value => JSON.stringify(value)).sort().join(",");

function setup(entries: [string, string][] = []) {
  const values = new Map(entries);
  const adapter = createDebuggerLayoutStorage({ getItem: key => values.get(key) ?? null, setItem: (key, value) => { values.set(key, value); } });
  return { values, adapter };
}

describe("debugger layout preference compatibility", () => {
  it("recovers the actual v3 constraint-keyed layout without changing its bytes", () => {
    const original = JSON.stringify({ [constraints]: { layout: [58, 42], expandToSizes: {} } });
    const { values, adapter } = setup([[legacyKey, original]]);
    expect(JSON.parse(adapter.getItem(DEBUGGER_LAYOUT_KEY)!)).toEqual({ source: 58, inspector: 42 });
    expect(values.size).toBe(1);
    adapter.setItem(DEBUGGER_LAYOUT_KEY, JSON.stringify({ source: 55, inspector: 45 }));
    expect(values.get(legacyKey)).toBe(original);
    expect(JSON.parse(adapter.getItem(DEBUGGER_LAYOUT_KEY)!)).toEqual({ source: 55, inspector: 45 });
  });
  it("uses valid v4 state ahead of legacy state", () => {
    const current = JSON.stringify({ source: 60, inspector: 40 });
    const { adapter } = setup([[DEBUGGER_LAYOUT_KEY, current], [legacyKey, "not json"]]);
    expect(adapter.getItem(DEBUGGER_LAYOUT_KEY)).toBe(current);
  });
  it.each(["bad json", "null", JSON.stringify({ source: -1, inspector: 101 }), JSON.stringify({ source: 20, inspector: 20 })])("ignores a corrupt preference %s", value => {
    const { adapter } = setup([[DEBUGGER_LAYOUT_KEY, value]]);
    expect(adapter.getItem(DEBUGGER_LAYOUT_KEY)).toBeNull();
  });
  it("does not reinterpret another legacy group or change unrelated storage", () => {
    const { adapter, values } = setup([[legacyKey, JSON.stringify({ unrelated: { layout: [58, 42] } })], ["unrelated", "keep"]]);
    expect(adapter.getItem(DEBUGGER_LAYOUT_KEY)).toBeNull();
    expect(adapter.getItem("unrelated")).toBe("keep");
    expect(values.size).toBe(2);
  });
});
