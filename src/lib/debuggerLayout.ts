const LEGACY_KEY = "react-resizable-panels:dsw-finding-debugger";
export const DEBUGGER_LAYOUT_KEY = `${LEGACY_KEY}:source:inspector`;
type StorageAccess = Pick<Storage, "getItem" | "setItem">;

function validSizes(values: unknown): values is [number, number] {
  return Array.isArray(values) && values.length === 2 &&
    values.every(value => typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100) &&
    Math.abs(values[0] + values[1] - 100) < 0.01;
}

/** Preserve v3's constraint-keyed layout without deleting or rewriting it. */
export function createDebuggerLayoutStorage(storage: StorageAccess = {
  getItem: key => localStorage.getItem(key),
  setItem: (key, value) => localStorage.setItem(key, value),
}): StorageAccess {
  return {
    getItem(key) {
      try {
        const existing = storage.getItem(key);
        if (key !== DEBUGGER_LAYOUT_KEY) return existing;
        if (existing) {
          try {
            const layout = JSON.parse(existing);
            if (layout && Object.keys(layout).sort().join(",") === "inspector,source" && validSizes([layout.source, layout.inspector])) return existing;
          } catch { /* A corrupt preference must not break the finding page. */ }
        }
        const legacy = JSON.parse(storage.getItem(LEGACY_KEY) ?? "null");
        if (!legacy || typeof legacy !== "object") return null;
        for (const [constraints, state] of Object.entries(legacy)) {
          if (!["\"defaultSize\":62", "\"minSize\":35", "\"defaultSize\":38", "\"minSize\":28"].every(token => constraints.includes(token))) continue;
          const sizes = (state as { layout?: unknown } | null)?.layout;
          if (validSizes(sizes)) return JSON.stringify({ source: sizes[0], inspector: sizes[1] });
        }
      } catch { /* Storage can be unavailable in a restricted WebView. */ }
      return null;
    },
    setItem(key, value) {
      try { storage.setItem(key, value); } catch { /* Layout persistence is best effort. */ }
    },
  };
}

export const debuggerLayoutStorage = createDebuggerLayoutStorage();
