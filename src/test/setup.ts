import "@testing-library/jest-dom/vitest";
const entries = new Map<string, string>();
const storage: Storage = {
  get length() { return entries.size; }, clear: () => entries.clear(),
  getItem: (key) => entries.get(key) ?? null, key: (index) => [...entries.keys()][index] ?? null,
  removeItem: (key) => { entries.delete(key); }, setItem: (key, value) => { entries.set(key, value); },
};
Object.defineProperty(globalThis, "localStorage", { value: storage, configurable: true });
// jsdom has no layout engine or ResizeObserver. Browser acceptance separately
// exercises real separator geometry, pointer/keyboard input and persistence.
class TestResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
Object.defineProperty(window, "ResizeObserver", { value: TestResizeObserver, configurable: true });
