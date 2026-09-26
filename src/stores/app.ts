import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { FindingFilters } from "../types/domain";
export type Theme = "dark" | "light" | "system";
interface AppStore {
  activeProjectId?: string; theme: Theme; sidebarCollapsed: boolean; inspectorCollapsed: boolean; commandOpen: boolean; filters?: FindingFilters;
  setActiveProject: (projectId?: string) => void; setTheme: (theme: Theme) => void; toggleSidebar: () => void; toggleInspector: () => void;
  setCommandOpen: (open: boolean) => void; setFilters: (filters?: FindingFilters) => void;
}
export const useAppStore = create<AppStore>()(persist(
  (set) => ({
    theme: "dark", sidebarCollapsed: false, inspectorCollapsed: false, commandOpen: false,
    setActiveProject: (activeProjectId) => set({ activeProjectId, filters: undefined }), setTheme: (theme) => set({ theme }),
    toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
    toggleInspector: () => set((state) => ({ inspectorCollapsed: !state.inspectorCollapsed })),
    setCommandOpen: (commandOpen) => set({ commandOpen }), setFilters: (filters) => set({ filters }),
  }),
  { name: "dsw-ui", partialize: (state) => ({ activeProjectId: state.activeProjectId, theme: state.theme, sidebarCollapsed: state.sidebarCollapsed, inspectorCollapsed: state.inspectorCollapsed }) },
));
