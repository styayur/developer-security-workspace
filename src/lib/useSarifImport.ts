import { useMutation } from "@tanstack/react-query";
import { listen } from "@tauri-apps/api/event";
import { useEffect, useRef, useState } from "react";
import { api, pickSarifFile } from "./api";
import type { ImportResult, Project } from "../types/domain";

export interface ImportProgress { importId: string; phase: string; processed: number; total?: number }
export function useSarifImport(onSuccess: (result: ImportResult) => Promise<void>, project?: Project) {
  const active = useRef<string | undefined>(undefined);
  const mounted = useRef(true);
  const [progress, setProgress] = useState<ImportProgress>();
  const [cancelling, setCancelling] = useState(false);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; if (active.current) void api.cancelImport(active.current); };
  }, []);
  const mutation = useMutation({
    mutationFn: async () => {
      const path = await pickSarifFile();
      if (!path) return null;
      if (!mounted.current) return null;
      let id: string | undefined;
      let unlisten: (() => void) | undefined;
      try {
        unlisten = await listen<ImportProgress>("import://progress", ({ payload }) => {
          if (payload.importId === id) setProgress(payload);
        });
        if (!mounted.current) return null;
        id = await api.prepareImport();
        active.current = id;
        if (!mounted.current) await api.cancelImport(id);
        setCancelling(false);
        setProgress({ importId: id, phase: "parsing", processed: 0 });
        return await api.importSarif(path, project?.id, project?.path, id);
      } finally {
        unlisten?.();
        active.current = undefined;
        setProgress(undefined);
        setCancelling(false);
      }
    },
    onSuccess: async (result) => { if (result) await onSuccess(result); },
  });
  const cancel = async () => {
    if (active.current) { setCancelling(true); await api.cancelImport(active.current); }
  };
  return { ...mutation, progress, cancelling, cancel };
}
