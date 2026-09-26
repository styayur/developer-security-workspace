import { useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Filter, RotateCcw, Search, ShieldCheck } from "lucide-react";
import { useDeferredValue, useEffect, useRef, useState } from "react";
import { useOutletContext, useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import { emptyFilters } from "../lib/filters";
import { cn } from "../lib/utils";
import { useAppStore } from "../stores/app";
import type { FindingCategory, FindingFilters, FindingStatus, Project, Severity } from "../types/domain";
import { FindingRow } from "../components/FindingRow";
import { Button, EmptyState, ErrorState, Input, Panel, Spinner } from "../components/ui";

const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
const categories: FindingCategory[] = ["sast", "secrets", "sca", "iac", "container", "license", "misconfiguration", "unknown"];
const statuses: FindingStatus[] = ["new", "existing", "fixed", "confirmed", "false_positive", "accepted_risk", "ignored", "reopened"];

export function FindingsPage() {
  const project = useOutletContext<Project>();
  const [params] = useSearchParams();
  const stored = useAppStore((state) => state.filters);
  const setStored = useAppStore((state) => state.setFilters);
  const [filters, setFilters] = useState<FindingFilters>(() => stored?.projectId === project.id ? stored : emptyFilters(project.id));
  const [search, setSearch] = useState(params.get("q") ?? filters.search ?? "");
  const deferredSearch = useDeferredValue(search);
  const scrollRef = useRef<HTMLDivElement>(null);
  useEffect(() => { setFilters((current) => ({ ...current, projectId: project.id, search: deferredSearch })); }, [deferredSearch, project.id]);
  useEffect(() => { setStored(filters); }, [filters, setStored]);
  const query = useQuery({ queryKey: ["findings", project.id, filters], queryFn: () => api.listFindings(filters) });
  const scannerOptions = useQuery({ queryKey: ["findings", project.id, "scanner-options"], queryFn: () => api.listFindings(emptyFilters(project.id)) });
  const data = query.data ?? [];
  const virtualizer = useVirtualizer({ count: data.length, getScrollElement: () => scrollRef.current, estimateSize: () => 78, overscan: 10 });
  const update = <K extends keyof FindingFilters>(key: K, value: FindingFilters[K]) => setFilters((current) => ({ ...current, [key]: value }));
  const toggle = <T,>(key: "severities" | "categories" | "statuses", value: T) => {
    const current = filters[key] as T[];
    update(key, (current.includes(value) ? current.filter((item) => item !== value) : [...current, value]) as never);
  };
  const reset = () => { const next = emptyFilters(project.id); setSearch(""); setFilters(next); };
  return (
    <div className="page findings-page">
      <header className="page-header"><div><span className="eyebrow">Security inbox</span><h1>Findings</h1><p>Search, filter, and open every normalized finding in the active project.</p></div><span className="result-count">{data.length.toLocaleString()} results</span></header>
      <Panel className="filters-panel">
        <div className="filter-main">
          <label className="search-field filter-search"><Search size={15} /><Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search title, message, rule, file, or scanner" /></label>
          <div className="filter-severities">{severities.map((severity) => <button key={severity} className={cn("filter-pill", "severity-" + severity, filters.severities.includes(severity) && "active")} onClick={() => toggle("severities", severity)}><span>{severity[0].toUpperCase()}</span>{severity}</button>)}</div>
          <Button variant="ghost" onClick={reset}><RotateCcw size={14} />Reset</Button>
        </div>
        <div className="filter-secondary"><span><Filter size={13} />Filter</span>
          <label><span>Scanner</span><select value={filters.scanners[0] ?? ""} onChange={(event) => update("scanners", event.target.value ? [event.target.value] : [])}><option value="">All scanners</option>{[...new Set((scannerOptions.data ?? []).map((finding) => finding.scannerId))].map((scanner) => <option key={scanner} value={scanner}>{scanner}</option>)}</select></label>
          <label><span>Category</span><select value={filters.categories[0] ?? ""} onChange={(event) => update("categories", event.target.value ? [event.target.value as FindingCategory] : [])}><option value="">All categories</option>{categories.map((category) => <option key={category} value={category}>{category}</option>)}</select></label>
          <label><span>Status</span><select value={filters.statuses[0] ?? ""} onChange={(event) => update("statuses", event.target.value ? [event.target.value as FindingStatus] : [])}><option value="">All statuses</option>{statuses.map((status) => <option key={status} value={status}>{status.replaceAll("_", " ")}</option>)}</select></label>
          <label className="file-filter"><span>File</span><Input value={filters.filePath ?? ""} onChange={(event) => update("filePath", event.target.value || undefined)} placeholder="src/…" /></label><label className="file-filter"><span>CWE</span><Input value={filters.cwe ?? ""} onChange={(event) => update("cwe", event.target.value || undefined)} placeholder="CWE-89" /></label><label className="file-filter"><span>Rule</span><Input value={filters.ruleId ?? ""} onChange={(event) => update("ruleId", event.target.value || undefined)} placeholder="rule id" /></label>
        </div>
      </Panel>
      {query.isLoading ? <div className="page-loading"><Spinner label="Loading findings…" /></div> : query.error ? <ErrorState error={query.error} /> : data.length === 0 ? <EmptyState icon={<ShieldCheck size={25} />} title={query.data?.length ? "No findings match these filters" : "No findings in this project"} description={query.data?.length ? "Adjust or reset the filters to widen the result set." : "Run a scanner, import SARIF, or open the Demo Workspace."} action={<Button onClick={reset}>Reset filters</Button>} /> : <Panel className="findings-table"><div className="findings-heading"><span>Severity</span><span>Finding</span></div><div ref={scrollRef} className="virtual-scroll"><div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>{virtualizer.getVirtualItems().map((virtualRow) => { const finding = data[virtualRow.index]; return <div key={finding.id} style={{ position: "absolute", top: 0, left: 0, width: "100%", transform: "translateY(" + virtualRow.start + "px)" }}><FindingRow finding={finding} projectId={project.id} /></div>; })}</div></div></Panel>}
    </div>
  );
}
