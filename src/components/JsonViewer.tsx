import { ChevronDown, ChevronRight, Copy, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Button, Input } from "./ui";

export function JsonViewer({ value, searchable = true, defaultExpanded = true }: { value: unknown; searchable?: boolean; defaultExpanded?: boolean }) {
  const [query, setQuery] = useState("");
  const text = useMemo(() => JSON.stringify(value, null, 2), [value]);
  const copy = () => navigator.clipboard.writeText(text);
  const matches = query && text.toLowerCase().includes(query.toLowerCase());
  return <div className="json-viewer"><div className="json-toolbar">{searchable ? <label className="search-field"><Search size={14} /><Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search this result" /></label> : <span />}{matches ? <span className="match-note">Match found</span> : null}<Button variant="ghost" onClick={copy}><Copy size={14} />Copy JSON</Button></div><JsonNode value={value} name="root" depth={0} defaultExpanded={defaultExpanded} query={query} /></div>;
}

function JsonNode({ value, name, depth, defaultExpanded, query }: { value: unknown; name: string; depth: number; defaultExpanded: boolean; query: string }) {
  const isContainer = value !== null && typeof value === "object";
  const [open, setOpen] = useState(defaultExpanded && depth < 3);
  if (query && JSON.stringify(value)?.toLowerCase().includes(query.toLowerCase())) { if (!open && depth < 5) setTimeout(() => setOpen(true), 0); }
  if (!isContainer) return <div className="json-row" style={{ paddingLeft: depth * 14 }}><span className="json-key">{name}:</span><span className={"json-value json-" + typeof value}>{JSON.stringify(value)}</span></div>;
  const entries = Array.isArray(value) ? value.map((item, index) => [String(index), item] as const) : Object.entries(value as Record<string, unknown>);
  return <div className="json-branch"><button className="json-toggle" style={{ paddingLeft: depth * 14 }} onClick={() => setOpen((current) => !current)}>{open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}<span>{name}</span><span className="json-count">{Array.isArray(value) ? "[ " + entries.length + " ]" : "{ " + entries.length + " }"}</span></button>{open ? <div>{entries.map(([key, item]) => <JsonNode key={key} name={key} value={item} depth={depth + 1} defaultExpanded={defaultExpanded} query={query} />)}</div> : null}</div>;
}
