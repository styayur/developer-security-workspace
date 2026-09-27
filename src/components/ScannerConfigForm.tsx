import type { ScannerConfigField } from "../types/domain";
import { Input } from "./ui";

/** Presentation consumes provider-owned configuration metadata, never scanner IDs. */
export function ScannerConfigForm({ fields, values, onChange }: { fields: ScannerConfigField[]; values: Record<string, unknown>; onChange: (values: Record<string, unknown>) => void }) {
  return <>{fields.map((field) => {
    const value = values[field.key] ?? field.defaultValue;
    const strings = Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
    const update = (next: unknown) => onChange({ ...values, [field.key]: next });
    return <div className="scanner-config" key={field.key}>
      {field.kind === "boolean" ? <label className="inline-check"><input type="checkbox" checked={value === true} onChange={(event) => update(event.target.checked)} />{field.label}</label>
        : field.kind === "multi_select" ? <><span>{field.label}</span><div className="check-row">{field.options.map((option) => <label key={option}><input type="checkbox" checked={strings.includes(option)} onChange={(event) => update(event.target.checked ? [...strings, option] : strings.filter((item) => item !== option))} />{option}</label>)}</div></>
          : <label><span>{field.label}</span><Input value={field.kind === "arguments" ? strings.join(" ") : String(value ?? "")} onChange={(event) => update(field.kind === "arguments" ? event.target.value.split(/\s+/).filter(Boolean) : event.target.value)} /></label>}
      {field.help && <p>{field.help}</p>}
    </div>;
  })}</>;
}
