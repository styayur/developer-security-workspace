import { ArrowDown, ArrowLeft, ArrowRight, CornerDownLeft, CornerUpRight, HelpCircle, LogIn, ShieldCheck, Target } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { CodeFlow, FindingLocation, TraceStepKind } from "../types/domain";
import { Button, EmptyState } from "./ui";

const kinds = {
  source: { label: "Source", Icon: LogIn }, propagation: { label: "Propagation", Icon: ArrowRight },
  sanitizer: { label: "Sanitizer", Icon: ShieldCheck }, sink: { label: "Sink", Icon: Target },
  call: { label: "Call", Icon: CornerDownLeft }, return: { label: "Return", Icon: CornerUpRight },
  unknown: { label: "Unknown", Icon: HelpCircle },
} satisfies Record<TraceStepKind, { label: string; Icon: typeof LogIn }>;

export function TraceDebugger({ flows, onSelect }: { flows: CodeFlow[]; onSelect: (location: FindingLocation) => void }) {
  const paths = useMemo(() => flows.flatMap((flow, fi) => flow.threadFlows.map((thread, ti) => ({
    key: `${fi}:${ti}`, label: `Flow ${fi + 1} · ${thread.id ?? `Thread ${ti + 1}`}`, thread,
  }))), [flows]);
  const [pathIndex, setPathIndex] = useState(0);
  const [stepIndex, setStepIndex] = useState(0);
  const path = paths[pathIndex];
  const steps = path?.thread.steps ?? [];
  useEffect(() => { setPathIndex(0); setStepIndex(0); }, [flows]);
  const select = (index: number) => { if (steps[index]) { setStepIndex(index); onSelect(steps[index].location); } };
  useEffect(() => { if (paths[0]?.thread.steps[0]) onSelect(paths[0].thread.steps[0].location); }, [paths, onSelect]);
  if (!paths.length) return <EmptyState title="No execution/data-flow trace" description="This scanner did not provide a trace." />;
  return <section aria-label="Trace debugger" tabIndex={0} onKeyDown={(event) => {
    if ((event.target as HTMLElement).tagName === "SELECT") return;
    if (["ArrowDown", "ArrowRight", "ArrowUp", "ArrowLeft", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      select(event.key === "Home" ? 0 : event.key === "End" ? steps.length - 1 : Math.max(0, Math.min(steps.length - 1, stepIndex + (["ArrowDown", "ArrowRight"].includes(event.key) ? 1 : -1))));
    }
  }}>
    <label className="trace-path">Trace path <select aria-label="Thread flow" value={pathIndex} onChange={(event) => {
      const next = Number(event.target.value); setPathIndex(next); setStepIndex(0);
      const first = paths[next].thread.steps[0]; if (first) onSelect(first.location);
    }}>{paths.map((item, index) => <option key={item.key} value={index}>{item.label}</option>)}</select></label>
    <p className="muted-copy">{path?.thread.message ?? path?.label} · Arrow keys to step</p>
    <div className="trace-controls"><Button disabled={stepIndex === 0 || !steps.length} onClick={() => select(stepIndex - 1)}><ArrowLeft size={14} />Previous step</Button><span aria-live="polite">Step {steps.length ? stepIndex + 1 : 0} / {steps.length}</span><Button disabled={stepIndex >= steps.length - 1} onClick={() => select(stepIndex + 1)}>Next step<ArrowDown size={14} /></Button></div>
    <div className="trace-steps">{steps.map((step, index) => {
      const { Icon, label } = kinds[step.kind ?? "unknown"];
      return <button key={index} aria-current={index === stepIndex ? "step" : undefined} className={`trace-step ${index === stepIndex ? "active" : ""}`} onClick={() => select(index)}>
        <span className="trace-index">{index + 1}</span><Icon size={15} /><span><strong>{label}</strong><small>{step.location.filePath}:{step.location.region.startLine}</small>{step.message && <small>{step.message}</small>}</span>
      </button>;
    })}</div>
  </section>;
}
