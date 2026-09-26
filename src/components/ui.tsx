import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { LoaderCircle, ShieldAlert } from "lucide-react";
import type { ButtonHTMLAttributes, HTMLAttributes, InputHTMLAttributes, ReactNode } from "react";
import type { FindingStatus, Severity } from "../types/domain";
import { cn } from "../lib/utils";

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";
export function Button({ variant = "secondary", className, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return <button className={cn("button", "button-" + variant, className)} {...props} />;
}

export function IconButton({ label, className, children, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { label: string; children: ReactNode }) {
  return <Tooltip content={label}><button aria-label={label} className={cn("icon-button", className)} {...props}>{children}</button></Tooltip>;
}

export function Tooltip({ content, children, side = "bottom" }: { content: string; children: ReactNode; side?: "top" | "bottom" | "left" | "right" }) {
  return <TooltipPrimitive.Root><TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger><TooltipPrimitive.Portal><TooltipPrimitive.Content className="tooltip" side={side} sideOffset={6}>{content}<TooltipPrimitive.Arrow className="fill-elevated" /></TooltipPrimitive.Content></TooltipPrimitive.Portal></TooltipPrimitive.Root>;
}

export function Badge({ children, tone = "neutral", className }: { children: ReactNode; tone?: "neutral" | "accent" | "danger" | "warning" | "success" | "muted"; className?: string }) {
  return <span className={cn("badge", "badge-" + tone, className)}>{children}</span>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const marker = { critical: "●", high: "▲", medium: "◆", low: "•", info: "·" }[severity];
  return <span className={cn("severity", "severity-" + severity)}><span aria-hidden>{marker}</span>{severity.toUpperCase()}</span>;
}

export function StatusBadge({ status }: { status: FindingStatus }) {
  const tone = status === "confirmed" ? "success" : status === "false_positive" || status === "ignored" ? "muted" : status === "accepted_risk" ? "warning" : "neutral";
  return <Badge tone={tone}>{status.replaceAll("_", " ")}</Badge>;
}

export function Panel({ className, ...props }: HTMLAttributes<HTMLDivElement>) { return <section className={cn("panel", className)} {...props} />; }
export function PanelHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return <header className="panel-header"><div><h2>{title}</h2>{subtitle ? <p>{subtitle}</p> : null}</div>{actions ? <div className="panel-actions">{actions}</div> : null}</header>;
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return <label className="field"><span className="field-label">{label}</span>{children}{hint ? <span className="field-hint">{hint}</span> : null}</label>;
}

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) { return <input className={cn("input", className)} {...props} />; }

export function EmptyState({ icon, title, description, action }: { icon?: ReactNode; title: string; description: string; action?: ReactNode }) {
  return <div className="empty-state">{icon ?? <ShieldAlert size={24} />}<h3>{title}</h3><p>{description}</p>{action}</div>;
}

export function ErrorState({ error }: { error: unknown }) {
  const message = typeof error === "string" ? error : error instanceof Error ? error.message : "Unexpected error";
  return <div className="error-state"><strong>Unable to load this view.</strong><span>{message}</span></div>;
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return <span className="spinner"><LoaderCircle size={16} className="animate-spin" />{label}</span>;
}

export function Metric({ label, value, detail, tone }: { label: string; value: ReactNode; detail?: ReactNode; tone?: string }) {
  return <div className="metric"><span className="metric-label">{label}</span><strong className={cn(tone)}>{value}</strong>{detail ? <span className="metric-detail">{detail}</span> : null}</div>;
}
