import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
export function cn(...inputs: ClassValue[]) { return twMerge(clsx(inputs)); }
export function formatDuration(milliseconds?: number) {
  if (milliseconds == null) return "—";
  if (milliseconds < 1000) return milliseconds + "ms";
  if (milliseconds < 60_000) return (milliseconds / 1000).toFixed(1) + "s";
  return Math.floor(milliseconds / 60_000) + "m " + Math.round((milliseconds % 60_000) / 1000) + "s";
}
export function formatTimestamp(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}
export function shortenCommit(commit?: string) { return commit ? commit.slice(0, 7) : "no commit"; }
export function errorMessage(error: unknown) {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return "Unexpected error";
}
