import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatNumber(val: number | null | undefined): string {
  if (val === null || val === undefined) return "—";
  return new Intl.NumberFormat("en-US").format(val);
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return iso;
  }
}

export function formatTimeAgo(date: Date | null): string {
  if (!date) return "never";
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

export function getSeverityStyle(band: string | null | undefined) {
  const b = (band || "").toUpperCase();
  switch (b) {
    case "CRITICAL":
      return {
        bg: "bg-red-500/10",
        text: "text-red-400",
        border: "border-red-500/30",
        dot: "bg-red-500",
      };
    case "HIGH":
      return {
        bg: "bg-orange-500/10",
        text: "text-orange-400",
        border: "border-orange-500/30",
        dot: "bg-orange-500",
      };
    case "MEDIUM":
      return {
        bg: "bg-amber-500/10",
        text: "text-amber-300",
        border: "border-amber-500/30",
        dot: "bg-amber-400",
      };
    case "LOW":
    default:
      return {
        bg: "bg-emerald-500/10",
        text: "text-emerald-400",
        border: "border-emerald-500/30",
        dot: "bg-emerald-400",
      };
  }
}

export function getActionStyle(action: string | null | undefined) {
  const a = (action || "").toUpperCase();
  switch (a) {
    case "BLOCK":
      return {
        bg: "bg-red-950/40",
        text: "text-red-400 font-bold",
        border: "border-red-600/40",
        glow: "shadow-[0_0_12px_rgba(239,68,68,0.25)]",
      };
    case "THROTTLE":
      return {
        bg: "bg-orange-950/40",
        text: "text-orange-400 font-semibold",
        border: "border-orange-500/40",
        glow: "shadow-[0_0_12px_rgba(249,115,22,0.2)]",
      };
    case "MONITOR":
      return {
        bg: "bg-amber-950/40",
        text: "text-amber-300 font-medium",
        border: "border-amber-500/40",
        glow: "shadow-[0_0_12px_rgba(245,158,11,0.2)]",
      };
    case "ALLOW":
    default:
      return {
        bg: "bg-emerald-950/30",
        text: "text-emerald-400 font-medium",
        border: "border-emerald-500/30",
        glow: "shadow-[0_0_12px_rgba(34,197,94,0.15)]",
      };
  }
}
