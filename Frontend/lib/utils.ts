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
        bg: "bg-red-50",
        text: "text-red-700",
        border: "border-red-200",
        dot: "bg-red-600",
      };
    case "HIGH":
      return {
        bg: "bg-amber-50",
        text: "text-amber-800",
        border: "border-amber-200",
        dot: "bg-amber-600",
      };
    case "MEDIUM":
      return {
        bg: "bg-[#EAF8F5]",
        text: "text-[#02353C]",
        border: "border-[#D5EAE5]",
        dot: "bg-[#3FD0C9]",
      };
    case "LOW":
    default:
      return {
        bg: "bg-[#F2FBF9]",
        text: "text-[#486966]",
        border: "border-[#D5EAE5]",
        dot: "bg-[#2EAF7D]",
      };
  }
}

export function getActionStyle(action: string | null | undefined) {
  const a = (action || "").toUpperCase();
  switch (a) {
    case "BLOCK":
      return {
        bg: "bg-red-50",
        text: "text-red-700 font-bold",
        border: "border-red-200",
        glow: "",
      };
    case "THROTTLE":
      return {
        bg: "bg-amber-50",
        text: "text-amber-800 font-semibold",
        border: "border-amber-200",
        glow: "",
      };
    case "MONITOR":
      return {
        bg: "bg-[#EAF8F5]",
        text: "text-[#02353C] font-medium",
        border: "border-[#D5EAE5]",
        glow: "",
      };
    case "ALLOW":
    default:
      return {
        bg: "bg-emerald-50",
        text: "text-emerald-800 font-medium",
        border: "border-emerald-200",
        glow: "",
      };
  }
}

