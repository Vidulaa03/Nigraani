"use client";

import React, { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  ShieldAlert,
  Brain,
  Activity,
  Search,
  Server,
  Shield,
  CircleDot,
  X,
  PhoneCall,
  Gauge,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { SystemHealth } from "@/lib/types";

interface SidebarProps {
  health: SystemHealth | null;
  backendOnline: boolean;
  backendChecking?: boolean;
  mobileOpen?: boolean;
  onNavigate?: () => void;
}

const NAV_ITEMS = [
  {
    name: "Command Center",
    href: "/",
    icon: LayoutDashboard,
  },
  {
    name: "Threat Intelligence",
    href: "/threats",
    icon: ShieldAlert,
  },
  {
    name: "Call Alerts",
    href: "/calls",
    icon: PhoneCall,
  },
  {
    name: "Rate Analysis",
    href: "/rate-analysis",
    icon: Gauge,
  },
  {
    name: "ML Behavior",
    href: "/ml",
    icon: Brain,
  },
  {
    name: "API Traffic",
    href: "/traffic",
    icon: Activity,
  },
  {
    name: "Investigate",
    href: "/investigate",
    icon: Search,
  },
  {
    name: "Monitoring",
    href: "/monitoring",
    icon: Server,
  },
];


export function Sidebar({ health, backendOnline, backendChecking = false, mobileOpen = false, onNavigate }: SidebarProps) {
  const pathname = usePathname();
  const sidebarRef = useRef<HTMLElement>(null);
  const [mobileViewport, setMobileViewport] = useState(false);

  useEffect(() => {
    const media = window.matchMedia("(max-width: 767px)");
    const updateViewport = () => setMobileViewport(media.matches);
    updateViewport();
    media.addEventListener("change", updateViewport);
    return () => media.removeEventListener("change", updateViewport);
  }, []);

  useEffect(() => {
    if (!mobileViewport || !mobileOpen) return;
    const sidebar = sidebarRef.current;
    const links = sidebar?.querySelectorAll<HTMLElement>("a, button");
    links?.[1]?.focus();
    const keepFocusInside = (event: KeyboardEvent) => {
      if (event.key !== "Tab" || !links?.length) return;
      const first = links[0];
      const last = links[links.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    sidebar?.addEventListener("keydown", keepFocusInside);
    return () => sidebar?.removeEventListener("keydown", keepFocusInside);
  }, [mobileOpen, mobileViewport]);

  const isDbOk = health?.database?.status === "connected";
  const isMlOk = health?.ml_engine?.status === "healthy";

  return (
    <>
    {mobileOpen && <button aria-label="Close navigation" onClick={onNavigate} className="fixed inset-0 z-30 bg-stone-950/35 backdrop-blur-[2px] md:hidden" />}
    <aside ref={sidebarRef} aria-hidden={mobileViewport && !mobileOpen} {...(mobileViewport && !mobileOpen ? { inert: "" as unknown as boolean } : {})} className={`fixed inset-y-0 left-0 z-40 flex min-h-screen w-64 shrink-0 select-none flex-col border-r border-[#D5EAE5] bg-white transition-transform duration-200 md:sticky md:top-0 md:z-20 md:translate-x-0 ${mobileOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"}`}>
      {/* Brand Header */}
      <div className="p-5 pb-4 border-b border-[#D5EAE5]">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-[4px] bg-[#EAF8F5] border border-[#D5EAE5] flex items-center justify-center text-[#2EAF7D] shrink-0">
            <Shield className="w-5 h-5 text-[#2EAF7D]" />
          </div>
          <div>
            <div className="text-base font-black tracking-wider text-[#02353C] font-sans flex items-center gap-1.5 leading-none">
              NIGRAANI
            </div>
            <div className="text-[10px] uppercase font-sans tracking-widest text-[#486966] mt-1">
              API Security Platform
            </div>
          </div>
          <button className="ml-auto rounded-[2px] p-2 text-[#486966] hover:bg-[#F2FBF9] md:hidden" onClick={onNavigate} aria-label="Close navigation"><X className="h-4 w-4" /></button>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="px-3 pb-2 text-[10px] font-sans uppercase tracking-wider text-[#486966]">
          Security Operations Deck
        </div>
        {NAV_ITEMS.map((item) => {
          const isActive =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);

          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              onClick={onNavigate}
              className={cn(
                "flex items-center gap-3 px-3 py-2 rounded-[2px] text-xs font-sans transition-all duration-150 group",
                isActive
                  ? "bg-[#EAF8F5] text-[#02353C] font-semibold border border-[#D5EAE5]"
                  : "text-[#486966] hover:text-[#02353C] hover:bg-[#F2FBF9] border border-transparent"
              )}
            >
              <Icon
                className={cn(
                  "w-4 h-4 shrink-0 transition-colors",
                  isActive
                    ? "text-[#2EAF7D]"
                    : "text-[#486966] group-hover:text-[#02353C]"
                )}
              />
              <span className="truncate">{item.name}</span>
            </Link>
          );
        })}
      </nav>

      {/* Live System Health Section at bottom */}
      <div className="p-4 border-t border-[#D5EAE5] bg-[#F2FBF9]">
        <div className="text-[10px] font-sans uppercase tracking-wider text-[#486966] mb-3 flex items-center justify-between">
          <span>Engine Status</span>
          <CircleDot className="w-3 h-3 text-[#2EAF7D]" />
        </div>

        <div className="space-y-2 text-xs font-sans">
          {/* Backend Status */}
          <div className="flex items-center justify-between">
            <span className="text-[#486966]">Backend API</span>
            <span
              className={cn(
                "inline-flex items-center gap-1.5 text-[11px] font-medium",
                backendChecking ? "text-amber-800" : backendOnline ? "text-[#2EAF7D]" : "text-red-700"
              )}
            >
              <span
                className={cn(
                  "w-1.5 h-1.5 rounded-full",
                  backendChecking
                    ? "bg-amber-600"
                    : backendOnline
                    ? "bg-[#2EAF7D]"
                    : "bg-red-600"
                )}
              />
              {backendChecking ? "Connecting" : backendOnline ? "Live" : "Offline"}
            </span>
          </div>

          {/* ML Engine Status */}
          <div className="flex items-center justify-between">
            <span className="text-[#486966]">ML Anomaly</span>
            <span
              className={cn(
                "inline-flex items-center gap-1.5 text-[11px] font-medium",
                isMlOk ? "text-[#2EAF7D]" : "text-amber-700"
              )}
            >
              <span
                className={cn(
                  "w-1.5 h-1.5 rounded-full",
                  isMlOk ? "bg-[#2EAF7D]" : "bg-amber-500"
                )}
              />
              {isMlOk ? "Isolation Forest" : "Unavailable"}
            </span>
          </div>

          {/* Database Status */}
          <div className="flex items-center justify-between">
            <span className="text-[#486966]">Telemetry DB</span>
            <span
              className={cn(
                "inline-flex items-center gap-1.5 text-[11px] font-medium",
                isDbOk ? "text-[#2EAF7D]" : "text-red-700"
              )}
            >
              <span
                className={cn(
                  "w-1.5 h-1.5 rounded-full",
                  isDbOk ? "bg-[#2EAF7D]" : "bg-red-600"
                )}
              />
              {isDbOk ? "SQLite (demo.db)" : "Error"}
            </span>
          </div>
        </div>
      </div>
    </aside>

    </>
  );
}
