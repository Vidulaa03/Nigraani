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
    <aside ref={sidebarRef} aria-hidden={mobileViewport && !mobileOpen} {...(mobileViewport && !mobileOpen ? { inert: "" as unknown as boolean } : {})} className={`fixed inset-y-0 left-0 z-40 flex min-h-screen w-64 shrink-0 select-none flex-col border-r border-[#e5e0d5] bg-white transition-transform duration-200 md:sticky md:top-0 md:z-20 md:translate-x-0 ${mobileOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"}`}>
      {/* Brand Header - explicitly padded and never clipped */}
      <div className="p-6 pb-5 border-b border-[#e5e0d5]">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-none bg-gradient-to-br from-amber-500/20 to-amber-700/10 border border-amber-500/30 flex items-center justify-center text-amber-800 shadow-[0_0_15px_rgba(189,123,18,0.12)] shrink-0">
            <Shield className="w-5 h-5 text-amber-800" />
          </div>
          <div>
            <div className="text-lg font-black tracking-wider text-[#27251f] font-sans flex items-center gap-1.5 leading-none">
              NIGRAANI
            </div>
            <div className="text-[10px] uppercase font-sans tracking-widest text-[#716c60] mt-1">
              Cybersecurity Intel
            </div>
          </div>
          <button className="ml-auto rounded-none p-2 text-[#716c60] hover:bg-[#ffffff] md:hidden" onClick={onNavigate} aria-label="Close navigation"><X className="h-4 w-4" /></button>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="px-3 pb-2 text-[10px] font-sans uppercase tracking-wider text-[#716c60]">
          Command Deck
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
                "flex items-center gap-3 px-3 py-2.5 rounded-none text-xs font-sans transition-all duration-150 group",
                isActive
                  ? "bg-amber-500/10 text-amber-900 font-semibold border border-amber-500/30 shadow-[inset_0_1px_0_0_rgba(255,255,255,0.05)]"
                  : "text-[#716c60] hover:text-[#27251f] hover:bg-[#ffffff] border border-transparent"
              )}
            >
              <Icon
                className={cn(
                  "w-4 h-4 shrink-0 transition-colors",
                  isActive
                    ? "text-amber-800"
                    : "text-[#716c60] group-hover:text-[#716c60]"
                )}
              />
              <span className="truncate">{item.name}</span>
            </Link>
          );
        })}
      </nav>

      {/* Live System Health Section at bottom */}
      <div className="p-4 border-t border-[#e5e0d5] bg-[#ffffff]">
        <div className="text-[10px] font-sans uppercase tracking-wider text-[#716c60] mb-3 flex items-center justify-between">
          <span>System Status</span>
          <CircleDot className="w-3 h-3 text-[#716c60]" />
        </div>

        <div className="space-y-2 text-xs font-sans">
          {/* Backend Status */}
          <div className="flex items-center justify-between">
            <span className="text-[#635d51]">Backend API</span>
            <span
              className={cn(
                "inline-flex items-center gap-1.5 text-[11px] font-medium",
                backendChecking ? "text-amber-800" : backendOnline ? "text-emerald-700" : "text-red-700"
              )}
            >
              <span
                className={cn(
                  "w-1.5 h-1.5 rounded-none",
                  backendChecking
                    ? "bg-amber-600"
                    : backendOnline
                    ? "bg-emerald-600"
                    : "bg-red-600"
                )}
              />
              {backendChecking ? "Checking" : backendOnline ? "Online" : "Offline"}
            </span>
          </div>

          {/* ML Engine Status */}
          <div className="flex items-center justify-between">
            <span className="text-[#635d51]">ML Engine</span>
            <span
              className={cn(
                "inline-flex items-center gap-1.5 text-[11px] font-medium",
                isMlOk ? "text-emerald-700" : "text-amber-800"
              )}
            >
              <span
                className={cn(
                  "w-1.5 h-1.5 rounded-none",
                  isMlOk
                    ? "bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.8)]"
                    : "bg-amber-400"
                )}
              />
              {isMlOk ? "Healthy" : "Unavailable"}
            </span>
          </div>

          {/* Database Status */}
          <div className="flex items-center justify-between">
            <span className="text-[#635d51]">Database</span>
            <span
              className={cn(
                "inline-flex items-center gap-1.5 text-[11px] font-medium",
                isDbOk ? "text-emerald-700" : "text-red-700"
              )}
            >
              <span
                className={cn(
                  "w-1.5 h-1.5 rounded-none",
                  isDbOk
                    ? "bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.8)]"
                    : "bg-red-400"
                )}
              />
              {isDbOk ? "Connected" : "Error"}
            </span>
          </div>
        </div>
      </div>
    </aside>
    </>
  );
}
