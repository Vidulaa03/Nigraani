"use client";

import React, { createContext, useContext, useEffect, useState } from "react";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { BackendOfflineBanner } from "./BackendOfflineBanner";
import { api } from "@/lib/api";
import { SystemHealth } from "@/lib/types";
import { useVisibilityInterval } from "@/lib/useVisibilityInterval";

interface DashboardContextType {
  health: SystemHealth | null;
  backendOnline: boolean;
  lastUpdated: Date | null;
  refreshHealth: () => Promise<void>;
  offlineError: string | null;
}

const DashboardContext = createContext<DashboardContextType>({
  health: null,
  backendOnline: false,
  lastUpdated: null,
  refreshHealth: async () => {},
  offlineError: null,
});

export const useDashboard = () => useContext(DashboardContext);

interface AppLayoutProps {
  children: React.ReactNode;
  title: string;
  subtitle?: string;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export function AppLayout({
  children,
  title,
  subtitle,
  onRefresh,
  isRefreshing = false,
}: AppLayoutProps) {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [backendOnline, setBackendOnline] = useState<boolean>(false);
  const [healthChecked, setHealthChecked] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [offlineError, setOfflineError] = useState<string | null>(null);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  const fetchHealth = async () => {
    try {
      const data = await api.getHealth();
      setHealth(data);
      setBackendOnline(true);
      setOfflineError(null);
      setLastUpdated(new Date());
    } catch (err: any) {
      setBackendOnline(false);
      setOfflineError(err.message || "Failed to reach NIGRAANI backend");
    } finally {
      setHealthChecked(true);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);
  useVisibilityInterval(fetchHealth, 30000);

  useEffect(() => {
    if (!mobileNavOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setMobileNavOpen(false);
        document.getElementById("navigation-menu")?.focus();
      }
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [mobileNavOpen]);

  const handleGlobalRefresh = () => {
    fetchHealth();
    if (onRefresh) onRefresh();
  };

  return (
    <DashboardContext.Provider
      value={{
        health,
        backendOnline,
        lastUpdated,
        refreshHealth: fetchHealth,
        offlineError,
      }}
    >
      <div className="flex min-h-screen bg-[#f7f5ef] text-[#27251f]">
        {/* Persistent Left Sidebar */}
        <Sidebar
          health={health}
          backendOnline={backendOnline}
          backendChecking={!healthChecked}
          mobileOpen={mobileNavOpen}
          onNavigate={() => {
            const wasOpen = mobileNavOpen;
            setMobileNavOpen(false);
            if (wasOpen) document.getElementById("navigation-menu")?.focus();
          }}
        />

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* Top Bar */}
          <Topbar
            title={title}
            subtitle={subtitle}
            onRefresh={handleGlobalRefresh}
            isRefreshing={isRefreshing}
            lastUpdated={lastUpdated}
            backendOnline={backendOnline}
            backendChecking={!healthChecked}
            onMenu={() => setMobileNavOpen(true)}
          />

          {/* Backend Offline Banner */}
          {healthChecked && !backendOnline && (
            <BackendOfflineBanner
              onRetry={handleGlobalRefresh}
              error={offlineError}
            />
          )}

          {/* Dynamic Page Content */}
          <main className="flex-1 p-6 lg:p-8 max-w-[1700px] w-full mx-auto">
            {children}
          </main>
        </div>
      </div>
    </DashboardContext.Provider>
  );
}
