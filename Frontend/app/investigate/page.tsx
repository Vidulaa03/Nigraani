"use client";

import React, { useEffect, useState } from "react";
import { Search, ChevronLeft, ChevronRight } from "lucide-react";
import { AppLayout } from "@/components/layout/AppLayout";
import { EventsTable } from "@/components/tables/EventsTable";
import { api } from "@/lib/api";
import { SecurityEvent } from "@/lib/types";

export default function InvestigateSearchPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [search, setSearch] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [methodFilter, setMethodFilter] = useState<string>("ALL");
  const [totalCount, setTotalCount] = useState<number>(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  const fetchEvents = async (requestedOffset = offset) => {
    try {
      const params: any = { limit: 100, offset: requestedOffset };
      if (search) params.search = search;
      if (statusFilter !== "ALL") params.statusCode = Number(statusFilter);
      if (methodFilter !== "ALL") params.method = methodFilter;

      const res = await api.getEvents(params);
      setEvents(res.events);
      setTotalCount(res.total);
    } catch {
      // handled
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [statusFilter, methodFilter, offset]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setOffset(0);
    fetchEvents(0);
  };

  const handleRefresh = () => {
    setRefreshing(true);
    fetchEvents();
  };

  return (
    <AppLayout
      title="REQUEST INVESTIGATION FORENSICS"
      subtitle="Search, Trace & Audit End-to-End Pipeline Decision Trails"
      onRefresh={handleRefresh}
      isRefreshing={refreshing}
    >
      <div className="space-y-6">
        {/* Search & Filter Toolbar */}
        <div className="bg-[#ffffff] border border-[#e5e0d5] rounded-none p-5">
          <form
            onSubmit={handleSearchSubmit}
            className="flex flex-col md:flex-row items-center gap-3"
          >
            {/* Search Input */}
            <div className="relative flex-1 w-full">
              <Search className="w-4 h-4 text-[#716c60] absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search by Event ID, IP Address, or Endpoint Path..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 rounded-none bg-[#ffffff] border border-[#e5e0d5] text-xs font-sans text-[#27251f] placeholder-[#716c60] focus:outline-none focus:border-amber-500/50"
              />
            </div>

            {/* Filter by Status */}
            <div className="flex items-center gap-2 w-full md:w-auto">
              <select
                value={statusFilter}
                onChange={(e) => { setOffset(0); setStatusFilter(e.target.value); }}
                className="px-3 py-2.5 rounded-none bg-[#ffffff] border border-[#e5e0d5] text-xs font-sans text-[#464238] focus:outline-none focus:border-amber-500/50"
              >
                <option value="ALL">All Status Codes</option>
                <option value="200">200 OK</option>
                <option value="401">401 Unauthorized</option>
                <option value="404">404 Not Found</option>
              </select>

              {/* Filter by Method */}
              <select
                value={methodFilter}
                onChange={(e) => { setOffset(0); setMethodFilter(e.target.value); }}
                className="px-3 py-2.5 rounded-none bg-[#ffffff] border border-[#e5e0d5] text-xs font-sans text-[#464238] focus:outline-none focus:border-amber-500/50"
              >
                <option value="ALL">All Methods</option>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
              </select>

              <button
                type="submit"
                className="px-4 py-2.5 rounded-none bg-amber-500/10 hover:bg-amber-500/20 text-amber-800 border border-amber-500/30 text-xs font-sans font-semibold transition-colors shrink-0"
              >
                Search
              </button>
            </div>
          </form>

          <div className="flex items-center justify-between mt-4 pt-3 border-t border-[#e5e0d5] text-xs font-sans text-[#716c60]">
            <span>
              Showing {events.length} of {totalCount} indexed security events
            </span>
            <span>Click any event&apos;s &quot;Trace&quot; button to view its full 5-stage lifecycle</span>
          </div>
        </div>

        {/* Events Table */}
        <div className="space-y-3">
          <EventsTable events={events} isLoading={loading} />
          {totalCount > 100 && (
            <nav aria-label="Event result pages" className="flex items-center justify-between border-t border-[#e5e0d5] pt-3 text-xs font-sans text-[#716c60]">
              <span>Page {Math.floor(offset / 100) + 1} of {Math.ceil(totalCount / 100)}</span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  aria-label="Previous page"
                  disabled={offset === 0 || loading}
                  onClick={() => setOffset((current) => Math.max(0, current - 100))}
                  className="inline-flex items-center gap-1 rounded-none border border-[#e5e0d5] bg-white px-3 py-2 text-[#464238] hover:bg-[#f4f1e8] disabled:cursor-not-allowed disabled:opacity-50"
                ><ChevronLeft className="h-4 w-4" />Previous</button>
                <button
                  type="button"
                  aria-label="Next page"
                  disabled={offset + 100 >= totalCount || loading}
                  onClick={() => setOffset((current) => current + 100)}
                  className="inline-flex items-center gap-1 rounded-none border border-[#e5e0d5] bg-white px-3 py-2 text-[#464238] hover:bg-[#f4f1e8] disabled:cursor-not-allowed disabled:opacity-50"
                >Next<ChevronRight className="h-4 w-4" /></button>
              </div>
            </nav>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
