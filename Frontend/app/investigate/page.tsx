"use client";

import React, { useEffect, useState } from "react";
import { Search, ChevronLeft, ChevronRight, FileSearch } from "lucide-react";
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
    if (offset !== 0) {
      setOffset(0);
      return;
    }
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
        <section className="border border-[#3FD0C9]/50 bg-[#FFFFFF] rounded-sm p-4 sm:p-5" aria-labelledby="report-entry-title">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="flex items-start gap-3">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-sm border border-[#3FD0C9]/40 bg-[#F2FBF9] text-[#02353C]">
                <FileSearch className="h-4 w-4 text-[#2EAF7D]" />
              </span>
              <div>
                <h2 id="report-entry-title" className="text-sm font-bold uppercase tracking-wide text-[#02353C]">
                  LLM Investigation Report
                </h2>
                <p className="mt-1 max-w-3xl text-xs leading-5 text-[#486966]">
                  Open an event with the <strong className="text-[#02353C]">Trace + Report</strong> action to see its incident summary, severity, linked event IDs, evidence, possible patterns, benign explanations, uncertainty, and human-review recommendations.
                </p>
                <span className="mt-2 inline-flex items-center rounded-sm border border-[#D5EAE5] bg-[#F2FBF9] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-[#02353C]">
                  Demo template · not an LLM response · enumeration and rate-spike scenarios
                </span>
              </div>
            </div>
            <a href="#investigation-events" className="shrink-0 self-start rounded-sm border border-[#D5EAE5] bg-[#FFFFFF] px-3 py-2 text-xs font-medium text-[#02353C] hover:bg-[#F2FBF9] transition-colors">
              Browse events
            </a>
          </div>
        </section>

        {/* Search & Filter Toolbar */}
        <div className="bg-[#FFFFFF] border border-[#D5EAE5] rounded-sm p-5">
          <form
            onSubmit={handleSearchSubmit}
            className="flex flex-col md:flex-row items-center gap-3"
          >
            {/* Search Input */}
            <div className="relative flex-1 w-full">
              <Search className="w-4 h-4 text-[#486966] absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search by Event ID, IP Address, or Endpoint Path..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 rounded-sm bg-[#FFFFFF] border border-[#D5EAE5] text-xs font-sans text-[#02353C] placeholder-[#486966] focus:outline-none focus:border-[#2EAF7D]"
              />
            </div>

            {/* Filter by Status */}
            <div className="flex items-center gap-2 w-full md:w-auto">
              <select
                value={statusFilter}
                onChange={(e) => { setOffset(0); setStatusFilter(e.target.value); }}
                className="px-3 py-2.5 rounded-sm bg-[#FFFFFF] border border-[#D5EAE5] text-xs font-sans text-[#02353C] focus:outline-none focus:border-[#2EAF7D]"
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
                className="px-3 py-2.5 rounded-sm bg-[#FFFFFF] border border-[#D5EAE5] text-xs font-sans text-[#02353C] focus:outline-none focus:border-[#2EAF7D]"
              >
                <option value="ALL">All Methods</option>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
              </select>

              <button
                type="submit"
                className="px-4 py-2.5 rounded-sm bg-[#2EAF7D] hover:bg-[#259b6d] text-white border border-[#2EAF7D] text-xs font-sans font-semibold transition-colors shrink-0 shadow-sm"
              >
                Search
              </button>
            </div>
          </form>

          <div className="flex items-center justify-between mt-4 pt-3 border-t border-[#D5EAE5] text-xs font-sans text-[#486966]">
            <span>
              Showing {events.length} of {totalCount} indexed security events
            </span>
            <span>Click any event&apos;s &quot;Trace&quot; button to view its full 6-stage lifecycle</span>
          </div>
        </div>

        {/* Events Table */}
        <div id="investigation-events" className="space-y-3">
          <EventsTable events={events} isLoading={loading} traceLabel="Trace + Report" />
          {totalCount > 100 && (
            <nav aria-label="Event result pages" className="flex items-center justify-between border-t border-[#D5EAE5] pt-3 text-xs font-sans text-[#486966]">
              <span>Page {Math.floor(offset / 100) + 1} of {Math.ceil(totalCount / 100)}</span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  aria-label="Previous page"
                  disabled={offset === 0 || loading}
                  onClick={() => setOffset((current) => Math.max(0, current - 100))}
                  className="inline-flex items-center gap-1 rounded-sm border border-[#D5EAE5] bg-[#FFFFFF] px-3 py-2 text-[#02353C] hover:bg-[#F2FBF9] disabled:cursor-not-allowed disabled:opacity-50"
                ><ChevronLeft className="h-4 w-4" />Previous</button>
                <button
                  type="button"
                  aria-label="Next page"
                  disabled={offset + 100 >= totalCount || loading}
                  onClick={() => setOffset((current) => current + 100)}
                  className="inline-flex items-center gap-1 rounded-sm border border-[#D5EAE5] bg-[#FFFFFF] px-3 py-2 text-[#02353C] hover:bg-[#F2FBF9] disabled:cursor-not-allowed disabled:opacity-50"
                >Next<ChevronRight className="h-4 w-4" /></button>
              </div>
            </nav>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
