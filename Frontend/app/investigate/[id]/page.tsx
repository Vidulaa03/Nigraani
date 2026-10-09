"use client";

import React, { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { AppLayout } from "@/components/layout/AppLayout";
import { InvestigationDetail } from "@/components/investigation/InvestigationDetail";
import { api } from "@/lib/api";
import { InvestigationTrail } from "@/lib/types";
import { EmptyState } from "@/components/cards/EmptyState";
import { AlertCircle } from "lucide-react";

export default function SingleEventInvestigationPage() {
  const params = useParams();
  const eventId = params?.id as string;

  const [data, setData] = useState<InvestigationTrail | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  const loadData = async () => {
    if (!eventId) return;
    try {
      const res = await api.getInvestigation(eventId);
      setData(res);
      setError(null);
    } catch (err: any) {
      setError(err.message || `Failed to load event ${eventId}`);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [eventId]);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
  };

  return (
    <AppLayout
      title={`INVESTIGATION: EVENT #${eventId || ""}`}
      subtitle="5-Stage Root Cause Analysis & Security Verdict Stepper"
      onRefresh={handleRefresh}
      isRefreshing={refreshing}
    >
      {loading ? (
        <div className="p-16 text-center text-xs font-sans text-[#716c60] bg-[#ffffff] border border-[#e5e0d5] rounded-none">
          Tracing event #{eventId} through detections, ML pipeline, and risk engine...
        </div>
      ) : error ? (
        <EmptyState
          title={`Event #${eventId} Not Found`}
          message={error}
          icon={AlertCircle}
        />
      ) : data ? (
        <InvestigationDetail data={data} />
      ) : null}
    </AppLayout>
  );
}
