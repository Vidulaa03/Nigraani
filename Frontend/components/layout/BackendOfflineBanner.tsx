import React from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

interface BackendOfflineBannerProps {
  onRetry?: () => void;
  error?: string | null;
}

export function BackendOfflineBanner({ onRetry, error }: BackendOfflineBannerProps) {
  return (
    <div className="bg-red-50 border-y border-red-200 px-4 py-3 text-red-900 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-none bg-red-100 border border-red-200 flex items-center justify-center text-red-700 shrink-0">
          <AlertTriangle className="w-4 h-4" />
        </div>
        <div>
          <div className="font-sans text-xs font-bold uppercase tracking-wider text-red-900">
            BACKEND OFFLINE — UNABLE TO REACH NIGRAANI ANALYSIS ENGINE
          </div>
          <div className="text-xs text-red-800 mt-0.5">
            {error || "Make sure FastAPI is running (`uvicorn backend.main:app --reload` on port 8000). Showing cached or waiting states."}
          </div>
        </div>
      </div>

      {onRetry && (
        <button
          onClick={onRetry}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-none bg-white hover:bg-red-100 border border-red-200 text-xs font-sans font-medium text-red-900 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Reconnect
        </button>
      )}
    </div>
  );
}
