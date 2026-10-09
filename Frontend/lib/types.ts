/**
 * Strict TypeScript types for NIGRAANI frontend models matching backend responses.
 */

export interface SystemHealth {
  status: "online" | "degraded" | "offline";
  timestamp: string;
  backend: {
    status: "online" | "offline";
    version: string;
    name: string;
  };
  database: {
    status: "connected" | "error";
    path: string;
    counts: {
      security_events?: number;
      detections?: number;
      decisions?: number;
      users?: number;
      orders?: number;
      error?: string;
    };
    last_event_timestamp: string | null;
  };
  ml_engine: {
    status: "healthy" | "unavailable";
    model: string;
    features_contract: string[];
    metadata: Record<string, any>;
    error: string | null;
  };
  analyzer: {
    status: "active" | "idle";
    total_decisions: number;
    total_detections: number;
  };
}

export interface ThreatPosture {
  decision_id: number;
  ip: string;
  risk_score: number;
  risk_level: "ALLOW" | "MONITOR" | "THROTTLE" | "BLOCK";
  action: "ALLOW" | "MONITOR" | "THROTTLE" | "BLOCK";
  reasons: string[];
  source: string;
}

export interface SecurityDetection {
  detection_id: number;
  detector: string;
  attack_type: string;
  severity: number;
  severity_band: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  ip: string;
  user_id: number | null;
  evidence: string;
  owasp: string;
  event_ids: number[];
  linked_endpoint?: string;
  linked_timestamp?: string | null;
  ml_score?: number | null;
  risk_score?: number | null;
  risk_level?: string | null;
  action?: string | null;
}

export interface DashboardSummary {
  kpis: {
    api_requests: number;
    ml_windows: number;
    ml_anomalies: number;
    security_detections: number;
    high_threats: number;
    critical_threats: number;
    blocked_requests: number;
  };
  threat_posture: ThreatPosture | null;
  severity_distribution: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  decision_distribution: {
    ALLOW: number;
    MONITOR: number;
    THROTTLE: number;
    BLOCK: number;
  };
  recent_detections: SecurityDetection[];
}

export interface TrafficSummary {
  request_volume: number;
  unique_ips: number;
  unique_endpoints: number;
  http_methods: number;
  error_rate_pct: number;
  avg_latency_ms: number;
}

export interface TrafficTimelinePoint {
  timestamp: string;
  requests: number;
  errors: number;
  avg_latency: number;
}

export interface EndpointStat {
  endpoint: string;
  count: number;
  error_rate: number;
  avg_latency: number;
}

export interface MethodStat {
  method: string;
  count: number;
}

export interface StatusCodeStat {
  status_code: string;
  count: number;
}

export interface LatencyBucket {
  range: string;
  count: number;
}

export interface TrafficData {
  summary: TrafficSummary;
  timeline: TrafficTimelinePoint[];
  endpoints: EndpointStat[];
  methods: MethodStat[];
  status_codes: StatusCodeStat[];
  latency_distribution: LatencyBucket[];
}

export interface TopSourceIp {
  ip: string;
  count: number;
  highest_severity: number;
  action: string;
  risk_score: number | null;
}

export interface ThreatIntelligenceData {
  summary: {
    total_detections: number;
    unique_attack_types: number;
    unique_source_ips: number;
    highest_severity: number;
  };
  attack_types: { attack_type: string; count: number }[];
  severities: { band: string; count: number }[];
  top_source_ips: TopSourceIp[];
  top_endpoints: { endpoint: string; count: number }[];
  timeline: { timestamp: string; detections: number }[];
  detections: SecurityDetection[];
}

export interface MLWindow {
  ip: string;
  window_start: string;
  window_end: string;
  ml_score: number;
  raw_score: number;
  is_anomalous: boolean;
  prediction: "ANOMALY" | "NORMAL";
  ground_truth: string;
  features: Record<string, number>;
  event_ids: number[];
}

export interface MLBehaviorData {
  status: "healthy" | "ready" | "unavailable";
  summary: {
    total_windows: number;
    anomaly_count: number;
    anomaly_rate_pct: number;
    max_score: number;
    avg_score: number;
  };
  features_contract: string[];
  normal_vs_anomaly: {
    normal: number;
    anomaly: number;
  };
  timeline: {
    window_start: string;
    window_end: string;
    ip: string;
    ml_score: number;
    raw_score: number;
    is_anomalous: boolean;
  }[];
  score_distribution: { range: string; count: number }[];
  windows: MLWindow[];
  metadata?: Record<string, any>;
  error?: string;
}

export interface SecurityEvent {
  event_id: number;
  timestamp: string;
  ip: string;
  user_id: number | null;
  user_name?: string | null;
  method: string;
  endpoint: string;
  endpoint_pattern: string;
  resource_id: number | null;
  resource_owner_id: number | null;
  status_code: number;
  response_time_ms: number;
  sim_label: string;
}

export interface SecurityEventsResponse {
  total: number;
  limit: number;
  offset: number;
  events: SecurityEvent[];
}

export interface InvestigationLifecycleStage {
  stage: number;
  name: string;
  title: string;
  status: string;
  data: any;
}

export interface InvestigationTrail {
  event: SecurityEvent;
  user: { name: string; email: string } | null;
  detections: SecurityDetection[];
  ml_window: MLWindow | null;
  decision: {
    decision_id: number;
    risk_score: number;
    risk_level: string;
    action: string;
    reasons: string[];
    source: string;
    total_decisions_for_ip: number;
  } | null;
  lifecycle: InvestigationLifecycleStage[];
}

export interface GeminiEvidenceObservation {
  observation: string;
  significance: string;
}

export interface GeminiInvestigationReport {
  incident_summary: string;
  likely_attack_type: string;
  severity: "low" | "medium" | "high" | "critical";
  evidence: GeminiEvidenceObservation[];
  confidence: number;
  recommended_actions: string[];
  limitations: string[];
}

export interface IncidentInvestigation {
  investigation_id: string;
  detection_id: number;
  status: "pending" | "in_progress" | "completed" | "failed";
  result: GeminiInvestigationReport | null;
  model_id: string;
  created_at: string;
  completed_at: string | null;
  error_code: string | null;
}
