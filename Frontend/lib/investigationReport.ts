import { InvestigationTrail, SecurityEvent } from "./types";

export type InvestigationScenario = "api-enumeration" | "rate-spike";

export interface ReportEvent {
  eventId: number;
  timestamp: string | null;
  method?: string;
  endpoint?: string;
  statusCode?: number;
  responseTimeMs?: number;
  detectorEvidence: string[];
}

export interface InvestigationReport {
  mode: "demo-template";
  summary: string;
  severity: number;
  severityBand: string;
  relatedEvents: ReportEvent[];
  observedFacts: string[];
  possiblePatterns: { title: string; detail: string }[];
  benignExplanations: string[];
  uncertainty: string[];
  nextSteps: { recommendation: string; approvalRequired: true }[];
}

const SCENARIOS: Record<
  InvestigationScenario,
  {
    title: string;
    pattern: string;
    benign: string[];
    nextSteps: string[];
  }
> = {
  "api-enumeration": {
    title: "API resource enumeration",
    pattern:
      "The enumeration rule matched resource-ID probing. This can be consistent with an attempt to discover valid resources; the rule match alone does not establish intent or access.",
    benign: [
      "A client may be retrying a batch of stale or sequential resource IDs.",
      "An authorized inventory, migration, or QA job may be checking resource availability.",
    ],
    nextSteps: [
      "Review the referenced requests and application logs to confirm which resources were accessed and by whom.",
      "Ask the service owner whether a migration, inventory, or QA job explains the ID pattern.",
      "If the activity is confirmed as unauthorized, have an operator review proposed safeguards before applying them.",
    ],
  },
  "rate-spike": {
    title: "API rate spike",
    pattern:
      "The rate rule matched a high request volume in its observation window. The burst may reflect abusive automation, retries, or a legitimate batch workload.",
    benign: [
      "A client retry loop, deployment, or scheduled batch may have produced a short burst.",
      "Several users behind a shared proxy or NAT may contribute to the same source-IP count.",
    ],
    nextSteps: [
      "Compare the event timestamps with service latency, error rates, and client-side retry logs.",
      "Check with the API owner whether a scheduled job or release explains the request volume.",
      "If abuse is confirmed, submit any rate-limit or access-control change for human review and approval.",
    ],
  },
};

function getScenarios(trail: InvestigationTrail): InvestigationScenario[] {
  const detectors = new Set(trail.detections.map((detection) => detection.detector));
  const scenarios: InvestigationScenario[] = [];
  if (detectors.has("enumeration_detector")) scenarios.push("api-enumeration");
  if (detectors.has("rate_detector")) scenarios.push("rate-spike");
  return scenarios;
}

function toReportEvent(
  eventId: number,
  event: SecurityEvent | undefined,
  evidence: string[],
): ReportEvent {
  if (!event) return { eventId, timestamp: null, detectorEvidence: evidence };
  return {
    eventId,
    timestamp: event.timestamp,
    method: event.method,
    endpoint: event.endpoint,
    statusCode: event.status_code,
    responseTimeMs: event.response_time_ms,
    detectorEvidence: evidence,
  };
}

/**
 * Isolated report adapter. Replace this deterministic demo template with the
 * backend/LLM endpoint when it is available; the UI does not claim this is LLM output.
 */
export async function loadInvestigationReport(
  trail: InvestigationTrail,
): Promise<InvestigationReport | null> {
  const scenarios = getScenarios(trail);
  if (scenarios.length === 0) return null;

  const linkedDetections = trail.detections.filter((detection) =>
    detection.detector === "enumeration_detector" ||
    detection.detector === "rate_detector",
  );
  const eventIds = Array.from(
    new Set([
      trail.event.event_id,
      ...linkedDetections.flatMap((detection) => detection.event_ids ?? []),
    ]),
  ).sort((left, right) => left - right);

  // Use the already-loaded trail. Do not issue a second request or imply that
  // event details are available when the backend only supplied event IDs.
  const eventsById = new Map([[trail.event.event_id, trail.event]]);

  const relatedEvents = eventIds.map((eventId) => {
    const evidence = linkedDetections
      .filter((detection) => detection.event_ids?.includes(eventId))
      .map((detection) => detection.evidence);
    return toReportEvent(eventId, eventsById.get(eventId), evidence);
  });

  const severity = Math.max(...linkedDetections.map((detection) => detection.severity));
  const severityBand = linkedDetections.find(
    (detection) => detection.severity === severity,
  )?.severity_band ?? "LOW";
  const observedFacts = [
    `Event #${trail.event.event_id} was recorded at ${trail.event.timestamp}.`,
    ...linkedDetections.map(
      (detection) => `${detection.attack_type}: ${detection.evidence}`,
    ),
  ];
  const nextSteps = Array.from(new Set(scenarios.flatMap((scenario) => SCENARIOS[scenario].nextSteps)))
    .map((recommendation) => ({ recommendation, approvalRequired: true as const }));

  return {
    mode: "demo-template",
    summary: `Existing rule evidence is consistent with ${scenarios.map((scenario) => SCENARIOS[scenario].title).join(" and ")}. This is a triage hypothesis, not a finding of attacker intent.`,
    severity,
    severityBand,
    relatedEvents,
    observedFacts,
    possiblePatterns: scenarios.map((scenario) => ({
      title: SCENARIOS[scenario].title,
      detail: SCENARIOS[scenario].pattern,
    })),
    benignExplanations: Array.from(
      new Set(scenarios.flatMap((scenario) => SCENARIOS[scenario].benign)),
    ),
    uncertainty: [
      "This deterministic demo template is not an LLM analysis and does not infer intent.",
      "Only the selected event's full row is available in this view. Other detector-referenced IDs are shown without additional event details.",
      "Client ownership, session context, and operator confirmation are not established by this report.",
    ],
    nextSteps,
  };
}
