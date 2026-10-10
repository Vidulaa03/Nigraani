"""Poll stored security events, run the detectors and risk engine, and save
detections and decisions.

Progress is kept in a cursor file next to the database
(``<db file>.analyzer-cursor.json``), written atomically after every batch
whose detections and decisions were all saved. A batch that fails is retried
with exponential backoff; the cursor does not move, and the retry is safe
because insert_detection/insert_decision are idempotent per analysis_key.

Backlogs are analyzed in consecutive 60-second windows per IP, so events
older than the newest minute are no longer skipped. Under run_loop the
analyzer also re-reads a short look-back below the cursor (events another
API process committed late) and analyzes events replayed from the recovery
spool, which keep their original, older IDs.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, BinaryIO, Callable

from prometheus_client import start_http_server

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

import backend.database as database
from backend.database import (
    DB_PATH,
    get_events_by_ids,
    get_events_since,
    get_ip_events_between,
    get_last_call_for_incident,
    get_max_event_id,
    insert_decision,
    insert_detection,
)
from backend.detection import (
    bola_detector,
    enumeration_detector,
    login_failure_detector,
    multi_rate_detector,
    rate_detector,
)
from backend.detection.risk_engine import compute_risk
from backend.event_recovery import replay_spool
from backend.notification_service import evaluate_and_notify_incident
from backend.twilio_service import initiate_voice_alert
from backend.ml.anomaly_detector import AnomalyDetector, ModelNotFoundError
from backend.metrics import (
    ANALYSIS_DURATION,
    ANALYSIS_FAILURES,
    ANALYSIS_RUNS,
    DETECTIONS,
    ML_CLASSIFICATIONS,
    ML_SCORE,
    RISK_DECISIONS,
    RISK_SCORE,
)

logger = logging.getLogger(__name__)

try:
    _ANOMALY_DETECTOR: AnomalyDetector | None = AnomalyDetector()
except ModelNotFoundError as exc:
    _ANOMALY_DETECTOR = None
    print(f"WARNING: {exc}", file=sys.stderr)

WINDOW = timedelta(seconds=60)
BATCH_LIMIT = 5000
# Event IDs are epoch microseconds; re-check this far below the cursor for
# events another API process committed after a higher ID was analyzed.
LOOKBACK_MICROSECONDS = int(
    float(os.environ.get("NIGRAANI_ANALYZER_LOOKBACK_SECONDS") or 30) * 1_000_000
)
MAX_TRACKED_IDS = 50_000
MAX_BACKOFF_SECONDS = 60.0
_CURSOR_VERSION = 1
# Notifications and calls only for decisions about recent traffic, so backlog
# processing, cursor resets, and spool replays never alert on old incidents.
ALERT_MAX_AGE = timedelta(
    seconds=float(os.environ.get("NIGRAANI_ALERT_MAX_AGE_SECONDS") or 300)
)

_RECENT_EVENTS_BY_IP: dict[str, list[dict[str, Any]]] = {}


@dataclass
class AnalyzerState:
    last_event_id: int | None = None
    # IDs analyzed within the look-back range, so re-reads skip them.
    processed_ids: set[int] = field(default_factory=set)
    # IDs replayed from the recovery spool that still need analysis.
    pending_event_ids: set[int] = field(default_factory=set)

    def prune(self) -> None:
        if self.last_event_id is not None:
            floor = self.last_event_id - LOOKBACK_MICROSECONDS
            self.processed_ids = {i for i in self.processed_ids if i > floor}
        if len(self.processed_ids) > MAX_TRACKED_IDS:
            self.processed_ids = set(sorted(self.processed_ids)[-MAX_TRACKED_IDS:])


# Set only while run_loop is running; direct process_new_events() calls keep
# the plain "event_id > cursor" behaviour.
_ACTIVE_STATE: AnalyzerState | None = None


def cursor_path() -> Path:
    override = os.environ.get("NIGRAANI_ANALYZER_CURSOR_PATH")
    if override:
        return Path(override)
    db_path = Path(database.DB_PATH)
    return db_path.with_name(f"{db_path.name}.analyzer-cursor.json")


def _ids(value: Any) -> set[int]:
    if not isinstance(value, list) or not all(
        isinstance(item, int) and not isinstance(item, bool) and item > 0 for item in value
    ):
        raise ValueError("expected a list of positive integers")
    return set(value)


def load_analyzer_state() -> AnalyzerState:
    """Read the cursor file; any doubt means reprocessing, never skipping."""
    path = cursor_path()
    if not path.exists():
        logger.info("No analyzer cursor at %s; analyzing all stored events", path)
        return AnalyzerState()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != _CURSOR_VERSION:
            raise ValueError("unknown cursor format")
        last = data["last_event_id"]
        if last is not None and (not isinstance(last, int) or isinstance(last, bool) or last < 0):
            raise ValueError("invalid last_event_id")
        state = AnalyzerState(
            last_event_id=last,
            processed_ids=_ids(data.get("processed_ids", [])),
            pending_event_ids=_ids(data.get("pending_event_ids", [])),
        )
    except (OSError, ValueError, KeyError) as error:
        corrupt = path.with_name(f"{path.name}.corrupt-{time.time_ns()}")
        try:
            os.replace(path, corrupt)
        except OSError:
            corrupt = path
        logger.error(
            "Analyzer cursor %s is unreadable (%s), kept as %s; re-analyzing all "
            "stored events (saving results is idempotent)",
            path, error, corrupt,
        )
        return AnalyzerState()

    if data.get("database") != str(Path(database.DB_PATH).resolve()):
        logger.warning("Analyzer cursor %s belongs to another database; starting over", path)
        return AnalyzerState(pending_event_ids=state.pending_event_ids)
    max_stored = get_max_event_id()
    if state.last_event_id is not None and state.last_event_id > max_stored:
        logger.warning(
            "Analyzer cursor %s (%d) is ahead of the newest stored event (%d); the "
            "database was replaced or reset, starting over",
            path, state.last_event_id, max_stored,
        )
        return AnalyzerState(pending_event_ids=state.pending_event_ids)
    return state


def save_analyzer_state(state: AnalyzerState) -> bool:
    """Write the cursor atomically (temp file + os.replace)."""
    state.prune()
    path = cursor_path()
    temporary = path.with_name(f"{path.name}.tmp")
    payload = {
        "version": _CURSOR_VERSION,
        "database": str(Path(database.DB_PATH).resolve()),
        "last_event_id": state.last_event_id,
        "processed_ids": sorted(state.processed_ids),
        "pending_event_ids": sorted(state.pending_event_ids),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(temporary, "w", encoding="utf-8") as file:
            json.dump(payload, file)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        return True
    except OSError as error:
        # Progress is still held in memory; after a restart the batch is
        # re-analyzed, which is idempotent.
        logger.error("Could not save analyzer cursor %s: %s", path, error)
        return False


def _event_timestamp(event: dict[str, Any]) -> datetime:
    timestamp = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
    return timestamp if timestamp.tzinfo is not None else timestamp.replace(tzinfo=timezone.utc)


def _acquire_single_instance_lock() -> BinaryIO:
    lock_name = hashlib.sha256(str(DB_PATH.resolve()).encode("utf-8")).hexdigest()
    lock_path = Path(tempfile.gettempdir()) / f"nigraani-analyzer-{lock_name}.lock"
    lock_file = lock_path.open("a+b")
    try:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0)
            if not lock_file.read(1):
                lock_file.write(b"\0")
                lock_file.flush()
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        lock_file.close()
        raise RuntimeError(
            "Another analyzer is already running for this database."
        ) from error
    return lock_file


def _release_single_instance_lock(lock_file: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        lock_file.seek(0)
        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    lock_file.close()


def _detect_ip_activity(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    detections: list[dict[str, Any]] = []
    detections.extend(login_failure_detector.detect(events))
    detections.extend(rate_detector.detect(events))
    detections.extend(enumeration_detector.detect(events))
    detections.extend(bola_detector.detect(events))
    detections.extend(multi_rate_detector.detect(events))
    return detections


def score_anomalies(events: list[dict[str, Any]]) -> dict[str, Any] | int | float:
    """Return the scored window when available, or zero otherwise."""
    if _ANOMALY_DETECTOR is None:
        return 0
    result = _ANOMALY_DETECTOR.score_ip_events(events)
    return result if result is not None else 0


def _get_new_events(last_event_id: int | None) -> list[dict[str, Any]]:
    parameters = inspect.signature(get_events_since).parameters
    parameter_name = (
        "last_id" if "last_id" in parameters and "last_event_id" not in parameters
        else "last_event_id"
    )
    kwargs: dict[str, Any] = {parameter_name: last_event_id}
    if "limit" in parameters:
        kwargs["limit"] = BATCH_LIMIT
    return get_events_since(**kwargs)


def _late_and_pending_events(state: AnalyzerState, cursor: int | None) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if cursor is not None and LOOKBACK_MICROSECONDS > 0:
        events.extend(
            get_events_since(
                last_event_id=max(cursor - LOOKBACK_MICROSECONDS, 0),
                max_event_id=cursor,
            )
        )
    if state.pending_event_ids:
        events.extend(get_events_by_ids(sorted(state.pending_event_ids)))
    return events


def _chronological_segments(events: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Split one IP's events into consecutive groups spanning at most WINDOW."""
    segments: list[list[dict[str, Any]]] = []
    for event in sorted(events, key=lambda e: (_event_timestamp(e), int(e["event_id"]))):
        if segments and _event_timestamp(event) - _event_timestamp(segments[-1][0]) <= WINDOW:
            segments[-1].append(event)
        else:
            segments.append([event])
    return segments


def _window_events(
    ip: str,
    segment: list[dict[str, Any]],
    cached: list[dict[str, Any]],
    batch_ids: set[int],
    max_event_id: int,
) -> list[dict[str, Any]]:
    """The 60-second window to analyze for one segment of an IP's events.

    For in-order events this is the usual window ending at the segment's
    newest event. A late or replayed event (older than events already seen)
    gets the window that would have contained it: it ends at the newest
    already-seen event at most 60 seconds after it.
    """
    oldest = min(map(_event_timestamp, segment))
    newest = max(map(_event_timestamp, segment))
    segment_ids = {int(event["event_id"]) for event in segment}
    candidates = {int(event["event_id"]): event for event in cached}
    # The in-memory cache only covers events seen since this process started.
    # After a restart, or for a late or replayed event, read the surrounding
    # events from the database. Other segments of this batch are analyzed
    # in their own windows, so they are left out here.
    if not cached or oldest < max(map(_event_timestamp, cached)):
        margin = timedelta(seconds=1)
        for event in get_ip_events_between(
            ip,
            (newest - WINDOW - margin).isoformat(),
            (oldest + WINDOW + margin).isoformat(),
            max_event_id,
        ):
            event_id = int(event["event_id"])
            if event_id in batch_ids and event_id not in segment_ids:
                continue
            candidates.setdefault(event_id, event)
    candidates.update((int(event["event_id"]), event) for event in segment)

    window_end = max(
        [newest]
        + [
            timestamp
            for timestamp in map(_event_timestamp, candidates.values())
            if newest < timestamp <= oldest + WINDOW
        ]
    )
    window_start = window_end - WINDOW
    return sorted(
        (
            event
            for event in candidates.values()
            if window_start <= _event_timestamp(event) <= window_end
        ),
        key=lambda event: int(event["event_id"]),
    )


def _merge_recent(
    cached: list[dict[str, Any]],
    window_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep every event within WINDOW of the newest one seen for the IP."""
    merged = {int(event["event_id"]): event for event in [*cached, *window_events]}
    newest = max(map(_event_timestamp, merged.values()))
    return sorted(
        (event for event in merged.values() if _event_timestamp(event) >= newest - WINDOW),
        key=lambda event: int(event["event_id"]),
    )


def _alert_incident(
    ip: str,
    decision_id: int,
    decision: dict[str, Any],
    detections: list[dict[str, Any]],
    window_events: list[dict[str, Any]],
) -> None:
    """In-app notification and Twilio voice alert for a saved decision.

    Runs after insert_decision, so a retried batch reuses the same decision_id:
    the notification is deduplicated by its idempotency key and the call by the
    existing call for that incident. Alert failures never fail the analysis.
    """
    newest = max(map(_event_timestamp, window_events))
    if datetime.now(timezone.utc) - newest > ALERT_MAX_AGE:
        logger.info(
            "Decision %s covers events up to %s; historical, so no notification or call",
            decision_id, newest.isoformat(),
        )
        return
    incident_id = f"decision-{decision_id}"
    alert_decision = {**decision, "ip": ip}
    endpoint = next((e.get("endpoint") for e in reversed(window_events) if e.get("endpoint")), None)
    notification = None
    try:
        notification = evaluate_and_notify_incident(alert_decision, detections, incident_id=incident_id)
    except Exception:
        logger.exception("Notification creation failed for %s", incident_id)
    try:
        if get_last_call_for_incident(incident_id) is not None:
            return  # one call per incident; a retry or re-analysis must not call again
        initiate_voice_alert(
            incident_id=incident_id,
            decision=alert_decision,
            detections=detections,
            notification_id=notification.get("notification_id") if notification else None,
            endpoint=endpoint,
        )
    except Exception:
        logger.exception("Voice alert failed for %s", incident_id)


def _analyze_window(
    ip: str,
    window_events: list[dict[str, Any]],
    record_metric: Callable[[Callable[[], None]], None],
) -> None:
    started = time.perf_counter()
    try:
        detections = _detect_ip_activity(window_events)
        ml_result = score_anomalies(window_events)
        if isinstance(ml_result, dict):
            ml_score = float(ml_result["ml_score"])
            ml_is_anomalous = bool(ml_result["is_anomalous"])
            record_metric(lambda: ML_SCORE.observe(ml_score))
            record_metric(
                lambda: ML_CLASSIFICATIONS.labels(
                    "anomalous" if ml_is_anomalous else "normal"
                ).inc()
            )
        else:
            ml_score = float(ml_result)
            ml_is_anomalous = ml_score > 0

        if not detections and not ml_is_anomalous:
            record_metric(ANALYSIS_RUNS.inc)
            return

        decision = compute_risk(detections, ml_score)
        for detection in detections:
            insert_detection(detection)
            detector = detection.get("detector")
            if detector in {
                "login_failure_detector",
                "rate_detector",
                "enumeration_detector",
                "bola_detector",
                "multi_rate_detector",
            }:
                severity = int(detection.get("severity", 0))
                severity_band = (
                    "critical" if severity >= 80 else
                    "high" if severity >= 60 else
                    "medium" if severity >= 30 else "low"
                )
                record_metric(
                    lambda d=detector, s=severity_band: DETECTIONS.labels(d, s).inc()
                )

        decision_id = insert_decision(
            {
                "ip": ip,
                "risk_score": decision["risk_score"],
                "risk_level": decision["risk_level"],
                "action": decision["action"],
                "reasons": decision["reasons"],
                "source": "analyzer",
                "event_ids": [int(event["event_id"]) for event in window_events],
            }
        )
        _alert_incident(ip, decision_id, decision, detections, window_events)
        if decision["action"] in {"ALLOW", "MONITOR", "THROTTLE", "BLOCK"}:
            record_metric(lambda: RISK_DECISIONS.labels(decision["action"]).inc())
        record_metric(lambda: RISK_SCORE.observe(decision["risk_score"]))
        record_metric(ANALYSIS_RUNS.inc)
    except Exception:
        ANALYSIS_FAILURES.inc()
        raise
    finally:
        ANALYSIS_DURATION.observe(time.perf_counter() - started)


def process_new_events(last_event_id: int | None = None) -> int:
    """Analyze events after the cursor and return the new cursor.

    Raises if any detection or decision could not be saved; the caller must
    then keep the old cursor and retry. Nothing about the batch (cursor,
    recent-event cache, result metrics) is committed until every window of
    the batch was saved.
    """
    state = _ACTIVE_STATE
    new_events = _get_new_events(last_event_id)
    if state is not None:
        seen = {int(event["event_id"]) for event in new_events}
        for event in _late_and_pending_events(state, last_event_id):
            if int(event["event_id"]) not in seen:
                seen.add(int(event["event_id"]))
                new_events.append(event)
        new_events = [e for e in new_events if int(e["event_id"]) not in state.processed_ids]
    if not new_events:
        return last_event_id if last_event_id is not None else 0

    batch_ids = {int(event["event_id"]) for event in new_events}
    batch_max_id = max(batch_ids)
    # Context may come from anything already analyzed or in this batch.
    context_max_id = max(batch_max_id, last_event_id or 0)
    events_by_ip: dict[str, list[dict[str, Any]]] = {}
    for event in new_events:
        ip = event.get("ip", "unknown")
        events_by_ip.setdefault(ip, []).append(event)

    staged_cache: dict[str, list[dict[str, Any]]] = {}
    deferred_metrics: list[Callable[[], None]] = []
    for ip, ip_events in events_by_ip.items():
        cached = _RECENT_EVENTS_BY_IP.get(ip, [])
        for segment in _chronological_segments(ip_events):
            window_events = _window_events(ip, segment, cached, batch_ids, context_max_id)
            _analyze_window(ip, window_events, deferred_metrics.append)
            cached = _merge_recent(cached, window_events)
        staged_cache[ip] = cached

    # Every window was saved: commit the batch.
    _RECENT_EVENTS_BY_IP.update(staged_cache)
    newest = max(_event_timestamp(event) for event in new_events)
    for ip in [ip for ip, events in _RECENT_EVENTS_BY_IP.items()
               if not events or max(map(_event_timestamp, events)) < newest - WINDOW]:
        del _RECENT_EVENTS_BY_IP[ip]
    for apply_metric in deferred_metrics:
        apply_metric()
    if state is not None:
        state.processed_ids.update(int(event["event_id"]) for event in new_events)
    return max(batch_max_id, last_event_id or 0)


def _backoff_delay(interval_seconds: float, failures: int, max_backoff: float) -> float:
    return min(max(interval_seconds, 1.0) * 2 ** (failures - 1), max_backoff)


def record_pending_events(state: AnalyzerState, event_ids: list[int]) -> None:
    """Persist recovered event IDs for analysis; raises if not saved, so the
    spool keeps its claimed file and reports the IDs again."""
    state.pending_event_ids.update(event_ids)
    if not save_analyzer_state(state):
        raise OSError("analyzer cursor not saved; recovered events stay claimed")


def _replay_spooled_events(state: AnalyzerState) -> None:
    try:
        replay_spool(on_recovered=lambda ids: record_pending_events(state, ids))
    except Exception:
        logger.exception("Replaying the event recovery spool failed")


def run_loop(
    interval_seconds: int = 5,
    stop_after: int | None = None,
    *,
    max_backoff_seconds: float = MAX_BACKOFF_SECONDS,
) -> None:
    global _ACTIVE_STATE
    lock_file = _acquire_single_instance_lock()
    try:
        state = load_analyzer_state()
        _ACTIVE_STATE = state
        iterations = 0
        failures = 0
        while stop_after is None or iterations < stop_after:
            _replay_spooled_events(state)
            try:
                cursor = process_new_events(state.last_event_id)
            except Exception:
                failures += 1
                delay = _backoff_delay(interval_seconds, failures, max_backoff_seconds)
                logger.exception(
                    "Analyzer batch failed (%d in a row); cursor stays at %s, retrying in %.0fs",
                    failures, state.last_event_id, delay,
                )
                iterations += 1
                if stop_after is not None and iterations >= stop_after:
                    break
                time.sleep(delay)
                continue

            failures = 0
            state.last_event_id = cursor
            state.pending_event_ids.clear()
            save_analyzer_state(state)
            iterations += 1
            if stop_after is not None and iterations >= stop_after:
                break
            if interval_seconds > 0:
                time.sleep(interval_seconds)
    finally:
        _ACTIVE_STATE = None
        _release_single_instance_lock(lock_file)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    start_http_server(port=8001, addr="127.0.0.1")
    run_loop()
