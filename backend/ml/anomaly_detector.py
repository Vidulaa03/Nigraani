"""Score per-IP traffic windows with the trained Isolation Forest.

Run from the repository root::

    python -m backend.ml.anomaly_detector            # score events in the DB
    python -m backend.ml.anomaly_detector --demo     # also score synthetic abuse (in memory only)

Scoring: ``raw_score = model.decision_function(x)`` (positive = normal,
negative = anomalous). It is mapped linearly to ``ml_score`` in 0-100 with the
decision threshold (0) at 50::

    ml_score = clip(50 - 50 * raw_score / score_scale, 0, 100)

A window is anomalous when ``raw_score < 0`` (the same boundary used by
``IsolationForest.predict`` returning -1).

Integration note: ``score_ip_events`` returns a dict whose ``ml_score`` can be
passed straight to ``detection.risk_engine.compute_risk(detections, ml_score)``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np

from backend.ml.features import (
    FEATURE_NAMES,
    WindowFeatures,
    extract_windows,
    load_events_from_db,
    windows_to_matrix,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = REPO_ROOT / "models" / "iforest.joblib"


class ModelNotFoundError(FileNotFoundError):
    """Raised when the trained model file is missing."""


class AnomalyDetector:
    """Loads ``models/iforest.joblib`` and scores traffic windows."""

    def __init__(self, model_path: Path | str = DEFAULT_MODEL_PATH) -> None:
        path = Path(model_path)
        if not path.exists():
            raise ModelNotFoundError(
                f"Model file not found: {path}. Train it first with: python -m backend.ml.train_model"
            )
        bundle = joblib.load(path)
        if list(bundle["feature_names"]) != list(FEATURE_NAMES):
            raise ValueError(
                "Saved model feature order does not match backend.ml.features.FEATURE_NAMES; retrain the model."
            )
        self.model = bundle["model"]
        self.feature_names: list[str] = list(bundle["feature_names"])
        self.score_scale: float = float(bundle.get("score_scale", 0.2))
        self.metadata: dict[str, Any] = dict(bundle.get("metadata", {}))
        self.model_path = path

    def _to_ml_score(self, raw_scores: np.ndarray) -> np.ndarray:
        return np.clip(50.0 - 50.0 * raw_scores / self.score_scale, 0.0, 100.0)

    def score_windows(self, windows: Sequence[WindowFeatures]) -> list[dict[str, Any]]:
        """Score already-extracted windows. Returns one result dict per window."""
        if not windows:
            return []
        X = windows_to_matrix(windows)
        raw = self.model.decision_function(X)
        ml = self._to_ml_score(raw)
        results = []
        for win, raw_score, ml_score in zip(windows, raw, ml):
            results.append(
                {
                    "ip": win.ip,
                    "window_start": win.window_start.isoformat(),
                    "window_end": win.window_end.isoformat(),
                    "ml_score": round(float(ml_score), 1),
                    "is_anomalous": bool(raw_score < 0),
                    "raw_score": round(float(raw_score), 4),
                    "features": {k: round(float(v), 3) for k, v in win.features.items()},
                    "event_ids": list(win.event_ids),
                }
            )
        return results

    def score_events(self, events: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        """Extract per-IP 30s windows from raw events and score each one."""
        return self.score_windows(extract_windows(events))

    def score_ip_events(self, events: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
        """Score events (typically one IP) and return the most anomalous window.

        Returns ``None`` if no window has enough requests to be scored.
        """
        results = self.score_events(events)
        if not results:
            return None
        return max(results, key=lambda r: r["ml_score"])


def _synthetic_events(ip: str, kind: str) -> list[dict[str, Any]]:
    """In-memory demo events (never written to the DB)."""
    from backend.detection.base import sample_event

    base = 1_800_000_000.0  # fixed epoch, aligned to a 30s boundary
    from datetime import datetime, timezone

    def ts(offset: float) -> str:
        return datetime.fromtimestamp(base + offset, tz=timezone.utc).isoformat()

    events = []
    if kind == "burst_enumeration":
        for i in range(60):
            events.append(sample_event(
                event_id=i + 1, ip=ip, timestamp=ts(i * 0.2), user_id=None, resource_id=1000 + i,
                resource_owner_id=None, endpoint=f"/api/users/{1000 + i}",
                endpoint_pattern="/api/users/{user_id}", status_code=404, response_time_ms=4.0,
                sim_label="unknown",
            ))
    elif kind == "login_bruteforce":
        for i in range(25):
            events.append(sample_event(
                event_id=i + 1, ip=ip, timestamp=ts(i * 0.8), user_id=None, resource_id=None,
                resource_owner_id=None, method="POST", endpoint="/api/auth/login",
                endpoint_pattern="/api/auth/{action}", status_code=401, response_time_ms=6.0,
                sim_label="unknown",
            ))
    return events


def _print_results(results: Sequence[dict[str, Any]]) -> None:
    header = f"{'ip':<16}{'window_start':<27}{'ml':>6} {'raw':>8}  anomalous  features"
    print(header)
    for r in results:
        feats = ", ".join(f"{k}={r['features'][k]:g}" for k in FEATURE_NAMES)
        print(f"{r['ip']:<16}{r['window_start']:<27}{r['ml_score']:>6.1f} {r['raw_score']:>8.3f}  "
              f"{str(r['is_anomalous']):<9}  {feats}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score traffic windows with the NIGRAANI Isolation Forest.")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--ip", help="only score windows for this IP")
    parser.add_argument("--top", type=int, default=15, help="show the N highest-scoring DB windows (default 15)")
    parser.add_argument("--demo", action="store_true",
                        help="also score synthetic abusive windows built in memory (DB is not modified)")
    args = parser.parse_args(argv)

    try:
        detector = AnomalyDetector(args.model)
    except (ModelNotFoundError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1

    events = load_events_from_db()
    if args.ip:
        events = [e for e in events if e["ip"] == args.ip]
    results = detector.score_events(events)
    results.sort(key=lambda r: r["ml_score"], reverse=True)

    flagged = sum(r["is_anomalous"] for r in results)
    print(f"Scored {len(results)} window(s) from {len(events)} event(s); {flagged} flagged anomalous.")
    _print_results(results[: args.top])

    if args.demo:
        print("\nSynthetic abusive windows (in memory only):")
        for kind in ("burst_enumeration", "login_bruteforce"):
            res = detector.score_events(_synthetic_events("203.0.113.9", kind))
            print(f"-- {kind}")
            _print_results(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
