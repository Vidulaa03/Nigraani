"""Smoke-test dashboard data paths against demo.db without launching Streamlit widgets."""
from __future__ import annotations

import ast
from pathlib import Path

from backend.database import get_connection, get_events_since
from backend.ml.anomaly_detector import AnomalyDetector
from backend.ml.features import FEATURE_NAMES, extract_windows

ROOT = Path(__file__).resolve().parent
src = (ROOT / "streamlit_app.py").read_text(encoding="utf-8")
ast.parse(src)
assert "use_container_width" not in src
print("syntax ok; no use_container_width")

events = get_events_since(None)
print("events", len(events))
with get_connection() as conn:
    det_n = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
    dec_n = conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
print("detections", det_n, "decisions", dec_n)

detector = AnomalyDetector()
windows = extract_windows(events)
results = detector.score_windows(windows)
print("windows", len(windows), "scored", len(results), "features", list(FEATURE_NAMES))
assert results
assert list(results[0]["features"].keys()) == list(FEATURE_NAMES)

# Empty-pipeline behavior used by the dashboard
assert extract_windows([]) == []
assert detector.score_windows([]) == []
print("empty windows/scoring ok")

fi = getattr(detector.model, "feature_importances_", None)
print("feature_importances_", "present" if fi is not None else "absent")
print("smoke ok")
