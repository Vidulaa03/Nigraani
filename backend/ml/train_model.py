"""Train the NIGRAANI Isolation Forest on NORMAL traffic only.

Run from the repository root::

    python -m backend.ml.train_model

Reads the existing ``security_events`` table, keeps only 30-second IP windows
whose events are ALL labelled ``sim_label == 'normal'`` (the label is used
solely to select training data, never as a feature), fits the model and saves
a joblib bundle to ``models/iforest.joblib``.

The bundle is a dict::

    {"model": IsolationForest, "feature_names": [...8 names in order...],
     "score_scale": float, "metadata": {...}}
"""

from __future__ import annotations

import argparse
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from backend.ml.features import (
    FEATURE_NAMES,
    MIN_REQUESTS_PER_WINDOW,
    WINDOW_SECONDS,
    WindowFeatures,
    extract_windows,
    load_events_from_db,
    windows_to_matrix,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = REPO_ROOT / "models" / "iforest.joblib"

MIN_TRAINING_WINDOWS = 10
RECOMMENDED_TRAINING_WINDOWS = 50

# decision_function distance (from the 0 threshold) that maps to the ends of the
# 0-100 ml_score range. Stored in the bundle so scoring stays consistent.
SCORE_SCALE = 0.2


def build_model() -> IsolationForest:
    """Isolation Forest with the project's fixed hyper-parameters."""
    return IsolationForest(n_estimators=100, contamination=0.05, random_state=42)


def select_normal_windows(windows: list[WindowFeatures]) -> list[WindowFeatures]:
    """Keep only windows in which every event is labelled normal."""
    return [w for w in windows if w.is_normal]


def train(model_path: Path = MODEL_PATH) -> dict[str, Any]:
    """Train on normal windows from the DB and save the bundle.

    Raises:
        RuntimeError: if there are too few normal windows to train on.
    """
    events = load_events_from_db()
    all_windows = extract_windows(events)
    normal = select_normal_windows(all_windows)

    if len(normal) < MIN_TRAINING_WINDOWS:
        raise RuntimeError(
            f"Only {len(normal)} normal window(s) found (need at least "
            f"{MIN_TRAINING_WINDOWS}). Generate more traffic first: "
            "python -m simulation.normal_traffic"
        )
    if len(normal) < RECOMMENDED_TRAINING_WINDOWS:
        warnings.warn(
            f"Training on only {len(normal)} windows; "
            f"{RECOMMENDED_TRAINING_WINDOWS}+ is recommended for a stable model.",
            stacklevel=2,
        )

    X = windows_to_matrix(normal)
    model = build_model()
    model.fit(X)

    bundle = {
        "model": model,
        "feature_names": list(FEATURE_NAMES),
        "score_scale": SCORE_SCALE,
        "metadata": {
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "n_training_windows": int(len(normal)),
            "n_events_total": int(len(events)),
            "n_windows_total": int(len(all_windows)),
            "n_windows_excluded_non_normal": int(len(all_windows) - len(normal)),
            "window_seconds": WINDOW_SECONDS,
            "min_requests_per_window": MIN_REQUESTS_PER_WINDOW,
            "sklearn_version": sklearn.__version__,
        },
    }

    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model_path)

    scores = model.decision_function(X)
    bundle["metadata"]["training_decision_min"] = float(np.min(scores))
    bundle["metadata"]["training_decision_mean"] = float(np.mean(scores))
    return bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the NIGRAANI Isolation Forest.")
    parser.add_argument("--output", type=Path, default=MODEL_PATH, help="model path (default: models/iforest.joblib)")
    args = parser.parse_args(argv)

    try:
        bundle = train(args.output)
    except RuntimeError as exc:
        print(f"Training failed: {exc}", file=sys.stderr)
        return 1

    meta = bundle["metadata"]
    try:
        shown = args.output.resolve().relative_to(REPO_ROOT)
    except ValueError:
        shown = args.output
    print(f"Saved model to {shown}")
    print(f"  training windows : {meta['n_training_windows']} "
          f"(of {meta['n_windows_total']} total, {meta['n_windows_excluded_non_normal']} non-normal excluded)")
    print(f"  feature order    : {', '.join(bundle['feature_names'])}")
    print(f"  decision_function on training data: min={meta['training_decision_min']:.3f} "
          f"mean={meta['training_decision_mean']:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
