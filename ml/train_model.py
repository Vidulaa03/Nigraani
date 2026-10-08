from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from ml.features import FEATURE_COLUMNS, extract_features

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "iforest.joblib"


def train_model(
    normal_events: list[dict[str, Any]],
    model_path: Path | None = None,
) -> Path:
    """Train on an explicitly normal-only event dataset; event labels are ignored."""
    if model_path is None:
        model_path = MODEL_PATH
    features = extract_features(normal_events)
    if len(features) < 2:
        raise ValueError(
            "At least two complete normal-traffic windows are required to train the model"
        )

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
    )
    model.fit(features.loc[:, FEATURE_COLUMNS])
    training_scores = model.decision_function(features.loc[:, FEATURE_COLUMNS])
    score_floor = min(float(np.min(training_scores)), -1e-9)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "feature_columns": FEATURE_COLUMNS,
            "score_floor": score_floor,
        },
        model_path,
    )
    return model_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train the Isolation Forest from an explicitly normal-only JSON event file."
    )
    parser.add_argument(
        "normal_events",
        type=Path,
        help="JSON file containing only known-normal security events",
    )
    parser.add_argument("--output", type=Path, default=MODEL_PATH)
    args = parser.parse_args()
    with args.normal_events.open(encoding="utf-8") as file:
        events = json.load(file)
    if not isinstance(events, list):
        raise ValueError("The normal-events JSON file must contain a list of event objects")
    model_path = train_model(events, args.output)
    print(f"Saved Isolation Forest model to {model_path}")


if __name__ == "__main__":
    main()
