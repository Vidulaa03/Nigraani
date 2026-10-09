from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
from functools import lru_cache

from ml.features import FEATURE_COLUMNS, extract_features
from ml.train_model import MODEL_PATH


@lru_cache(maxsize=4)
def _load_model(model_path: str, modified_ns: int) -> dict[str, Any]:
    return joblib.load(model_path)


def score(
    events: list[dict[str, Any]],
    model_path: Path | None = None,
) -> int:
    if model_path is None:
        model_path = MODEL_PATH
    if not model_path.is_file():
        raise FileNotFoundError(
            f"Isolation Forest model not found at {model_path}. "
            "Train it with `python -m ml.train_model <normal-only-events.json>` first."
        )

    features = extract_features(events)
    if features.empty:
        return 0

    artifact = _load_model(str(model_path), model_path.stat().st_mtime_ns)
    model = artifact["model"]
    feature_columns = artifact["feature_columns"]
    score_floor = float(artifact["score_floor"])
    model_scores = model.decision_function(features.loc[:, feature_columns])
    most_anomalous = float(min(model_scores))
    if most_anomalous >= 0:
        return 0
    return min(100, max(0, round(100 * -most_anomalous / abs(score_floor))))
