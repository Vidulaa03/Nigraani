"""Machine-learning anomaly detection for NIGRAANI (Person 3).

Modules:
    features         - turn ``security_events`` rows into per-IP window features
    train_model      - train an Isolation Forest on NORMAL traffic only
    anomaly_detector - load the saved model and score windows (ml_score 0-100)
"""
