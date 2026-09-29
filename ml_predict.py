"""
ml_predict.py
--------------
Loads the trained models (joblib .pkl files) and runs predictions on
new, cleaned traffic data. Produces, for every row:
    - is_anomaly (True/False)
    - risk_score (0-100)
    - risk_level (Low/Medium/High)
    - explanation (short text)
"""

import os
import joblib
import pandas as pd

from preprocessing import extract_features, FEATURE_COLUMNS
from risk_scoring import (
    normalize_isolation_score,
    compute_risk_score,
    risk_level_from_score,
    explain_row,
)

MODELS_DIR = "models"


class ModelNotTrainedError(Exception):
    pass


def _model_paths():
    return {
        "iso": os.path.join(MODELS_DIR, "isolation_forest.pkl"),
        "rf": os.path.join(MODELS_DIR, "random_forest.pkl"),
        "scaler": os.path.join(MODELS_DIR, "scaler.pkl"),
    }


def models_exist() -> bool:
    paths = _model_paths()
    return all(os.path.exists(p) for p in paths.values())


def load_models():
    if not models_exist():
        raise ModelNotTrainedError(
            "ML models not found. Run 'python train_model.py' first."
        )
    paths = _model_paths()
    iso_forest = joblib.load(paths["iso"])
    rf_clf = joblib.load(paths["rf"])
    scaler = joblib.load(paths["scaler"])
    return iso_forest, rf_clf, scaler


def predict(df_clean: pd.DataFrame) -> pd.DataFrame:
    """
    df_clean: output of preprocessing.clean_data()
    Returns df_clean with extra prediction columns appended.
    """
    iso_forest, rf_clf, scaler = load_models()

    features = extract_features(df_clean)
    X_scaled = scaler.transform(features[FEATURE_COLUMNS])

    # Isolation Forest: decision_function -> higher = more normal
    iso_raw_scores = iso_forest.decision_function(X_scaled)
    iso_predictions = iso_forest.predict(X_scaled)  # -1 = anomaly, 1 = normal

    # Random Forest: probability of class 1 (anomaly)
    rf_probabilities = rf_clf.predict_proba(X_scaled)[:, 1]

    results = df_clean.copy()
    risk_scores = []
    risk_levels = []
    explanations = []
    is_anomaly_flags = []

    for i in range(len(results)):
        iso_likelihood = normalize_isolation_score(iso_raw_scores[i])
        rf_prob = float(rf_probabilities[i])

        score = compute_risk_score(iso_likelihood, rf_prob)
        level = risk_level_from_score(score)

        # Final anomaly flag: either model agrees it's suspicious
        is_anomaly = bool(iso_predictions[i] == -1 or rf_prob >= 0.5)

        row_dict = features.iloc[i].to_dict()
        explanation = explain_row(row_dict, score) if is_anomaly else "Normal traffic pattern."

        risk_scores.append(score)
        risk_levels.append(level)
        explanations.append(explanation)
        is_anomaly_flags.append(is_anomaly)

    results["is_anomaly"] = is_anomaly_flags
    results["risk_score"] = risk_scores
    results["risk_level"] = risk_levels
    results["explanation"] = explanations

    return results
