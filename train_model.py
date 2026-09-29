"""
train_model.py
----------------
Trains the two ML models used by this project and saves them to
/models using joblib:

  1. IsolationForest  -> unsupervised anomaly detector
                         (learns what "normal" traffic looks like,
                          flags statistical outliers)
  2. RandomForestClassifier -> supervised classifier
                         (learns from labelled normal/anomalous
                          examples so it can output a confidence
                          probability for new traffic)

Run from the project root:
    python train_model.py
"""

import os
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from preprocessing import load_and_validate, clean_data, extract_features, FEATURE_COLUMNS

DATA_PATH = os.path.join("data", "sample_network_traffic.csv")
MODELS_DIR = "models"

# A row is treated as "anomalous" for supervised training purposes if it
# matches simple heuristic patterns (this creates weak/pseudo labels from
# the synthetic data, which is normal practice for an educational project
# that doesn't have hand-labelled ground truth).
def pseudo_label(features: pd.DataFrame) -> pd.Series:
    conditions = (
        (features["failed_connections"] >= 3)
        | (features["packet_count"] >= 400)
        | (features["bytes_transferred"] >= 100000)
        | ((features["duration"] <= 0.15) & (features["packet_count"] > 1))
    )
    return conditions.astype(int)  # 1 = anomaly, 0 = normal


def main():
    print("1) Loading & validating dataset...")
    df = load_and_validate(DATA_PATH)

    print("2) Cleaning data...")
    df_clean = clean_data(df)

    print("3) Extracting features...")
    features = extract_features(df_clean)
    labels = pseudo_label(features)
    print(f"   -> {len(features)} rows | {labels.sum()} pseudo-labelled anomalies")

    print("4) Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features[FEATURE_COLUMNS])

    print("5) Training IsolationForest (unsupervised)...")
    iso_forest = IsolationForest(
        n_estimators=150,
        contamination=0.15,
        random_state=42,
    )
    iso_forest.fit(X_scaled)

    print("6) Training RandomForestClassifier (supervised)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, labels, test_size=0.2, random_state=42, stratify=labels
    )
    rf_clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        random_state=42,
        class_weight="balanced",
    )
    rf_clf.fit(X_train, y_train)
    accuracy = rf_clf.score(X_test, y_test)
    print(f"   -> RandomForest test accuracy: {accuracy:.3f}")

    print("7) Saving models to /models ...")
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(iso_forest, os.path.join(MODELS_DIR, "isolation_forest.pkl"))
    joblib.dump(rf_clf, os.path.join(MODELS_DIR, "random_forest.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.pkl"))

    print("Done. Models saved in the models/ folder.")


if __name__ == "__main__":
    main()
