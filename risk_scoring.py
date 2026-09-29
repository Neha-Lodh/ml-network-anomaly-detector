"""
risk_scoring.py
-----------------
Converts raw ML outputs (Isolation Forest anomaly score + Random Forest
probability) into:
  - a simple 0-100 "risk_score"
  - a risk_level label: Low / Medium / High
  - a short, human-readable explanation of WHY the row looks risky

This is a project-defined scoring scheme (not a real-world standard),
kept simple on purpose so it's easy to explain in a viva.
"""

import numpy as np

# Heuristic thresholds used only for generating a human explanation.
PORT_SCAN_DST_PORT_HINT = True  # unusual/uncommon destination port
HIGH_FAILED_CONN_THRESHOLD = 3
HIGH_PACKET_COUNT_THRESHOLD = 400
HIGH_BYTES_THRESHOLD = 100000
SHORT_DURATION_THRESHOLD = 0.15
COMMON_PORTS = {80, 443, 22, 21, 25, 53, 3389, 8080, 445, 3306}


def normalize_isolation_score(raw_score: float) -> float:
    """
    scikit-learn's IsolationForest.decision_function() returns roughly
    [-0.5, 0.5], where LOWER (more negative) = more anomalous.
    We flip and rescale this to a 0-1 "anomaly likelihood".
    """
    # clip to a reasonable range then rescale
    clipped = np.clip(raw_score, -0.5, 0.5)
    likelihood = (0.5 - clipped) / 1.0  # 0 (normal) .. 1 (anomalous)
    return float(np.clip(likelihood, 0, 1))


def compute_risk_score(iso_anomaly_likelihood: float, rf_anomaly_probability: float) -> int:
    """
    Combine the two model signals into a single 0-100 risk score.
    Simple weighted average - easy to explain:
        60% Isolation Forest (unsupervised outlier signal)
        40% Random Forest (supervised classification confidence)
    """
    combined = (0.6 * iso_anomaly_likelihood) + (0.4 * rf_anomaly_probability)
    score = int(round(combined * 100))
    return max(0, min(100, score))


def risk_level_from_score(score: int) -> str:
    if score < 40:
        return "Low"
    elif score < 70:
        return "Medium"
    else:
        return "High"


def explain_row(row: dict, score: int) -> str:
    """
    Build a short, plain-English explanation for a single traffic row
    based on simple rule checks (NOT the ML model internals - this is
    just to make the output understandable to a human/beginner).
    """
    reasons = []

    if row.get("failed_connections", 0) >= HIGH_FAILED_CONN_THRESHOLD:
        reasons.append(f"{int(row['failed_connections'])} failed connection attempts")

    if row.get("packet_count", 0) >= HIGH_PACKET_COUNT_THRESHOLD:
        reasons.append(f"unusually high packet count ({int(row['packet_count'])})")

    if row.get("bytes_transferred", 0) >= HIGH_BYTES_THRESHOLD:
        reasons.append(f"large data volume ({int(row['bytes_transferred'])} bytes)")

    if row.get("duration", 1) <= SHORT_DURATION_THRESHOLD and row.get("packet_count", 0) > 1:
        reasons.append("very short connection duration")

    dst_port = row.get("dst_port")
    if dst_port is not None and int(dst_port) not in COMMON_PORTS:
        reasons.append(f"uncommon destination port ({int(dst_port)})")

    if not reasons:
        if score >= 70:
            reasons.append("traffic pattern statistically deviates from normal baseline")
        else:
            return "No significant anomaly indicators detected."

    return "Flagged due to: " + "; ".join(reasons) + "."
