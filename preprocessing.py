"""
preprocessing.py
-----------------
Cleans a raw network-traffic CSV/DataFrame and extracts the numeric
features used by the ML model.

Expected raw columns (case-insensitive, some optional):
    timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
    duration, packet_count, bytes_transferred, failed_connections

This module is intentionally simple and heavily commented so it is
easy to explain in a viva.
"""

import pandas as pd
import numpy as np

# Columns the rest of the app expects to exist after cleaning
REQUIRED_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "duration", "packet_count", "bytes_transferred",
    "failed_connections",
]

# Numeric columns used directly as ML features
NUMERIC_FEATURES = [
    "src_port", "dst_port", "duration", "packet_count",
    "bytes_transferred", "failed_connections",
]

PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2}


class DataValidationError(Exception):
    """Raised when the uploaded CSV is missing required columns."""
    pass


def load_and_validate(file_path_or_buffer):
    """Read a CSV and make sure the columns we need are present."""
    df = pd.read_csv(file_path_or_buffer)

    # normalise column names: lowercase + strip spaces
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise DataValidationError(
            f"CSV is missing required column(s): {', '.join(missing)}"
        )

    return df


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Basic, beginner-friendly cleaning steps:
      1. Drop exact duplicate rows
      2. Fill/repair missing numeric values
      3. Coerce numeric columns to numbers (bad values -> NaN -> filled)
      4. Clip impossible/negative values
      5. Normalise protocol text (upper-case, unknown -> 'OTHER')
    """
    df = df.copy()

    # 1. Remove duplicate rows
    df = df.drop_duplicates()

    # 2 & 3. Force numeric columns to be numeric; anything invalid becomes NaN
    for col in NUMERIC_FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Fill missing numeric values with the column median (robust to outliers)
    for col in NUMERIC_FEATURES:
        if df[col].isna().any():
            median_val = df[col].median()
            df[col] = df[col].fillna(median_val if not np.isnan(median_val) else 0)

    # 4. Clip negative values (durations/bytes/ports can't be negative)
    for col in NUMERIC_FEATURES:
        df[col] = df[col].clip(lower=0)

    # Ports must be within a valid range
    df["src_port"] = df["src_port"].clip(lower=0, upper=65535)
    df["dst_port"] = df["dst_port"].clip(lower=0, upper=65535)

    # 5. Normalise protocol text
    df["protocol"] = df["protocol"].astype(str).str.upper().str.strip()
    df["protocol"] = df["protocol"].where(df["protocol"].isin(PROTOCOL_MAP.keys()), "OTHER")

    # Fill missing IPs / timestamps with placeholders so display doesn't break
    df["src_ip"] = df["src_ip"].fillna("0.0.0.0").astype(str)
    df["dst_ip"] = df["dst_ip"].fillna("0.0.0.0").astype(str)
    df["timestamp"] = df["timestamp"].ffill()

    df = df.reset_index(drop=True)
    return df


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Turn the cleaned DataFrame into the numeric feature matrix the
    ML model was trained on. Returns a NEW DataFrame containing only
    feature columns (order matters - must match training order).
    """
    features = pd.DataFrame()
    features["src_port"] = df["src_port"]
    features["dst_port"] = df["dst_port"]
    features["duration"] = df["duration"]
    features["packet_count"] = df["packet_count"]
    features["bytes_transferred"] = df["bytes_transferred"]
    features["failed_connections"] = df["failed_connections"]

    # Encode protocol as a number (simple label encoding - easy to explain)
    features["protocol_encoded"] = df["protocol"].map(PROTOCOL_MAP).fillna(3).astype(int)

    # Engineered ratio feature: bytes per packet (helps flag DoS / scan patterns)
    features["bytes_per_packet"] = features["bytes_transferred"] / features["packet_count"].replace(0, 1)

    return features


FEATURE_COLUMNS = [
    "src_port", "dst_port", "duration", "packet_count",
    "bytes_transferred", "failed_connections", "protocol_encoded",
    "bytes_per_packet",
]
