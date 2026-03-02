"""
Train a minimal Isolation Forest compatible with the API's ISO_FEATURES.
Run this when cicids_isolation_forest.pkl is missing (no CICIDS dataset required).
"""
import sys
from pathlib import Path

import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

# Ensure we can import from project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

MODELS_DIR = PROJECT_ROOT / "models"
MODELS_DIR.mkdir(exist_ok=True)

ISO_FEATURES = [
    "Average Packet Size",
    "Max Packet Length",
    "Packet Length Mean",
    "Bwd Packet Length Max",
    "Bwd Packet Length Std",
    "Avg Bwd Segment Size",
    "Fwd Packet Length Mean",
    "Min Packet Length",
    "Destination Port",
    "Init_Win_bytes_backward",
    "Flow Duration",
    "Total Fwd Packets",
]


def main():
    np.random.seed(42)
    n_samples = 5000

    # Synthetic benign-like traffic (rough CICIDS ranges)
    data = {
        "Average Packet Size": np.clip(np.random.exponential(400, n_samples), 40, 6000),
        "Max Packet Length": np.clip(np.random.exponential(800, n_samples), 40, 65000),
        "Packet Length Mean": np.clip(np.random.exponential(350, n_samples), 40, 5000),
        "Bwd Packet Length Max": np.clip(np.random.exponential(600, n_samples), 0, 65000),
        "Bwd Packet Length Std": np.clip(np.random.exponential(150, n_samples), 0, 5000),
        "Avg Bwd Segment Size": np.clip(np.random.exponential(300, n_samples), 0, 5000),
        "Fwd Packet Length Mean": np.clip(np.random.exponential(350, n_samples), 40, 5000),
        "Min Packet Length": np.random.choice([40, 60, 80], n_samples),
        "Destination Port": np.random.choice([80, 443, 53, 22, 8080, 3306], n_samples),
        "Init_Win_bytes_backward": np.clip(np.random.exponential(1000, n_samples), 0, 65535),
        "Flow Duration": np.clip(np.random.exponential(5000, n_samples), 0, 120000),
        "Total Fwd Packets": np.clip(np.random.exponential(50, n_samples), 1, 1000),
    }

    X = np.column_stack([data[f] for f in ISO_FEATURES])

    iso = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X)

    out_path = MODELS_DIR / "cicids_isolation_forest.pkl"
    joblib.dump(iso, out_path)
    print(f"Isolation Forest saved to {out_path}")
    print(f"Features: {ISO_FEATURES}")


if __name__ == "__main__":
    main()
