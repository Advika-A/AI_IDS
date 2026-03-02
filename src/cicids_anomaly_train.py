import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# Load cleaned data
df = pd.read_csv("data/cicids2017/cicids_clean.csv")

# Selected features
features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count"
]

X = df[features]
y = df["Label"]

# Train only on BENIGN traffic
X_normal = X[y == "BENIGN"]

# Scale
scaler = StandardScaler()
X_normal_scaled = scaler.fit_transform(X_normal)

# Isolation Forest
iso = IsolationForest(
    n_estimators=300,
    contamination=0.1,
    random_state=42,
    n_jobs=-1
)
iso.fit(X_normal_scaled)

# Save model and scaler
joblib.dump(iso, "models/cicids_isolation_forest.pkl")
joblib.dump(scaler, "models/cicids_scaler.pkl")

print("Isolation Forest trained on CICIDS2017 BENIGN traffic")
print("Training samples:", X_normal.shape[0])
