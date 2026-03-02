import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest

# Sample dataset
data = {
    "duration": [0.1, 0.2, 0.15, 0.18, 2.5],
    "src_bytes": [100, 120, 90, 110, 5000],
    "dst_bytes": [400, 450, 420, 410, 20],
    "label": ["Normal", "Normal", "Normal", "Normal", "Attack"]
}

df = pd.DataFrame(data)

# ------------------
# Supervised Model
# ------------------
X = df[["duration", "src_bytes", "dst_bytes"]]
y = df["label"]

rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X, y)

# ------------------
# Anomaly Detection (train only on NORMAL data)
# ------------------
normal_data = df[df["label"] == "Normal"][["duration", "src_bytes", "dst_bytes"]]

iso_model = IsolationForest(contamination=0.2, random_state=42)
iso_model.fit(normal_data)

# ------------------
# Test new traffic
# ------------------
new_traffic = [[3.0, 6000, 15]]

rf_pred = rf_model.predict(new_traffic)[0]
iso_pred = iso_model.predict(new_traffic)[0]

print("Random Forest Prediction:", rf_pred)

if iso_pred == -1:
    print("Anomaly Detection: Suspicious traffic detected")
else:
    print("Anomaly Detection: Normal traffic")
