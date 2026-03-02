import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# -----------------------------
# Load dataset
# -----------------------------
columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "label","difficulty"
]

df = pd.read_csv("data/KDDTrain+.txt", names=columns)

# -----------------------------
# Binary label
# -----------------------------
df["label"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)

# -----------------------------
# Encode categorical features
# -----------------------------
categorical_cols = ["protocol_type", "service", "flag"]
encoder = LabelEncoder()

for col in categorical_cols:
    df[col] = encoder.fit_transform(df[col])

# -----------------------------
# Feature selection
# -----------------------------
features = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "logged_in","count","srv_count","same_srv_rate","diff_srv_rate",
    "dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate"
]

X = df[features]
y = df["label"]

# -----------------------------
# Train-test split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

# -----------------------------
# Train Random Forest
# -----------------------------
rf = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    n_jobs=-1
)

rf.fit(X_train, y_train)

# -----------------------------
# Evaluate
# -----------------------------
y_pred = rf.predict(X_test)

print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))
import numpy as np

from sklearn.ensemble import IsolationForest

# -----------------------------
# Train Isolation Forest on NORMAL traffic only
# -----------------------------
normal_data = X_train[y_train == 0]

iso_forest = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)

iso_forest.fit(normal_data)

# -----------------------------
# Test anomaly detection
# -----------------------------
iso_pred = iso_forest.predict(X_test)

# Isolation Forest outputs:
#  1  -> Normal
# -1  -> Anomaly

anomalies = (iso_pred == -1).sum()

print("\nAnomaly Detection Results:")
print("Total test samples:", len(X_test))
print("Anomalies detected:", anomalies)


# Feature importance
importances = rf.feature_importances_
indices = np.argsort(importances)[::-1]

print("\nTop 10 Important Features:")
for i in range(10):
    print(f"{features[indices[i]]}: {importances[indices[i]]:.4f}")

