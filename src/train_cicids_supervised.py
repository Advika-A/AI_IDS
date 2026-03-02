import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import joblib

# ==============================
# 1. Load cleaned CICIDS dataset
# ==============================

data_path = "data/cicids2017/cicids_cleaned.csv"
df = pd.read_csv(data_path)

print("Dataset shape:", df.shape)

# ==============================
# 2. Binary label conversion
# ==============================

df["Label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

print("\nLabel distribution:")
print(df["Label"].value_counts())

# ==============================
# 3. Drop leakage features
# ==============================

leakage_cols = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp"
]

df.drop(columns=[c for c in leakage_cols if c in df.columns], inplace=True)

# ==============================
# 4. Handle missing / infinite
# ==============================

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# ==============================
# 5. Train-test split
# ==============================

X = df.drop("Label", axis=1)
y = df["Label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

print("\nTraining samples:", X_train.shape[0])
print("Testing samples:", X_test.shape[0])

# ==============================
# 6. Train Random Forest
# ==============================

rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=None,
    n_jobs=-1,
    random_state=42
)

rf.fit(X_train, y_train)

# ==============================
# 7. Evaluation
# ==============================

y_pred = rf.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# ==============================
# 8. Feature importance
# ==============================

importances = pd.Series(rf.feature_importances_, index=X.columns)
top_features = importances.sort_values(ascending=False).head(10)

print("\nTop 10 Important Features:")
print(top_features)

# ==============================
# 9. Save model (LOCAL ONLY)
# ==============================

joblib.dump(rf, "models/rf_cicids_supervised.pkl")
print("\nModel saved successfully.")
