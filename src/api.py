import logging
import os
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import joblib
import numpy as np

from security import require_api_key, apply_rate_limit, get_client_ip
from defense import defense_manager
from explainability import (
    generate_simple_explanations,
    group_features_for_dashboard,
    adjust_confidence_for_disagreement,
)

print("API FILE STARTED")

# -----------------------------
# Paths (project root = parent of src/)
# -----------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# -----------------------------
# App Setup
# -----------------------------
app = Flask(__name__, static_folder=str(PROJECT_ROOT / "frontend"))
CORS(app)

# API key stored in config (override with environment variable in production)
app.config["IDS_API_KEY"] = os.environ.get("IDS_API_KEY", "demo-secret-key")

# -----------------------------
# Logging Setup
# -----------------------------
logs_dir = PROJECT_ROOT / "logs"
logs_dir.mkdir(exist_ok=True)
log_path = logs_dir / "ids.log"

logger = logging.getLogger("ids_logger")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.FileHandler(log_path, encoding="utf-8")
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# -----------------------------
# Load Models
# -----------------------------
MODELS_DIR = PROJECT_ROOT / "models"
RF_PATH = MODELS_DIR / "rf_cicids_supervised.pkl"
ISO_PATH = MODELS_DIR / "cicids_isolation_forest.pkl"

if not ISO_PATH.exists():
    raise FileNotFoundError(
        f"Isolation Forest model not found at {ISO_PATH}. "
        "Run: python scripts/train_minimal_isolation_forest.py"
    )
if not RF_PATH.exists():
    raise FileNotFoundError(
        f"Random Forest model not found at {RF_PATH}. "
        "Run: python src/train_cicids_supervised.py (requires CICIDS data)"
    )

rf_model = joblib.load(RF_PATH)
iso_model = joblib.load(ISO_PATH)

# -----------------------------
# Feature Definitions
# -----------------------------
RF_FEATURES = list(rf_model.feature_names_in_)

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

ALL_REQUIRED_FEATURES = sorted(set(RF_FEATURES) | set(ISO_FEATURES))


def validate_input_payload(payload):
    """
    Basic input validation:
    - JSON must be an object
    - Values must be numeric and non-negative when present
    - Ports must be in a realistic range
    - Missing features are allowed (defaulted to 0 in prediction)
    """
    if not isinstance(payload, dict):
        return False, "Request body must be a JSON object."

    for feature, raw_value in payload.items():
        try:
            value = float(raw_value)
        except (TypeError, ValueError):
            return False, f"Feature '{feature}' must be numeric."

        if value < 0:
            return False, f"Feature '{feature}' cannot be negative."

        if feature == "Destination Port":
            port = int(value)
            if port <= 0 or port > 65535:
                return False, "Destination Port must be between 1 and 65535."

    return True, ""


# -----------------------------
# Serve Frontend
# -----------------------------
@app.route("/")
def home():
    return send_from_directory(app.static_folder, "index_ids.html")


# -----------------------------
# Prediction API
# -----------------------------
@app.route("/predict", methods=["POST"])
@require_api_key
@apply_rate_limit
def predict():
    client_ip = get_client_ip()

    # Immediate block if IP already marked as blocked
    if defense_manager.is_ip_blocked(client_ip):
        logger.warning("Blocked IP attempted access - ip=%s", client_ip)
        return jsonify(
            {
                "verdict": "BLOCKED",
                "message": "Your IP has been temporarily blocked due to repeated malicious behavior.",
            }
        )

    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Malformed JSON body."}), 400

    is_valid, validation_error = validate_input_payload(data)
    if not is_valid:
        return jsonify({"error": validation_error}), 400

    try:
        # ---------- Random Forest ----------
        X_rf = np.array([float(data.get(f, 0)) for f in RF_FEATURES]).reshape(1, -1)
        rf_pred = int(rf_model.predict(X_rf)[0])
        rf_prob = rf_model.predict_proba(X_rf)[0]
        rf_conf = float(np.max(rf_prob))

        # ---------- Isolation Forest ----------
        X_iso = np.array([float(data.get(f, 0)) for f in ISO_FEATURES]).reshape(1, -1)
        iso_pred_num = int(iso_model.predict(X_iso)[0])
        iso_decision = "Anomalous" if iso_pred_num == -1 else "Normal"

        # ---------- Model Decisions ----------
        rf_decision = "Attack" if rf_pred == 1 else "Normal"
        models_agree = (rf_decision == "Attack" and iso_decision == "Anomalous") or (
            rf_decision == "Normal" and iso_decision == "Normal"
        )

        # ---------- Base Final Verdict ----------
        if rf_pred == 1:
            base_verdict = "Attack"
        elif rf_pred == 0 and iso_pred_num == -1:
            base_verdict = "Suspicious"
        else:
            base_verdict = "Normal"

        # Adaptive confidence behaviour
        adjusted_confidence, confidence_explanation = adjust_confidence_for_disagreement(
            rf_conf, models_agree
        )

        # Defense & escalation
        defense_result = defense_manager.register_behavior(
            ip=client_ip,
            base_verdict=base_verdict,
            rf_decision=rf_decision,
            rf_confidence=rf_conf,
            if_decision=iso_decision,
        )

        final_verdict = defense_result.final_verdict
        severity = defense_result.severity

        # Simple, examiner-friendly explanations
        feature_explanations = generate_simple_explanations(data)

        # Group features for UI
        grouped_features = group_features_for_dashboard(data)

        # Structured logging
        logger.info(
            "ip=%s rf_decision=%s rf_conf=%.3f if_decision=%s agreement=%s final_verdict=%s severity=%s suspicious_count=%d ip_blocked=%s",
            client_ip,
            rf_decision,
            rf_conf,
            iso_decision,
            "yes" if models_agree else "no",
            final_verdict,
            severity,
            defense_result.suspicious_count,
            defense_result.ip_blocked,
        )

        response = {
            "final_verdict": final_verdict,
            "severity": severity,
            "confidence": round(adjusted_confidence, 2),
            "confidence_explanation": confidence_explanation,
            "model_results": {
                "random_forest": {
                    "decision": rf_decision,
                    "confidence": round(rf_conf, 2),
                },
                "isolation_forest": {
                    "decision": iso_decision,
                },
                "agreement": models_agree,
            },
            "feature_analysis": grouped_features,
            "defense_actions": {
                "ip_blocked": defense_result.ip_blocked,
                "suspicious_count": defense_result.suspicious_count,
                "recommendation": defense_result.recommendation,
            },
            "feature_explanations": feature_explanations,
        }

        return jsonify(response)

    except Exception as e:
        logger.exception("Error during prediction for ip=%s", client_ip)
        return jsonify({"error": str(e)}), 500


print("ABOUT TO START FLASK")

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False,
    )
