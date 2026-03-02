    Overview

AI_IDS is a hybrid Intrusion Detection System (IDS) with adaptive Intrusion Prevention (IPS) capabilities. It combines supervised and unsupervised machine learning models to detect known attacks and anomalous network behavior in real time.

The system includes confidence-aware model agreement, explainable decision output, rate limiting, and automatic IP escalation and blocking.

    Key Features

-Hybrid detection using Random Forest and Isolation Forest

-Confidence scoring with disagreement adjustment

-Per-IP suspicious activity tracking

-Automatic escalation and IP blocking logic

-Structured explainability with feature grouping

-Real-time interactive dashboard

-Rate limiting and API key authentication

-Modular Flask backend architecture

    Architecture

-Detection Layer

  Random Forest for supervised attack classification

  Isolation Forest for anomaly detection

  Model agreement logic with confidence adjustment

-Defense Layer

  Suspicious count tracking per IP

  Escalation thresholds for repeated anomalies

  Automatic blocking under high-risk conditions

-Explainability Layer

  Plain-language reasoning

  Feature behavior grouping (packet, flow, port)

  Structured JSON output for UI integration

    Technology Stack

-Backend

  Python

  Flask

  scikit-learn

  joblib

-Frontend

  HTML

  CSS

  Vanilla JavaScript

  Chart.js

    API Endpoint

POST /predict

Authentication via X-API-KEY header.
Returns structured detection result including:

-Final verdict

-Severity level

-Confidence score

-Model agreement

-Defense actions

-Feature-based explanations

    Running the Project

-Install dependencies:

  pip install -r requirements.txt

-Run the backend:

  python src/api.py

-Access dashboard:

  http://127.0.0.1:5000/
  
    Highlights

-Combines supervised and unsupervised ML in a unified detection pipeline

-Implements adaptive security response logic beyond basic classification

Integrates explainability directly into real-time threat reporting

Designed with modular, production-aware backend structure
