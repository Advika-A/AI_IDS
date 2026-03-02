from typing import Dict, Any, List, Tuple


def generate_simple_explanations(data: Dict[str, Any]) -> List[str]:
    """
    High-level, non-technical explanations of traffic behaviour.
    """
    reasons: List[str] = []

    if float(data.get("Average Packet Size", 0) or 0) > 1200:
        reasons.append("Packets are larger than what we normally see.")

    if float(data.get("Flow Duration", 0) or 0) > 60000:
        reasons.append("The connection stayed open for an unusually long time.")

    if float(data.get("Total Fwd Packets", 0) or 0) > 800:
        reasons.append("A lot of packets were sent in one direction.")

    if int(float(data.get("Destination Port", 0) or 0)) not in [80, 443, 53]:
        reasons.append("Traffic is going to a less common port.")

    if not reasons:
        reasons.append("Traffic looks close to everyday usage.")

    return reasons


def group_features_for_dashboard(data: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Organise features into packet, flow, and port behaviour groups for the UI.
    Values are kept simple and suitable for bar charts / lists.
    """
    packet_keys = [
        "Average Packet Size",
        "Max Packet Length",
        "Packet Length Mean",
        "Bwd Packet Length Max",
        "Bwd Packet Length Std",
        "Avg Bwd Segment Size",
        "Fwd Packet Length Mean",
        "Min Packet Length",
    ]
    flow_keys = [
        "Flow Duration",
        "Total Fwd Packets",
    ]
    port_keys = [
        "Destination Port",
        "Init_Win_bytes_backward",
    ]

    def _collect(keys: List[str]) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for k in keys:
            v = data.get(k)
            try:
                v = float(v)
            except (TypeError, ValueError):
                v = 0.0
            items.append({"feature": k, "value": v})
        return items

    return {
        "packet_behavior": _collect(packet_keys),
        "flow_behavior": _collect(flow_keys),
        "port_behavior": _collect(port_keys),
    }


def adjust_confidence_for_disagreement(
    rf_confidence: float,
    models_agree: bool,
    reduction_factor: float = 0.7,
) -> Tuple[float, str]:
    """
    Apply adaptive confidence behaviour:
    - If models disagree, reduce displayed confidence.
    - Return new confidence and a short natural language explanation.
    """
    if models_agree:
        return rf_confidence, ""

    adjusted = round(rf_confidence * reduction_factor, 2)
    explanation = "Confidence reduced because the two models disagree on the traffic."
    return adjusted, explanation

