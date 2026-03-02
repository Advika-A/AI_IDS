from dataclasses import dataclass
from typing import Dict, Set, Tuple


@dataclass
class DefenseResult:
    suspicious_count: int
    ip_blocked: bool
    severity: str
    final_verdict: str
    recommendation: str


class DefenseManager:
    def __init__(self) -> None:
        self.suspicious_ip_counts: Dict[str, int] = {}
        self.blocked_ips: Set[str] = set()

    def is_ip_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def register_block(self, ip: str) -> None:
        self.blocked_ips.add(ip)

    def register_behavior(
        self,
        ip: str,
        base_verdict: str,
        rf_decision: str,
        rf_confidence: float,
        if_decision: str,
    ) -> DefenseResult:
        """
        Update suspicious counters and decide on escalation / blocking.
        """
        suspicious_count = self.suspicious_ip_counts.get(ip, 0)

        # Base rule: suspicious / attack-like verdicts increase suspicion
        if base_verdict in {"Suspicious", "Attack"} or rf_decision == "Attack":
            suspicious_count += 1
            self.suspicious_ip_counts[ip] = suspicious_count

        ip_blocked = False
        severity = self._map_base_severity(base_verdict, rf_confidence)
        final_verdict = base_verdict
        recommendation = ""

        # Escalate if repeated suspicious behavior
        if suspicious_count >= 3 and base_verdict != "Normal":
            final_verdict = "Attack"
            severity = "HIGH"
            recommendation = (
                "IP has shown repeated suspicious activity. Treat as an active attack."
            )

        # Simulated IP blocking
        if (rf_decision == "Attack" and rf_confidence > 0.85) or suspicious_count >= 5:
            self.register_block(ip)
            ip_blocked = True
            final_verdict = "Attack"
            severity = "CRITICAL"
            recommendation = (
                "Traffic from this IP is blocked due to repeated or high-confidence attacks."
            )

        # Fallback recommendation text if still empty
        if not recommendation:
            if final_verdict == "Normal":
                recommendation = "Traffic looks safe. No action required."
            elif final_verdict == "Suspicious":
                recommendation = "Watch this IP more closely and review logs."
            else:
                recommendation = "Investigate this IP and consider blocking in production."

        return DefenseResult(
            suspicious_count=suspicious_count,
            ip_blocked=ip_blocked,
            severity=severity,
            final_verdict=final_verdict,
            recommendation=recommendation,
        )

    @staticmethod
    def _map_base_severity(base_verdict: str, rf_confidence: float) -> str:
        """
        Threat severity mapping:
        - Normal → LOW
        - Suspicious → MEDIUM
        - Attack (low confidence) → HIGH
        - Attack (high confidence) → CRITICAL
        """
        if base_verdict == "Normal":
            return "LOW"
        if base_verdict == "Suspicious":
            return "MEDIUM"
        if base_verdict == "Attack":
            return "CRITICAL" if rf_confidence >= 0.85 else "HIGH"
        # default fallback
        return "MEDIUM"


defense_manager = DefenseManager()

