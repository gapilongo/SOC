"""Base class for human loop agent."""
# src/lg_sotf/agents/human_loop/base.py
from datetime import datetime, timedelta
from typing import Any, Dict


class HumanLoopAgent:
    def __init__(self, escalation_threshold: float = 0.6, sla_hours: int = 4):
        """
        Parameters:
        - escalation_threshold: alerts below this confidence go to human review
        - sla_hours: SLA for human feedback
        """
        self.escalation_threshold = escalation_threshold
        self.sla = timedelta(hours=sla_hours)
        self.pending_alerts: Dict[str, Dict[str, Any]] = {}

    def receive_alert(self, alert_id: str, alert_data: Dict[str, Any]):
        """Add alert for human review."""
        self.pending_alerts[alert_id] = {
            "alert_data": alert_data,
            "received_at": datetime.utcnow(),
            "status": "pending",
            "feedback": None,
        }

    def get_pending_alerts(self):
        """Return pending alerts that need human attention."""
        return {
            aid: a for aid, a in self.pending_alerts.items() if a["status"] == "pending"
        }

    def submit_feedback(self, alert_id: str, feedback: Dict[str, Any]):
        """Store human analyst feedback."""
        if alert_id in self.pending_alerts:
            self.pending_alerts[alert_id]["feedback"] = feedback
            self.pending_alerts[alert_id]["status"] = "reviewed"
