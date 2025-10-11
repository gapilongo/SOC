"""Human loop escalation agent."""
# src/lg_sotf/agents/human_loop/escalation.py
from datetime import datetime

from .base import HumanLoopAgent


class EscalationManager:
    def __init__(self, human_agent: HumanLoopAgent):
        self.agent = human_agent

    def evaluate_alert(self, alert_id: str, confidence_score: float):
        """
        Decide if alert needs human escalation
        """
        if confidence_score < self.agent.escalation_threshold:
            self.agent.pending_alerts[alert_id] = {
                "alert_data": {"confidence_score": confidence_score},
                "received_at": datetime.utcnow(),
                "status": "pending",
                "feedback": None,
            }
            return True
        return False
