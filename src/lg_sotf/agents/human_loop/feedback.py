"""Human loop feedback agent."""
# src/lg_sotf/agents/human_loop/feedback.py

from .base import HumanLoopAgent


class FeedbackCollector:
    def __init__(self, human_agent: HumanLoopAgent):
        self.agent = human_agent

    def collect_feedback(
        self, alert_id: str, analyst: str, decision: str, notes: str = ""
    ):
        """
        Store structured feedback
        """
        feedback = {
            "analyst": analyst,
            "decision": decision,  # "approve", "deny", "more_info"
            "notes": notes,
        }
        self.agent.submit_feedback(alert_id, feedback)
