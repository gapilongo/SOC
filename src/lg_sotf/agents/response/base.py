"""
Production-grade Response Agent for automated threat response.

This agent executes automated response actions based on threat analysis,
following pre-defined playbooks for different threat scenarios.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from lg_sotf.agents.base import BaseAgent
from lg_sotf.agents.response.playbook import (
    PlaybookRegistry,
    ResponseAction,
    ResponsePlaybook,
    RiskLevel
)
from lg_sotf.core.exceptions import AgentError
from lg_sotf.tools.orchestrator import ToolOrchestrator


class ResponseAgent(BaseAgent):
    """Production-grade response agent for automated threat remediation.

    This agent:
    1. Analyzes alert threat type and confidence
    2. Selects appropriate response playbook
    3. Executes automated response actions via tool orchestrator
    4. Handles approval workflows for high-risk actions
    5. Maintains detailed audit trail of all actions

    Follows project best practices:
    - Returns only state updates (LangGraph pattern)
    - Async execution with proper error handling
    - Comprehensive logging and metrics
    - Configurable risk thresholds
    - Graceful degradation on failures
    """

    def __init__(
        self,
        config: Dict[str, Any],
        tool_orchestrator: Optional[ToolOrchestrator] = None
    ):
        """Initialize the response agent.

        Args:
            config: Agent configuration dictionary
            tool_orchestrator: Tool orchestrator for executing actions
        """
        super().__init__(config)
        self.logger = logging.getLogger(__name__)

        # Tool orchestrator for executing response actions
        self.tool_orchestrator = tool_orchestrator

        # Playbook registry
        self.playbook_registry = PlaybookRegistry()

        # Response configuration
        self.enabled = self.get_config("enabled", True)
        self.dry_run_mode = self.get_config("dry_run_mode", False)
        self.auto_approve_low_risk = self.get_config("auto_approve_low_risk", True)
        self.auto_approve_medium_risk = self.get_config("auto_approve_medium_risk", False)
        self.auto_approve_high_risk = self.get_config("auto_approve_high_risk", False)
        self.max_parallel_actions = self.get_config("max_parallel_actions", 3)
        self.action_timeout = self.get_config("action_timeout", 60)

        # Statistics
        self._actions_executed = 0
        self._actions_failed = 0
        self._playbooks_executed = 0

    async def initialize(self):
        """Initialize the response agent."""
        try:
            self.logger.info("Initializing response agent")

            # Validate configuration
            self.validate_config()

            # Verify tool orchestrator is available
            if not self.tool_orchestrator and not self.dry_run_mode:
                self.logger.warning(
                    "Tool orchestrator not available - response actions will be simulated"
                )
                self.dry_run_mode = True

            # Load custom playbooks if configured
            await self._load_custom_playbooks()

            self.initialized = True
            self.logger.info(
                f"Response agent initialized - "
                f"Mode: {'DRY RUN' if self.dry_run_mode else 'LIVE'}, "
                f"Playbooks loaded: {len(self.playbook_registry.list_playbooks())}"
            )

        except Exception as e:
            self.logger.error(f"Failed to initialize response agent: {e}")
            raise AgentError(f"Response agent initialization failed: {e}")

    async def _load_custom_playbooks(self):
        """Load custom playbooks from configuration."""
        # Placeholder for loading custom playbooks from config/files
        # Could load from YAML, JSON, or database
        custom_playbooks = self.get_config("custom_playbooks", [])
        if custom_playbooks:
            self.logger.info(f"Loading {len(custom_playbooks)} custom playbooks")
            # Implementation would parse and register custom playbooks

    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute automated response based on alert analysis.

        Returns only state updates, following LangGraph best practices.

        Args:
            state: Current workflow state with alert data and analysis

        Returns:
            Dict containing state updates (response actions, status, etc.)
        """
        try:
            alert_id = state.get("alert_id", "unknown")
            self.logger.info(f"Executing response for alert {alert_id}")

            # Check if response is enabled
            if not self.enabled:
                self.logger.info("Response agent disabled in configuration")
                return {
                    "triage_status": "response_skipped",
                    "processing_notes": ["Response agent disabled"],
                    "current_node": "response"
                }

            # Validate input
            if not await self.validate_input(state):
                raise ValueError("Invalid input state for response")

            # Extract alert data
            raw_alert = state.get("raw_alert", {})
            confidence_score = state.get("confidence_score", 0)
            enriched_data = state.get("enriched_data", {})

            # Determine threat type and select playbook
            threat_type = await self._determine_threat_type(state)
            playbook = await self._select_playbook(threat_type, confidence_score)

            if not playbook:
                self.logger.info(
                    f"No playbook found for threat type '{threat_type}' "
                    f"with confidence {confidence_score}%"
                )
                return {
                    "triage_status": "no_response_needed",
                    "processing_notes": [
                        f"No playbook matched threat type '{threat_type}' "
                        f"at confidence {confidence_score}%"
                    ],
                    "current_node": "response",
                    "enriched_data": {
                        **enriched_data,
                        "response_decision": {
                            "threat_type": threat_type,
                            "playbook_selected": None,
                            "reason": "No matching playbook"
                        }
                    }
                }

            self.logger.info(
                f"Selected playbook '{playbook.name}' for threat type '{threat_type}'"
            )

            # Check if playbook requires approval
            if playbook.requires_approval:
                self.logger.info(
                    f"Playbook '{playbook.name}' requires approval - escalating"
                )
                return await self._handle_approval_required(state, playbook, threat_type)

            # Execute playbook
            execution_result = await self._execute_playbook(state, playbook)

            # Build state updates
            updates = {
                "triage_status": execution_result["status"],
                "last_updated": datetime.utcnow().isoformat(),
                "current_node": "response",
                "processing_notes": execution_result["processing_notes"],
                "enriched_data": {
                    **enriched_data,
                    "response_execution": {
                        "playbook_name": playbook.name,
                        "threat_type": threat_type,
                        "actions_attempted": execution_result["actions_attempted"],
                        "actions_succeeded": execution_result["actions_succeeded"],
                        "actions_failed": execution_result["actions_failed"],
                        "execution_time_seconds": execution_result["execution_time"],
                        "dry_run": self.dry_run_mode,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                },
                "recommended_actions": execution_result.get("recommended_actions", [])
            }

            # Update statistics
            self._playbooks_executed += 1
            self._actions_executed += execution_result["actions_succeeded"]
            self._actions_failed += execution_result["actions_failed"]

            self.logger.info(
                f"Response completed for alert {alert_id}: "
                f"{execution_result['actions_succeeded']}/{execution_result['actions_attempted']} "
                f"actions succeeded"
            )

            return updates

        except Exception as e:
            self.logger.error(f"Response execution failed: {e}", exc_info=True)

            # Build detailed escalation message for analysts
            escalation_reason = (
                f"⚠️ Automated response failed - Manual intervention required\n\n"
                f"**Reason**: {str(e)}\n"
                f"**Alert ID**: {alert_id}\n"
                f"**Recommended Action**: Review alert details and execute manual response"
            )

            return {
                "triage_status": "escalated",  # Escalate for manual intervention
                "last_updated": datetime.utcnow().isoformat(),
                "current_node": "response",
                "processing_notes": [
                    f"❌ Response execution failed: {str(e)}",
                    f"Escalated to L1/L2 analyst for manual intervention",
                    f"Review required: Automated response could not be executed"
                ],
                "enriched_data": {
                    **state.get("enriched_data", {}),
                    "escalation_info": {
                        "reason": "response_execution_failed",
                        "error_message": str(e),
                        "escalation_reason": escalation_reason,
                        "requires_manual_response": True,
                        "timestamp": datetime.utcnow().isoformat()
                    },
                    "response_error": {
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat()
                    }
                }
            }

    async def _determine_threat_type(self, state: Dict[str, Any]) -> str:
        """Determine the primary threat type from alert data.

        Args:
            state: Current workflow state

        Returns:
            Threat type string (e.g., "malware_callback", "port_scan")
        """
        # Check enriched data first (from correlation/analysis)
        enriched_data = state.get("enriched_data", {})
        if "threat_type" in enriched_data:
            return enriched_data["threat_type"]

        # Check raw alert
        raw_alert = state.get("raw_alert", {})

        # Try category field
        category = raw_alert.get("category", "").lower()
        if category:
            return category

        # Try title/name field
        title = raw_alert.get("title", "").lower()
        if "malware" in title or "c2" in title or "callback" in title:
            return "malware_callback"
        elif "port" in title and "scan" in title:
            return "port_scan"
        elif "sql" in title or "injection" in title:
            return "sql_injection_attempt"
        elif "lateral" in title or "movement" in title:
            return "lateral_movement"
        elif "credential" in title or "mimikatz" in title:
            return "credential_access"

        # Default to unknown
        return "unknown"

    async def _select_playbook(
        self,
        threat_type: str,
        confidence_score: int
    ) -> Optional[ResponsePlaybook]:
        """Select the appropriate playbook for the threat.

        Args:
            threat_type: Type of threat detected
            confidence_score: Confidence score from triage/analysis

        Returns:
            Selected playbook or None if no match
        """
        playbook = self.playbook_registry.get_playbook_for_threat(
            threat_type,
            confidence_score
        )

        if playbook:
            self.logger.info(
                f"Selected playbook: {playbook.name} "
                f"(min_confidence: {playbook.min_confidence}, "
                f"requires_approval: {playbook.requires_approval})"
            )

        return playbook

    async def _execute_playbook(
        self,
        state: Dict[str, Any],
        playbook: ResponsePlaybook
    ) -> Dict[str, Any]:
        """Execute a response playbook.

        Args:
            state: Current workflow state
            playbook: Playbook to execute

        Returns:
            Dict with execution results
        """
        start_time = datetime.utcnow()
        actions_attempted = 0
        actions_succeeded = 0
        actions_failed = 0
        processing_notes = []
        action_results = []

        try:
            self.logger.info(
                f"Executing playbook '{playbook.name}' with {len(playbook.actions)} actions"
            )

            if playbook.parallel_execution and len(playbook.actions) > 1:
                # Execute actions in parallel
                results = await self._execute_actions_parallel(state, playbook.actions)
            else:
                # Execute actions sequentially
                results = await self._execute_actions_sequential(state, playbook.actions)

            # Process results
            for result in results:
                actions_attempted += 1
                if result["success"]:
                    actions_succeeded += 1
                    processing_notes.append(f"✓ {result['action_description']}")
                else:
                    actions_failed += 1
                    processing_notes.append(f"✗ {result['action_description']}: {result['error']}")

                    # Stop on failure if configured
                    if playbook.stop_on_failure:
                        self.logger.warning("Stopping playbook execution due to failure")
                        processing_notes.append("Playbook execution stopped due to failure")
                        break

                action_results.append(result)

            execution_time = (datetime.utcnow() - start_time).total_seconds()

            # Determine final status and add context for analysts
            if actions_failed == 0:
                status = "responded"
                processing_notes.append(f"✅ All {actions_succeeded} response actions completed successfully")
            elif actions_succeeded > 0:
                status = "responded"  # Partial success still counts as responded
                processing_notes.append(
                    f"⚠️ Partial success: {actions_succeeded}/{actions_attempted} actions succeeded, "
                    f"{actions_failed} failed - Review failed actions"
                )
            else:
                status = "escalated"  # All failed - escalate for manual intervention
                processing_notes.append(
                    f"❌ All {actions_failed} response actions failed - Manual intervention required"
                )
                processing_notes.append(
                    f"Escalated to L1/L2 analyst: Review playbook '{playbook.name}' and execute manually"
                )

            return {
                "status": status,
                "actions_attempted": actions_attempted,
                "actions_succeeded": actions_succeeded,
                "actions_failed": actions_failed,
                "processing_notes": processing_notes,
                "action_results": action_results,
                "execution_time": execution_time,
                "recommended_actions": self._generate_recommended_actions(action_results)
            }

        except Exception as e:
            self.logger.error(f"Playbook execution failed: {e}", exc_info=True)

            # Add detailed error information for analysts
            error_notes = processing_notes + [
                f"❌ Playbook execution error: {str(e)}",
                f"Playbook: {playbook.name}",
                f"Actions attempted before failure: {actions_attempted}",
                f"Actions succeeded: {actions_succeeded}",
                f"⚠️ Manual intervention required - Review failed actions and execute manually"
            ]

            return {
                "status": "escalated",  # Escalate for manual intervention
                "actions_attempted": actions_attempted,
                "actions_succeeded": actions_succeeded,
                "actions_failed": actions_failed + 1,
                "processing_notes": error_notes,
                "action_results": action_results,
                "execution_time": (datetime.utcnow() - start_time).total_seconds(),
                "recommended_actions": [
                    {
                        "action": "review_failed_playbook",
                        "description": f"Review and manually execute playbook: {playbook.name}",
                        "priority": "high"
                    }
                ]
            }

    async def _execute_actions_sequential(
        self,
        state: Dict[str, Any],
        actions: List[ResponseAction]
    ) -> List[Dict[str, Any]]:
        """Execute response actions sequentially.

        Args:
            state: Current workflow state
            actions: List of actions to execute

        Returns:
            List of action results
        """
        results = []

        for action in actions:
            result = await self._execute_single_action(state, action)
            results.append(result)

        return results

    async def _execute_actions_parallel(
        self,
        state: Dict[str, Any],
        actions: List[ResponseAction]
    ) -> List[Dict[str, Any]]:
        """Execute response actions in parallel.

        Args:
            state: Current workflow state
            actions: List of actions to execute

        Returns:
            List of action results
        """
        # Execute in batches to respect max_parallel_actions
        results = []

        for i in range(0, len(actions), self.max_parallel_actions):
            batch = actions[i:i + self.max_parallel_actions]
            tasks = [self._execute_single_action(state, action) for action in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Handle exceptions
            for idx, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    results.append({
                        "success": False,
                        "action_description": batch[idx].description,
                        "error": str(result)
                    })
                else:
                    results.append(result)

        return results

    async def _execute_single_action(
        self,
        state: Dict[str, Any],
        action: ResponseAction
    ) -> Dict[str, Any]:
        """Execute a single response action.

        Args:
            state: Current workflow state
            action: Response action to execute

        Returns:
            Dict with action result
        """
        try:
            # Check risk level and approval
            if not await self._check_action_approval(action):
                return {
                    "success": False,
                    "action_description": action.description,
                    "action_type": action.action_type.value,
                    "error": "Action requires approval",
                    "requires_approval": True
                }

            # Dry run mode - simulate execution
            if self.dry_run_mode:
                self.logger.info(f"DRY RUN: Would execute {action.description}")
                return {
                    "success": True,
                    "action_description": action.description,
                    "action_type": action.action_type.value,
                    "dry_run": True,
                    "simulated": True
                }

            # Prepare action parameters with context from state
            action_params = self._prepare_action_parameters(state, action)

            # Execute via tool orchestrator
            self.logger.info(
                f"Executing action: {action.description} "
                f"(tool: {action.tool_name}, method: {action.tool_method})"
            )

            result = await asyncio.wait_for(
                self._execute_with_tool_orchestrator(action, action_params),
                timeout=action.timeout
            )

            return {
                "success": True,
                "action_description": action.description,
                "action_type": action.action_type.value,
                "tool_name": action.tool_name,
                "tool_method": action.tool_method,
                "result": result,
                "dry_run": False
            }

        except asyncio.TimeoutError:
            self.logger.error(f"Action timed out: {action.description}")
            return {
                "success": False,
                "action_description": action.description,
                "action_type": action.action_type.value,
                "error": f"Timeout after {action.timeout}s"
            }
        except Exception as e:
            self.logger.error(f"Action failed: {action.description} - {e}")

            # Retry if configured
            if action.retry_on_failure and action.max_retries > 0:
                return await self._retry_action(state, action, e)

            return {
                "success": False,
                "action_description": action.description,
                "action_type": action.action_type.value,
                "error": str(e)
            }

    async def _execute_with_tool_orchestrator(
        self,
        action: ResponseAction,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute action via tool orchestrator.

        Args:
            action: Response action
            parameters: Prepared parameters

        Returns:
            Tool execution result
        """
        if not self.tool_orchestrator:
            # Fallback: simulate execution
            self.logger.warning("Tool orchestrator not available - simulating action")
            return {"simulated": True, "status": "success"}

        # Call tool orchestrator
        result = await self.tool_orchestrator.execute_tool(
            tool_name=action.tool_name,
            tool_args={
                "method": action.tool_method,
                **parameters
            },
            context={
                "action_type": action.action_type.value,
                "risk_level": action.risk_level.value
            }
        )

        return result

    def _prepare_action_parameters(
        self,
        state: Dict[str, Any],
        action: ResponseAction
    ) -> Dict[str, Any]:
        """Prepare action parameters by extracting values from state.

        Args:
            state: Current workflow state
            action: Response action

        Returns:
            Dict of parameters for tool execution
        """
        # Start with static parameters from action
        params = action.parameters.copy()

        # Extract dynamic values from alert data
        raw_alert = state.get("raw_alert", {})

        # Add common parameters based on action type
        if action.action_type.value in ["block_ip", "block_domain"]:
            # Extract IP/domain from alert
            params["source_ip"] = raw_alert.get("source_ip")
            params["destination_ip"] = raw_alert.get("destination_ip")
            params["alert_id"] = state.get("alert_id")

        elif action.action_type.value == "isolate_host":
            # Extract hostname
            params["hostname"] = raw_alert.get("hostname") or raw_alert.get("computer_name")
            params["alert_id"] = state.get("alert_id")

        elif action.action_type.value in ["terminate_process", "quarantine_file"]:
            # Extract process/file info
            params["process_id"] = raw_alert.get("process_id")
            params["file_path"] = raw_alert.get("file_path")
            params["file_hash"] = raw_alert.get("sha256") or raw_alert.get("md5")
            params["hostname"] = raw_alert.get("hostname") or raw_alert.get("computer_name")

        elif action.action_type.value in ["disable_user", "reset_password"]:
            # Extract user info
            params["username"] = raw_alert.get("username") or raw_alert.get("user")
            params["alert_id"] = state.get("alert_id")

        # Add alert context for logging/audit
        params["alert_id"] = state.get("alert_id")
        params["confidence_score"] = state.get("confidence_score")

        return params

    async def _check_action_approval(self, action: ResponseAction) -> bool:
        """Check if action is approved based on risk level.

        Args:
            action: Response action to check

        Returns:
            True if approved, False otherwise
        """
        risk_level = action.risk_level

        if risk_level == RiskLevel.LOW:
            return self.auto_approve_low_risk
        elif risk_level == RiskLevel.MEDIUM:
            return self.auto_approve_medium_risk
        elif risk_level == RiskLevel.HIGH:
            return self.auto_approve_high_risk
        else:  # CRITICAL
            # Critical actions should never auto-approve in production
            return False

    async def _retry_action(
        self,
        state: Dict[str, Any],
        action: ResponseAction,
        last_error: Exception
    ) -> Dict[str, Any]:
        """Retry a failed action.

        Args:
            state: Current workflow state
            action: Action to retry
            last_error: Last error encountered

        Returns:
            Action result after retries
        """
        for attempt in range(action.max_retries):
            self.logger.info(f"Retrying action (attempt {attempt + 1}/{action.max_retries}): {action.description}")

            try:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                return await self._execute_single_action(state, action)
            except Exception as e:
                last_error = e
                continue

        return {
            "success": False,
            "action_description": action.description,
            "action_type": action.action_type.value,
            "error": f"Failed after {action.max_retries} retries: {str(last_error)}"
        }

    async def _handle_approval_required(
        self,
        state: Dict[str, Any],
        playbook: ResponsePlaybook,
        threat_type: str
    ) -> Dict[str, Any]:
        """Handle playbook that requires approval.

        Args:
            state: Current workflow state
            playbook: Playbook requiring approval
            threat_type: Threat type detected

        Returns:
            State updates for escalation
        """
        self.logger.info(f"Playbook '{playbook.name}' requires approval - escalating to human review")

        return {
            "triage_status": "escalated",  # Escalated for approval
            "last_updated": datetime.utcnow().isoformat(),
            "current_node": "response",
            "processing_notes": [
                f"Playbook '{playbook.name}' requires approval",
                f"Threat type: {threat_type}",
                f"Actions pending: {len(playbook.actions)}"
            ],
            "enriched_data": {
                **state.get("enriched_data", {}),
                "response_approval": {
                    "playbook_name": playbook.name,
                    "threat_type": threat_type,
                    "actions_pending": [a.to_dict() for a in playbook.actions],
                    "requires_approval": True,
                    "approval_requested_at": datetime.utcnow().isoformat()
                }
            }
        }

    def _generate_recommended_actions(self, action_results: List[Dict[str, Any]]) -> List[str]:
        """Generate follow-up recommended actions based on execution results.

        Args:
            action_results: List of action execution results

        Returns:
            List of recommended follow-up actions
        """
        recommendations = []

        # Check for failed actions
        failed_actions = [r for r in action_results if not r["success"]]
        if failed_actions:
            recommendations.append(
                f"Manual review required: {len(failed_actions)} automated actions failed"
            )
            for failed in failed_actions[:3]:  # Limit to first 3
                recommendations.append(f"  - Retry: {failed['action_description']}")

        # Check if critical actions were executed
        if any(r.get("action_type") == "isolate_host" for r in action_results):
            recommendations.append("Monitor isolated host for additional IOCs")
            recommendations.append("Schedule forensic investigation")

        if any(r.get("action_type") == "disable_user" for r in action_results):
            recommendations.append("Investigate user account activity history")
            recommendations.append("Review access logs for lateral movement")

        return recommendations

    async def cleanup(self):
        """Cleanup resources."""
        self.logger.info("Response agent cleanup complete")

    async def _validate_input_custom(self, state: Dict[str, Any]) -> bool:
        """Custom input validation for response agent.

        Args:
            state: Input state to validate

        Returns:
            True if valid, False otherwise
        """
        # Require raw_alert
        if "raw_alert" not in state or not state["raw_alert"]:
            self.logger.error("Missing raw_alert in state")
            return False

        # Require alert_id
        if "alert_id" not in state:
            self.logger.error("Missing alert_id in state")
            return False

        # Require confidence_score
        if "confidence_score" not in state:
            self.logger.error("Missing confidence_score in state")
            return False

        return True

    def get_required_config_keys(self) -> List[str]:
        """Get required configuration keys.

        Returns:
            List of required config keys
        """
        return []  # All config keys have defaults

    def get_statistics(self) -> Dict[str, Any]:
        """Get response agent statistics.

        Returns:
            Dict with execution statistics
        """
        return {
            "playbooks_executed": self._playbooks_executed,
            "actions_executed": self._actions_executed,
            "actions_failed": self._actions_failed,
            "success_rate": (
                self._actions_executed / (self._actions_executed + self._actions_failed)
                if (self._actions_executed + self._actions_failed) > 0
                else 0
            ),
            "dry_run_mode": self.dry_run_mode,
            "enabled": self.enabled
        }
