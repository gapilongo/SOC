
"""
Production-grade APIs for SOC Dashboard integration.

This module provides RESTful APIs and WebSocket endpoints for real-time
SOC dashboard functionality, integrating with the existing LG-SOTF architecture.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4

import uvicorn
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from lg_sotf.agents.registry import agent_registry
from lg_sotf.main import LG_SOTFApplication


class IngestionStatusResponse(BaseModel):
    is_active: bool
    last_poll_time: Optional[str]
    next_poll_time: Optional[str]
    polling_interval: int
    sources_enabled: List[str]
    sources_stats: Dict[str, Dict[str, int]]
    total_ingested: int
    total_deduplicated: int
    total_errors: int

class IngestionControlRequest(BaseModel):
    action: str  # "start", "stop", "trigger_poll"
    sources: Optional[List[str]] = None

class SourceConfigRequest(BaseModel):
    source_name: str
    enabled: bool
    config: Optional[Dict[str, Any]] = None
    
class AlertRequest(BaseModel):
    alert_data: Dict[str, Any]
    priority: Optional[str] = "normal"

class AlertResponse(BaseModel):
    alert_id: str
    status: str
    workflow_instance_id: str
    processing_started: bool
    estimated_completion: Optional[str] = None

class WorkflowStatusResponse(BaseModel):
    alert_id: str
    workflow_instance_id: str
    current_node: str
    triage_status: str
    confidence_score: int
    threat_score: Optional[int] = 0
    processing_notes: List[str]
    enriched_data: Optional[Dict[str, Any]] = {}
    escalation_info: Optional[Dict[str, Any]] = None
    response_execution: Optional[Dict[str, Any]] = None
    # FP/TP indicators from triage
    fp_indicators: Optional[List[str]] = []
    tp_indicators: Optional[List[str]] = []
    # Correlation and analysis data
    correlations: Optional[List[Dict[str, Any]]] = []
    correlation_score: Optional[int] = 0
    analysis_conclusion: Optional[str] = None
    recommended_actions: Optional[List[str]] = []
    last_updated: str
    progress_percentage: int

class MetricsResponse(BaseModel):
    timestamp: str
    alerts_processed_today: int
    alerts_in_progress: int
    average_processing_time: float
    success_rate: float
    agent_health: Dict[str, bool]
    system_health: bool

class DashboardStatsResponse(BaseModel):
    total_alerts_today: int
    high_priority_alerts: int
    alerts_by_status: Dict[str, int]
    alerts_by_severity: Dict[str, int]
    top_threat_indicators: List[Dict[str, Any]]
    recent_escalations: List[Dict[str, Any]]
    processing_time_avg: float

class CorrelationResponse(BaseModel):
    alert_id: str
    correlations: List[Dict[str, Any]]
    correlation_score: int
    attack_campaign_indicators: List[str]
    threat_actor_patterns: List[str]

class FeedbackRequest(BaseModel):
    analyst_username: str
    decision: str
    confidence: int = Field(ge=1, le=10)
    notes: str
    actions_taken: Optional[List[str]] = None
    actions_recommended: Optional[List[str]] = None
    triage_correct: Optional[bool] = None
    correlation_helpful: Optional[bool] = None
    analysis_accurate: Optional[bool] = None

class AgentStatusResponse(BaseModel):
    agent_name: str
    status: str
    last_execution: Optional[str]
    success_rate: float
    average_execution_time: float
    error_count: int


class WebSocketManager:
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.client_subscriptions: Dict[str, List[str]] = {}
        self.heartbeat_task = None
        
    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        self.client_subscriptions[client_id] = []
        
        await self.send_personal_message({
            "type": "connection",
            "status": "connected",
            "client_id": client_id,
            "server_time": datetime.utcnow().isoformat()
        }, client_id)
        
    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        if client_id in self.client_subscriptions:
            del self.client_subscriptions[client_id]
            
    async def send_personal_message(self, message: dict, client_id: str):
        if client_id not in self.active_connections:
            return
            
        try:
            await self.active_connections[client_id].send_text(
                json.dumps(message, default=str)
            )
        except Exception as e:
            logging.warning(f"Failed to send to {client_id}: {e}")
            self.disconnect(client_id)
            
    async def broadcast(self, message: dict, subscription_type: str = None):
        disconnected = []
        
        for client_id, websocket in self.active_connections.items():
            if subscription_type:
                subscriptions = self.client_subscriptions.get(client_id, [])
                if subscription_type not in subscriptions:
                    continue
            
            try:
                await websocket.send_text(json.dumps(message, default=str))
            except Exception as e:
                logging.warning(f"Broadcast error to {client_id}: {e}")
                disconnected.append(client_id)
                
        for client_id in disconnected:
            self.disconnect(client_id)
    
    async def heartbeat_loop(self):
        while True:
            try:
                await asyncio.sleep(30)
                
                message = {
                    "type": "heartbeat",
                    "timestamp": datetime.utcnow().isoformat(),
                    "active_connections": len(self.active_connections)
                }
                
                await self.broadcast(message)
                
            except Exception as e:
                logging.error(f"Heartbeat error: {e}")


class SOCDashboardAPI:

    def __init__(self, lg_sotf_app: LG_SOTFApplication):
        self.lg_sotf_app = lg_sotf_app
        self.websocket_manager = WebSocketManager()
        self.logger = logging.getLogger(__name__)

        # Track background tasks for proper shutdown
        self.background_tasks: List[asyncio.Task] = []

        # Initialize FastAPI
        self.app = FastAPI(
            title="LG-SOTF Dashboard API",
            description="Production-grade SOC Dashboard API",
            version="1.0.0",
            docs_url="/api/docs",
            redoc_url="/api/redoc"
        )
        
        # Add CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        self._setup_routes()
        self._start_background_tasks()
    
    def _setup_routes(self):
        
        @self.app.post("/api/v1/alerts/process", response_model=AlertResponse)
        async def process_alert(alert_request: AlertRequest, background_tasks: BackgroundTasks):
            try:
                alert_id = str(uuid4())
                
                background_tasks.add_task(
                    self._process_alert_background,
                    alert_id,
                    alert_request.alert_data
                )
                
                await self.websocket_manager.broadcast({
                    "type": "new_alert",
                    "alert_id": alert_id,
                    "severity": alert_request.alert_data.get("severity", "unknown"),
                    "timestamp": datetime.utcnow().isoformat()
                }, "new_alerts")
                
                return AlertResponse(
                    alert_id=alert_id,
                    status="processing",
                    workflow_instance_id=f"{alert_id}_{int(time.time())}",
                    processing_started=True,
                    estimated_completion=(datetime.utcnow() + timedelta(minutes=2)).isoformat()
                )
                
            except Exception as e:
                self.logger.error(f"Alert processing failed: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/v1/alerts/{alert_id}/status", response_model=WorkflowStatusResponse)
        async def get_alert_status(alert_id: str):
            try:
                state = await self._get_alert_state(alert_id)
                
                if not state:
                    raise HTTPException(status_code=404, detail="Alert not found")
                
                # Extract enriched data
                enriched_data = state.get("enriched_data", {})

                return WorkflowStatusResponse(
                    alert_id=alert_id,
                    workflow_instance_id=state.get("workflow_instance_id", ""),
                    current_node=state.get("current_node", "unknown"),
                    triage_status=state.get("triage_status", "unknown"),
                    confidence_score=state.get("confidence_score", 0),
                    threat_score=state.get("threat_score", 0),
                    processing_notes=state.get("processing_notes", []),
                    enriched_data=enriched_data,
                    escalation_info=enriched_data.get("escalation_info"),
                    response_execution=state.get("response_execution"),
                    # FP/TP indicators from triage
                    fp_indicators=state.get("fp_indicators", []),
                    tp_indicators=state.get("tp_indicators", []),
                    # Correlation and analysis data
                    correlations=state.get("correlations", []),
                    correlation_score=state.get("correlation_score", 0),
                    analysis_conclusion=state.get("analysis_conclusion"),
                    recommended_actions=state.get("recommended_actions", []),
                    last_updated=state.get("last_updated", datetime.utcnow().isoformat()),
                    progress_percentage=self._calculate_progress(state)
                )
                
            except HTTPException:
                raise
            except Exception as e:
                self.logger.error(f"Status retrieval failed: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/v1/alerts")
        async def get_alerts(
            limit: int = 50,
            status: Optional[str] = None,
            hours: int = 24
        ):
            try:
                alerts = await self._query_recent_alerts(limit, status, hours)
                return alerts
                
            except Exception as e:
                self.logger.error(f"Alert retrieval failed: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/v1/alerts/{alert_id}/correlations", response_model=CorrelationResponse)
        async def get_alert_correlations(alert_id: str):
            try:
                correlations = await self._get_alert_correlations(alert_id)
                return correlations
                
            except Exception as e:
                self.logger.error(f"Correlation retrieval failed: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/v1/dashboard/stats", response_model=DashboardStatsResponse)
        async def get_dashboard_stats():
            try:
                stats = await self._get_dashboard_statistics()
                return stats
                
            except Exception as e:
                self.logger.error(f"Dashboard stats retrieval failed: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/v1/agents/status", response_model=List[AgentStatusResponse])
        async def get_agents_status():
            try:
                agents_status = []
                stats = agent_registry.get_registry_stats()
                
                for agent_name in stats.get("agent_instances", []):
                    try:
                        agent = agent_registry.get_agent(agent_name)
                        metrics = agent.get_metrics()
                        is_healthy = await agent.health_check() if hasattr(agent, 'health_check') else agent.initialized
                        
                        agents_status.append(AgentStatusResponse(
                            agent_name=agent_name,
                            status="healthy" if is_healthy else "unhealthy",
                            last_execution=metrics.get("last_execution"),
                            success_rate=1.0 - metrics.get("error_rate", 0),
                            average_execution_time=metrics.get("avg_execution_time", 0),
                            error_count=metrics.get("error_count", 0)
                        ))
                    except Exception as e:
                        self.logger.warning(f"Agent {agent_name} status error: {e}")
                        agents_status.append(AgentStatusResponse(
                            agent_name=agent_name,
                            status="error",
                            last_execution=None,
                            success_rate=0.0,
                            average_execution_time=0.0,
                            error_count=1
                        ))
                
                return agents_status
                
            except Exception as e:
                self.logger.error(f"Agent status retrieval failed: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.websocket("/ws/{client_id}")
        async def websocket_endpoint(websocket: WebSocket, client_id: str):
            await self.websocket_manager.connect(websocket, client_id)
            
            try:
                while True:
                    data = await websocket.receive_text()
                    message = json.loads(data)
                    
                    if message.get("type") == "subscribe":
                        subscriptions = message.get("subscriptions", [])
                        self.websocket_manager.client_subscriptions[client_id] = subscriptions
                        
                        await self.websocket_manager.send_personal_message({
                            "type": "subscription_confirmed",
                            "subscriptions": subscriptions
                        }, client_id)
                        
                    elif message.get("type") == "ping":
                        await self.websocket_manager.send_personal_message({
                            "type": "pong",
                            "timestamp": datetime.utcnow().isoformat()
                        }, client_id)
                        
            except WebSocketDisconnect:
                self.websocket_manager.disconnect(client_id)
                self.logger.info(f"Client {client_id} disconnected")
        
        @self.app.get("/api/v1/health")
        async def health_check():
            try:
                app_health = await self.lg_sotf_app.health_check()
                
                return {
                    "status": "healthy" if app_health else "unhealthy",
                    "timestamp": datetime.utcnow().isoformat(),
                    "version": "1.0.0",
                    "components": {
                        "lg_sotf_app": app_health,
                        "websocket_connections": len(self.websocket_manager.active_connections),
                        "api": True
                    }
                }
            except Exception as e:
                return JSONResponse(
                    status_code=503,
                    content={
                        "status": "unhealthy",
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat()
                    }
                )
            
        @self.app.get("/api/v1/ingestion/status", response_model=IngestionStatusResponse)
        async def get_ingestion_status():
            """Get current ingestion status and metrics."""
            try:
                if not self.lg_sotf_app.workflow_engine or "ingestion" not in self.lg_sotf_app.workflow_engine.agents:
                    raise HTTPException(status_code=503, detail="Ingestion agent not available")
                
                ingestion_agent = (
                    self.lg_sotf_app.workflow_engine.agents.get("ingestion_instance") or 
                    self.lg_sotf_app.workflow_engine.agents.get("ingestion")
                )
                ingestion_config = self.lg_sotf_app.config_manager.get_agent_config("ingestion")
                
                # Calculate next poll time
                next_poll = None
                if self.lg_sotf_app._last_ingestion_poll:
                    polling_interval = ingestion_config.get("polling_interval", 60)
                    next_poll = (self.lg_sotf_app._last_ingestion_poll + timedelta(seconds=polling_interval)).isoformat()

                # Check if ingestion is active (agent is initialized and has sources)
                # Note: We check initialized + enabled sources instead of self.running
                # because the app can run in API-only mode without the continuous loop
                is_active = ingestion_agent.initialized and len(ingestion_agent.enabled_sources) > 0

                return IngestionStatusResponse(
                    is_active=is_active,
                    last_poll_time=self.lg_sotf_app._last_ingestion_poll.isoformat() if self.lg_sotf_app._last_ingestion_poll else None,
                    next_poll_time=next_poll,
                    polling_interval=ingestion_config.get("polling_interval", 60),
                    sources_enabled=ingestion_agent.enabled_sources,
                    sources_stats=ingestion_agent.get_source_stats()["by_source"],
                    total_ingested=ingestion_agent.ingestion_stats["total_ingested"],
                    total_deduplicated=ingestion_agent.ingestion_stats["total_deduplicated"],
                    total_errors=ingestion_agent.ingestion_stats["total_errors"]
                )
                
            except HTTPException:
                raise
            except Exception as e:
                self.logger.error(f"Ingestion status retrieval failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/v1/ingestion/control")
        async def control_ingestion(request: IngestionControlRequest):
            """Control ingestion process (trigger poll, etc)."""
            try:
                ingestion_agent = (
                    self.lg_sotf_app.workflow_engine.agents.get("ingestion_instance") or 
                    self.lg_sotf_app.workflow_engine.agents.get("ingestion")
                )
                
                if not ingestion_agent:
                    raise HTTPException(status_code=503, detail="Ingestion agent not available")
                
                if request.action == "trigger_poll":
                    # ✅ ACTUALLY POLL - don't just reset the timer
                    self.logger.info("Manual ingestion poll triggered")
                    
                    try:
                        # Call poll_sources directly
                        new_alerts = await ingestion_agent.poll_sources()

                        # Update last poll timestamp
                        self.lg_sotf_app._last_ingestion_poll = datetime.utcnow()

                        self.logger.info(f"Manual poll found {len(new_alerts)} alerts")

                        # Broadcast ingestion triggered event
                        await self.websocket_manager.broadcast({
                            "type": "ingestion_triggered",
                            "timestamp": datetime.utcnow().isoformat(),
                            "sources": request.sources or ingestion_agent.enabled_sources,
                            "alerts_found": len(new_alerts)
                        }, "ingestion_updates")
                        
                        # Process each alert through workflow
                        # NOTE: Manual trigger processes alerts immediately. If automatic polling
                        # is also running, the same alerts might be processed twice. This is by design
                        # for now - deduplication happens at the ingestion level, but alerts can still
                        # be processed multiple times if they arrive close together.
                        # The workflow engine should handle this gracefully via state versioning.
                        for alert in new_alerts:
                            try:
                                # Broadcast that alert was ingested
                                await self.websocket_manager.broadcast({
                                    "type": "new_alert",
                                    "alert_id": alert["id"],
                                    "severity": alert.get("severity", "unknown"),
                                    "source": alert.get("source", "unknown"),
                                    "timestamp": datetime.utcnow().isoformat()
                                }, "new_alerts")

                                # Process alert in background
                                asyncio.create_task(
                                    self._process_alert_background(alert["id"], alert)
                                )
                                
                            except Exception as e:
                                self.logger.error(f"Error processing alert {alert.get('id')}: {e}")
                        
                        return {
                            "status": "success",
                            "message": f"Ingestion poll completed - found {len(new_alerts)} alerts",
                            "alerts_found": len(new_alerts),
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        
                    except Exception as e:
                        self.logger.error(f"Manual poll failed: {e}", exc_info=True)
                        raise HTTPException(status_code=500, detail=f"Poll failed: {str(e)}")
                
                elif request.action == "get_stats":
                    return ingestion_agent.get_source_stats()
                
                else:
                    raise HTTPException(status_code=400, detail=f"Unknown action: {request.action}")
                    
            except HTTPException:
                raise
            except Exception as e:
                self.logger.error(f"Ingestion control failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/v1/ingestion/sources")
        async def get_ingestion_sources():
            """Get all configured ingestion sources and their status."""
            try:
                if not self.lg_sotf_app.workflow_engine or "ingestion" not in self.lg_sotf_app.workflow_engine.agents:
                    return {"sources": []}

                ingestion_agent = (
                    self.lg_sotf_app.workflow_engine.agents.get("ingestion_instance") or
                    self.lg_sotf_app.workflow_engine.agents.get("ingestion")
                )
                sources_info = []

                for source_name, plugin in ingestion_agent.plugins.items():
                    try:
                        is_healthy = await plugin.health_check()
                        metrics = plugin.get_metrics()

                        sources_info.append({
                            "name": source_name,
                            "enabled": plugin.enabled,
                            "healthy": is_healthy,
                            "initialized": plugin.initialized,
                            "fetch_count": metrics["fetch_count"],
                            "error_count": metrics["error_count"],
                            "last_fetch": metrics["last_fetch_time"]
                        })
                    except Exception as e:
                        self.logger.warning(f"Error getting info for source {source_name}: {e}")
                        sources_info.append({
                            "name": source_name,
                            "enabled": False,
                            "healthy": False,
                            "error": str(e)
                        })

                return {"sources": sources_info}

            except Exception as e:
                self.logger.error(f"Sources retrieval failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/v1/correlations/metrics")
        async def get_correlation_metrics():
            """Get real-time correlation metrics from Redis."""
            try:
                metrics = await self._get_correlation_metrics()
                return metrics

            except Exception as e:
                self.logger.error(f"Correlation metrics retrieval failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/v1/correlations/network")
        async def get_correlation_network(limit: int = 50):
            """Get correlation network graph data showing alert relationships."""
            try:
                network_data = await self._get_correlation_network(limit)
                return network_data

            except Exception as e:
                self.logger.error(f"Correlation network retrieval failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        # ===== Escalation Management Endpoints =====

        @self.app.get("/api/v1/escalations")
        async def get_pending_escalations(level: Optional[str] = None, limit: int = 50):
            """Get pending escalations from queue."""
            try:
                human_loop_agent = self.lg_sotf_app.workflow_engine.agents.get("human_loop")
                if not human_loop_agent:
                    raise HTTPException(status_code=503, detail="Human loop agent not available")

                escalations = await human_loop_agent.get_pending_escalations(level=level, limit=limit)
                return {"escalations": escalations, "count": len(escalations)}

            except HTTPException:
                raise
            except Exception as e:
                self.logger.error(f"Escalation retrieval failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/api/v1/escalations/{escalation_id}/assign")
        async def assign_escalation(escalation_id: str, analyst_username: str):
            """Assign escalation to analyst."""
            try:
                human_loop_agent = self.lg_sotf_app.workflow_engine.agents.get("human_loop")
                if not human_loop_agent:
                    raise HTTPException(status_code=503, detail="Human loop agent not available")

                result = await human_loop_agent.assign_escalation(
                    escalation_id=escalation_id,
                    analyst_username=analyst_username
                )
                return result

            except HTTPException:
                raise
            except ValueError as e:
                raise HTTPException(status_code=404, detail=str(e))
            except Exception as e:
                self.logger.error(f"Escalation assignment failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/api/v1/escalations/{escalation_id}/feedback")
        async def submit_feedback(
            escalation_id: str,
            feedback: FeedbackRequest
        ):
            """Submit analyst feedback for escalation."""
            try:
                human_loop_agent = self.lg_sotf_app.workflow_engine.agents.get("human_loop")
                if not human_loop_agent:
                    raise HTTPException(status_code=503, detail="Human loop agent not available")

                result = await human_loop_agent.submit_feedback(
                    escalation_id=escalation_id,
                    analyst_username=feedback.analyst_username,
                    decision=feedback.decision,
                    confidence=feedback.confidence,
                    notes=feedback.notes,
                    actions_taken=feedback.actions_taken,
                    actions_recommended=feedback.actions_recommended,
                    triage_correct=feedback.triage_correct,
                    correlation_helpful=feedback.correlation_helpful,
                    analysis_accurate=feedback.analysis_accurate
                )
                return result

            except HTTPException:
                raise
            except ValueError as e:
                raise HTTPException(status_code=404, detail=str(e))
            except Exception as e:
                self.logger.error(f"Feedback submission failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/v1/escalations/stats")
        async def get_escalation_stats():
            """Get escalation queue statistics."""
            try:
                human_loop_agent = self.lg_sotf_app.workflow_engine.agents.get("human_loop")
                if not human_loop_agent:
                    raise HTTPException(status_code=503, detail="Human loop agent not available")

                # Get queue stats from PostgreSQL
                queue_stats = await human_loop_agent.get_queue_stats()

                # Try to get decision stats and accuracy, but don't fail if not available
                try:
                    decision_stats = await human_loop_agent.get_decision_stats()
                    triage_accuracy = await human_loop_agent.get_triage_accuracy()
                    if triage_accuracy and 'accuracy_rate' in triage_accuracy:
                        queue_stats['accuracy_rate'] = triage_accuracy['accuracy_rate']
                except Exception as e:
                    self.logger.warning(f"Could not get decision stats: {e}")

                return queue_stats

            except HTTPException:
                raise
            except Exception as e:
                self.logger.error(f"Escalation stats retrieval failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))


    async def _process_alert_background(self, alert_id: str, alert_data: Dict[str, Any]):
        try:
            await self.websocket_manager.broadcast({
                "type": "ingestion_event",
                "event": "alert_ingested",
                "alert_id": alert_id,
                "source": alert_data.get("source", "unknown"),
                "severity": alert_data.get("severity", "unknown"),
                "timestamp": datetime.utcnow().isoformat()
            }, "ingestion_updates")
                
            await self.websocket_manager.broadcast({
                "type": "alert_update",
                "alert_id": alert_id,
                "status": "processing",
                "progress": 10
            }, "alert_updates")
            
            result = await self.lg_sotf_app.process_single_alert(alert_id, alert_data)
            
            await self.websocket_manager.broadcast({
                "type": "alert_update",
                "alert_id": alert_id,
                "status": "completed",
                "progress": 100,
                "result": result}, "alert_updates")
            
        except Exception as e:
            self.logger.error(f"Background processing failed: {e}")
            
            await self.websocket_manager.broadcast({
                "type": "alert_update",
                "alert_id": alert_id,
                "status": "failed",
                "error": str(e)
            }, "alert_updates")
    
    async def _get_alert_correlations(self, alert_id: str) -> CorrelationResponse:
        """Get correlations for a specific alert with Redis integration."""
        try:
            # Get the alert state
            state = await self._get_alert_state(alert_id)

            if not state:
                return CorrelationResponse(
                    alert_id=alert_id,
                    correlations=[],
                    correlation_score=0,
                    attack_campaign_indicators=[],
                    threat_actor_patterns=[]
                )

            # Extract correlation data from metadata (workflow-generated correlations)
            metadata = state.get("metadata", {}) if isinstance(state, dict) else {}
            base_correlations = metadata.get("correlations", [])

            # NEW: Get Redis-based real-time correlations
            redis_correlations = await self._get_redis_correlations(alert_id)

            # Merge both sources (deduplicate by indicator)
            all_correlations = base_correlations.copy()
            existing_indicators = {c.get('indicator') for c in base_correlations}

            for redis_corr in redis_correlations:
                if redis_corr.get('indicator') not in existing_indicators:
                    all_correlations.append(redis_corr)

            return CorrelationResponse(
                alert_id=alert_id,
                correlations=all_correlations,
                correlation_score=metadata.get("correlation_score", 0),
                attack_campaign_indicators=metadata.get("attack_campaign_indicators", []),
                threat_actor_patterns=metadata.get("threat_actor_patterns", [])
            )

        except Exception as e:
            self.logger.error(f"Correlation retrieval error: {e}")
            return CorrelationResponse(
                alert_id=alert_id,
                correlations=[],
                correlation_score=0,
                attack_campaign_indicators=[],
                threat_actor_patterns=[]
            )

    async def _get_redis_correlations(self, alert_id: str) -> List[Dict[str, Any]]:
        """Get real-time correlations from Redis."""
        correlations = []

        try:
            redis_storage = self.lg_sotf_app.redis_storage
            if not redis_storage or not redis_storage.redis_client:
                return correlations

            # Get all indicators for this alert
            indicators_key = f"alert:{alert_id}:indicators"
            indicators_raw = await redis_storage.redis_client.smembers(indicators_key)

            if not indicators_raw:
                return correlations

            # Decode and parse indicators
            indicators = []
            for ind in indicators_raw:
                ind_str = ind.decode('utf-8') if isinstance(ind, bytes) else str(ind)
                parts = ind_str.split(":", 1)
                if len(parts) == 2:
                    indicators.append({
                        'type': parts[0],
                        'value': parts[1]
                    })

            # For each indicator, find related alerts and co-occurrences
            seen_alerts = set()

            for indicator in indicators:
                indicator_type = indicator['type']
                indicator_value = indicator['value']

                # 1. Get related alerts sharing this indicator
                alerts_key = f"indicator:{indicator_type}:{indicator_value}:alerts"
                related_alerts_raw = await redis_storage.redis_client.smembers(alerts_key)

                related_alerts = []
                for alert_raw in related_alerts_raw:
                    related_alert_id = alert_raw.decode('utf-8') if isinstance(alert_raw, bytes) else str(alert_raw)
                    if related_alert_id != alert_id and related_alert_id not in seen_alerts:
                        related_alerts.append(related_alert_id)
                        seen_alerts.add(related_alert_id)

                if related_alerts:
                    correlations.append({
                        "type": "shared_indicator",
                        "indicator": f"{indicator_type}:{indicator_value}",
                        "indicator_type": indicator_type,
                        "indicator_value": indicator_value,
                        "description": f"Indicator {indicator_type}={indicator_value} shared with {len(related_alerts)} other alert(s)",
                        "confidence": min(90, 50 + len(related_alerts) * 10),
                        "weight": 30,
                        "threat_level": "high" if len(related_alerts) > 3 else "medium" if len(related_alerts) > 1 else "low",
                        "related_alerts": related_alerts[:5],  # Top 5
                        "total_related": len(related_alerts)
                    })

                # 2. Get co-occurring indicators
                cooccur_key = f"indicator:{indicator_type}:{indicator_value}:cooccur"
                cooccur_raw = await redis_storage.redis_client.zrevrange(
                    cooccur_key, 0, 4, withscores=True  # Top 5
                )

                if cooccur_raw:
                    cooccurring = []
                    for i in range(0, len(cooccur_raw), 2):
                        member = cooccur_raw[i].decode('utf-8') if isinstance(cooccur_raw[i], bytes) else str(cooccur_raw[i])
                        score = int(cooccur_raw[i + 1]) if i + 1 < len(cooccur_raw) else 0
                        cooccurring.append({
                            'indicator': member,
                            'count': score
                        })

                    if cooccurring:
                        correlations.append({
                            "type": "co_occurrence",
                            "indicator": f"{indicator_type}:{indicator_value}",
                            "description": f"Frequently co-occurs with {len(cooccurring)} other indicator(s)",
                            "confidence": 70,
                            "weight": 20,
                            "threat_level": "medium",
                            "co_occurring_indicators": cooccurring
                        })

                # 3. Get indicator metadata (count, first/last seen)
                metadata_key = f"indicator:{indicator_type}:{indicator_value}"
                metadata_raw = await redis_storage.redis_client.hgetall(metadata_key)

                if metadata_raw:
                    metadata = {}
                    for key, value in metadata_raw.items():
                        key_str = key.decode('utf-8') if isinstance(key, bytes) else str(key)
                        value_str = value.decode('utf-8') if isinstance(value, bytes) else str(value)
                        metadata[key_str] = value_str

                    count = int(metadata.get('count', 0))
                    if count > 1:
                        correlations.append({
                            "type": "frequency",
                            "indicator": f"{indicator_type}:{indicator_value}",
                            "description": f"Seen {count} times (first: {metadata.get('first_seen', 'unknown')}, last: {metadata.get('last_seen', 'unknown')})",
                            "confidence": min(80, 40 + count * 10),
                            "weight": 15,
                            "threat_level": "high" if count > 5 else "medium" if count > 2 else "low",
                            "frequency_count": count,
                            "first_seen": metadata.get('first_seen'),
                            "last_seen": metadata.get('last_seen')
                        })

            return correlations

        except Exception as e:
            self.logger.error(f"Redis correlation retrieval error: {e}", exc_info=True)
            return []

    
    async def _get_alert_state(self, alert_id: str) -> Optional[Dict[str, Any]]:
        try:
            storage = self.lg_sotf_app.postgres_storage
            
            query = """
                SELECT state_data, version, created_at
                FROM states
                WHERE alert_id = $1
                ORDER BY version DESC
                LIMIT 1
            """
            
            async with storage.pool.acquire() as conn:
                result = await conn.fetchrow(query, alert_id)
                
                if not result:
                    return None
                
                state_json = result['state_data']
                state_data = json.loads(state_json) if isinstance(state_json, str) else state_json
                
                # Debug logging
                self.logger.info(f"State data for {alert_id}: triage_status={state_data.get('triage_status')}, confidence={state_data.get('confidence_score')}, threat_score={state_data.get('threat_score', 0)}")
                
                # Extract metadata
                metadata = state_data.get("metadata", {})
                
                # Handle enum conversion for triage_status
                triage_status = state_data.get("triage_status", "unknown")
                if isinstance(triage_status, dict) and "_value_" in triage_status:
                    # Pydantic enum serialization
                    triage_status = triage_status["_value_"]
                elif hasattr(triage_status, 'value'):
                    # Python enum
                    triage_status = triage_status.value
                else:
                    # String - clean it up
                    triage_status = str(triage_status).replace("TriageStatus.", "").replace("_", " ").lower()
                
                # Build the response with correct field extraction
                enriched_data = state_data.get("enriched_data", {})
                llm_insights = enriched_data.get("llm_insights", {})

                merged_state = {
                    "alert_id": alert_id,
                    "workflow_instance_id": state_data.get("workflow_instance_id", ""),
                    "current_node": state_data.get("current_node", "unknown"),
                    "triage_status": triage_status,
                    "confidence_score": int(state_data.get("confidence_score", 0)),
                    "threat_score": int(state_data.get("threat_score", 0)),
                    "processing_notes": metadata.get("processing_notes", []),
                    "enriched_data": enriched_data,
                    "correlations": state_data.get("correlations", []),
                    "correlation_score": int(state_data.get("correlation_score", 0)),
                    "analysis_conclusion": state_data.get("analysis_conclusion", ""),
                    "recommended_actions": state_data.get("recommended_actions", []),
                    # Extract FP/TP indicators to top level for easy access
                    "fp_indicators": state_data.get("fp_indicators", llm_insights.get("fp_indicators", [])),
                    "tp_indicators": state_data.get("tp_indicators", llm_insights.get("tp_indicators", [])),
                    # Extract response execution to top level
                    "response_execution": enriched_data.get("response_execution"),
                    "last_updated": result['created_at'].isoformat(),
                    "raw_alert": state_data.get("raw_alert", {})
                }

                self.logger.info(f"Returning merged state: confidence={merged_state['confidence_score']}, threat_score={merged_state['threat_score']}, status={merged_state['triage_status']}")

                return merged_state
                
        except Exception as e:
            self.logger.error(f"State retrieval error: {e}", exc_info=True)
            return None
    
    async def _query_recent_alerts(self, limit: int, status: Optional[str], hours: int) -> List[Dict]:
        try:
            storage = self.lg_sotf_app.postgres_storage
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            if status:
                query = """
                    SELECT DISTINCT ON (alert_id)
                        alert_id,
                        state_data->>'workflow_instance_id' as workflow_instance_id,
                        state_data->>'triage_status' as status,
                        state_data->>'current_node' as current_node,
                        (state_data->>'confidence_score')::int as confidence_score,
                        COALESCE((state_data->>'threat_score')::int, 0) as threat_score,
                        state_data->'raw_alert'->>'severity' as severity,
                        state_data->'raw_alert'->>'description' as description,
                        state_data->'raw_alert'->>'title' as title,
                        created_at
                    FROM states
                    WHERE created_at >= $1
                        AND state_data->>'triage_status' = $2
                    ORDER BY alert_id, version DESC
                    LIMIT $3
                """

                async with storage.pool.acquire() as conn:
                    results = await conn.fetch(query, cutoff_time, status, limit)
            else:
                query = """
                    SELECT DISTINCT ON (alert_id)
                        alert_id,
                        state_data->>'workflow_instance_id' as workflow_instance_id,
                        state_data->>'triage_status' as status,
                        state_data->>'current_node' as current_node,
                        (state_data->>'confidence_score')::int as confidence_score,
                        COALESCE((state_data->>'threat_score')::int, 0) as threat_score,
                        state_data->'raw_alert'->>'severity' as severity,
                        state_data->'raw_alert'->>'description' as description,
                        state_data->'raw_alert'->>'title' as title,
                        created_at
                    FROM states
                    WHERE created_at >= $1
                    ORDER BY alert_id, version DESC
                    LIMIT $2
                """

                async with storage.pool.acquire() as conn:
                    results = await conn.fetch(query, cutoff_time, limit)
            
            alerts = []
            for row in results:
                alerts.append({
                    "alert_id": row['alert_id'],
                    "workflow_instance_id": row['workflow_instance_id'],
                    "status": row['status'],
                    "current_node": row['current_node'],
                    "confidence_score": row['confidence_score'],
                    "threat_score": row['threat_score'],
                    "severity": row['severity'] or 'medium',
                    "description": row['description'] or row['title'] or 'Security alert',
                    "created_at": row['created_at'].isoformat()
                })
            
            return alerts
            
        except Exception as e:
            self.logger.error(f"Query recent alerts error: {e}")
            return []
    
    async def _collect_system_metrics(self) -> MetricsResponse:
        try:
            app_status = self.lg_sotf_app.get_application_status()
            storage = self.lg_sotf_app.postgres_storage
            
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            
            async with storage.pool.acquire() as conn:
                alerts_today = await conn.fetchval("""
                    SELECT COUNT(DISTINCT alert_id)
                    FROM states
                    WHERE created_at >= $1
                """, cutoff_time)

                alerts_in_progress = await conn.fetchval("""
                    SELECT COUNT(DISTINCT s1.alert_id)
                    FROM states s1
                    INNER JOIN (
                        SELECT alert_id, MAX(version) as max_version
                        FROM states
                        GROUP BY alert_id
                    ) s2 ON s1.alert_id = s2.alert_id AND s1.version = s2.max_version
                    WHERE state_data->>'triage_status' IN ('processing', 'triaged', 'correlated', 'analyzed')
                """)

                # Calculate average processing time (from first state to last state)
                avg_processing_time = await conn.fetchval("""
                    WITH alert_times AS (
                        SELECT
                            alert_id,
                            MIN(created_at) as first_state,
                            MAX(created_at) as last_state
                        FROM states
                        WHERE created_at >= $1
                        GROUP BY alert_id
                    )
                    SELECT AVG(EXTRACT(EPOCH FROM (last_state - first_state)))
                    FROM alert_times
                    WHERE EXTRACT(EPOCH FROM (last_state - first_state)) > 0
                """, cutoff_time)

                # Calculate success rate (closed or responded / total)
                total_completed = await conn.fetchval("""
                    SELECT COUNT(DISTINCT s1.alert_id)
                    FROM states s1
                    INNER JOIN (
                        SELECT alert_id, MAX(version) as max_version
                        FROM states
                        WHERE created_at >= $1
                        GROUP BY alert_id
                    ) s2 ON s1.alert_id = s2.alert_id AND s1.version = s2.max_version
                    WHERE state_data->>'triage_status' IN ('closed', 'responded')
                """, cutoff_time)

                success_rate = (total_completed / alerts_today) if alerts_today and alerts_today > 0 else 0.0

            agent_health = {}
            stats = agent_registry.get_registry_stats()
            for agent_name in stats.get("agent_instances", []):
                try:
                    agent = agent_registry.get_agent(agent_name)
                    agent_health[agent_name] = await agent.health_check() if hasattr(agent, 'health_check') else agent.initialized
                except Exception:
                    agent_health[agent_name] = False

            system_health = app_status.get("running", False) and app_status.get("initialized", False)

            return MetricsResponse(
                timestamp=datetime.utcnow().isoformat(),
                alerts_processed_today=alerts_today or 0,
                alerts_in_progress=alerts_in_progress or 0,
                average_processing_time=float(avg_processing_time) if avg_processing_time else 0.0,
                success_rate=float(success_rate),
                agent_health=agent_health,
                system_health=system_health
            )
            
        except Exception as e:
            self.logger.error(f"Metrics collection error: {e}")
            return MetricsResponse(
                timestamp=datetime.utcnow().isoformat(),
                alerts_processed_today=0,
                alerts_in_progress=0,
                average_processing_time=0.0,
                success_rate=0.0,
                agent_health={},
                system_health=False
            )
    
    async def _get_dashboard_statistics(self) -> DashboardStatsResponse:
        try:
            storage = self.lg_sotf_app.postgres_storage
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            
            async with storage.pool.acquire() as conn:
                total_alerts = await conn.fetchval("""
                    SELECT COUNT(DISTINCT alert_id)
                    FROM states
                    WHERE created_at >= $1
                """, cutoff_time)
                
                high_priority = await conn.fetchval("""
                    SELECT COUNT(DISTINCT s1.alert_id)
                    FROM states s1
                    INNER JOIN (
                        SELECT alert_id, MAX(version) as max_version
                        FROM states
                        WHERE created_at >= $1
                        GROUP BY alert_id
                    ) s2 ON s1.alert_id = s2.alert_id AND s1.version = s2.max_version
                    WHERE (state_data->>'priority_level')::int <= 2
                """, cutoff_time)
                
                status_results = await conn.fetch("""
                    SELECT 
                        state_data->>'triage_status' as status,
                        COUNT(DISTINCT s1.alert_id) as count
                    FROM states s1
                    INNER JOIN (
                        SELECT alert_id, MAX(version) as max_version
                        FROM states
                        WHERE created_at >= $1
                        GROUP BY alert_id
                    ) s2 ON s1.alert_id = s2.alert_id AND s1.version = s2.max_version
                    GROUP BY state_data->>'triage_status'
                """, cutoff_time)
                
                severity_results = await conn.fetch("""
                    SELECT 
                        state_data->'raw_alert'->>'severity' as severity,
                        COUNT(DISTINCT alert_id) as count
                    FROM states
                    WHERE created_at >= $1
                    GROUP BY state_data->'raw_alert'->>'severity'
                """, cutoff_time)
            
            alerts_by_status = {row['status']: row['count'] for row in status_results if row['status']}
            alerts_by_severity = {row['severity']: row['count'] for row in severity_results if row['severity']}

            # NEW: Get top threat indicators from Redis
            top_threat_indicators = await self._get_top_threat_indicators()

            return DashboardStatsResponse(
                total_alerts_today=total_alerts or 0,
                high_priority_alerts=high_priority or 0,
                alerts_by_status=alerts_by_status,
                alerts_by_severity=alerts_by_severity,
                top_threat_indicators=top_threat_indicators,
                recent_escalations=[],
                processing_time_avg=125.0
            )
            
        except Exception as e:
            self.logger.error(f"Dashboard statistics error: {e}")
            return DashboardStatsResponse(
                total_alerts_today=0,
                high_priority_alerts=0,
                alerts_by_status={},
                alerts_by_severity={},
                top_threat_indicators=[],
                recent_escalations=[],
                processing_time_avg=0.0
            )

    async def _get_top_threat_indicators(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top threat indicators from Redis based on frequency and correlation."""
        try:
            redis_storage = self.lg_sotf_app.redis_storage
            if not redis_storage or not redis_storage.redis_client:
                return []

            indicators_data = []

            # Scan all indicator alert sets
            async for key in redis_storage.redis_client.scan_iter(match="indicator:*:alerts"):
                key_str = key.decode('utf-8') if isinstance(key, bytes) else str(key)

                # Extract indicator type and value from key
                # Format: indicator:{type}:{value}:alerts
                parts = key_str.split(":")
                if len(parts) >= 3:
                    indicator_type = parts[1]
                    indicator_value = ":".join(parts[2:-1])  # Handle values with colons

                    # Get count of alerts with this indicator
                    alert_count = await redis_storage.redis_client.scard(key)

                    if alert_count > 0:
                        # Get metadata for additional context
                        metadata_key = f"indicator:{indicator_type}:{indicator_value}"
                        metadata_raw = await redis_storage.redis_client.hgetall(metadata_key)

                        metadata = {}
                        if metadata_raw:
                            for k, v in metadata_raw.items():
                                k_str = k.decode('utf-8') if isinstance(k, bytes) else str(k)
                                v_str = v.decode('utf-8') if isinstance(v, bytes) else str(v)
                                metadata[k_str] = v_str

                        # Calculate threat score based on frequency and recency
                        frequency_count = int(metadata.get('count', alert_count))
                        threat_score = alert_count * 10  # Base score from alert count

                        # Boost score for high-risk indicator types
                        risk_multipliers = {
                            'file_hash': 2.0,
                            'destination_ip': 1.5,
                            'user': 1.3,
                            'username': 1.3,
                            'source_ip': 1.2
                        }
                        threat_score *= risk_multipliers.get(indicator_type, 1.0)

                        indicators_data.append({
                            'indicator': f"{indicator_type}:{indicator_value}",
                            'indicator_type': indicator_type,
                            'indicator_value': indicator_value,
                            'count': alert_count,
                            'frequency': frequency_count,
                            'threat_score': int(threat_score),
                            'first_seen': metadata.get('first_seen'),
                            'last_seen': metadata.get('last_seen')
                        })

            # Sort by threat score descending
            indicators_data.sort(key=lambda x: x['threat_score'], reverse=True)

            # Return top N with formatted output
            top_indicators = []
            for ind in indicators_data[:limit]:
                top_indicators.append({
                    'indicator': ind['indicator'],
                    'indicator_type': ind['indicator_type'],
                    'indicator_value': ind['indicator_value'],
                    'count': ind['count'],
                    'threat_level': 'high' if ind['threat_score'] > 50 else 'medium' if ind['threat_score'] > 20 else 'low',
                    'first_seen': ind['first_seen'],
                    'last_seen': ind['last_seen']
                })

            return top_indicators

        except Exception as e:
            self.logger.error(f"Top threat indicators error: {e}", exc_info=True)
            return []

    async def _get_correlation_metrics(self) -> Dict[str, Any]:
        """Get comprehensive correlation metrics from Redis."""
        try:
            redis_storage = self.lg_sotf_app.redis_storage
            if not redis_storage or not redis_storage.redis_client:
                return {
                    "total_indicators": 0,
                    "total_alerts": 0,
                    "correlation_patterns": {},
                    "timestamp": datetime.utcnow().isoformat()
                }

            # Count total unique indicators
            indicator_count = 0
            alert_ids = set()
            indicator_types = {}

            async for key in redis_storage.redis_client.scan_iter(match="indicator:*:alerts"):
                indicator_count += 1
                key_str = key.decode('utf-8') if isinstance(key, bytes) else str(key)

                # Extract indicator type
                parts = key_str.split(":")
                if len(parts) >= 2:
                    indicator_type = parts[1]
                    indicator_types[indicator_type] = indicator_types.get(indicator_type, 0) + 1

                # Get alerts for this indicator
                alerts_raw = await redis_storage.redis_client.smembers(key)
                for alert in alerts_raw:
                    alert_str = alert.decode('utf-8') if isinstance(alert, bytes) else str(alert)
                    alert_ids.add(alert_str)

            # Count total unique alerts
            total_alerts = len(alert_ids)

            # Calculate correlation patterns
            shared_indicators = 0
            async for key in redis_storage.redis_client.scan_iter(match="indicator:*:alerts"):
                count = await redis_storage.redis_client.scard(key)
                if count > 1:
                    shared_indicators += 1

            return {
                "total_indicators": indicator_count,
                "total_alerts": total_alerts,
                "shared_indicators": shared_indicators,
                "correlation_rate": round((shared_indicators / indicator_count * 100) if indicator_count > 0 else 0, 2),
                "indicator_types": indicator_types,
                "avg_indicators_per_alert": round(indicator_count / total_alerts, 2) if total_alerts > 0 else 0,
                "timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            self.logger.error(f"Correlation metrics error: {e}", exc_info=True)
            return {
                "total_indicators": 0,
                "total_alerts": 0,
                "correlation_patterns": {},
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    async def _get_correlation_network(self, limit: int = 50) -> Dict[str, Any]:
        """Build correlation network graph showing alert relationships."""
        try:
            redis_storage = self.lg_sotf_app.redis_storage
            if not redis_storage or not redis_storage.redis_client:
                return {"nodes": [], "edges": []}

            nodes = []  # Alerts
            edges = []  # Relationships via shared indicators
            alert_indicators = {}  # Track which indicators each alert has

            # Get all alerts
            alert_keys = []
            async for key in redis_storage.redis_client.scan_iter(match="alert:*:indicators"):
                key_str = key.decode('utf-8') if isinstance(key, bytes) else str(key)
                alert_id = key_str.split(":")[1]
                alert_keys.append((alert_id, key_str))

            # Limit to most recent alerts
            alert_keys = alert_keys[:limit]

            # Build nodes and collect indicators
            for alert_id, key in alert_keys:
                # Get indicators for this alert
                indicators_raw = await redis_storage.redis_client.smembers(key)
                indicators = []
                for ind in indicators_raw:
                    ind_str = ind.decode('utf-8') if isinstance(ind, bytes) else str(ind)
                    indicators.append(ind_str)

                alert_indicators[alert_id] = set(indicators)

                # Get alert metadata from PostgreSQL if available
                alert_state = await self._get_alert_state(alert_id)
                severity = "unknown"
                status = "unknown"

                if alert_state:
                    raw_alert = alert_state.get("raw_alert", {}) if isinstance(alert_state, dict) else {}
                    if isinstance(raw_alert, dict):
                        severity = raw_alert.get("severity", "unknown")
                    status = alert_state.get("triage_status", "unknown")

                nodes.append({
                    "id": alert_id,
                    "type": "alert",
                    "label": alert_id,
                    "severity": severity,
                    "status": status,
                    "indicator_count": len(indicators)
                })

            # Build edges (connections via shared indicators)
            edge_id = 0
            processed_pairs = set()

            for alert1_id, indicators1 in alert_indicators.items():
                for alert2_id, indicators2 in alert_indicators.items():
                    if alert1_id >= alert2_id:  # Skip self and duplicates
                        continue

                    # Check if already processed
                    pair = tuple(sorted([alert1_id, alert2_id]))
                    if pair in processed_pairs:
                        continue

                    # Find shared indicators
                    shared = indicators1.intersection(indicators2)

                    if shared:
                        processed_pairs.add(pair)
                        edges.append({
                            "id": f"edge_{edge_id}",
                            "source": alert1_id,
                            "target": alert2_id,
                            "shared_indicators": list(shared),
                            "shared_count": len(shared),
                            "weight": len(shared)  # For graph visualization
                        })
                        edge_id += 1

            return {
                "nodes": nodes,
                "edges": edges,
                "summary": {
                    "total_alerts": len(nodes),
                    "total_connections": len(edges),
                    "timestamp": datetime.utcnow().isoformat()
                }
            }

        except Exception as e:
            self.logger.error(f"Correlation network error: {e}", exc_info=True)
            return {
                "nodes": [],
                "edges": [],
                "error": str(e)
            }

    def _calculate_progress(self, state: Dict[str, Any]) -> int:
        node_progress = {
            "ingestion": 10,
            "triage": 30,
            "correlation": 50,
            "analysis": 70,
            "human_loop": 85,
            "response": 95,
            "close": 100
        }
        
        current_node = state.get("current_node", "ingestion")
        return node_progress.get(current_node, 0)
    
    def _start_background_tasks(self):
        async def metrics_updater():
            while True:
                try:
                    await asyncio.sleep(10)

                    metrics = await self._collect_system_metrics()

                    await self.websocket_manager.broadcast({
                        "type": "system_metrics",
                        "data": metrics.model_dump()
                    }, "system_metrics")

                except asyncio.CancelledError:
                    self.logger.info("Metrics updater cancelled")
                    break
                except Exception as e:
                    self.logger.error(f"Metrics updater error: {e}")

        async def ingestion_monitor():
            """Monitor ingestion activity and broadcast updates."""
            while True:
                try:
                    await asyncio.sleep(5)  # Check every 5 seconds
                    
                    if not self.lg_sotf_app.workflow_engine:
                        continue

                    ingestion_agent = (
                        self.lg_sotf_app.workflow_engine.agents.get("ingestion_instance") or 
                        self.lg_sotf_app.workflow_engine.agents.get("ingestion")
                    )

                    if not ingestion_agent:
                        continue
                    
                    # Broadcast ingestion stats
                    await self.websocket_manager.broadcast({
                        "type": "ingestion_stats",
                        "data": {
                            "total_ingested": ingestion_agent.ingestion_stats["total_ingested"],
                            "total_deduplicated": ingestion_agent.ingestion_stats["total_deduplicated"],
                            "total_errors": ingestion_agent.ingestion_stats["total_errors"],
                            "by_source": dict(ingestion_agent.ingestion_stats["by_source"]),
                            "enabled_sources": ingestion_agent.enabled_sources,
                            "last_poll": self.lg_sotf_app._last_ingestion_poll.isoformat() if self.lg_sotf_app._last_ingestion_poll else None
                        }
                    }, "ingestion_updates")
                    
                except asyncio.CancelledError:
                    self.logger.info("Ingestion monitor cancelled")
                    break
                except Exception as e:
                    self.logger.error(f"Ingestion monitor error: {e}")

        # Create and track background tasks
        self.background_tasks.append(asyncio.create_task(self.websocket_manager.heartbeat_loop()))
        self.background_tasks.append(asyncio.create_task(metrics_updater()))
        self.background_tasks.append(asyncio.create_task(ingestion_monitor()))


async def run_soc_dashboard_api(
    config_path: str = "configs/poc.yaml",
    host: str = "0.0.0.0",
    port: int = 8000
):
    
    lg_sotf_app = LG_SOTFApplication(config_path=config_path)
    await lg_sotf_app.initialize()
    
    api_server = SOCDashboardAPI(lg_sotf_app)
    
    config = uvicorn.Config(
        app=api_server.app,
        host=host,
        port=port,
        log_level="info",
        access_log=True,
        ws_ping_interval=20,
        ws_ping_timeout=10
    )
    
    server = uvicorn.Server(config)
    
    print(f"🚀 Starting SOC Dashboard API server...")
    print(f"📊 API Documentation: http://{host}:{port}/api/docs")
    print(f"🔌 WebSocket endpoint: ws://{host}:{port}/ws/{{client_id}}")
    print(f"💊 Health check: http://{host}:{port}/api/v1/health")
    
    try:
        await server.serve()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down API server...")
        await lg_sotf_app.shutdown()
    finally:
        await lg_sotf_app.shutdown()

def get_application():
    """Factory to create application instance for uvicorn."""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Create app without signal handlers (uvicorn handles signals)
    lg_sotf = LG_SOTFApplication(setup_signal_handlers=False)
    dashboard = SOCDashboardAPI(lg_sotf)

    @dashboard.app.on_event("startup")
    async def startup():
        await lg_sotf.initialize()
    
    @dashboard.app.on_event("shutdown")
    async def shutdown():
        print("\n🛑 Shutting down API server...")

        # Close all WebSocket connections
        if dashboard.websocket_manager.active_connections:
            print(f"Closing {len(dashboard.websocket_manager.active_connections)} WebSocket connections...")
            # Make a copy of the list to avoid modification during iteration
            connections = list(dashboard.websocket_manager.active_connections.values())
            for ws in connections:
                try:
                    await ws.close()
                except Exception as e:
                    print(f"Error closing WebSocket: {e}")
            dashboard.websocket_manager.active_connections.clear()
            print("✓ WebSocket connections closed")

        # Cancel background tasks
        if dashboard.background_tasks:
            print(f"Cancelling {len(dashboard.background_tasks)} background tasks...")
            for task in dashboard.background_tasks:
                if not task.done():
                    task.cancel()

            # Wait for tasks to complete with timeout
            try:
                await asyncio.wait_for(
                    asyncio.gather(*dashboard.background_tasks, return_exceptions=True),
                    timeout=5.0
                )
                print("✓ Background tasks cancelled")
            except asyncio.TimeoutError:
                print("⚠ Some background tasks did not complete within timeout")

        # Shutdown LG-SOTF application
        await lg_sotf.shutdown()
        print("✅ Shutdown complete")
    
    return dashboard.app

# Export app instance for uvicorn
app = get_application()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SOC Dashboard API Server")
    parser.add_argument("--config", "-c", default="configs/poc.yaml", help="Configuration file path")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    asyncio.run(run_soc_dashboard_api(
        config_path=args.config,
        host=args.host,
        port=args.port
    ))