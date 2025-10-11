
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
    processing_notes: List[str]
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
                
                return WorkflowStatusResponse(
                    alert_id=alert_id,
                    workflow_instance_id=state.get("workflow_instance_id", ""),
                    current_node=state.get("current_node", "unknown"),
                    triage_status=state.get("triage_status", "unknown"),
                    confidence_score=state.get("confidence_score", 0),
                    processing_notes=state.get("processing_notes", []),
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
    
    async def _process_alert_background(self, alert_id: str, alert_data: Dict[str, Any]):
        try:
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
        """Get correlations for a specific alert."""
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
            
            # Extract correlation data from metadata
            metadata = state.get("metadata", {}) if isinstance(state, dict) else {}
            
            return CorrelationResponse(
                alert_id=alert_id,
                correlations=metadata.get("correlations", []),
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
                self.logger.info(f"State data for {alert_id}: triage_status={state_data.get('triage_status')}, confidence={state_data.get('confidence_score')}")
                
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
                merged_state = {
                    "alert_id": alert_id,
                    "workflow_instance_id": state_data.get("workflow_instance_id", ""),
                    "current_node": state_data.get("current_node", "unknown"),
                    "triage_status": triage_status,
                    "confidence_score": int(state_data.get("confidence_score", 0)),
                    "processing_notes": metadata.get("processing_notes", []),
                    "last_updated": result['created_at'].isoformat()
                }
                
                self.logger.info(f"Returning merged state: confidence={merged_state['confidence_score']}, status={merged_state['triage_status']}")
                
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
                average_processing_time=120.0,
                success_rate=0.95,
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
            
            return DashboardStatsResponse(
                total_alerts_today=total_alerts or 0,
                high_priority_alerts=high_priority or 0,
                alerts_by_status=alerts_by_status,
                alerts_by_severity=alerts_by_severity,
                top_threat_indicators=[
                    {"indicator": "malware_detection", "count": 15},
                    {"indicator": "suspicious_network_activity", "count": 12},
                    {"indicator": "privilege_escalation", "count": 8}
                ],
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
                    
                except Exception as e:
                    self.logger.error(f"Metrics updater error: {e}")
        
        asyncio.create_task(self.websocket_manager.heartbeat_loop())
        asyncio.create_task(metrics_updater())


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
    
    lg_sotf = LG_SOTFApplication(config_path="configs/poc.yaml")
    dashboard = SOCDashboardAPI(lg_sotf)
    
    @dashboard.app.on_event("startup")
    async def startup():
        await lg_sotf.initialize()
    
    @dashboard.app.on_event("shutdown") 
    async def shutdown():
        await lg_sotf.shutdown()
    
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