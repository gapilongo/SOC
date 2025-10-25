"""Health and metrics endpoints."""

import logging
from datetime import datetime, timedelta
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from lg_sotf.app_initializer import LG_SOTFApplication
from lg_sotf.agents.registry import agent_registry
from lg_sotf.api.dependencies import get_lg_sotf_app
from lg_sotf.api.models.metrics import (
    MetricsResponse,
    AgentStatusResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["metrics"])


@router.get("/health")
async def health_check(
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app)
):
    """Health check endpoint."""
    try:
        app_health = await lg_sotf_app.health_check()

        # Get WebSocket manager from app state
        from fastapi import Request
        request: Request = lg_sotf_app  # This will be properly injected
        ws_manager = getattr(request.app.state, 'ws_manager', None)
        ws_connections = len(ws_manager.active_connections) if ws_manager else 0

        return {
            "status": "healthy" if app_health else "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "components": {
                "lg_sotf_app": app_health,
                "websocket_connections": ws_connections,
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


@router.get("/metrics", response_model=MetricsResponse)
async def get_system_metrics(
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app)
):
    """Get system-wide metrics."""
    try:
        return await _collect_system_metrics(lg_sotf_app)
    except Exception as e:
        logger.error(f"Metrics collection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents/status", response_model=List[AgentStatusResponse])
async def get_agents_status(
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app)
):
    """Get status of all registered agents."""
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
                logger.warning(f"Agent {agent_name} status error: {e}")
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
        logger.error(f"Agent status retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Helper functions

async def _collect_system_metrics(lg_sotf_app: LG_SOTFApplication) -> MetricsResponse:
    """Collect comprehensive system metrics from PostgreSQL."""
    try:
        app_status = lg_sotf_app.get_application_status()
        storage = lg_sotf_app.postgres_storage

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
        logger.error(f"Metrics collection error: {e}")
        return MetricsResponse(
            timestamp=datetime.utcnow().isoformat(),
            alerts_processed_today=0,
            alerts_in_progress=0,
            average_processing_time=0.0,
            success_rate=0.0,
            agent_health={},
            system_health=False
        )
