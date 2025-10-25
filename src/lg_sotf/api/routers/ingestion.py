"""Ingestion control and monitoring endpoints."""

import asyncio
import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException

from lg_sotf.app_initializer import LG_SOTFApplication
from lg_sotf.api.dependencies import get_lg_sotf_app, get_websocket_manager
from lg_sotf.api.models.ingestion import (
    IngestionStatusResponse,
    IngestionControlRequest,
)
from lg_sotf.api.utils.websocket import WebSocketManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ingestion", tags=["ingestion"])


@router.get("/status", response_model=IngestionStatusResponse)
async def get_ingestion_status(
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app)
):
    """Get current ingestion status and metrics."""
    try:
        if not lg_sotf_app.workflow_engine or "ingestion" not in lg_sotf_app.workflow_engine.agents:
            raise HTTPException(status_code=503, detail="Ingestion agent not available")

        ingestion_agent = (
            lg_sotf_app.workflow_engine.agents.get("ingestion_instance") or
            lg_sotf_app.workflow_engine.agents.get("ingestion")
        )
        ingestion_config = lg_sotf_app.config_manager.get_agent_config("ingestion")

        # Calculate next poll time
        next_poll = None
        if lg_sotf_app._last_ingestion_poll:
            polling_interval = ingestion_config.get("polling_interval", 60)
            next_poll = (lg_sotf_app._last_ingestion_poll + timedelta(seconds=polling_interval)).isoformat()

        # Check if ingestion is active (agent is initialized and has sources)
        # Note: We check initialized + enabled sources instead of self.running
        # because the app can run in API-only mode without the continuous loop
        is_active = ingestion_agent.initialized and len(ingestion_agent.enabled_sources) > 0

        return IngestionStatusResponse(
            is_active=is_active,
            last_poll_time=lg_sotf_app._last_ingestion_poll.isoformat() if lg_sotf_app._last_ingestion_poll else None,
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
        logger.error(f"Ingestion status retrieval failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/control")
async def control_ingestion(
    request: IngestionControlRequest,
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app),
    ws_manager: WebSocketManager = Depends(get_websocket_manager),
):
    """Control ingestion process (trigger poll, etc)."""
    try:
        ingestion_agent = (
            lg_sotf_app.workflow_engine.agents.get("ingestion_instance") or
            lg_sotf_app.workflow_engine.agents.get("ingestion")
        )

        if not ingestion_agent:
            raise HTTPException(status_code=503, detail="Ingestion agent not available")

        if request.action == "trigger_poll":
            # Actually poll - don't just reset the timer
            logger.info("Manual ingestion poll triggered")

            try:
                # Call poll_sources directly
                new_alerts = await ingestion_agent.poll_sources()

                # Update last poll timestamp
                lg_sotf_app._last_ingestion_poll = datetime.utcnow()

                logger.info(f"Manual poll found {len(new_alerts)} alerts")

                # Broadcast ingestion triggered event
                await ws_manager.broadcast({
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
                        await ws_manager.broadcast({
                            "type": "new_alert",
                            "alert_id": alert["id"],
                            "severity": alert.get("severity", "unknown"),
                            "source": alert.get("source", "unknown"),
                            "timestamp": datetime.utcnow().isoformat()
                        }, "new_alerts")

                        # Process alert in background
                        asyncio.create_task(
                            _process_alert_background(alert["id"], alert, lg_sotf_app, ws_manager)
                        )

                    except Exception as e:
                        logger.error(f"Error processing alert {alert.get('id')}: {e}")

                return {
                    "status": "success",
                    "message": f"Ingestion poll completed - found {len(new_alerts)} alerts",
                    "alerts_found": len(new_alerts),
                    "timestamp": datetime.utcnow().isoformat()
                }

            except Exception as e:
                logger.error(f"Manual poll failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=f"Poll failed: {str(e)}")

        elif request.action == "get_stats":
            return ingestion_agent.get_source_stats()

        else:
            raise HTTPException(status_code=400, detail=f"Unknown action: {request.action}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ingestion control failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sources")
async def get_ingestion_sources(
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app)
):
    """Get all configured ingestion sources and their status."""
    try:
        if not lg_sotf_app.workflow_engine or "ingestion" not in lg_sotf_app.workflow_engine.agents:
            return {"sources": []}

        ingestion_agent = (
            lg_sotf_app.workflow_engine.agents.get("ingestion_instance") or
            lg_sotf_app.workflow_engine.agents.get("ingestion")
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
                logger.warning(f"Error getting info for source {source_name}: {e}")
                sources_info.append({
                    "name": source_name,
                    "enabled": False,
                    "healthy": False,
                    "error": str(e)
                })

        return {"sources": sources_info}

    except Exception as e:
        logger.error(f"Sources retrieval failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# Helper functions

async def _process_alert_background(
    alert_id: str,
    alert_data: dict,
    lg_sotf_app: LG_SOTFApplication,
    ws_manager: WebSocketManager,
):
    """Process an alert through the workflow."""
    try:
        await ws_manager.broadcast({
            "type": "alert_update",
            "alert_id": alert_id,
            "status": "processing",
            "progress": 10
        }, "alert_updates")

        result = await lg_sotf_app.process_single_alert(alert_id, alert_data)

        await ws_manager.broadcast({
            "type": "alert_update",
            "alert_id": alert_id,
            "status": "completed",
            "progress": 100,
            "result": result
        }, "alert_updates")

    except Exception as e:
        logger.error(f"Background processing failed for {alert_id}: {e}")

        await ws_manager.broadcast({
            "type": "alert_update",
            "alert_id": alert_id,
            "status": "failed",
            "error": str(e)
        }, "alert_updates")
