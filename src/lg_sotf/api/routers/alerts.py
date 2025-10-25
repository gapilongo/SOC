"""Alert processing and status endpoints."""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from lg_sotf.app_initializer import LG_SOTFApplication
from lg_sotf.api.dependencies import get_lg_sotf_app, get_websocket_manager
from lg_sotf.api.models.alerts import AlertRequest, AlertResponse
from lg_sotf.api.models.workflows import (
    WorkflowStatusResponse,
    CorrelationResponse,
    FeedbackRequest,
)
from lg_sotf.api.utils.websocket import WebSocketManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.post("/process", response_model=AlertResponse)
async def process_alert(
    alert_request: AlertRequest,
    background_tasks: BackgroundTasks,
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app),
    ws_manager: WebSocketManager = Depends(get_websocket_manager),
):
    """Submit a new alert for processing through the workflow."""
    try:
        alert_id = str(uuid4())

        background_tasks.add_task(
            _process_alert_background,
            alert_id,
            alert_request.alert_data,
            lg_sotf_app,
            ws_manager
        )

        await ws_manager.broadcast({
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
        logger.error(f"Alert processing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{alert_id}/status", response_model=WorkflowStatusResponse)
async def get_alert_status(
    alert_id: str,
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app),
):
    """Get current workflow status for an alert."""
    try:
        state = await _get_alert_state(alert_id, lg_sotf_app)

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
            fp_indicators=state.get("fp_indicators", []),
            tp_indicators=state.get("tp_indicators", []),
            correlations=state.get("correlations", []),
            correlation_score=state.get("correlation_score", 0),
            analysis_conclusion=state.get("analysis_conclusion"),
            recommended_actions=state.get("recommended_actions", []),
            last_updated=state.get("last_updated", datetime.utcnow().isoformat()),
            progress_percentage=_calculate_progress(state)
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Status retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("")
async def get_alerts(
    limit: int = 50,
    status: Optional[str] = None,
    hours: int = 24,
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app),
):
    """Query recent alerts with optional filtering."""
    try:
        alerts = await _query_recent_alerts(limit, status, hours, lg_sotf_app)
        return alerts

    except Exception as e:
        logger.error(f"Alert retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{alert_id}/correlations", response_model=CorrelationResponse)
async def get_alert_correlations(
    alert_id: str,
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app),
):
    """Get correlations for a specific alert."""
    try:
        correlations = await _get_alert_correlations(alert_id, lg_sotf_app)
        return correlations

    except Exception as e:
        logger.error(f"Correlation retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Helper functions

async def _process_alert_background(
    alert_id: str,
    alert_data: Dict[str, Any],
    lg_sotf_app: LG_SOTFApplication,
    ws_manager: WebSocketManager,
):
    """Background task to process an alert through the workflow."""
    try:
        await ws_manager.broadcast({
            "type": "ingestion_event",
            "event": "alert_ingested",
            "alert_id": alert_id,
            "source": alert_data.get("source", "unknown"),
            "severity": alert_data.get("severity", "unknown"),
            "timestamp": datetime.utcnow().isoformat()
        }, "ingestion_updates")

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
        logger.error(f"Background processing failed: {e}")

        await ws_manager.broadcast({
            "type": "alert_update",
            "alert_id": alert_id,
            "status": "failed",
            "error": str(e)
        }, "alert_updates")


async def _get_alert_state(alert_id: str, lg_sotf_app: LG_SOTFApplication) -> Optional[Dict[str, Any]]:
    """Retrieve alert state from PostgreSQL."""
    try:
        storage = lg_sotf_app.postgres_storage

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
            logger.info(f"State data for {alert_id}: triage_status={state_data.get('triage_status')}, confidence={state_data.get('confidence_score')}, threat_score={state_data.get('threat_score', 0)}")

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

            logger.info(f"Returning merged state: confidence={merged_state['confidence_score']}, threat_score={merged_state['threat_score']}, status={merged_state['triage_status']}")

            return merged_state

    except Exception as e:
        logger.error(f"State retrieval error: {e}", exc_info=True)
        return None


async def _query_recent_alerts(
    limit: int,
    status: Optional[str],
    hours: int,
    lg_sotf_app: LG_SOTFApplication
) -> List[Dict]:
    """Query recent alerts from PostgreSQL with filtering."""
    try:
        storage = lg_sotf_app.postgres_storage
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
        logger.error(f"Query recent alerts error: {e}")
        return []


async def _get_alert_correlations(alert_id: str, lg_sotf_app: LG_SOTFApplication) -> CorrelationResponse:
    """Get correlations for a specific alert with Redis integration."""
    try:
        # Get the alert state
        state = await _get_alert_state(alert_id, lg_sotf_app)

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

        # Get Redis-based real-time correlations
        redis_correlations = await _get_redis_correlations(alert_id, lg_sotf_app)

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
        logger.error(f"Correlation retrieval error: {e}")
        return CorrelationResponse(
            alert_id=alert_id,
            correlations=[],
            correlation_score=0,
            attack_campaign_indicators=[],
            threat_actor_patterns=[]
        )


async def _get_redis_correlations(alert_id: str, lg_sotf_app: LG_SOTFApplication) -> List[Dict[str, Any]]:
    """Get real-time correlations from Redis."""
    correlations = []

    try:
        redis_storage = lg_sotf_app.redis_storage
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
        logger.error(f"Redis correlation retrieval error: {e}", exc_info=True)
        return []


def _calculate_progress(state: Dict[str, Any]) -> int:
    """Calculate workflow progress percentage based on current node."""
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
