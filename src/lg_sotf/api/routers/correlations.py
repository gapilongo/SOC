"""Correlation metrics and network analysis endpoints."""

import json
import logging
from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from lg_sotf.app_initializer import LG_SOTFApplication
from lg_sotf.api.dependencies import get_lg_sotf_app

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/correlations", tags=["correlations"])


@router.get("/metrics")
async def get_correlation_metrics(
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app)
):
    """Get real-time correlation metrics from Redis."""
    try:
        metrics = await _get_correlation_metrics(lg_sotf_app)
        return metrics

    except Exception as e:
        logger.error(f"Correlation metrics retrieval failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/network")
async def get_correlation_network(
    limit: int = 50,
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app)
):
    """Get correlation network graph data showing alert relationships."""
    try:
        network_data = await _get_correlation_network(limit, lg_sotf_app)
        return network_data

    except Exception as e:
        logger.error(f"Correlation network retrieval failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# Helper functions

async def _get_correlation_metrics(lg_sotf_app: LG_SOTFApplication) -> Dict[str, Any]:
    """Get comprehensive correlation metrics from Redis."""
    try:
        redis_storage = lg_sotf_app.redis_storage
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
        logger.error(f"Correlation metrics error: {e}", exc_info=True)
        return {
            "total_indicators": 0,
            "total_alerts": 0,
            "correlation_patterns": {},
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


async def _get_correlation_network(limit: int, lg_sotf_app: LG_SOTFApplication) -> Dict[str, Any]:
    """Build correlation network graph showing alert relationships."""
    try:
        redis_storage = lg_sotf_app.redis_storage
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
            alert_state = await _get_alert_state(alert_id, lg_sotf_app)
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
        logger.error(f"Correlation network error: {e}", exc_info=True)
        return {
            "nodes": [],
            "edges": [],
            "error": str(e)
        }


async def _get_alert_state(alert_id: str, lg_sotf_app: LG_SOTFApplication) -> Dict[str, Any]:
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
                return {}

            state_json = result['state_data']
            state_data = json.loads(state_json) if isinstance(state_json, str) else state_json

            # Handle enum conversion for triage_status
            triage_status = state_data.get("triage_status", "unknown")
            if isinstance(triage_status, dict) and "_value_" in triage_status:
                triage_status = triage_status["_value_"]
            elif hasattr(triage_status, 'value'):
                triage_status = triage_status.value
            else:
                triage_status = str(triage_status).replace("TriageStatus.", "").replace("_", " ").lower()

            return {
                "alert_id": alert_id,
                "triage_status": triage_status,
                "raw_alert": state_data.get("raw_alert", {})
            }

    except Exception as e:
        logger.error(f"Alert state retrieval error: {e}")
        return {}
