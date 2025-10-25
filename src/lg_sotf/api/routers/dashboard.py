"""Dashboard statistics and analytics endpoints."""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException

from lg_sotf.app_initializer import LG_SOTFApplication
from lg_sotf.api.dependencies import get_lg_sotf_app
from lg_sotf.api.models.metrics import DashboardStatsResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats(
    lg_sotf_app: LG_SOTFApplication = Depends(get_lg_sotf_app)
):
    """Get comprehensive dashboard statistics."""
    try:
        stats = await _get_dashboard_statistics(lg_sotf_app)
        return stats

    except Exception as e:
        logger.error(f"Dashboard stats retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Helper functions

async def _get_dashboard_statistics(lg_sotf_app: LG_SOTFApplication) -> DashboardStatsResponse:
    """Collect dashboard statistics from PostgreSQL and Redis."""
    try:
        storage = lg_sotf_app.postgres_storage
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

        # Get top threat indicators from Redis
        top_threat_indicators = await _get_top_threat_indicators(lg_sotf_app)

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
        logger.error(f"Dashboard statistics error: {e}")
        return DashboardStatsResponse(
            total_alerts_today=0,
            high_priority_alerts=0,
            alerts_by_status={},
            alerts_by_severity={},
            top_threat_indicators=[],
            recent_escalations=[],
            processing_time_avg=0.0
        )


async def _get_top_threat_indicators(lg_sotf_app: LG_SOTFApplication, limit: int = 10) -> List[Dict[str, Any]]:
    """Get top threat indicators from Redis based on frequency and correlation."""
    try:
        redis_storage = lg_sotf_app.redis_storage
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
        logger.error(f"Top threat indicators error: {e}", exc_info=True)
        return []
