"""FastAPI application factory for LG-SOTF API."""

import asyncio
import logging
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from lg_sotf.app_initializer import LG_SOTFApplication
from lg_sotf.api.utils.websocket import WebSocketManager
from lg_sotf.api.routers import (
    alerts,
    correlations,
    dashboard,
    escalations,
    ingestion,
    metrics,
    websocket,
)

logger = logging.getLogger(__name__)


def create_app(
    config_path: str = "configs/development.yaml",
    setup_signal_handlers: bool = False,
) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        config_path: Path to configuration file
        setup_signal_handlers: Whether to setup signal handlers (False for uvicorn)

    Returns:
        Configured FastAPI application instance
    """
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Create FastAPI app
    app = FastAPI(
        title="LG-SOTF Dashboard API",
        description="Production-grade SOC Dashboard API",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc"
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Create application instances (will be initialized in startup event)
    lg_sotf_app = LG_SOTFApplication(
        config_path=config_path,
        setup_signal_handlers=setup_signal_handlers
    )
    ws_manager = WebSocketManager()

    # Store in app state for dependency injection
    app.state.lg_sotf_app = lg_sotf_app
    app.state.ws_manager = ws_manager

    # Track background tasks for proper shutdown
    app.state.background_tasks = []

    # Register routers
    app.include_router(metrics.router)
    app.include_router(alerts.router)
    app.include_router(ingestion.router)
    app.include_router(dashboard.router)
    app.include_router(correlations.router)
    app.include_router(escalations.router)
    app.include_router(websocket.router)

    # Startup event handler
    @app.on_event("startup")
    async def startup():
        """Initialize application on startup."""
        logger.info("Starting LG-SOTF API server...")

        # Initialize LG-SOTF application
        await lg_sotf_app.initialize()
        logger.info("LG-SOTF application initialized")

        # Start background tasks
        _start_background_tasks(app)
        logger.info("Background tasks started")

        logger.info("✅ LG-SOTF API server ready")

    # Shutdown event handler
    @app.on_event("shutdown")
    async def shutdown():
        """Cleanup on shutdown."""
        logger.info("🛑 Shutting down API server...")

        # Close all WebSocket connections
        if ws_manager.active_connections:
            logger.info(f"Closing {len(ws_manager.active_connections)} WebSocket connections...")
            connections = list(ws_manager.active_connections.values())
            for ws in connections:
                try:
                    await ws.close()
                except Exception as e:
                    logger.error(f"Error closing WebSocket: {e}")
            ws_manager.active_connections.clear()
            logger.info("✓ WebSocket connections closed")

        # Cancel background tasks
        if app.state.background_tasks:
            logger.info(f"Cancelling {len(app.state.background_tasks)} background tasks...")
            for task in app.state.background_tasks:
                if not task.done():
                    task.cancel()

            # Wait for tasks to complete with timeout
            try:
                await asyncio.wait_for(
                    asyncio.gather(*app.state.background_tasks, return_exceptions=True),
                    timeout=5.0
                )
                logger.info("✓ Background tasks cancelled")
            except asyncio.TimeoutError:
                logger.warning("⚠ Some background tasks did not complete within timeout")

        # Shutdown LG-SOTF application
        await lg_sotf_app.shutdown()
        logger.info("✅ Shutdown complete")

    return app


def _start_background_tasks(app: FastAPI):
    """Start background monitoring and update tasks."""
    ws_manager: WebSocketManager = app.state.ws_manager
    lg_sotf_app: LG_SOTFApplication = app.state.lg_sotf_app

    async def metrics_updater():
        """Periodically collect and broadcast system metrics."""
        while True:
            try:
                await asyncio.sleep(10)

                # Import here to avoid circular dependency
                from lg_sotf.api.routers.metrics import _collect_system_metrics

                metrics = await _collect_system_metrics(lg_sotf_app)

                await ws_manager.broadcast({
                    "type": "system_metrics",
                    "data": metrics.model_dump()
                }, "system_metrics")

            except asyncio.CancelledError:
                logger.info("Metrics updater cancelled")
                break
            except Exception as e:
                logger.error(f"Metrics updater error: {e}")

    async def ingestion_monitor():
        """Monitor ingestion activity and broadcast updates."""
        while True:
            try:
                await asyncio.sleep(5)  # Check every 5 seconds

                if not lg_sotf_app.workflow_engine:
                    continue

                ingestion_agent = (
                    lg_sotf_app.workflow_engine.agents.get("ingestion_instance") or
                    lg_sotf_app.workflow_engine.agents.get("ingestion")
                )

                if not ingestion_agent:
                    continue

                # Broadcast ingestion stats
                await ws_manager.broadcast({
                    "type": "ingestion_stats",
                    "data": {
                        "total_ingested": ingestion_agent.ingestion_stats["total_ingested"],
                        "total_deduplicated": ingestion_agent.ingestion_stats["total_deduplicated"],
                        "total_errors": ingestion_agent.ingestion_stats["total_errors"],
                        "by_source": dict(ingestion_agent.ingestion_stats["by_source"]),
                        "enabled_sources": ingestion_agent.enabled_sources,
                        "last_poll": lg_sotf_app._last_ingestion_poll.isoformat() if lg_sotf_app._last_ingestion_poll else None
                    }
                }, "ingestion_updates")

            except asyncio.CancelledError:
                logger.info("Ingestion monitor cancelled")
                break
            except Exception as e:
                logger.error(f"Ingestion monitor error: {e}")

    # Create and track background tasks
    app.state.background_tasks.append(asyncio.create_task(ws_manager.heartbeat_loop()))
    app.state.background_tasks.append(asyncio.create_task(metrics_updater()))
    app.state.background_tasks.append(asyncio.create_task(ingestion_monitor()))


# Create app instance for uvicorn
app = create_app()
