"""Lightweight main entry point for LG-SOTF."""

import argparse
import logging

import uvicorn


def main():
    """Run the LG-SOTF API server."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="LG-SOTF SOC Dashboard API Server")
    parser.add_argument("--config", "-c", default="configs/development.yaml", help="Configuration file path")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    args = parser.parse_args()

    # Print startup banner
    print("🚀 Starting LG-SOTF SOC Dashboard API server...")
    print(f"📊 API Documentation: http://{args.host}:{args.port}/api/docs")
    print(f"🔌 WebSocket endpoint: ws://{args.host}:{args.port}/ws/{{client_id}}")
    print(f"💊 Health check: http://{args.host}:{args.port}/api/v1/health")
    print()

    # Run uvicorn server
    uvicorn.run(
        "lg_sotf.api.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
        access_log=True,
        ws_ping_interval=20,
        ws_ping_timeout=10,
    )


if __name__ == "__main__":
    main()
