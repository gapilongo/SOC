# src/lg_sotf/main.py (Updated)
"""
Main application entry point for LG-SOTF - Updated with agent initialization.
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

from .src.lg_sotf.audit.logger import AuditLogger
from .src.lg_sotf.audit.metrics import MetricsCollector
from .src.lg_sotf.core.config.manager import ConfigManager
from .src.lg_sotf.core.exceptions import LG_SOTFError
from .src.lg_sotf.core.state.manager import StateManager
from .src.lg_sotf.core.workflow import WorkflowEngine
from .src.lg_sotf.storage.postgres import PostgreSQLStorage
from .src.lg_sotf.storage.redis import RedisStorage


class LG_SOTFApplication:
    """Main application class for LG-SOTF."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the application."""
        self.config_path = config_path
        self.config_manager = None
        self.state_manager = None
        self.workflow_engine = None
        self.audit_logger = None
        self.metrics = None
        self.running = False
        
        # Setup signal handlers
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logging.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    async def initialize(self):
        """Initialize the application components."""
        try:
            # Load configuration
            self.config_manager = ConfigManager(self.config_path)
            
            # Initialize audit and metrics
            self.audit_logger = AuditLogger()
            self.metrics = MetricsCollector()
            
            # Initialize storage
            db_config = self.config_manager.get_database_config()
            connection_string = (
                f"postgresql://{db_config.username}:{db_config.password}@"
                f"{db_config.host}:{db_config.port}/{db_config.database}"
            )
            
            postgres_storage = PostgreSQLStorage(connection_string)
            await postgres_storage.initialize()
            
            redis_config = self.config_manager.get_redis_config()
            redis_connection_string = (
                f"redis://:{redis_config.password}@{redis_config.host}:{redis_config.port}/{redis_config.db}"
            )
            
            redis_storage = RedisStorage(redis_connection_string)
            await redis_storage.initialize()
            
            # Initialize state manager
            self.state_manager = StateManager(postgres_storage)
            
            # Initialize workflow engine
            self.workflow_engine = WorkflowEngine(self.config_manager, self.state_manager)
            await self.workflow_engine.initialize()
            
            # Log application start
            self.audit_logger.log_application_start(
                config_path=self.config_path,
                version="0.1.0"
            )
            
            logging.info("LG-SOTF application initialized successfully")
            
        except Exception as e:
            logging.error(f"Failed to initialize application: {e}")
            raise LG_SOTFError(f"Application initialization failed: {e}")
    
    async def run(self):
        """Run the application."""
        try:
            self.running = True
            logging.info("LG-SOTF application started")
            
            # Main application loop
            while self.running:
                try:
                    # Process alerts (this would be replaced with actual alert processing)
                    await self._process_alerts()
                    
                    # Sleep for a short interval
                    await asyncio.sleep(1)
                    
                except Exception as e:
                    logging.error(f"Error in main loop: {e}")
                    await asyncio.sleep(5)  # Wait before retrying
            
        except KeyboardInterrupt:
            logging.info("Received keyboard interrupt, shutting down...")
        except Exception as e:
            logging.error(f"Unexpected error in main loop: {e}")
        finally:
            await self.shutdown()
    
    async def _process_alerts(self):
        """Process alerts (placeholder for POC)."""
        # This is a placeholder for the actual alert processing logic
        # In Sprint 1, this would be replaced with actual alert ingestion and processing
        pass
    
    async def shutdown(self):
        """Shutdown the application gracefully."""
        try:
            logging.info("Shutting down LG-SOTF application...")
            
            # Log application shutdown
            if self.audit_logger:
                self.audit_logger.log_application_shutdown()
            
            # Shutdown workflow engine
            if self.workflow_engine:
                # Workflow engine will handle agent cleanup
                pass
            
            # Close storage connections
            if self.state_manager:
                # State manager will close storage connections
                pass
            
            # Shutdown metrics collection
            if self.metrics:
                self.metrics.shutdown()
            
            logging.info("LG-SOTF application shutdown completed")
            
        except Exception as e:
            logging.error(f"Error during shutdown: {e}")
    
    async def health_check(self) -> bool:
        """Perform application health check."""
        try:
            # Check configuration
            if not self.config_manager:
                return False
            
            # Check storage
            if not self.state_manager:
                return False
            
            # Check workflow engine
            if not self.workflow_engine:
                return False
            
            # Check database connection
            db_config = self.config_manager.get_database_config()
            connection_string = (
                f"postgresql://{db_config.username}:{db_config.password}@"
                f"{db_config.host}:{db_config.port}/{db_config.database}"
            )
            
            postgres_storage = PostgreSQLStorage(connection_string)
            if not await postgres_storage.health_check():
                return False
            
            # Check Redis connection
            redis_config = self.config_manager.get_redis_config()
            redis_connection_string = (
                f"redis://:{redis_config.password}@{redis_config.host}:{redis_config.port}/{redis_config.db}"
            )
            
            redis_storage = RedisStorage(redis_connection_string)
            if not await redis_storage.health_check():
                return False
            
            return True
            
        except Exception as e:
            logging.error(f"Health check failed: {e}")
            return False


async def main():
    """Main entry point."""
    import argparse

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="LG-SOTF: LangGraph SOC Triage & Orchestration Framework"
    )
    
    parser.add_argument(
        "--config", "-c",
        type=str,
        help="Path to configuration file"
    )
    
    parser.add_argument(
        "--mode", "-m",
        choices=["run", "health-check"],
        default="run",
        help="Application mode"
    )
    
    parser.add_argument(
        "--log-level", "-l",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level"
    )
    
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="LG-SOTF 0.1.0"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Create application instance
    app = LG_SOTFApplication(config_path=args.config)
    
    try:
        # Initialize application
        await app.initialize()
        
        if args.mode == "health-check":
            # Perform health check
            health_status = await app.health_check()
            if health_status:
                print("✅ Application is healthy")
                sys.exit(0)
            else:
                print("❌ Application is not healthy")
                sys.exit(1)
        else:
            # Run application
            await app.run()
            
    except KeyboardInterrupt:
        logging.info("Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Application failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())