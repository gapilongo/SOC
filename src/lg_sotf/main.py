"""
Main application entry point for LG-SOTF - Fixed agent initialization.
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

# Fixed imports - remove .src prefix
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.audit.metrics import MetricsCollector
from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.core.exceptions import LG_SOTFError
from lg_sotf.core.state.manager import StateManager
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.storage.postgres import PostgreSQLStorage
from lg_sotf.storage.redis import RedisStorage


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
            logging.info("Initializing LG-SOTF application...")
            
            # Load configuration
            self.config_manager = ConfigManager(self.config_path)
            logging.info("Configuration loaded successfully")
            
            # Initialize audit and metrics
            self.audit_logger = AuditLogger()
            self.metrics = MetricsCollector(self.config_manager)
            logging.info("Audit and metrics initialized")
            
            # Initialize storage backends
            await self._initialize_storage()
            logging.info("Storage backends initialized")
            
            # Initialize state manager
            self.state_manager = StateManager(self.postgres_storage)
            logging.info("State manager initialized")
            
            # ✅ REMOVED: Duplicate agent initialization
            # The WorkflowEngine will handle all agent setup
            
            # Initialize workflow engine (this will setup agents)
            self.workflow_engine = WorkflowEngine(self.config_manager, self.state_manager)
            await self.workflow_engine.initialize()
            logging.info("Workflow engine initialized")
            
            # Get agent registry stats AFTER workflow engine initialization
            from lg_sotf.agents.registry import agent_registry
            stats = agent_registry.get_registry_stats()
            logging.info(f"Agent registry stats: {stats}")
            
            # Log application start
            self.audit_logger.log_application_start(
                config_path=self.config_path,
                version="0.1.0"
            )
            
            logging.info("LG-SOTF application initialized successfully")
            
        except Exception as e:
            logging.error(f"Failed to initialize application: {e}")
            raise LG_SOTFError(f"Application initialization failed: {e}")
    
    async def _initialize_storage(self):
        """Initialize storage backends."""
        try:
            # Initialize PostgreSQL
            db_config = self.config_manager.get_database_config()
            connection_string = (
                f"postgresql://{db_config.username}:{db_config.password}@"
                f"{db_config.host}:{db_config.port}/{db_config.database}"
            )
            
            self.postgres_storage = PostgreSQLStorage(connection_string)
            await self.postgres_storage.initialize()
            logging.info("PostgreSQL storage initialized")
            
            # Initialize Redis
            redis_config = self.config_manager.get_redis_config()
            redis_connection_string = (
                f"redis://:{redis_config.password or ''}@{redis_config.host}:{redis_config.port}/{redis_config.db}"
            )
            
            self.redis_storage = RedisStorage(redis_connection_string)
            await self.redis_storage.initialize()
            logging.info("Redis storage initialized")
            
        except Exception as e:
            logging.error(f"Failed to initialize storage: {e}")
            raise
    
    # ✅ REMOVED: _initialize_agents method entirely
    # Let WorkflowEngine handle all agent initialization
    
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
                    
                    # Perform periodic health checks
                    await self._perform_health_checks()
                    
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
    
    async def _perform_health_checks(self):
        """Perform periodic health checks."""
        try:
            # Check every 60 seconds
            if hasattr(self, '_last_health_check'):
                import time
                if time.time() - self._last_health_check < 60:
                    return
            
            # Perform health checks
            health_status = await self.health_check()
            
            if not health_status:
                logging.warning("Health check failed - some components may be unhealthy")
            
            # Update last health check time
            import time
            self._last_health_check = time.time()
            
        except Exception as e:
            logging.error(f"Error during health check: {e}")
    
    async def shutdown(self):
        """Shutdown the application gracefully."""
        try:
            logging.info("Shutting down LG-SOTF application...")
            
            # Log application shutdown
            if self.audit_logger:
                self.audit_logger.log_application_shutdown()
            
            # Shutdown agents (through workflow engine)
            await self._shutdown_agents()
            
            # Shutdown workflow engine
            if self.workflow_engine:
                # Workflow engine cleanup if needed
                pass
            
            # Close storage connections properly
            await self._shutdown_storage()
            
            # Shutdown metrics collection
            if self.metrics:
                try:
                    self.metrics.shutdown()
                    logging.info("Metrics collection shutdown")
                except Exception as e:
                    logging.warning(f"Error shutting down metrics: {e}")
            
            logging.info("LG-SOTF application shutdown completed")
            
        except Exception as e:
            logging.error(f"Error during shutdown: {e}")
    
    async def _shutdown_agents(self):
        """Shutdown all agents."""
        try:
            from lg_sotf.agents.registry import agent_registry
            
            logging.info("Shutting down agents...")
            await agent_registry.cleanup_all_agents()
            logging.info("All agents shutdown completed")
            
        except Exception as e:
            logging.warning(f"Error shutting down agents: {e}")
    
    async def _shutdown_storage(self):
        """Shutdown storage connections."""
        storage_tasks = []
        
        # Schedule storage cleanup
        if hasattr(self, 'postgres_storage') and self.postgres_storage:
            try:
                storage_tasks.append(self.postgres_storage.close())
            except Exception as e:
                logging.warning(f"Error scheduling PostgreSQL close: {e}")
        
        if hasattr(self, 'redis_storage') and self.redis_storage:
            try:
                storage_tasks.append(self.redis_storage.close())
            except Exception as e:
                logging.warning(f"Error scheduling Redis close: {e}")
        
        # Wait for storage cleanup with timeout
        if storage_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*storage_tasks, return_exceptions=True),
                    timeout=5.0
                )
                logging.info("Storage connections closed")
            except asyncio.TimeoutError:
                logging.warning("Storage cleanup timed out")
            except Exception as e:
                logging.warning(f"Error during storage cleanup: {e}")
    
    async def health_check(self) -> bool:
        """Perform application health check."""
        try:
            health_results = {
                'config_manager': False,
                'state_manager': False,
                'workflow_engine': False,
                'postgres_storage': False,
                'redis_storage': False,
                'agents': False
            }
            
            # Check configuration
            if self.config_manager:
                health_results['config_manager'] = True
            
            # Check state manager
            if self.state_manager:
                health_results['state_manager'] = True
            
            # Check workflow engine
            if self.workflow_engine:
                health_results['workflow_engine'] = True
            
            # Check PostgreSQL connection
            if hasattr(self, 'postgres_storage') and self.postgres_storage:
                health_results['postgres_storage'] = await self.postgres_storage.health_check()
            
            # Check Redis connection
            if hasattr(self, 'redis_storage') and self.redis_storage:
                health_results['redis_storage'] = await self.redis_storage.health_check()
            
            # Check agents
            try:
                from lg_sotf.agents.registry import agent_registry

                # Check if triage agent is healthy
                if agent_registry.agent_exists("triage_instance"):  # ✅ Use correct agent name
                    triage_agent = agent_registry.get_agent("triage_instance")
                    if hasattr(triage_agent, 'health_check'):
                        health_results['agents'] = await triage_agent.health_check()
                    else:
                        health_results['agents'] = triage_agent.initialized
                
            except Exception as e:
                logging.warning(f"Error checking agent health: {e}")
                health_results['agents'] = False
            
            # Log health status
            unhealthy_components = [comp for comp, status in health_results.items() if not status]
            if unhealthy_components:
                logging.warning(f"Unhealthy components: {unhealthy_components}")
            else:
                logging.debug("All components healthy")
            
            # Return overall health status
            overall_health = all(health_results.values())
            
            # Record health metrics
            if self.metrics:
                for component, status in health_results.items():
                    self.metrics.set_gauge(f"health_{component}", 1 if status else 0)
                self.metrics.set_gauge("health_overall", 1 if overall_health else 0)
            
            return overall_health
            
        except Exception as e:
            logging.error(f"Health check failed: {e}")
            return False
    
    async def process_single_alert(self, alert_id: str, alert_data: dict) -> dict:
        """Process a single alert through the workflow (for testing/POC)."""
        try:
            if not self.workflow_engine:
                raise LG_SOTFError("Workflow engine not initialized")
            
            logging.info(f"Processing alert {alert_id}")
            
            # Execute the workflow
            result = await self.workflow_engine.execute_workflow(alert_id, alert_data)
            
            logging.info(f"Alert {alert_id} processed successfully")
            return result
            
        except Exception as e:
            logging.error(f"Failed to process alert {alert_id}: {e}")
            raise
    
    def get_application_status(self) -> dict:
        """Get application status information."""
        try:
            status = {
                'running': self.running,
                'initialized': all([
                    self.config_manager is not None,
                    self.state_manager is not None,
                    self.workflow_engine is not None
                ]),
                'components': {
                    'config_manager': self.config_manager is not None,
                    'state_manager': self.state_manager is not None,
                    'workflow_engine': self.workflow_engine is not None,
                    'audit_logger': self.audit_logger is not None,
                    'metrics': self.metrics is not None
                }
            }
            
            # Add agent status
            try:
                from lg_sotf.agents.registry import agent_registry
                status['agents'] = agent_registry.get_registry_stats()
            except Exception as e:
                logging.warning(f"Error getting agent status: {e}")
                status['agents'] = {'error': str(e)}
            
            # Add storage status
            status['storage'] = {
                'postgres': hasattr(self, 'postgres_storage') and self.postgres_storage is not None,
                'redis': hasattr(self, 'redis_storage') and self.redis_storage is not None
            }
            
            return status
            
        except Exception as e:
            logging.error(f"Error getting application status: {e}")
            return {'error': str(e)}


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
        choices=["run", "health-check", "process-alert"],
        default="run",
        help="Application mode"
    )
    
    parser.add_argument(
        "--alert-id",
        type=str,
        help="Alert ID for process-alert mode"
    )
    
    parser.add_argument(
        "--alert-data",
        type=str,
        help="Alert data JSON file for process-alert mode"
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
            status_info = app.get_application_status()
            
            print("🏥 Application Health Check")
            print("=" * 40)
            print(f"Overall Health: {'✅ Healthy' if health_status else '❌ Unhealthy'}")
            print(f"Running: {'✅ Yes' if status_info['running'] else '❌ No'}")
            print(f"Initialized: {'✅ Yes' if status_info['initialized'] else '❌ No'}")
            
            print("\n🔧 Components:")
            for component, status in status_info['components'].items():
                print(f"  {component}: {'✅' if status else '❌'}")
            
            print("\n🤖 Agents:")
            if 'error' in status_info['agents']:
                print(f"  Error: {status_info['agents']['error']}")
            else:
                agents_info = status_info['agents']
                print(f"  Types: {agents_info['agent_types_count']}")
                print(f"  Instances: {agents_info['agent_instances_count']}")
                print(f"  Initialized: {len(agents_info['initialized_agents'])}")
            
            print("\n💾 Storage:")
            for storage_type, status in status_info['storage'].items():
                print(f"  {storage_type}: {'✅' if status else '❌'}")
            
            sys.exit(0 if health_status else 1)
        
        elif args.mode == "process-alert":
            # Process a single alert
            if not args.alert_id:
                print("❌ Alert ID is required for process-alert mode")
                sys.exit(1)
            
            # Load alert data
            if args.alert_data:
                import json
                with open(args.alert_data, 'r') as f:
                    alert_data = json.load(f)
            else:
                # Use sample alert data
                alert_data = {
                    "id": args.alert_id,
                    "source": "test",
                    "timestamp": "2024-01-01T00:00:00Z",
                    "severity": "high",
                    "description": "Test alert for processing"
                }
            
            print(f"🔄 Processing alert {args.alert_id}...")
            result = await app.process_single_alert(args.alert_id, alert_data)
            
            print("✅ Alert processed successfully!")
            print(f"Final status: {result.get('triage_status', 'unknown')}")
            print(f"Confidence score: {result.get('confidence_score', 0)}")
            print(f"Processing notes: {len(result.get('processing_notes', []))}")
            
            sys.exit(0)
        
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