"""
Main application entry point for LG-SOTF - Production Version.

This module provides the main application lifecycle management including:
- Component initialization and dependency injection
- Continuous alert ingestion and processing
- Health monitoring and metrics collection
- Graceful shutdown with resource cleanup
"""

import asyncio
import logging
import signal
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Set

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
        """Initialize the application.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.config_manager = None
        self.state_manager = None
        self.workflow_engine = None
        self.audit_logger = None
        self.metrics = None
        self.postgres_storage = None
        self.redis_storage = None
        
        # Application state
        self.running = False
        self.initialized = False
        
        # Task tracking for graceful shutdown
        self._active_tasks: Set[asyncio.Task] = set()
        self._shutdown_event = asyncio.Event()
        
        # Ingestion tracking
        self._last_ingestion_poll: Optional[datetime] = None
        self._last_health_check: Optional[datetime] = None
        self._ingestion_lock = asyncio.Lock()
        
        # Setup signal handlers
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            """Handle shutdown signals."""
            logging.info(f"Received signal {signum}, initiating graceful shutdown...")
            self.running = False
            self._shutdown_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def initialize(self):
        """Initialize all application components.
        
        Raises:
            LG_SOTFError: If initialization fails
        """
        try:
            logging.info("=== Initializing LG-SOTF Application ===")
            
            # Load configuration
            self.config_manager = ConfigManager(self.config_path)
            logging.info("✓ Configuration loaded")
            
            # Validate configuration
            self.config_manager.validate()
            logging.info("✓ Configuration validated")
            
            # Initialize audit and metrics
            self.audit_logger = AuditLogger()
            self.metrics = MetricsCollector(self.config_manager)
            logging.info("✓ Audit and metrics initialized")
            
            # Initialize storage backends
            await self._initialize_storage()
            logging.info("✓ Storage backends initialized")
            
            # Initialize state manager
            self.state_manager = StateManager(self.postgres_storage)
            logging.info("✓ State manager initialized")
            
            # Initialize workflow engine (handles agent initialization)
            self.workflow_engine = WorkflowEngine(self.config_manager, self.state_manager)
            await self.workflow_engine.initialize()
            logging.info("✓ Workflow engine initialized")
            
            # Verify agents are registered
            from lg_sotf.agents.registry import agent_registry
            stats = agent_registry.get_registry_stats()
            logging.info(
                f"✓ Agent registry: {stats['agent_types_count']} types, "
                f"{stats['agent_instances_count']} instances, "
                f"{len(stats['initialized_agents'])} initialized"
            )
            
            # Log application start
            self.audit_logger.log_application_start(
                config_path=self.config_path,
                version="0.1.0"
            )
            
            self.initialized = True
            logging.info("=== LG-SOTF Application Initialized Successfully ===\n")
            
        except Exception as e:
            logging.error(f"Failed to initialize application: {e}", exc_info=True)
            raise LG_SOTFError(f"Application initialization failed: {e}")
    
    async def _initialize_storage(self):
        """Initialize storage backends.
        
        Raises:
            Exception: If storage initialization fails
        """
        try:
            # Initialize PostgreSQL
            db_config = self.config_manager.get_database_config()
            connection_string = (
                f"postgresql://{db_config.username}:{db_config.password}@"
                f"{db_config.host}:{db_config.port}/{db_config.database}"
            )
            
            self.postgres_storage = PostgreSQLStorage(connection_string)
            await self.postgres_storage.initialize()
            logging.info(f"  - PostgreSQL connected: {db_config.host}:{db_config.port}")
            
            # Initialize Redis
            redis_config = self.config_manager.get_redis_config()
            redis_password = f":{redis_config.password}@" if redis_config.password else ""
            redis_connection_string = (
                f"redis://{redis_password}{redis_config.host}:{redis_config.port}/{redis_config.db}"
            )
            
            self.redis_storage = RedisStorage(redis_connection_string)
            await self.redis_storage.initialize()
            logging.info(f"  - Redis connected: {redis_config.host}:{redis_config.port}")
            
        except Exception as e:
            logging.error(f"Failed to initialize storage: {e}", exc_info=True)
            raise
    
    async def run(self):
        """Run the main application loop.
        
        This method handles:
        - Continuous alert ingestion and processing
        - Periodic health checks
        - Graceful shutdown on signal
        """
        try:
            self.running = True
            logging.info("🚀 LG-SOTF Application Started")
            logging.info("Press Ctrl+C to shutdown gracefully\n")
            
            # Create background tasks
            ingestion_task = asyncio.create_task(self._ingestion_loop())
            health_check_task = asyncio.create_task(self._health_check_loop())
            
            # Wait for shutdown signal
            await self._shutdown_event.wait()
            
            # Cancel background tasks
            logging.info("Stopping background tasks...")
            ingestion_task.cancel()
            health_check_task.cancel()
            
            # Wait for tasks to complete
            await asyncio.gather(ingestion_task, health_check_task, return_exceptions=True)
            
        except asyncio.CancelledError:
            logging.info("Main loop cancelled")
        except Exception as e:
            logging.error(f"Unexpected error in main loop: {e}", exc_info=True)
        finally:
            await self.shutdown()
    
    async def _ingestion_loop(self):
        """Continuous ingestion loop.
        
        Polls configured sources at regular intervals and processes alerts.
        """
        try:
            while self.running:
                try:
                    await self._process_alerts()
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logging.error(f"Error in ingestion loop: {e}", exc_info=True)
                    self.metrics.increment_counter("ingestion_loop_errors")
                    await asyncio.sleep(5)  # Back off on error
                
                # Sleep briefly to prevent tight loop
                await asyncio.sleep(1)
                
        except asyncio.CancelledError:
            logging.info("Ingestion loop cancelled")
    
    async def _health_check_loop(self):
        """Periodic health check loop.
        
        Performs system health checks at regular intervals.
        """
        try:
            while self.running:
                try:
                    await self._perform_health_checks()
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logging.error(f"Error in health check loop: {e}", exc_info=True)
                    self.metrics.increment_counter("health_check_errors")
                
                # Wait before next health check
                await asyncio.sleep(60)
                
        except asyncio.CancelledError:
            logging.info("Health check loop cancelled")
    
    async def _process_alerts(self):
        """Process alerts from ingestion sources.
        
        This method:
        - Respects polling interval configuration
        - Enforces max concurrent alert limit
        - Tracks tasks for graceful shutdown
        """
        # Check if ingestion agent is available
        if not self.workflow_engine or "ingestion" not in self.workflow_engine.agents:
            return
        
        ingestion_agent = self.workflow_engine.agents["ingestion"]
        
        # Get polling configuration
        ingestion_config = self.config_manager.get_agent_config("ingestion")
        polling_interval = ingestion_config.get("polling_interval", 60)
        max_concurrent = ingestion_agent.max_concurrent_alerts
        
        # Check if it's time to poll
        if self._last_ingestion_poll is not None:
            time_since_poll = (datetime.utcnow() - self._last_ingestion_poll).total_seconds()
            if time_since_poll < polling_interval:
                return
        
        # Use lock to prevent concurrent polling
        if self._ingestion_lock.locked():
            return
        
        async with self._ingestion_lock:
            try:
                # Check active task count
                active_count = len(self._active_tasks)
                if active_count >= max_concurrent:
                    logging.warning(
                        f"Max concurrent alerts reached ({active_count}/{max_concurrent}), "
                        "skipping this poll cycle"
                    )
                    self.metrics.increment_counter("ingestion_poll_skipped_max_concurrent")
                    return
                
                # Poll for new alerts
                logging.debug("Polling ingestion sources...")
                new_alerts = await ingestion_agent.poll_sources()
                
                if not new_alerts:
                    self._last_ingestion_poll = datetime.utcnow()
                    return
                
                logging.info(f"📥 Ingestion: Found {len(new_alerts)} new alerts")
                self.metrics.increment_counter("ingestion_alerts_received", len(new_alerts))
                
                # Process alerts respecting concurrency limit
                processed_count = 0
                for alert in new_alerts:
                    # Check if we can process more alerts
                    if len(self._active_tasks) >= max_concurrent:
                        remaining = len(new_alerts) - processed_count
                        logging.warning(
                            f"Max concurrent limit reached, "
                            f"queueing {remaining} alerts for next cycle"
                        )
                        self.metrics.increment_counter("ingestion_alerts_queued", remaining)
                        break
                    
                    try:
                        # Create workflow task
                        task = asyncio.create_task(
                            self._process_single_workflow(alert["id"], alert)
                        )
                        
                        # Track task
                        self._active_tasks.add(task)
                        task.add_done_callback(self._active_tasks.discard)
                        
                        processed_count += 1
                        
                    except Exception as e:
                        logging.error(
                            f"Failed to create workflow task for alert {alert.get('id', 'unknown')}: {e}",
                            exc_info=True
                        )
                        self.metrics.increment_counter("workflow_creation_errors")
                
                logging.info(
                    f"✓ Created {processed_count} workflow tasks "
                    f"({len(self._active_tasks)} active)"
                )
                self.metrics.set_gauge("active_workflow_tasks", len(self._active_tasks))
                
                # Update last poll time
                self._last_ingestion_poll = datetime.utcnow()
                self.metrics.record_histogram("ingestion_poll_interval", polling_interval)
                
            except Exception as e:
                logging.error(f"Ingestion polling error: {e}", exc_info=True)
                self.metrics.increment_counter("ingestion_poll_errors")
    
    async def _process_single_workflow(self, alert_id: str, alert_data: dict):
        """Process a single alert through the workflow.
        
        Args:
            alert_id: Alert identifier
            alert_data: Alert data dictionary
        """
        start_time = datetime.utcnow()
        
        try:
            logging.debug(f"Processing workflow for alert {alert_id}")
            
            result = await self.workflow_engine.execute_workflow(alert_id, alert_data)
            
            # Calculate processing time
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            logging.info(
                f"✓ Alert {alert_id} processed: "
                f"status={result.get('triage_status', 'unknown')}, "
                f"confidence={result.get('confidence_score', 0)}, "
                f"time={processing_time:.2f}s"
            )
            
            # Record metrics
            self.metrics.increment_counter("workflow_success")
            self.metrics.record_histogram("workflow_processing_time", processing_time)
            
        except asyncio.CancelledError:
            logging.info(f"Workflow for alert {alert_id} cancelled (shutdown)")
            raise
        except Exception as e:
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            logging.error(
                f"✗ Failed to process alert {alert_id}: {e}",
                exc_info=True
            )
            self.metrics.increment_counter("workflow_errors")
            self.metrics.record_histogram("workflow_error_time", processing_time)
    
    async def _perform_health_checks(self):
        """Perform periodic health checks on all components."""
        # Check if it's time for health check (every 60 seconds)
        if self._last_health_check is not None:
            time_since_check = (datetime.utcnow() - self._last_health_check).total_seconds()
            if time_since_check < 60:
                return
        
        try:
            logging.debug("Performing health checks...")
            health_status = await self.health_check()
            
            if health_status:
                logging.debug("✓ All components healthy")
            else:
                logging.warning("⚠ Some components unhealthy")
            
            self.metrics.set_gauge("health_check_status", 1 if health_status else 0)
            self._last_health_check = datetime.utcnow()
            
        except Exception as e:
            logging.error(f"Health check error: {e}", exc_info=True)
            self.metrics.increment_counter("health_check_errors")
    
    async def shutdown(self):
        """Shutdown the application gracefully.
        
        This method:
        - Cancels all active workflow tasks
        - Shuts down agents
        - Closes storage connections
        - Cleans up resources
        """
        try:
            logging.info("\n=== Shutting Down LG-SOTF Application ===")
            
            # Cancel active workflow tasks
            if self._active_tasks:
                task_count = len(self._active_tasks)
                logging.info(f"Cancelling {task_count} active workflow tasks...")
                
                for task in self._active_tasks:
                    if not task.done():
                        task.cancel()
                
                # Wait for tasks to complete with timeout
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*self._active_tasks, return_exceptions=True),
                        timeout=10.0
                    )
                    logging.info(f"✓ All {task_count} workflow tasks cancelled")
                except asyncio.TimeoutError:
                    logging.warning(f"⚠ Some workflow tasks did not complete within timeout")
            
            # Log application shutdown
            if self.audit_logger:
                self.audit_logger.log_application_shutdown()
            
            # Shutdown agents
            await self._shutdown_agents()
            
            # Close storage connections
            await self._shutdown_storage()
            
            # Shutdown metrics collection
            if self.metrics:
                try:
                    self.metrics.shutdown()
                    logging.info("✓ Metrics collection stopped")
                except Exception as e:
                    logging.warning(f"⚠ Error shutting down metrics: {e}")
            
            logging.info("=== LG-SOTF Application Shutdown Complete ===\n")
            
        except Exception as e:
            logging.error(f"Error during shutdown: {e}", exc_info=True)
    
    async def _shutdown_agents(self):
        """Shutdown all registered agents."""
        try:
            from lg_sotf.agents.registry import agent_registry
            
            logging.info("Shutting down agents...")
            await agent_registry.cleanup_all_agents()
            logging.info("✓ All agents stopped")
            
        except Exception as e:
            logging.warning(f"⚠ Error shutting down agents: {e}")
    
    async def _shutdown_storage(self):
        """Shutdown storage connections."""
        storage_tasks = []
        
        # Schedule PostgreSQL cleanup
        if self.postgres_storage:
            try:
                storage_tasks.append(
                    asyncio.create_task(self.postgres_storage.close())
                )
            except Exception as e:
                logging.warning(f"⚠ Error scheduling PostgreSQL close: {e}")
        
        # Schedule Redis cleanup
        if self.redis_storage:
            try:
                storage_tasks.append(
                    asyncio.create_task(self.redis_storage.close())
                )
            except Exception as e:
                logging.warning(f"⚠ Error scheduling Redis close: {e}")
        
        # Wait for storage cleanup with timeout
        if storage_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*storage_tasks, return_exceptions=True),
                    timeout=5.0
                )
                logging.info("✓ Storage connections closed")
            except asyncio.TimeoutError:
                logging.warning("⚠ Storage cleanup timed out")
            except Exception as e:
                logging.warning(f"⚠ Error during storage cleanup: {e}")
    
    async def health_check(self) -> bool:
        """Perform comprehensive health check.
        
        Returns:
            bool: True if all components healthy, False otherwise
        """
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
            
            # Check PostgreSQL
            if self.postgres_storage:
                health_results['postgres_storage'] = await self.postgres_storage.health_check()
            
            # Check Redis
            if self.redis_storage:
                health_results['redis_storage'] = await self.redis_storage.health_check()
            
            # Check agents
            try:
                from lg_sotf.agents.registry import agent_registry

                # Check if any agent is healthy
                if agent_registry.agent_exists("ingestion_instance"):
                    ingestion_agent = agent_registry.get_agent("ingestion_instance")
                    if hasattr(ingestion_agent, 'health_check'):
                        health_results['agents'] = await ingestion_agent.health_check()
                    else:
                        health_results['agents'] = ingestion_agent.initialized
                
            except Exception as e:
                logging.debug(f"Agent health check error: {e}")
                health_results['agents'] = False
            
            # Record component health metrics
            if self.metrics:
                for component, status in health_results.items():
                    self.metrics.set_gauge(f"health_{component}", 1 if status else 0)
            
            # Calculate overall health
            overall_health = all(health_results.values())
            
            # Log unhealthy components
            unhealthy = [comp for comp, status in health_results.items() if not status]
            if unhealthy:
                logging.debug(f"Unhealthy components: {', '.join(unhealthy)}")
            
            return overall_health
            
        except Exception as e:
            logging.error(f"Health check failed: {e}", exc_info=True)
            return False
    
    async def process_single_alert(self, alert_id: str, alert_data: dict) -> dict:
        """Process a single alert through the workflow.
        
        This method is used for testing and manual alert processing.
        
        Args:
            alert_id: Alert identifier
            alert_data: Alert data dictionary
            
        Returns:
            dict: Workflow result
            
        Raises:
            LG_SOTFError: If workflow engine not initialized
        """
        try:
            if not self.workflow_engine:
                raise LG_SOTFError("Workflow engine not initialized")
            
            logging.info(f"Processing single alert: {alert_id}")
            
            result = await self.workflow_engine.execute_workflow(alert_id, alert_data)
            
            logging.info(f"Alert {alert_id} processed successfully")
            return result
            
        except Exception as e:
            logging.error(f"Failed to process alert {alert_id}: {e}", exc_info=True)
            raise
    
    def get_application_status(self) -> dict:
        """Get comprehensive application status.
        
        Returns:
            dict: Application status information
        """
        try:
            status = {
                'running': self.running,
                'initialized': self.initialized,
                'active_workflow_tasks': len(self._active_tasks),
                'last_ingestion_poll': self._last_ingestion_poll.isoformat() if self._last_ingestion_poll else None,
                'last_health_check': self._last_health_check.isoformat() if self._last_health_check else None,
                'components': {
                    'config_manager': self.config_manager is not None,
                    'state_manager': self.state_manager is not None,
                    'workflow_engine': self.workflow_engine is not None,
                    'audit_logger': self.audit_logger is not None,
                    'metrics': self.metrics is not None
                },
                'storage': {
                    'postgres': self.postgres_storage is not None,
                    'redis': self.redis_storage is not None
                }
            }
            
            # Add agent status
            try:
                from lg_sotf.agents.registry import agent_registry
                status['agents'] = agent_registry.get_registry_stats()
            except Exception as e:
                logging.warning(f"Error getting agent status: {e}")
                status['agents'] = {'error': str(e)}
            
            return status
            
        except Exception as e:
            logging.error(f"Error getting application status: {e}", exc_info=True)
            return {'error': str(e)}


async def main():
    """Main entry point for LG-SOTF application."""
    import argparse
    import json

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="LG-SOTF: LangGraph SOC Triage & Orchestration Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
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
        help="Application mode (default: run)"
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
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Logging level (default: INFO)"
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
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Create application instance
    app = LG_SOTFApplication(config_path=args.config)
    
    try:
        # Initialize application
        await app.initialize()
        
        # Execute based on mode
        if args.mode == "health-check":
            # Perform health check
            health_status = await app.health_check()
            status_info = app.get_application_status()
            
            print("\n" + "=" * 60)
            print("🏥 LG-SOTF APPLICATION HEALTH CHECK")
            print("=" * 60)
            print(f"\nOverall Health: {'✅ HEALTHY' if health_status else '❌ UNHEALTHY'}")
            print(f"Running: {'✅ Yes' if status_info['running'] else '❌ No'}")
            print(f"Initialized: {'✅ Yes' if status_info['initialized'] else '❌ No'}")
            print(f"Active Workflow Tasks: {status_info['active_workflow_tasks']}")
            
            print("\n" + "-" * 60)
            print("🔧 COMPONENTS")
            print("-" * 60)
            for component, status in status_info['components'].items():
                status_icon = '✅' if status else '❌'
                print(f"  {status_icon} {component}")
            
            print("\n" + "-" * 60)
            print("🤖 AGENTS")
            print("-" * 60)
            if 'error' in status_info['agents']:
                print(f"  ❌ Error: {status_info['agents']['error']}")
            else:
                agents_info = status_info['agents']
                print(f"  Types: {agents_info['agent_types_count']}")
                print(f"  Instances: {agents_info['agent_instances_count']}")
                print(f"  Initialized: {len(agents_info['initialized_agents'])}")
                if agents_info['initialized_agents']:
                    for agent_name in agents_info['initialized_agents']:
                        print(f"    ✅ {agent_name}")
            
            print("\n" + "-" * 60)
            print("💾 STORAGE")
            print("-" * 60)
            for storage_type, status in status_info['storage'].items():
                status_icon = '✅' if status else '❌'
                print(f"  {status_icon} {storage_type}")
            
            print("\n" + "=" * 60 + "\n")
            
            sys.exit(0 if health_status else 1)
        
        elif args.mode == "process-alert":
            # Process a single alert
            if not args.alert_id:
                print("❌ Error: Alert ID is required for process-alert mode")
                print("Usage: python -m lg_sotf.main --mode process-alert --alert-id <id> [--alert-data <file>]")
                sys.exit(1)
            
            # Load alert data
            if args.alert_data:
                with open(args.alert_data, 'r') as f:
                    alert_data = json.load(f)
            else:
                # Use sample alert data
                alert_data = {
                    "id": args.alert_id,
                    "source": "manual",
                    "timestamp": datetime.utcnow().isoformat(),
                    "severity": "high",
                    "title": "Manual test alert",
                    "description": "Test alert for manual processing"
                }
            
            print(f"\n🔄 Processing alert: {args.alert_id}")
            result = await app.process_single_alert(args.alert_id, alert_data)
            
            print("\n" + "=" * 60)
            print("✅ ALERT PROCESSED SUCCESSFULLY")
            print("=" * 60)
            print(f"Alert ID: {args.alert_id}")
            print(f"Final Status: {result.get('triage_status', 'unknown')}")
            print(f"Confidence Score: {result.get('confidence_score', 0)}")
            print(f"Processing Notes: {len(result.get('processing_notes', []))}")
            print("=" * 60 + "\n")
            
            sys.exit(0)
        
        else:
            # Run application in continuous mode
            await app.run()
            
    except KeyboardInterrupt:
        logging.info("\nApplication interrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Application failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())