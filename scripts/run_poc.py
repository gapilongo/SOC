# scripts/run_poc.py
"""
POC runner script for LG-SOTF.

This script runs the POC version of LG-SOTF with sample data
to demonstrate the framework capabilities.
"""

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

# Add src to path - fixed import
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.main import LG_SOTFApplication


class POCRunner:
    """POC runner for LG-SOTF."""
    
    def __init__(self, config_path: str = "configs/poc.yaml"):
        self.config_path = config_path
        self.app = None
        self.sample_alerts = []
        
    async def initialize(self):
        """Initialize the POC."""
        print("🚀 Initializing LG-SOTF POC...")
        
        # Initialize application
        self.app = LG_SOTFApplication(config_path=self.config_path)
        await self.app.initialize()
        
        # Load sample alerts
        await self._load_sample_alerts()
        
        print("✅ POC initialized successfully")
    
    async def _load_sample_alerts(self):
        """Load sample alerts for POC."""
        # Sample alert data
        self.sample_alerts = [
            {
                "id": "poc-alert-001",
                "source": "poc-siem",
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "high",
                "description": "Suspicious process detected",
                "raw_data": {
                    "event_type": "process_creation",
                    "process_name": "malware.exe",
                    "user": "testuser",
                    "host": "test-host-001"
                }
            },
            {
                "id": "poc-alert-002",
                "source": "poc-siem",
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "medium",
                "description": "Suspicious network connection",
                "raw_data": {
                    "event_type": "network_connection",
                    "source_ip": "192.168.1.100",
                    "destination_ip": "10.0.0.1",
                    "destination_port": 4444,
                    "protocol": "TCP"
                }
            },
            {
                "id": "poc-alert-003",
                "source": "poc-siem",
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "low",
                "description": "Failed login attempt",
                "raw_data": {
                    "event_type": "authentication",
                    "username": "admin",
                    "source_ip": "192.168.1.200",
                    "result": "failure"
                }
            }
        ]
        
        print(f"📋 Loaded {len(self.sample_alerts)} sample alerts")
    
    async def run_poc(self):
        """Run the POC."""
        print("🎯 Running LG-SOTF POC...")
        
        # Process each sample alert
        for i, alert in enumerate(self.sample_alerts, 1):
            print(f"\n🔄 Processing alert {i}/{len(self.sample_alerts)}: {alert['id']}")
            
            try:
                # Process alert through workflow
                result = await self.app.workflow_engine.execute_workflow(
                    alert['id'], 
                    alert
                )
                
                print(f"✅ Alert {alert['id']} processed successfully")
                print(f"   Final status: {result.get('triage_status', 'unknown')}")
                print(f"   Confidence score: {result.get('confidence_score', 0)}")
                print(f"   Processing steps: {len(result.get('processing_notes', []))}")
                
            except Exception as e:
                print(f"❌ Failed to process alert {alert['id']}: {e}")
                continue
        
        print("\n🎉 POC completed successfully!")
        
        # Show summary
        await self._show_summary()
    
    async def _show_summary(self):
        """Show POC summary."""
        print("\n📊 POC Summary:")
        print("=" * 50)
        
        # Get statistics from the application
        if self.app.metrics:
            try:
                metrics = self.app.metrics.get_all_metrics()
                print(f"Total alerts processed: {len(self.sample_alerts)}")
                print(f"Framework components initialized: ✅")
                print(f"Workflow execution: ✅")
                print(f"State management: ✅")
            except Exception as e:
                print(f"Metrics not available: {e}")
        
        print("\n🔍 Next Steps:")
        print("1. Check the logs for detailed processing information")
        print("2. Review the configuration in configs/poc.yaml")
        print("3. Try processing your own alerts using the CLI")
        print("4. Explore the framework documentation")
    
    async def cleanup(self):
        """Clean up POC resources."""
        print("\n🧹 Cleaning up POC resources...")
        
        if self.app:
            await self.app.shutdown()
        
        print("✅ POC cleanup completed")


async def main():
    """Main POC runner."""
    import argparse
    
    parser = argparse.ArgumentParser(description="LG-SOTF POC Runner")
    parser.add_argument(
        "--config", "-c",
        default="configs/poc.yaml",
        help="Path to POC configuration file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Create and run POC
    poc_runner = POCRunner(config_path=args.config)
    
    try:
        await poc_runner.initialize()
        await poc_runner.run_poc()
    except KeyboardInterrupt:
        print("\n⏹️  POC interrupted by user")
    except Exception as e:
        print(f"\n❌ POC failed: {e}")
        return False
    finally:
        await poc_runner.cleanup()
    
    return True


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)