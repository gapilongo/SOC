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
                "source": "production-siem",
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "high",
                "description": "Suspicious executable detected with network communication",
                "raw_data": {
                    "event_type": "malware_detection",
                    "process_name": "update.exe",
                    "user": "SYSTEM",
                    "host": "workstation-001",
                    "file_hash": "a1b2c3d4e5f6789",
                    "destination_ip": "185.220.101.44",
                    "destination_port": 4444,
                    "file_path": "C:\\temp\\update.exe",
                },
            },
            {
                "id": "poc-alert-002",
                "source": "production-siem",
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "medium",
                "description": "Multiple failed login attempts from external IP",
                "raw_data": {
                    "event_type": "authentication",
                    "source_ip": "45.133.1.87",
                    "username": "administrator",
                    "failed_attempts": 15,
                    "time_window": "5 minutes",
                    "target_service": "RDP",
                },
            },
            {
                "id": "poc-alert-003",
                "source": "test-siem",
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "low",
                "description": "Scheduled maintenance backup process",
                "raw_data": {
                    "event_type": "file_operation",
                    "process_name": "backup_service.exe",
                    "user": "backup_service",
                    "operation": "scheduled_backup",
                    "files_processed": 1250,
                },
            },
        ]

        print(f"📋 Loaded {len(self.sample_alerts)} sample alerts")

    async def run_poc(self):
        """Run the POC."""
        print("🎯 Running LG-SOTF POC...")

        # Process each sample alert
        for i, alert in enumerate(self.sample_alerts, 1):
            print(f"\n🔄 Processing alert {i}/{len(self.sample_alerts)}: {alert['id']}")
            print(f"📝 Alert Details:")
            print(f"   Source: {alert['source']}")
            print(f"   Severity: {alert['severity']}")
            print(f"   Description: {alert['description']}")

            try:
                # Process alert through workflow
                result = await self.app.workflow_engine.execute_workflow(
                    alert["id"], alert
                )

                print(f"✅ Alert {alert['id']} processed successfully")
                print(f"📊 Processing Results:")
                print(f"   Final status: {result.get('triage_status', 'unknown')}")
                print(f"   Confidence score: {result.get('confidence_score', 0)}")
                print(f"   Priority level: {result.get('priority_level', 'unknown')}")
                print(f"   FP indicators: {len(result.get('fp_indicators', []))}")
                print(f"   TP indicators: {len(result.get('tp_indicators', []))}")

                # Show LLM insights if available
                enriched = result.get("enriched_data", {})
                llm_insights = enriched.get("llm_insights", {})
                if llm_insights:
                    print(f"🧠 LLM Insights:")
                    print(
                        f"   Threat Assessment: {llm_insights.get('threat_assessment', 'N/A')}"
                    )
                    print(
                        f"   Threat Categories: {llm_insights.get('threat_categories', [])}"
                    )
                    print(
                        f"   Recommended Actions: {llm_insights.get('recommended_actions', [])}"
                    )

                print(f"   Processing steps: {len(result.get('processing_notes', []))}")

                # Show processing notes
                notes = result.get("processing_notes", [])
                if notes:
                    print(f"📋 Processing Notes:")
                    for note in notes[-3:]:  # Show last 3 notes
                        print(f"   - {note}")

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
        "--config",
        "-c",
        default="configs/poc.yaml",
        help="Path to POC configuration file",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
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
