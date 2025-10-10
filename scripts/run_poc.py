"""
Simplified POC runner for LG-SOTF with file-based ingestion.
"""

import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from lg_sotf.main import LG_SOTFApplication


class POCRunner:
    """Simplified POC runner for file-based ingestion."""

    def __init__(self, config_path: str = "configs/development.yaml"):
        self.config_path = config_path
        self.app = None
        self.alerts_directory = Path("tests/fixtures/alerts")

    async def initialize(self):
        """Initialize the POC."""
        print("🚀 Initializing LG-SOTF POC...")
        
        # Verify alerts directory exists
        if not self.alerts_directory.exists():
            print(f"⚠️  Alerts directory not found: {self.alerts_directory}")
            print(f"📁 Creating directory...")
            self.alerts_directory.mkdir(parents=True, exist_ok=True)
            (self.alerts_directory / "processed").mkdir(exist_ok=True)

        # Initialize application
        self.app = LG_SOTFApplication(config_path=self.config_path)
        await self.app.initialize()

        print("✅ POC initialized successfully")
        print(f"📁 Monitoring: {self.alerts_directory}")

    async def run_poc(self):
        """Run the POC with file-based ingestion."""
        print("\n🎯 Running File-Based Ingestion POC...")
        print("=" * 60)

        # Get ingestion agent
        ingestion_agent = self.app.workflow_engine.agents.get("ingestion")
        
        if not ingestion_agent:
            print("❌ Ingestion agent not initialized")
            return
        
        # Poll for alerts
        print("\n📥 Polling for alerts...")
        ingested_alerts = await ingestion_agent.poll_sources()
        
        print(f"✅ Found {len(ingested_alerts)} alerts to process\n")
        
        # Process each alert through workflow
        for i, alert in enumerate(ingested_alerts, 1):
            print(f"{'='*60}")
            print(f"🔄 Processing alert {i}/{len(ingested_alerts)}: {alert['id']}")
            print(f"{'='*60}")
            print(f"📝 Alert Details:")
            print(f"   Source: {alert['source']}")
            print(f"   Severity: {alert['severity']}")
            print(f"   Title: {alert.get('title', 'N/A')}")
            
            try:
                # Process through workflow
                result = await self.app.workflow_engine.execute_workflow(
                    alert["id"],
                    alert
                )
                
                await self._display_results(alert['id'], result)
                
            except Exception as e:
                print(f"❌ Failed to process alert {alert['id']}: {e}")
                import traceback
                traceback.print_exc()
                continue
        
        print(f"\n{'='*60}")
        print("🎉 POC completed!")
        
        # Show summary
        await self._show_summary(len(ingested_alerts))

    async def _display_results(self, alert_id: str, result: dict):
        """Display processing results."""
        print(f"\n✅ Alert {alert_id} processed successfully\n")
        print(f"📊 Processing Results:")
        print(f"   Final status: {result.get('triage_status', 'unknown')}")
        print(f"   Confidence score: {result.get('confidence_score', 0)}%")
        print(f"   Priority level: {result.get('priority_level', 'unknown')}")
        print(f"   FP indicators: {len(result.get('fp_indicators', []))}")
        print(f"   TP indicators: {len(result.get('tp_indicators', []))}")
        
        # Show ingestion info
        enriched = result.get("enriched_data", {})
        ingestion_meta = enriched.get("ingestion_metadata", {})
        if ingestion_meta:
            print(f"\n📥 Ingestion Info:")
            print(f"   Source: {ingestion_meta.get('source', 'unknown')}")
            print(f"   Normalized: {ingestion_meta.get('normalized', False)}")
            alert_hash = ingestion_meta.get('alert_hash', 'N/A')
            print(f"   Alert Hash: {alert_hash[:16]}...")

        # Show LLM insights
        llm_insights = enriched.get("llm_insights", {})
        if llm_insights:
            print(f"\n🧠 LLM Insights:")
            print(f"   Threat Assessment: {llm_insights.get('threat_assessment', 'N/A')}")
            categories = llm_insights.get('threat_categories', [])
            if categories:
                print(f"   Threat Categories: {categories}")
            actions = llm_insights.get('recommended_actions', [])
            if actions:
                print(f"   Recommended Actions: {actions[:2]}")

        # Show processing notes
        notes = result.get("processing_notes", [])
        if notes:
            print(f"\n📋 Processing Notes:")
            for note in notes[-3:]:
                print(f"   - {note}")

    async def _show_summary(self, total_processed: int):
        """Show POC summary."""
        print("\n📊 POC Summary:")
        print("=" * 60)
        
        # Get ingestion stats
        try:
            ingestion_agent = self.app.workflow_engine.agents.get("ingestion")
            if ingestion_agent:
                stats = ingestion_agent.get_source_stats()
                
                print(f"\n📈 Ingestion Statistics:")
                print(f"   Total Ingested: {stats['total_ingested']}")
                print(f"   Total Deduplicated: {stats['total_deduplicated']}")
                print(f"   Total Errors: {stats['total_errors']}")
                
                if stats.get('by_source'):
                    print(f"\n📊 By Source:")
                    for source, data in stats['by_source'].items():
                        print(f"   {source}:")
                        print(f"      Ingested: {data['ingested']}")
                        print(f"      Deduplicated: {data['deduplicated']}")
                        print(f"      Errors: {data['errors']}")
        except Exception as e:
            print(f"⚠️  Could not retrieve ingestion stats: {e}")
        
        print(f"\n✅ Successfully processed {total_processed} alerts")
        print(f"✅ All agents operational")
        print(f"✅ Workflow execution complete")
        
        print("\n🔍 Next Steps:")
        print(f"1. Check processed files: {self.alerts_directory / 'processed'}/")
        print("2. Review logs for detailed processing information")
        print(f"3. Add more alert files to: {self.alerts_directory}/")
        print("4. Configure additional data sources in your config")

    async def cleanup(self):
        """Clean up POC resources."""
        print("\n🧹 Cleaning up...")
        
        if self.app:
            await self.app.shutdown()
        
        print("✅ Cleanup completed")


async def main():
    """Main POC runner."""
    import argparse

    parser = argparse.ArgumentParser(description="LG-SOTF POC Runner")
    parser.add_argument(
        "--config",
        "-c",
        default="configs/development.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--verbose",
        "-v",
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
        import traceback
        traceback.print_exc()
        return False
    finally:
        await poc_runner.cleanup()

    return True


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)