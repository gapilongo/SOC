# src/lg_sotf/cli.py
"""
Command-line interface for LG-SOTF.

This module provides a comprehensive CLI for interacting with the LG-SOTF framework.
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click

from .main import LG_SOTFApplication
from .src.lg_sotf.core.config.manager import ConfigManager
from .src.lg_sotf.core.exceptions import LG_SOTFError


@click.group()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    help="Path to configuration file"
)
@click.option(
    "--log-level", "-l",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="INFO",
    help="Logging level"
)
@click.pass_context
def cli(ctx, config, log_level):
    """LG-SOTF: LangGraph SOC Triage & Orchestration Framework."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = config
    ctx.obj["log_level"] = log_level


@cli.command()
@click.pass_context
def run(ctx):
    """Run the LG-SOTF application."""
    import logging

    # Setup logging
    logging.basicConfig(level=getattr(logging, ctx.obj["log_level"]))
    
    async def _run():
        app = LG_SOTFApplication(config_path=ctx.obj["config"])
        await app.initialize()
        await app.run()
    
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        click.echo("Application stopped by user")
        sys.exit(0)
    except LG_SOTFError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def health_check(ctx):
    """Perform application health check."""
    async def _health_check():
        app = LG_SOTFApplication(config_path=ctx.obj["config"])
        await app.initialize()
        return await app.health_check()
    
    try:
        healthy = asyncio.run(_health_check())
        if healthy:
            click.echo("✅ Application is healthy")
            sys.exit(0)
        else:
            click.echo("❌ Application is not healthy")
            sys.exit(1)
    except LG_SOTFError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--alert-id",
    required=True,
    help="Alert ID to process"
)
@click.option(
    "--alert-data",
    type=click.Path(exists=True),
    help="Path to alert data JSON file"
)
@click.pass_context
def process_alert(ctx, alert_id, alert_data):
    """Process a single alert for testing."""
    import json
    import logging

    # Setup logging
    logging.basicConfig(level=getattr(logging, ctx.obj["log_level"]))
    
    async def _process_alert():
        app = LG_SOTFApplication(config_path=ctx.obj["config"])
        await app.initialize()
        
        # Load alert data
        if alert_data:
            with open(alert_data, 'r') as f:
                alert_data = json.load(f)
        else:
            # Use sample alert data
            alert_data = {
                "id": alert_id,
                "source": "test",
                "timestamp": "2024-01-01T00:00:00Z",
                "severity": "high",
                "description": "Test alert"
            }
        
        # Process alert through workflow
        result = await app.workflow_engine.execute_workflow(alert_id, alert_data)
        
        click.echo(f"✅ Alert {alert_id} processed successfully")
        click.echo(f"Result: {result}")
    
    try:
        asyncio.run(_process_alert())
    except LG_SOTFError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def setup_db(ctx):
    """Set up the database schema."""
    from scripts.setup_db import setup_database
    
    try:
        success = asyncio.run(setup_database())
        if success:
            click.echo("✅ Database setup completed successfully")
            sys.exit(0)
        else:
            click.echo("❌ Database setup failed")
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def version(ctx):
    """Show version information."""
    click.echo("LG-SOTF v0.1.0")
    click.echo("LangGraph SOC Triage & Orchestration Framework")
    click.echo("© 2024 LG-SOTF Team")


if __name__ == "__main__":
    cli()