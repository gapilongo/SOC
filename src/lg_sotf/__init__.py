"""
LG-SOTF: LangGraph SOC Triage & Orchestration Framework

A production-grade framework for automating Security Operations Center workflows
using LangGraph for intelligent alert processing and response.
"""

__version__ = "0.1.0"
__author__ = "LG-SOTF Team"
__email__ = "team@lg-sotf.org"

from .core.config.manager import ConfigManager
from .core.state.manager import StateManager
from .core.workflow import WorkflowEngine

__all__ = [
    "WorkflowEngine",
    "StateManager", 
    "ConfigManager",
]