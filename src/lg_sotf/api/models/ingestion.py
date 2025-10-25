"""Ingestion-related Pydantic models."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

class IngestionStatusResponse(BaseModel):
    is_active: bool
    last_poll_time: Optional[str]
    next_poll_time: Optional[str]
    polling_interval: int
    sources_enabled: List[str]
    sources_stats: Dict[str, Dict[str, int]]
    total_ingested: int
    total_deduplicated: int
    total_errors: int

class IngestionControlRequest(BaseModel):
    action: str
    sources: Optional[List[str]] = None

class SourceConfigRequest(BaseModel):
    source_name: str
    enabled: bool
    config: Optional[Dict[str, Any]] = None
