 
"""
Distributed tracing for LG-SOTF.

This module provides distributed tracing capabilities for tracking
requests across different components and services.
"""

import threading
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from ..core.config.manager import ConfigManager
from ..core.exceptions import TracingError


class SpanStatus(Enum):
    """Span status enumeration."""
    STARTED = "started"
    FINISHED = "finished"
    ERROR = "error"


@dataclass
class Span:
    """A single span in a trace."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    operation_name: str
    start_time: datetime
    end_time: Optional[datetime]
    status: SpanStatus
    tags: Dict[str, str]
    logs: List[Dict[str, Any]]
    metrics: Dict[str, Union[int, float]]
    error: Optional[str]
    
    def duration(self) -> Optional[float]:
        """Calculate span duration in seconds."""
        if self.end_time is None:
            return None
        return (self.end_time - self.start_time).total_seconds()
    
    def is_finished(self) -> bool:
        """Check if span is finished."""
        return self.status in [SpanStatus.FINISHED, SpanStatus.ERROR]


@dataclass
class TraceContext:
    """Context for a trace."""
    trace_id: str
    span_id: str
    baggage: Dict[str, str]
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary for propagation."""
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "baggage": self.baggage
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'TraceContext':
        """Create from dictionary."""
        return cls(
            trace_id=data["trace_id"],
            span_id=data["span_id"],
            baggage=data.get("baggage", {})
        )


class DistributedTracer:
    """Distributed tracer for LG-SOTF."""
    
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.tracing_config = config_manager.get('monitoring', {}).get('tracing', {})
        
        # Storage for traces and spans
        self.traces: Dict[str, List[Span]] = {}
        self.active_spans: Dict[str, Span] = {}
        
        # Configuration
        self.enabled = self.tracing_config.get('enabled', True)
        self.sample_rate = self.tracing_config.get('sample_rate', 0.1)
        self.max_spans = self.tracing_config.get('max_spans', 10000)
        self.retention_hours = self.tracing_config.get('retention_hours', 24)
        
        # Lock for thread safety
        self._lock = threading.RLock()
        
        # Background cleanup thread
        self._cleanup_thread = None
        self._running = False
        
        if self.enabled:
            self._start_cleanup_thread()
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread."""
        self._running = True
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def _cleanup_loop(self):
        """Background cleanup loop."""
        while self._running:
            try:
                time.sleep(3600)  # Run cleanup every hour
                self._cleanup_old_traces()
            except Exception as e:
                # Log error but continue running
                pass
    
    def _cleanup_old_traces(self):
        """Clean up old traces based on retention policy."""
        cutoff_time = datetime.utcnow() - timedelta(hours=self.retention_hours)
        
        with self._lock:
            # Clean up old traces
            for trace_id, spans in list(self.traces.items()):
                if not spans:
                    del self.traces[trace_id]
                    continue
                
                # Check if trace has any recent spans
                recent_spans = [span for span in spans if span.start_time > cutoff_time]
                if not recent_spans:
                    del self.traces[trace_id]
    
    def start_span(self, operation_name: str, parent_span_id: str = None, 
                  tags: Dict[str, str] = None) -> Span:
        """Start a new span."""
        if not self.enabled:
            # Return a dummy span
            return Span(
                trace_id="dummy",
                span_id="dummy",
                parent_span_id=parent_span_id,
                operation_name=operation_name,
                start_time=datetime.utcnow(),
                end_time=None,
                status=SpanStatus.STARTED,
                tags=tags or {},
                logs=[],
                metrics={},
                error=None
            )
        
        # Check if we should sample this trace
        if parent_span_id is None and not self._should_sample():
            return Span(
                trace_id="unsampled",
                span_id=str(uuid.uuid4()),
                parent_span_id=None,
                operation_name=operation_name,
                start_time=datetime.utcnow(),
                end_time=None,
                status=SpanStatus.STARTED,
                tags=tags or {},
                logs=[],
                metrics={},
                error=None
            )
        
        # Get trace ID from parent span or create new
        if parent_span_id:
            parent_span = self.active_spans.get(parent_span_id)
            if parent_span:
                trace_id = parent_span.trace_id
            else:
                trace_id = str(uuid.uuid4())
        else:
            trace_id = str(uuid.uuid4())
        
        # Create new span
        span_id = str(uuid.uuid4())
        span = Span(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            start_time=datetime.utcnow(),
            end_time=None,
            status=SpanStatus.STARTED,
            tags=tags or {},
            logs=[],
            metrics={},
            error=None
        )
        
        with self._lock:
            # Store span
            if trace_id not in self.traces:
                self.traces[trace_id] = []
            self.traces[trace_id].append(span)
            self.active_spans[span_id] = span
            
            # Enforce max spans limit
            if len(self.traces[trace_id]) > self.max_spans:
                self.traces[trace_id] = self.traces[trace_id][-self.max_spans:]
        
        return span
    
    def finish_span(self, span: Span, error: str = None):
        """Finish a span."""
        if not self.enabled or span.trace_id == "dummy":
            return
        
        with self._lock:
            span.end_time = datetime.utcnow()
            span.status = SpanStatus.ERROR if error else SpanStatus.FINISHED
            span.error = error
            
            # Remove from active spans
            if span.span_id in self.active_spans:
                del self.active_spans[span.span_id]
    
    def add_tag(self, span: Span, key: str, value: str):
        """Add a tag to a span."""
        if not self.enabled or span.trace_id == "dummy":
            return
        
        with self._lock:
            span.tags[key] = value
    
    def add_log(self, span: Span, message: str, level: str = "info", fields: Dict[str, Any] = None):
        """Add a log entry to a span."""
        if not self.enabled or span.trace_id == "dummy":
            return
        
        with self._lock:
            log_entry = {
                "timestamp": datetime.utcnow(),
        "level": level,
                "message": message,
                "fields": fields or {}
            }
            span.logs.append(log_entry)
    
    def add_metric(self, span: Span, key: str, value: Union[int, float]):
        """Add a metric to a span."""
        if not self.enabled or span.trace_id == "dummy":
            return
        
        with self._lock:
            span.metrics[key] = value
    
    def get_trace(self, trace_id: str) -> List[Span]:
        """Get all spans for a trace."""
        with self._lock:
            return self.traces.get(trace_id, [])
    
    def get_span(self, span_id: str) -> Optional[Span]:
        """Get a specific span."""
        with self._lock:
            return self.active_spans.get(span_id)
    
    def get_active_traces(self) -> Dict[str, List[Span]]:
        """Get all active traces."""
        with self._lock:
            return {trace_id: spans for trace_id, spans in self.traces.items() 
                   if any(span.end_time is None for span in spans)}
    
    def get_trace_context(self) -> TraceContext:
        """Get current trace context."""
        # In a real implementation, this would get the context from thread-local storage
        # For now, we'll return a dummy context
        return TraceContext(
            trace_id=str(uuid.uuid4()),
            span_id=str(uuid.uuid4()),
            baggage={}
        )
    
    def set_trace_context(self, context: TraceContext):
        """Set trace context."""
        # In a real implementation, this would set the context in thread-local storage
        pass
    
    def extract_context_from_carrier(self, carrier: Dict[str, str]) -> TraceContext:
        """Extract trace context from carrier (HTTP headers, message headers, etc.)."""
        try:
            return TraceContext.from_dict(carrier)
        except (KeyError, ValueError):
            # Return new context if extraction fails
            return TraceContext(
                trace_id=str(uuid.uuid4()),
                span_id=str(uuid.uuid4()),
                baggage={}
            )
    
    def inject_context_to_carrier(self, context: TraceContext, carrier: Dict[str, str]):
        """Inject trace context into carrier."""
        carrier.update(context.to_dict())
    
    def _should_sample(self) -> bool:
        """Determine if we should sample this trace."""
        import random
        return random.random() < self.sample_rate
    
    def get_trace_stats(self) -> Dict[str, Any]:
        """Get tracing statistics."""
        with self._lock:
            total_traces = len(self.traces)
            active_traces = len(self.get_active_traces())
            total_spans = sum(len(spans) for spans in self.traces.values())
            active_spans = len(self.active_spans)
            
            # Calculate average span duration
            completed_spans = [
                span for spans in self.traces.values() for span in spans 
                if span.is_finished()
            ]
            
            avg_duration = 0
            if completed_spans:
                avg_duration = sum(span.duration() for span in completed_spans if span.duration()) / len(completed_spans)
            
            return {
                "total_traces": total_traces,
                "active_traces": active_traces,
                "total_spans": total_spans,
                "active_spans": active_spans,
                "average_span_duration": avg_duration,
                "sample_rate": self.sample_rate,
                "enabled": self.enabled
            }
    
    def get_trace_by_id(self, trace_id: str) -> Optional[Dict[str, Any]]:
        """Get trace details by ID."""
        spans = self.get_trace(trace_id)
        if not spans:
            return None
        
        return {
            "trace_id": trace_id,
            "spans": [
                {
                    "span_id": span.span_id,
                    "parent_span_id": span.parent_span_id,
                    "operation_name": span.operation_name,
                    "start_time": span.start_time.isoformat(),
                    "end_time": span.end_time.isoformat() if span.end_time else None,
                    "duration": span.duration(),
                    "status": span.status.value,
                    "tags": span.tags,
                    "error": span.error
                }
                for span in spans
            ]
        }
    
    def find_traces_by_operation(self, operation_name: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Find traces by operation name."""
        matching_traces = []
        
        with self._lock:
            for trace_id, spans in self.traces.items():
                for span in spans:
                    if span.operation_name == operation_name:
                        matching_traces.append(self.get_trace_by_id(trace_id))
                        break
                
                if len(matching_traces) >= limit:
                    break
        
        return matching_traces
    
    def find_traces_by_time_range(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Find traces within a time range."""
        matching_traces = []
        
        with self._lock:
            for trace_id, spans in self.traces.items():
                for span in spans:
                    if start_time <= span.start_time <= end_time:
                        matching_traces.append(self.get_trace_by_id(trace_id))
                        break
        
        return matching_traces
    
    def find_traces_by_tag(self, tag_key: str, tag_value: str) -> List[Dict[str, Any]]:
        """Find traces by tag."""
        matching_traces = []
        
        with self._lock:
            for trace_id, spans in self.traces.items():
                for span in spans:
                    if span.tags.get(tag_key) == tag_value:
                        matching_traces.append(self.get_trace_by_id(trace_id))
                        break
        
        return matching_traces
    
    def reset_trace(self, trace_id: str):
        """Reset a specific trace."""
        with self._lock:
            if trace_id in self.traces:
                # Remove from active spans
                for span in self.traces[trace_id]:
                    if span.span_id in self.active_spans:
                        del self.active_spans[span.span_id]
                
                del self.traces[trace_id]
    
    def reset_all_traces(self):
        """Reset all traces."""
        with self._lock:
            self.traces.clear()
            self.active_spans.clear()
    
    def shutdown(self):
        """Shutdown the tracer."""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)