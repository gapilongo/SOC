"""
Metrics collection for LG-SOTF.

This module provides comprehensive metrics collection for monitoring
framework performance, agent execution, and system health.
"""

import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

from lg_sotf.core.config.manager import ConfigManager
from lg_sotf.core.exceptions import MetricsError


@dataclass
class MetricPoint:
    """A single metric data point."""

    timestamp: float
    name: str
    value: Union[int, float]
    tags: Dict[str, str]
    type: str  # 'gauge', 'counter', 'histogram', 'summary'


@dataclass
class HistogramBucket:
    """Histogram bucket for timing metrics."""

    upper_bound: float
    count: int


@dataclass
class SummaryStats:
    """Summary statistics for timing metrics."""

    count: int
    sum_: float
    min_: float
    max_: float
    avg_: float


class MetricsCollector:
    """Collects and manages metrics for the LG-SOTF framework."""

    def __init__(self, config_manager: ConfigManager = None):
        if config_manager:
            self.config = config_manager
            self.metrics_config = config_manager.get("monitoring", {}).get(
                "metrics", {}
            )
        else:
            self.config = None
            self.metrics_config = {}

        # Storage for metrics
        self.counters: Dict[str, float] = defaultdict(float)
        self.gauges: Dict[str, float] = defaultdict(float)
        self.histograms: Dict[str, List[HistogramBucket]] = defaultdict(list)
        self.summaries: Dict[str, SummaryStats] = {}

        # Timing metrics
        self.timings: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.execution_times: Dict[str, List[float]] = defaultdict(list)

        # Error tracking
        self.error_counts: Dict[str, int] = defaultdict(int)
        self.error_rates: Dict[str, float] = defaultdict(float)

        # Performance tracking
        self.performance_metrics: Dict[str, Dict[str, float]] = defaultdict(dict)

        # Lock for thread safety
        self._lock = threading.RLock()

        # Configuration
        self.enabled = self.metrics_config.get("enabled", True)
        self.max_metrics = self.metrics_config.get("max_metrics", 10000)
        self.retention_hours = self.metrics_config.get("retention_hours", 24)

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
                self._cleanup_old_metrics()
            except Exception as e:
                # Log error but continue running
                pass

    def _cleanup_old_metrics(self):
        """Clean up old metrics based on retention policy."""
        cutoff_time = time.time() - (self.retention_hours * 3600)

        with self._lock:
            # Clean up timing metrics
            for name, timing_queue in self.timings.items():
                while timing_queue and timing_queue[0][0] < cutoff_time:
                    timing_queue.popleft()

            # Clean up execution times
            for name, times in self.execution_times.items():
                times[:] = [t for t in times if t >= cutoff_time]

    def increment_counter(
        self, name: str, value: float = 1.0, tags: Dict[str, str] = None
    ):
        """Increment a counter metric."""
        if not self.enabled:
            return

        with self._lock:
            self.counters[name] += value

            # Record metric point
            self._record_metric(name, self.counters[name], "counter", tags or {})

    def set_gauge(self, name: str, value: float, tags: Dict[str, str] = None):
        """Set a gauge metric."""
        if not self.enabled:
            return

        with self._lock:
            self.gauges[name] = value

            # Record metric point
            self._record_metric(name, value, "gauge", tags or {})

    def record_timing(self, name: str, duration: float, tags: Dict[str, str] = None):
        """Record a timing metric."""
        if not self.enabled:
            return

        with self._lock:
            # Add to timing queue
            self.timings[name].append((time.time(), duration))

            # Add to execution times for summary stats
            self.execution_times[name].append(duration)

            # Update summary statistics
            self._update_summary_stats(name, duration)

            # Record metric point
            self._record_metric(name, duration, "histogram", tags or {})

    def record_histogram(self, name: str, value: float, tags: Dict[str, str] = None):
        """Record a histogram metric."""
        if not self.enabled:
            return

        with self._lock:
            # Create histogram buckets if not exists
            if name not in self.histograms:
                self.histograms[name] = self._create_histogram_buckets()

            # Find appropriate bucket
            for bucket in self.histograms[name]:
                if value <= bucket.upper_bound:
                    bucket.count += 1
                    break

            # Record metric point
            self._record_metric(name, value, "histogram", tags or {})

    def _create_histogram_buckets(self) -> List[HistogramBucket]:
        """Create standard histogram buckets."""
        buckets = [
            HistogramBucket(0.005, 0),
            HistogramBucket(0.01, 0),
            HistogramBucket(0.025, 0),
            HistogramBucket(0.05, 0),
            HistogramBucket(0.075, 0),
            HistogramBucket(0.1, 0),
            HistogramBucket(0.25, 0),
            HistogramBucket(0.5, 0),
            HistogramBucket(0.75, 0),
            HistogramBucket(1.0, 0),
            HistogramBucket(2.5, 0),
            HistogramBucket(5.0, 0),
            HistogramBucket(7.5, 0),
            HistogramBucket(10.0, 0),
        ]
        return buckets

    def _update_summary_stats(self, name: str, value: float):
        """Update summary statistics for a timing metric."""
        if name not in self.summaries:
            self.summaries[name] = SummaryStats(0, 0.0, float("inf"), 0.0, 0.0)

        stats = self.summaries[name]
        stats.count += 1
        stats.sum_ += value
        stats.min_ = min(stats.min_, value)
        stats.max_ = max(stats.max_, value)
        stats.avg_ = stats.sum_ / stats.count

    def record_error(
        self, name: str, error_type: str = "error", tags: Dict[str, str] = None
    ):
        """Record an error metric."""
        if not self.enabled:
            return

        with self._lock:
            error_key = f"{name}_{error_type}"
            self.error_counts[error_key] += 1

            # Calculate error rate
            total_operations = self.counters.get(name, 1.0)
            self.error_rates[error_key] = (
                self.error_counts[error_key] / total_operations
            )

            # Record metric point
            self._record_metric(
                error_key, self.error_counts[error_key], "counter", tags or {}
            )

    def record_tool_execution(
        self, tool_name: str, execution_time: float, success: bool
    ):
        """Record tool execution metrics."""
        if not self.enabled:
            return

        with self._lock:
            # Record timing
            self.record_timing(f"tool_{tool_name}_execution_time", execution_time)

            # Record success/failure
            status = "success" if success else "failure"
            self.increment_counter(f"tool_{tool_name}_{status}")

            # Update performance metrics
            if tool_name not in self.performance_metrics:
                self.performance_metrics[tool_name] = {}

            self.performance_metrics[tool_name]["last_execution"] = time.time()
            self.performance_metrics[tool_name]["last_execution_time"] = execution_time
            self.performance_metrics[tool_name]["success_rate"] = self.counters.get(
                f"tool_{tool_name}_success", 0
            ) / max(
                1,
                self.counters.get(f"tool_{tool_name}_success", 0)
                + self.counters.get(f"tool_{tool_name}_failure", 0),
            )

    def record_agent_execution(
        self, agent_name: str, execution_time: float, success: bool
    ):
        """Record agent execution metrics."""
        if not self.enabled:
            return

        with self._lock:
            # Record timing
            self.record_timing(f"agent_{agent_name}_execution_time", execution_time)

            # Record success/failure
            status = "success" if success else "failure"
            self.increment_counter(f"agent_{agent_name}_{status}")

            # Update performance metrics
            if agent_name not in self.performance_metrics:
                self.performance_metrics[agent_name] = {}

            self.performance_metrics[agent_name]["last_execution"] = time.time()
            self.performance_metrics[agent_name]["last_execution_time"] = execution_time
            self.performance_metrics[agent_name]["success_rate"] = self.counters.get(
                f"agent_{agent_name}_success", 0
            ) / max(
                1,
                self.counters.get(f"agent_{agent_name}_success", 0)
                + self.counters.get(f"agent_{agent_name}_failure", 0),
            )

    def record_workflow_execution(
        self, workflow_id: str, execution_time: float, success: bool
    ):
        """Record workflow execution metrics."""
        if not self.enabled:
            return

        with self._lock:
            # Record timing
            self.record_timing(f"workflow_execution_time", execution_time)

            # Record success/failure
            status = "success" if success else "failure"
            self.increment_counter(f"workflow_{status}")

            # Update performance metrics
            if "workflow" not in self.performance_metrics:
                self.performance_metrics["workflow"] = {}

            self.performance_metrics["workflow"]["last_execution"] = time.time()
            self.performance_metrics["workflow"]["last_execution_time"] = execution_time
            self.performance_metrics["workflow"]["success_rate"] = self.counters.get(
                "workflow_success", 0
            ) / max(
                1,
                self.counters.get("workflow_success", 0)
                + self.counters.get("workflow_failure", 0),
            )

    def _record_metric(self, name: str, value: float, type_: str, tags: Dict[str, str]):
        """Record a metric point."""
        metric_point = MetricPoint(
            timestamp=time.time(), name=name, value=value, tags=tags, type=type_
        )

        # In a real implementation, this would send to Prometheus, InfluxDB, etc.
        # For now, we'll just keep it in memory
        pass

    def get_counter(self, name: str) -> float:
        """Get counter value."""
        with self._lock:
            return self.counters.get(name, 0.0)

    def get_gauge(self, name: str) -> float:
        """Get gauge value."""
        with self._lock:
            return self.gauges.get(name, 0.0)

    def get_timing_stats(self, name: str) -> Dict[str, float]:
        """Get timing statistics."""
        with self._lock:
            if name not in self.summaries:
                return {"count": 0, "sum": 0.0, "min": 0.0, "max": 0.0, "avg": 0.0}

            stats = self.summaries[name]
            return {
                "count": stats.count,
                "sum": stats.sum_,
                "min": stats.min_,
                "max": stats.max_,
                "avg": stats.avg_,
            }

    def get_histogram(self, name: str) -> List[Dict[str, Any]]:
        """Get histogram data."""
        with self._lock:
            if name not in self.histograms:
                return []

            return [
                {"upper_bound": bucket.upper_bound, "count": bucket.count}
                for bucket in self.histograms[name]
            ]

    def get_error_rate(self, name: str, error_type: str = "error") -> float:
        """Get error rate."""
        with self._lock:
            error_key = f"{name}_{error_type}"
            return self.error_rates.get(error_key, 0.0)

    def get_performance_metrics(self, name: str) -> Dict[str, Any]:
        """Get performance metrics for a component."""
        with self._lock:
            return self.performance_metrics.get(name, {})

    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all metrics."""
        with self._lock:
            return {
                "counters": dict(self.counters),
                "gauges": dict(self.gauges),
                "timing_stats": {
                    name: asdict(stats) for name, stats in self.summaries.items()
                },
                "error_rates": dict(self.error_rates),
                "performance_metrics": dict(self.performance_metrics),
            }

    def get_recent_timings(self, name: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent timing data."""
        with self._lock:
            if name not in self.timings:
                return []

            return [
                {"timestamp": timestamp, "duration": duration}
                for timestamp, duration in list(self.timings[name])[-limit:]
            ]

    def reset_metric(self, name: str):
        """Reset a specific metric."""
        with self._lock:
            if name in self.counters:
                del self.counters[name]
            if name in self.gauges:
                del self.gauges[name]
            if name in self.histograms:
                del self.histograms[name]
            if name in self.summaries:
                del self.summaries[name]
            if name in self.timings:
                del self.timings[name]
            if name in self.execution_times:
                del self.execution_times[name]

    def reset_all_metrics(self):
        """Reset all metrics."""
        with self._lock:
            self.counters.clear()
            self.gauges.clear()
            self.histograms.clear()
            self.summaries.clear()
            self.timings.clear()
            self.execution_times.clear()
            self.error_counts.clear()
            self.error_rates.clear()
            self.performance_metrics.clear()

    def shutdown(self):
        """Shutdown the metrics collector."""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)
