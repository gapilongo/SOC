"""
Custom exceptions for LG-SOTF.

This module defines custom exceptions used throughout the framework
to provide clear error handling and debugging information.
"""


class LG_SOTFError(Exception):
    """Base exception for LG-SOTF."""
    pass


class ConfigError(LG_SOTFError):
    """Configuration-related errors."""
    pass


class StateError(LG_SOTFError):
    """State management errors."""
    pass


class WorkflowError(LG_SOTFError):
    """Workflow execution errors."""
    pass


class NodeError(LG_SOTFError):
    """Node execution errors."""
    pass


class RoutingError(LG_SOTFError):
    """Edge routing errors."""
    pass


class AgentError(LG_SOTFError):
    """Agent execution errors."""
    pass


class ToolError(LG_SOTFError):
    """Tool execution errors."""
    pass


class StorageError(LG_SOTFError):
    """Storage-related errors."""
    pass


class AuthenticationError(LG_SOTFError):
    """Authentication errors."""
    pass


class AuthorizationError(LG_SOTFError):
    """Authorization errors."""
    pass


class ValidationError(LG_SOTFError):
    """Validation errors."""
    pass


class TimeoutError(LG_SOTFError):
    """Timeout errors."""
    pass


class RateLimitError(LG_SOTFError):
    """Rate limiting errors."""
    pass

class TracingError(LG_SOTFError):
    """Tracing errors."""
    pass

class MetricsError(LG_SOTFError):
    """Metrics errors."""
    pass