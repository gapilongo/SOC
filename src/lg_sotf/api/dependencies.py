"""Dependency injection for FastAPI routes."""

from fastapi import Depends, Request

from lg_sotf.app_initializer import LG_SOTFApplication
from lg_sotf.api.utils.websocket import WebSocketManager


def get_lg_sotf_app(request: Request) -> LG_SOTFApplication:
    """Get the LG-SOTF application instance.
    
    Args:
        request: FastAPI request object
        
    Returns:
        LG-SOTF application instance from app state
    """
    return request.app.state.lg_sotf_app


def get_websocket_manager(request: Request) -> WebSocketManager:
    """Get the WebSocket manager instance.
    
    Args:
        request: FastAPI request object
        
    Returns:
        WebSocket manager from app state
    """
    return request.app.state.ws_manager
