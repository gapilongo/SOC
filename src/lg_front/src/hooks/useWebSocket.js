import { useEffect, useRef, useState, useCallback } from 'react';

const WS_BASE_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:8000/ws';

const useWebSocket = ({ onMessage, onConnect, onDisconnect } = {}) => {
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState(null);
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const reconnectAttemptsRef = useRef(0);
  const isIntentionalCloseRef = useRef(false);

  const connect = useCallback(() => {
    // Prevent multiple connections
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      console.log('WebSocket already connected, skipping...');
      return;
    }

    // Clear any existing reconnection attempts
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    try {
      const clientId = `client-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      const wsUrl = `${WS_BASE_URL}/${clientId}`;
      
      console.log('Attempting WebSocket connection to:', wsUrl);
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('WebSocket connected successfully');
        setConnected(true);
        setError(null);
        reconnectAttemptsRef.current = 0;

        // Subscribe to channels
        try {
          ws.send(JSON.stringify({
            type: 'subscribe',
            subscriptions: ['new_alerts', 'alert_updates', 'system_metrics']
          }));
        } catch (err) {
          console.error('Failed to send subscription:', err);
        }

        if (onConnect) onConnect();
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (onMessage) onMessage(data);
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err);
        }
      };

      ws.onerror = (event) => {
        console.error('WebSocket error:', event);
        setError('WebSocket connection error');
      };

      ws.onclose = (event) => {
        console.log('WebSocket disconnected', event.code, event.reason);
        setConnected(false);
        wsRef.current = null;
        
        if (onDisconnect) onDisconnect();

        // Only attempt reconnection if it wasn't an intentional close
        if (!isIntentionalCloseRef.current) {
          const maxAttempts = 5;
          const baseDelay = 1000;
          
          if (reconnectAttemptsRef.current < maxAttempts) {
            const delay = baseDelay * Math.pow(2, reconnectAttemptsRef.current);
            console.log(`Reconnecting in ${delay}ms (attempt ${reconnectAttemptsRef.current + 1}/${maxAttempts})`);
            
            reconnectTimeoutRef.current = setTimeout(() => {
              reconnectAttemptsRef.current += 1;
              connect();
            }, delay);
          } else {
            console.error('Max reconnection attempts reached');
            setError('Failed to establish connection after multiple attempts');
          }
        }
      };
    } catch (err) {
      console.error('Failed to create WebSocket:', err);
      setError('Failed to create WebSocket connection');
    }
  }, [onMessage, onConnect, onDisconnect]);

  const disconnect = useCallback(() => {
    isIntentionalCloseRef.current = true;
    
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    
    if (wsRef.current) {
      if (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING) {
        wsRef.current.close();
      }
      wsRef.current = null;
    }
    
    setConnected(false);
  }, []);

  const sendMessage = useCallback((message) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      try {
        wsRef.current.send(JSON.stringify(message));
        return true;
      } catch (err) {
        console.error('Failed to send message:', err);
        return false;
      }
    }
    console.warn('WebSocket is not connected');
    return false;
  }, []);

  useEffect(() => {
    isIntentionalCloseRef.current = false;
    
    // Small delay to prevent React StrictMode double-mount issues
    const connectTimer = setTimeout(() => {
      connect();
    }, 100);

    return () => {
      clearTimeout(connectTimer);
      disconnect();
    };
  }, [connect, disconnect]);

  return {
    connected,
    error,
    sendMessage,
    reconnect: connect,
    disconnect
  };
};

export default useWebSocket;