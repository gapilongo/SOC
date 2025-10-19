import { useEffect, useRef, useState } from 'react';

const WS_BASE_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:8000/ws';

const useWebSocket = ({ onMessage, onConnect, onDisconnect } = {}) => {
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const isUnmountingRef = useRef(false);

  useEffect(() => {
    isUnmountingRef.current = false;

    function connect() {
      if (isUnmountingRef.current) return;

      // EXACTLY like HTML: ws://localhost:8000/ws/dashboard-{timestamp}
      const WS_URL = `${WS_BASE_URL}/dashboard-${Date.now()}`;
      console.log('Connecting to WebSocket:', WS_URL);

      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        if (isUnmountingRef.current) {
          ws.close();
          return;
        }

        console.log('✅ WebSocket connected');
        setConnected(true);

        // EXACTLY like HTML: send subscribe message
        ws.send(JSON.stringify({ 
          type: 'subscribe', 
          subscriptions: ['new_alerts', 'alert_updates', 'system_metrics'] 
        }));

        if (onConnect) {
          onConnect();
        }
      };

      ws.onmessage = (e) => {
        if (isUnmountingRef.current) return;

        try {
          const data = JSON.parse(e.data);
          if (onMessage) {
            onMessage(data);
          }
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      ws.onclose = () => {
        console.log('🔌 WebSocket disconnected');
        
        if (isUnmountingRef.current) return;

        setConnected(false);
        wsRef.current = null;

        if (onDisconnect) {
          onDisconnect();
        }

        // EXACTLY like HTML: reconnect after 5 seconds
        if (reconnectTimerRef.current) {
          clearTimeout(reconnectTimerRef.current);
        }
        reconnectTimerRef.current = setTimeout(() => {
          if (!isUnmountingRef.current) {
            connect();
          }
        }, 5000);
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };
    }

    // Start connection
    connect();

    // Cleanup function
    return () => {
      console.log('🧹 Cleaning up WebSocket');
      isUnmountingRef.current = true;

      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }

      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []); // Empty dependency array - connect only once

  const sendMessage = (payload) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(payload));
      return true;
    }
    return false;
  };

  return { connected, sendMessage };
};

export default useWebSocket;