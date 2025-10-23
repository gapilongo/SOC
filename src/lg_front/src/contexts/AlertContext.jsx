import React, { createContext, useContext, useState, useEffect } from 'react';
import useWebSocket from '../hooks/useWebSocket';
import { alertsAPI } from '../services/api';

const AlertContext = createContext();

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';

export const AlertProvider = ({ children }) => {
  const [alerts, setAlerts] = useState([]);
  const [metrics, setMetrics] = useState({
    alerts_processed_today: 0,
    alerts_in_progress: 0,
    average_processing_time: 0,
    success_rate: 0,
    agent_health: {}
  });
  const [dashboardStats, setDashboardStats] = useState(null);

  // Fetch initial data - EXACTLY like HTML fetchData()
  const fetchData = async () => {
    try {
      const [alertsResponse, statsResponse] = await Promise.all([
        fetch(`${API_BASE}/alerts?limit=100`),
        fetch(`${API_BASE}/dashboard/stats`)
      ]);

      const alertsData = await alertsResponse.json();
      const stats = await statsResponse.json();

      // EXACTLY like HTML: map alerts
      const mappedAlerts = alertsData.map(x => ({
        id: x.alert_id,
        severity: x.severity || 'high',
        timestamp: new Date(x.created_at),
        status: x.status,
        confidence: x.confidence_score,
        description: x.description || 'Security alert'
      }));

      setAlerts(mappedAlerts);
      setDashboardStats(stats);

      console.log('✅ Fetched', alertsData.length, 'alerts');
    } catch (error) {
      console.error('Error fetching data:', error);
    }
  };

  // Handle WebSocket messages - EXACTLY like HTML handleMessage(d)
  const handleMessage = (d) => {
    if (d.type === 'new_alert') {
      // EXACTLY like HTML: unshift new alert, pop if > 15
      setAlerts(prev => {
        const newAlerts = [{
          id: d.alert_id,
          severity: d.severity || 'medium',
          timestamp: new Date(d.timestamp),
          status: 'processing',
          description: 'Security event detected'
        }, ...prev];
        
        if (newAlerts.length > 15) {
          newAlerts.pop();
        }
        
        return newAlerts;
      });
    } 
    else if (d.type === 'alert_update') {
      // EXACTLY like HTML: find and update alert
      setAlerts(prev => prev.map(a => {
        if (a.id === d.alert_id) {
          return {
            ...a,
            status: d.status,
            confidence: d.result?.confidence_score
          };
        }
        return a;
      }));
    } 
    else if (d.type === 'system_metrics') {
      // EXACTLY like HTML: update metrics
      setMetrics(d.data);
    }
  };

  // Initialize WebSocket
  const { connected, sendMessage } = useWebSocket({
    onMessage: handleMessage,
    onConnect: () => {
      console.log('WebSocket connected - fetching data');
      fetchData();
    },
    onDisconnect: () => {
      console.log('WebSocket disconnected');
    }
  });

  // Periodic data fetch - EXACTLY like HTML: setInterval(fetchData, 30000)
  useEffect(() => {
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  // Submit alert function - Using ORIGINAL API format from your documents
  const submitAlert = async (alertData) => {
    try {
           const response = await alertsAPI.submitAlert(alertData);


      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP error! status: ${response.status}, message: ${errorText}`);
      }

      const result = await response.json();
      console.log('✅ Alert submitted successfully:', result);
      return result;
    } catch (error) {
      console.error('❌ Failed to submit alert:', error);
      throw error;
    }
  };

  const value = {
    alerts,
    metrics,
    dashboardStats,
    connected,
    submitAlert,
    sendMessage
  };

  return (
    <AlertContext.Provider value={value}>
      {children}
    </AlertContext.Provider>
  );
};

export const useAlerts = () => {
  const context = useContext(AlertContext);
  if (!context) {
    throw new Error('useAlerts must be used within AlertProvider');
  }
  return context;
};

export default AlertContext;