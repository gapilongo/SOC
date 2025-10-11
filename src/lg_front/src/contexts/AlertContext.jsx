import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { alertsAPI } from '../services/api';
import useWebSocket from '../hooks/useWebSocket';

const AlertContext = createContext(null);

export const useAlerts = () => {
  const context = useContext(AlertContext);
  if (!context) {
    throw new Error('useAlerts must be used within AlertProvider');
  }
  return context;
};

export const AlertProvider = ({ children }) => {
  const [alerts, setAlerts] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const { connected, sendMessage } = useWebSocket({
    onMessage: handleWebSocketMessage
  });

  function handleWebSocketMessage(data) {
    switch (data.type) {
      case 'new_alert':
        setAlerts(prev => [{
          id: data.alert_id,
          severity: data.severity || 'medium',
          timestamp: new Date(data.timestamp),
          status: 'processing',
          description: 'Security event detected',
          confidence: 0
        }, ...prev].slice(0, 100));
        break;

      case 'alert_update':
        setAlerts(prev => prev.map(alert =>
          alert.id === data.alert_id
            ? { ...alert, status: data.status, confidence: data.result?.confidence_score || alert.confidence }
            : alert
        ));
        break;

      case 'system_metrics':
        setMetrics(data.data);
        break;

      default:
        break;
    }
  }

  const fetchAlerts = useCallback(async (params = {}) => {
    try {
      setLoading(true);
      const data = await alertsAPI.getAlerts(params);
      setAlerts(data.map(a => ({
        id: a.alert_id,
        severity: 'medium',
        timestamp: new Date(a.created_at),
        status: a.status,
        confidence: a.confidence_score,
        description: 'Security alert from database'
      })));
      setError(null);
    } catch (err) {
      setError(err.message);
      console.error('Failed to fetch alerts:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  const submitAlert = useCallback(async (alertData) => {
    try {
      const response = await alertsAPI.submitAlert(alertData);
      return response;
    } catch (err) {
      console.error('Failed to submit alert:', err);
      throw err;
    }
  }, []);

  const getAlertDetails = useCallback(async (alertId) => {
    try {
      const data = await alertsAPI.getAlertStatus(alertId);
      return data;
    } catch (err) {
      console.error('Failed to get alert details:', err);
      throw err;
    }
  }, []);

  useEffect(() => {
    fetchAlerts({ limit: 50 });
  }, [fetchAlerts]);

  const value = {
    alerts,
    metrics,
    loading,
    error,
    connected,
    fetchAlerts,
    submitAlert,
    getAlertDetails,
    sendMessage
  };

  return (
    <AlertContext.Provider value={value}>
      {children}
    </AlertContext.Provider>
  );
};