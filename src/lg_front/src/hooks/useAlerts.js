import { useState, useEffect, useCallback } from 'react';
import { alertsAPI } from '../services/api';

/**
 * Alternative hook to use alerts without context
 * Use this if you prefer hooks over context
 */
const useAlerts = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

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

  return {
    alerts,
    loading,
    error,
    fetchAlerts,
    submitAlert,
    getAlertDetails
  };
};

export default useAlerts;