import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';

// Create axios instance with default config
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000, // 30 seconds
});

// Request interceptor - Add auth token to all requests
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('soc_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    console.error('Request interceptor error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor - Handle errors globally
apiClient.interceptors.response.use(
  (response) => {
    // Return only the data
    return response.data;
  },
  (error) => {
    // Handle different error types
    if (error.response) {
      // Server responded with error
      const message = error.response.data?.detail || error.response.data?.message || error.message;
      console.error('API Error:', message);
      
      // Handle specific status codes
      if (error.response.status === 401) {
        // Unauthorized - clear token and redirect to login
        localStorage.removeItem('soc_token');
        localStorage.removeItem('soc_user');
        window.location.href = '/login';
      }
      
      return Promise.reject(new Error(message));
    } else if (error.request) {
      // Request made but no response
      console.error('No response from server:', error.request);
      return Promise.reject(new Error('No response from server. Please check your connection.'));
    } else {
      // Error in request setup
      console.error('Request setup error:', error.message);
      return Promise.reject(new Error(error.message));
    }
  }
);

// ============================================
// ALERTS API
// ============================================
export const alertsAPI = {
  /**
   * Get list of alerts
   * @param {Object} params - Query parameters (limit, status, severity, etc.)
   */
  getAlerts: (params = {}) => {
    return apiClient.get('/alerts', { params });
  },

  /**
   * Submit a new alert for processing
   * @param {Object} alertData - Alert data with alert_data and priority
   */
  submitAlert: (alertData) => {
    return apiClient.post('/alerts/process', alertData);
  },

  /**
   * Get status of a specific alert
   * @param {string} alertId - Alert ID
   */
  getAlertStatus: (alertId) => {
    return apiClient.get(`/alerts/${alertId}/status`);
  },

  /**
   * Get correlations for a specific alert
   * @param {string} alertId - Alert ID
   */
  getAlertCorrelations: (alertId) => {
    return apiClient.get(`/alerts/${alertId}/correlations`);
  },

  /**
   * Get alert details
   * @param {string} alertId - Alert ID
   */
  getAlertDetails: (alertId) => {
    return apiClient.get(`/alerts/${alertId}`);
  },

  /**
   * Update alert status
   * @param {string} alertId - Alert ID
   * @param {Object} data - Update data
   */
  updateAlert: (alertId, data) => {
    return apiClient.patch(`/alerts/${alertId}`, data);
  },

  /**
   * Delete an alert
   * @param {string} alertId - Alert ID
   */
  deleteAlert: (alertId) => {
    return apiClient.delete(`/alerts/${alertId}`);
  },
};

// ============================================
// DASHBOARD API
// ============================================
export const dashboardAPI = {
  /**
   * Get dashboard statistics
   */
  getStats: () => {
    return apiClient.get('/dashboard/stats');
  },

  /**
   * Get system metrics
   */
  getMetrics: () => {
    return apiClient.get('/metrics');
  },

  /**
   * Get dashboard summary
   */
  getSummary: () => {
    return apiClient.get('/dashboard/summary');
  },
};

// ============================================
// AGENTS API
// ============================================
export const agentsAPI = {
  /**
   * Get all agents status
   */
  getStatus: () => {
    return apiClient.get('/agents/status');
  },

  /**
   * Get specific agent details
   * @param {string} agentName - Agent name
   */
  getAgentDetails: (agentName) => {
    return apiClient.get(`/agents/${agentName}`);
  },

  /**
   * Get agent metrics
   * @param {string} agentName - Agent name
   */
  getAgentMetrics: (agentName) => {
    return apiClient.get(`/agents/${agentName}/metrics`);
  },

  /**
   * Restart an agent
   * @param {string} agentName - Agent name
   */
  restartAgent: (agentName) => {
    return apiClient.post(`/agents/${agentName}/restart`);
  },
};

// ============================================
// ANALYTICS API
// ============================================
export const analyticsAPI = {
  /**
   * Get analytics data
   * @param {Object} params - Query parameters (timeRange, type, etc.)
   */
  getAnalytics: (params = {}) => {
    return apiClient.get('/analytics', { params });
  },

  /**
   * Get trends data
   * @param {string} timeRange - Time range (24h, 7d, 30d, 90d)
   */
  getTrends: (timeRange = '24h') => {
    return apiClient.get('/analytics/trends', { params: { timeRange } });
  },

  /**
   * Get threat intelligence data
   */
  getThreatIntelligence: () => {
    return apiClient.get('/analytics/threats');
  },
};

// ============================================
// HEALTH API
// ============================================
export const healthAPI = {
  /**
   * Check system health
   */
  check: () => {
    return apiClient.get('/health');
  },

  /**
   * Get detailed health status
   */
  getDetailedStatus: () => {
    return apiClient.get('/health/detailed');
  },
};

// ============================================
// SETTINGS API
// ============================================
export const settingsAPI = {
  /**
   * Get user settings
   */
  getSettings: () => {
    return apiClient.get('/settings');
  },

  /**
   * Update user settings
   * @param {Object} settings - Settings object
   */
  updateSettings: (settings) => {
    return apiClient.put('/settings', settings);
  },

  /**
   * Reset settings to default
   */
  resetSettings: () => {
    return apiClient.post('/settings/reset');
  },
};

// ============================================
// EXPORT API CLIENT
// ============================================
export default apiClient;