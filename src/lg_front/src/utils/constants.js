/**
 * Application Constants
 * All constant values used throughout the application
 */

// ============================================
// API CONFIGURATION
// ============================================
export const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
export const WS_BASE_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:8000/ws';
export const APP_VERSION = process.env.REACT_APP_VERSION || '1.0.0';

// ============================================
// ALERT SEVERITY LEVELS
// ============================================
export const SEVERITY_LEVELS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low'
};

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

// ============================================
// ALERT STATUS
// ============================================
export const ALERT_STATUS = {
  PROCESSING: 'processing',
  TRIAGED: 'triaged',
  CORRELATED: 'correlated',
  ANALYZED: 'analyzed',
  CLOSED: 'closed',
  FAILED: 'failed',
  PENDING: 'pending'
};

// ============================================
// SEVERITY COLORS (Tailwind classes)
// ============================================
export const SEVERITY_COLORS = {
  critical: {
    bg: 'bg-red-500/10',
    text: 'text-red-400',
    border: 'border-red-500',
    solid: 'bg-red-500'
  },
  high: {
    bg: 'bg-orange-500/10',
    text: 'text-orange-400',
    border: 'border-orange-500',
    solid: 'bg-orange-500'
  },
  medium: {
    bg: 'bg-yellow-500/10',
    text: 'text-yellow-400',
    border: 'border-yellow-500',
    solid: 'bg-yellow-500'
  },
  low: {
    bg: 'bg-blue-500/10',
    text: 'text-blue-400',
    border: 'border-blue-500',
    solid: 'bg-blue-500'
  }
};

// ============================================
// STATUS COLORS (Tailwind classes)
// ============================================
export const STATUS_COLORS = {
  processing: {
    bg: 'bg-blue-500/20',
    text: 'text-blue-400',
    border: 'border-blue-500/30'
  },
  triaged: {
    bg: 'bg-purple-500/20',
    text: 'text-purple-400',
    border: 'border-purple-500/30'
  },
  correlated: {
    bg: 'bg-cyan-500/20',
    text: 'text-cyan-400',
    border: 'border-cyan-500/30'
  },
  analyzed: {
    bg: 'bg-indigo-500/20',
    text: 'text-indigo-400',
    border: 'border-indigo-500/30'
  },
  closed: {
    bg: 'bg-green-500/20',
    text: 'text-green-400',
    border: 'border-green-500/30'
  },
  failed: {
    bg: 'bg-red-500/20',
    text: 'text-red-400',
    border: 'border-red-500/30'
  },
  pending: {
    bg: 'bg-gray-500/20',
    text: 'text-gray-400',
    border: 'border-gray-500/30'
  }
};

// ============================================
// WEBSOCKET EVENT TYPES
// ============================================
export const WS_EVENT_TYPES = {
  NEW_ALERT: 'new_alert',
  ALERT_UPDATE: 'alert_update',
  SYSTEM_METRICS: 'system_metrics',
  HEARTBEAT: 'heartbeat',
  CONNECTION: 'connection',
  SUBSCRIBE: 'subscribe',
  UNSUBSCRIBE: 'unsubscribe',
  PING: 'ping',
  PONG: 'pong'
};

// ============================================
// CHART COLORS
// ============================================
export const CHART_COLORS = {
  primary: '#3b82f6',
  secondary: '#8b5cf6',
  success: '#10b981',
  warning: '#f59e0b',
  danger: '#ef4444',
  info: '#06b6d4',
  purple: '#a855f7',
  pink: '#ec4899',
  indigo: '#6366f1',
  teal: '#14b8a6'
};

export const CHART_COLOR_ARRAY = [
  '#3b82f6', '#8b5cf6', '#10b981', '#f59e0b',
  '#ef4444', '#06b6d4', '#a855f7', '#ec4899'
];

// ============================================
// TIME RANGES
// ============================================
export const TIME_RANGES = {
  '1h': { label: 'Last Hour', hours: 1 },
  '24h': { label: 'Last 24 Hours', hours: 24 },
  '7d': { label: 'Last 7 Days', hours: 168 },
  '30d': { label: 'Last 30 Days', hours: 720 },
  '90d': { label: 'Last 90 Days', hours: 2160 }
};

// ============================================
// PAGINATION
// ============================================
export const DEFAULT_PAGE_SIZE = 50;
export const PAGE_SIZE_OPTIONS = [10, 25, 50, 100, 200];

// ============================================
// REFRESH INTERVALS (milliseconds)
// ============================================
export const REFRESH_INTERVALS = {
  FAST: 5000,      // 5 seconds
  NORMAL: 10000,   // 10 seconds
  SLOW: 30000,     // 30 seconds
  VERY_SLOW: 60000 // 1 minute
};

// ============================================
// AGENT TYPES
// ============================================
export const AGENT_TYPES = {
  TRIAGE: 'triage',
  CORRELATION: 'correlation',
  ANALYSIS: 'analysis',
  RESPONSE: 'response'
};

// ============================================
// USER ROLES
// ============================================
export const USER_ROLES = {
  ADMIN: 'admin',
  ANALYST: 'analyst',
  VIEWER: 'viewer',
  OPERATOR: 'operator'
};

// ============================================
// PERMISSIONS
// ============================================
export const PERMISSIONS = {
  READ: 'read',
  WRITE: 'write',
  DELETE: 'delete',
  ANALYZE: 'analyze',
  ADMIN: 'admin'
};

// ============================================
// ROUTES
// ============================================
export const ROUTES = {
  LOGIN: '/login',
  DASHBOARD: '/dashboard',
  ALERTS: '/alerts',
  ANALYTICS: '/analytics',
  AGENTS: '/agents',
  SETTINGS: '/settings'
};

// ============================================
// LOCAL STORAGE KEYS
// ============================================
export const STORAGE_KEYS = {
  USER: 'soc_user',
  TOKEN: 'soc_token',
  SETTINGS: 'soc_settings',
  THEME: 'soc_theme',
  SIDEBAR_STATE: 'soc_sidebar_state'
};

// ============================================
// DATE FORMATS
// ============================================
export const DATE_FORMATS = {
  FULL: 'YYYY-MM-DD HH:mm:ss',
  SHORT: 'YYYY-MM-DD',
  TIME: 'HH:mm:ss',
  DATETIME: 'MMM DD, YYYY HH:mm'
};

// ============================================
// ERROR MESSAGES
// ============================================
export const ERROR_MESSAGES = {
  NETWORK_ERROR: 'Network error. Please check your connection.',
  AUTH_ERROR: 'Authentication failed. Please login again.',
  SERVER_ERROR: 'Server error. Please try again later.',
  NOT_FOUND: 'Resource not found.',
  VALIDATION_ERROR: 'Validation error. Please check your input.',
  TIMEOUT: 'Request timeout. Please try again.'
};

// ============================================
// SUCCESS MESSAGES
// ============================================
export const SUCCESS_MESSAGES = {
  LOGIN_SUCCESS: 'Login successful!',
  LOGOUT_SUCCESS: 'Logout successful!',
  SAVE_SUCCESS: 'Settings saved successfully!',
  UPDATE_SUCCESS: 'Updated successfully!',
  DELETE_SUCCESS: 'Deleted successfully!',
  SUBMIT_SUCCESS: 'Submitted successfully!'
};

// ============================================
// NOTIFICATION TYPES
// ============================================
export const NOTIFICATION_TYPES = {
  SUCCESS: 'success',
  ERROR: 'error',
  WARNING: 'warning',
  INFO: 'info'
};

// ============================================
// EXPORT ALL
// ============================================
export default {
  API_BASE_URL,
  WS_BASE_URL,
  APP_VERSION,
  SEVERITY_LEVELS,
  SEVERITY_ORDER,
  ALERT_STATUS,
  SEVERITY_COLORS,
  STATUS_COLORS,
  WS_EVENT_TYPES,
  CHART_COLORS,
  CHART_COLOR_ARRAY,
  TIME_RANGES,
  DEFAULT_PAGE_SIZE,
  PAGE_SIZE_OPTIONS,
  REFRESH_INTERVALS,
  AGENT_TYPES,
  USER_ROLES,
  PERMISSIONS,
  ROUTES,
  STORAGE_KEYS,
  DATE_FORMATS,
  ERROR_MESSAGES,
  SUCCESS_MESSAGES,
  NOTIFICATION_TYPES
};