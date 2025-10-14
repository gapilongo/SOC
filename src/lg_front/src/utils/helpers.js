/**
 * Helper Functions
 * Utility functions used throughout the application
 */

// ============================================
// DATE & TIME HELPERS
// ============================================

/**
 * Format timestamp to relative time (e.g., "2 minutes ago")
 * @param {Date|string|number} date - Date to format
 * @returns {string} Formatted relative time
 */
export const formatTimeAgo = (date) => {
  const seconds = Math.floor((new Date() - new Date(date)) / 1000);
  
  const intervals = {
    year: 31536000,
    month: 2592000,
    week: 604800,
    day: 86400,
    hour: 3600,
    minute: 60,
    second: 1
  };

  for (const [unit, secondsInUnit] of Object.entries(intervals)) {
    const interval = Math.floor(seconds / secondsInUnit);
    if (interval >= 1) {
      return `${interval} ${unit}${interval > 1 ? 's' : ''} ago`;
    }
  }

  return 'just now';
};

/**
 * Format date to readable string
 * @param {Date|string|number} date - Date to format
 * @param {Object} options - Intl.DateTimeFormat options
 * @returns {string} Formatted date
 */
export const formatDate = (date, options = {}) => {
  const defaultOptions = {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    ...options
  };

  return new Date(date).toLocaleDateString('en-US', defaultOptions);
};

/**
 * Format time to readable string
 * @param {Date|string|number} date - Date to format
 * @returns {string} Formatted time
 */
export const formatTime = (date) => {
  return new Date(date).toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
};

/**
 * Get time difference in human readable format
 * @param {Date|string} startDate - Start date
 * @param {Date|string} endDate - End date
 * @returns {string} Time difference
 */
export const getTimeDifference = (startDate, endDate = new Date()) => {
  const diff = Math.abs(new Date(endDate) - new Date(startDate));
  const hours = Math.floor(diff / 3600000);
  const minutes = Math.floor((diff % 3600000) / 60000);
  const seconds = Math.floor((diff % 60000) / 1000);

  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
};

// ============================================
// NUMBER HELPERS
// ============================================

/**
 * Format number with commas (e.g., 1000 -> 1,000)
 * @param {number} num - Number to format
 * @returns {string} Formatted number
 */
export const formatNumber = (num) => {
  if (num === null || num === undefined) return '0';
  return new Intl.NumberFormat('en-US').format(num);
};

/**
 * Format bytes to human readable size
 * @param {number} bytes - Bytes to format
 * @param {number} decimals - Number of decimal places
 * @returns {string} Formatted size
 */
export const formatBytes = (bytes, decimals = 2) => {
  if (bytes === 0) return '0 Bytes';
  if (!bytes) return 'N/A';

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];

  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
};

/**
 * Calculate percentage
 * @param {number} value - Current value
 * @param {number} total - Total value
 * @param {number} decimals - Number of decimal places
 * @returns {number} Percentage
 */
export const calculatePercentage = (value, total, decimals = 1) => {
  if (total === 0) return 0;
  return parseFloat(((value / total) * 100).toFixed(decimals));
};

/**
 * Clamp number between min and max
 * @param {number} value - Value to clamp
 * @param {number} min - Minimum value
 * @param {number} max - Maximum value
 * @returns {number} Clamped value
 */
export const clamp = (value, min, max) => {
  return Math.min(Math.max(value, min), max);
};

// ============================================
// STRING HELPERS
// ============================================

/**
 * Truncate string to specified length
 * @param {string} str - String to truncate
 * @param {number} length - Maximum length
 * @returns {string} Truncated string
 */
export const truncate = (str, length = 50) => {
  if (!str) return '';
  if (str.length <= length) return str;
  return str.substring(0, length) + '...';
};

/**
 * Capitalize first letter of string
 * @param {string} str - String to capitalize
 * @returns {string} Capitalized string
 */
export const capitalize = (str) => {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1);
};

/**
 * Convert camelCase to Title Case
 * @param {string} str - String to convert
 * @returns {string} Title case string
 */
export const camelToTitle = (str) => {
  if (!str) return '';
  return str
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, (s) => s.toUpperCase())
    .trim();
};

/**
 * Convert snake_case to Title Case
 * @param {string} str - String to convert
 * @returns {string} Title case string
 */
export const snakeToTitle = (str) => {
  if (!str) return '';
  return str
    .split('_')
    .map(word => capitalize(word))
    .join(' ');
};

/**
 * Generate random string
 * @param {number} length - Length of string
 * @returns {string} Random string
 */
export const generateRandomString = (length = 10) => {
  return Math.random().toString(36).substring(2, length + 2);
};

// ============================================
// ID HELPERS
// ============================================

/**
 * Generate unique ID
 * @returns {string} Unique ID
 */
export const generateId = () => {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
};

/**
 * Generate UUID v4
 * @returns {string} UUID
 */
export const generateUUID = () => {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
};

// ============================================
// VALIDATION HELPERS
// ============================================

/**
 * Validate email address
 * @param {string} email - Email to validate
 * @returns {boolean} Is valid email
 */
export const isValidEmail = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
};

/**
 * Validate URL
 * @param {string} url - URL to validate
 * @returns {boolean} Is valid URL
 */
export const isValidURL = (url) => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};

/**
 * Check if value is empty
 * @param {*} value - Value to check
 * @returns {boolean} Is empty
 */
export const isEmpty = (value) => {
  if (value === null || value === undefined) return true;
  if (typeof value === 'string') return value.trim().length === 0;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === 'object') return Object.keys(value).length === 0;
  return false;
};

// ============================================
// OBJECT HELPERS
// ============================================

/**
 * Deep clone object
 * @param {Object} obj - Object to clone
 * @returns {Object} Cloned object
 */
export const deepClone = (obj) => {
  if (obj === null || typeof obj !== 'object') return obj;
  return JSON.parse(JSON.stringify(obj));
};

/**
 * Deep merge objects
 * @param {Object} target - Target object
 * @param {Object} source - Source object
 * @returns {Object} Merged object
 */
export const deepMerge = (target, source) => {
  const output = { ...target };
  if (isObject(target) && isObject(source)) {
    Object.keys(source).forEach(key => {
      if (isObject(source[key])) {
        if (!(key in target)) {
          Object.assign(output, { [key]: source[key] });
        } else {
          output[key] = deepMerge(target[key], source[key]);
        }
      } else {
        Object.assign(output, { [key]: source[key] });
      }
    });
  }
  return output;
};

/**
 * Check if value is object
 * @param {*} item - Item to check
 * @returns {boolean} Is object
 */
export const isObject = (item) => {
  return item && typeof item === 'object' && !Array.isArray(item);
};

// ============================================
// ARRAY HELPERS
// ============================================

/**
 * Remove duplicates from array
 * @param {Array} arr - Array to process
 * @returns {Array} Array without duplicates
 */
export const removeDuplicates = (arr) => {
  return [...new Set(arr)];
};

/**
 * Sort array of objects by property
 * @param {Array} arr - Array to sort
 * @param {string} key - Property to sort by
 * @param {string} order - Sort order ('asc' or 'desc')
 * @returns {Array} Sorted array
 */
export const sortByProperty = (arr, key, order = 'asc') => {
  return [...arr].sort((a, b) => {
    const aVal = a[key];
    const bVal = b[key];
    
    if (aVal < bVal) return order === 'asc' ? -1 : 1;
    if (aVal > bVal) return order === 'asc' ? 1 : -1;
    return 0;
  });
};

/**
 * Group array by property
 * @param {Array} arr - Array to group
 * @param {string} key - Property to group by
 * @returns {Object} Grouped object
 */
export const groupBy = (arr, key) => {
  return arr.reduce((result, item) => {
    const group = item[key];
    if (!result[group]) {
      result[group] = [];
    }
    result[group].push(item);
    return result;
  }, {});
};

// ============================================
// DEBOUNCE & THROTTLE
// ============================================

/**
 * Debounce function
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} Debounced function
 */
export const debounce = (func, wait = 300) => {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
};

/**
 * Throttle function
 * @param {Function} func - Function to throttle
 * @param {number} limit - Time limit in milliseconds
 * @returns {Function} Throttled function
 */
export const throttle = (func, limit = 300) => {
  let inThrottle;
  return function executedFunction(...args) {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
};

// ============================================
// COLOR HELPERS
// ============================================

/**
 * Get severity color class
 * @param {string} severity - Severity level
 * @returns {string} Color class
 */
export const getSeverityColor = (severity) => {
  const colors = {
    critical: 'text-red-400',
    high: 'text-orange-400',
    medium: 'text-yellow-400',
    low: 'text-blue-400'
  };
  return colors[severity?.toLowerCase()] || colors.low;
};

/**
 * Get status color class
 * @param {string} status - Status
 * @returns {string} Color class
 */
export const getStatusColor = (status) => {
  const colors = {
    processing: 'text-blue-400',
    triaged: 'text-purple-400',
    correlated: 'text-cyan-400',
    analyzed: 'text-indigo-400',
    closed: 'text-green-400',
    failed: 'text-red-400'
  };
  return colors[status?.toLowerCase()] || colors.processing;
};

// ============================================
// ASYNC HELPERS
// ============================================

/**
 * Sleep/delay function
 * @param {number} ms - Milliseconds to sleep
 * @returns {Promise} Promise that resolves after delay
 */
export const sleep = (ms) => {
  return new Promise(resolve => setTimeout(resolve, ms));
};

/**
 * Retry async function
 * @param {Function} fn - Async function to retry
 * @param {number} retries - Number of retries
 * @param {number} delay - Delay between retries
 * @returns {Promise} Result of function
 */
export const retry = async (fn, retries = 3, delay = 1000) => {
  try {
    return await fn();
  } catch (error) {
    if (retries <= 0) throw error;
    await sleep(delay);
    return retry(fn, retries - 1, delay);
  }
};

// ============================================
// EXPORT ALL
// ============================================
export default {
  formatTimeAgo,
  formatDate,
  formatTime,
  getTimeDifference,
  formatNumber,
  formatBytes,
  calculatePercentage,
  clamp,
  truncate,
  capitalize,
  camelToTitle,
  snakeToTitle,
  generateRandomString,
  generateId,
  generateUUID,
  isValidEmail,
  isValidURL,
  isEmpty,
  deepClone,
  deepMerge,
  isObject,
  removeDuplicates,
  sortByProperty,
  groupBy,
  debounce,
  throttle,
  getSeverityColor,
  getStatusColor,
  sleep,
  retry
};