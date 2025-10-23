import React, { useState, useEffect } from 'react';
import {
  Download, Clock, CheckCircle, XCircle, AlertCircle, RefreshCw,
  Zap, TrendingUp, Activity
} from 'lucide-react';
import { ingestionAPI } from '../../services/api';

const IngestionPanel = () => {
  const [ingestionStatus, setIngestionStatus] = useState(null);
  const [isPolling, setIsPolling] = useState(false);
  const [lastPollResult, setLastPollResult] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Fetch ingestion status
  const fetchIngestionStatus = async () => {
    try {
      const status = await ingestionAPI.getStatus();
      setIngestionStatus(status);
    } catch (error) {
      console.error('Failed to fetch ingestion status:', error);
    }
  };

  // Trigger manual poll
  const handleTriggerPoll = async () => {
    setIsPolling(true);
    setLastPollResult(null);

    try {
      const result = await ingestionAPI.triggerPoll();

      // The backend returns: { status: "success", message: "...", alerts_found: 10, timestamp: "..." }
      const ingestedCount = result.alerts_found || 0;

      setLastPollResult({
        success: true,
        message: result.message || `Successfully ingested ${ingestedCount} alerts`,
        count: ingestedCount
      });

      // Refresh status after polling
      setTimeout(() => {
        fetchIngestionStatus();
      }, 1000);
    } catch (error) {
      setLastPollResult({
        success: false,
        message: error.message || 'Failed to trigger ingestion',
        count: 0
      });
    } finally {
      setTimeout(() => setIsPolling(false), 2000);
    }
  };

  // Auto-refresh every 5 seconds
  useEffect(() => {
    fetchIngestionStatus();

    if (autoRefresh) {
      const interval = setInterval(() => {
        fetchIngestionStatus();
      }, 5000);

      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  // Calculate time until next poll
  const getTimeUntilNextPoll = () => {
    if (!ingestionStatus?.next_poll_time) return null;

    const nextPoll = new Date(ingestionStatus.next_poll_time);
    const now = new Date();
    const diff = nextPoll - now;

    if (diff <= 0) return 'Now';

    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;

    if (minutes > 0) {
      return `${minutes}m ${remainingSeconds}s`;
    }
    return `${remainingSeconds}s`;
  };

  // Format timestamp
  const formatTime = (timestamp) => {
    if (!timestamp) return 'Never';
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const timeUntilNext = getTimeUntilNextPoll();

  return (
    <div className="space-y-4">
      {/* Header with Status Indicator */}
      <div className="glass rounded-xl p-5 border-l-4 border-blue-500">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-gradient-to-br from-blue-500/20 to-purple-600/20 backdrop-blur-sm">
              <Download className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <h2 className="text-xl font-bold">Ingestion Control</h2>
              <p className="text-sm text-dark-400">Real-time alert collection & processing</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Auto-refresh toggle */}
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`px-3 py-2 rounded-lg text-sm font-semibold transition-all ${
                autoRefresh
                  ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                  : 'bg-dark-700 text-dark-400 border border-dark-600'
              }`}
            >
              <Activity className={`w-4 h-4 inline mr-1 ${autoRefresh ? 'animate-pulse' : ''}`} />
              {autoRefresh ? 'Live' : 'Paused'}
            </button>

            {/* Trigger Poll Button */}
            <button
              onClick={handleTriggerPoll}
              disabled={isPolling}
              className={`px-4 py-2 rounded-lg font-semibold transition-all flex items-center gap-2 ${
                isPolling
                  ? 'bg-dark-700 cursor-not-allowed opacity-50'
                  : 'bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 shadow-lg hover:shadow-blue-500/50'
              }`}
            >
              <RefreshCw className={`w-4 h-4 ${isPolling ? 'animate-spin' : ''}`} />
              {isPolling ? 'Polling...' : 'Trigger Poll'}
            </button>
          </div>
        </div>

        {/* Last Poll Result Toast */}
        {lastPollResult && (
          <div
            className={`mb-4 p-3 rounded-lg border-l-4 animate-fadeIn ${
              lastPollResult.success
                ? 'bg-green-500/10 border-green-500'
                : 'bg-red-500/10 border-red-500'
            }`}
          >
            <div className="flex items-center gap-2">
              {lastPollResult.success ? (
                <CheckCircle className="w-5 h-5 text-green-400" />
              ) : (
                <XCircle className="w-5 h-5 text-red-400" />
              )}
              <span className="text-sm font-semibold">{lastPollResult.message}</span>
            </div>
          </div>
        )}

        {/* Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {/* Status */}
          <div className="bg-dark-800/50 rounded-lg p-3 border border-dark-700">
            <div className="flex items-center gap-2 mb-2">
              <div className={`w-3 h-3 rounded-full animate-pulse ${
                ingestionStatus?.is_active ? 'bg-green-500' : 'bg-red-500'
              }`}></div>
              <span className="text-xs text-dark-400 uppercase font-semibold">Status</span>
            </div>
            <div className="text-lg font-bold">
              {ingestionStatus?.is_active ? 'Active' : 'Inactive'}
            </div>
          </div>

          {/* Total Ingested */}
          <div className="bg-dark-800/50 rounded-lg p-3 border border-dark-700" title="Total unique alerts ingested (cumulative)">
            <div className="flex items-center gap-2 mb-2">
              <Zap className="w-4 h-4 text-yellow-400" />
              <span className="text-xs text-dark-400 uppercase font-semibold">Ingested</span>
            </div>
            <div className="text-lg font-bold text-yellow-400">
              {ingestionStatus?.total_ingested || 0}
            </div>
          </div>

          {/* Duplicates */}
          <div className="bg-dark-800/50 rounded-lg p-3 border border-dark-700" title="Total duplicates filtered out (cumulative)">
            <div className="flex items-center gap-2 mb-2">
              <AlertCircle className="w-4 h-4 text-orange-400" />
              <span className="text-xs text-dark-400 uppercase font-semibold">Duplicates</span>
            </div>
            <div className="text-lg font-bold text-orange-400">
              {ingestionStatus?.total_deduplicated || 0}
            </div>
          </div>

          {/* Errors */}
          <div className="bg-dark-800/50 rounded-lg p-3 border border-dark-700">
            <div className="flex items-center gap-2 mb-2">
              <XCircle className="w-4 h-4 text-red-400" />
              <span className="text-xs text-dark-400 uppercase font-semibold">Errors</span>
            </div>
            <div className="text-lg font-bold text-red-400">
              {ingestionStatus?.total_errors || 0}
            </div>
          </div>
        </div>

        {/* Timing Information */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-3">
          {/* Last Poll */}
          <div className="bg-gradient-to-br from-blue-500/10 to-purple-600/10 rounded-lg p-3 border border-blue-500/30" title="Timestamp of last ingestion poll (manual or automatic)">
            <div className="flex items-center gap-2 mb-1">
              <Clock className="w-4 h-4 text-blue-400" />
              <span className="text-xs text-dark-400 uppercase font-semibold">Last Poll</span>
            </div>
            <div className="text-sm font-bold text-blue-400">
              {formatTime(ingestionStatus?.last_poll_time)}
            </div>
          </div>

          {/* Next Poll */}
          <div className="bg-gradient-to-br from-green-500/10 to-emerald-600/10 rounded-lg p-3 border border-green-500/30" title="Countdown to next automatic poll">
            <div className="flex items-center gap-2 mb-1">
              <Clock className="w-4 h-4 text-green-400" />
              <span className="text-xs text-dark-400 uppercase font-semibold">Next Poll</span>
            </div>
            <div className="text-sm font-bold text-green-400">
              {timeUntilNext || formatTime(ingestionStatus?.next_poll_time)}
            </div>
          </div>

          {/* Interval */}
          <div className="bg-gradient-to-br from-purple-500/10 to-pink-600/10 rounded-lg p-3 border border-purple-500/30" title="Time between automatic polls (configured in settings)">
            <div className="flex items-center gap-2 mb-1">
              <TrendingUp className="w-4 h-4 text-purple-400" />
              <span className="text-xs text-dark-400 uppercase font-semibold">Interval</span>
            </div>
            <div className="text-sm font-bold text-purple-400">
              {ingestionStatus?.polling_interval || 0}s
            </div>
          </div>
        </div>
      </div>

    </div>
  );
};

export default IngestionPanel;
