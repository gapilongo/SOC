import React, { useState, useEffect } from 'react';
import { Activity, AlertCircle, Clock, TrendingUp, Zap, Shield, Target } from 'lucide-react';
import { useAlerts } from '../contexts/AlertContext';
import { dashboardAPI } from '../services/api';
import IngestionPanel from '../components/dashboard/IngestionPanel';

const Dashboard = () => {
  const { alerts, metrics } = useAlerts();
  const [dashboardStats, setDashboardStats] = useState(null);

  useEffect(() => {
    fetchDashboardStats();

    // Refresh stats every 10 seconds
    const interval = setInterval(fetchDashboardStats, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardStats = async () => {
    try {
      const stats = await dashboardAPI.getStats();
      setDashboardStats(stats);
    } catch (error) {
      console.error('Failed to fetch dashboard stats:', error);
    }
  };

  const criticalCount = alerts.filter(a => a.severity === 'critical').length;

  return (
    <div className="space-y-4 animate-fadeIn">
      {/* Compact Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-sm text-dark-400">Real-time security operations overview</p>
        </div>
      </div>

      {/* Compact Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="glass rounded-lg p-4 card-hover">
          <div className="flex items-center gap-2 mb-2">
            <div className="p-2 rounded-lg bg-blue-500/20">
              <Activity className="w-4 h-4 text-blue-400" />
            </div>
            <div className="text-xl font-bold">
              {dashboardStats?.total_alerts_today || metrics?.alerts_processed_today || 0}
            </div>
          </div>
          <div className="text-xs text-dark-400">Total Today</div>
        </div>

        <div className="glass rounded-lg p-4 card-hover">
          <div className="flex items-center gap-2 mb-2">
            <div className="p-2 rounded-lg bg-yellow-500/20">
              <Zap className="w-4 h-4 text-yellow-400" />
            </div>
            <div className="text-xl font-bold">
              {metrics?.alerts_in_progress || 0}
            </div>
          </div>
          <div className="text-xs text-dark-400">In Progress</div>
        </div>

        <div className="glass rounded-lg p-4 card-hover">
          <div className="flex items-center gap-2 mb-2">
            <div className="p-2 rounded-lg bg-green-500/20">
              <Clock className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-xl font-bold">
              {dashboardStats?.processing_time_avg
                ? `${dashboardStats.processing_time_avg.toFixed(1)}s`
                : metrics?.average_processing_time
                ? `${metrics.average_processing_time.toFixed(1)}s`
                : '0.0s'}
            </div>
          </div>
          <div className="text-xs text-dark-400">Avg Time</div>
        </div>

        <div className="glass rounded-lg p-4 card-hover">
          <div className="flex items-center gap-2 mb-2">
            <div className="p-2 rounded-lg bg-purple-500/20">
              <TrendingUp className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-xl font-bold">
              {metrics?.success_rate
                ? `${(metrics.success_rate * 100).toFixed(0)}%`
                : '0%'}
            </div>
          </div>
          <div className="text-xs text-dark-400">Success Rate</div>
        </div>

        <div className="glass rounded-lg p-4 card-hover">
          <div className="flex items-center gap-2 mb-2">
            <div className="p-2 rounded-lg bg-red-500/20">
              <AlertCircle className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-xl font-bold text-red-400">
              {dashboardStats?.high_priority_alerts || criticalCount || 0}
            </div>
          </div>
          <div className="text-xs text-dark-400">High Priority</div>
        </div>
      </div>

      {/* ============================================ */}
      {/* INGESTION CONTROL PANEL */}
      {/* ============================================ */}
      <IngestionPanel />

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Alerts Feed - 2 columns, more compact */}
        <div className="lg:col-span-2 glass rounded-lg p-4">
          <h2 className="text-lg font-bold mb-3 flex items-center gap-2">
            <AlertCircle className="w-5 h-5" />
            Live Alert Stream
          </h2>
          <div className="space-y-2 max-h-72 overflow-y-auto pr-2">
            {alerts.length === 0 ? (
              <div className="text-center py-8 text-dark-500">
                <Activity className="w-10 h-10 mx-auto mb-3 opacity-50" />
                <p className="text-sm">No alerts detected. System monitoring...</p>
              </div>
            ) : (
              alerts.slice(0, 8).map((alert, index) => (
                <div
                  key={`${alert.id}-${alert.timestamp}-${index}`}
                  className={`border-l-4 rounded-lg p-3 transition-all hover:translate-x-1 cursor-pointer ${
                    alert.severity === 'critical' ? 'border-red-500 bg-red-500/10' :
                    alert.severity === 'high' ? 'border-orange-500 bg-orange-500/10' :
                    alert.severity === 'medium' ? 'border-yellow-500 bg-yellow-500/10' :
                    'border-blue-500 bg-blue-500/10'
                  }`}
                >
                  <div className="flex justify-between items-start mb-1">
                    <span className="font-mono text-xs text-blue-400 font-semibold">
                      {alert.id.substring(0, 12)}
                    </span>
                    <span className="text-xs text-dark-500">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-sm mb-2 line-clamp-1">{alert.description}</p>
                  <div className="flex gap-2 flex-wrap">
                    <span className="px-2 py-0.5 rounded text-xs font-semibold bg-blue-500/20 text-blue-400 uppercase">
                      {alert.status}
                    </span>
                    {alert.confidence && (
                      <span className="px-2 py-0.5 rounded text-xs font-semibold bg-green-500/20 text-green-400">
                        {alert.confidence}%
                      </span>
                    )}
                    <span className="px-2 py-0.5 rounded text-xs font-semibold bg-dark-700 uppercase">
                      {alert.severity}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Top Threats - Compact */}
        <div className="glass rounded-lg p-4">
          <h2 className="text-lg font-bold mb-3 flex items-center gap-2">
            <Target className="w-5 h-5 text-red-400" />
            Top Threats
          </h2>
          <div className="space-y-2">
            {dashboardStats?.top_threat_indicators && dashboardStats.top_threat_indicators.length > 0 ? (
              dashboardStats.top_threat_indicators.slice(0, 5).map((threat, index) => (
                <div
                  key={index}
                  className="bg-dark-800/50 rounded-lg p-3 border-l-2 border-red-500/50 hover:border-red-500 transition-all"
                >
                  <div className="flex justify-between items-center mb-1">
                    <span className="font-semibold text-xs capitalize">
                      {threat.indicator.replace(/_/g, ' ')}
                    </span>
                    <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs font-bold">
                      {threat.count}
                    </span>
                  </div>
                  <div className="w-full bg-dark-700 rounded-full h-1.5 overflow-hidden">
                    <div
                      className="bg-gradient-to-r from-red-500 to-orange-500 h-1.5 rounded-full transition-all"
                      style={{width: `${Math.min((threat.count / 20) * 100, 100)}%`}}
                    ></div>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-6 text-dark-500">
                <Shield className="w-10 h-10 mx-auto mb-2 opacity-50" />
                <p className="text-xs">No threat data available</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Compact Agent Status + Stats in One Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Agent Status */}
        <div className="glass rounded-lg p-4">
          <h2 className="text-lg font-bold mb-3 flex items-center gap-2">
            <Activity className="w-5 h-5" />
            Agent Status
          </h2>
          <div className="grid grid-cols-2 gap-2">
            {metrics?.agent_health && Object.entries(metrics.agent_health).map(([agentName, isHealthy]) => (
              <div
                key={agentName}
                className={`bg-dark-800/50 rounded-lg p-3 border-l-2 transition-all hover:bg-dark-800 ${
                  isHealthy ? 'border-green-500' : 'border-red-500'
                }`}
              >
                <div className="flex justify-between items-center">
                  <span className="font-semibold text-xs uppercase">
                    {agentName.replace('_instance', '').replace('_', ' ')}
                  </span>
                  <div className={`w-2 h-2 rounded-full ${
                    isHealthy ? 'bg-green-400' : 'bg-red-400'
                  } animate-pulse`}></div>
                </div>
                <div className="text-xs text-dark-400 mt-1">
                  {isHealthy ? 'Operational' : 'Error'}
                </div>
              </div>
            ))}

            {(!metrics?.agent_health || Object.keys(metrics.agent_health).length === 0) && (
              <div className="col-span-2 text-center py-6 text-dark-500">
                <Activity className="w-10 h-10 mx-auto mb-2 opacity-50" />
                <p className="text-xs">No agent data available</p>
              </div>
            )}
          </div>
        </div>

        {/* Combined Stats: Alerts by Status & Severity */}
        <div className="glass rounded-lg p-4">
          <h3 className="text-lg font-bold mb-3 flex items-center gap-2">
            <TrendingUp className="w-5 h-5" />
            Alert Distribution
          </h3>

          {dashboardStats?.alerts_by_severity && (
            <div className="mb-3">
              <div className="text-xs text-dark-400 mb-2 font-semibold">BY SEVERITY</div>
              <div className="space-y-1.5">
                {Object.entries(dashboardStats.alerts_by_severity).map(([severity, count]) => (
                  <div key={severity} className="flex items-center gap-2">
                    <span className="text-xs font-semibold capitalize w-16">{severity}</span>
                    <div className="flex-1 bg-dark-800 rounded-full h-1.5 overflow-hidden">
                      <div
                        className={`h-1.5 rounded-full transition-all ${
                          severity === 'critical' ? 'bg-red-500' :
                          severity === 'high' ? 'bg-orange-500' :
                          severity === 'medium' ? 'bg-yellow-500' :
                          'bg-blue-500'
                        }`}
                        style={{width: `${Math.min((count / Math.max(...Object.values(dashboardStats.alerts_by_severity))) * 100, 100)}%`}}
                      ></div>
                    </div>
                    <span className="text-xs font-bold w-8 text-right">{count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {dashboardStats?.alerts_by_status && (
            <div>
              <div className="text-xs text-dark-400 mb-2 font-semibold">BY STATUS</div>
              <div className="space-y-1.5">
                {Object.entries(dashboardStats.alerts_by_status).slice(0, 4).map(([status, count]) => (
                  <div key={status} className="flex items-center gap-2">
                    <span className="text-xs font-semibold capitalize w-16">{status}</span>
                    <div className="flex-1 bg-dark-800 rounded-full h-1.5 overflow-hidden">
                      <div
                        className={`h-1.5 rounded-full transition-all ${
                          status === 'closed' ? 'bg-green-500' :
                          status === 'new' ? 'bg-blue-500' :
                          status === 'in_progress' ? 'bg-yellow-500' :
                          'bg-gradient-to-r from-blue-500 to-purple-600'
                        }`}
                        style={{width: `${Math.min((count / Math.max(...Object.values(dashboardStats.alerts_by_status))) * 100, 100)}%`}}
                      ></div>
                    </div>
                    <span className="text-xs font-bold w-8 text-right">{count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {!dashboardStats?.alerts_by_severity && !dashboardStats?.alerts_by_status && (
            <div className="text-center py-6 text-dark-500">
              <AlertCircle className="w-10 h-10 mx-auto mb-2 opacity-50" />
              <p className="text-xs">No distribution data available</p>
            </div>
          )}
        </div>
      </div>

      {/* Recent Escalations - Only show if exists, compact */}
      {dashboardStats?.recent_escalations && dashboardStats.recent_escalations.length > 0 && (
        <div className="glass rounded-lg p-4">
          <h3 className="text-lg font-bold mb-3 flex items-center gap-2">
            <Shield className="w-5 h-5 text-orange-400" />
            Recent Escalations
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {dashboardStats.recent_escalations.slice(0, 4).map((escalation, index) => (
              <div
                key={index}
                className="bg-orange-500/10 border-l-2 border-orange-500 rounded-lg p-3"
              >
                <p className="text-sm font-semibold line-clamp-1">{escalation.title || escalation.description}</p>
                <p className="text-xs text-dark-400 mt-1">{escalation.timestamp}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
