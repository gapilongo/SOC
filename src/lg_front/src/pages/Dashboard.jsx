import React, { useState, useEffect } from 'react';
import { Activity, AlertCircle, Clock, TrendingUp, Zap, Play, Shield, Target } from 'lucide-react';
import { useAlerts } from '../contexts/AlertContext';
import { dashboardAPI, alertsAPI } from '../services/api';

const Dashboard = () => {
  const { alerts, metrics } = useAlerts();
  const [dashboardStats, setDashboardStats] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    fetchDashboardStats();
  }, []);

  const fetchDashboardStats = async () => {
    try {
      const stats = await dashboardAPI.getStats();
      setDashboardStats(stats);
      console.log('📊 Dashboard Stats:', stats);
    } catch (error) {
      console.error('Failed to fetch dashboard stats:', error);
    }
  };

  const handleTestAlert = async () => {
    setIsSubmitting(true);
    try {
      // Use alertsAPI.submitAlert (which calls /alerts/process)
      await alertsAPI.submitAlert({
        alert_data: {
          id: `test-${Date.now()}`,
          source: 'demo-siem',
          timestamp: new Date().toISOString(),
          severity: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)],
          description: 'Demo security event for testing',
          raw_data: {
            event_type: 'test_event',
            process_name: 'demo.exe',
            user: 'SYSTEM',
            host: 'demo-server-01',
            source_ip: '192.168.1.100',
            destination_ip: '10.0.0.50'
          }
        },
        priority: 'normal'
      });
      console.log('✅ Test alert submitted successfully');
      // Refresh stats after submitting
      setTimeout(() => fetchDashboardStats(), 1000);
    } catch (error) {
      console.error('❌ Failed to submit test alert:', error);
    } finally {
      setTimeout(() => setIsSubmitting(false), 2000);
    }
  };

  // Calculate critical alerts count from alerts array
  const criticalCount = alerts.filter(a => a.severity === 'critical').length;

  return (
    <div className="space-y-6 animate-fadeIn">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Dashboard</h1>
          <p className="text-dark-400">Real-time security operations overview</p>
        </div>
        <button
          onClick={handleTestAlert}
          disabled={isSubmitting}
          className="px-4 py-2 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 rounded-lg font-semibold transition-all flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
        >
          {isSubmitting ? (
            <>
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
              Processing...
            </>
          ) : (
            <>
              <Play className="w-4 h-4" />
              Test Alert
            </>
          )}
        </button>
      </div>

      {/* Stats Grid - Display Real WebSocket Metrics + API Stats */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div className="glass rounded-xl p-6 card-hover">
          <div className="flex justify-between items-start mb-4">
            <div className="p-3 rounded-lg bg-blue-500/20">
              <Activity className="w-6 h-6 text-blue-400" />
            </div>
          </div>
          <div className="text-3xl font-bold mb-1">
            {dashboardStats?.total_alerts_today || metrics?.alerts_processed_today || 0}
          </div>
          <div className="text-sm text-dark-400">Total Alerts Today</div>
        </div>

        <div className="glass rounded-xl p-6 card-hover">
          <div className="flex justify-between items-start mb-4">
            <div className="p-3 rounded-lg bg-yellow-500/20">
              <Zap className="w-6 h-6 text-yellow-400" />
            </div>
          </div>
          <div className="text-3xl font-bold mb-1">
            {metrics?.alerts_in_progress || 0}
          </div>
          <div className="text-sm text-dark-400">In Progress</div>
        </div>

        <div className="glass rounded-xl p-6 card-hover">
          <div className="flex justify-between items-start mb-4">
            <div className="p-3 rounded-lg bg-green-500/20">
              <Clock className="w-6 h-6 text-green-400" />
            </div>
          </div>
          <div className="text-3xl font-bold mb-1">
            {dashboardStats?.processing_time_avg 
              ? `${dashboardStats.processing_time_avg.toFixed(1)}s` 
              : metrics?.average_processing_time 
              ? `${metrics.average_processing_time.toFixed(1)}s` 
              : '0.0s'}
          </div>
          <div className="text-sm text-dark-400">Avg Processing Time</div>
        </div>

        <div className="glass rounded-xl p-6 card-hover">
          <div className="flex justify-between items-start mb-4">
            <div className="p-3 rounded-lg bg-purple-500/20">
              <TrendingUp className="w-6 h-6 text-purple-400" />
            </div>
          </div>
          <div className="text-3xl font-bold mb-1">
            {metrics?.success_rate 
              ? `${(metrics.success_rate * 100).toFixed(1)}%` 
              : '0.0%'}
          </div>
          <div className="text-sm text-dark-400">Success Rate</div>
        </div>

        <div className="glass rounded-xl p-6 card-hover">
          <div className="flex justify-between items-start mb-4">
            <div className="p-3 rounded-lg bg-red-500/20">
              <AlertCircle className="w-6 h-6 text-red-400" />
            </div>
          </div>
          <div className="text-3xl font-bold mb-1 text-red-400">
            {dashboardStats?.high_priority_alerts || criticalCount || 0}
          </div>
          <div className="text-sm text-dark-400">High Priority</div>
        </div>
      </div>

      {/* System Health Indicator */}
      {metrics?.system_health !== undefined && (
        <div className={`glass rounded-xl p-4 border-l-4 ${
          metrics.system_health 
            ? 'border-green-500 bg-green-500/5' 
            : 'border-red-500 bg-red-500/5'
        }`}>
          <div className="flex items-center gap-3">
            <div className={`w-3 h-3 rounded-full animate-pulse ${
              metrics.system_health ? 'bg-green-500' : 'bg-red-500'
            }`}></div>
            <span className="font-semibold">
              System Health: {metrics.system_health ? 'Healthy' : 'Degraded'}
            </span>
          </div>
        </div>
      )}

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Alerts Feed - 2 columns */}
        <div className="lg:col-span-2 glass rounded-xl p-6">
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <AlertCircle className="w-5 h-5" />
            Live Alert Stream
          </h2>
          <div className="space-y-3 max-h-96 overflow-y-auto pr-2">
            {alerts.length === 0 ? (
              <div className="text-center py-12 text-dark-500">
                <Activity className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No alerts detected. System monitoring...</p>
              </div>
            ) : (
              alerts.slice(0, 10).map((alert) => (
                <div
                  key={alert.id}
                  className={`border-l-4 rounded-lg p-4 transition-all hover:translate-x-1 ${
                    alert.severity === 'critical' ? 'border-red-500 bg-red-500/10' :
                    alert.severity === 'high' ? 'border-orange-500 bg-orange-500/10' :
                    alert.severity === 'medium' ? 'border-yellow-500 bg-yellow-500/10' :
                    'border-blue-500 bg-blue-500/10'
                  }`}
                >
                  <div className="flex justify-between items-start mb-2">
                    <span className="font-mono text-sm text-blue-400 font-semibold">
                      {alert.id.substring(0, 8)}
                    </span>
                    <span className="text-xs text-dark-500">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-sm mb-3">{alert.description}</p>
                  <div className="flex gap-2 flex-wrap">
                    <span className="px-2 py-1 rounded text-xs font-semibold bg-blue-500/20 text-blue-400 uppercase">
                      {alert.status}
                    </span>
                    {alert.confidence && (
                      <span className="px-2 py-1 rounded text-xs font-semibold bg-green-500/20 text-green-400">
                        {alert.confidence}%
                      </span>
                    )}
                    <span className="px-2 py-1 rounded text-xs font-semibold bg-dark-700 uppercase">
                      {alert.severity}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Top Threat Indicators - 1 column */}
        <div className="glass rounded-xl p-6">
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Target className="w-5 h-5 text-red-400" />
            Top Threats
          </h2>
          <div className="space-y-3">
            {dashboardStats?.top_threat_indicators && dashboardStats.top_threat_indicators.length > 0 ? (
              dashboardStats.top_threat_indicators.map((threat, index) => (
                <div 
                  key={index}
                  className="bg-dark-800/50 rounded-lg p-4 border-l-4 border-red-500/50 hover:border-red-500 transition-all"
                >
                  <div className="flex justify-between items-center mb-2">
                    <span className="font-semibold text-sm capitalize">
                      {threat.indicator.replace(/_/g, ' ')}
                    </span>
                    <span className="px-2 py-1 bg-red-500/20 text-red-400 rounded text-xs font-bold">
                      {threat.count}
                    </span>
                  </div>
                  <div className="w-full bg-dark-700 rounded-full h-2 overflow-hidden">
                    <div 
                      className="bg-gradient-to-r from-red-500 to-orange-500 h-2 rounded-full transition-all"
                      style={{width: `${Math.min((threat.count / 20) * 100, 100)}%`}}
                    ></div>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-dark-500">
                <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p className="text-sm">No threat data available</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Agent Status - Display Real Agent Health */}
      <div className="glass rounded-xl p-6">
        <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
          <Activity className="w-5 h-5" />
          Agent Status
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {metrics?.agent_health && Object.entries(metrics.agent_health).map(([agentName, isHealthy]) => (
            <div 
              key={agentName} 
              className={`bg-dark-800/50 rounded-lg p-4 border-l-4 transition-all hover:bg-dark-800 ${
                isHealthy ? 'border-green-500' : 'border-red-500'
              }`}
            >
              <div className="flex justify-between items-center mb-2">
                <span className="font-semibold text-sm uppercase">
                  {agentName.replace('_instance', '').replace('_', ' ')}
                </span>
                <div className={`w-3 h-3 rounded-full ${
                  isHealthy ? 'bg-green-400' : 'bg-red-400'
                } animate-pulse shadow-lg ${
                  isHealthy ? 'shadow-green-400/50' : 'shadow-red-400/50'
                }`}></div>
              </div>
              <div className="text-xs text-dark-400">
                {isHealthy ? '✅ Operational' : '❌ Error'}
              </div>
            </div>
          ))}
        </div>
        
        {/* Show message if no agents */}
        {(!metrics?.agent_health || Object.keys(metrics.agent_health).length === 0) && (
          <div className="text-center py-8 text-dark-500">
            <Activity className="w-12 h-12 mx-auto mb-4 opacity-50" />
            <p>No agent data available</p>
          </div>
        )}
      </div>

      {/* Alerts by Status and Severity */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Alerts by Status */}
        {dashboardStats?.alerts_by_status && (
          <div className="glass rounded-xl p-6">
            <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
              <TrendingUp className="w-5 h-5" />
              Alerts by Status
            </h3>
            <div className="space-y-3">
              {Object.entries(dashboardStats.alerts_by_status).map(([status, count]) => (
                <div key={status}>
                  <div className="flex justify-between mb-2">
                    <span className="text-sm font-semibold capitalize">{status}</span>
                    <span className="text-sm font-bold">{count}</span>
                  </div>
                  <div className="w-full bg-dark-800 rounded-full h-2 overflow-hidden">
                    <div 
                      className={`h-2 rounded-full transition-all ${
                        status === 'closed' ? 'bg-green-500' :
                        status === 'new' ? 'bg-blue-500' :
                        status === 'in_progress' ? 'bg-yellow-500' :
                        'bg-gradient-to-r from-blue-500 to-purple-600'
                      }`}
                      style={{width: `${Math.min((count / Math.max(...Object.values(dashboardStats.alerts_by_status))) * 100, 100)}%`}}
                    ></div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Alerts by Severity */}
        {dashboardStats?.alerts_by_severity && (
          <div className="glass rounded-xl p-6">
            <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
              <AlertCircle className="w-5 h-5" />
              Alerts by Severity
            </h3>
            <div className="space-y-3">
              {Object.entries(dashboardStats.alerts_by_severity).map(([severity, count]) => (
                <div key={severity}>
                  <div className="flex justify-between mb-2">
                    <span className="text-sm font-semibold capitalize">{severity}</span>
                    <span className="text-sm font-bold">{count}</span>
                  </div>
                  <div className="w-full bg-dark-800 rounded-full h-2 overflow-hidden">
                    <div 
                      className={`h-2 rounded-full transition-all ${
                        severity === 'critical' ? 'bg-red-500' :
                        severity === 'high' ? 'bg-orange-500' :
                        severity === 'medium' ? 'bg-yellow-500' :
                        'bg-blue-500'
                      }`}
                      style={{width: `${Math.min((count / Math.max(...Object.values(dashboardStats.alerts_by_severity))) * 100, 100)}%`}}
                    ></div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Recent Escalations */}
      {dashboardStats?.recent_escalations && dashboardStats.recent_escalations.length > 0 && (
        <div className="glass rounded-xl p-6">
          <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5 text-orange-400" />
            Recent Escalations
          </h3>
          <div className="space-y-2">
            {dashboardStats.recent_escalations.map((escalation, index) => (
              <div 
                key={index}
                className="bg-orange-500/10 border-l-4 border-orange-500 rounded-lg p-3"
              >
                <p className="text-sm font-semibold">{escalation.title || escalation.description}</p>
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