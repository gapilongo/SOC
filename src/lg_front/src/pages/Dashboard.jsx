import React, { useState, useEffect } from 'react';
import { Activity, AlertCircle, Clock, TrendingUp, Zap, Play } from 'lucide-react';
import { useAlerts } from '../contexts/AlertContext';
import { dashboardAPI, agentsAPI } from '../services/api';

const Dashboard = () => {
  const { alerts, metrics, submitAlert } = useAlerts();
  const [dashboardStats, setDashboardStats] = useState(null);
  const [agents, setAgents] = useState([]);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [stats, agentsData] = await Promise.all([
        dashboardAPI.getStats(),
        agentsAPI.getStatus()
      ]);
      setDashboardStats(stats);
      setAgents(agentsData);
    } catch (error) {
      console.error('Failed to fetch:', error);
    }
  };

  const handleTestAlert = async () => {
    setIsSubmitting(true);
    try {
      await submitAlert({
        alert_data: {
          id: `test-${Date.now()}`,
          source: 'demo-siem',
          timestamp: new Date().toISOString(),
          severity: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)],
          description: 'Demo security event',
          raw_data: {
            event_type: 'test_event',
            process_name: 'demo.exe',
            user: 'SYSTEM',
            host: 'demo-server-01'
          }
        },
        priority: 'normal'
      });
    } catch (error) {
      console.error('Failed:', error);
    } finally {
      setTimeout(() => setIsSubmitting(false), 2000);
    }
  };

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
          className="px-4 py-2 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 rounded-lg font-semibold transition-all flex items-center gap-2 disabled:opacity-50"
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

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        {[
          { title: 'Total Alerts', value: metrics?.alerts_processed_today || 0, icon: Activity, color: 'blue' },
          { title: 'In Progress', value: metrics?.alerts_in_progress || 0, icon: Zap, color: 'yellow' },
          { title: 'Avg Response', value: `${metrics?.average_processing_time?.toFixed(1) || '0.0'}s`, icon: Clock, color: 'green' },
          { title: 'Success Rate', value: `${((metrics?.success_rate || 0) * 100).toFixed(1)}%`, icon: TrendingUp, color: 'purple' },
          { title: 'Critical', value: dashboardStats?.high_priority_alerts || 0, icon: AlertCircle, color: 'red' }
        ].map((stat, idx) => (
          <div key={idx} className="glass rounded-xl p-6 card-hover">
            <div className="flex justify-between items-start mb-4">
              <div className={`p-3 rounded-lg bg-${stat.color}-500/20`}>
                <stat.icon className="w-6 h-6" />
              </div>
            </div>
            <div className="text-3xl font-bold mb-1">{stat.value}</div>
            <div className="text-sm text-dark-400">{stat.title}</div>
          </div>
        ))}
      </div>

      {/* Alerts Feed */}
      <div className="glass rounded-xl p-6">
        <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
          <AlertCircle className="w-5 h-5" />
          Live Alert Stream
        </h2>
        <div className="space-y-3">
          {alerts.slice(0, 10).length === 0 ? (
            <div className="text-center py-12 text-dark-500">
              <Activity className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No alerts detected. System monitoring...</p>
            </div>
          ) : (
            alerts.slice(0, 10).map((alert) => (
              <div
                key={alert.id}
                className="border-l-4 border-yellow-500 bg-yellow-500/10 rounded-lg p-4"
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
                <div className="flex gap-2">
                  <span className="px-2 py-1 rounded text-xs font-semibold bg-blue-500/20 text-blue-400">
                    {alert.status}
                  </span>
                  <span className="px-2 py-1 rounded text-xs font-semibold bg-dark-700">
                    {alert.severity}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Agent Status */}
      <div className="glass rounded-xl p-6">
        <h2 className="text-xl font-bold mb-4">Agent Status</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {agents.map((agent) => (
            <div key={agent.agent_name} className="bg-dark-800/50 rounded-lg p-4">
              <div className="flex justify-between items-center mb-2">
                <span className="font-semibold text-sm">
                  {agent.agent_name.replace('_instance', '').toUpperCase()}
                </span>
                <div className={`w-3 h-3 rounded-full ${
                  agent.status === 'healthy' ? 'bg-green-400' : 'bg-red-400'
                } animate-pulse`}></div>
              </div>
              <div className="text-xs text-dark-400">
                Success: {(agent.success_rate * 100).toFixed(1)}%
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;