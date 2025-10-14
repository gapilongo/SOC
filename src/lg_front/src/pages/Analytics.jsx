import React, { useState, useEffect } from 'react';
import { BarChart3, TrendingUp, PieChart as PieChartIcon, Activity } from 'lucide-react';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { dashboardAPI } from '../services/api';

const Analytics = () => {
  const [stats, setStats] = useState(null);
  const [timeRange, setTimeRange] = useState('24h');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAnalytics();
  }, [timeRange]);

  const fetchAnalytics = async () => {
    try {
      setLoading(true);
      const data = await dashboardAPI.getStats();
      setStats(data);
    } catch (error) {
      console.error('Failed to fetch analytics:', error);
    } finally {
      setLoading(false);
    }
  };

  // Generate trend data
  const trendData = Array.from({ length: 30 }, (_, i) => ({
    day: `Day ${i + 1}`,
    alerts: Math.floor(Math.random() * 50) + 10,
    resolved: Math.floor(Math.random() * 40) + 5,
    critical: Math.floor(Math.random() * 10)
  }));

  // Generate severity data
  const severityData = stats?.alerts_by_severity
    ? Object.entries(stats.alerts_by_severity).map(([name, value]) => ({ name, value }))
    : [
        { name: 'Critical', value: 15 },
        { name: 'High', value: 35 },
        { name: 'Medium', value: 45 },
        { name: 'Low', value: 80 }
      ];

  // Generate response time data
  const responseTimeData = Array.from({ length: 24 }, (_, i) => ({
    hour: `${i}:00`,
    avgTime: Math.floor(Math.random() * 100) + 50
  }));

  // Generate threat category data
  const threatCategoryData = [
    { name: 'Malware', value: 35, color: '#ef4444' },
    { name: 'Phishing', value: 28, color: '#f59e0b' },
    { name: 'Network', value: 22, color: '#3b82f6' },
    { name: 'Insider', value: 15, color: '#8b5cf6' }
  ];

  const SEVERITY_COLORS = ['#ef4444', '#fb923c', '#f59e0b', '#3b82f6'];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-dark-400">Loading analytics...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Analytics & Insights</h1>
          <p className="text-dark-400">Comprehensive security metrics and trends</p>
        </div>
        <select
          value={timeRange}
          onChange={(e) => setTimeRange(e.target.value)}
          className="px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="24h">Last 24 Hours</option>
          <option value="7d">Last 7 Days</option>
          <option value="30d">Last 30 Days</option>
          <option value="90d">Last 90 Days</option>
        </select>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="glass rounded-xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 bg-blue-500/20 rounded-lg">
              <Activity className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <p className="text-sm text-dark-400">Total Alerts</p>
              <p className="text-2xl font-bold">{stats?.total_alerts_today || 175}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <TrendingUp className="w-4 h-4 text-green-400" />
            <span className="text-green-400 font-semibold">+12.5%</span>
            <span className="text-dark-500">vs last period</span>
          </div>
        </div>

        <div className="glass rounded-xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 bg-purple-500/20 rounded-lg">
              <TrendingUp className="w-6 h-6 text-purple-400" />
            </div>
            <div>
              <p className="text-sm text-dark-400">Avg Response</p>
              <p className="text-2xl font-bold">2.3m</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <TrendingUp className="w-4 h-4 text-green-400" />
            <span className="text-green-400 font-semibold">-8.2%</span>
            <span className="text-dark-500">improvement</span>
          </div>
        </div>

        <div className="glass rounded-xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 bg-green-500/20 rounded-lg">
              <BarChart3 className="w-6 h-6 text-green-400" />
            </div>
            <div>
              <p className="text-sm text-dark-400">Resolution Rate</p>
              <p className="text-2xl font-bold">94.5%</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <TrendingUp className="w-4 h-4 text-green-400" />
            <span className="text-green-400 font-semibold">+3.1%</span>
            <span className="text-dark-500">efficiency gain</span>
          </div>
        </div>

        <div className="glass rounded-xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 bg-red-500/20 rounded-lg">
              <PieChartIcon className="w-6 h-6 text-red-400" />
            </div>
            <div>
              <p className="text-sm text-dark-400">Critical Events</p>
              <p className="text-2xl font-bold">{stats?.high_priority_alerts || 12}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="text-red-400 font-semibold">Active</span>
            <span className="text-dark-500">requires attention</span>
          </div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alert Trends */}
        <div className="glass rounded-xl p-6">
          <h2 className="text-xl font-bold mb-4">Alert Trends</h2>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={trendData}>
              <defs>
                <linearGradient id="alertGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="resolvedGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="day" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }} />
              <Legend />
              <Area type="monotone" dataKey="alerts" stroke="#3b82f6" fillOpacity={1} fill="url(#alertGradient)" />
              <Area type="monotone" dataKey="resolved" stroke="#10b981" fillOpacity={1} fill="url(#resolvedGradient)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Distribution */}
        <div className="glass rounded-xl p-6">
          <h2 className="text-xl font-bold mb-4">Severity Distribution</h2>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[index % SEVERITY_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Response Time Analysis */}
        <div className="glass rounded-xl p-6">
          <h2 className="text-xl font-bold mb-4">Response Time Analysis</h2>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={responseTimeData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="hour" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }} />
              <Line type="monotone" dataKey="avgTime" stroke="#8b5cf6" strokeWidth={2} dot={{ fill: '#8b5cf6' }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Threat Categories */}
        <div className="glass rounded-xl p-6">
          <h2 className="text-xl font-bold mb-4">Threat Categories</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={threatCategoryData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="name" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }} />
              <Bar dataKey="value" fill="#3b82f6" radius={[8, 8, 0, 0]}>
                {threatCategoryData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Performance Insights */}
      <div className="glass rounded-xl p-6">
        <h2 className="text-xl font-bold mb-4">Performance Insights</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-dark-800/50 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm text-dark-400">Detection Rate</span>
              <span className="text-2xl font-bold text-green-400">98.7%</span>
            </div>
            <div className="w-full bg-dark-700 rounded-full h-2">
              <div className="bg-gradient-to-r from-green-500 to-emerald-600 h-2 rounded-full" style={{ width: '98.7%' }}></div>
            </div>
          </div>

          <div className="bg-dark-800/50 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm text-dark-400">False Positive Rate</span>
              <span className="text-2xl font-bold text-blue-400">2.3%</span>
            </div>
            <div className="w-full bg-dark-700 rounded-full h-2">
              <div className="bg-gradient-to-r from-blue-500 to-blue-600 h-2 rounded-full" style={{ width: '2.3%' }}></div>
            </div>
          </div>

          <div className="bg-dark-800/50 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm text-dark-400">Agent Efficiency</span>
              <span className="text-2xl font-bold text-purple-400">96.2%</span>
            </div>
            <div className="w-full bg-dark-700 rounded-full h-2">
              <div className="bg-gradient-to-r from-purple-500 to-pink-600 h-2 rounded-full" style={{ width: '96.2%' }}></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Analytics;