import React, { useState, useEffect } from 'react';
import { Cpu, Activity, CheckCircle, XCircle, RefreshCw } from 'lucide-react';
import { agentsAPI } from '../services/api';

const Agents = () => {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAgent, setSelectedAgent] = useState(null);

  useEffect(() => {
    fetchAgents();
  }, []);

  const fetchAgents = async () => {
    try {
      setLoading(true);
      const data = await agentsAPI.getStatus();
      setAgents(data);
    } catch (error) {
      console.error('Failed to fetch agents:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">AI Agents</h1>
          <p className="text-dark-400">Monitor and manage autonomous security agents</p>
        </div>
        <button
          onClick={fetchAgents}
          className="px-4 py-2 bg-dark-800 hover:bg-dark-700 rounded-lg transition-all flex items-center gap-2"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Agent Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="glass rounded-xl p-6">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-3 bg-blue-500/20 rounded-lg">
              <Cpu className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <p className="text-sm text-dark-400">Total Agents</p>
              <p className="text-2xl font-bold">{agents.length}</p>
            </div>
          </div>
        </div>

        <div className="glass rounded-xl p-6">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-3 bg-green-500/20 rounded-lg">
              <CheckCircle className="w-6 h-6 text-green-400" />
            </div>
            <div>
              <p className="text-sm text-dark-400">Healthy</p>
              <p className="text-2xl font-bold text-green-400">
                {agents.filter(a => a.status === 'healthy').length}
              </p>
            </div>
          </div>
        </div>

        <div className="glass rounded-xl p-6">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-3 bg-red-500/20 rounded-lg">
              <XCircle className="w-6 h-6 text-red-400" />
            </div>
            <div>
              <p className="text-sm text-dark-400">Unhealthy</p>
              <p className="text-2xl font-bold text-red-400">
                {agents.filter(a => a.status !== 'healthy').length}
              </p>
            </div>
          </div>
        </div>

        <div className="glass rounded-xl p-6">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-3 bg-purple-500/20 rounded-lg">
              <Activity className="w-6 h-6 text-purple-400" />
            </div>
            <div>
              <p className="text-sm text-dark-400">Avg Success</p>
              <p className="text-2xl font-bold text-purple-400">
                {agents.length > 0 
                  ? ((agents.reduce((acc, a) => acc + a.success_rate, 0) / agents.length) * 100).toFixed(1)
                  : 0}%
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Agents Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        {loading ? (
          <div className="col-span-full flex items-center justify-center py-12">
            <div className="text-center">
              <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
              <p className="text-dark-400">Loading agents...</p>
            </div>
          </div>
        ) : agents.length === 0 ? (
          <div className="col-span-full text-center py-12 text-dark-500">
            <Cpu className="w-16 h-16 mx-auto mb-4 opacity-50" />
            <p>No agents found</p>
          </div>
        ) : (
          agents.map((agent) => (
            <div
              key={agent.agent_name}
              className="glass rounded-xl p-6 card-hover cursor-pointer"
              onClick={() => setSelectedAgent(agent)}
            >
              {/* Agent Header */}
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className={`p-3 rounded-xl ${
                    agent.status === 'healthy' 
                      ? 'bg-green-500/20' 
                      : 'bg-red-500/20'
                  }`}>
                    <Cpu className={`w-6 h-6 ${
                      agent.status === 'healthy' 
                        ? 'text-green-400' 
                        : 'text-red-400'
                    }`} />
                  </div>
                  <div>
                    <h3 className="font-bold text-lg">
                      {agent.agent_name.replace('_instance', '').replace('_', ' ').toUpperCase()}
                    </h3>
                    <p className="text-xs text-dark-400">AI Security Agent</p>
                  </div>
                </div>
                <div className={`w-3 h-3 rounded-full animate-pulse ${
                  agent.status === 'healthy' 
                    ? 'bg-green-400' 
                    : 'bg-red-400'
                }`}></div>
              </div>

              {/* Agent Stats */}
              <div className="space-y-3">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-dark-400">Status</span>
                  <span className={`font-semibold ${
                    agent.status === 'healthy' 
                      ? 'text-green-400' 
                      : 'text-red-400'
                  }`}>
                    {agent.status}
                  </span>
                </div>

                <div className="flex items-center justify-between text-sm">
                  <span className="text-dark-400">Success Rate</span>
                  <span className="font-semibold text-blue-400">
                    {(agent.success_rate * 100).toFixed(1)}%
                  </span>
                </div>

                <div className="flex items-center justify-between text-sm">
                  <span className="text-dark-400">Avg Execution</span>
                  <span className="font-semibold text-purple-400">
                    {agent.average_execution_time.toFixed(2)}s
                  </span>
                </div>

                {agent.error_count > 0 && (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-dark-400">Errors</span>
                    <span className="font-semibold text-red-400">
                      {agent.error_count}
                    </span>
                  </div>
                )}
              </div>

              {/* Performance Bar */}
              <div className="mt-4 pt-4 border-t border-dark-700">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-dark-400">Performance</span>
                  <span className="text-xs font-semibold text-white">
                    {(agent.success_rate * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="w-full bg-dark-700 rounded-full h-2">
                  <div
                    className="bg-gradient-to-r from-blue-500 to-purple-600 h-2 rounded-full transition-all"
                    style={{ width: `${agent.success_rate * 100}%` }}
                  ></div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Agent Detail Modal */}
      {selectedAgent && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="glass rounded-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="p-6 border-b border-dark-700">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className={`p-4 rounded-xl ${
                    selectedAgent.status === 'healthy' 
                      ? 'bg-green-500/20' 
                      : 'bg-red-500/20'
                  }`}>
                    <Cpu className={`w-8 h-8 ${
                      selectedAgent.status === 'healthy' 
                        ? 'text-green-400' 
                        : 'text-red-400'
                    }`} />
                  </div>
                  <div>
                    <h3 className="text-2xl font-bold">
                      {selectedAgent.agent_name.replace('_instance', '').replace('_', ' ').toUpperCase()}
                    </h3>
                    <p className="text-dark-400">Detailed Agent Information</p>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedAgent(null)}
                  className="p-2 hover:bg-dark-700 rounded-lg transition-colors text-2xl"
                >
                  ×
                </button>
              </div>
            </div>

            {/* Modal Content */}
            <div className="p-6 space-y-6">
              {/* Metrics Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-dark-800/50 rounded-lg p-4">
                  <p className="text-xs text-dark-400 mb-1">Status</p>
                  <p className={`text-lg font-bold ${
                    selectedAgent.status === 'healthy' 
                      ? 'text-green-400' 
                      : 'text-red-400'
                  }`}>
                    {selectedAgent.status}
                  </p>
                </div>

                <div className="bg-dark-800/50 rounded-lg p-4">
                  <p className="text-xs text-dark-400 mb-1">Success Rate</p>
                  <p className="text-lg font-bold text-blue-400">
                    {(selectedAgent.success_rate * 100).toFixed(1)}%
                  </p>
                </div>

                <div className="bg-dark-800/50 rounded-lg p-4">
                  <p className="text-xs text-dark-400 mb-1">Avg Time</p>
                  <p className="text-lg font-bold text-purple-400">
                    {selectedAgent.average_execution_time.toFixed(2)}s
                  </p>
                </div>

                <div className="bg-dark-800/50 rounded-lg p-4">
                  <p className="text-xs text-dark-400 mb-1">Errors</p>
                  <p className="text-lg font-bold text-red-400">
                    {selectedAgent.error_count}
                  </p>
                </div>
              </div>

              {/* Agent Description */}
              <div className="bg-dark-800/50 rounded-xl p-6">
                <h4 className="text-lg font-bold mb-3">Agent Description</h4>
                <p className="text-dark-300 leading-relaxed">
                  {selectedAgent.agent_name.includes('triage') && 
                    'The Triage Agent performs initial alert classification and prioritization using machine learning models to determine severity and confidence scores.'}
                  {selectedAgent.agent_name.includes('correlation') && 
                    'The Correlation Agent identifies relationships between security events, detects patterns, and links related incidents for comprehensive threat analysis.'}
                  {selectedAgent.agent_name.includes('analysis') && 
                    'The Analysis Agent conducts deep investigation of security events using ReAct reasoning, executing tools and generating actionable insights.'}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Agents;