import React, { useState, useEffect } from 'react';
import {
  Clock, User, CheckCircle, AlertTriangle,
  TrendingUp, Users, X
} from 'lucide-react';
import { escalationsAPI, alertsAPI } from '../services/api';

const Escalations = () => {
  const [escalations, setEscalations] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedEscalation, setSelectedEscalation] = useState(null);
  const [filterLevel, setFilterLevel] = useState('all');
  const [showFeedbackModal, setShowFeedbackModal] = useState(false);
  const [alertDetails, setAlertDetails] = useState(null);

  // Feedback form state
  const [feedback, setFeedback] = useState({
    analyst_username: 'analyst',
    decision: '',
    confidence: 5,
    notes: '',
    actions_taken: [],
    actions_recommended: [],
    triage_correct: null,
    correlation_helpful: null,
    analysis_accurate: null
  });

  useEffect(() => {
    fetchEscalations();
    fetchStats();

    // Auto-refresh every 30 seconds
    const interval = setInterval(() => {
      fetchEscalations();
      fetchStats();
    }, 30000);

    return () => clearInterval(interval);
  }, [filterLevel]);

  const fetchEscalations = async () => {
    try {
      const params = filterLevel !== 'all' ? { level: filterLevel } : {};
      const data = await escalationsAPI.getEscalations(params);
      console.log('📊 Fetched escalations:', data);

      // Parse alert_summary to extract severity and confidence
      const enrichedEscalations = (data.escalations || []).map(esc => {
        const summary = esc.alert_summary || '';

        // Extract severity: "Severity: critical" or "Severity: high"
        const severityMatch = summary.match(/Severity:\s*(\w+)/i);
        const severity = severityMatch ? severityMatch[1] : null;

        // Extract confidence: "Confidence: 84.0%" or "Confidence: 40.0%"
        const confidenceMatch = summary.match(/Confidence:\s*(\d+\.?\d*)%/i);
        const confidence_score = confidenceMatch ? Math.round(parseFloat(confidenceMatch[1])) : null;

        return {
          ...esc,
          severity,
          confidence_score
        };
      });

      console.log('✨ Enriched escalations:', enrichedEscalations);
      setEscalations(enrichedEscalations);
    } catch (error) {
      console.error('Failed to fetch escalations:', error);
      setEscalations([]);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      console.log('📊 Fetching escalation stats...');
      const statsData = await escalationsAPI.getStats();
      console.log('✅ Stats received:', statsData);
      setStats(statsData);
    } catch (error) {
      console.error('❌ Failed to fetch escalation stats:', error);
    }
  };

  const handleClaimEscalation = async (escalationId) => {
    try {
      console.log('🔵 Claiming escalation:', escalationId);
      await escalationsAPI.assignEscalation(escalationId, 'analyst');
      console.log('✅ Escalation claimed, refreshing data...');
      await fetchEscalations();
      await fetchStats();  // Refresh stats to update "In Review" counter
      console.log('✅ Data refreshed');
    } catch (error) {
      console.error('❌ Failed to claim escalation:', error);
    }
  };

  const handleViewDetails = async (escalation) => {
    setSelectedEscalation(escalation);

    // Fetch full alert details
    try {
      const details = await alertsAPI.getAlertStatus(escalation.alert_id);
      setAlertDetails(details);
    } catch (error) {
      console.error('Failed to fetch alert details:', error);
    }

    setShowFeedbackModal(true);
  };

  const handleSubmitFeedback = async () => {
    if (!selectedEscalation || !feedback.decision || !feedback.notes) {
      alert('Please fill in decision and notes');
      return;
    }

    try {
      await escalationsAPI.submitFeedback(selectedEscalation.escalation_id, feedback);
      setShowFeedbackModal(false);
      setSelectedEscalation(null);
      setAlertDetails(null);
      setFeedback({
        analyst_username: 'analyst',
        decision: '',
        confidence: 5,
        notes: '',
        actions_taken: [],
        actions_recommended: [],
        triage_correct: null,
        correlation_helpful: null,
        analysis_accurate: null
      });
      fetchEscalations();
      fetchStats();  // Refresh stats after feedback submission
    } catch (error) {
      console.error('Failed to submit feedback:', error);
      alert('Failed to submit feedback: ' + error.message);
    }
  };

  const getPriorityColor = (priority) => {
    const p = parseInt(priority);
    switch (p) {
      case 1:
        return 'bg-red-500';
      case 2:
        return 'bg-orange-500';
      case 3:
        return 'bg-yellow-500';
      case 4:
        return 'bg-blue-500';
      default:
        return 'bg-gray-500';
    }
  };

  const getPriorityTextColor = (priority) => {
    const p = parseInt(priority);
    switch (p) {
      case 1:
        return 'text-red-400';
      case 2:
        return 'text-orange-400';
      case 3:
        return 'text-yellow-400';
      case 4:
        return 'text-blue-400';
      default:
        return 'text-gray-400';
    }
  };

  const getPriorityLabel = (priority) => {
    return `P${priority}`;
  };

  const getReasonLabel = (reason) => {
    if (!reason) return 'Requires Review';

    const labels = {
      'grey_zone': 'Grey Zone Confidence - Alert confidence between 30-70% requires analyst judgment',
      'high_risk': 'High Risk Detected - Multiple threat indicators found',
      'complex_pattern': 'Complex Attack Pattern - Sophisticated techniques detected',
      'needs_context': 'Requires Context - Additional information needed for decision',
      'unusual_activity': 'Unusual Activity - Behavior deviates from baseline'
    };
    return labels[reason] || reason.replace(/_/g, ' ').charAt(0).toUpperCase() + reason.replace(/_/g, ' ').slice(1);
  };

  const formatTimeAgo = (timestamp) => {
    if (!timestamp) return 'Just now';

    const now = new Date();
    const time = new Date(timestamp);

    // Check if valid date
    if (isNaN(time.getTime())) return 'Just now';

    const diff = Math.floor((now - time) / 1000); // seconds

    if (diff < 0) return 'Just now'; // Future date
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  };

  // Group escalations by priority
  const groupedEscalations = escalations.reduce((acc, esc) => {
    const priority = esc.priority || 3;
    if (!acc[priority]) acc[priority] = [];
    acc[priority].push(esc);
    return acc;
  }, {});

  return (
    <div className="space-y-4 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Escalations Queue</h1>
          <p className="text-sm text-dark-400">Alerts requiring human review and decision</p>
        </div>
      </div>

      {/* Statistics Banner */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <div className="glass rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="w-4 h-4 text-orange-400" />
              <div className="text-xl font-bold">{stats.total_pending || 0}</div>
            </div>
            <div className="text-xs text-dark-400">Pending</div>
          </div>

          <div className="glass rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <Users className="w-4 h-4 text-blue-400" />
              <div className="text-xl font-bold">{stats.total_in_review || 0}</div>
            </div>
            <div className="text-xs text-dark-400">In Review</div>
          </div>

          <div className="glass rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <CheckCircle className="w-4 h-4 text-green-400" />
              <div className="text-xl font-bold">{stats.resolved_today || 0}</div>
            </div>
            <div className="text-xs text-dark-400">Resolved Today</div>
          </div>

          <div className="glass rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <Clock className="w-4 h-4 text-purple-400" />
              <div className="text-xl font-bold">
                {stats.avg_response_time ? `${stats.avg_response_time.toFixed(1)}m` : 'N/A'}
              </div>
            </div>
            <div className="text-xs text-dark-400">Avg Response</div>
          </div>

          <div className="glass rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <div className="text-xl font-bold">
                {stats.accuracy_rate ? `${(stats.accuracy_rate * 100).toFixed(0)}%` : 'N/A'}
              </div>
            </div>
            <div className="text-xs text-dark-400">Accuracy</div>
          </div>
        </div>
      )}

      {/* Filter Tabs */}
      <div className="flex gap-2">
        {['all', 'L1', 'L2', 'L3'].map((level) => (
          <button
            key={level}
            onClick={() => setFilterLevel(level)}
            className={`px-4 py-2 rounded-lg font-semibold transition-all ${
              filterLevel === level
                ? 'bg-blue-500 text-white'
                : 'bg-dark-800 text-dark-400 hover:bg-dark-700'
            }`}
          >
            {level === 'all' ? 'All Levels' : level}
          </button>
        ))}
      </div>

      {/* Priority Queue View */}
      {loading ? (
        <div className="flex items-center justify-center py-12">
          <div className="text-dark-400">Loading escalations...</div>
        </div>
      ) : escalations.length === 0 ? (
        <div className="glass rounded-lg p-12 text-center">
          <CheckCircle className="w-16 h-16 mx-auto mb-4 text-green-400 opacity-50" />
          <h3 className="text-xl font-bold mb-2">All Clear!</h3>
          <p className="text-dark-400">No escalations pending review</p>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Display all priority levels that have escalations */}
          {Object.keys(groupedEscalations).sort((a, b) => a - b).map((priority) => {
            const priorityEscalations = groupedEscalations[priority] || [];
            if (priorityEscalations.length === 0) return null;

            return (
              <div key={priority} className="glass rounded-xl p-5">
                <div className="flex items-center gap-3 mb-4">
                  <div className={`w-3 h-3 rounded-full ${getPriorityColor(priority)} animate-pulse`}></div>
                  <h3 className={`text-lg font-bold ${getPriorityTextColor(priority)}`}>
                    Priority {priority} - {priorityEscalations.length} {priorityEscalations.length === 1 ? 'Alert' : 'Alerts'}
                  </h3>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                  {priorityEscalations.map((escalation) => (
                    <div
                      key={escalation.escalation_id}
                      className="bg-dark-800/50 rounded-lg p-4 border border-dark-700 hover:border-blue-500/50 transition-all"
                    >
                      {/* Card Header */}
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className={`px-2 py-1 rounded text-xs font-bold ${getPriorityColor(priority)} text-white`}>
                              {getPriorityLabel(escalation.priority)}
                            </span>
                            <span className="font-mono text-xs text-blue-400">
                              {escalation.alert_id.substring(0, 8)}...
                            </span>
                          </div>
                          <div className="text-xs text-dark-400">
                            {formatTimeAgo(escalation.created_at)}
                          </div>
                        </div>
                        {escalation.assigned_to ? (
                          <div className="flex items-center gap-1 px-2 py-1 bg-blue-500/20 rounded text-xs">
                            <User className="w-3 h-3" />
                            <span>{escalation.assigned_to}</span>
                          </div>
                        ) : (
                          <div className="px-2 py-1 bg-dark-700 rounded text-xs text-dark-400">
                            Unassigned
                          </div>
                        )}
                      </div>

                      {/* Reason */}
                      <div className="mb-3">
                        <div className="text-xs text-dark-400 mb-1">Escalation Reason:</div>
                        <div className="text-sm font-semibold text-orange-400">
                          {getReasonLabel(escalation.reason)}
                        </div>
                      </div>

                      {/* Key Info */}
                      <div className="space-y-2 mb-3">
                        <div className="flex justify-between text-xs">
                          <span className="text-dark-400">Severity:</span>
                          <span className={`font-semibold capitalize ${
                            !escalation.severity || escalation.severity === 'unknown' ? 'text-dark-500' : ''
                          }`}>
                            {escalation.severity && escalation.severity !== 'unknown' ? escalation.severity : 'Pending'}
                          </span>
                        </div>
                        <div className="flex justify-between text-xs">
                          <span className="text-dark-400">Confidence:</span>
                          <span className={`font-semibold ${
                            !escalation.confidence_score || escalation.confidence_score === 0 ? 'text-dark-500' : ''
                          }`}>
                            {escalation.confidence_score && escalation.confidence_score > 0 ? `${escalation.confidence_score}%` : 'Analyzing...'}
                          </span>
                        </div>
                        <div className="flex justify-between text-xs">
                          <span className="text-dark-400">Level:</span>
                          <span className="font-semibold">{escalation.level || 'L1'}</span>
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="flex gap-2">
                        {!escalation.assigned_to && (
                          <button
                            onClick={() => handleClaimEscalation(escalation.escalation_id)}
                            className="flex-1 px-3 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg text-xs font-semibold transition-all"
                          >
                            Claim
                          </button>
                        )}
                        <button
                          onClick={() => handleViewDetails(escalation)}
                          className="flex-1 px-3 py-2 bg-dark-700 hover:bg-dark-600 rounded-lg text-xs font-semibold transition-all"
                        >
                          Review
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Feedback Modal */}
      {showFeedbackModal && selectedEscalation && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-2xl shadow-2xl border border-dark-700 max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-6 border-b border-dark-700">
              <div>
                <h3 className="text-2xl font-bold mb-1">Escalation Review</h3>
                <p className="font-mono text-sm text-blue-400">{selectedEscalation.alert_id}</p>
              </div>
              <button
                onClick={() => {
                  setShowFeedbackModal(false);
                  setSelectedEscalation(null);
                  setAlertDetails(null);
                }}
                className="text-2xl hover:bg-dark-700 rounded-lg p-2 transition-all"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto p-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Left: Alert Info */}
                <div className="space-y-4">
                  <div>
                    <h4 className="text-sm font-bold text-dark-400 mb-3">ALERT DETAILS</h4>
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span className="text-sm text-dark-400">Priority:</span>
                        <span className={`text-sm font-bold ${getPriorityTextColor(selectedEscalation.priority)}`}>
                          {getPriorityLabel(selectedEscalation.priority)}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-dark-400">Severity:</span>
                        <span className={`text-sm font-semibold capitalize ${
                          !selectedEscalation.severity || selectedEscalation.severity === 'unknown' ? 'text-dark-500' : ''
                        }`}>
                          {selectedEscalation.severity && selectedEscalation.severity !== 'unknown' ? selectedEscalation.severity : 'Pending'}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-dark-400">Confidence:</span>
                        <span className={`text-sm font-semibold ${
                          !selectedEscalation.confidence_score || selectedEscalation.confidence_score === 0 ? 'text-dark-500' : ''
                        }`}>
                          {selectedEscalation.confidence_score && selectedEscalation.confidence_score > 0 ? `${selectedEscalation.confidence_score}%` : 'Analyzing...'}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-dark-400">Escalated:</span>
                        <span className="text-sm font-semibold">{formatTimeAgo(selectedEscalation.created_at)}</span>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-sm font-bold text-dark-400 mb-2">WHY THIS WAS ESCALATED</h4>
                    <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-3">
                      <p className="text-sm text-orange-400 leading-relaxed">
                        {getReasonLabel(selectedEscalation.reason)}
                      </p>
                    </div>
                  </div>

                  {/* AI Analysis Summary */}
                  {selectedEscalation.alert_summary && (
                    <div>
                      <h4 className="text-sm font-bold text-dark-400 mb-2">AI ANALYSIS SUMMARY</h4>
                      <div className="bg-dark-800/50 rounded-lg p-3 max-h-64 overflow-y-auto space-y-3">
                        {/* Extract reasoning section */}
                        {(() => {
                          const summary = selectedEscalation.alert_summary;

                          // Extract Analysis Reasoning
                          const reasoningMatch = summary.match(/🤔 ANALYSIS REASONING:\n([\s\S]*?)(?=\n\n💡|$)/);
                          const reasoning = reasoningMatch ? reasoningMatch[1].trim() : null;

                          // Extract Recommended Actions
                          const actionsMatch = summary.match(/💡 RECOMMENDED ACTIONS:\n([\s\S]*?)$/);
                          const actions = actionsMatch ? actionsMatch[1].trim().split(/\n\d+\.\s+/).filter(Boolean) : [];

                          // Extract Triage info
                          const confidenceMatch = summary.match(/Confidence:\s*(\d+\.?\d*)%/);
                          const threatScoreMatch = summary.match(/Threat Score:\s*(\d+\.?\d*)/);
                          const llmMatch = summary.match(/LLM Assessment:\s*(\w+)/);

                          return (
                            <>
                              {/* Agent Assessment Timeline */}
                              <div>
                                <div className="text-xs font-bold text-blue-400 mb-2">📊 Agent Assessment Timeline</div>
                                <div className="space-y-2">
                                  {/* Triage Agent */}
                                  {confidenceMatch && (
                                    <div className="text-xs text-dark-300">
                                      <div className="font-semibold text-yellow-400">🎯 Triage Agent</div>
                                      <div className="pl-3 mt-1 space-y-0.5">
                                        <div>├─ Confidence: <span className="text-yellow-400 font-semibold">{confidenceMatch[1]}%</span></div>
                                        {llmMatch && (
                                          <div>├─ LLM Assessment: <span className="text-purple-400 capitalize">{llmMatch[1].replace(/_/g, ' ')}</span></div>
                                        )}
                                        {(() => {
                                          const threatScore = threatScoreMatch ? parseFloat(threatScoreMatch[1]) : 0;
                                          const llmAssessment = llmMatch ? llmMatch[1] : null;

                                          const preliminaryScoreMap = {
                                            'confirmed_threat': 90,
                                            'likely_threat': 70,
                                            'possible_threat': 50,
                                            'suspicious': 50,
                                            'unlikely_threat': 30,
                                            'benign': 10
                                          };

                                          const preliminaryScore = llmAssessment ? preliminaryScoreMap[llmAssessment] || 0 : 0;
                                          const displayScore = threatScore > 0 ? threatScore : preliminaryScore;
                                          const isPreliminary = threatScore === 0 && preliminaryScore > 0;

                                          if (displayScore > 0) {
                                            return (
                                              <div>
                                                └─ {isPreliminary ? 'Preliminary Threat' : 'Threat Score'}:
                                                <span className={`font-semibold ml-1 ${
                                                  displayScore >= 70 ? 'text-red-400' :
                                                  displayScore >= 40 ? 'text-orange-400' :
                                                  'text-yellow-400'
                                                }`}>
                                                  {displayScore}%
                                                </span>
                                                {isPreliminary && (
                                                  <span className="text-xs text-dark-500 ml-1">(LLM)</span>
                                                )}
                                              </div>
                                            );
                                          }
                                          return <div>└─ No threat score</div>;
                                        })()}
                                      </div>
                                    </div>
                                  )}

                                  {/* Escalation Status */}
                                  <div className="text-xs text-dark-300">
                                    <div className="font-semibold text-orange-400">👤 Human Review</div>
                                    <div className="pl-3 mt-1">
                                      <div>└─ Escalated for L{selectedEscalation.level || 1} analyst review</div>
                                    </div>
                                  </div>
                                </div>
                              </div>

                              {/* Analysis Reasoning */}
                              {reasoning && (
                                <div>
                                  <div className="text-xs font-bold text-green-400 mb-1">🔍 Why This Alert Matters</div>
                                  <p className="text-xs text-dark-300 leading-relaxed">
                                    {reasoning}
                                  </p>
                                </div>
                              )}

                              {/* Recommended Actions */}
                              {actions.length > 0 && (
                                <div>
                                  <div className="text-xs font-bold text-orange-400 mb-1">💡 Recommended Actions</div>
                                  <ol className="text-xs text-dark-300 space-y-1 list-decimal list-inside">
                                    {actions.slice(0, 5).map((action, idx) => (
                                      <li key={idx} className="leading-relaxed">{action}</li>
                                    ))}
                                  </ol>
                                </div>
                              )}
                            </>
                          );
                        })()}
                      </div>
                    </div>
                  )}
                </div>

                {/* Right: Feedback Form */}
                <div className="space-y-4">
                  <h4 className="text-sm font-bold text-dark-400 mb-3">YOUR DECISION</h4>

                  {/* Decision Buttons */}
                  <div>
                    <label className="text-sm text-dark-400 block mb-2">Verdict *</label>
                    <div className="grid grid-cols-3 gap-2">
                      {['true_positive', 'false_positive', 'needs_investigation'].map((decision) => (
                        <button
                          key={decision}
                          onClick={() => setFeedback({ ...feedback, decision })}
                          className={`px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
                            feedback.decision === decision
                              ? decision === 'true_positive'
                                ? 'bg-red-500 text-white'
                                : decision === 'false_positive'
                                ? 'bg-green-500 text-white'
                                : 'bg-yellow-500 text-white'
                              : 'bg-dark-800 text-dark-400 hover:bg-dark-700'
                          }`}
                        >
                          {decision.split('_').map(w => w[0].toUpperCase() + w.slice(1)).join(' ')}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Confidence Slider */}
                  <div>
                    <label className="text-sm text-dark-400 block mb-2">Confidence (1-10)</label>
                    <input
                      type="range"
                      min="1"
                      max="10"
                      value={feedback.confidence}
                      onChange={(e) => setFeedback({ ...feedback, confidence: parseInt(e.target.value) })}
                      className="w-full"
                    />
                    <div className="flex justify-between text-xs text-dark-400 mt-1">
                      <span>Low</span>
                      <span className="font-bold text-white">{feedback.confidence}</span>
                      <span>High</span>
                    </div>
                  </div>

                  {/* Notes */}
                  <div>
                    <label className="text-sm text-dark-400 block mb-2">Notes *</label>
                    <textarea
                      value={feedback.notes}
                      onChange={(e) => setFeedback({ ...feedback, notes: e.target.value })}
                      placeholder="Explain your decision..."
                      className="w-full bg-dark-800 border border-dark-700 rounded-lg p-3 text-sm resize-none focus:border-blue-500 outline-none"
                      rows="4"
                    />
                  </div>

                  {/* AI Feedback */}
                  <div>
                    <label className="text-sm text-dark-400 block mb-2">AI Analysis Feedback</label>
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          id="triage_correct"
                          checked={feedback.triage_correct === true}
                          onChange={(e) => setFeedback({ ...feedback, triage_correct: e.target.checked ? true : null })}
                          className="rounded"
                        />
                        <label htmlFor="triage_correct" className="text-xs">Triage was correct</label>
                      </div>
                      <div className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          id="correlation_helpful"
                          checked={feedback.correlation_helpful === true}
                          onChange={(e) => setFeedback({ ...feedback, correlation_helpful: e.target.checked ? true : null })}
                          className="rounded"
                        />
                        <label htmlFor="correlation_helpful" className="text-xs">Correlation was helpful</label>
                      </div>
                      <div className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          id="analysis_accurate"
                          checked={feedback.analysis_accurate === true}
                          onChange={(e) => setFeedback({ ...feedback, analysis_accurate: e.target.checked ? true : null })}
                          className="rounded"
                        />
                        <label htmlFor="analysis_accurate" className="text-xs">Analysis was accurate</label>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-end gap-3 p-6 border-t border-dark-700">
              <button
                onClick={() => {
                  setShowFeedbackModal(false);
                  setSelectedEscalation(null);
                  setAlertDetails(null);
                }}
                className="px-4 py-2 bg-dark-700 hover:bg-dark-600 rounded-lg font-semibold transition-all"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmitFeedback}
                className="px-4 py-2 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 rounded-lg font-semibold transition-all"
              >
                Submit Feedback
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Escalations;
