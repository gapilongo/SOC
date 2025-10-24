import React, { useState, useMemo, useEffect } from 'react';
import {
  AlertCircle, Search, Filter, Download, X, Check,
  ChevronLeft, ChevronRight, Eye, Copy, FileJson, FileText,
  Activity, ShieldCheck, GitBranch, Brain, Users, Zap,
  ArrowUp, ArrowDown, ArrowUpDown
} from 'lucide-react';
import { useAlerts } from '../contexts/AlertContext';
import { alertsAPI } from '../services/api';

const Alerts = () => {
  const { alerts } = useAlerts();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedAlerts, setSelectedAlerts] = useState(new Set());
  const [showFilters, setShowFilters] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [activeTab, setActiveTab] = useState('overview');
  const [alertNotes, setAlertNotes] = useState({});
  const [newNote, setNewNote] = useState('');
  const [alertDetails, setAlertDetails] = useState(null);
  const [loadingDetails, setLoadingDetails] = useState(false);

  // Filter states
  const [filters, setFilters] = useState({
    severity: [],
    status: [],
    timeRange: 'all'
  });

  // Fetch alert details when modal opens
  useEffect(() => {
    const fetchAlertDetails = async () => {
      if (selectedAlert) {
        setLoadingDetails(true);
        try {
          const details = await alertsAPI.getAlertStatus(selectedAlert.alert_id || selectedAlert.id);
          setAlertDetails(details);
        } catch (error) {
          console.error('Failed to fetch alert details:', error);
          setAlertDetails(null);
        } finally {
          setLoadingDetails(false);
        }
      }
    };

    fetchAlertDetails();
  }, [selectedAlert]);

  // Parse processing notes into timeline events
  const parseTimeline = (processingNotes) => {
    if (!processingNotes || processingNotes.length === 0) {
      return [];
    }

    // Deduplicate processing notes (sometimes workflow runs twice)
    const uniqueNotes = [];
    const seenNotes = new Set();

    for (const note of processingNotes) {
      if (!seenNotes.has(note)) {
        uniqueNotes.push(note);
        seenNotes.add(note);
      }
    }

    const events = [];

    uniqueNotes.forEach((note, index) => {
      let event = {
        id: index,
        text: note,
        icon: Activity,
        color: 'blue'
      };

      // Workflow started
      if (note.includes('workflow started')) {
        event.title = 'Workflow Started';
        event.description = 'Multi-agent orchestration initiated';
        event.icon = Zap;
        event.color = 'purple';
      }
      // Ingestion
      else if (note.toLowerCase().includes('ingestion')) {
        event.title = 'Ingestion Agent';
        const sourceMatch = note.match(/source=([^,)]+)/);
        event.description = sourceMatch ? `Alert ingested from ${sourceMatch[1]}` : 'Alert data collected and normalized';
        event.icon = Download;
        event.color = 'blue';
      }
      // Triage
      else if (note.toLowerCase().includes('triage')) {
        event.title = 'Triage Agent';
        const confMatch = note.match(/confidence=(\d+)%/);
        const fpMatch = note.match(/FP=(\d+)/);
        const tpMatch = note.match(/TP=(\d+)/);
        event.description = `Risk assessment: ${confMatch ? confMatch[1] + '% confidence' : 'analyzed'}${fpMatch && tpMatch ? `, ${fpMatch[1]} false positive indicators, ${tpMatch[1]} threat indicators` : ''}`;
        event.icon = ShieldCheck;
        event.color = 'yellow';
      }
      // Correlation
      else if (note.toLowerCase().includes('correlation')) {
        event.title = 'Correlation Agent';
        const corrMatch = note.match(/found (\d+) correlations/);
        const scoreMatch = note.match(/score: (\d+)%/);
        event.description = corrMatch ? `Found ${corrMatch[1]} related alerts${scoreMatch ? ` (${scoreMatch[1]}% correlation score)` : ''}` : 'Analyzed relationships with historical alerts';
        event.icon = GitBranch;
        event.color = 'cyan';
      }
      // Analysis
      else if (note.toLowerCase().includes('analysis')) {
        event.title = 'Analysis Agent';
        const threatMatch = note.match(/threat_score=(\d+)%/);
        const stepsMatch = note.match(/reasoning_steps=(\d+)/);
        event.description = `Deep threat analysis${threatMatch ? `: ${threatMatch[1]}% threat score` : ''}${stepsMatch ? `, ${stepsMatch[1]} reasoning steps` : ''}`;
        event.icon = Brain;
        event.color = 'green';
      }
      // Human loop / Escalation
      else if (note.toLowerCase().includes('escalat')) {
        event.title = 'Human Review';
        const priorityMatch = note.match(/Priority: (\d+)/);
        const reasonMatch = note.match(/Reason: ([^)]+)/);
        event.description = `Escalated for analyst review${priorityMatch ? ` (Priority ${priorityMatch[1]})` : ''}${reasonMatch ? `: ${reasonMatch[1].replace(/_/g, ' ')}` : ''}`;
        event.icon = Users;
        event.color = 'orange';
      }
      // Response
      else if (note.toLowerCase().includes('response')) {
        event.title = 'Response Agent';
        event.description = 'Automated response actions executed';
        event.icon = Activity;
        event.color = 'red';
      }
      // Errors
      else if (note.toLowerCase().includes('error') || note.toLowerCase().includes('failed')) {
        event.title = 'Error Occurred';
        event.description = note;
        event.icon = AlertCircle;
        event.color = 'red';
      }
      // Closed
      else if (note.toLowerCase().includes('closed') || note.toLowerCase().includes('complete')) {
        event.title = 'Alert Closed';
        event.description = note;
        event.icon = Check;
        event.color = 'green';
      }
      // Generic
      else {
        event.title = 'Processing Step';
        event.description = note;
      }

      events.push(event);
    });

    return events;
  };

  // Sorting state
  const [sortBy, setSortBy] = useState('timestamp');
  const [sortOrder, setSortOrder] = useState('desc'); // 'asc' or 'desc'

  // Toggle sort
  const toggleSort = (field) => {
    if (sortBy === field) {
      setSortOrder(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(field);
      setSortOrder('desc'); // Default to descending for new field
    }
  };

  // Apply filters, search, and sorting
  const filteredAlerts = useMemo(() => {
    let filtered = alerts.filter(alert => {
      // Search filter
      const matchesSearch = !searchTerm ||
        alert.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        alert.description.toLowerCase().includes(searchTerm.toLowerCase());

      // Severity filter
      const matchesSeverity = filters.severity.length === 0 ||
        filters.severity.includes(alert.severity);

      // Status filter
      const matchesStatus = filters.status.length === 0 ||
        filters.status.includes(alert.status);

      // Time range filter
      let matchesTime = true;
      if (filters.timeRange !== 'all') {
        const alertTime = new Date(alert.timestamp).getTime();
        const now = Date.now();
        const ranges = {
          '1h': 60 * 60 * 1000,
          '6h': 6 * 60 * 60 * 1000,
          '24h': 24 * 60 * 60 * 1000,
          '7d': 7 * 24 * 60 * 60 * 1000
        };
        matchesTime = alertTime >= (now - (ranges[filters.timeRange] || 0));
      }

      return matchesSearch && matchesSeverity && matchesStatus && matchesTime;
    });

    // Sort alerts
    filtered.sort((a, b) => {
      let aValue, bValue;

      switch (sortBy) {
        case 'timestamp':
          aValue = new Date(a.timestamp).getTime();
          bValue = new Date(b.timestamp).getTime();
          break;
        case 'severity':
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
          aValue = severityOrder[a.severity] || 0;
          bValue = severityOrder[b.severity] || 0;
          break;
        case 'status':
          aValue = a.status;
          bValue = b.status;
          break;
        case 'id':
          aValue = a.id;
          bValue = b.id;
          break;
        default:
          return 0;
      }

      if (sortOrder === 'asc') {
        return aValue > bValue ? 1 : aValue < bValue ? -1 : 0;
      } else {
        return aValue < bValue ? 1 : aValue > bValue ? -1 : 0;
      }
    });

    return filtered;
  }, [alerts, searchTerm, filters, sortBy, sortOrder]);

  // Pagination
  const totalPages = Math.ceil(filteredAlerts.length / pageSize);
  const paginatedAlerts = filteredAlerts.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize
  );

  // Toggle filter
  const toggleFilter = (category, value) => {
    setFilters(prev => {
      const current = prev[category];
      const updated = current.includes(value)
        ? current.filter(v => v !== value)
        : [...current, value];
      return { ...prev, [category]: updated };
    });
  };

  // Clear all filters
  const clearFilters = () => {
    setFilters({ severity: [], status: [], timeRange: 'all' });
    setSearchTerm('');
  };

  // Select/deselect alerts
  const toggleSelectAlert = (alertId) => {
    setSelectedAlerts(prev => {
      const newSet = new Set(prev);
      if (newSet.has(alertId)) {
        newSet.delete(alertId);
      } else {
        newSet.add(alertId);
      }
      return newSet;
    });
  };

  const toggleSelectAll = () => {
    if (selectedAlerts.size === paginatedAlerts.length) {
      setSelectedAlerts(new Set());
    } else {
      setSelectedAlerts(new Set(paginatedAlerts.map(a => a.id)));
    }
  };

  // Export functions
  const exportToCSV = () => {
    const headers = ['Alert ID', 'Timestamp', 'Severity', 'Status', 'Description'];
    const rows = filteredAlerts.map(a => [
      a.id,
      new Date(a.timestamp).toLocaleString(),
      a.severity,
      a.status,
      a.description
    ]);

    const csv = [headers, ...rows]
      .map(row => row.map(cell => `"${cell}"`).join(','))
      .join('\n');

    downloadFile(csv, 'alerts.csv', 'text/csv');
  };

  const exportToJSON = () => {
    const json = JSON.stringify(filteredAlerts, null, 2);
    downloadFile(json, 'alerts.json', 'application/json');
  };

  const downloadFile = (content, filename, mimeType) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Copy to clipboard
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  // Add note
  const addNote = () => {
    if (!newNote.trim() || !selectedAlert) return;

    setAlertNotes(prev => ({
      ...prev,
      [selectedAlert.id]: [
        ...(prev[selectedAlert.id] || []),
        {
          content: newNote,
          author: 'Current User',
          timestamp: new Date()
        }
      ]
    }));
    setNewNote('');
  };

  // Get severity badge color
  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-500',
      high: 'bg-orange-500',
      medium: 'bg-yellow-500',
      low: 'bg-blue-500'
    };
    return colors[severity] || 'bg-gray-500';
  };

  const activeFilterCount = filters.severity.length + filters.status.length +
    (filters.timeRange !== 'all' ? 1 : 0);

  return (
    <div className="space-y-4 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Security Alerts</h1>
          <p className="text-dark-400">Monitor and manage security events</p>
        </div>

        {/* Export buttons */}
        <div className="flex gap-2">
          <button
            onClick={exportToCSV}
            className="px-4 py-2 bg-dark-700 hover:bg-dark-600 rounded-lg font-semibold transition-all flex items-center gap-2"
          >
            <FileText className="w-4 h-4" />
            Export CSV
          </button>
          <button
            onClick={exportToJSON}
            className="px-4 py-2 bg-dark-700 hover:bg-dark-600 rounded-lg font-semibold transition-all flex items-center gap-2"
          >
            <FileJson className="w-4 h-4" />
            Export JSON
          </button>
        </div>
      </div>

      {/* Search and Filter Bar */}
      <div className="glass rounded-xl p-4">
        <div className="flex gap-3">
          {/* Search */}
          <div className="flex-1 flex items-center gap-2 bg-dark-800/50 px-4 py-3 rounded-lg border border-dark-700">
            <Search className="w-5 h-5 text-dark-500" />
            <input
              type="text"
              placeholder="Search by ID or description..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-transparent border-none outline-none text-sm text-white placeholder-dark-500 flex-1"
            />
          </div>

          {/* Filter Toggle */}
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`px-4 py-3 rounded-lg font-semibold transition-all flex items-center gap-2 ${
              showFilters ? 'bg-blue-500' : 'bg-dark-700 hover:bg-dark-600'
            }`}
          >
            <Filter className="w-4 h-4" />
            Filters
            {activeFilterCount > 0 && (
              <span className="px-2 py-0.5 bg-white text-black rounded-full text-xs font-bold">
                {activeFilterCount}
              </span>
            )}
          </button>

          {/* Clear Filters */}
          {activeFilterCount > 0 && (
            <button
              onClick={clearFilters}
              className="px-4 py-3 bg-dark-700 hover:bg-dark-600 rounded-lg font-semibold transition-all"
            >
              Clear All
            </button>
          )}
        </div>

        {/* Filter Panel */}
        {showFilters && (
          <div className="mt-4 p-4 bg-dark-800/50 rounded-lg border border-dark-700 grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Time Range */}
            <div>
              <h4 className="text-sm font-semibold mb-2 text-dark-400">TIME RANGE</h4>
              <div className="space-y-2">
                {['all', '1h', '6h', '24h', '7d'].map(range => (
                  <label key={range} className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      checked={filters.timeRange === range}
                      onChange={() => setFilters(prev => ({ ...prev, timeRange: range }))}
                      className="form-radio text-blue-500"
                    />
                    <span className="text-sm uppercase">{range === 'all' ? 'All Time' : range}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Severity */}
            <div>
              <h4 className="text-sm font-semibold mb-2 text-dark-400">SEVERITY</h4>
              <div className="space-y-2">
                {['critical', 'high', 'medium', 'low'].map(sev => (
                  <label key={sev} className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={filters.severity.includes(sev)}
                      onChange={() => toggleFilter('severity', sev)}
                      className="form-checkbox text-blue-500"
                    />
                    <span className="text-sm capitalize">{sev}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Status */}
            <div>
              <h4 className="text-sm font-semibold mb-2 text-dark-400">STATUS</h4>
              <div className="space-y-2">
                {['pending', 'processing', 'triaged', 'escalated', 'closed'].map(stat => (
                  <label key={stat} className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={filters.status.includes(stat)}
                      onChange={() => toggleFilter('status', stat)}
                      className="form-checkbox text-blue-500"
                    />
                    <span className="text-sm capitalize">{stat}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Bulk Actions Bar */}
      {selectedAlerts.size > 0 && (
        <div className="glass rounded-xl p-4 flex items-center justify-between border-l-4 border-blue-500">
          <span className="font-semibold">{selectedAlerts.size} alert(s) selected</span>
          <div className="flex gap-2">
            <button
              onClick={() => {
                const selected = alerts.filter(a => selectedAlerts.has(a.id));
                exportToJSON(selected);
              }}
              className="px-3 py-2 bg-dark-700 hover:bg-dark-600 rounded-lg text-sm font-semibold transition-all"
            >
              Export Selected
            </button>
            <button
              onClick={() => setSelectedAlerts(new Set())}
              className="px-3 py-2 bg-dark-700 hover:bg-dark-600 rounded-lg text-sm font-semibold transition-all"
            >
              Deselect All
            </button>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="glass rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-dark-800/50 border-b border-dark-700">
              <tr>
                <th className="px-4 py-3 text-left w-12">
                  <input
                    type="checkbox"
                    checked={selectedAlerts.size === paginatedAlerts.length && paginatedAlerts.length > 0}
                    onChange={toggleSelectAll}
                    className="form-checkbox text-blue-500"
                  />
                </th>
                <th className="px-6 py-3 text-left">
                  <button
                    onClick={() => toggleSort('id')}
                    className="flex items-center gap-2 text-xs font-semibold text-dark-400 uppercase hover:text-white transition-colors"
                  >
                    Alert ID
                    {sortBy === 'id' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3" /> : <ArrowDown className="w-3 h-3" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 opacity-30" />
                    )}
                  </button>
                </th>
                <th className="px-6 py-3 text-left">
                  <button
                    onClick={() => toggleSort('timestamp')}
                    className="flex items-center gap-2 text-xs font-semibold text-dark-400 uppercase hover:text-white transition-colors"
                  >
                    Timestamp
                    {sortBy === 'timestamp' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3" /> : <ArrowDown className="w-3 h-3" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 opacity-30" />
                    )}
                  </button>
                </th>
                <th className="px-6 py-3 text-left">
                  <button
                    onClick={() => toggleSort('severity')}
                    className="flex items-center gap-2 text-xs font-semibold text-dark-400 uppercase hover:text-white transition-colors"
                  >
                    Severity
                    {sortBy === 'severity' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3" /> : <ArrowDown className="w-3 h-3" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 opacity-30" />
                    )}
                  </button>
                </th>
                <th className="px-6 py-3 text-left">
                  <button
                    onClick={() => toggleSort('status')}
                    className="flex items-center gap-2 text-xs font-semibold text-dark-400 uppercase hover:text-white transition-colors"
                  >
                    Status
                    {sortBy === 'status' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3" /> : <ArrowDown className="w-3 h-3" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 opacity-30" />
                    )}
                  </button>
                </th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-dark-400 uppercase">Description</th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-dark-400 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-800">
              {paginatedAlerts.length === 0 ? (
                <tr>
                  <td colSpan="7" className="px-6 py-12 text-center text-dark-500">
                    <AlertCircle className="w-12 h-12 mx-auto mb-4 opacity-50" />
                    <p>No alerts found</p>
                  </td>
                </tr>
              ) : (
                paginatedAlerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className={`hover:bg-dark-800/30 transition-colors ${
                      selectedAlerts.has(alert.id) ? 'bg-blue-500/10' : ''
                    }`}
                  >
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selectedAlerts.has(alert.id)}
                        onChange={() => toggleSelectAlert(alert.id)}
                        className="form-checkbox text-blue-500"
                      />
                    </td>
                    <td className="px-6 py-3">
                      <span className="font-mono text-sm text-blue-400 font-semibold">
                        {alert.id.substring(0, 12)}...
                      </span>
                    </td>
                    <td className="px-6 py-3 text-sm text-dark-400">
                      {new Date(alert.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-3">
                      <span className={`px-3 py-1 rounded-full text-xs font-bold ${getSeverityColor(alert.severity)} text-white uppercase`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-6 py-3">
                      <span className="px-3 py-1 rounded-full text-xs font-semibold bg-blue-500/20 text-blue-400 capitalize">
                        {alert.status}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-sm max-w-md truncate">
                      {alert.description}
                    </td>
                    <td className="px-6 py-3">
                      <button
                        onClick={() => setSelectedAlert(alert)}
                        className="p-2 hover:bg-dark-700 rounded-lg transition-colors"
                        title="View Details"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="px-6 py-4 bg-dark-800/30 border-t border-dark-700 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-sm text-dark-400">Show</span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setCurrentPage(1);
                }}
                className="bg-dark-700 border border-dark-600 rounded-lg px-3 py-1 text-sm"
              >
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
              <span className="text-sm text-dark-400">
                Showing {((currentPage - 1) * pageSize) + 1} to {Math.min(currentPage * pageSize, filteredAlerts.length)} of {filteredAlerts.length}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentPage(1)}
                disabled={currentPage === 1}
                className="px-3 py-1 bg-dark-700 hover:bg-dark-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                First
              </button>
              <button
                onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                disabled={currentPage === 1}
                className="p-2 bg-dark-700 hover:bg-dark-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="px-4 py-2 bg-dark-800 rounded-lg font-semibold">
                {currentPage} / {totalPages}
              </span>
              <button
                onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                disabled={currentPage === totalPages}
                className="p-2 bg-dark-700 hover:bg-dark-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
              <button
                onClick={() => setCurrentPage(totalPages)}
                disabled={currentPage === totalPages}
                className="px-3 py-1 bg-dark-700 hover:bg-dark-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                Last
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Alert Detail Modal with Tabs */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="glass rounded-xl max-w-4xl w-full max-h-[90vh] flex flex-col">
            {/* Modal Header */}
            <div className="p-6 border-b border-dark-700">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="text-2xl font-bold mb-2">Alert Details</h3>
                  <p className="font-mono text-sm text-blue-400">{selectedAlert.id}</p>
                </div>
                <button
                  onClick={() => {
                    setSelectedAlert(null);
                    setAlertDetails(null);
                    setActiveTab('overview');
                  }}
                  className="text-2xl hover:bg-dark-700 rounded-lg p-2 transition-all"
                >
                  <X className="w-6 h-6" />
                </button>
              </div>
            </div>

            {/* Tabs */}
            <div className="flex border-b border-dark-700 px-6">
              {['overview', 'timeline', 'notes', 'raw'].map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-4 py-3 font-semibold capitalize transition-all border-b-2 ${
                    activeTab === tab
                      ? 'border-blue-500 text-blue-400'
                      : 'border-transparent text-dark-400 hover:text-white'
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="flex-1 overflow-y-auto p-6">
              {activeTab === 'overview' && (
                <div className="space-y-4">
                  {/* Escalation Alert Banner */}
                  {selectedAlert.status === 'escalated' && alertDetails?.escalation_info && (
                    <div className="bg-orange-500/10 border border-orange-500/50 rounded-lg p-4">
                      <div className="flex items-start gap-3">
                        <AlertCircle className="w-5 h-5 text-orange-400 mt-0.5 flex-shrink-0" />
                        <div className="flex-1">
                          <h4 className="font-semibold text-orange-400 mb-2">⚠️ Manual Intervention Required</h4>
                          <p className="text-sm text-dark-300 mb-2">
                            <strong>Reason:</strong> {alertDetails.escalation_info.reason.replace(/_/g, ' ')}
                          </p>
                          {alertDetails.escalation_info.error_message && (
                            <p className="text-sm text-dark-300 mb-2">
                              <strong>Error:</strong> {alertDetails.escalation_info.error_message}
                            </p>
                          )}
                          {alertDetails.escalation_info.requires_manual_response && (
                            <p className="text-sm text-orange-300 font-semibold">
                              📋 Action Required: Review and execute manual response
                            </p>
                          )}
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm text-dark-400 block mb-1">Severity</label>
                      <span className={`inline-block px-3 py-1 rounded-full text-xs font-bold ${getSeverityColor(selectedAlert.severity)} text-white uppercase`}>
                        {selectedAlert.severity}
                      </span>
                    </div>
                    <div>
                      <label className="text-sm text-dark-400 block mb-1">Status</label>
                      <span className={`inline-block px-3 py-1 rounded-full text-xs font-semibold ${
                        selectedAlert.status === 'escalated' ? 'bg-orange-500/20 text-orange-400' : 'bg-blue-500/20 text-blue-400'
                      } capitalize`}>
                        {selectedAlert.status}
                      </span>
                    </div>
                  </div>
                  <div>
                    <label className="text-sm text-dark-400 block mb-1">Description</label>
                    <p className="text-white">{selectedAlert.description}</p>
                  </div>
                  <div>
                    <label className="text-sm text-dark-400 block mb-1">Timestamp</label>
                    <p className="text-white">{new Date(selectedAlert.timestamp).toLocaleString()}</p>
                  </div>

                  {/* Agent Assessment Timeline */}
                  {alertDetails && (
                    <div className="bg-dark-800/50 border border-dark-700 rounded-lg p-4">
                      <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                        <Activity className="w-4 h-4" />
                        Agent Assessment Timeline
                      </h4>
                      <div className="space-y-4">
                        {/* Triage Agent Assessment */}
                        {(() => {
                          const llmInsights = alertDetails?.enriched_data?.llm_insights;
                          const fpIndicators = alertDetails?.fp_indicators || [];
                          const tpIndicators = alertDetails?.tp_indicators || [];

                          if (selectedAlert.confidence || llmInsights) {
                            return (
                              <div className="flex gap-3">
                                <div className="flex-shrink-0">
                                  <div className="w-8 h-8 rounded-full bg-yellow-500/20 flex items-center justify-center">
                                    <ShieldCheck className="w-4 h-4 text-yellow-400" />
                                  </div>
                                </div>
                                <div className="flex-1">
                                  <div className="font-semibold text-white text-sm">🎯 Triage Agent</div>
                                  <div className="text-xs text-dark-400 mt-1 space-y-1">
                                    <div>├─ Confidence: <span className="text-yellow-400 font-semibold">{selectedAlert.confidence}%</span></div>
                                    {llmInsights?.threat_assessment && (
                                      <div>├─ LLM Assessment: <span className="text-purple-400 capitalize">{llmInsights.threat_assessment.replace('_', ' ')}</span></div>
                                    )}
                                    <div>├─ False Positive Indicators: <span className="text-red-400">{fpIndicators.length}</span></div>
                                    <div>└─ True Positive Indicators: <span className="text-green-400">{tpIndicators.length}</span></div>
                                  </div>
                                </div>
                              </div>
                            );
                          }
                          return null;
                        })()}

                        {/* Correlation Agent Assessment */}
                        {(() => {
                          const correlations = alertDetails?.correlations || [];
                          const correlationScore = alertDetails?.correlation_score;

                          if (correlations.length > 0 || correlationScore) {
                            return (
                              <div className="flex gap-3">
                                <div className="flex-shrink-0">
                                  <div className="w-8 h-8 rounded-full bg-cyan-500/20 flex items-center justify-center">
                                    <GitBranch className="w-4 h-4 text-cyan-400" />
                                  </div>
                                </div>
                                <div className="flex-1">
                                  <div className="font-semibold text-white text-sm">🔗 Correlation Agent</div>
                                  <div className="text-xs text-dark-400 mt-1 space-y-1">
                                    <div>├─ Correlations Found: <span className="text-cyan-400 font-semibold">{correlations.length}</span></div>
                                    {correlationScore > 0 && (
                                      <div>├─ Correlation Score: <span className="text-cyan-400 font-semibold">{correlationScore}%</span></div>
                                    )}
                                    <div>└─ Related Alerts: <span className="text-dark-300">{correlations.slice(0, 3).map(c => c.alert_id || 'unknown').join(', ')}{correlations.length > 3 ? '...' : ''}</span></div>
                                  </div>
                                </div>
                              </div>
                            );
                          }
                          return null;
                        })()}

                        {/* Analysis Agent Assessment */}
                        {(() => {
                          const threatScore = alertDetails?.threat_score;
                          const analysisConclusion = alertDetails?.analysis_conclusion;
                          const recommendedActions = alertDetails?.recommended_actions || [];

                          if (threatScore > 0 || analysisConclusion) {
                            return (
                              <div className="flex gap-3">
                                <div className="flex-shrink-0">
                                  <div className="w-8 h-8 rounded-full bg-green-500/20 flex items-center justify-center">
                                    <Brain className="w-4 h-4 text-green-400" />
                                  </div>
                                </div>
                                <div className="flex-1">
                                  <div className="font-semibold text-white text-sm">🧠 Analysis Agent</div>
                                  <div className="text-xs text-dark-400 mt-1 space-y-1">
                                    {threatScore > 0 && (
                                      <div>├─ Threat Score: <span className={`font-semibold ${threatScore >= 70 ? 'text-red-400' : threatScore >= 40 ? 'text-orange-400' : 'text-yellow-400'}`}>{threatScore}%</span></div>
                                    )}
                                    {analysisConclusion && (
                                      <div>├─ Conclusion: <span className="text-green-400">{analysisConclusion.substring(0, 100)}{analysisConclusion.length > 100 ? '...' : ''}</span></div>
                                    )}
                                    <div>└─ Recommended Actions: <span className="text-dark-300">{recommendedActions.length} actions</span></div>
                                  </div>
                                </div>
                              </div>
                            );
                          }
                          return null;
                        })()}

                        {/* Human Loop / Escalation */}
                        {selectedAlert.status === 'escalated' && (
                          <div className="flex gap-3">
                            <div className="flex-shrink-0">
                              <div className="w-8 h-8 rounded-full bg-orange-500/20 flex items-center justify-center">
                                <Users className="w-4 h-4 text-orange-400" />
                              </div>
                            </div>
                            <div className="flex-1">
                              <div className="font-semibold text-white text-sm">👤 Human Review</div>
                              <div className="text-xs text-dark-400 mt-1 space-y-1">
                                <div>└─ Escalated for L1/L2 analyst review</div>
                              </div>
                            </div>
                          </div>
                        )}

                        {/* Response Agent */}
                        {alertDetails?.response_execution && (
                          <div className="flex gap-3">
                            <div className="flex-shrink-0">
                              <div className="w-8 h-8 rounded-full bg-red-500/20 flex items-center justify-center">
                                <Zap className="w-4 h-4 text-red-400" />
                              </div>
                            </div>
                            <div className="flex-1">
                              <div className="font-semibold text-white text-sm">⚡ Response Agent</div>
                              <div className="text-xs text-dark-400 mt-1 space-y-1">
                                <div>├─ Playbook: <span className="text-red-400">{alertDetails.response_execution.playbook_name}</span></div>
                                <div>├─ Actions Succeeded: <span className="text-green-400">{alertDetails.response_execution.actions_succeeded}/{alertDetails.response_execution.actions_attempted}</span></div>
                                <div>└─ Actions Failed: <span className="text-red-400">{alertDetails.response_execution.actions_failed}</span></div>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                  <div className="grid grid-cols-2 gap-4">
                    {selectedAlert.confidence && (
                      <div>
                        <label className="text-sm text-dark-400 block mb-1">Confidence Score</label>
                        <div className="flex items-center gap-3">
                          <div className="flex-1 bg-dark-800 rounded-full h-2">
                            <div
                              className="bg-gradient-to-r from-blue-500 to-purple-600 h-2 rounded-full transition-all"
                              style={{ width: `${selectedAlert.confidence}%` }}
                            ></div>
                          </div>
                          <span className="font-bold">{selectedAlert.confidence}%</span>
                        </div>
                      </div>
                    )}
                    {(() => {
                      // Calculate threat score (actual or preliminary)
                      const actualThreatScore = selectedAlert.threat_score || alertDetails?.threat_score;
                      const llmInsights = alertDetails?.enriched_data?.llm_insights || alertDetails?.llm_insights;
                      const threatAssessment = llmInsights?.threat_assessment;

                      // Map LLM threat assessment to preliminary score
                      const preliminaryScoreMap = {
                        'confirmed_threat': 90,
                        'likely_threat': 70,
                        'possible_threat': 50,
                        'suspicious': 50,
                        'unlikely_threat': 30,
                        'benign': 10
                      };

                      const preliminaryScore = threatAssessment ? preliminaryScoreMap[threatAssessment] || 0 : 0;
                      const displayScore = actualThreatScore > 0 ? actualThreatScore : preliminaryScore;
                      const isPreliminary = actualThreatScore === 0 || actualThreatScore === undefined;

                      if (displayScore > 0 || threatAssessment) {
                        return (
                          <div>
                            <label className="text-sm text-dark-400 block mb-1">
                              {isPreliminary ? 'Preliminary Threat Score' : 'Threat Score'}
                              {isPreliminary && threatAssessment && (
                                <span className="ml-2 text-xs text-yellow-400">(from LLM assessment)</span>
                              )}
                            </label>
                            <div className="flex items-center gap-3">
                              <div className="flex-1 bg-dark-800 rounded-full h-2">
                                <div
                                  className={`h-2 rounded-full transition-all ${
                                    displayScore >= 70
                                      ? 'bg-gradient-to-r from-red-500 to-orange-500'
                                      : displayScore >= 40
                                      ? 'bg-gradient-to-r from-orange-500 to-yellow-500'
                                      : 'bg-gradient-to-r from-yellow-500 to-green-500'
                                  }`}
                                  style={{ width: `${displayScore}%` }}
                                ></div>
                              </div>
                              <span className="font-bold">{displayScore}%</span>
                            </div>
                            {isPreliminary && threatAssessment && (
                              <p className="text-xs text-dark-400 mt-1">
                                Assessment: <span className="text-yellow-400 capitalize">{threatAssessment.replace('_', ' ')}</span>
                                {!actualThreatScore && ' • Deep analysis pending'}
                              </p>
                            )}
                          </div>
                        );
                      }
                      return null;
                    })()}
                  </div>

                  {/* LLM Threat Assessment (if available) */}
                  {(() => {
                    const llmInsights = alertDetails?.enriched_data?.llm_insights || alertDetails?.llm_insights;
                    if (llmInsights && llmInsights.threat_assessment) {
                      return (
                        <div className="bg-dark-800/50 border border-dark-700 rounded-lg p-4">
                          <h4 className="font-semibold text-white mb-3">LLM Threat Assessment</h4>
                          <div className="grid grid-cols-2 gap-4 text-sm">
                            <div>
                              <span className="text-dark-400 block mb-1">Assessment</span>
                              <span className={`capitalize font-semibold ${
                                llmInsights.threat_assessment === 'confirmed_threat' ? 'text-red-400' :
                                llmInsights.threat_assessment === 'likely_threat' ? 'text-orange-400' :
                                llmInsights.threat_assessment === 'suspicious' || llmInsights.threat_assessment === 'possible_threat' ? 'text-yellow-400' :
                                'text-green-400'
                              }`}>
                                {llmInsights.threat_assessment.replace('_', ' ')}
                              </span>
                            </div>
                            {llmInsights.threat_categories && llmInsights.threat_categories.length > 0 && (
                              <div>
                                <span className="text-dark-400 block mb-1">Threat Categories</span>
                                <div className="flex flex-wrap gap-1">
                                  {llmInsights.threat_categories.map((category, idx) => (
                                    <span key={idx} className="px-2 py-1 bg-orange-500/20 text-orange-400 text-xs rounded">
                                      {category}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                          {llmInsights.analysis_reasoning && (
                            <div className="mt-3 pt-3 border-t border-dark-700">
                              <span className="text-dark-400 block mb-2 text-sm">LLM Reasoning</span>
                              <p className="text-sm text-dark-300">{llmInsights.analysis_reasoning}</p>
                            </div>
                          )}
                        </div>
                      );
                    }
                    return null;
                  })()}

                  {/* Response Execution Summary */}
                  {alertDetails?.response_execution && (
                    <div className="bg-dark-800/50 border border-dark-700 rounded-lg p-4">
                      <h4 className="font-semibold text-white mb-3">Response Execution Summary</h4>
                      <div className="grid grid-cols-3 gap-4 text-sm">
                        <div>
                          <span className="text-dark-400 block mb-1">Playbook</span>
                          <span className="text-white font-semibold">{alertDetails.response_execution.playbook_name}</span>
                        </div>
                        <div>
                          <span className="text-dark-400 block mb-1">Threat Type</span>
                          <span className="text-white capitalize">{alertDetails.response_execution.threat_type}</span>
                        </div>
                        <div>
                          <span className="text-dark-400 block mb-1">Execution Time</span>
                          <span className="text-white">{alertDetails.response_execution.execution_time_seconds?.toFixed(2)}s</span>
                        </div>
                      </div>
                      <div className="grid grid-cols-3 gap-4 mt-3 text-sm">
                        <div>
                          <span className="text-dark-400 block mb-1">Actions Attempted</span>
                          <span className="text-white font-semibold">{alertDetails.response_execution.actions_attempted}</span>
                        </div>
                        <div>
                          <span className="text-dark-400 block mb-1">Succeeded</span>
                          <span className="text-green-400 font-semibold">{alertDetails.response_execution.actions_succeeded}</span>
                        </div>
                        <div>
                          <span className="text-dark-400 block mb-1">Failed</span>
                          <span className="text-red-400 font-semibold">{alertDetails.response_execution.actions_failed}</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'timeline' && (
                <div className="space-y-4">
                  {loadingDetails ? (
                    <div className="flex items-center justify-center py-12">
                      <Activity className="w-8 h-8 animate-spin text-blue-400" />
                      <span className="ml-3 text-dark-400">Loading timeline...</span>
                    </div>
                  ) : alertDetails?.processing_notes && alertDetails.processing_notes.length > 0 ? (
                    <div className="relative pl-8 border-l-2 border-dark-700">
                      {/* Initial alert creation */}
                      <div className="mb-6">
                        <div className="absolute -left-2 w-4 h-4 bg-blue-500 rounded-full ring-4 ring-dark-900"></div>
                        <div className="text-xs text-dark-500 mb-1">
                          {new Date(selectedAlert.timestamp || selectedAlert.created_at).toLocaleString()}
                        </div>
                        <div className="font-semibold text-white">Alert Created</div>
                        <div className="text-sm text-dark-400">
                          Initial detection by {selectedAlert.source || 'system'}
                        </div>
                      </div>

                      {/* Agent processing timeline */}
                      {parseTimeline(alertDetails.processing_notes).map((event, index) => {
                        const Icon = event.icon;
                        const colorClasses = {
                          blue: 'bg-blue-500 text-blue-400',
                          green: 'bg-green-500 text-green-400',
                          yellow: 'bg-yellow-500 text-yellow-400',
                          orange: 'bg-orange-500 text-orange-400',
                          red: 'bg-red-500 text-red-400',
                          purple: 'bg-purple-500 text-purple-400',
                          cyan: 'bg-cyan-500 text-cyan-400'
                        };
                        const colorClass = colorClasses[event.color] || colorClasses.blue;
                        const bgColor = colorClass.split(' ')[0];
                        const textColor = colorClass.split(' ')[1];

                        return (
                          <div key={event.id} className="mb-6 group">
                            <div className={`absolute -left-2.5 w-5 h-5 ${bgColor} rounded-full ring-4 ring-dark-900 flex items-center justify-center group-hover:scale-110 transition-transform`}>
                              <Icon className="w-3 h-3 text-white" />
                            </div>
                            <div className="bg-dark-800/30 rounded-lg p-3 hover:bg-dark-800/50 transition-all border border-dark-700/50 hover:border-dark-600">
                              <div className={`font-semibold ${textColor} mb-1`}>
                                {event.title}
                              </div>
                              <div className="text-sm text-dark-300">
                                {event.description}
                              </div>
                            </div>
                          </div>
                        );
                      })}

                      {/* Final status */}
                      {selectedAlert.status === 'closed' && (
                        <div className="mb-6">
                          <div className="absolute -left-2 w-4 h-4 bg-green-500 rounded-full ring-4 ring-dark-900 animate-pulse"></div>
                          <div className="font-semibold text-green-400">Alert Closed</div>
                          <div className="text-sm text-dark-400">
                            Processing completed • Final confidence: {selectedAlert.confidence_score || selectedAlert.confidence || 'N/A'}%
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="text-center py-12 text-dark-500">
                      <AlertCircle className="w-12 h-12 mx-auto mb-3 opacity-50" />
                      <p className="text-sm">No processing timeline available</p>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'notes' && (
                <div className="space-y-4">
                  <div>
                    <textarea
                      value={newNote}
                      onChange={(e) => setNewNote(e.target.value)}
                      placeholder="Add a note about this alert..."
                      className="w-full bg-dark-800 border border-dark-700 rounded-lg p-3 text-sm resize-none focus:border-blue-500 outline-none"
                      rows="3"
                    />
                    <button
                      onClick={addNote}
                      className="mt-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg font-semibold transition-all"
                    >
                      Add Note
                    </button>
                  </div>
                  <div className="space-y-3">
                    {alertNotes[selectedAlert.id]?.length > 0 ? (
                      alertNotes[selectedAlert.id].map((note, idx) => (
                        <div key={idx} className="bg-dark-800/50 rounded-lg p-4 border border-dark-700">
                          <div className="flex justify-between items-start mb-2">
                            <span className="font-semibold text-sm">{note.author}</span>
                            <span className="text-xs text-dark-400">
                              {new Date(note.timestamp).toLocaleString()}
                            </span>
                          </div>
                          <p className="text-sm">{note.content}</p>
                        </div>
                      ))
                    ) : (
                      <p className="text-center text-dark-500 py-8">No notes yet. Add the first note above.</p>
                    )}
                  </div>
                </div>
              )}

              {activeTab === 'raw' && (
                <div>
                  <div className="flex justify-end mb-3">
                    <button
                      onClick={() => copyToClipboard(JSON.stringify(selectedAlert, null, 2))}
                      className="px-3 py-2 bg-dark-700 hover:bg-dark-600 rounded-lg text-sm font-semibold transition-all flex items-center gap-2"
                    >
                      <Copy className="w-4 h-4" />
                      Copy JSON
                    </button>
                  </div>
                  <pre className="bg-dark-900 border border-dark-700 rounded-lg p-4 text-xs overflow-x-auto">
                    {JSON.stringify(selectedAlert, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Alerts;
