import React, { useState } from 'react';
import { AlertCircle, Search, Eye } from 'lucide-react';
import { useAlerts } from '../contexts/AlertContext';

const Alerts = () => {
  const { alerts } = useAlerts();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedAlert, setSelectedAlert] = useState(null);

  const filteredAlerts = alerts.filter(alert =>
    alert.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    alert.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6 animate-fadeIn">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Security Alerts</h1>
        <p className="text-dark-400">Monitor and manage security events</p>
      </div>

      <div className="glass rounded-xl p-6">
        <div className="flex items-center gap-2 bg-dark-800/50 px-4 py-3 rounded-lg border border-dark-700 mb-4">
          <Search className="w-5 h-5 text-dark-500" />
          <input
            type="text"
            placeholder="Search alerts..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-transparent border-none outline-none text-sm text-white placeholder-dark-500 flex-1"
          />
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-dark-800/50 border-b border-dark-700">
              <tr>
                <th className="px-6 py-4 text-left text-xs font-semibold text-dark-400 uppercase">Alert ID</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-dark-400 uppercase">Description</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-dark-400 uppercase">Severity</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-dark-400 uppercase">Status</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-dark-400 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-800">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan="5" className="px-6 py-12 text-center text-dark-500">
                    <AlertCircle className="w-12 h-12 mx-auto mb-4 opacity-50" />
                    <p>No alerts found</p>
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-dark-800/30 transition-colors">
                    <td className="px-6 py-4">
                      <span className="font-mono text-sm text-blue-400">
                        {alert.id.substring(0, 12)}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm">{alert.description}</td>
                    <td className="px-6 py-4">
                      <span className="px-3 py-1 rounded-full text-xs font-semibold bg-yellow-500 text-black">
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="px-3 py-1 rounded-full text-xs font-semibold bg-blue-500/20 text-blue-400">
                        {alert.status}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <button
                        onClick={() => setSelectedAlert(alert)}
                        className="p-2 hover:bg-dark-700 rounded-lg transition-colors"
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
      </div>

      {selectedAlert && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="glass rounded-xl max-w-2xl w-full p-6">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-bold">Alert Details</h3>
              <button
                onClick={() => setSelectedAlert(null)}
                className="text-2xl hover:bg-dark-700 rounded-lg px-3"
              >
                ×
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="text-sm text-dark-400">Alert ID</label>
                <p className="font-mono text-blue-400">{selectedAlert.id}</p>
              </div>
              <div>
                <label className="text-sm text-dark-400">Description</label>
                <p>{selectedAlert.description}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm text-dark-400">Severity</label>
                  <p className="font-semibold">{selectedAlert.severity}</p>
                </div>
                <div>
                  <label className="text-sm text-dark-400">Status</label>
                  <p className="font-semibold">{selectedAlert.status}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Alerts;