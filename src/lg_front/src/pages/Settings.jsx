import React, { useState } from 'react';
import { Settings as SettingsIcon, Bell, Shield, Database, Save, Trash2 } from 'lucide-react';

const Settings = () => {
  const [activeTab, setActiveTab] = useState('general');
  const [settings, setSettings] = useState({
    organizationName: 'SOC Operations',
    timezone: 'UTC',
    language: 'en',
    emailNotifications: true,
    slackNotifications: false,
    criticalAlerts: true,
    dailyReports: true,
    sessionTimeout: 30,
    mfaEnabled: false,
    apiAccess: true,
    dataRetention: 90,
    autoArchive: true,
    debugMode: false
  });

  const handleChange = (key, value) => {
    setSettings(prev => ({ ...prev, [key]: value }));
  };

  const handleSave = () => {
    console.log('Saving settings:', settings);
    alert('Settings saved successfully!');
  };

  const tabs = [
    { id: 'general', name: 'General', icon: SettingsIcon },
    { id: 'notifications', name: 'Notifications', icon: Bell },
    { id: 'security', name: 'Security', icon: Shield },
    { id: 'system', name: 'System', icon: Database }
  ];

  const ToggleSwitch = ({ checked, onChange }) => (
    <label className="relative inline-flex items-center cursor-pointer">
      <input type="checkbox" checked={checked} onChange={onChange} className="sr-only peer" />
      <div className="w-11 h-6 bg-dark-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
    </label>
  );

  return (
    <div className="space-y-6 animate-fadeIn">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Settings</h1>
        <p className="text-dark-400">Manage your SOC platform configuration</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Sidebar Tabs */}
        <div className="lg:col-span-1">
          <div className="glass rounded-xl p-4 space-y-2">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
                  activeTab === tab.id
                    ? 'bg-gradient-to-r from-blue-500 to-purple-600 text-white'
                    : 'text-dark-400 hover:bg-dark-800 hover:text-white'
                }`}
              >
                <tab.icon className="w-5 h-5" />
                <span className="font-medium">{tab.name}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Content Area */}
        <div className="lg:col-span-3">
          <div className="glass rounded-xl p-6">
            {/* General Settings */}
            {activeTab === 'general' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-xl font-bold mb-4">General Settings</h3>
                  <p className="text-dark-400 text-sm mb-6">Configure basic platform settings</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-dark-300 mb-2">Organization Name</label>
                  <input
                    type="text"
                    value={settings.organizationName}
                    onChange={(e) => handleChange('organizationName', e.target.value)}
                    className="w-full px-4 py-3 bg-dark-800/50 border border-dark-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-dark-300 mb-2">Timezone</label>
                  <select
                    value={settings.timezone}
                    onChange={(e) => handleChange('timezone', e.target.value)}
                    className="w-full px-4 py-3 bg-dark-800/50 border border-dark-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="UTC">UTC</option>
                    <option value="EST">Eastern Time</option>
                    <option value="PST">Pacific Time</option>
                    <option value="CET">Central European Time</option>
                  </select>
                </div>
              </div>
            )}

            {/* Notification Settings */}
            {activeTab === 'notifications' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-xl font-bold mb-4">Notification Settings</h3>
                  <p className="text-dark-400 text-sm mb-6">Manage alerts and updates</p>
                </div>
                <div className="space-y-4">
                  {[
                    { key: 'emailNotifications', title: 'Email Notifications', desc: 'Receive alerts via email' },
                    { key: 'slackNotifications', title: 'Slack Integration', desc: 'Send alerts to Slack' },
                    { key: 'criticalAlerts', title: 'Critical Alerts', desc: 'Instant notifications for critical events' },
                    { key: 'dailyReports', title: 'Daily Reports', desc: 'Receive daily summary reports' }
                  ].map(item => (
                    <div key={item.key} className="flex items-center justify-between p-4 bg-dark-800/50 rounded-lg">
                      <div>
                        <p className="font-medium text-white">{item.title}</p>
                        <p className="text-sm text-dark-400">{item.desc}</p>
                      </div>
                      <ToggleSwitch
                        checked={settings[item.key]}
                        onChange={(e) => handleChange(item.key, e.target.checked)}
                      />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Security Settings */}
            {activeTab === 'security' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-xl font-bold mb-4">Security Settings</h3>
                  <p className="text-dark-400 text-sm mb-6">Configure security settings</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-dark-300 mb-2">Session Timeout (minutes)</label>
                  <input
                    type="number"
                    value={settings.sessionTimeout}
                    onChange={(e) => handleChange('sessionTimeout', parseInt(e.target.value))}
                    className="w-full px-4 py-3 bg-dark-800/50 border border-dark-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div className="flex items-center justify-between p-4 bg-dark-800/50 rounded-lg">
                  <div>
                    <p className="font-medium text-white">Multi-Factor Authentication</p>
                    <p className="text-sm text-dark-400">Require MFA for all users</p>
                  </div>
                  <ToggleSwitch
                    checked={settings.mfaEnabled}
                    onChange={(e) => handleChange('mfaEnabled', e.target.checked)}
                  />
                </div>
              </div>
            )}

            {/* System Settings */}
            {activeTab === 'system' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-xl font-bold mb-4">System Settings</h3>
                  <p className="text-dark-400 text-sm mb-6">Configure system parameters</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-dark-300 mb-2">Data Retention (days)</label>
                  <input
                    type="number"
                    value={settings.dataRetention}
                    onChange={(e) => handleChange('dataRetention', parseInt(e.target.value))}
                    className="w-full px-4 py-3 bg-dark-800/50 border border-dark-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div className="border-t border-dark-700 pt-6">
                  <h4 className="font-semibold text-red-400 mb-3">Danger Zone</h4>
                  <button className="w-full px-4 py-3 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 rounded-lg transition-all flex items-center justify-center gap-2">
                    <Trash2 className="w-4 h-4" />
                    Clear All Cache
                  </button>
                </div>
              </div>
            )}

            {/* Save Button */}
            <div className="flex items-center justify-end gap-3 pt-6 border-t border-dark-700 mt-6">
              <button className="px-6 py-3 bg-dark-800 hover:bg-dark-700 text-white rounded-lg transition-all">
                Cancel
              </button>
              <button
                onClick={handleSave}
                className="px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white rounded-lg font-semibold transition-all flex items-center gap-2"
              >
                <Save className="w-4 h-4" />
                Save Changes
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;