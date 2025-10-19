import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, Search, User, LogOut, Menu, Wifi, WifiOff } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { useAlerts } from '../../contexts/AlertContext';

const TopBar = ({ onMenuClick }) => {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { connected, alerts } = useAlerts();
  const [currentTime, setCurrentTime] = useState(new Date());
  const [showUserMenu, setShowUserMenu] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  // Count unread alerts (new alerts in last 5 minutes)
  const recentAlerts = alerts.filter(alert => {
    const alertTime = new Date(alert.timestamp);
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    return alertTime > fiveMinutesAgo;
  });

  return (
    <header className="h-16 bg-dark-900/80 backdrop-blur-xl border-b border-dark-800 sticky top-0 z-40">
      <div className="h-full px-6 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={onMenuClick}
            className="lg:hidden p-2 hover:bg-dark-800 rounded-lg transition-colors"
          >
            <Menu className="w-5 h-5" />
          </button>

          <div className="hidden md:flex items-center gap-2 bg-dark-800/50 px-4 py-2 rounded-lg border border-dark-700 min-w-[300px]">
            <Search className="w-4 h-4 text-dark-500" />
            <input
              type="text"
              placeholder="Search alerts, agents..."
              className="bg-transparent border-none outline-none text-sm text-white placeholder-dark-500 flex-1"
            />
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* Real-time Clock */}
          <div className="hidden md:flex items-center gap-2 px-4 py-2 bg-dark-800/50 rounded-lg border border-dark-700">
            <span className="text-sm font-mono text-blue-400 font-semibold">
              {currentTime.toLocaleTimeString('en-US', { 
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
              })}
            </span>
          </div>

          {/* WebSocket Connection Status */}
          <div className={`flex items-center gap-2 px-3 py-2 rounded-lg font-semibold text-xs shadow-lg transition-all ${
            connected
              ? 'bg-green-500/10 text-green-400 border border-green-500/20 animate-pulse'
              : 'bg-red-500/10 text-red-400 border border-red-500/20'
          }`}>
            {connected ? (
              <>
                <Wifi className="w-4 h-4" />
                <span className="hidden sm:inline">LIVE</span>
              </>
            ) : (
              <>
                <WifiOff className="w-4 h-4" />
                <span className="hidden sm:inline">OFFLINE</span>
              </>
            )}
          </div>

          {/* Notification Bell with Badge */}
          <button className="relative p-2 hover:bg-dark-800 rounded-lg transition-colors">
            <Bell className="w-5 h-5" />
            {recentAlerts.length > 0 && (
              <>
                <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full animate-ping"></span>
                <span className="absolute top-0 right-0 -mt-1 -mr-1 px-1.5 py-0.5 bg-red-500 text-white text-xs font-bold rounded-full min-w-[20px] text-center">
                  {recentAlerts.length > 9 ? '9+' : recentAlerts.length}
                </span>
              </>
            )}
          </button>

          {/* User Menu */}
          <div className="relative">
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="flex items-center gap-3 px-3 py-2 hover:bg-dark-800 rounded-lg transition-colors"
            >
              <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                <User className="w-5 h-5 text-white" />
              </div>
              <div className="hidden md:block text-left">
                <p className="text-sm font-semibold text-white">{user?.username || 'Demo User'}</p>
                <p className="text-xs text-dark-400">{user?.role || 'SOC Analyst'}</p>
              </div>
            </button>

            {showUserMenu && (
              <div className="absolute right-0 mt-2 w-48 bg-dark-800 border border-dark-700 rounded-lg shadow-xl py-2 animate-fadeIn z-50">
                <div className="px-4 py-2 border-b border-dark-700">
                  <p className="text-sm font-semibold text-white">{user?.username || 'Demo User'}</p>
                  <p className="text-xs text-dark-500">{user?.email || 'demo@lg-sotf.com'}</p>
                </div>
                <button
                  onClick={handleLogout}
                  className="w-full px-4 py-2 text-left text-sm text-red-400 hover:bg-dark-700 flex items-center gap-2 transition-colors"
                >
                  <LogOut className="w-4 h-4" />
                  Logout
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};

export default TopBar;