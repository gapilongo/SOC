import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  AlertCircle, 
  BarChart3, 
  Cpu, 
  Settings, 
  Shield,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';

const Sidebar = ({ isOpen, onToggle }) => {
  const menuItems = [
    { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard, badge: null },
    { name: 'Alerts', path: '/alerts', icon: AlertCircle, badge: 'live' },
    { name: 'Analytics', path: '/analytics', icon: BarChart3, badge: null },
    { name: 'Agents', path: '/agents', icon: Cpu, badge: null },
    { name: 'Settings', path: '/settings', icon: Settings, badge: null }
  ];

  return (
    <aside className={`fixed left-0 top-0 h-screen bg-dark-900/95 backdrop-blur-xl border-r border-dark-800 transition-all duration-300 z-50 ${isOpen ? 'w-64' : 'w-20'}`}>
      <div className="h-16 flex items-center justify-between px-4 border-b border-dark-800">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl flex items-center justify-center shadow-lg">
            <Shield className="w-6 h-6 text-white" />
          </div>
          {isOpen && (
            <div className="animate-fadeIn">
              <h1 className="text-lg font-bold text-white">LG-SOTF</h1>
              <p className="text-xs text-dark-400">SOC Platform</p>
            </div>
          )}
        </div>
      </div>

      <button
        onClick={onToggle}
        className="absolute -right-3 top-20 w-6 h-6 bg-dark-800 border border-dark-700 rounded-full flex items-center justify-center hover:bg-dark-700 transition-colors"
      >
        {isOpen ? <ChevronLeft className="w-4 h-4 text-dark-400" /> : <ChevronRight className="w-4 h-4 text-dark-400" />}
      </button>

      <nav className="mt-6 px-3">
        <ul className="space-y-2">
          {menuItems.map((item) => (
            <li key={item.path}>
              <NavLink
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-3 rounded-lg transition-all group ${
                    isActive
                      ? 'bg-gradient-to-r from-blue-500 to-purple-600 text-white shadow-lg'
                      : 'text-dark-400 hover:bg-dark-800 hover:text-white'
                  }`
                }
              >
                <item.icon className="w-5 h-5 flex-shrink-0" />
                {isOpen && (
                  <>
                    <span className="flex-1 font-medium animate-fadeIn">{item.name}</span>
                    {item.badge && (
                      <span className="px-2 py-0.5 text-xs font-bold bg-red-500 text-white rounded-full animate-pulse">
                        {item.badge}
                      </span>
                    )}
                  </>
                )}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      {isOpen && (
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-dark-800 animate-fadeIn">
          <div className="bg-dark-800/50 rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-dark-400">SYSTEM STATUS</span>
              <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
            </div>
            <p className="text-xs text-dark-500">All systems operational</p>
          </div>
        </div>
      )}
    </aside>
  );
};

export default Sidebar;