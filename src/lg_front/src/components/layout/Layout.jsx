import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './SideBar';
import TopBar from './TopBar';

const Layout = () => {
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="min-h-screen bg-dark-950 flex relative overflow-hidden">
      {/* Background effects */}
      <div className="fixed inset-0 grid-background opacity-10 pointer-events-none"></div>
      <div className="fixed top-0 right-0 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl pointer-events-none"></div>
      <div className="fixed bottom-0 left-0 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl pointer-events-none"></div>

      {/* Sidebar */}
      <Sidebar isOpen={sidebarOpen} onToggle={() => setSidebarOpen(!sidebarOpen)} />

      {/* Main content */}
      <div className={`flex-1 flex flex-col transition-all duration-300 ${sidebarOpen ? 'ml-64' : 'ml-20'}`}>
        <TopBar onMenuClick={() => setSidebarOpen(!sidebarOpen)} />
        
        <main className="flex-1 p-6 relative z-10 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default Layout;