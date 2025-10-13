import { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Metrics from './pages/Metrics';
import Logs from './pages/Logs';
import Alerts from './pages/Alerts';
import Settings from './pages/Settings';
import { NotificationProvider } from './components/NotificationSystem';

function App() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [darkMode, setDarkMode] = useState(false);

  return (
    <NotificationProvider>
      <Router>
        <div className={`min-h-screen bg-gray-50 dark:bg-gray-900 ${darkMode ? 'dark' : ''}`}>
          <div className="flex h-screen overflow-hidden">
            {/* Sidebar */}
            <Sidebar 
              isOpen={sidebarOpen} 
              onClose={() => setSidebarOpen(false)} 
            />
            
            {/* Main content */}
            <div className="flex-1 flex flex-col overflow-hidden">
              <Header 
                onMenuClick={() => setSidebarOpen(!sidebarOpen)}
                darkMode={darkMode}
                onDarkModeToggle={() => setDarkMode(!darkMode)}
              />
              
              <main className="flex-1 overflow-x-hidden overflow-y-auto bg-gray-50 dark:bg-gray-900">
                <div className="container mx-auto px-6 py-8">
                  <Routes>
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/metrics" element={<Metrics />} />
                    <Route path="/logs" element={<Logs />} />
                    <Route path="/alerts" element={<Alerts />} />
                    <Route path="/settings" element={<Settings />} />
                  </Routes>
                </div>
              </main>
            </div>
          </div>
        </div>
      </Router>
    </NotificationProvider>
  );
}

export default App;