import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { DashboardPage } from './pages/DashboardPage';
import { DataSourcesPage } from './pages/DataSourcesPage';
import { PipelinesPage } from './pages/PipelinesPage';
import { DataQualityPage } from './pages/DataQualityPage';
import { AnalyticsPage } from './pages/AnalyticsPage';
import { MonitoringPage } from './pages/MonitoringPage';
import { SettingsPage } from './pages/SettingsPage';
import { useDefaultLanguage } from './hooks/useDefaultLanguage';

function App() {
  useDefaultLanguage();

  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/sources" element={<DataSourcesPage />} />
          <Route path="/pipelines" element={<PipelinesPage />} />
          <Route path="/quality" element={<DataQualityPage />} />
          <Route path="/analytics" element={<AnalyticsPage />} />
          <Route path="/monitoring" element={<MonitoringPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;