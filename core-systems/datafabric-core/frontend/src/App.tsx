import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';

// Providers
import { ThemeProvider } from './components/common/ThemeProvider';
import { AuthProvider } from './components/common/AuthProvider';
import { ErrorBoundary } from './components/common/ErrorBoundary';

// Layout
import { Layout } from './components/layout/Layout';

// Pages
import {
  Dashboard,
  DataCatalog,
  Pipelines,
  Analytics,
  Governance,
  Settings
} from './pages';

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      cacheTime: 1000 * 60 * 10, // 10 minutes
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

const App: React.FC = () => {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider>
          <AuthProvider>
            <Router>
              <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors">
                <Layout>
                  <Routes>
                    <Route path="/" element={<Navigate to="/dashboard" replace />} />
                    <Route path="/dashboard" element={<Dashboard />} />
                    <Route path="/catalog" element={<DataCatalog />} />
                    <Route path="/pipelines" element={<Pipelines />} />
                    <Route path="/analytics" element={<Analytics />} />
                    <Route path="/governance" element={<Governance />} />
                    <Route path="/settings" element={<Settings />} />
                    <Route path="*" element={<Navigate to="/dashboard" replace />} />
                  </Routes>
                </Layout>
              </div>
            </Router>
          </AuthProvider>
        </ThemeProvider>

      </QueryClientProvider>
    </ErrorBoundary>
  );
};

export default App;
