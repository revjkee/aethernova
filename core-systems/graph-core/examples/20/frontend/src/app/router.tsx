import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom'
import { Suspense, lazy } from 'react'
import { useAuth } from '@/shared/hooks/useAuth'
import { Layout } from '@/shared/layout/Layout'
import { LoadingScreen } from '@/shared/components/LoadingScreen'
import { ErrorBoundary } from '@/shared/components/ErrorBoundary'
import { routeGuard } from '@/shared/security/routeGuard'
import { monitorRoute } from '@/shared/monitoring/monitorRoute'

// Lazy loading critical pages
const HomePage = lazy(() => import('@/pages/HomePage'))
const HRDashboard = lazy(() => import('@/pages/HRDashboard'))
const AgentControl = lazy(() => import('@/pages/AgentControl'))
const GovernancePanel = lazy(() => import('@/pages/GovernancePanel'))
const EthicsAnalyzer = lazy(() => import('@/pages/EthicsAnalyzer'))
const NotFound = lazy(() => import('@/pages/NotFound'))

export const AppRouter = () => {
  const { isAuthenticated, roles } = useAuth()

  const GuardedRoute = ({
    element: Component,
    allowedRoles,
  }: {
    element: JSX.Element
    allowedRoles: string[]
  }) => {
    const access = routeGuard(isAuthenticated, roles, allowedRoles)
    if (!access) return <Navigate to="/" replace />
    return Component
  }

  return (
    <Router>
      <ErrorBoundary>
        <Suspense fallback={<LoadingScreen />}>
          <Layout>
            <Routes>
              <Route path="/" element={<HomePage />} />
              <Route
                path="/hr"
                element={monitorRoute(<GuardedRoute element={<HRDashboard />} allowedRoles={['hr', 'admin']} />, 'HRDashboard')}
              />
              <Route
                path="/agents"
                element={monitorRoute(<GuardedRoute element={<AgentControl />} allowedRoles={['admin', 'agent-manager']} />, 'AgentControl')}
              />
              <Route
                path="/governance"
                element={monitorRoute(<GuardedRoute element={<GovernancePanel />} allowedRoles={['governor', 'admin']} />, 'GovernancePanel')}
              />
              <Route
                path="/ethics"
                element={monitorRoute(<GuardedRoute element={<EthicsAnalyzer />} allowedRoles={['ethics', 'admin']} />, 'EthicsAnalyzer')}
              />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Layout>
        </Suspense>
      </ErrorBoundary>
    </Router>
  )
}
