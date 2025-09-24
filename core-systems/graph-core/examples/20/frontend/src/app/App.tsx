// src/app/App.tsx

import React, { useEffect, Suspense, lazy } from "react"
import { BrowserRouter as Router } from "react-router-dom"
import { ErrorBoundary } from "@/shared/components/ErrorBoundary"
import { Layout } from "@/shared/layout/Layout"
import { ThemeProvider } from "@/shared/ui/ThemeProvider"
import { AuthProvider } from "@/features/auth/context/AuthContext"
import { TelemetryAgent } from "@/features/monitoring/TelemetryAgent"
import { TokenRefresher } from "@/features/auth/components/TokenRefresher"
import { GlobalHotkeys } from "@/shared/components/GlobalHotkeys"
import { SecureOverlay } from "@/features/security/components/SecureOverlay"
import { AiGuardrails } from "@/features/security/AiGuardrails"
import { SessionTracer } from "@/features/monitoring/SessionTracer"
import { ErrorTracker } from "@/features/monitoring/ErrorTracker"
import { IntlProviderWrapper } from "@/shared/i18n/IntlProviderWrapper"
import { ConsentManager } from "@/features/privacy/ConsentManager"
import { EventBusProvider } from "@/shared/utils/EventBus"
import { ToastContainer } from "react-toastify"
import { MotionWrapper } from "@/shared/ui/MotionWrapper"
import { AccessibilityAnnouncer } from "@/shared/ui/AccessibilityAnnouncer"
import { WorkerManager } from "@/features/performance/WorkerManager"
import { ModalProvider } from "@/shared/components/ModalProvider"
import { AnalyticsSync } from "@/features/monitoring/AnalyticsSync"
import { useSystemStatusCheck } from "@/shared/hooks/useSystemStatusCheck"

import "@/shared/styles/global.css"
import "react-toastify/dist/ReactToastify.css"

const AppRouter = lazy(() => import("./router"))

export const App = (): JSX.Element => {
  useSystemStatusCheck()

  useEffect(() => {
    // Mount-level performance marker
    performance.mark("app-mounted")
  }, [])

  return (
    <ErrorBoundary fallback={<div className="error-screen">Critical failure</div>}>
      <Suspense fallback={<div className="loading-screen">Initializing...</div>}>
        <Router>
          <AuthProvider>
            <ThemeProvider>
              <IntlProviderWrapper>
                <EventBusProvider>
                  <ModalProvider>
                    <MotionWrapper>
                      <Layout>
                        <AppRouter />
                      </Layout>
                      <TokenRefresher />
                      <TelemetryAgent />
                      <AnalyticsSync />
                      <SessionTracer />
                      <ErrorTracker />
                      <GlobalHotkeys />
                      <AiGuardrails />
                      <SecureOverlay />
                      <ConsentManager />
                      <AccessibilityAnnouncer />
                      <WorkerManager />
                      <ToastContainer
                        position="bottom-right"
                        autoClose={5000}
                        hideProgressBar
                        newestOnTop
                        closeOnClick
                        rtl={false}
                        pauseOnFocusLoss
                        draggable
                        pauseOnHover
                        theme="dark"
                      />
                    </MotionWrapper>
                  </ModalProvider>
                </EventBusProvider>
              </IntlProviderWrapper>
            </ThemeProvider>
          </AuthProvider>
        </Router>
      </Suspense>
    </ErrorBoundary>
  )
}

export default App
