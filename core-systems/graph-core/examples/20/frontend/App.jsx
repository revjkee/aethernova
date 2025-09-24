import React, { Suspense, useEffect } from "react";
import { BrowserRouter as Router } from "react-router-dom";
import { useAppInit } from "@/shared/hooks/useAppInit";
import { AppRoutes } from "@/app/providers/router";
import { AppErrorBoundary } from "@/shared/lib/errors/AppErrorBoundary";
import { WebAppOverlay } from "@/widgets/WebAppOverlay";
import { Toaster } from "@/shared/ui/Toaster";
import { TonConnectUIProvider } from "@tonconnect/ui-react";
import { tonConfig } from "@/shared/config/ton";
import { SessionProvider } from "@/shared/lib/session";
import { ThemeProvider } from "@/shared/ui/theme";
import { useSecurityGuards } from "@/shared/lib/security/guards";
import { GlobalAIOverlay } from "@/widgets/GlobalAIOverlay";
import { detectWebApp } from "@/shared/lib/platform";

export const App = () => {
  useAppInit(); // Инициализация сессий, тем, языка и авторизации
  useSecurityGuards(); // Защита от XSS, токенов, hijack

  useEffect(() => {
    detectWebApp(); // установка флагов WebApp, Telegram Web или Mobile
  }, []);

  return (
    <AppErrorBoundary>
      <Suspense fallback={<div className="loading-screen">Загрузка...</div>}>
        <TonConnectUIProvider manifestUrl={tonConfig.manifestUrl}>
          <SessionProvider>
            <ThemeProvider defaultTheme="system" storageKey="theme">
              <Router>
                <AppRoutes />
                <WebAppOverlay />
                <GlobalAIOverlay />
                <Toaster position="top-center" />
              </Router>
            </ThemeProvider>
          </SessionProvider>
        </TonConnectUIProvider>
      </Suspense>
    </AppErrorBoundary>
  );
};

export default App;
