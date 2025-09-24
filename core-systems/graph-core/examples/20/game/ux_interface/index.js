// index.js
// Центральная точка инициализации UX-контекстов и провайдеров TeslaAI Genesis

import React from 'react';

// Провайдеры контекста
import { UXProvider } from './UXContext';
import { InputProvider } from './InputContext';

// Дополнительные провайдеры (если внедрены)
import { ThemeProvider } from '../theme/ThemeManager';
import { AccessibilityProvider } from '../accessibility/AccessibilityContext';
import { NotificationProvider } from '../dialogs/NotificationContext';

// Логгирование событий UX
import { logUXInit } from '../../logging/telemetry/uxTelemetry';

export function UXInterfaceRoot({ children }) {
  // Лог при монтировании
  React.useEffect(() => {
    logUXInit({ timestamp: Date.now(), source: 'UXInterfaceRoot' });
  }, []);

  return (
    <ThemeProvider>
      <AccessibilityProvider>
        <NotificationProvider>
          <InputProvider>
            <UXProvider>
              {children}
            </UXProvider>
          </InputProvider>
        </NotificationProvider>
      </AccessibilityProvider>
    </ThemeProvider>
  );
}
