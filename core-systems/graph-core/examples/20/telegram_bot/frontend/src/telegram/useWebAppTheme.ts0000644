// src/telegram/useWebAppTheme.ts
import { useEffect, useState } from 'react';

type TelegramThemeParams = {
  bg_color: string;
  text_color: string;
  hint_color: string;
  link_color: string;
  button_color: string;
  button_text_color: string;
  secondary_bg_color: string;
};

declare global {
  interface Window {
    Telegram?: {
      WebApp?: {
        colorScheme: 'light' | 'dark';
        themeParams: TelegramThemeParams;
        onEvent: (event: string, handler: () => void) => void;
        offEvent: (event: string, handler: () => void) => void;
      };
    };
  }
}

export const useWebAppTheme = () => {
  const [theme, setTheme] = useState<TelegramThemeParams | null>(null);
  const [colorScheme, setColorScheme] = useState<'light' | 'dark'>('light');

  useEffect(() => {
    const webApp = window.Telegram?.WebApp;
    if (!webApp) return;

    const applyTheme = () => {
      setTheme(webApp.themeParams);
      setColorScheme(webApp.colorScheme);
    };

    applyTheme();
    webApp.onEvent('themeChanged', applyTheme);

    return () => {
      webApp.offEvent('themeChanged', applyTheme);
    };
  }, []);

  return {
    theme,
    colorScheme,
    isDark: colorScheme === 'dark',
  };
};
