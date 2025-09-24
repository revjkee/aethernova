// src/shared/hooks/useTelegramTheme.ts
import { useEffect } from "react";
import { getTelegramTheme } from "../utils/telegramTheme";

export const useTelegramTheme = () => {
  useEffect(() => {
    const applyTheme = () => {
      const theme = getTelegramTheme();
      const root = document.documentElement;
      Object.entries(theme).forEach(([key, value]) =>
        root.style.setProperty(`--tg-${key.replace(/_/g, "-")}`, value),
      );
    };
    applyTheme();
  }, []);
};
