// src/shared/utils/telegramTheme.ts
export const getTelegramTheme = () => {
  const tg = (window as any).Telegram?.WebApp;
  const theme = tg?.themeParams || {};
  return {
    bg_color: theme.bg_color || "#ffffff",
    text_color: theme.text_color || "#000000",
    hint_color: theme.hint_color || "#999999",
    link_color: theme.link_color || "#1e90ff",
    button_color: theme.button_color || "#2ea6ff",
    button_text_color: theme.button_text_color || "#ffffff",
    secondary_bg_color: theme.secondary_bg_color || "#f4f4f4",
  };
};
