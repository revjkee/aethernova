import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import { Inter } from "next/font/google";
import React from "react";

// Оптимизированный системный шрифт с автогостингом через next/font (рекомендуется Next.js)
// Документация: next/font в App Router.  :contentReference[oaicite:1]{index=1}
const inter = Inter({
  subsets: ["latin", "cyrillic"],
  display: "swap", // уменьшает риск FOUT/FOIT; допускается Next.js.  :contentReference[oaicite:2]{index=2}
  variable: "--font-inter",
});

// Статическое Metadata API для SEO/шеринга (поддерживается App Router).
// Подробнее: Metadata API и OG в App Router.  :contentReference[oaicite:3]{index=3}
export const metadata: Metadata = {
  metadataBase: new URL("https://omnimind.example.com"),
  applicationName: "OmniMind Core Dashboard",
  title: {
    default: "OmniMind Core Dashboard",
    template: "%s | OmniMind",
  },
  description:
    "Промышленная панель управления OmniMind Core: наблюдаемость, конфигурация и аналитика.",
  icons: {
    icon: [{ url: "/icon.png", sizes: "32x32", type: "image/png" }],
    apple: [{ url: "/apple-touch-icon.png", sizes: "180x180", type: "image/png" }],
  },
  openGraph: {
    type: "website",
    siteName: "OmniMind Core",
    title: "OmniMind Core Dashboard",
    description:
      "Промышленная панель управления OmniMind Core: наблюдаемость, конфигурация и аналитика.",
    url: "https://omnimind.example.com",
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "OmniMind Core" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "OmniMind Core Dashboard",
    description:
      "Промышленная панель управления OmniMind Core: наблюдаемость, конфигурация и аналитика.",
    images: ["/og.png"],
  },
  category: "technology",
};

// Viewport можно задавать статически через export const viewport.
// Документация: generateViewport/viewport API.  :contentReference[oaicite:4]{index=4}
export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
  viewportFit: "cover",
  themeColor: [
    { media: "(prefers-color-scheme: dark)", color: "#0b0f19" },
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
  ],
};

// Root layout (обязателен): должен содержать <html> и <body>.  :contentReference[oaicite:5]{index=5}
export default function RootLayout({ children }: { children: React.ReactNode }) {
  // Если в ответе сервера выставлен CSP nonce (например, через middleware/headers),
  // прокинем его в inline-скрипт и next/script для корректной работы CSP.
  const cspNonce = headers().get("x-nonce") ?? undefined;

  return (
    <html
      lang="ru"
      dir="ltr"
      suppressHydrationWarning
      className={inter.variable}
      data-app="omnimind-core"
    >
      <head />
      <body
        // Базовая поддержка системной цветовой схемы + шрифт на всём приложении
        className="min-h-dvh antialiased"
      >
        {/* Инициализация темы до гидратации: предотвращает FOUC.
            Не хранит личные данные; читает system preference и localStorage('theme'). */}
        <script
          nonce={cspNonce}
          dangerouslySetInnerHTML={{
            __html: `
(function () {
  try {
    var key = 'theme';
    var stored = localStorage.getItem(key);
    var systemDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    var theme = stored ? stored : (systemDark ? 'dark' : 'light');
    if (!document.documentElement.dataset) document.documentElement.dataset = {};
    document.documentElement.dataset.theme = theme;
  } catch (e) { /* no-op */ }
}());
`.trim(),
          }}
        />
        {children}
      </body>
    </html>
  );
}
