"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  PropsWithChildren,
} from "react";

type ThemeName = "light" | "dark" | "system";

type ThemeContextValue = {
  theme: ThemeName;            // выбранное пользователем значение
  resolvedTheme: "light" | "dark"; // итоговая тема после разрешения "system"
  setTheme: (t: ThemeName) => void;
  toggleTheme: () => void;     // переключение light <-> dark (system не трогаем)
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

const STORAGE_KEY = "omnimind:theme";
const DATA_ATTR = "data-theme"; // пишем на <html data-theme="light|dark">
const COLOR_SCHEME_PROP = "color-scheme"; // системное свойство браузера

// Безопасный layout effect для CSR/SSR
const useIsoLayoutEffect =
  typeof window !== "undefined" ? useLayoutEffect : () => {};

// Применение темы к документу (idempotent)
function applyThemeToDocument(target: "light" | "dark", metaColor?: string) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;

  root.setAttribute(DATA_ATTR, target);
  // Это влияет на нативные компоненты прокрутки/форм
  root.style.setProperty(COLOR_SCHEME_PROP, target);

  // Обновляем theme-color (PWA / системный статусбар)
  const meta =
    document.querySelector<HTMLMetaElement>('meta[name="theme-color"]') ??
    (() => {
      const m = document.createElement("meta");
      m.setAttribute("name", "theme-color");
      document.head.appendChild(m);
      return m;
    })();

  // Если не передали цвет, используем CSS-переменную --theme-color (если определена),
  // иначе разумные дефолты.
  let color = metaColor;
  if (!color) {
    const computed = getComputedStyle(root).getPropertyValue("--theme-color").trim();
    color =
      computed ||
      (target === "dark" ? "#0B0B0F" : "#FFFFFF");
  }
  meta.setAttribute("content", color);
}

// Определение system-темы
function getSystemTheme(): "light" | "dark" {
  if (typeof window === "undefined" || typeof matchMedia === "undefined") {
    return "light";
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

// Безопасное чтение сохраненного значения
function readStoredTheme(): ThemeName | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    if (raw === "light" || raw === "dark" || raw === "system") return raw;
    return null;
  } catch {
    return null;
  }
}

// Безопасная запись
function writeStoredTheme(value: ThemeName) {
  try {
    localStorage.setItem(STORAGE_KEY, value);
  } catch {
    // ignore
  }
}

// Inline-скрипт для мгновенной установки темы ДО гидратации (избежание мигания)
// Возвращает строку JS для вставки в <script dangerouslySetInnerHTML>
export function getInlineThemeInitScript(
  fallback: ThemeName = "system",
  options?: { metaColor?: string }
) {
  // Нельзя использовать внешние переменные в этом инлайне — только самодостаточный код.
  const metaColor = options?.metaColor ?? "";
  return `
(function(){
  try {
    var STORAGE_KEY="${STORAGE_KEY}";
    var DATA_ATTR="${DATA_ATTR}";
    var COLOR_SCHEME_PROP="${COLOR_SCHEME_PROP}";
    var d=document, e=d.documentElement;
    function sys(){return (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches)?"dark":"light";}
    var v=null;
    try{v=localStorage.getItem(STORAGE_KEY)}catch(_){}
    var t=(v==="light"||v==="dark"||v==="system")?v:"${fallback}";
    var r=(t==="system")?sys():t;
    e.setAttribute(DATA_ATTR,r);
    e.style.setProperty(COLOR_SCHEME_PROP,r);
    var m=d.querySelector('meta[name="theme-color"]');
    if(!m){m=d.createElement("meta");m.setAttribute("name","theme-color");d.head.appendChild(m);}
    var c="${metaColor}";
    if(!c){
      var comp=getComputedStyle(e).getPropertyValue("--theme-color").trim();
      c=comp||(r==="dark"?"#0B0B0F":"#FFFFFF");
    }
    m.setAttribute("content",c);
  } catch(_){}
})();`.trim();
}

// Провайдер темы
export function ThemeProvider({
  children,
  defaultTheme = "system",
  metaThemeColor, // опционально переопределить цвет meta[theme-color]
}: PropsWithChildren<{ defaultTheme?: ThemeName; metaThemeColor?: string }>) {
  const [theme, setThemeState] = useState<ThemeName>(() => {
    // SSR: просто вернем defaultTheme, реальное применение произойдет в ефектах
    if (typeof window === "undefined") return defaultTheme;
    return readStoredTheme() ?? defaultTheme;
  });

  const systemThemeRef = useRef<"light" | "dark">(getSystemTheme());
  const resolvedTheme: "light" | "dark" =
    theme === "system" ? systemThemeRef.current : theme;

  // Применяем тему максимально рано (layout effect при CSR)
  useIsoLayoutEffect(() => {
    applyThemeToDocument(resolvedTheme, metaThemeColor);
  }, [resolvedTheme, metaThemeColor]);

  // Подписка на изменения system-темы
  useEffect(() => {
    if (typeof window === "undefined" || theme !== "system") return;

    const mql = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => {
      systemThemeRef.current = mql.matches ? "dark" : "light";
      applyThemeToDocument(systemThemeRef.current, metaThemeColor);
    };

    if ("addEventListener" in mql) {
      mql.addEventListener("change", onChange);
    } else {
      // Safari < 14
      // @ts-expect-error legacy
      mql.addListener(onChange);
    }

    return () => {
      if ("removeEventListener" in mql) {
        mql.removeEventListener("change", onChange);
      } else {
        // @ts-expect-error legacy
        mql.removeListener(onChange);
      }
    };
  }, [theme, metaThemeColor]);

  // Синхронизация между вкладками
  useEffect(() => {
    if (typeof window === "undefined") return;
    const onStorage = (ev: StorageEvent) => {
      if (ev.key !== STORAGE_KEY) return;
      const next = readStoredTheme();
      if (next && next !== theme) {
        setThemeState(next);
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [theme]);

  const setTheme = useCallback((t: ThemeName) => {
    setThemeState((prev) => {
      if (prev === t) return prev;
      writeStoredTheme(t);
      return t;
    });
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => {
      // Если system — переключаем относительно текущего разрешенного значения
      if (prev === "system") {
        return systemThemeRef.current === "dark" ? "light" : "dark";
      }
      return prev === "dark" ? "light" : "dark";
    });
  }, [setTheme]);

  const value = useMemo<ThemeContextValue>(
    () => ({
      theme,
      resolvedTheme: theme === "system" ? systemThemeRef.current : theme,
      setTheme,
      toggleTheme,
    }),
    [theme, setTheme, toggleTheme]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

// Хук доступа к теме
export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error("useTheme must be used within <ThemeProvider>");
  }
  return ctx;
}

/**
 * Пример интеграции в Next.js (app router):
 *
 * В layout.tsx внутри <head> вставьте:
 *
 * <script
 *   dangerouslySetInnerHTML={{ __html: getInlineThemeInitScript("system") }}
 * />
 *
 * Затем оберните тело:
 *
 * <ThemeProvider defaultTheme="system">
 *   {children}
 * </ThemeProvider>
 *
 * В CSS определите базовые токены:
 *
 * :root[data-theme="light"] {
 *   --theme-color: #ffffff;
 *   color-scheme: light;
 * }
 * :root[data-theme="dark"] {
 *   --theme-color: #0B0B0F;
 *   color-scheme: dark;
 * }
 */
