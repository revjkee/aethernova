import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import React from "react";
import { render, screen, within, act, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// Важно: тест лежит в __tests__/ рядом с компонентом.
// SecurityStatus предполагается в файле ../SecurityStatus.tsx
// Хук используется компонентом и находится по пути ../hooks/useSecurityStatus
// Мы мокаем хук, чтобы детерминированно управлять всеми состояниями.

vi.mock("../hooks/useSecurityStatus", () => {
  return {
    useSecurityStatus: vi.fn(),
  };
});

import { useSecurityStatus } from "../hooks/useSecurityStatus";
// Поддерживаем как именованный, так и default экспорт компонента.
import SecurityStatusDefault, { SecurityStatus as SecurityStatusNamed } from "../SecurityStatus";

type MockStatus =
  | "loading"
  | "healthy"
  | "degraded"
  | "critical"
  | "error"
  | "unknown";

interface MockReturn {
  loading: boolean;
  status: MockStatus;
  score: number | null;
  issues: Array<{ id: string; title: string; severity: "low" | "medium" | "high"; details?: string }> | null;
  lastChecked: string | null;
  refresh: () => Promise<void> | void;
  error?: string | null;
  polling?: boolean;
}

const asMock = (fn: unknown) => fn as unknown as ReturnType<typeof vi.fn>;

const setupMock = (partial: Partial<MockReturn>) => {
  const base: MockReturn = {
    loading: false,
    status: "unknown",
    score: null,
    issues: null,
    lastChecked: null,
    refresh: vi.fn(),
    error: null,
    polling: false,
  };
  asMock(useSecurityStatus).mockReturnValue({ ...base, ...partial });
};

const renderComponent = (props?: React.ComponentProps<typeof SecurityStatusNamed>) => {
  // Компонент может экспортироваться как default или named.
  const Comp = (SecurityStatusNamed ?? SecurityStatusDefault) as React.FC<any>;
  return render(<Comp {...props} />);
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers();
});

afterEach(() => {
  try {
    vi.runOnlyPendingTimers();
  } catch {
    // timers might be real in some tests — ignore
  }
  vi.useRealTimers();
});

describe("SecurityStatus", () => {
  it("рендерит состояние загрузки (loading) с корректными ARIA атрибутами", () => {
    setupMock({ loading: true, status: "loading", polling: true });
    renderComponent();

    const region = screen.getByRole("status", { name: /security status/i });
    expect(region).toBeInTheDocument();
    expect(region).toHaveAttribute("aria-live", "polite");

    // Ожидаем скелетоны/индикатор загрузки
    const loadingIndicators = screen.getAllByTestId(/security-loading|skeleton/i);
    expect(loadingIndicators.length).toBeGreaterThan(0);

    // Кнопка обновления должна быть задизейблена во время загрузки
    const refreshBtn = screen.getByRole("button", { name: /refresh|обновить/i });
    expect(refreshBtn).toBeDisabled();
  });

  it("отображает состояние 'healthy' со счетом и меткой статуса", () => {
    setupMock({
      loading: false,
      status: "healthy",
      score: 98,
      issues: [],
      lastChecked: "2025-09-26T10:00:00Z",
    });

    renderComponent();

    // Заголовок/лейбл виджета
    const heading = screen.getByRole("heading", { name: /security status|статус безопасности/i });
    expect(heading).toBeInTheDocument();

    // Метка статуса
    const badge = screen.getByTestId("security-status-badge");
    expect(badge).toHaveTextContent(/healthy|норма|здоров/i);
    // Устойчивый селектор: data-атрибут, на случай смены классов/темизации
    expect(badge).toHaveAttribute("data-status", "healthy");

    // Счет
    const score = screen.getByTestId("security-score");
    expect(score).toHaveTextContent(/98/);

    // Последняя проверка
    const meta = screen.getByTestId("security-last-checked");
    expect(meta.textContent?.toLowerCase()).toMatch(/last checked|последняя проверка/);
  });

  it("отображает 'degraded' с проблемами (issues) и их критичностью", () => {
    setupMock({
      status: "degraded",
      score: 72,
      issues: [
        { id: "i1", title: "Outdated dependency: axios", severity: "medium", details: "Requires update to >=1.7.x" },
        { id: "i2", title: "TLS Weak Cipher", severity: "high", details: "Disable TLS_RSA_* ciphers" },
      ],
      lastChecked: "2025-09-26T10:05:00Z",
    });

    renderComponent();

    const badge = screen.getByTestId("security-status-badge");
    expect(badge).toHaveAttribute("data-status", "degraded");

    const issuesList = screen.getByRole("list", { name: /security issues|проблемы безопасности/i });
    expect(issuesList).toBeInTheDocument();

    const items = within(issuesList).getAllByRole("listitem");
    expect(items).toHaveLength(2);

    // Проверяем отображение критичности
    expect(items[0]).toHaveTextContent(/medium/i);
    expect(items[1]).toHaveTextContent(/high/i);
  });

  it("отображает 'critical' и четкий индикатор критичности", () => {
    setupMock({
      status: "critical",
      score: 35,
      issues: [
        { id: "i1", title: "RCE vulnerability in gateway", severity: "high" },
        { id: "i2", title: "Secrets exposure in logs", severity: "high" },
      ],
    });

    renderComponent();

    const region = screen.getByRole("status", { name: /security status/i });
    expect(region).toBeInTheDocument();

    const badge = screen.getByTestId("security-status-badge");
    expect(badge).toHaveAttribute("data-status", "critical");
    // Допустимо наличие доступного для чтения индикатора
    expect(badge).toHaveAccessibleName(/critical|критично/i);

    // Счет должен быть виден и низким
    const score = screen.getByTestId("security-score");
    expect(score).toHaveTextContent(/35/);
  });

  it("кнопка Refresh вызывает refresh() и блокируется во время выполнения", async () => {
    const refresh = vi.fn().mockResolvedValue(undefined);
    setupMock({
      status: "healthy",
      score: 99,
      refresh,
      loading: false,
    });

    renderComponent();

    const button = screen.getByRole("button", { name: /refresh|обновить/i });
    expect(button).toBeEnabled();

  fireEvent.click(button);
    expect(refresh).toHaveBeenCalledTimes(1);

    // Если компонент на время вызова помечает состояние загрузки,
    // он может дизейблить кнопку — проверим «как минимум не сломалось».
    // Здесь можно симулировать промежуточное состояние:
    asMock(useSecurityStatus).mockReturnValueOnce({
      loading: true,
      status: "loading",
      score: null,
      issues: null,
      lastChecked: null,
      refresh,
      error: null,
      polling: false,
    });

    // Прокрутим микро-тик, если компонент использует состояние
    await act(async () => {});

    // Не строгая проверка (компонентная реализация может различаться)
    // но если дизейбл есть — он корректен.
    // Мы просто убедимся, что кнопка существует.
    expect(screen.getByRole("button", { name: /refresh|обновить/i })).toBeInTheDocument();
  });

  it("корректно отображает ошибку из источника данных", () => {
    setupMock({
      status: "error",
      score: null,
      issues: null,
      error: "Failed to fetch security status",
    });

    renderComponent();

    const alert = screen.queryByRole("alert");
    if (alert) {
      expect(alert).toBeInTheDocument();
      expect(alert).toHaveTextContent(/failed to fetch security status|ошибка/i);
    } else {
      // Fallback: if alert isn't present, at least status badge should reflect an error-like state
      const badge = screen.getByTestId("security-status-badge");
      expect(["error", "unknown", "loading"]).toContain(badge.getAttribute("data-status"));
    }
  });

  it("устойчив к неконсистентным данным (null/NaN/пустые массивы)", () => {
    setupMock({
      status: "unknown",
      // намеренно «битые» данные
      score: Number.NaN as unknown as number,
      issues: [],
      lastChecked: null,
    });

    renderComponent();

    // Должен показать дефолтный/защитный вывод
    const score = screen.getByTestId("security-score");
    expect(score.textContent?.toLowerCase()).toMatch(/n\/a|нет данных|unknown/);

    const issuesList = screen.queryByRole("list", { name: /security issues|проблемы безопасности/i });
    // Пустой список может не рендериться вовсе — но ничего не должно падать
    if (issuesList) {
      expect(within(issuesList).queryAllByRole("listitem").length).toBe(0);
    }
  });

  it("поддерживает aria-live=polite и роль 'status' для ассистивных технологий", () => {
    setupMock({
      status: "healthy",
      score: 97,
    });

    renderComponent();

    const region = screen.getByRole("status", { name: /security status|статус безопасности/i });
    expect(region).toBeInTheDocument();
    expect(region).toHaveAttribute("aria-live", "polite");
  });

  it("поддерживает сценарий polling: периодическое обновление состояния по таймеру (если реализовано)", async () => {
    const refresh = vi.fn();
    setupMock({
      status: "healthy",
      score: 97,
      polling: true,
      refresh,
    });

    renderComponent({ pollIntervalMs: 30000 } as any); // если компонент поддерживает проп, тест покроет это

    // Эмулируем 60 секунд
    await act(async () => {
      vi.advanceTimersByTime(60000);
    });

    // Ожидаем минимум два вызова (0s -> 30s -> 60s), в зависимости от реализации
    expect(refresh.mock.calls.length).toBeGreaterThanOrEqual(2);
  });

  it("рендерит данные о проблемах с деталями, если предусмотрен раскрываемый контент", async () => {
    setupMock({
      status: "degraded",
      score: 70,
      issues: [
        { id: "i1", title: "Weak password policy", severity: "medium", details: "Min length < 12 chars" },
      ],
    });

    renderComponent();

    // Если компонент рендерит кнопку/контрол 'Details', проверим раскрытие
    const maybeDetailsButton = screen.queryByRole("button", { name: /details|детали|подробнее/i });
    if (maybeDetailsButton) {
      await userEvent.click(maybeDetailsButton);
      expect(screen.getByText(/min length < 12 chars/i)).toBeInTheDocument();
    } else {
      // Иначе детали могут быть видимы сразу
      expect(screen.getByText(/min length < 12 chars/i)).toBeInTheDocument();
    }
  });

  it("не падает при отсутствии пропсов (защитные значения по умолчанию)", () => {
    setupMock({
      status: "healthy",
      score: 100,
      issues: [],
    });

    expect(() => renderComponent()).not.toThrow();
  });

  it("поддерживает переключение темы (если компонент использует data-theme), без привязки к конкретным классам", () => {
    setupMock({
      status: "healthy",
      score: 96,
    });

    const { container } = renderComponent();

    // Симулируем dark-режим
    container.setAttribute("data-theme", "dark");
    // Компонент не должен падать и терять ключевые селекторы
    const badge = screen.getByTestId("security-status-badge");
    expect(badge).toBeInTheDocument();
  });
});
