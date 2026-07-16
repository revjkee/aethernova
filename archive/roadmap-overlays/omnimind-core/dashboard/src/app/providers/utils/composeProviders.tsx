/* eslint-disable @typescript-eslint/no-explicit-any */
import React, {
  ComponentType,
  PropsWithChildren,
  ReactNode,
  useMemo,
  useRef,
} from "react";

/**
 * Базовый тип провайдера: React-компонент, принимающий children и произвольные props.
 */
export type Provider<P = Record<string, unknown>> = ComponentType<
  PropsWithChildren<P>
>;

/**
 * Спецификация включения провайдера:
 * - как сам провайдер (будет использован с пустыми пропсами),
 * - как кортеж [Провайдер, props],
 * - как объект со свойствами, включая условие when и приоритет priority.
 */
export type ProviderSpec<P = any> =
  | Provider<P>
  | [Provider<P>, P?]
  | {
      provider: Provider<P>;
      props?: P;
      /** Условие включения провайдера (по умолчанию true). */
      when?: boolean;
      /** Порядок применения: меньше — раньше. По умолчанию 100. */
      priority?: number;
      /** Человекочитаемое имя для дебага. */
      name?: string;
    };

/**
 * Настройки компоновщика.
 */
export type ComposeOptions = {
  /** Включить ErrorBoundary вокруг дерева провайдеров. */
  withBoundary?: boolean;
  /** Имя компоновки для displayName и логов. */
  name?: string;
  /** В dev-режиме включать предупреждения. */
  devWarnings?: boolean;
};

/**
 * Свой Bailout Error для ErrorBoundary.
 */
class ProviderBoundaryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProviderBoundaryError";
  }
}

/**
 * Простой ErrorBoundary без сторонних зависимостей.
 * SSR-safe: не использует browser-only API.
 */
class ProviderErrorBoundary extends React.Component<
  PropsWithChildren<{ fallback?: ReactNode; name?: string }>
> {
  state = { hasError: false };

  static getDerivedStateFromError(): { hasError: boolean } {
    return { hasError: true };
  }

  componentDidCatch(error: unknown) {
    if (process.env.NODE_ENV !== "production") {
      // eslint-disable-next-line no-console
      console.error("[ProviderErrorBoundary]", this.props.name ?? "", error);
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        this.props.fallback ?? (
          <div style={{ display: "none" }} aria-hidden="true" />
        )
      );
    }
    return this.props.children as React.ReactElement;
  }
}

/**
 * Нормализует входную спецификацию к унифицированной форме.
 */
function normalizeSpec(entry: ProviderSpec): {
  provider: Provider<any>;
  props: Record<string, unknown>;
  when: boolean;
  priority: number;
  name: string;
} {
  if (typeof entry === "function") {
    return {
      provider: entry as Provider<any>,
      props: {},
      when: true,
      priority: 100,
      name: entry.displayName || entry.name || "AnonymousProvider",
    };
  }

  if (Array.isArray(entry)) {
    const [prov, p = {}] = entry;
    return {
      provider: prov as Provider<any>,
      props: (p as Record<string, unknown>) ?? {},
      when: true,
      priority: 100,
      name: (prov as Provider<any>).displayName || prov.name || "TupleProvider",
    };
  }

  const prov = entry.provider;
  return {
    provider: prov as Provider<any>,
    props: (entry.props as Record<string, unknown>) ?? {},
    when: entry.when ?? true,
    priority: entry.priority ?? 100,
    name:
      entry.name ||
      (prov as Provider<any>).displayName ||
      prov.name ||
      "ObjectProvider",
  };
}

/**
 * Собирает провайдеров в единый корневой провайдер.
 *
 * Пример:
 * const AppProviders = composeProviders([
 *   ThemeProvider,
 *   [AuthProvider, { session }],
 *   { provider: OTELProvider, props: { tracer }, when: isProd, priority: 50 },
 * ], { withBoundary: true, name: "OmniMindProviders" });
 *
 * <AppProviders><App /></AppProviders>
 */
export function composeProviders(
  specs: ProviderSpec[],
  options: ComposeOptions = {}
): Provider {
  const { withBoundary = true, name = "ComposedProviders", devWarnings = true } =
    options;

  const normalized = specs.map(normalizeSpec).filter((s) => s.when);

  // Стабильная сортировка по priority, затем по имени — для предсказуемости.
  normalized.sort((a, b) => {
    if (a.priority !== b.priority) return a.priority - b.priority;
    return a.name.localeCompare(b.name);
  });

  if (devWarnings && process.env.NODE_ENV !== "production") {
    // Поиск дубликатов по имени компонента для раннего обнаружения ошибок порядка/дублирования.
    const names = normalized.map((n) => n.name);
    const seen = new Set<string>();
    const dups: string[] = [];
    for (const n of names) {
      if (seen.has(n)) dups.push(n);
      else seen.add(n);
    }
    if (dups.length > 0) {
      // eslint-disable-next-line no-console
      console.warn(
        `[composeProviders:${name}] Duplicate provider names detected: ${dups.join(
          ", "
        )}`
      );
    }
  }

  const Composed: Provider = ({ children }) => {
    // Мемоизация дерева провайдеров по списку спецификаций.
    const tree = useMemo(() => {
      let node: ReactNode = children;

      for (let i = normalized.length - 1; i >= 0; i--) {
        const { provider: Prov, props, name: provName } = normalized[i];

        if (process.env.NODE_ENV !== "production" && !Prov) {
          throw new ProviderBoundaryError(
            `[composeProviders:${name}] Provider "${provName}" is undefined`
          );
        }

        node = <Prov {...props}>{node}</Prov>;
      }

      return node;
      // Зависимости: провайдеры и их пропсы.
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [
      children,
      // Ключ для "структурной" мемоизации: список провайдеров и json пропсов.
      // В runtime избегаем тяжелого JSON.stringify, заменяем на ссылки+приоритеты+имена.
      ...normalized.map((n) => n.provider),
      ...normalized.map((n) => n.priority),
      ...normalized.map((n) => n.name),
      // Пропсы могут быть новыми по ссылке — потребитель должен следить за стабильностью.
      ...normalized.map((n) => n.props),
    ]);

    // Хук-сторожок: один раз логируем итоговый порядок.
    const loggedOnceRef = useRef(false);
    if (
      devWarnings &&
      process.env.NODE_ENV !== "production" &&
      !loggedOnceRef.current
    ) {
      loggedOnceRef.current = true;
      // eslint-disable-next-line no-console
      console.debug(
        `[composeProviders:${name}] Order: ${normalized
          .map((n) => `${n.priority}:${n.name}`)
          .join(" -> ")}`
      );
    }

    if (withBoundary) {
      return (
        <ProviderErrorBoundary
          name={name}
          fallback={<div style={{ display: "none" }} aria-hidden="true" />}
        >
          {tree}
        </ProviderErrorBoundary>
      );
    }
    return <>{tree}</>;
  };

  Composed.displayName = name;
  return Composed;
}

/**
 * Сахар: фабрика компоновщика с предустановленными опциями.
 * Удобно, если в проекте несколько независимых наборов провайдеров.
 */
export function createProviderComposer(defaults?: ComposeOptions) {
  return (specs: ProviderSpec[], opts?: ComposeOptions) =>
    composeProviders(specs, { ...defaults, ...opts });
}

/**
 * Пример строгих типов для провайдеров с пропсами.
 * Оставлено в файле намеренно, чтобы облегчить подключение.
 */
// type AuthProviderProps = { session?: unknown };
// declare const AuthProvider: Provider<AuthProviderProps>;

// type OTELProviderProps = { tracer?: unknown };
// declare const OTELProvider: Provider<OTELProviderProps>;

// type ThemeProviderProps = { initial?: "light" | "dark" };
// declare const ThemeProvider: Provider<ThemeProviderProps>;

// export const AppProviders = composeProviders(
//   [
//     { provider: ThemeProvider, props: { initial: "dark" }, priority: 10 },
//     [AuthProvider, { session: undefined }],
//     { provider: OTELProvider, props: { tracer: undefined }, when: true, priority: 50 },
//   ],
//   { withBoundary: true, name: "OmniMindProviders" }
// );
