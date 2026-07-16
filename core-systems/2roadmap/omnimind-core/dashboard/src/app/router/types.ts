/* eslint-disable @typescript-eslint/consistent-type-definitions */
/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Типы маршрутизации для dashboard.
 * Без внешних зависимостей: только типы и утилиты типов/генериков.
 */

import type React from "react";

/* -------------------------------------------
 * БАЗОВЫЕ МОДЕЛИ И ВСПОМОГАТЕЛЬНЫЕ ТИПЫ
 * -----------------------------------------*/

/** Путь маршрута в стиле '/users/:id/edit' или '/files/*' */
export type RoutePath = `/${string}`;

/** Шаблон ключа i18n, например 'app.routes.users.title' */
export type LocaleKey = `app.${string}`;

/** Идентификаторы ролей и прав доступа */
export type RoleId = `role:${string}`;
export type PermissionId = `perm:${string}`;

/** Модель права (можно расширять доменно) */
export type Permission =
  | PermissionId
  | "perm:read"
  | "perm:write"
  | "perm:update"
  | "perm:delete"
  | "perm:admin";

/** RBAC-спека для маршрута */
export type RBACSpec = {
  /** Требуются ли любые аутентифицированные пользователи */
  requiresAuth?: boolean;
  /** Разрешенные роли (хватает одной) */
  allowRoles?: RoleId[];
  /** Обязательные права (нужны все) */
  requireAll?: Permission[];
  /** Достаточные права (хватает одного из) */
  requireAny?: Permission[];
};

/** Примитивная модель состояния навигации (history.state) */
export type NavigationState = Record<string, unknown> | undefined;

/** Редирект как результат guard/loader */
export type Redirect = {
  to: RoutePath | string;
  /** replace в history */
  replace?: boolean;
  /** состояние history */
  state?: NavigationState;
};

/** Результат Guard: пропустить, запретить или редиректить */
export type GuardResult = boolean | Redirect | Promise<boolean | Redirect>;

/** Контекст выполнения guard/loader/action */
export type RouteContext<P extends Record<string, string> = Record<string, string>> = {
  /** Параметры пути */
  params: P;
  /** Параметры query (строковые ключи/значения) */
  query: Record<string, string | string[]>;
  /** Абсолютный текущий URL (если доступен) */
  url?: URL;
  /** Пользователь/сессия/контекст безопасности (любой) */
  auth?: unknown;
  /** Произвольные инжектируемые сервисы (IoC) */
  services?: Record<string, unknown>;
  /** Сигнал отмены длительных операций (fetch и т.д.) */
  signal?: AbortSignal;
};

/* -------------------------------------------
 * УТИЛИТЫ ТИПОВ: ИЗВЛЕЧЕНИЕ ПАРАМЕТРОВ ПУТИ
 * -----------------------------------------*/

/** Нормализуем сегменты пути, отбрасывая пустые */
type _Segments<S extends string> = S extends `${infer A}/${infer B}`
  ? A extends "" ? _Segments<B> : [A, ..._Segments<B>]
  : S extends "" ? [] : [S];

/** Извлекаем имена параметров ':id' и wildcard '*' как 'splat' */
type _ParamName<S extends string> =
  S extends `:${infer N}` ? N :
  S extends "*" ? "splat" :
  never;

/** Собираем имена всех параметров из массива сегментов */
type _CollectParams<T extends readonly string[], Acc extends string = never> =
  T extends [infer H, ...infer R]
    ? H extends string
      ? R extends string[]
        ? _CollectParams<R, Acc | _ParamName<H>>
        : Acc | _ParamName<H>
      : Acc
    : Acc;

/** Преобразуем union имен в объект {name: string} */
type _UnionToObj<U extends string> =
  [U] extends [never] ? {} : { [K in U]: string };

/** Публичный тип: из строки пути RoutePath получаем объект параметров */
export type PathParams<S extends RoutePath> = _UnionToObj<_CollectParams<_Segments<S>>>;

/** Пример:
 * PathParams<"/users/:id/edit"> -> { id: string }
 * PathParams<"/files/*">        -> { splat: string }
 */

/* -------------------------------------------
 * LOADER / ACTION / GUARD
 * -----------------------------------------*/

export type RouteLoader<Params extends Record<string, string> = Record<string, string>, TData = unknown> =
  (ctx: RouteContext<Params>) => Promise<TData> | TData;

export type RouteAction<Params extends Record<string, string> = Record<string, string>, TResult = unknown> =
  (ctx: RouteContext<Params>) => Promise<TResult> | TResult;

export type NavigationGuard<Params extends Record<string, string> = Record<string, string>> =
  (ctx: RouteContext<Params>) => GuardResult;

/* -------------------------------------------
 * МЕТАДАННЫЕ МАРШРУТА
 * -----------------------------------------*/

export type BreadcrumbItem = {
  /** Текст хлебной крошки (i18n ключ или строка) */
  label: string | LocaleKey;
  /** Явная ссылка, если крошка кликабельна */
  to?: string;
  /** Арбитрарная мета */
  extra?: Record<string, unknown>;
};

export type RouteMeta = {
  /** Заголовок страницы (i18n ключ или строка) */
  title?: string | LocaleKey;
  /** Описание для SEO */
  description?: string;
  /** Иконка (имя, JSX или arbitrary payload) */
  icon?: React.ReactNode | string;
  /** Позиция в меню/навигации (чем меньше — тем выше) */
  order?: number;
  /** Спрятать из меню/быстрой навигации */
  hidden?: boolean;
  /** Раздел/layout-слот (например, 'dashboard' | 'auth' | 'blank') */
  layout?: string;
  /** RBAC-политики */
  access?: RBACSpec;
  /** Генератор хлебных крошек на основе контекста/данных */
  breadcrumb?: (ctx: { params: Record<string, string>; data?: unknown }) => BreadcrumbItem[];
  /** Произвольная расширяемая мета */
  extra?: Record<string, unknown>;
};

/* -------------------------------------------
 * КОМПОНЕНТЫ И ОШИБКИ
 * -----------------------------------------*/

/** Любой React-компонент страницы */
export type RouteComponent<P = any> =
  React.ComponentType<P> | React.LazyExoticComponent<React.ComponentType<P>>;

/** Компонент ошибки для boundary конкретного маршрута */
export type RouteErrorComponent =
  React.ComponentType<{ error: Error }> | React.LazyExoticComponent<React.ComponentType<{ error: Error }>>;

/* -------------------------------------------
 * ОПРЕДЕЛЕНИЕ МАРШРУТА
 * -----------------------------------------*/

/** Статический/шаблонный путь или индекс */
export type RoutePathLike = RoutePath | "";

/** Общее определение маршрута.
 * P — тип параметров, автоматически выводится из path, если path — литерал. */
export type RouteDefinition<
  Path extends RoutePathLike = RoutePathLike,
  P extends Record<string, string> = Path extends RoutePath ? PathParams<Path> : Record<string, string>,
  TData = unknown
> = {
  /** Уникальный ID маршрута (используется в меню/линкбилдере) */
  id: string;
  /** Путь маршрута (литерал предпочтителен для лучшего вывода типов) */
  path: Path;
  /** Дочерние маршруты */
  children?: RouteDefinition<any, any, any>[];

  /** Компонент представления */
  element?: RouteComponent;
  /** Error boundary на уровень маршрута */
  errorElement?: RouteErrorComponent;

  /** Loader (SSR/CSR) */
  loader?: RouteLoader<P, TData>;
  /** Action (мутация/submit) */
  action?: RouteAction<P, unknown>;

  /** Guards — выполняются до рендеринга; первый false или Redirect прерывает цепочку */
  guards?: NavigationGuard<P>[];

  /** Метаданные */
  meta?: RouteMeta;

  /** Предзагрузка компонента/данных (хинт для навигации) */
  preload?: {
    /** Предзагрузить компонент (для lazy) */
    component?: boolean;
    /** Предзагрузить данные (вызвать loader) */
    data?: boolean;
  };
};

/* -------------------------------------------
 * КОНФИГ РОУТЕРА
 * -----------------------------------------*/

export type RouterConfig = {
  /** Базовый префикс приложения, например '/app' */
  basename?: `/${string}`;
  /** Корневые маршруты */
  routes: RouteDefinition[];
  /** Фоллбек для Suspense */
  suspenseFallback?: React.ReactNode;
  /** Компонент 404/ошибка верхнего уровня */
  notFoundElement?: RouteErrorComponent | React.ReactNode;
};

/* -------------------------------------------
 * УТИЛИТЫ: КОНСТРУКТОР ССЫЛОК И СБОРКА ПУТИ
 * -----------------------------------------*/

/** Сериализация query-объекта в строку поиска. */
export type QueryInput = Record<string, string | number | boolean | (string | number | boolean)[] | undefined>;

export type LinkBuildOptions = {
  /** Относительно какого base строить ссылку (если нужен абсолют) */
  base?: string;
  /** Replace вместо push (передаётся наружу) */
  replace?: boolean;
  /** Состояние history */
  state?: NavigationState;
};

/** Построитель ссылок для конкретного RouteDefinition */
export type LinkBuilder<Path extends RoutePath, P extends Record<string, string> = PathParams<Path>> = (
  params: P,
  query?: QueryInput,
  opts?: LinkBuildOptions
) => { href: string; replace?: boolean; state?: NavigationState };

/** Вспомогательный тип: карта линкбилдеров по id маршрутов */
export type LinkMap = Record<string, LinkBuilder<any, any>>;

/* -------------------------------------------
 * НАВИГАЦИОННОЕ ДЕРЕВО / МЕНЮ
 * -----------------------------------------*/

export type NavItem = {
  id: string;
  label: string | LocaleKey;
  icon?: React.ReactNode | string;
  to?: string; // если есть прямой путь
  /** ID маршрута, если пункт привязан к нему */
  routeId?: string;
  /** RBAC для скрытия/блокировки пунктов */
  access?: RBACSpec;
  order?: number;
  hidden?: boolean;
  children?: NavItem[];
  extra?: Record<string, unknown>;
};

export type NavTree = NavItem[];

/* -------------------------------------------
 * ВСПОМОГАТЕЛЬНЫЕ УТИЛИТЫ ТИПОВ/ФУНКЦИЙ (only types)
 * -----------------------------------------*/

/** Преобразование params -> путь. Runtime-реализацию держите в utils, тут — только сигнатура. */
export type BuildPathFn = <S extends RoutePath>(
  path: S,
  params: PathParams<S>,
  query?: QueryInput
) => string;

/** Валидация доступа (RBAC). Runtime-реализацию держите в security-слое. */
export type AccessEvaluator = (spec: RBACSpec | undefined, ctx: { roles?: RoleId[]; perms?: Permission[]; auth?: unknown }) => boolean;

/** Компиляция LinkMap из набора RouteDefinition. Runtime-реализация вне типов. */
export type CreateLinkMap = (defs: RouteDefinition[], buildPath: BuildPathFn) => LinkMap;

/* -------------------------------------------
 * ПРИМЕРЫ СПЕЦИАЛИЗАЦИЙ ТИПОВ (без кода исполнения)
 * -----------------------------------------*/

/** Пример: вывод типов параметров из литерального пути. */
export type Example_UserEdit_Params = PathParams<"/users/:id/edit">; // -> { id: string }
/** Пример: wildcard */
export type Example_Files_Params = PathParams<"/files/*">; // -> { splat: string }

/* -------------------------------------------
 * ФИНАЛ
 * -----------------------------------------*/

export {}; // чтобы файл рассматривался как модуль
