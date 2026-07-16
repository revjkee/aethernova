import Link from "next/link";
import type { ComponentPropsWithoutRef, ReactNode } from "react";

/**
 * Промышленный UI-компонент для 404-сценариев в Next.js App Router.
 * Основано на официальной конфигурации not-found.tsx / notFound(). Источники: Next.js docs.  :contentReference[oaicite:1]{index=1}
 *
 * Ключевые особенности:
 * - Без клиентских хуков: серверный компонент по умолчанию (минимальный бандл).
 * - Доступность: семантические роли, aria-метки, фокусируемая ссылка возврата.
 * - Не привязывается к теме: использует нейтральные классы, совместим с Tailwind.
 * - Расширяемость: заголовок, описание, действия и слоты можно переопределить через props.
 */

export type NotFoundProps = {
  title?: string;
  description?: string;
  /** Куда вести основную кнопку возврата. */
  backHref?: string;
  /** Текст кнопки возврата. */
  backLabel?: string;
  /** Дополнительные действия (например, вторичные ссылки). */
  actions?: ReactNode;
  /** Опциональный тестовый идентификатор. */
  "data-testid"?: string;
} & Omit<ComponentPropsWithoutRef<"section">, "children" | "title">;

export default function NotFound(props: NotFoundProps) {
  const {
    title = "Страница не найдена",
    description = "Запрошенный ресурс не существует или был перемещён.",
    backHref = "/",
    backLabel = "На главную",
    actions = null,
    "data-testid": testId = "not-found-root",
    ...sectionProps
  } = props;

  return (
    <section
      {...sectionProps}
      data-testid={testId}
      role="region"
      aria-labelledby="nf-title"
      className={[
        "mx-auto flex min-h-[60vh] max-w-3xl flex-col items-center",
        "justify-center gap-6 px-6 text-center",
      ].join(" ")}
    >
      {/* Статусный код и машинночитаемое описание */}
      <div
        aria-hidden="true"
        className="select-none text-8xl font-extrabold leading-none tracking-tight opacity-10"
      >
        404
      </div>

      <header className="space-y-2">
        <h1 id="nf-title" className="text-2xl font-semibold leading-tight">
          {title}
        </h1>
        <p className="text-sm opacity-80">{description}</p>
      </header>

      <nav aria-label="Действия на странице 404" className="mt-2 flex items-center gap-3">
        <Link
          href={backHref}
          prefetch
          className={[
            "inline-flex items-center justify-center rounded-lg px-4 py-2",
            "text-sm font-medium ring-1 ring-inset",
            "transition-colors focus-visible:outline-none focus-visible:ring-2",
            "ring-neutral-300 hover:bg-neutral-100",
            "dark:ring-neutral-800 dark:hover:bg-neutral-900",
          ].join(" ")}
        >
          {backLabel}
        </Link>
        {actions}
      </nav>

      {/* Техническая справка для разработчиков (невидима для пользователей скринридеров) */}
      <div aria-hidden="true" className="mt-8 max-w-prose text-left text-xs opacity-60">
        <ul className="list-disc space-y-1 pl-5">
          <li>
            Отрисовывайте этот UI из сегмента маршрута через файл{" "}
            <code className="rounded bg-neutral-100 px-1 py-0.5 dark:bg-neutral-900">not-found.tsx</code>{" "}
            или через вызов{" "}
            <code className="rounded bg-neutral-100 px-1 py-0.5 dark:bg-neutral-900">notFound()</code>.
          </li>
          <li>
            Поведение и API зафиксированы в официальной документации Next.js по{" "}
            <code className="rounded bg-neutral-100 px-1 py-0.5 dark:bg-neutral-900">not-found</code> и{" "}
            <code className="rounded bg-neutral-100 px-1 py-0.5 dark:bg-neutral-900">notFound()</code>.
          </li>
        </ul>
      </div>
    </section>
  );
}

/**
 * Примечания по интеграции (подтверждено документацией Next.js):
 * - Файл-конвенция `app/**/not-found.tsx` рендерит данный UI при вызове `notFound()` в том же сегменте. :contentReference[oaicite:2]{index=2}
 * - Функция `notFound()` из `next/navigation` инициирует отображение близлежащего `not-found.tsx`. :contentReference[oaicite:3]{index=3}
 */
