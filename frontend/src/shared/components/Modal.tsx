// frontend/src/shared/components/Modal.tsx
import React, {
  useCallback,
  useEffect,
  useId,
  useImperativeHandle,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  forwardRef,
  ReactNode,
  KeyboardEvent,
  MouseEvent,
  CSSProperties,
} from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";

/**
 * Модальный стек для корректной блокировки скролла при множественных модалках.
 */
let modalStackCount = 0;
const isBrowser = typeof window !== "undefined" && typeof document !== "undefined";

function getScrollbarWidth(): number {
  if (!isBrowser) return 0;
  // Создаем offscreen элемент, чтобы точно измерить ширину системного скроллбара
  const scrollDiv = document.createElement("div");
  scrollDiv.style.width = "100px";
  scrollDiv.style.height = "100px";
  scrollDiv.style.position = "absolute";
  scrollDiv.style.top = "-9999px";
  scrollDiv.style.overflow = "scroll";
  document.body.appendChild(scrollDiv);
  const scrollbarWidth = scrollDiv.offsetWidth - scrollDiv.clientWidth;
  document.body.removeChild(scrollDiv);
  return scrollbarWidth;
}

function lockBodyScroll(): () => void {
  if (!isBrowser) return () => {};
  modalStackCount += 1;
  if (modalStackCount === 1) {
    const scrollbarWidth = getScrollbarWidth();
    const originalOverflow = document.body.style.overflow;
    const originalPaddingRight = document.body.style.paddingRight;
    document.body.style.overflow = "hidden";
    // Компенсируем исчезновение скроллбара, чтобы не прыгала верстка
    if (scrollbarWidth > 0) {
      const current = parseInt(
        window.getComputedStyle(document.body).paddingRight || "0",
        10
      );
      document.body.style.paddingRight = `${current + scrollbarWidth}px`;
    }
    return () => {
      modalStackCount = Math.max(0, modalStackCount - 1);
      if (modalStackCount === 0) {
        document.body.style.overflow = originalOverflow;
        document.body.style.paddingRight = originalPaddingRight;
      }
    };
  }
  // Если уже заблокировано — просто вернуть корректный декремент при закрытии
  return () => {
    modalStackCount = Math.max(0, modalStackCount - 1);
    if (modalStackCount === 0) {
      document.body.style.overflow = "";
      document.body.style.paddingRight = "";
    }
  };
}

type ModalSize = "sm" | "md" | "lg" | "xl" | "full";
type ModalVariant = "default" | "danger";
type OverlayKind = "default" | "transparent" | "blur";
type Density = "comfortable" | "compact";

export interface ModalHandles {
  open: () => void;
  close: () => void;
  focusFirst: () => void;
}

export interface ModalProps {
  open?: boolean;                 // Управляемый режим
  defaultOpen?: boolean;          // Неуправляемый режим
  onOpenChange?: (next: boolean) => void;

  title?: ReactNode;              // Текст/нода заголовка
  description?: ReactNode;        // Подзаголовок/описание
  children?: ReactNode;

  size?: ModalSize;
  variant?: ModalVariant;
  density?: Density;

  overlay?: OverlayKind;
  showCloseButton?: boolean;
  closeOnOverlayClick?: boolean;
  closeOnEsc?: boolean;
  isDismissable?: boolean;        // общий флаг на закрываемость (ESC/overlay)
  portalContainer?: Element | null;
  portalId?: string;              // для тестов/идентификации
  zIndex?: number;                // пользовательский z-index

  initialFocusRef?: React.RefObject<HTMLElement>;
  returnFocusRef?: React.RefObject<HTMLElement>;
  ariaLabel?: string;

  // События жизненного цикла
  onOpenAutoFocus?: () => void;
  onCloseAutoFocus?: () => void;

  // Стили
  className?: string;
  style?: CSSProperties;

  // Кнопки/слоты
  headerActions?: ReactNode;
  footer?: ReactNode;
}

const sizeClasses: Record<ModalSize, string> = {
  sm: "max-w-sm",
  md: "max-w-md",
  lg: "max-w-lg",
  xl: "max-w-2xl",
  full: "max-w-[min(100vw,1000px)] md:max-w-3xl w-[calc(100vw-2rem)] md:w-auto", // адаптив
};

const variantClasses: Record<ModalVariant, string> = {
  default: "",
  danger: "ring-1 ring-red-500/20",
};

const densityClasses: Record<Density, string> = {
  comfortable: "p-6",
  compact: "p-4",
};

const overlayClasses: Record<OverlayKind, string> = {
  default: "bg-black/50",
  transparent: "bg-transparent",
  blur: "backdrop-blur-sm bg-black/30",
};

const dialogMotion = {
  initial: { opacity: 0, scale: 0.98, y: 8 },
  animate: { opacity: 1, scale: 1, y: 0, transition: { duration: 0.18 } },
  exit: { opacity: 0, scale: 0.98, y: 8, transition: { duration: 0.12 } },
};

const overlayMotion = {
  initial: { opacity: 0 },
  animate: { opacity: 1, transition: { duration: 0.18 } },
  exit: { opacity: 0, transition: { duration: 0.12 } },
};

/**
 * Возвращает массив фокусируемых элементов внутри контейнера.
 */
function getFocusable(container: HTMLElement | null): HTMLElement[] {
  if (!container) return [];
  const selectors = [
    "a[href]",
    "area[href]",
    "button:not([disabled])",
    "input:not([disabled]):not([type='hidden'])",
    "select:not([disabled])",
    "textarea:not([disabled])",
    "iframe",
    "audio[controls]",
    "video[controls]",
    "[contenteditable]",
    "[tabindex]:not([tabindex='-1'])",
  ].join(",");
  const nodes = Array.from(container.querySelectorAll<HTMLElement>(selectors));
  return nodes.filter((el) => !!el && el.offsetParent !== null);
}

/**
 * Основной компонент модального окна.
 */
export const Modal = forwardRef<ModalHandles, ModalProps>(function Modal(
  {
    open,
    defaultOpen = false,
    onOpenChange,

    title,
    description,
    children,

    size = "md",
    variant = "default",
    density = "comfortable",

    overlay = "default",
    showCloseButton = true,
    closeOnOverlayClick = true,
    closeOnEsc = true,
    isDismissable = true,

    portalContainer = isBrowser ? document.body : null,
    portalId,
    zIndex = 50,

    initialFocusRef,
    returnFocusRef,
    ariaLabel,

    onOpenAutoFocus,
    onCloseAutoFocus,

    className,
    style,

    headerActions,
    footer,
  },
  ref
) {
  const [uncontrolledOpen, setUncontrolledOpen] = useState(defaultOpen);
  const isControlled = typeof open === "boolean";
  const isOpen = isControlled ? !!open : uncontrolledOpen;

  const dialogRef = useRef<HTMLDivElement | null>(null);
  const overlayRef = useRef<HTMLDivElement | null>(null);

  const internalId = useId();
  const titleId = `modal-title-${internalId}`;
  const descId = `modal-desc-${internalId}`;

  const setOpen = useCallback(
    (next: boolean) => {
      if (isControlled) {
        onOpenChange?.(next);
      } else {
        setUncontrolledOpen(next);
        onOpenChange?.(next);
      }
    },
    [isControlled, onOpenChange]
  );

  // Фокус-менеджмент и возврат фокуса
  const lastFocusedRef = useRef<HTMLElement | null>(null);

  useLayoutEffect(() => {
    if (!isBrowser) return;
    if (isOpen) {
      // Сохраняем инициатора и блокируем скролл
      lastFocusedRef.current =
        (document.activeElement as HTMLElement) || null;
      const unlock = lockBodyScroll();

      // Вызов хука автофокуса
      onOpenAutoFocus?.();

      // Устанавливаем фокус
      const toFocus =
        initialFocusRef?.current ||
        getFocusable(dialogRef.current)[0] ||
        dialogRef.current;
      toFocus?.focus?.({ preventScroll: true });

      return () => {
        // Возврат фокуса и разблокировка
        onCloseAutoFocus?.();
        unlock();
        const returnTo = returnFocusRef?.current || lastFocusedRef.current;
        returnTo?.focus?.({ preventScroll: true });
      };
    }
    return;
  }, [isOpen, initialFocusRef, returnFocusRef, onOpenAutoFocus, onCloseAutoFocus]);

  // Закрытие по ESC
  const onKeyDown = useCallback(
    (e: KeyboardEvent<HTMLDivElement>) => {
      if (e.key === "Escape" && isDismissable && closeOnEsc && isOpen) {
        e.stopPropagation();
        e.preventDefault();
        setOpen(false);
      }
      if (e.key === "Tab" && isOpen) {
        // Циклирование фокуса
        const focusables = getFocusable(dialogRef.current);
        if (focusables.length === 0) {
          e.preventDefault();
          dialogRef.current?.focus();
          return;
        }
        const current = document.activeElement as HTMLElement | null;
        const idx = focusables.indexOf(current || focusables[0]);
        let nextIdx = idx;
        if (e.shiftKey) {
          nextIdx = idx <= 0 ? focusables.length - 1 : idx - 1;
        } else {
          nextIdx = idx === focusables.length - 1 ? 0 : idx + 1;
        }
        e.preventDefault();
        focusables[nextIdx]?.focus();
      }
    },
    [isDismissable, closeOnEsc, isOpen, setOpen]
  );

  // Клик по оверлею
  const onOverlayMouseDown = useCallback(
    (e: MouseEvent<HTMLDivElement>) => {
      if (!isOpen) return;
      if (!isDismissable || !closeOnOverlayClick) return;
      // Закрывать только если клик реальный по фону (не по диалогу)
      if (e.target === overlayRef.current) {
        setOpen(false);
      }
    },
    [isOpen, isDismissable, closeOnOverlayClick, setOpen]
  );

  // Императивное API
  useImperativeHandle(
    ref,
    (): ModalHandles => ({
      open: () => setOpen(true),
      close: () => setOpen(false),
      focusFirst: () => {
        const first = getFocusable(dialogRef.current)[0] || dialogRef.current;
        first?.focus?.();
      },
    }),
    [setOpen]
  );

  // Комбинированные классы
  const dialogClasses = useMemo(
    () =>
      [
        "relative w-full",
        sizeClasses[size],
        "bg-white dark:bg-neutral-900 rounded-2xl shadow-2xl outline-none",
        "ring-1 ring-black/5 dark:ring-white/10",
        variantClasses[variant],
        densityClasses[density],
        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500",
        className,
      ]
        .filter(Boolean)
        .join(" "),
    [size, variant, density, className]
  );

  const headerPadding = density === "compact" ? "pb-3" : "pb-4";
  const bodyPadding = density === "compact" ? "py-2" : "py-3";
  const footerPadding = density === "compact" ? "pt-3" : "pt-4";

  // Контейнер портала
  const portalTarget = portalContainer ?? (isBrowser ? document.body : null);
  if (!isBrowser || !portalTarget) {
    // SSR: ничего не рендерим до гидратации
    return null;
  }

  return createPortal(
    <AnimatePresence>
      {isOpen ? (
        <div
          id={portalId}
          aria-hidden={!isOpen}
          className="fixed inset-0"
          style={{ zIndex }}
        >
          {/* Overlay */}
          <motion.div
            ref={overlayRef}
            className={[
              "fixed inset-0",
              "flex items-end sm:items-center justify-center",
              overlayClasses[overlay],
            ].join(" ")}
            {...overlayMotion}
            onMouseDown={onOverlayMouseDown}
          >
            {/* Sentinel для фокуса перед диалогом */}
            <span tabIndex={0} aria-hidden className="sr-only" />

            {/* Dialog */}
            <motion.div
              role="dialog"
              aria-modal="true"
              aria-labelledby={title ? titleId : undefined}
              aria-describedby={description ? descId : undefined}
              aria-label={!title ? ariaLabel : undefined}
              className={dialogClasses}
              style={style}
              ref={dialogRef}
              {...dialogMotion}
              onKeyDown={onKeyDown}
              tabIndex={-1}
            >
              {/* Header */}
              {(title || showCloseButton || headerActions) && (
                <div
                  className={[
                    "flex items-start gap-3",
                    headerPadding,
                    "border-b border-neutral-200/60 dark:border-neutral-700/50",
                  ].join(" ")}
                >
                  <div className="flex-1 min-w-0">
                    {title ? (
                      <h2
                        id={titleId}
                        className="text-lg font-semibold leading-6 text-neutral-900 dark:text-neutral-50"
                      >
                        {title}
                      </h2>
                    ) : null}
                    {description ? (
                      <p
                        id={descId}
                        className="mt-1 text-sm text-neutral-600 dark:text-neutral-300"
                      >
                        {description}
                      </p>
                    ) : null}
                  </div>
                  <div className="flex items-center gap-2">
                    {headerActions}
                    {showCloseButton && (
                      <button
                        type="button"
                        onClick={() => setOpen(false)}
                        className={[
                          "inline-flex items-center justify-center",
                          "h-9 w-9 rounded-xl",
                          "text-neutral-600 hover:text-neutral-900",
                          "dark:text-neutral-300 dark:hover:text-white",
                          "hover:bg-neutral-100 dark:hover:bg-neutral-800",
                          "focus-visible:outline focus-visible:outline-2 focus-visible:outline-indigo-500",
                        ].join(" ")}
                        aria-label="Закрыть модальное окно"
                      >
                        <svg
                          xmlns="http://www.w3.org/2000/svg"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth={2}
                          className="h-5 w-5"
                          aria-hidden="true"
                        >
                          <path d="M6 6l12 12M18 6L6 18" />
                        </svg>
                      </button>
                    )}
                  </div>
                </div>
              )}

              {/* Body */}
              <div className={["relative", bodyPadding].join(" ")}>
                {children}
              </div>

              {/* Footer */}
              {footer && (
                <div
                  className={[
                    "flex items-center justify-end gap-2",
                    footerPadding,
                    "border-t border-neutral-200/60 dark:border-neutral-700/50",
                  ].join(" ")}
                >
                  {footer}
                </div>
              )}
            </motion.div>

            {/* Sentinel для фокуса после диалога */}
            <span tabIndex={0} aria-hidden className="sr-only" />
          </motion.div>
        </div>
      ) : null}
    </AnimatePresence>,
    portalTarget
  );
});

/**
 * Вспомогательные подкомпоненты с семантическими слотами.
 * Использование опционально — можно собирать контент напрямую.
 */

export function ModalHeader({
  children,
  className,
}: {
  children?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={[
        "mb-2",
        "text-lg font-semibold leading-6 text-neutral-900 dark:text-neutral-50",
        className,
      ].join(" ")}
    >
      {children}
    </div>
  );
}

export function ModalBody({
  children,
  className,
}: {
  children?: ReactNode;
  className?: string;
}) {
  return <div className={className}>{children}</div>;
}

export function ModalFooter({
  children,
  className,
}: {
  children?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={[
        "mt-4 flex items-center justify-end gap-2",
        className,
      ].join(" ")}
    >
      {children}
    </div>
  );
}

/**
 * Хук для локального управления модалкой без внешнего стейта.
 * Подходит для кейсов внутри форм/виджетов.
 */
export function useModal(initial = false) {
  const [open, setOpen] = useState<boolean>(initial);
  const api = useMemo(
    () => ({
      open: () => setOpen(true),
      close: () => setOpen(false),
      toggle: () => setOpen((v) => !v),
      isOpen: () => open,
      set: setOpen,
    }),
    [open]
  );
  return [open, api] as const;
}
