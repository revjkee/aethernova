// frontend/src/components/ui/scroll-area.tsx
import * as React from "react";
import * as ScrollAreaPrimitive from "@radix-ui/react-scroll-area";
import { cn } from "@/lib/utils";

/**
 * Industrial ScrollArea for shadcn/ui with:
 * - Radix primitives (Root/Viewport/Scrollbar/Thumb/Corner)
 * - Vertical + horizontal scrollbars (add second Scrollbar for horizontal)
 * - Root props pass-through: `type`, `scrollHideDelay`, `dir`, etc. (Radix API)
 * - Programmatic control via ref: scrollToTop/Bottom/Left/Right/Selector
 * - Edge shadows that react to scroll position
 * - onReachEnd callback with threshold for vertical & horizontal
 * - Sizes: sm | md | lg (scrollbar thickness)
 * - Custom class overrides for viewport/scrollbar/thumb/corner
 *
 * Docs:
 * Radix Scroll Area API (Root/Viewport/Scrollbar/Thumb/Corner, type, scrollHideDelay).
 * Horizontal scrollbar: add second Scrollbar with orientation="horizontal".
 */

export type ScrollAreaSize = "sm" | "md" | "lg";

export interface ScrollAreaHandle {
  scrollToTop: (behavior?: ScrollBehavior) => void;
  scrollToBottom: (behavior?: ScrollBehavior) => void;
  scrollToLeft: (behavior?: ScrollBehavior) => void;
  scrollToRight: (behavior?: ScrollBehavior) => void;
  scrollTo: (selector: string, behavior?: ScrollBehavior) => void;
  getViewport: () => HTMLDivElement | null;
}

export interface ScrollAreaProps
  extends Omit<
    React.ComponentPropsWithoutRef<typeof ScrollAreaPrimitive.Root>,
    "asChild"
  > {
  className?: string;
  viewportClassName?: string;
  scrollbarClassName?: string;
  thumbClassName?: string;
  cornerClassName?: string;
  /**
   * Rendered scrollbars. "both" by default.
   */
  scrollbars?: "vertical" | "horizontal" | "both" | "none";
  /**
   * Visual edge shadows that fade based on scroll position.
   */
  shadows?: boolean;
  /**
   * Fire when user scrolls near the end of content.
   * direction: "vertical" | "horizontal".
   */
  onReachEnd?: (direction: "vertical" | "horizontal") => void;
  /**
   * Distance in px from the end to trigger onReachEnd (default: 32).
   */
  reachEndThreshold?: number;
  /**
   * Scrollbar thickness preset.
   */
  size?: ScrollAreaSize;
}

const sizeMap = {
  sm: {
    bar: "data-[orientation=vertical]:w-1.5 data-[orientation=horizontal]:h-1.5",
    pad: "p-0.5",
    thumb: "rounded-full",
  },
  md: {
    bar: "data-[orientation=vertical]:w-2.5 data-[orientation=horizontal]:h-2.5",
    pad: "p-0.5",
    thumb: "rounded-full",
  },
  lg: {
    bar: "data-[orientation=vertical]:w-3 data-[orientation=horizontal]:h-3",
    pad: "p-0.5",
    thumb: "rounded-full",
  },
} as const;

export const ScrollArea = React.forwardRef<
  React.ElementRef<typeof ScrollAreaPrimitive.Root>,
  ScrollAreaProps
>((props, ref) => {
  const {
    className,
    viewportClassName,
    scrollbarClassName,
    thumbClassName,
    cornerClassName,
    scrollbars = "both",
    shadows = true,
    onReachEnd,
    reachEndThreshold = 32,
    size = "md",
    // Radix Root props (e.g., type, scrollHideDelay, dir) pass-through:
    // type?: "always" | "scroll" | "hover" | "auto"
    // scrollHideDelay?: number
    ...rootProps
  } = props;

  const viewportRef = React.useRef<HTMLDivElement | null>(null);
  const [shadowTop, setShadowTop] = React.useState(0);
  const [shadowBottom, setShadowBottom] = React.useState(0);
  const [shadowLeft, setShadowLeft] = React.useState(0);
  const [shadowRight, setShadowRight] = React.useState(0);

  // Programmatic API
  React.useImperativeHandle(
    ref as React.Ref<ScrollAreaHandle>,
    () => ({
      scrollToTop: (behavior = "smooth") => {
        viewportRef.current?.scrollTo({ top: 0, behavior });
      },
      scrollToBottom: (behavior = "smooth") => {
        const v = viewportRef.current;
        if (!v) return;
        v.scrollTo({ top: v.scrollHeight, behavior });
      },
      scrollToLeft: (behavior = "smooth") => {
        viewportRef.current?.scrollTo({ left: 0, behavior });
      },
      scrollToRight: (behavior = "smooth") => {
        const v = viewportRef.current;
        if (!v) return;
        v.scrollTo({ left: v.scrollWidth, behavior });
      },
      scrollTo: (selector: string, behavior = "smooth") => {
        const v = viewportRef.current;
        const el = v?.querySelector<HTMLElement>(selector);
        if (v && el) {
          const r1 = v.getBoundingClientRect();
          const r2 = el.getBoundingClientRect();
          v.scrollTo({
            top: v.scrollTop + (r2.top - r1.top),
            left: v.scrollLeft + (r2.left - r1.left),
            behavior,
          });
        }
      },
      getViewport: () => viewportRef.current,
    }),
    []
  );

  const computeShadows = React.useCallback(() => {
    const v = viewportRef.current;
    if (!v) return;

    const { scrollTop, scrollHeight, clientHeight, scrollLeft, scrollWidth, clientWidth } = v;

    // Vertical
    const atTop = Math.max(0, Math.min(1, scrollTop / 16));
    const atBottom = Math.max(
      0,
      Math.min(1, (scrollHeight - clientHeight - scrollTop) / 16)
    );
    setShadowTop(atTop);
    setShadowBottom(atBottom);

    // Horizontal
    const atLeft = Math.max(0, Math.min(1, scrollLeft / 16));
    const atRight = Math.max(
      0,
      Math.min(1, (scrollWidth - clientWidth - scrollLeft) / 16)
    );
    setShadowLeft(atLeft);
    setShadowRight(atRight);

    // Reach end detection
    if (onReachEnd) {
      if (scrollHeight - clientHeight - scrollTop <= reachEndThreshold) {
        onReachEnd("vertical");
      }
      if (scrollWidth - clientWidth - scrollLeft <= reachEndThreshold) {
        onReachEnd("horizontal");
      }
    }
  }, [onReachEnd, reachEndThreshold]);

  React.useEffect(() => {
    const v = viewportRef.current;
    if (!v) return;
    computeShadows();
    const onScroll = () => computeShadows();

    // Also react to content size changes
    const ro = new ResizeObserver(() => computeShadows());
    ro.observe(v);
    v.addEventListener("scroll", onScroll, { passive: true });

    return () => {
      v.removeEventListener("scroll", onScroll);
      ro.disconnect();
    };
  }, [computeShadows]);

  const sz = sizeMap[size];

  const showVertical = scrollbars === "both" || scrollbars === "vertical";
  const showHorizontal = scrollbars === "both" || scrollbars === "horizontal";

  return (
    <ScrollAreaPrimitive.Root
      className={cn(
        "relative overflow-hidden", // base as in shadcn
        className
      )}
      {...rootProps}
    >
      {/* Edge shadows */}
      {shadows && (
        <>
          {/* Top shadow */}
          <div
            aria-hidden
            className="pointer-events-none absolute inset-x-0 top-0 h-4 bg-gradient-to-b from-background to-transparent"
            style={{ opacity: shadowTop }}
          />
          {/* Bottom shadow */}
          <div
            aria-hidden
            className="pointer-events-none absolute inset-x-0 bottom-0 h-4 bg-gradient-to-t from-background to-transparent"
            style={{ opacity: shadowBottom }}
          />
          {/* Left shadow */}
          <div
            aria-hidden
            className="pointer-events-none absolute inset-y-0 left-0 w-4 bg-gradient-to-r from-background to-transparent"
            style={{ opacity: shadowLeft }}
          />
          {/* Right shadow */}
          <div
            aria-hidden
            className="pointer-events-none absolute inset-y-0 right-0 w-4 bg-gradient-to-l from-background to-transparent"
            style={{ opacity: shadowRight }}
          />
        </>
      )}

      <ScrollAreaPrimitive.Viewport
        ref={viewportRef}
        className={cn(
          "h-full w-full rounded-[inherit]",
          viewportClassName
        )}
      >
        {props.children}
      </ScrollAreaPrimitive.Viewport>

      {showVertical && (
        <ScrollBar
          orientation="vertical"
          className={scrollbarClassName}
          thumbClassName={thumbClassName}
          size={size}
        />
      )}

      {showHorizontal && (
        <ScrollBar
          orientation="horizontal"
          className={scrollbarClassName}
          thumbClassName={thumbClassName}
          size={size}
        />
      )}

      {(showVertical || showHorizontal) && (
        <ScrollAreaPrimitive.Corner
          className={cn("bg-transparent", cornerClassName)}
        />
      )}
    </ScrollAreaPrimitive.Root>
  );
});
ScrollArea.displayName = "ScrollArea";

/**
 * ScrollBar wrapper with consistent Tailwind styles and sizes.
 */
export interface ScrollBarProps
  extends Omit<
    React.ComponentPropsWithoutRef<typeof ScrollAreaPrimitive.Scrollbar>,
    "asChild"
  > {
  size?: ScrollAreaSize;
  thumbClassName?: string;
}

export const ScrollBar = React.forwardRef<
  React.ElementRef<typeof ScrollAreaPrimitive.Scrollbar>,
  ScrollBarProps
>(({ className, thumbClassName, orientation = "vertical", size = "md", ...rest }, ref) => {
  const sz = sizeMap[size];
  return (
    <ScrollAreaPrimitive.Scrollbar
      ref={ref}
      orientation={orientation}
      className={cn(
        "flex touch-none select-none transition-colors",
        "data-[orientation=vertical]:h-full data-[orientation=horizontal]:w-full",
        sz.bar,
        sz.pad,
        className
      )}
      {...rest}
    >
      <ScrollAreaPrimitive.Thumb
        className={cn(
          "relative flex-1 rounded-full bg-border",
          "data-[state=visible]:bg-foreground/30",
          "hover:bg-foreground/40",
          sz.thumb,
          thumbClassName
        )}
      />
    </ScrollAreaPrimitive.Scrollbar>
  );
});
ScrollBar.displayName = "ScrollBar";

export default ScrollArea;
