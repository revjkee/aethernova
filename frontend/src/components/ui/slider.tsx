// frontend/src/components/ui/slider.tsx
import * as React from "react";
import * as SliderPrimitive from "@radix-ui/react-slider";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { cn } from "@/lib/utils";

/**
 * Industrial Slider for shadcn/ui with:
 * - Radix-based accessibility (aria, keyboard, range)
 * - Horizontal & vertical orientations
 * - Controlled/uncontrolled usage
 * - Marks with labels (optional)
 * - Live tooltips (optional) with custom formatter
 * - onCommit fired on pointer/key commit
 * - Sizes: sm, md, lg
 */

export type SliderValue = number[];

export type SliderSize = "sm" | "md" | "lg";

export interface SliderMark {
  value: number;
  label?: string;
}

export interface SliderProps
  extends Omit<SliderPrimitive.SliderProps, "onValueChange" | "onValueCommit"> {
  value?: SliderValue;
  defaultValue?: SliderValue;
  onValueChange?: (value: SliderValue) => void;
  onCommit?: (value: SliderValue) => void;
  min?: number;
  max?: number;
  step?: number;
  disabled?: boolean;
  orientation?: "horizontal" | "vertical";
  size?: SliderSize;
  /**
   * Show floating tooltip(s) above thumbs with formatted values.
   */
  showTooltip?: boolean;
  /**
   * Custom value formatter for tooltips and marks.
   */
  format?: (v: number) => string;
  /**
   * Visual ticks along the track. Not interactive; for navigation keep default step/keyboard.
   */
  marks?: SliderMark[];
  /**
   * If true, marks are dense (smaller spacing and label size).
   */
  denseMarks?: boolean;
  /**
   * Class names overrides.
   */
  className?: string;
  trackClassName?: string;
  rangeClassName?: string;
  thumbClassName?: string;
}

/**
 * Utility: convert a numeric value -> percent in [0..100] based on min/max.
 */
export function valueToPercent(value: number, min: number, max: number): number {
  if (max === min) return 0;
  return ((value - min) * 100) / (max - min);
}

/**
 * Thumb Tooltip wrapper (Radix Tooltip)
 */
const ThumbWithTooltip = React.forwardRef<
  HTMLSpanElement,
  React.ComponentPropsWithoutRef<typeof SliderPrimitive.Thumb> & {
    open?: boolean;
    content?: React.ReactNode;
    disabled?: boolean;
  }
>(({ open, content, disabled, ...thumbProps }, ref) => {
  return (
    <TooltipPrimitive.Provider>
      <TooltipPrimitive.Root open={open}>
        <TooltipPrimitive.Trigger asChild>
          <SliderPrimitive.Thumb
            ref={ref}
            {...thumbProps}
            aria-disabled={disabled || undefined}
          />
        </TooltipPrimitive.Trigger>
        <TooltipPrimitive.Content
          side="top"
          align="center"
          sideOffset={8}
          className={cn(
            "z-50 rounded-md border bg-popover px-2 py-1 text-xs text-popover-foreground shadow-md",
            "data-[state=delayed-open]:animate-in data-[state=closed]:animate-out",
            "data-[state=delayed-open]:fade-in-0 data-[state=closed]:fade-out-0",
            "data-[state=delayed-open]:zoom-in-95 data-[state=closed]:zoom-out-95"
          )}
        >
          {content}
          <TooltipPrimitive.Arrow className="fill-popover" />
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Root>
    </TooltipPrimitive.Provider>
  );
});
ThumbWithTooltip.displayName = "ThumbWithTooltip";

/**
 * Main Slider component
 */
export const Slider = React.forwardRef<
  React.ElementRef<typeof SliderPrimitive.Root>,
  SliderProps
>((props, ref) => {
  const {
    value,
    defaultValue,
    onValueChange,
    onCommit,
    min = 0,
    max = 100,
    step = 1,
    disabled = false,
    orientation = "horizontal",
    size = "md",
    showTooltip = false,
    format,
    marks,
    denseMarks,
    className,
    trackClassName,
    rangeClassName,
    thumbClassName,
    ...rest
  } = props;

  // Internal state to control tooltip visibility while interacting
  const [active, setActive] = React.useState(false);

  // Keep latest value for onCommit dispatch
  const latest = React.useRef<SliderValue>(value ?? defaultValue ?? [min]);

  const handleChange = React.useCallback(
    (v: SliderValue) => {
      latest.current = v;
      onValueChange?.(v);
    },
    [onValueChange]
  );

  const handleCommit = React.useCallback(() => {
    onCommit?.(latest.current);
  }, [onCommit]);

  const sizeClasses = React.useMemo(() => {
    switch (size) {
      case "sm":
        return {
          track: "h-1 data-[orientation=vertical]:w-1",
          thumb: "h-3 w-3",
          mark: "h-2 w-0.5",
          label: "text-[10px]",
        };
      case "lg":
        return {
          track: "h-2.5 data-[orientation=vertical]:w-2.5",
          thumb: "h-5 w-5",
          mark: "h-3.5 w-0.5",
          label: "text-xs",
        };
      case "md":
      default:
        return {
          track: "h-2 data-[orientation=vertical]:w-2",
          thumb: "h-4 w-4",
          mark: "h-3 w-0.5",
          label: "text-[11px]",
        };
    }
  }, [size]);

  const isVertical = orientation === "vertical";

  const values = value ?? latest.current;

  const formatter = React.useCallback(
    (n: number) => (format ? format(n) : String(n)),
    [format]
  );

  // Accessibility: commit on keyboard Enter/Space, pointer up, blur
  const onKeyDown = (e: React.KeyboardEvent<HTMLSpanElement>) => {
    if (e.key === "Enter" || e.key === " ") {
      handleCommit();
    }
  };

  const onPointerDown = () => setActive(true);
  const onPointerUp = () => {
    setActive(false);
    handleCommit();
  };

  return (
    <div
      className={cn(
        "relative flex",
        isVertical ? "h-48 items-stretch" : "w-full items-center",
        className
      )}
      data-orientation={orientation}
    >
      {/* Marks layer */}
      {Array.isArray(marks) && marks.length > 0 && (
        <MarksLayer
          marks={marks}
          min={min}
          max={max}
          orientation={orientation}
          dense={denseMarks}
          formatter={formatter}
          sizeLabelClass={sizeClasses.label}
        />
      )}

      <SliderPrimitive.Root
        ref={ref}
        value={value}
        defaultValue={defaultValue}
        onValueChange={handleChange}
        min={min}
        max={max}
        step={step}
        disabled={disabled}
        orientation={orientation}
        onPointerDown={onPointerDown}
        onPointerUp={onPointerUp}
        className={cn(
          "relative touch-none select-none",
          isVertical ? "flex h-full w-10" : "flex w-full",
          "items-center"
        )}
        {...rest}
      >
        <SliderPrimitive.Track
          className={cn(
            "relative grow overflow-hidden rounded-full bg-secondary",
            sizeClasses.track,
            trackClassName
          )}
        >
          <SliderPrimitive.Range
            className={cn(
              "absolute rounded-full bg-primary",
              rangeClassName
            )}
          />
        </SliderPrimitive.Track>

        {values.map((v, i) => {
          const tooltipOpen = showTooltip && active;
          const tooltipContent = formatter(v);
          const ThumbComponent = showTooltip ? ThumbWithTooltip : SliderPrimitive.Thumb;
          return (
            <ThumbComponent
              key={i}
              onKeyDown={onKeyDown}
              className={cn(
                "block rounded-full border border-primary/30 bg-background shadow",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
                "disabled:pointer-events-none disabled:opacity-50",
                sizeClasses.thumb,
                thumbClassName
              )}
              data-index={i}
              aria-label={values.length > 1 ? `Thumb ${i + 1}` : "Thumb"}
              {...(showTooltip ? {
                open: tooltipOpen,
                content: tooltipContent,
                disabled: disabled
              } : {})}
            />
          );
        })}
      </SliderPrimitive.Root>
    </div>
  );
});
Slider.displayName = "Slider";

/**
 * Marks layer (non-interactive)
 */
function MarksLayer({
  marks,
  min,
  max,
  orientation,
  dense,
  formatter,
  sizeLabelClass,
}: {
  marks: SliderMark[];
  min: number;
  max: number;
  orientation: "horizontal" | "vertical";
  dense?: boolean;
  formatter: (v: number) => string;
  sizeLabelClass: string;
}) {
  const isVertical = orientation === "vertical";
  const sorted = React.useMemo(
    () => [...marks].sort((a, b) => a.value - b.value),
    [marks]
  );

  return (
    <div
      aria-hidden
      className={cn(
        "pointer-events-none absolute inset-0",
        isVertical ? "mx-auto w-10" : "h-8"
      )}
    >
      {sorted.map((m, idx) => {
        const pct = valueToPercent(m.value, min, max);
        const style = isVertical
          ? { bottom: `${pct}%`, left: "50%", transform: "translateX(-50%)" }
          : { left: `${pct}%`, top: "50%", transform: "translate(-50%, -50%)" };

        return (
          <div
            key={`${m.value}-${idx}`}
            className="absolute flex flex-col items-center"
            style={style}
          >
            <div
              className={cn(
                "bg-border",
                isVertical ? "w-0.5" : "h-0.5",
                isVertical ? (dense ? "h-2" : "h-3") : (dense ? "w-2" : "w-3"),
                "rounded"
              )}
            />
            {m.label && (
              <div
                className={cn(
                  "mt-1 whitespace-nowrap rounded px-1 text-muted-foreground",
                  sizeLabelClass,
                  dense ? "opacity-70" : "opacity-100",
                  isVertical ? "translate-y-0" : "translate-y-0"
                )}
              >
                {formatter(m.value)}{m.label ? ` ${m.label}` : ""}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export default Slider;
