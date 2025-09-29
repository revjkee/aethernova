// frontend/src/components/ui/select.tsx
"use client";

import * as React from "react";
import * as SelectPrimitive from "@radix-ui/react-select";
import { cn } from "@/lib/utils";

/** Встроенные иконки (без lucide-react) */
const SvgChevronDown: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
  <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" {...props}>
    <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);
const SvgCheck: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
  <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" {...props}>
    <path d="M20 6L9 17l-5-5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);
const SvgChevronUp: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
  <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" {...props}>
    <path d="M18 15l-6-6-6 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

/** Базовые реэкспорты */
const Select = SelectPrimitive.Root;
const SelectGroup = SelectPrimitive.Group;
const SelectValue = SelectPrimitive.Value;
const SelectLabel = SelectPrimitive.Label;
const SelectSeparator = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.Separator>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.Separator>
>(({ className, ...props }, ref) => (
  <SelectPrimitive.Separator
    ref={ref}
    className={cn("-mx-1 my-1 h-px bg-border", className)}
    {...props}
  />
));
SelectSeparator.displayName = SelectPrimitive.Separator.displayName;

/** Триггер */
const SelectTrigger = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.Trigger>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.Trigger> & { error?: boolean }
>(({ className, error, children, ...props }, ref) => (
  <SelectPrimitive.Trigger
    ref={ref}
    className={cn(
      "inline-flex w-full items-center justify-between rounded-xl border bg-background px-3 py-2 text-sm",
      "ring-offset-background placeholder:text-muted-foreground",
      "focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
      "disabled:cursor-not-allowed disabled:opacity-50",
      "data-[state=open]:border-input data-[state=open]:bg-accent/20",
      error ? "border-destructive" : "border-input",
      className
    )}
    {...props}
  >
    {children}
    <SelectPrimitive.Icon className="ml-2 opacity-70">
      <SvgChevronDown className="h-4 w-4" />
    </SelectPrimitive.Icon>
  </SelectPrimitive.Trigger>
));
SelectTrigger.displayName = SelectPrimitive.Trigger.displayName;

/** Контейнер контента (портал) */
const SelectContent = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.Content> & { portal?: boolean }
>(({ className, children, position = "popper", portal = true, ...props }, ref) => {
  const Cmp = (
    <SelectPrimitive.Content
      ref={ref}
      className={cn(
        "z-50 min-w-[8rem] overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-md",
        "data-[state=open]:animate-in data-[state=closed]:animate-out",
        "data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
        "data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95",
        "data-[side=bottom]:slide-in-from-top-2 data-[side=top]:slide-in-from-bottom-2",
        className
      )}
      position={position}
      sideOffset={6}
      {...props}
    >
      <SelectPrimitive.ScrollUpButton className="flex cursor-default items-center justify-center py-1 text-muted-foreground">
        <SvgChevronUp className="h-4 w-4" />
      </SelectPrimitive.ScrollUpButton>
      <SelectPrimitive.Viewport
        className={cn(
          "p-1",
          position === "popper" ? "h-[var(--radix-select-trigger-height)] w-full min-w-[var(--radix-select-trigger-width)]" : ""
        )}
      >
        {children}
      </SelectPrimitive.Viewport>
      <SelectPrimitive.ScrollDownButton className="flex cursor-default items-center justify-center py-1 text-muted-foreground">
        <SvgChevronDown className="h-4 w-4" />
      </SelectPrimitive.ScrollDownButton>
    </SelectPrimitive.Content>
  );

  return portal ? <SelectPrimitive.Portal>{Cmp}</SelectPrimitive.Portal> : Cmp;
});
SelectContent.displayName = SelectPrimitive.Content.displayName;

/** Элемент списка */
const SelectItem = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.Item>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.Item>
>(({ className, children, disabled, ...props }, ref) => (
  <SelectPrimitive.Item
    ref={ref}
    disabled={disabled}
    className={cn(
      "relative flex w-full select-none items-center rounded-lg px-8 py-2 text-sm outline-none",
      "focus:bg-accent focus:text-accent-foreground",
      "data-[disabled=true]:pointer-events-none data-[disabled=true]:opacity-50",
      "cursor-default",
      className
    )}
    {...props}
  >
    <span className="absolute left-2 flex size-4 items-center justify-center">
      <SelectPrimitive.ItemIndicator>
        <SvgCheck className="h-4 w-4" />
      </SelectPrimitive.ItemIndicator>
    </span>
    <SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>
  </SelectPrimitive.Item>
));
SelectItem.displayName = SelectPrimitive.Item.displayName;

/** Заголовок группы */
const SelectGroupLabel: React.FC<React.ComponentPropsWithoutRef<typeof SelectPrimitive.Label>> = ({
  className,
  ...props
}) => (
  <SelectLabel className={cn("px-2 py-1.5 text-xs font-medium text-muted-foreground", className)} {...props} />
);

/** Поле-отображение значения (для удобства импорта) */
const SelectDisplayValue: React.FC<React.ComponentPropsWithoutRef<typeof SelectPrimitive.Value>> = (props) => (
  <SelectValue placeholder={props?.placeholder ?? "Select…"} {...props} />
);

/** Комбинированный preset (пример использования)
 * <Select>
 *   <SelectTrigger><SelectDisplayValue /></SelectTrigger>
 *   <SelectContent>
 *     <SelectGroup>
 *       <SelectGroupLabel>Group</SelectGroupLabel>
 *       <SelectItem value="a">Option A</SelectItem>
 *     </SelectGroup>
 *   </SelectContent>
 * </Select>
 */

export {
  Select,
  SelectGroup,
  SelectValue,
  SelectTrigger,
  SelectContent,
  SelectItem,
  SelectLabel,
  SelectSeparator,
  SelectGroupLabel,
  SelectDisplayValue,
};
