import { useState, useEffect } from "react"
import { Badge } from "@/shared/components/Badge"
import { Tooltip } from "@/shared/components/Tooltip"
import { trackEvent } from "@/shared/utils/telemetry"
import clsx from "clsx"

export type Severity =
  | "CRITICAL"
  | "ERROR"
  | "WARNING"
  | "INFO"
  | "DEBUG"
  | "TRACE"

export interface LogSeverityFilterProps {
  value: Severity[]
  onChange: (v: Severity[]) => void
  showAllOption?: boolean
  disabled?: boolean
  className?: string
}

const SEVERITY_CONFIG: Record<Severity, { color: string; label: string; desc: string }> = {
  CRITICAL: {
    color: "bg-red-700 text-white",
    label: "Critical",
    desc: "Критические сбои, требующие немедленного вмешательства"
  },
  ERROR: {
    color: "bg-red-500 text-white",
    label: "Error",
    desc: "Ошибки, влияющие на стабильность"
  },
  WARNING: {
    color: "bg-yellow-400 text-yellow-900",
    label: "Warning",
    desc: "Возможные проблемы или аномалии"
  },
  INFO: {
    color: "bg-blue-400 text-white",
    label: "Info",
    desc: "Информационные события"
  },
  DEBUG: {
    color: "bg-green-400 text-white",
    label: "Debug",
    desc: "Отладочные сообщения"
  },
  TRACE: {
    color: "bg-gray-400 text-white",
    label: "Trace",
    desc: "Глубокий технический трассинг"
  }
}

const ALL_SEVERITIES: Severity[] = [
  "CRITICAL",
  "ERROR",
  "WARNING",
  "INFO",
  "DEBUG",
  "TRACE"
]

export const LogSeverityFilter = ({
  value,
  onChange,
  showAllOption = true,
  disabled = false,
  className
}: LogSeverityFilterProps) => {
  const [selected, setSelected] = useState<Severity[]>(value.length ? value : ALL_SEVERITIES)

  useEffect(() => {
    setSelected(value.length ? value : ALL_SEVERITIES)
  }, [value])

  const handleToggle = (sev: Severity) => {
    if (disabled) return
    let next: Severity[]
    if (selected.includes(sev)) {
      next = selected.filter((s) => s !== sev)
      if (next.length === 0) next = []
    } else {
      next = [...selected, sev]
    }
    setSelected(next)
    onChange(next)
    trackEvent("log_severity_filter_changed", { selected: next })
  }

  const handleAll = () => {
    if (disabled) return
    if (selected.length === ALL_SEVERITIES.length) {
      setSelected([])
      onChange([])
      trackEvent("log_severity_filter_all_off", {})
    } else {
      setSelected(ALL_SEVERITIES)
      onChange(ALL_SEVERITIES)
      trackEvent("log_severity_filter_all_on", {})
    }
  }

  return (
    <div className={clsx("flex flex-wrap gap-2 items-center", className)}>
      {showAllOption && (
        <Badge
          onClick={handleAll}
          className={clsx(
            "cursor-pointer select-none px-3 py-1",
            selected.length === ALL_SEVERITIES.length
              ? "bg-neutral-900 text-white"
              : "bg-neutral-300 text-neutral-800 dark:bg-neutral-800 dark:text-neutral-200"
          )}
        >
          Все
        </Badge>
      )}

      {ALL_SEVERITIES.map((sev) => (
        <Tooltip key={sev} content={SEVERITY_CONFIG[sev].desc}>
          <Badge
            onClick={() => handleToggle(sev)}
            className={clsx(
              "cursor-pointer select-none px-3 py-1 transition-all",
              SEVERITY_CONFIG[sev].color,
              selected.includes(sev)
                ? "ring-2 ring-black ring-opacity-30 dark:ring-white"
                : "opacity-50"
            )}
            aria-pressed={selected.includes(sev)}
            tabIndex={0}
          >
            {SEVERITY_CONFIG[sev].label}
          </Badge>
        </Tooltip>
      ))}
    </div>
  )
}
