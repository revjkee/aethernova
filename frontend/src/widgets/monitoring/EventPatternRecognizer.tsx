import React, { useState, useEffect, useMemo } from "react"
import { Card } from "@/shared/components/Card"
import { PatternRadar } from "@/widgets/Monitoring/components/PatternRadar"
import { useEventStream } from "@/services/monitoring/useEventStream"
import { usePatternDetection } from "@/services/monitoring/usePatternDetection"
import { PatternMatch } from "@/types/pattern"
import { Select } from "@/shared/components/Select"
import { Badge } from "@/shared/components/Badge"
import { Tooltip } from "@/shared/components/Tooltip"
import { cn } from "@/shared/utils/style"
import { ScrollArea } from "@/shared/components/ScrollArea"
import { Flame, Clock4, CheckCircle2, XCircle } from "lucide-react"

const severityColors: Record<string, string> = {
  low: "bg-green-500",
  medium: "bg-yellow-500",
  high: "bg-orange-500",
  critical: "bg-red-600"
}

export const EventPatternRecognizer: React.FC = () => {
  const [timeWindow, setTimeWindow] = useState<number>(300) // seconds
  const { events, loading } = useEventStream({ interval: 5 })
  const { patterns, status } = usePatternDetection(events, timeWindow)

  const windowOptions = [
    { label: "5 мин", value: 300 },
    { label: "15 мин", value: 900 },
    { label: "1 час", value: 3600 },
    { label: "6 часов", value: 21600 },
  ]

  const renderIcon = (match: PatternMatch) => {
    if (!match.valid) return <XCircle className="text-red-500 w-4 h-4" />
    if (match.severity === "critical") return <Flame className="text-red-600 w-4 h-4" />
    if (match.severity === "high") return <Clock4 className="text-orange-500 w-4 h-4" />
    return <CheckCircle2 className="text-green-500 w-4 h-4" />
  }

  const sortedMatches = useMemo(() => {
    return [...patterns].sort((a, b) => {
      const s1 = ["low", "medium", "high", "critical"].indexOf(a.severity)
      const s2 = ["low", "medium", "high", "critical"].indexOf(b.severity)
      return s2 - s1
    })
  }, [patterns])

  return (
    <Card title="AI Event Pattern Recognizer" className="p-6 space-y-6" loading={loading || status === "loading"}>
      <div className="flex justify-between items-center">
        <Select
          label="Временное окно"
          value={timeWindow}
          onChange={setTimeWindow}
          options={windowOptions}
          className="w-48"
        />
        <span className="text-sm text-neutral-400">
          Статус: <Badge variant="outline">{status.toUpperCase()}</Badge>
        </span>
      </div>

      <ScrollArea className="max-h-[400px] border rounded-md bg-neutral-900/50">
        {sortedMatches.map((match, idx) => (
          <div
            key={idx}
            className={cn("flex items-start gap-4 px-4 py-3 border-b border-neutral-700", {
              "bg-neutral-800/40": idx % 2 === 0
            })}
          >
            <div className="mt-1">{renderIcon(match)}</div>
            <div className="flex flex-col gap-1 w-full">
              <div className="flex justify-between items-center">
                <div className="font-semibold text-white">{match.patternName}</div>
                <Tooltip content={`Сигнатура: ${match.signature}`}>
                  <Badge variant="secondary">{match.severity}</Badge>
                </Tooltip>
              </div>
              <div className="text-sm text-neutral-300">{match.description}</div>
              <div className="text-xs text-neutral-500 italic">Совпадения: {match.matchCount}</div>
            </div>
          </div>
        ))}

        {sortedMatches.length === 0 && (
          <div className="text-center py-10 text-sm text-neutral-400">
            Совпадений не обнаружено.
          </div>
        )}
      </ScrollArea>

      <div className="pt-6">
        <PatternRadar matches={sortedMatches} />
      </div>
    </Card>
  )
}
