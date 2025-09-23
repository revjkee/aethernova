import React, { useMemo, useState } from "react"
import { useInternalBusStats } from "@/services/monitoring/useInternalBusStats"
import { Card } from "@/shared/components/Card"
import { Badge } from "@/shared/components/Badge"
import { Tooltip } from "@/shared/components/Tooltip"
import { ScrollArea } from "@/shared/components/ScrollArea"
import { cn } from "@/shared/utils/style"
import { BusQueueChart } from "@/widgets/Monitoring/components/BusQueueChart"
import { DeliveryPathMap } from "@/widgets/Monitoring/components/DeliveryPathMap"
import { FlameIcon, ClockIcon, InfoIcon } from "lucide-react"

const SEVERITY_COLORS: Record<string, string> = {
  low: "text-green-500",
  medium: "text-yellow-500",
  high: "text-red-500",
  critical: "text-pink-500"
}

export const InternalBusMonitor: React.FC = () => {
  const { queues, status } = useInternalBusStats()
  const [filter, setFilter] = useState<string>("all")

  const filteredQueues = useMemo(() => {
    if (filter === "all") return queues
    return queues.filter(q => q.priority === filter)
  }, [queues, filter])

  return (
    <Card title="Монитор внутренних очередей и событий" className="p-6 space-y-8" loading={status === "loading"}>
      <div className="flex justify-between items-center">
        <div className="flex gap-2">
          <Badge onClick={() => setFilter("all")} className={cn("cursor-pointer", { "border": filter === "all" })}>Все</Badge>
          <Badge onClick={() => setFilter("low")} variant="outline" className={cn({ "border": filter === "low" })}>Низкий приоритет</Badge>
          <Badge onClick={() => setFilter("medium")} variant="outline" className={cn({ "border": filter === "medium" })}>Средний</Badge>
          <Badge onClick={() => setFilter("high")} variant="outline" className={cn({ "border": filter === "high" })}>Высокий</Badge>
          <Badge onClick={() => setFilter("critical")} variant="outline" className={cn({ "border": filter === "critical" })}>Критический</Badge>
        </div>
        <span className="text-xs text-neutral-400">Очередей: {filteredQueues.length}</span>
      </div>

      <ScrollArea className="max-h-[420px] rounded-lg bg-neutral-900/40 border border-neutral-700">
        {filteredQueues.map((queue, idx) => (
          <div key={queue.id} className={cn("flex flex-col gap-1 px-5 py-3 border-b border-neutral-700", {
            "bg-neutral-800/40": idx % 2 === 0
          })}>
            <div className="flex justify-between items-center">
              <div className="flex gap-2 items-center">
                <Tooltip content={`Тип: ${queue.type} | ID: ${queue.id}`}>
                  <span className="text-sm font-semibold text-white">{queue.name}</span>
                </Tooltip>
                <Tooltip content="Приоритет">
                  <span className={cn("text-xs", SEVERITY_COLORS[queue.priority])}>{queue.priority.toUpperCase()}</span>
                </Tooltip>
              </div>
              <Badge variant="outline" className="text-xs">{queue.status}</Badge>
            </div>

            <div className="flex justify-between items-center gap-4">
              <div className="text-xs text-neutral-400">В очереди: {queue.length}</div>
              <div className="text-xs text-neutral-400 italic">Задержка: {queue.avgDelay}ms</div>
              <div className="text-xs text-neutral-400 italic">Последнее событие: {queue.lastEvent}</div>
            </div>
          </div>
        ))}
        {filteredQueues.length === 0 && (
          <div className="text-center text-sm text-neutral-500 py-10">Очереди по данному фильтру отсутствуют.</div>
        )}
      </ScrollArea>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 pt-4">
        <BusQueueChart queues={queues} />
        <DeliveryPathMap queues={queues} />
      </div>
    </Card>
  )
}
