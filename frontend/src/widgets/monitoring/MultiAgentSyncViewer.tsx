import React, { useEffect, useMemo, useState } from "react"
import { Card } from "@/shared/components/Card"
import { Badge } from "@/shared/components/Badge"
import { Tooltip } from "@/shared/components/Tooltip"
import { cn } from "@/shared/utils/style"
import { useAgentSyncData } from "@/services/monitoring/useAgentSyncData"
import { SyncStatus, AgentSyncMeta } from "@/types/agents"
import { ScrollArea } from "@/shared/components/ScrollArea"
import { RefreshCw, AlertCircle, CheckCircle2, Clock } from "lucide-react"
import { AgentCoordinationGraph } from "@/widgets/Monitoring/components/AgentCoordinationGraph"
import { LatencyBar } from "@/widgets/Monitoring/components/LatencyBar"
import { SyncDriftChart } from "@/widgets/Monitoring/components/SyncDriftChart"

const syncColors: Record<SyncStatus, string> = {
  synced: "text-green-500",
  delayed: "text-yellow-500",
  desynced: "text-red-600",
  unknown: "text-neutral-500"
}

export const MultiAgentSyncViewer: React.FC = () => {
  const { agents, status } = useAgentSyncData()
  const [filter, setFilter] = useState<SyncStatus | "all">("all")

  const filteredAgents = useMemo(() => {
    if (filter === "all") return agents
    return agents.filter((a) => a.syncStatus === filter)
  }, [agents, filter])

  const renderIcon = (syncStatus: SyncStatus) => {
    switch (syncStatus) {
      case "synced": return <CheckCircle2 className="text-green-500 w-4 h-4" />
      case "delayed": return <Clock className="text-yellow-500 w-4 h-4" />
      case "desynced": return <AlertCircle className="text-red-600 w-4 h-4" />
      default: return <RefreshCw className="text-neutral-500 w-4 h-4 animate-spin" />
    }
  }

  return (
    <Card title="Мультиагентный монитор синхронности" className="space-y-6 p-6" loading={status === "loading"}>
      <div className="flex justify-between items-center">
        <div className="flex gap-3">
          <Badge onClick={() => setFilter("all")} className={cn("cursor-pointer", { "border": filter === "all" })}>Все</Badge>
          <Badge onClick={() => setFilter("synced")} variant="outline" className={cn({ "border": filter === "synced" })}>Синхронны</Badge>
          <Badge onClick={() => setFilter("delayed")} variant="outline" className={cn({ "border": filter === "delayed" })}>Задержки</Badge>
          <Badge onClick={() => setFilter("desynced")} variant="outline" className={cn({ "border": filter === "desynced" })}>Рассинхрон</Badge>
        </div>
        <span className="text-sm text-neutral-400">Агентов: {filteredAgents.length}</span>
      </div>

      <ScrollArea className="max-h-[400px] border rounded-md bg-neutral-900/40">
        {filteredAgents.map((agent: AgentSyncMeta, idx: number) => (
          <div key={agent.id} className={cn("flex items-start px-4 py-3 border-b border-neutral-700 gap-4", {
            "bg-neutral-800/40": idx % 2 === 0
          })}>
            <div className="mt-1">{renderIcon(agent.syncStatus)}</div>
            <div className="flex flex-col w-full gap-1">
              <div className="flex justify-between items-center">
                <div className="font-semibold text-white">{agent.agentName}</div>
                <Tooltip content={`Sync Delta: ${agent.syncDrift} ms`}>
                  <Badge variant="secondary">{agent.syncStatus}</Badge>
                </Tooltip>
              </div>
              <LatencyBar latency={agent.latency} max={1000} />
              <div className="text-xs text-neutral-500 italic">ZK-подпись: {agent.zkSignature.slice(0, 12)}…</div>
            </div>
          </div>
        ))}
        {filteredAgents.length === 0 && (
          <div className="text-center py-10 text-sm text-neutral-400">Нет агентов по выбранному фильтру.</div>
        )}
      </ScrollArea>

      <div className="pt-6 grid grid-cols-1 xl:grid-cols-2 gap-6">
        <SyncDriftChart agents={agents} />
        <AgentCoordinationGraph agents={agents} />
      </div>
    </Card>
  )
}
