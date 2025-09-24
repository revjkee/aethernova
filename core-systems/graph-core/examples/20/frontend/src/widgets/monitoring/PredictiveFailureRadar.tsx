import React, { useMemo, useState } from "react"
import { usePredictiveFailureData } from "@/services/monitoring/usePredictiveFailureData"
import { RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, Tooltip, ResponsiveContainer, Legend } from "recharts"
import { Card } from "@/shared/components/Card"
import { Select } from "@/shared/components/Select"
import { Badge } from "@/shared/components/Badge"
import { format } from "date-fns"
import { AlertTriangle } from "lucide-react"
import { cn } from "@/shared/utils/style"

const riskLevelColor = (level: number) => {
  if (level >= 0.8) return "bg-red-600"
  if (level >= 0.5) return "bg-yellow-500"
  if (level >= 0.2) return "bg-blue-400"
  return "bg-green-500"
}

export const PredictiveFailureRadar: React.FC = () => {
  const { data, isLoading } = usePredictiveFailureData()
  const [systemFilter, setSystemFilter] = useState<string>("all")

  const systems = useMemo(() => {
    const raw = data?.map(d => d.system) || []
    return ["all", ...new Set(raw)]
  }, [data])

  const filteredData = useMemo(() => {
    if (!data) return []
    if (systemFilter === "all") return data
    return data.filter(d => d.system === systemFilter)
  }, [data, systemFilter])

  const chartData = useMemo(() => {
    const groups = filteredData.reduce((acc, item) => {
      if (!acc[item.component]) acc[item.component] = []
      acc[item.component].push(item.risk)
      return acc
    }, {} as Record<string, number[]>)

    return Object.entries(groups).map(([component, values]) => ({
      component,
      avgRisk: parseFloat((values.reduce((a, b) => a + b, 0) / values.length).toFixed(2))
    }))
  }, [filteredData])

  return (
    <Card title="Прогноз отказов AI-систем" className="p-4 space-y-4" loading={isLoading}>
      <div className="flex flex-col sm:flex-row justify-between items-center gap-4">
        <Select
          label="Подсистема"
          value={systemFilter}
          onChange={setSystemFilter}
          options={systems.map(sys => ({ value: sys, label: sys.toUpperCase() }))}
          className="w-64"
        />
        <div className="flex gap-3 items-center text-sm text-neutral-500">
          <AlertTriangle className="w-4 h-4 text-yellow-500" />
          Обновлено: {format(new Date(), "dd.MM.yyyy HH:mm:ss")}
        </div>
      </div>

      <ResponsiveContainer width="100%" height={400}>
        <RadarChart data={chartData}>
          <PolarGrid />
          <PolarAngleAxis dataKey="component" />
          <PolarRadiusAxis domain={[0, 1]} tickCount={6} />
          <Radar
            name="Риск отказа"
            dataKey="avgRisk"
            stroke="#e53e3e"
            fill="#f56565"
            fillOpacity={0.6}
          />
          <Tooltip
            formatter={(value: number) => `${(value * 100).toFixed(1)}%`}
            labelFormatter={(label) => `Компонент: ${label}`}
          />
          <Legend />
        </RadarChart>
      </ResponsiveContainer>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 pt-4">
        {chartData.map((entry) => (
          <div
            key={entry.component}
            className={cn(
              "flex items-center justify-between p-3 rounded-xl shadow-md",
              riskLevelColor(entry.avgRisk),
              "text-white"
            )}
          >
            <span className="text-sm font-semibold">{entry.component}</span>
            <Badge className="bg-white text-black">{(entry.avgRisk * 100).toFixed(1)}%</Badge>
          </div>
        ))}
      </div>
    </Card>
  )
}
