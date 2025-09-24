import { useEffect, useState } from "react"
import { getGPUUsageStats } from "@/services/gpuMonitoringService"
import { Spinner } from "@/shared/components/Spinner"
import { Tooltip } from "@/shared/components/Tooltip"
import clsx from "clsx"
import { trackEvent } from "@/shared/utils/telemetry"

interface GPUStat {
  id: string
  name: string
  usage: number     // 0-100 (%)
  temperature: number // °C
  memoryUsed: number // MB
  memoryTotal: number // MB
  lastUpdated: string // ISO date
}

interface GPUUsageHeatmapProps {
  pollIntervalMs?: number
  maxColumns?: number
}

export const GPUUsageHeatmap = ({
  pollIntervalMs = 6000,
  maxColumns = 6
}: GPUUsageHeatmapProps) => {
  const [stats, setStats] = useState<GPUStat[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchStats()
    const interval = setInterval(fetchStats, pollIntervalMs)
    return () => clearInterval(interval)
  }, [pollIntervalMs])

  const fetchStats = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getGPUUsageStats()
      setStats(data)
      trackEvent("gpu_usage_heatmap_loaded", { count: data.length })
    } catch (err) {
      setError("Ошибка загрузки состояния GPU")
      trackEvent("gpu_usage_heatmap_error", { error: String(err) })
    } finally {
      setLoading(false)
    }
  }

  const getHeatColor = (usage: number): string => {
    if (usage >= 90) return "#dc2626"       // красный
    if (usage >= 70) return "#f59e42"       // оранжевый
    if (usage >= 50) return "#facc15"       // жёлтый
    if (usage >= 30) return "#4ade80"       // зелёный
    return "#38bdf8"                        // синий
  }

  return (
    <div className="w-full border rounded-xl shadow-sm bg-white dark:bg-neutral-900 p-6 min-h-[340px]">
      <div className="flex items-center justify-between mb-4">
        <div className="font-semibold text-neutral-800 dark:text-neutral-100 flex gap-2 items-center">
          Интенсивность загрузки GPU
        </div>
        <button
          onClick={fetchStats}
          className="text-xs text-neutral-500 hover:text-neutral-900 dark:hover:text-white flex items-center gap-1"
        >
          Обновить
        </button>
      </div>
      {loading ? (
        <div className="flex items-center justify-center h-52">
          <Spinner size="lg" />
        </div>
      ) : error ? (
        <div className="text-sm text-red-600">{error}</div>
      ) : stats.length === 0 ? (
        <div className="text-sm text-neutral-500">Нет данных о GPU.</div>
      ) : (
        <div
          className={clsx(
            "grid gap-3",
            `grid-cols-1`,
            { [`md:grid-cols-${Math.min(stats.length, maxColumns)}`]: stats.length > 1 }
          )}
        >
          {stats.map((gpu) => (
            <Tooltip
              key={gpu.id}
              content={
                <div className="text-xs space-y-1">
                  <div className="font-medium">{gpu.name}</div>
                  <div>Загрузка: <b>{gpu.usage}%</b></div>
                  <div>Температура: <b>{gpu.temperature}°C</b></div>
                  <div>Память: <b>{gpu.memoryUsed} / {gpu.memoryTotal} МБ</b></div>
                  <div>Обновлено: <span>{new Date(gpu.lastUpdated).toLocaleTimeString()}</span></div>
                </div>
              }
            >
              <div
                className={clsx(
                  "rounded-xl transition-all duration-300 shadow-md flex flex-col items-center justify-center p-3 h-36",
                  "hover:scale-105 border-2",
                  {
                    "border-red-500": gpu.usage >= 90,
                    "border-yellow-500": gpu.usage >= 70 && gpu.usage < 90,
                    "border-green-500": gpu.usage >= 30 && gpu.usage < 70,
                    "border-blue-500": gpu.usage < 30
                  }
                )}
                style={{
                  background: `linear-gradient(180deg, ${getHeatColor(gpu.usage)}80 80%, transparent 100%)`
                }}
              >
                <span className="font-bold text-lg text-neutral-900 dark:text-white">{gpu.usage}%</span>
                <span className="mt-2 text-sm text-neutral-600 dark:text-neutral-300">{gpu.name}</span>
                <div className="mt-2 text-xs text-neutral-500">
                  <span>t: {gpu.temperature}°C</span>
                </div>
                <div className="text-xs text-neutral-400">
                  <span>RAM: {gpu.memoryUsed}/{gpu.memoryTotal} МБ</span>
                </div>
              </div>
            </Tooltip>
          ))}
        </div>
      )}
    </div>
  )
}
