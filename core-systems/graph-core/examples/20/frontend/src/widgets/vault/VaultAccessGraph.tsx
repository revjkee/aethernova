import dynamic from "next/dynamic"
import { useEffect, useRef, useState } from "react"
import { getAccessGraph } from "@/services/accessGraphService"
import { VaultAccessGraphNode, VaultAccessGraphLink } from "@/types/accessGraph"
import { Spinner } from "@/shared/components/Spinner"
import { Badge } from "@/shared/components/Badge"
import { Tooltip } from "@/shared/components/Tooltip"
import { IconRefreshCw, IconShield, IconUser, IconLock, IconUsers } from "lucide-react"
import { trackEvent } from "@/shared/utils/telemetry"

const ForceGraph2D = dynamic(() => import("react-force-graph").then(mod => mod.ForceGraph2D), {
  ssr: false
})

interface VaultAccessGraphProps {
  vaultId: string
}

export const VaultAccessGraph = ({ vaultId }: VaultAccessGraphProps) => {
  const [nodes, setNodes] = useState<VaultAccessGraphNode[]>([])
  const [links, setLinks] = useState<VaultAccessGraphLink[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const graphRef = useRef<any>(null)

  useEffect(() => {
    fetchGraph()
  }, [vaultId])

  const fetchGraph = async () => {
    setLoading(true)
    try {
      const res = await getAccessGraph(vaultId)
      setNodes(res.nodes)
      setLinks(res.links)
      trackEvent("vault_access_graph_loaded", { vaultId, nodeCount: res.nodes.length })
    } catch (err) {
      setError("Ошибка загрузки графа доступа")
      trackEvent("vault_access_graph_error", { vaultId, error: String(err) })
    } finally {
      setLoading(false)
    }
  }

  const getNodeColor = (type: string) => {
    switch (type) {
      case "user": return "#3b82f6"
      case "agent": return "#8b5cf6"
      case "key": return "#22c55e"
      case "folder": return "#f59e0b"
      case "policy": return "#ef4444"
      default: return "#6b7280"
    }
  }

  const renderLegend = () => (
    <div className="flex gap-4 text-xs text-neutral-600 dark:text-neutral-400 mb-2 flex-wrap">
      <div className="flex items-center gap-1"><IconUser className="w-3 h-3 text-blue-500" /> Пользователь</div>
      <div className="flex items-center gap-1"><IconUsers className="w-3 h-3 text-purple-500" /> Агент</div>
      <div className="flex items-center gap-1"><IconLock className="w-3 h-3 text-green-500" /> Ключ</div>
      <div className="flex items-center gap-1"><IconShield className="w-3 h-3 text-red-500" /> Политика</div>
    </div>
  )

  return (
    <div className="w-full h-[550px] border rounded-xl shadow-sm p-4 bg-white dark:bg-neutral-900">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <IconShield className="w-5 h-5 text-indigo-600" />
          <span className="font-semibold text-neutral-800 dark:text-neutral-100 text-sm">
            Граф прав доступа
          </span>
        </div>
        <button
          onClick={fetchGraph}
          className="text-xs text-neutral-500 hover:text-neutral-800 dark:hover:text-white flex items-center gap-1"
        >
          <IconRefreshCw className="w-4 h-4" /> Обновить
        </button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-full">
          <Spinner size="lg" />
        </div>
      ) : error ? (
        <div className="text-sm text-red-600">{error}</div>
      ) : (
        <>
          {renderLegend()}
          <ForceGraph2D
            ref={graphRef}
            graphData={{ nodes, links }}
            nodeId="id"
            nodeLabel="label"
            nodeCanvasObject={(node, ctx, globalScale) => {
              const label = node.label || ""
              const fontSize = 12 / globalScale
              ctx.font = `${fontSize}px Inter`
              ctx.fillStyle = getNodeColor(node.type)
              ctx.beginPath()
              ctx.arc(node.x!, node.y!, 5, 0, 2 * Math.PI, false)
              ctx.fill()
              ctx.fillStyle = "#333"
              ctx.fillText(label, node.x! + 8, node.y! + 4)
            }}
            linkDirectionalArrowLength={6}
            linkDirectionalArrowRelPos={1}
            linkCurvature={0.25}
            linkWidth={1}
            linkColor={() => "#aaa"}
            backgroundColor="transparent"
          />
        </>
      )}
    </div>
  )
}
