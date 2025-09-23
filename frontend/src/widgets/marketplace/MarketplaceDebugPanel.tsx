import React, { useState, useEffect, useCallback } from "react"
import { Card, CardHeader, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useToast } from "@/shared/hooks/useToast"
import { useDebugStore } from "@/store/marketplace/debugStore"
import { useLogsStore } from "@/store/logs/logsStore"
import { useWalletStore } from "@/store/wallet/walletStore"
import { fetchMarketplaceDiagnostics } from "@/services/devops/marketplaceDiagnostics"
import { decodeTxInput, fetchLastTx } from "@/services/web3/txUtils"
import { copyToClipboard } from "@/shared/utils/copy"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Skeleton } from "@/components/ui/skeleton"
import { Separator } from "@/components/ui/separator"
import { cn } from "@/shared/utils/cn"

export const MarketplaceDebugPanel: React.FC = () => {
  const { toast } = useToast()
  const { logs, loadLogs, clearLogs } = useLogsStore()
  const { diagnostics, loadDiagnostics, loading } = useDebugStore()
  const { activeWallet } = useWalletStore()
  const [filter, setFilter] = useState("")

  const fetchData = useCallback(async () => {
    try {
      await loadDiagnostics()
      await loadLogs()
    } catch (err) {
      toast.error("Failed to load debug data.")
    }
  }, [loadDiagnostics, loadLogs, toast])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const filteredLogs = logs.filter((log) =>
    log.message.toLowerCase().includes(filter.toLowerCase())
  )

  const handleCopy = async (content: string) => {
    await copyToClipboard(content)
    toast.success("Copied to clipboard")
  }

  const renderTxInfo = () => {
    if (!activeWallet?.address) return null
    return (
      <div className="mb-4">
        <h4 className="text-sm font-semibold mb-2">Recent Transactions</h4>
        <Button
          variant="ghost"
          className="text-xs px-2 py-1"
          onClick={async () => {
            const tx = await fetchLastTx(activeWallet.address)
            if (tx) toast.info(decodeTxInput(tx.input))
          }}
        >
          Fetch & Decode Last TX
        </Button>
      </div>
    )
  }

  return (
    <Card className="w-full shadow-md border border-muted bg-background/60 backdrop-blur">
      <CardHeader>
        <div className="flex justify-between items-center">
          <h3 className="text-lg font-semibold">Marketplace Debug Panel</h3>
          <div className="flex gap-2">
            <Input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter logs..."
              className="max-w-[200px]"
            />
            <Button size="sm" variant="outline" onClick={clearLogs}>
              Clear Logs
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="space-y-2">
            {[...Array(6)].map((_, idx) => (
              <Skeleton key={idx} className="h-4 w-full" />
            ))}
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex flex-col gap-3">
              {renderTxInfo()}
              <div>
                <h4 className="text-sm font-semibold mb-2">System Diagnostics</h4>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                  {Object.entries(diagnostics).map(([key, value]) => (
                    <div
                      key={key}
                      className={cn(
                        "flex items-center justify-between text-sm px-3 py-1 rounded-md border",
                        value.status === "ok"
                          ? "border-green-500 bg-green-50"
                          : "border-red-500 bg-red-50"
                      )}
                    >
                      <span>{key}</span>
                      <Badge
                        variant={value.status === "ok" ? "success" : "destructive"}
                        onClick={() => handleCopy(value.message)}
                      >
                        {value.status.toUpperCase()}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
              <Separator />
              <div>
                <h4 className="text-sm font-semibold mb-2">Log Events</h4>
                <ScrollArea className="h-60 border rounded-md p-2 bg-muted/10">
                  {filteredLogs.length === 0 ? (
                    <span className="text-muted-foreground text-xs">No logs match filter</span>
                  ) : (
                    filteredLogs.map((log, idx) => (
                      <div
                        key={idx}
                        className="text-xs mb-1 font-mono hover:bg-accent/10 px-1 py-0.5 rounded cursor-pointer"
                        onClick={() => handleCopy(log.message)}
                      >
                        [{log.level.toUpperCase()}] {log.message}
                      </div>
                    ))
                  )}
                </ScrollArea>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
