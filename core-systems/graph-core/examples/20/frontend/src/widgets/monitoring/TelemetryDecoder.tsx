import React, { useState, useEffect, useMemo } from "react"
import { Card } from "@/shared/components/Card"
import { Textarea } from "@/shared/components/Textarea"
import { Badge } from "@/shared/components/Badge"
import { Tooltip } from "@/shared/components/Tooltip"
import { Select } from "@/shared/components/Select"
import { useDecodedTelemetry } from "@/services/monitoring/useDecodedTelemetry"
import { useSchemaRegistry } from "@/services/monitoring/useSchemaRegistry"
import { cn } from "@/shared/utils/style"
import { CheckCircle2, XCircle, AlertTriangle } from "lucide-react"

type DecodedResult = {
  label: string
  value: string | number
  type: string
  valid: boolean
  severity: "low" | "medium" | "high" | "critical"
}

const severityColor = {
  low: "bg-green-500",
  medium: "bg-yellow-500",
  high: "bg-orange-500",
  critical: "bg-red-600"
}

export const TelemetryDecoder: React.FC = () => {
  const [rawInput, setRawInput] = useState<string>("")
  const [schemaKey, setSchemaKey] = useState<string>("auto")

  const { schemas } = useSchemaRegistry()
  const { result, status } = useDecodedTelemetry(rawInput, schemaKey)

  const schemaOptions = useMemo(() => {
    return [{ value: "auto", label: "Автоопределение" }].concat(
      schemas.map((s) => ({ value: s.id, label: s.name }))
    )
  }, [schemas])

  const renderIcon = (valid: boolean, severity: string) => {
    if (!valid) return <XCircle className="text-red-500 w-4 h-4" />
    if (severity === "critical") return <AlertTriangle className="text-yellow-300 w-4 h-4" />
    return <CheckCircle2 className="text-green-500 w-4 h-4" />
  }

  return (
    <Card title="Telemetry Decoder" className="p-6 space-y-6" loading={status === "loading"}>
      <div className="flex flex-col gap-4 sm:flex-row items-center justify-between">
        <Select
          label="Схема декодирования"
          value={schemaKey}
          onChange={setSchemaKey}
          options={schemaOptions}
          className="w-full sm:w-64"
        />
        <span className="text-sm text-neutral-400">Статус: <Badge variant="outline">{status.toUpperCase()}</Badge></span>
      </div>

      <Textarea
        value={rawInput}
        onChange={(e) => setRawInput(e.target.value)}
        label="Сырые данные телеметрии"
        placeholder='{"packet": "A1:B2:C3", "metric": "0x4F7D"}'
        className="min-h-[120px]"
      />

      {status === "success" && result?.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 pt-6">
          {result.map((entry: DecodedResult, index: number) => (
            <div key={index} className="p-4 rounded-xl border shadow-md bg-neutral-900/40 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold">{entry.label}</span>
                {renderIcon(entry.valid, entry.severity)}
              </div>
              <div className="text-md font-mono text-white break-all">{entry.value}</div>
              <div className="flex justify-between text-xs text-neutral-400">
                <span>{entry.type}</span>
                <Tooltip content={`Уровень: ${entry.severity}`}>
                  <span className={cn("px-2 py-0.5 rounded", severityColor[entry.severity])}>
                    {entry.severity}
                  </span>
                </Tooltip>
              </div>
            </div>
          ))}
        </div>
      )}

      {status === "error" && (
        <div className="p-4 text-red-600 bg-red-100 border border-red-300 rounded-md text-sm">
          Не удалось декодировать. Проверьте формат, шифрование или схему.
        </div>
      )}
    </Card>
  )
}
