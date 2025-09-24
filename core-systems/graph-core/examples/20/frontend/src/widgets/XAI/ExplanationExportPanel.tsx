import React, { useState, useEffect, useCallback } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { Checkbox } from '@/components/ui/checkbox'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { toast } from '@/components/ui/use-toast'
import { FileExporter } from '@/utils/xai/FileExporter'
import { useExplainAuditMeta } from '@/hooks/xai/useExplainAuditMeta'
import { useZKProofAttach } from '@/hooks/xai/useZKProofAttach'
import { Badge } from '@/components/ui/badge'
import { IconDownload, IconKey, IconShieldCheck, IconCode, IconSettings } from '@tabler/icons-react'
import JSZip from 'jszip'

type ExportFormat = 'pdf' | 'json' | 'csv' | 'zip'

export const ExplanationExportPanel: React.FC<{
  explanationId: string
  modelId: string
  includeZK?: boolean
}> = ({ explanationId, modelId, includeZK = true }) => {
  const [selectedFormat, setFormat] = useState<ExportFormat>('pdf')
  const [includeMeta, setIncludeMeta] = useState(true)
  const [includeTokens, setIncludeTokens] = useState(true)
  const [fileName, setFileName] = useState('xai-export')
  const [loading, setLoading] = useState(false)

  const { auditMeta, loading: auditLoading } = useExplainAuditMeta(explanationId)
  const { zkProof, loading: zkLoading } = useZKProofAttach(explanationId)

  const handleExport = useCallback(async () => {
    setLoading(true)
    try {
      const content = await FileExporter.generate({
        format: selectedFormat,
        explanationId,
        modelId,
        fileName,
        includeTokens,
        includeMeta,
        auditMeta,
        zkProof: includeZK ? zkProof : null,
      })

      const blob =
        selectedFormat === 'zip'
          ? await new JSZip().file(`${fileName}.pdf`, content.pdfBlob)
              .file(`${fileName}.json`, content.jsonBlob)
              .generateAsync({ type: 'blob' })
          : content.blob

      const downloadUrl = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = downloadUrl
      a.download = `${fileName}.${selectedFormat}`
      document.body.appendChild(a)
      a.click()
      a.remove()
      window.URL.revokeObjectURL(downloadUrl)
      toast({ title: 'Успешно', description: 'Файл выгружен.' })
    } catch (err) {
      console.error(err)
      toast({ title: 'Ошибка', description: 'Не удалось экспортировать файл' })
    } finally {
      setLoading(false)
    }
  }, [selectedFormat, fileName, explanationId, modelId, includeMeta, includeTokens, auditMeta, zkProof, includeZK])

  return (
    <div className="space-y-4 p-5 border rounded-lg bg-muted/30 shadow">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold">Выгрузка объяснения</h3>
        {zkProof && includeZK && <Badge variant="outline" className="flex items-center gap-1"><IconShieldCheck size={14} /> ZK-подписано</Badge>}
      </div>

      <div className="flex flex-col gap-3">
        <Input
          placeholder="Имя файла"
          value={fileName}
          onChange={(e) => setFileName(e.target.value)}
        />

        <div className="flex gap-3 items-center">
          <span className="text-sm text-muted-foreground">Формат:</span>
          <Select value={selectedFormat} onValueChange={(val) => setFormat(val as ExportFormat)}>
            <SelectTrigger className="w-[140px]">
              <SelectValue placeholder="Формат" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="pdf"><IconDownload size={14} className="mr-1" /> PDF</SelectItem>
              <SelectItem value="json"><IconCode size={14} className="mr-1" /> JSON</SelectItem>
              <SelectItem value="csv"><IconCode size={14} className="mr-1" /> CSV</SelectItem>
              <SelectItem value="zip"><IconSettings size={14} className="mr-1" /> Архив (всё)</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="flex gap-4 items-center">
          <Checkbox checked={includeMeta} onCheckedChange={(v) => setIncludeMeta(Boolean(v))} />
          <span className="text-sm text-muted-foreground">Включить метаданные</span>
        </div>

        <div className="flex gap-4 items-center">
          <Checkbox checked={includeTokens} onCheckedChange={(v) => setIncludeTokens(Boolean(v))} />
          <span className="text-sm text-muted-foreground">Включить токены/фичи</span>
        </div>

        {includeZK && (
          <div className="flex gap-4 items-center">
            <Checkbox checked={!!zkProof} disabled />
            <span className="text-sm text-muted-foreground">ZK-доказательство приложено</span>
          </div>
        )}
      </div>

      <Button disabled={loading || auditLoading || zkLoading} onClick={handleExport}>
        <IconDownload size={16} className="mr-2" />
        Выгрузить
      </Button>
    </div>
  )
}
