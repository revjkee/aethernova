import React, { useEffect, useState } from 'react'
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { FileDown, CheckCircle, AlertCircle, Copy, Lock } from 'lucide-react'
import { useToast } from '@/components/ui/use-toast'
import { useDeliveryAccess } from '@/hooks/delivery/useDeliveryAccess'
import { formatFileSize } from '@/shared/utils/formatFileSize'
import { copyToClipboard } from '@/shared/utils/clipboard'
import { decryptBlob } from '@/shared/utils/crypto'
import { useUser } from '@/hooks/auth/useUser'
import { cn } from '@/shared/utils/classNames'

type DeliveryFile = {
  id: string
  fileName: string
  encryptedBlob: string
  size: number
  type: string
  oneTime: boolean
  downloaded: boolean
}

type LicenseKey = {
  key: string
  description?: string
  copied: boolean
}

type ProductDigitalDeliveryProps = {
  productId: string
}

export const ProductDigitalDelivery: React.FC<ProductDigitalDeliveryProps> = ({ productId }) => {
  const { toast } = useToast()
  const { user } = useUser()
  const { files, keys, loading, fetchDelivery, markDownloaded, error } = useDeliveryAccess(productId, user?.id)

  const [decryptedFiles, setDecryptedFiles] = useState<Record<string, Blob | null>>({})
  const [copiedKeys, setCopiedKeys] = useState<Record<string, boolean>>({})

  useEffect(() => {
    fetchDelivery()
  }, [productId])

  const handleFileDownload = async (file: DeliveryFile) => {
    try {
      if (!decryptedFiles[file.id]) {
        const decrypted = await decryptBlob(file.encryptedBlob, file.id)
        setDecryptedFiles((prev) => ({ ...prev, [file.id]: decrypted }))
      }

      const blob = decryptedFiles[file.id]
      if (!blob) throw new Error('Файл не расшифрован')

      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = file.fileName
      a.click()
      URL.revokeObjectURL(url)

      if (file.oneTime && !file.downloaded) {
        await markDownloaded(file.id)
      }

      toast({ title: 'Загрузка началась', description: file.fileName, variant: 'success' })
    } catch (e: any) {
      toast({ title: 'Ошибка загрузки', description: e.message || 'Не удалось расшифровать файл', variant: 'destructive' })
    }
  }

  const handleCopyKey = (key: string) => {
    copyToClipboard(key)
    setCopiedKeys((prev) => ({ ...prev, [key]: true }))
    toast({ title: 'Ключ скопирован', description: key, variant: 'success' })
  }

  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-6 w-1/2" />
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-12 w-full" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-sm text-red-600 flex items-center gap-2">
        <AlertCircle className="w-5 h-5" /> {error}
      </div>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Цифровая доставка</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {keys.length > 0 && (
          <div>
            <div className="font-medium mb-2 text-muted-foreground">Лицензионные ключи:</div>
            <div className="space-y-2">
              {keys.map((k) => (
                <div key={k.key} className="flex items-center justify-between border rounded p-3 bg-muted/20">
                  <div>
                    <div className="font-mono text-sm">{k.key}</div>
                    {k.description && <div className="text-xs text-muted-foreground mt-1">{k.description}</div>}
                  </div>
                  <Button
                    onClick={() => handleCopyKey(k.key)}
                    variant="ghost"
                    size="icon"
                    aria-label="Copy license key"
                  >
                    {copiedKeys[k.key] ? <CheckCircle className="w-5 h-5 text-green-600" /> : <Copy className="w-5 h-5" />}
                  </Button>
                </div>
              ))}
            </div>
          </div>
        )}

        {files.length > 0 && (
          <div>
            <div className="font-medium mb-2 text-muted-foreground">Файлы для скачивания:</div>
            <div className="space-y-3">
              {files.map((f) => (
                <div
                  key={f.id}
                  className={cn(
                    'flex justify-between items-center border rounded p-3',
                    f.oneTime && f.downloaded ? 'opacity-50 pointer-events-none' : 'bg-background'
                  )}
                >
                  <div className="flex flex-col gap-1">
                    <span className="text-sm font-medium">{f.fileName}</span>
                    <span className="text-xs text-muted-foreground">{formatFileSize(f.size)} · {f.type}</span>
                    {f.oneTime && (
                      <span className="text-xs text-amber-700 flex items-center gap-1 mt-1">
                        <Lock className="w-3 h-3" /> Одноразовая загрузка
                      </span>
                    )}
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleFileDownload(f)}
                    disabled={f.oneTime && f.downloaded}
                  >
                    <FileDown className="w-4 h-4 mr-2" />
                    Скачать
                  </Button>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
      <CardFooter className="text-xs text-muted-foreground">
        Выдача зашифрована. Каждый доступ логируется и защищён.
      </CardFooter>
    </Card>
  )
}

export default ProductDigitalDelivery
