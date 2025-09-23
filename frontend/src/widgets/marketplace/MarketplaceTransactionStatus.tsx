import React, { useEffect, useState } from 'react'
import { Badge } from '@/components/ui/badge'
import { Copy, CheckCircle2, XCircle, Loader2, Clock3, ExternalLink } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/shared/utils/classNames'
import { useToast } from '@/components/ui/use-toast'
import { getTxStatus, openExplorer } from '@/shared/web3/txUtils'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'

type TxStatus = 'pending' | 'success' | 'failed' | 'cancelled'

type MarketplaceTransactionStatusProps = {
  txHash: string
  chainId: string
  pollingInterval?: number
  className?: string
}

export const MarketplaceTransactionStatus: React.FC<MarketplaceTransactionStatusProps> = ({
  txHash,
  chainId,
  pollingInterval = 5000,
  className,
}) => {
  const [status, setStatus] = useState<TxStatus>('pending')
  const [copied, setCopied] = useState(false)
  const { toast } = useToast()

  const updateStatus = async () => {
    try {
      const result = await getTxStatus(txHash, chainId)
      setStatus(result)
    } catch (err) {
      console.error('Ошибка получения статуса транзакции:', err)
      toast({
        title: 'Ошибка',
        description: 'Не удалось получить статус транзакции',
        variant: 'destructive',
      })
    }
  }

  useEffect(() => {
    const interval = setInterval(() => {
      if (status === 'pending') {
        updateStatus()
      }
    }, pollingInterval)

    updateStatus()
    return () => clearInterval(interval)
  }, [txHash, chainId, status])

  const handleCopy = async () => {
    await navigator.clipboard.writeText(txHash)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  const renderStatusIcon = () => {
    switch (status) {
      case 'pending':
        return <Loader2 className="h-4 w-4 animate-spin text-yellow-500" />
      case 'success':
        return <CheckCircle2 className="h-4 w-4 text-green-500" />
      case 'failed':
      case 'cancelled':
        return <XCircle className="h-4 w-4 text-red-500" />
      default:
        return <Clock3 className="h-4 w-4 text-muted-foreground" />
    }
  }

  const renderStatusText = () => {
    switch (status) {
      case 'pending':
        return 'В ожидании подтверждения'
      case 'success':
        return 'Успешно выполнена'
      case 'failed':
        return 'Ошибка выполнения'
      case 'cancelled':
        return 'Отменена'
      default:
        return 'Неизвестный статус'
    }
  }

  return (
    <div
      className={cn(
        'w-full flex items-center gap-4 p-4 border rounded-md bg-background shadow-sm',
        className
      )}
      role="status"
      aria-live="polite"
    >
      <div className="flex items-center gap-2">
        {renderStatusIcon()}
        <Badge variant="secondary" className="text-xs px-2 py-1">
          {renderStatusText()}
        </Badge>
      </div>

      <div className="flex flex-col gap-1 overflow-hidden">
        <span className="truncate text-sm font-mono text-muted-foreground max-w-[260px]">
          {txHash}
        </span>

        <div className="flex gap-2 items-center">
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={handleCopy}
                  aria-label="Копировать хеш транзакции"
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side="top">
                {copied ? 'Скопировано' : 'Копировать хеш'}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>

          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => openExplorer(txHash, chainId)}
                  aria-label="Открыть в блокчейн-эксплорере"
                >
                  <ExternalLink className="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side="top">Открыть в обозревателе</TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </div>
      </div>
    </div>
  )
}

export default MarketplaceTransactionStatus
