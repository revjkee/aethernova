import React, { useState, useEffect, useCallback } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { useToast } from '@/components/ui/use-toast'
import { Loader2, ShoppingCart, Lock, CheckCircle2 } from 'lucide-react'
import { cn } from '@/shared/utils/classNames'
import { useBuyNowStore } from '@/state/marketplaceBuyNowStore'
import { formatPrice } from '@/shared/utils/formatPrice'
import { useWeb3Wallet } from '@/shared/hooks/useWeb3Wallet'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'

type BuyNowPanelProps = {
  productId: string
  isAvailable: boolean
  priceUSD: number
  priceNEURO: number
  currency: 'USD' | 'NEURO'
  sellerId: string
}

export const BuyNowPanel: React.FC<BuyNowPanelProps> = ({
  productId,
  isAvailable,
  priceUSD,
  priceNEURO,
  currency,
  sellerId,
}) => {
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)
  const { toast } = useToast()
  const { buyNow } = useBuyNowStore()
  const { isConnected, connect, address } = useWeb3Wallet()

  const price = currency === 'NEURO' ? priceNEURO : priceUSD

  const handleBuyNow = useCallback(async () => {
    if (!isAvailable || loading || success) return

    if (currency === 'NEURO' && !isConnected) {
      await connect()
    }

    try {
      setLoading(true)
      const tx = await buyNow({
        productId,
        buyer: address,
        seller: sellerId,
        amount: price,
        currency,
      })

      if (tx.success) {
        setSuccess(true)
        toast({ title: 'Успешно', description: 'Покупка завершена', variant: 'success' })
      } else {
        toast({ title: 'Ошибка', description: tx.message || 'Не удалось выполнить покупку', variant: 'destructive' })
      }
    } catch (e: any) {
      toast({ title: 'Ошибка', description: e.message || 'Непредвиденная ошибка', variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }, [isAvailable, loading, success, currency, isConnected, productId, price, address, sellerId, buyNow])

  useEffect(() => {
    if (!isAvailable) setLoading(false)
  }, [isAvailable])

  return (
    <Card className="w-full max-w-md shadow-xl border bg-background">
      <CardHeader className="pb-0">
        <div className="text-base font-semibold text-foreground">Купить сейчас</div>
      </CardHeader>
      <CardContent className="pt-4 flex flex-col gap-4">
        <div className="flex justify-between items-center">
          <span className="text-muted-foreground text-sm">Цена:</span>
          <span className="text-xl font-bold text-primary">
            {currency === 'NEURO' ? `${price.toFixed(2)} $NEURO` : formatPrice(price, 'USD')}
          </span>
        </div>

        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                disabled={!isAvailable || loading || success}
                onClick={handleBuyNow}
                className={cn('w-full text-white text-base gap-2', success && 'bg-green-600 hover:bg-green-700')}
              >
                {loading ? (
                  <Loader2 className="h-5 w-5 animate-spin" />
                ) : success ? (
                  <>
                    <CheckCircle2 className="w-5 h-5" />
                    Куплено
                  </>
                ) : (
                  <>
                    <ShoppingCart className="w-5 h-5" />
                    Купить
                  </>
                )}
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              {!isAvailable ? 'Товар недоступен' : 'Оплата мгновенная, возврат невозможен'}
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>

        {!isAvailable && (
          <div className="text-xs text-red-500 flex items-center gap-1">
            <Lock className="w-4 h-4" />
            Товар временно недоступен
          </div>
        )}

        <div className="text-[10px] text-muted-foreground text-right">
          Оплата осуществляется через защищённый шлюз TeslaAI Market Core
        </div>
      </CardContent>
    </Card>
  )
}

export default BuyNowPanel
