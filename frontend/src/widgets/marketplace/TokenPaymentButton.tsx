import React, { useState, useEffect } from "react"
import { Button } from "@/shared/components/Button"
import { useWallet } from "@/shared/hooks/useWallet"
import { useToast } from "@/shared/components/useToast"
import { formatToken } from "@/shared/utils/format"
import { Spinner } from "@/shared/components/Spinner"
import { sendNeuroPayment, checkPaymentStatus } from "@/services/ton/paymentService"
import { TokenIcon } from "@/shared/components/TokenIcon"
import { useDebounce } from "@/shared/hooks/useDebounce"

interface TokenPaymentButtonProps {
  amount: number                // в $NEURO
  recipient: string             // TON адрес/смарт-контракт
  orderId?: string              // (опционально) ID заказа в backend
  onSuccess?: (txHash: string) => void
  onFailure?: (reason: string) => void
}

export const TokenPaymentButton: React.FC<TokenPaymentButtonProps> = ({
  amount,
  recipient,
  orderId,
  onSuccess,
  onFailure
}) => {
  const { toast } = useToast()
  const { connected, connect, address, network, balance, sendTransaction, disconnect } = useWallet()

  const [loading, setLoading] = useState(false)
  const [txHash, setTxHash] = useState<string | null>(null)
  const [status, setStatus] = useState<"idle" | "confirming" | "confirmed" | "failed">("idle")

  const handlePayment = async () => {
    if (!connected) {
      await connect()
      return
    }

    if (!balance || balance < amount) {
      toast({ title: "Недостаточно средств", description: `На кошельке ${formatToken(balance)} $NEURO`, variant: "destructive" })
      return
    }

    try {
      setLoading(true)
      setStatus("confirming")

      const tx = await sendNeuroPayment({
        recipient,
        amount,
        sender: address,
        metadata: orderId ? { orderId } : undefined
      })

      if (!tx || !tx.hash) throw new Error("Транзакция не отправлена")

      setTxHash(tx.hash)

      const confirmed = await checkPaymentStatus(tx.hash, 15_000)

      if (confirmed) {
        setStatus("confirmed")
        toast({ title: "Оплата прошла", description: "Токены отправлены", variant: "success" })
        onSuccess?.(tx.hash)
      } else {
        setStatus("failed")
        toast({ title: "Ошибка", description: "Транзакция не подтверждена", variant: "destructive" })
        onFailure?.("not_confirmed")
      }
    } catch (e: any) {
      setStatus("failed")
      toast({ title: "Ошибка оплаты", description: e.message, variant: "destructive" })
      onFailure?.(e.message)
    } finally {
      setLoading(false)
    }
  }

  const getButtonText = () => {
    if (loading) return "Оплата..."
    if (!connected) return "Подключить кошелёк"
    if (status === "confirming") return "Ожидание подтверждения..."
    if (status === "confirmed") return "Оплачено"
    return `Оплатить ${formatToken(amount)}`
  }

  return (
    <Button
      onClick={handlePayment}
      disabled={loading || status === "confirmed"}
      variant="token"
      className="w-full flex items-center justify-center gap-2"
    >
      {loading ? <Spinner size="sm" /> : <TokenIcon symbol="$NEURO" />}
      {getButtonText()}
    </Button>
  )
}
