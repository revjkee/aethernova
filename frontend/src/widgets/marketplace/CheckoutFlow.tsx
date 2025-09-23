import React, { useState, useEffect } from "react"
import { useCart } from "@/features/commerce/hooks/useCart"
import { useToast } from "@/shared/components/useToast"
import { Button } from "@/shared/components/Button"
import { TokenPaymentButton } from "@/widgets/Marketplace/TokenPaymentButton"
import { DeliveryOptions } from "@/widgets/Marketplace/DeliveryOptions"
import { PaymentMethodSelector } from "@/widgets/Marketplace/PaymentMethodSelector"
import { CheckoutSummary } from "@/widgets/Marketplace/CheckoutSummary"
import { useOrderSubmission } from "@/features/commerce/hooks/useOrderSubmission"
import { useUser } from "@/features/auth/hooks/useUser"
import { TermsCheckbox } from "@/shared/components/TermsCheckbox"
import { CheckoutSteps } from "@/features/commerce/constants/steps"
import { useNavigationGuard } from "@/shared/hooks/useNavigationGuard"
import { useTelemetry } from "@/shared/telemetry/useTelemetry"

export const CheckoutFlow: React.FC = () => {
  const { items, total, clearCart } = useCart()
  const { user } = useUser()
  const { toast } = useToast()
  const [step, setStep] = useState<CheckoutSteps>("summary")
  const [acceptTerms, setAcceptTerms] = useState(false)
  const [delivery, setDelivery] = useState<"digital" | "physical" | "nft">("digital")
  const [paymentMethod, setPaymentMethod] = useState<"neuro" | "ton" | "offchain">("neuro")
  const [orderId, setOrderId] = useState<string | null>(null)
  const { submitOrder, status, error } = useOrderSubmission()
  const { record } = useTelemetry("checkout")

  useNavigationGuard(step !== "confirmation")

  const onNext = async () => {
    if (step === "summary") {
      setStep("delivery")
      return
    }
    if (step === "delivery") {
      setStep("payment")
      return
    }
    if (step === "payment") {
      if (!acceptTerms) {
        toast({ title: "Подтвердите условия", variant: "destructive" })
        return
      }

      const newOrderId = crypto.randomUUID()
      setOrderId(newOrderId)

      await submitOrder({
        orderId: newOrderId,
        userId: user?.id,
        items,
        total,
        delivery,
        paymentMethod,
        signedAt: Date.now(),
      })

      record("order_submitted", { delivery, paymentMethod, total })
    }
  }

  useEffect(() => {
    if (status === "success") {
      toast({ title: "Заказ оформлен", description: "Вы можете отслеживать его в разделе 'Мои заказы'", variant: "success" })
      clearCart()
      setStep("confirmation")
    } else if (status === "error") {
      toast({ title: "Ошибка оформления", description: error || "Неизвестная ошибка", variant: "destructive" })
    }
  }, [status])

  const renderStep = () => {
    switch (step) {
      case "summary":
        return <CheckoutSummary items={items} total={total} onNext={onNext} />
      case "delivery":
        return <DeliveryOptions value={delivery} onChange={setDelivery} onNext={onNext} onBack={() => setStep("summary")} />
      case "payment":
        return (
          <div className="space-y-4">
            <PaymentMethodSelector value={paymentMethod} onChange={setPaymentMethod} />
            <TermsCheckbox checked={acceptTerms} onChange={setAcceptTerms} />
            <div className="flex justify-between">
              <Button variant="ghost" onClick={() => setStep("delivery")}>Назад</Button>
              {orderId && (
                <TokenPaymentButton
                  amount={total}
                  recipient="EQDxZ0...NEUROADDR"
                  orderId={orderId}
                  onSuccess={() => setStep("confirmation")}
                  onFailure={(e) =>
                    toast({ title: "Платёж не прошёл", description: e, variant: "destructive" })
                  }
                />
              )}
            </div>
          </div>
        )
      case "confirmation":
        return (
          <div className="text-center">
            <h2 className="text-xl font-semibold">Спасибо за заказ!</h2>
            <p className="text-muted-foreground mt-2">Заказ №{orderId?.slice(0, 8)} создан</p>
            <Button className="mt-4" onClick={() => setStep("summary")}>Вернуться в маркетплейс</Button>
          </div>
        )
    }
  }

  return (
    <div className="p-6 max-w-2xl mx-auto bg-background rounded-2xl shadow-xl border border-border">
      <h1 className="text-2xl font-bold mb-4">Оформление заказа</h1>
      {renderStep()}
    </div>
  )
}
