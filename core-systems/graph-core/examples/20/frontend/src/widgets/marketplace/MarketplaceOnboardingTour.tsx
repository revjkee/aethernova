import React, { useEffect, useState, useCallback } from "react"
import { useTranslation } from "react-i18next"
import { useOnboardingStore } from "@/store/onboarding/onboardingStore"
import { useUserStore } from "@/store/auth/userStore"
import { getTourSteps } from "@/shared/constants/onboardingSteps"
import { useTour } from "@reactour/tour"
import { isMobile } from "@/shared/utils/isMobile"
import { markTourStepCompleted } from "@/services/onboarding/trackProgress"
import { useLocalStorage } from "@/shared/hooks/useLocalStorage"

interface MarketplaceOnboardingTourProps {
  userId?: string
}

export const MarketplaceOnboardingTour: React.FC<MarketplaceOnboardingTourProps> = ({ userId }) => {
  const { t } = useTranslation("marketplace")
  const { profile } = useUserStore()
  const { tourSteps, loadSteps } = useOnboardingStore()
  const { isOpen, currentStep, setIsOpen, setCurrentStep, steps, setSteps } = useTour()

  const [hasRun, setHasRun] = useLocalStorage<boolean>("marketplace_tour_ran", false)
  const [loading, setLoading] = useState(true)

  const eligible = useMemo(() => {
    return !profile?.onboardingDisabled && profile?.role !== "admin" && !isMobile()
  }, [profile])

  const buildSteps = useCallback(() => {
    const stepsData = getTourSteps(t)
    setSteps(stepsData)
  }, [t, setSteps])

  useEffect(() => {
    if (!eligible || hasRun) return
    buildSteps()
    setLoading(false)
    setIsOpen(true)
  }, [eligible, hasRun, buildSteps, setIsOpen])

  useEffect(() => {
    if (!steps.length || !isOpen) return

    const current = steps[currentStep]
    if (current && current.selector) {
      const el = document.querySelector(current.selector)
      el?.scrollIntoView({ behavior: "smooth", block: "center" })
    }
  }, [currentStep, steps, isOpen])

  const onStepChange = useCallback(
    (stepIndex: number) => {
      if (!userId || !steps[stepIndex]) return
      markTourStepCompleted(userId, steps[stepIndex].id)
      setCurrentStep(stepIndex)
    },
    [userId, steps, setCurrentStep]
  )

  const onClose = () => {
    setIsOpen(false)
    setHasRun(true)
  }

  return (
    <>
      {/* Скрытый div для отслеживания и управления стейтом через хук useTour */}
      <div data-tour-active={isOpen} data-tour-step={currentStep} style={{ display: "none" }} />
      {/* Не отображаем UI, Reactour работает через хук */}
    </>
  )
}
