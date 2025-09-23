// src/pages/HomePage.tsx

import React, { useEffect, useMemo } from "react"
import { Helmet } from "react-helmet-async"
import { useTranslation } from "react-i18next"
import { useNavigate } from "react-router-dom"
import { useAuth } from "@/features/auth/hooks/useAuth"
import { useSystemStatus } from "@/features/monitoring/hooks/useSystemStatus"
import { HeroSection } from "@/widgets/Core/HeroSection"
import { FeatureCards } from "@/widgets/Core/FeatureCards"
import { MetricsOverview } from "@/widgets/Monitoring/MetricsOverview"
import { UserAgentBanner } from "@/widgets/Agents/UserAgentBanner"
import { FeedbackBar } from "@/widgets/HR/FeedbackBar"
import { AnnouncementBanner } from "@/widgets/Governance/AnnouncementBanner"
import { LazySecurityStatus } from "@/widgets/Security/SecurityStatus"
import { TokenEconomyPreview } from "@/widgets/Marketplace/TokenEconomyPreview"
import { Footer } from "@/shared/ui/Footer"
import { Container } from "@/shared/ui/Container"
import { WelcomeOverlay } from "@/features/ui_feedback/WelcomeOverlay"
import { useTelemetry } from "@/features/monitoring/hooks/useTelemetry"
import { useThemeContext } from "@/shared/ui/ThemeProvider"
import { Button } from "@/shared/ui/Button"
import { motion } from "framer-motion"
import { EventBus } from "@/shared/utils/EventBus"
import { VersionInfo } from "@/shared/components/VersionInfo"
import { getAppVersion } from "@/shared/utils/constants"
import { SystemDiagnostic } from "@/widgets/Monitoring/SystemDiagnostic"
import { AppMeta } from "@/shared/components/AppMeta"
import { ComplianceBadge } from "@/widgets/Privacy/ComplianceBadge"
import { GitCommitHash } from "@/widgets/CI_CD/GitCommitHash"

export const HomePage: React.FC = () => {
  const { t } = useTranslation()
  const { user } = useAuth()
  const { isSystemStable, health } = useSystemStatus()
  const telemetry = useTelemetry()
  const { currentTheme } = useThemeContext()
  const navigate = useNavigate()

  const version = useMemo(() => getAppVersion(), [])

  useEffect(() => {
    telemetry.trackPage("HomePage")
    EventBus.emit("UI_RENDERED", { page: "HomePage" })
  }, [telemetry])

  return (
    <>
      <Helmet>
        <title>{t("home.title")}</title>
        <meta name="description" content={t("home.description") ?? ""} />
      </Helmet>

      <AppMeta
        environment="production"
        version={version}
        commit={process.env.REACT_APP_COMMIT_HASH ?? "dev"}
        theme={currentTheme}
      />

      <WelcomeOverlay user={user} />

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.15, duration: 0.4 }}
      >
        <Container>
          <HeroSection
            title={t("home.hero.title")}
            subtitle={t("home.hero.subtitle")}
            ctaButton={
              <Button
                size="lg"
                variant="primary"
                onClick={() => navigate("/dashboard")}
                data-testid="get-started-btn"
              >
                {t("home.hero.cta")}
              </Button>
            }
          />

          <AnnouncementBanner />
          <FeatureCards />
          <UserAgentBanner />
          <LazySecurityStatus />
          <TokenEconomyPreview />
          <MetricsOverview />
          <FeedbackBar />
          <SystemDiagnostic />

          <div className="mt-10 flex justify-between items-center">
            <ComplianceBadge />
            <VersionInfo version={version} />
            <GitCommitHash hash={process.env.REACT_APP_COMMIT_HASH ?? "N/A"} />
          </div>
        </Container>
        <Footer />
      </motion.div>
    </>
  )
}

export default HomePage
