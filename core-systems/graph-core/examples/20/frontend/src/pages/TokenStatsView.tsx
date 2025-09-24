// src/pages/TokenStatsView.tsx

import React, { useEffect, useState, useMemo } from "react"
import { Helmet } from "react-helmet-async"
import { useTranslation } from "react-i18next"
import { Container } from "@/shared/ui/Container"
import { PageHeader } from "@/shared/ui/PageHeader"
import { TokenPriceChart } from "@/widgets/Marketplace/TokenPriceChart"
import { TokenSupplyPanel } from "@/widgets/Marketplace/TokenSupplyPanel"
import { HolderDistribution } from "@/widgets/Marketplace/HolderDistribution"
import { TransactionVolumeGraph } from "@/widgets/Marketplace/TransactionVolumeGraph"
import { GovernanceVotingPower } from "@/widgets/DAO/GovernanceVotingPower"
import { TreasuryBreakdown } from "@/widgets/Marketplace/TreasuryBreakdown"
import { TokenomicsSummary } from "@/widgets/Marketplace/TokenomicsSummary"
import { Divider } from "@/shared/ui/Divider"
import { RefreshButton } from "@/shared/ui/RefreshButton"
import { useTokenStats } from "@/features/marketplace/hooks/useTokenStats"
import { Spinner } from "@/shared/ui/Spinner"
import { motion } from "framer-motion"

export const TokenStatsView: React.FC = () => {
  const { t } = useTranslation()
  const {
    tokenData,
    priceHistory,
    supplyStats,
    governanceStats,
    holderStats,
    treasuryStats,
    txVolume,
    loading,
    refresh
  } = useTokenStats()

  useEffect(() => {
    refresh()
  }, [refresh])

  const metricsLoaded = useMemo(() => !loading && tokenData, [loading, tokenData])

  return (
    <>
      <Helmet>
        <title>{t("token_stats.title")}</title>
        <meta name="description" content={t("token_stats.meta_description")} />
      </Helmet>

      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.2 }}>
        <Container>
          <PageHeader
            title={t("token_stats.header")}
            subtitle={t("token_stats.subtitle")}
            action={<RefreshButton onClick={refresh} />}
          />

          {loading || !tokenData ? (
            <div className="flex justify-center py-32">
              <Spinner />
            </div>
          ) : (
            <>
              <Divider label={t("token_stats.summary")} />
              <TokenomicsSummary data={tokenData} />

              <Divider label={t("token_stats.price")} />
              <TokenPriceChart history={priceHistory} />

              <Divider label={t("token_stats.supply")} />
              <TokenSupplyPanel stats={supplyStats} />

              <Divider label={t("token_stats.holders")} />
              <HolderDistribution data={holderStats} />

              <Divider label={t("token_stats.transactions")} />
              <TransactionVolumeGraph volumeData={txVolume} />

              <Divider label={t("token_stats.governance")} />
              <GovernanceVotingPower data={governanceStats} />

              <Divider label={t("token_stats.treasury")} />
              <TreasuryBreakdown stats={treasuryStats} />
            </>
          )}
        </Container>
      </motion.div>
    </>
  )
}

export default TokenStatsView
