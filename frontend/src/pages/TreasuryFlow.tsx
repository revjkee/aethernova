// src/pages/TreasuryFlow.tsx

import React, { useEffect, useMemo } from "react"
import { Helmet } from "react-helmet-async"
import { useTranslation } from "react-i18next"
import { motion } from "framer-motion"
import { Container } from "@/shared/ui/Container"
import { PageHeader } from "@/shared/ui/PageHeader"
import { Divider } from "@/shared/ui/Divider"
import { Spinner } from "@/shared/ui/Spinner"
import { RefreshButton } from "@/shared/ui/RefreshButton"
import { useTreasuryFlow } from "@/features/dao/hooks/useTreasuryFlow"

import { TreasuryBalanceOverview } from "@/widgets/DAO/TreasuryBalanceOverview"
import { TreasuryIncomeChart } from "@/widgets/DAO/TreasuryIncomeChart"
import { TreasuryExpensesChart } from "@/widgets/DAO/TreasuryExpensesChart"
import { TreasuryCategoryBreakdown } from "@/widgets/DAO/TreasuryCategoryBreakdown"
import { TreasuryHistoricalFlow } from "@/widgets/DAO/TreasuryHistoricalFlow"
import { TreasuryAllocationGovernance } from "@/widgets/DAO/TreasuryAllocationGovernance"
import { TreasuryAuditPanel } from "@/widgets/DAO/TreasuryAuditPanel"

export const TreasuryFlow: React.FC = () => {
  const { t } = useTranslation()
  const {
    balances,
    incomeStats,
    expensesStats,
    breakdown,
    flowHistory,
    governanceImpact,
    auditHistory,
    loading,
    refresh
  } = useTreasuryFlow()

  const isReady = useMemo(() => !loading && balances, [loading, balances])

  useEffect(() => {
    refresh()
  }, [refresh])

  return (
    <>
      <Helmet>
        <title>{t("treasury.title")}</title>
        <meta name="description" content={t("treasury.meta_description")} />
      </Helmet>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.25 }}
      >
        <Container>
          <PageHeader
            title={t("treasury.header")}
            subtitle={t("treasury.description")}
            action={<RefreshButton onClick={refresh} />}
          />

          {!isReady ? (
            <div className="flex justify-center items-center h-96">
              <Spinner />
            </div>
          ) : (
            <>
              <Divider label={t("treasury.section.balance")} />
              <TreasuryBalanceOverview data={balances} />

              <Divider label={t("treasury.section.income")} />
              <TreasuryIncomeChart data={incomeStats} />

              <Divider label={t("treasury.section.expenses")} />
              <TreasuryExpensesChart data={expensesStats} />

              <Divider label={t("treasury.section.categories")} />
              <TreasuryCategoryBreakdown data={breakdown} />

              <Divider label={t("treasury.section.flow")} />
              <TreasuryHistoricalFlow data={flowHistory} />

              <Divider label={t("treasury.section.governance")} />
              <TreasuryAllocationGovernance data={governanceImpact} />

              <Divider label={t("treasury.section.audit")} />
              <TreasuryAuditPanel history={auditHistory} />
            </>
          )}
        </Container>
      </motion.div>
    </>
  )
}

export default TreasuryFlow
