// src/pages/XAIInspector.tsx

import React, { useEffect, useState, useCallback } from "react"
import { Helmet } from "react-helmet-async"
import { useTranslation } from "react-i18next"
import { Container } from "@/shared/ui/Container"
import { PageHeader } from "@/shared/ui/PageHeader"
import { ExplanationChart } from "@/widgets/XAI/ExplanationChart"
import { FeatureImportanceTable } from "@/widgets/XAI/FeatureImportanceTable"
import { LLMExplanationPanel } from "@/widgets/XAI/LLMExplanationPanel"
import { ModelDecisionTimeline } from "@/widgets/XAI/ModelDecisionTimeline"
import { XAIEntitySelector } from "@/widgets/XAI/XAIEntitySelector"
import { ExplanationTypeToggle } from "@/widgets/XAI/ExplanationTypeToggle"
import { Spinner } from "@/shared/ui/Spinner"
import { Divider } from "@/shared/ui/Divider"
import { useXAIAnalysis } from "@/features/ai_insight/hooks/useXAIAnalysis"
import { useNotification } from "@/shared/hooks/useNotification"
import { motion } from "framer-motion"

export const XAIInspector: React.FC = () => {
  const { t } = useTranslation()
  const notify = useNotification()

  const {
    loadEntities,
    entities,
    selectedEntity,
    selectEntity,
    explanation,
    explanationType,
    setExplanationType,
    fetchExplanation,
    loading
  } = useXAIAnalysis()

  useEffect(() => {
    loadEntities()
  }, [loadEntities])

  useEffect(() => {
    if (selectedEntity) fetchExplanation(selectedEntity.id, explanationType)
  }, [selectedEntity, explanationType, fetchExplanation])

  const onEntityChange = useCallback(
    (id: string) => {
      const entity = entities.find(e => e.id === id)
      if (entity) selectEntity(entity)
    },
    [entities, selectEntity]
  )

  const onExplanationTypeToggle = useCallback(
    (type: "shap" | "lime" | "attention" | "saliency") => {
      setExplanationType(type)
    },
    [setExplanationType]
  )

  return (
    <>
      <Helmet>
        <title>{t("xai.title")}</title>
        <meta name="description" content={t("xai.description")} />
      </Helmet>

      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.2 }}>
        <Container>
          <PageHeader
            title={t("xai.header")}
            subtitle={t("xai.subtitle")}
          />

          <Divider label={t("xai.entity_selector")} />
          <XAIEntitySelector entities={entities} selected={selectedEntity?.id} onSelect={onEntityChange} />

          <Divider label={t("xai.explanation_type")} />
          <ExplanationTypeToggle selected={explanationType} onChange={onExplanationTypeToggle} />

          {loading ? (
            <div className="flex justify-center py-16">
              <Spinner />
            </div>
          ) : explanation ? (
            <>
              <Divider label={t("xai.feature_importance")} />
              <FeatureImportanceTable explanation={explanation} />

              <Divider label={t("xai.visual_analysis")} />
              <ExplanationChart explanation={explanation} />

              <Divider label={t("xai.decision_timeline")} />
              <ModelDecisionTimeline explanation={explanation} />

              <Divider label={t("xai.llm_explanation")} />
              <LLMExplanationPanel entity={selectedEntity} explanation={explanation} />
            </>
          ) : (
            <div className="text-center text-gray-500 mt-10">{t("xai.no_data")}</div>
          )}
        </Container>
      </motion.div>
    </>
  )
}

export default XAIInspector
