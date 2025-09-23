// src/pages/WorldEditor.tsx

import React, { useEffect, useState, useCallback } from "react"
import { Helmet } from "react-helmet-async"
import { useTranslation } from "react-i18next"
import { Container } from "@/shared/ui/Container"
import { PageHeader } from "@/shared/ui/PageHeader"
import { ScenarioBuilder } from "@/widgets/Simulation/ScenarioBuilder"
import { WorldMap } from "@/widgets/Game3D/WorldMap"
import { EntityEditor } from "@/widgets/Game3D/EntityEditor"
import { VisualSimulationPanel } from "@/widgets/Game3D/VisualSimulationPanel"
import { useWorldEditor } from "@/features/game3d/hooks/useWorldEditor"
import { Entity } from "@/features/game3d/types"
import { motion } from "framer-motion"
import { Divider } from "@/shared/ui/Divider"
import { Button } from "@/shared/ui/Button"
import { useAIIntent } from "@/features/ai_insight/hooks/useAIIntent"
import { ScenarioValidationReport } from "@/widgets/Simulation/ScenarioValidationReport"

export const WorldEditor: React.FC = () => {
  const { t } = useTranslation()
  const {
    entities,
    scenario,
    selectedEntity,
    worldMetadata,
    simulationResults,
    loadWorld,
    updateEntity,
    deleteEntity,
    selectEntity,
    createNewEntity,
    runSimulation,
    validateScenario
  } = useWorldEditor()

  const [validationReport, setValidationReport] = useState<any | null>(null)
  const { triggerIntent, aiLoading, aiSuggestions } = useAIIntent()

  useEffect(() => {
    loadWorld()
  }, [loadWorld])

  const handleEntityUpdate = useCallback(
    (entity: Entity) => {
      updateEntity(entity)
    },
    [updateEntity]
  )

  const handleScenarioValidate = useCallback(() => {
    const report = validateScenario()
    setValidationReport(report)
  }, [validateScenario])

  return (
    <>
      <Helmet>
        <title>{t("world_editor.title")}</title>
        <meta name="description" content={t("world_editor.meta_description")} />
      </Helmet>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.25 }}
      >
        <Container>
          <PageHeader
            title={t("world_editor.header")}
            subtitle={t("world_editor.description")}
            action={
              <div className="flex gap-4">
                <Button variant="outline" onClick={createNewEntity}>
                  {t("world_editor.new_entity")}
                </Button>
                <Button onClick={runSimulation}>
                  {t("world_editor.run_simulation")}
                </Button>
              </div>
            }
          />

          <Divider label={t("world_editor.map")} />
          <WorldMap
            entities={entities}
            onSelect={selectEntity}
            selectedEntityId={selectedEntity?.id}
          />

          <Divider label={t("world_editor.editor")} />
          <EntityEditor
            entity={selectedEntity}
            onUpdate={handleEntityUpdate}
            onDelete={deleteEntity}
          />

          <Divider label={t("world_editor.simulation")} />
          <VisualSimulationPanel
            metadata={worldMetadata}
            entities={entities}
            simulationData={simulationResults}
          />

          <Divider label={t("world_editor.ai_intent")} />
          <ScenarioBuilder
            scenario={scenario}
            onScenarioChange={validateScenario}
            aiSuggestions={aiSuggestions}
            loading={aiLoading}
            onRequestAI={() => triggerIntent(scenario)}
          />

          <Divider label={t("world_editor.validation")} />
          <Button variant="secondary" onClick={handleScenarioValidate}>
            {t("world_editor.validate_scenario")}
          </Button>
          {validationReport && (
            <ScenarioValidationReport report={validationReport} />
          )}
        </Container>
      </motion.div>
    </>
  )
}

export default WorldEditor
