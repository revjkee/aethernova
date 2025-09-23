// src/pages/Game3DView.tsx

import React, { Suspense, useEffect, useRef, useState } from "react"
import { Canvas } from "@react-three/fiber"
import { OrbitControls, Stats, Html, Loader } from "@react-three/drei"
import { SceneManager } from "@/threejs/engine/SceneManager"
import { CameraController } from "@/threejs/engine/CameraController"
import { RendererCore } from "@/threejs/engine/RendererCore"
import { SimulationNode } from "@/threejs/components/SimulationNode"
import { AIEntity } from "@/threejs/components/AIEntity"
import { AgentOrbit } from "@/threejs/components/AgentOrbit"
import { useSimulationData } from "@/features/game3d/hooks/useSimulationData"
import { Helmet } from "react-helmet-async"
import { useTranslation } from "react-i18next"
import { motion } from "framer-motion"
import { Button } from "@/shared/ui/Button"
import { Toggle } from "@/shared/ui/Toggle"
import { ScenarioPanel } from "@/widgets/Simulation/ScenarioPanel"
import { MiniMapOverlay } from "@/widgets/Game3D/MiniMapOverlay"
import { EntityInspector } from "@/widgets/Game3D/EntityInspector"

export const Game3DView: React.FC = () => {
  const { t } = useTranslation()
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const [showMiniMap, setShowMiniMap] = useState(true)
  const [debugStats, setDebugStats] = useState(false)

  const {
    simulationNodes,
    aiEntities,
    environmentConfig,
    selectedEntity,
    onSelectEntity,
    loadScenario,
    resetScene
  } = useSimulationData()

  useEffect(() => {
    loadScenario()
  }, [loadScenario])

  return (
    <>
      <Helmet>
        <title>{t("game3d.title")}</title>
        <meta name="description" content={t("game3d.meta_description")} />
      </Helmet>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="relative w-full h-screen overflow-hidden"
      >
        <div className="absolute top-4 left-4 z-10 flex gap-3">
          <Button size="sm" variant="secondary" onClick={resetScene}>
            {t("game3d.reset")}
          </Button>
          <Toggle
            label={t("game3d.show_map")}
            checked={showMiniMap}
            onChange={setShowMiniMap}
          />
          <Toggle
            label="Debug Stats"
            checked={debugStats}
            onChange={setDebugStats}
          />
        </div>

        <Canvas
          ref={canvasRef}
          shadows
          gl={{ antialias: true }}
          camera={{ position: [0, 25, 60], fov: 60, near: 0.1, far: 1000 }}
        >
          <ambientLight intensity={0.3} />
          <directionalLight
            position={[50, 100, 50]}
            intensity={1.0}
            castShadow
            shadow-mapSize-width={2048}
            shadow-mapSize-height={2048}
          />
          <Suspense
            fallback={
              <Html>
                <span>{t("game3d.loading_scene")}</span>
              </Html>
            }
          >
            <SceneManager environment={environmentConfig} />
            <CameraController />
            <RendererCore />

            {simulationNodes.map((node, i) => (
              <SimulationNode key={i} node={node} onSelect={onSelectEntity} />
            ))}

            {aiEntities.map((agent, i) => (
              <React.Fragment key={i}>
                <AIEntity agent={agent} />
                <AgentOrbit agent={agent} />
              </React.Fragment>
            ))}
          </Suspense>

          <OrbitControls />
          {debugStats && <Stats />}
        </Canvas>

        {showMiniMap && <MiniMapOverlay nodes={simulationNodes} agents={aiEntities} />}

        <div className="absolute bottom-4 left-4 w-[380px] z-10">
          <ScenarioPanel />
        </div>

        <div className="absolute right-4 top-4 w-[420px] z-10">
          <EntityInspector entity={selectedEntity} />
        </div>

        <Loader />
      </motion.div>
    </>
  )
}

export default Game3DView
