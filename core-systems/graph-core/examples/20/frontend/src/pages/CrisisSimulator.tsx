// path: src/pages/CrisisSimulator.tsx

import { useEffect, useMemo, useState } from "react";
import { Helmet } from "react-helmet";
import { toast } from "react-toastify";

import { useAuth } from "@/features/auth/hooks/useAuth";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Button } from "@/shared/components/Button";
import { Spinner } from "@/shared/components/Spinner";
import { Modal } from "@/shared/components/Modal";

import { useScenariosQuery, useSimulationControl, useCrisisStream } from "@/features/simulation/simulationAPI";
import { ScenarioSelector } from "@/features/simulation/components/ScenarioSelector";
import { CrisisMap } from "@/features/simulation/components/CrisisMap";
import { CrisisLogStream } from "@/features/simulation/components/CrisisLogStream";
import { CrisisMetricRadar } from "@/features/simulation/components/CrisisMetricRadar";
import { AgentResponseMonitor } from "@/features/simulation/components/AgentResponseMonitor";
import { ScenarioConfigModal } from "@/features/simulation/components/ScenarioConfigModal";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";

const CrisisSimulator = () => {
  const { user } = useAuth();
  const [selectedScenario, setSelectedScenario] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  const { data: scenarios, refetch } = useScenariosQuery();
  const {
    stream,
    connect,
    disconnect,
    zkVerified,
    agentResponses,
    crisisMetrics
  } = useCrisisStream();
  const { startSimulation, stopSimulation, isRunning } = useSimulationControl();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleRun = () => {
    if (!selectedScenario) {
      toast.warning("Выберите сценарий");
      return;
    }
    startSimulation(selectedScenario);
  };

  const handleStop = () => {
    stopSimulation();
  };

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.SIMULATION_OFFICER, ROLE.INTEL_DIRECTOR]}>
      <Helmet>
        <title>Crisis Simulator | TeslaAI</title>
        <meta name="description" content="Запуск и контроль симуляций кризисов. Моделирование угроз, реакция агентов, логика управления и этика" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Crisis Simulator</h1>
          <div className="flex gap-2">
            <Button onClick={() => setModalOpen(true)}>Добавить сценарий</Button>
            <Button onClick={handleRun} disabled={!selectedScenario || isRunning}>Запуск</Button>
            <Button onClick={handleStop} disabled={!isRunning}>Остановить</Button>
          </div>
        </div>

        <div className="mb-6">
          <ScenarioSelector
            scenarios={scenarios ?? []}
            selected={selectedScenario}
            onSelect={setSelectedScenario}
          />
        </div>

        <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
          <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">ZK Подтверждение сценария</h3>
            <ZKProofBadge verified={zkVerified} />
          </div>

          <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">Метрики кризиса</h3>
            <CrisisMetricRadar metrics={crisisMetrics} />
          </div>

          <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">Реакция агентов</h3>
            <AgentResponseMonitor agents={agentResponses} />
          </div>
        </section>

        <section className="mb-10">
          <h2 className="text-xl font-semibold mb-4">Карта событий</h2>
          <CrisisMap events={stream.events} />
        </section>

        <section className="mb-10">
          <h2 className="text-xl font-semibold mb-4">Журнал симуляции</h2>
          <CrisisLogStream logs={stream.logs} />
        </section>

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          <ScenarioConfigModal
            onClose={() => {
              setModalOpen(false);
              refetch();
            }}
          />
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default CrisisSimulator;
