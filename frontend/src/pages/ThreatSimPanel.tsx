// path: src/pages/ThreatSimPanel.tsx

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useThreatSimQuery, useThreatSimStream } from "@/features/threatsim/threatSimAPI";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Helmet } from "react-helmet";
import { Spinner } from "@/shared/components/Spinner";
import { Button } from "@/shared/components/Button";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { toast } from "react-toastify";
import { Modal } from "@/shared/components/Modal";
import { ThreatSimScenarioTable } from "@/features/threatsim/components/ThreatSimScenarioTable";
import { ThreatSimFilterPanel } from "@/features/threatsim/components/ThreatSimFilterPanel";
import { ThreatSimStatusRadar } from "@/features/threatsim/components/ThreatSimStatusRadar";
import { ThreatSimDetailModal } from "@/features/threatsim/components/ThreatSimDetailModal";
import { ThreatSimLiveLog } from "@/features/threatsim/components/ThreatSimLiveLog";
import { ThreatSimSurfaceMap } from "@/features/threatsim/components/ThreatSimSurfaceMap";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { ThreatSimRunnerModal } from "@/features/threatsim/components/ThreatSimRunnerModal";

const ThreatSimPanel = () => {
  const { user } = useAuth();
  const [selectedScenarioId, setSelectedScenarioId] = useState<string | null>(null);
  const [runnerOpen, setRunnerOpen] = useState(false);

  const [filters, setFilters] = useState({
    tactic: "all",
    impact: "all",
    status: "all",
    tag: "",
  });

  const debouncedFilters = useDebounce(filters, 400);
  const { data: scenarios, isLoading, refetch } = useThreatSimQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useThreatSimStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleSelect = (id: string) => {
    setSelectedScenarioId(id);
  };

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(scenarios, null, 2));
      toast.success("Сценарии экспортированы");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  const simStats = useMemo(() => {
    if (!scenarios) return { running: 0, failed: 0, completed: 0 };
    return scenarios.reduce(
      (acc, s) => {
        if (s.status === "RUNNING") acc.running++;
        else if (s.status === "FAILED") acc.failed++;
        else acc.completed++;
        return acc;
      },
      { running: 0, failed: 0, completed: 0 }
    );
  }, [scenarios]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.BLUE_TEAM, ROLE.RED_TEAM]}>
      <Helmet>
        <title>Threat Simulator | TeslaAI NeuroCity</title>
        <meta name="description" content="Центр симуляции угроз: запуск, аудит, карты поверхности атаки, ZK-подписи, анализ последствий." />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Threat Simulation Panel</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
            <Button onClick={() => setRunnerOpen(true)}>Запустить сценарий</Button>
          </div>
        </div>

        <div className="mb-6">
          <ThreatSimFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Проверка сценариев</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Карта поверхности атаки</h3>
                <ThreatSimSurfaceMap surface={stream.attackSurface} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Статистика по сценариям</h3>
                <ThreatSimStatusRadar stats={simStats} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Сценарии угроз</h2>
              <ThreatSimScenarioTable scenarios={scenarios ?? []} onSelect={handleSelect} />
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Live Лог активности</h2>
              <ThreatSimLiveLog logs={stream.logs} />
            </section>
          </>
        )}

        <Modal open={!!selectedScenarioId} onClose={() => setSelectedScenarioId(null)}>
          {selectedScenarioId && <ThreatSimDetailModal scenarioId={selectedScenarioId} />}
        </Modal>

        <Modal open={runnerOpen} onClose={() => setRunnerOpen(false)}>
          <ThreatSimRunnerModal onExecuted={refetch} />
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default ThreatSimPanel;
