// path: src/pages/EthicsAnalyzer.tsx

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useEthicsScan, useFlaggedActionsQuery } from "@/features/ethics/ethicsAPI";
import { useBehaviorAudit } from "@/features/ethics/hooks/useBehaviorAudit";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Helmet } from "react-helmet";
import { Spinner } from "@/shared/components/Spinner";
import { toast } from "react-toastify";
import { Button } from "@/shared/components/Button";
import { Modal } from "@/shared/components/Modal";
import { EthicsRadarChart } from "@/features/ethics/components/EthicsRadarChart";
import { EthicsLogTable } from "@/features/ethics/components/EthicsLogTable";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { AIConflictHeatmap } from "@/features/ethics/components/AIConflictHeatmap";
import { MoralContractReport } from "@/features/ethics/components/MoralContractReport";

const EthicsAnalyzer = () => {
  const { user } = useAuth();
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 400);
  const [modalOpen, setModalOpen] = useState(false);

  const { data: ethicsData, isLoading, refetch } = useEthicsScan({ query: debouncedSearch });
  const { data: violations } = useFlaggedActionsQuery({ userId: user?.id });
  const audit = useBehaviorAudit(user?.id);

  useEffect(() => {
    audit.init();
    return () => audit.shutdown();
  }, []);

  const riskScore = useMemo(() => {
    if (!ethicsData) return 0;
    const { safety, bias, transparency, autonomy } = ethicsData.indicators;
    return (safety + bias + transparency + autonomy) / 4;
  }, [ethicsData]);

  const handleForceScan = async () => {
    try {
      await refetch();
      toast.success("Этический анализ обновлён");
    } catch {
      toast.error("Ошибка повторного сканирования");
    }
  };

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.AUDITOR]}>
      <Helmet>
        <title>Ethics Analyzer | NeuroCity</title>
        <meta name="description" content="AI-система анализа этических нарушений, прозрачности и автономии" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-3xl font-bold">Ethics Analyzer</h1>
          <Button onClick={handleForceScan}>Пересканировать</Button>
        </div>

        <div className="mb-6">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full max-w-lg px-4 py-2 border rounded-md"
            placeholder="Поиск по идентификатору или нарушению..."
          />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 rounded-lg p-5 shadow">
                <h3 className="text-lg font-semibold mb-2">AI Risk Profile</h3>
                <EthicsRadarChart indicators={ethicsData?.indicators} />
              </div>

              <div className="bg-white dark:bg-zinc-900 rounded-lg p-5 shadow">
                <h3 className="text-lg font-semibold mb-2">ZK-Доказательство Безопасности</h3>
                <ZKProofBadge verified={ethicsData?.zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 rounded-lg p-5 shadow">
                <h3 className="text-lg font-semibold mb-2">Конфликты в принятии решений</h3>
                <AIConflictHeatmap matrix={ethicsData?.conflictMatrix} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Этические нарушения и флаги</h2>
              <EthicsLogTable logs={violations ?? []} filter={debouncedSearch} />
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Моральный контракт</h2>
              <MoralContractReport contract={ethicsData?.moralContract} />
            </section>
          </>
        )}

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          <div className="p-6">
            <h2 className="text-xl font-semibold mb-4">Логи поведенческого аудита</h2>
            <ul className="text-sm text-gray-700 dark:text-gray-300 space-y-2 max-h-[400px] overflow-auto">
              {audit.logs.map((log, index) => (
                <li key={index} className="border-b py-1">{log}</li>
              ))}
            </ul>
          </div>
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default EthicsAnalyzer;
