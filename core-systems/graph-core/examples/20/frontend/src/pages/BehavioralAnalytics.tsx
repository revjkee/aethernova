// path: src/pages/BehavioralAnalytics.tsx

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useBehaviorStream, useBehaviorQuery } from "@/features/behavior/behaviorAPI";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Helmet } from "react-helmet";
import { Spinner } from "@/shared/components/Spinner";
import { Button } from "@/shared/components/Button";
import { toast } from "react-toastify";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { BehaviorFilterPanel } from "@/features/behavior/components/BehaviorFilterPanel";
import { BehaviorRiskChart } from "@/features/behavior/components/BehaviorRiskChart";
import { BehaviorHeatmap } from "@/features/behavior/components/BehaviorHeatmap";
import { BehaviorPatternTable } from "@/features/behavior/components/BehaviorPatternTable";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { Modal } from "@/shared/components/Modal";
import { BehaviorDetailModal } from "@/features/behavior/components/BehaviorDetailModal";

const BehavioralAnalytics = () => {
  const { user } = useAuth();
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);

  const [filters, setFilters] = useState({
    userId: "",
    role: "all",
    riskLevel: "all",
    behaviorTag: "",
  });

  const debouncedFilters = useDebounce(filters, 400);
  const { data: patterns, isLoading, refetch } = useBehaviorQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useBehaviorStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleSelect = (id: string) => {
    setSelectedSessionId(id);
    setModalOpen(true);
  };

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(patterns, null, 2));
      toast.success("Данные экспортированы");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  const riskSummary = useMemo(() => {
    if (!patterns) return { high: 0, medium: 0, low: 0 };
    return patterns.reduce(
      (acc, p) => {
        if (p.risk === "HIGH") acc.high++;
        else if (p.risk === "MEDIUM") acc.medium++;
        else acc.low++;
        return acc;
      },
      { high: 0, medium: 0, low: 0 }
    );
  }, [patterns]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.SECURITY, ROLE.ANALYST]}>
      <Helmet>
        <title>Behavioral Analytics | NeuroCity</title>
        <meta name="description" content="Анализ поведенческих паттернов пользователей и агентов, выявление аномалий и рисков" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Behavioral Analytics</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
          </div>
        </div>

        <div className="mb-6">
          <BehaviorFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 rounded-lg p-6 shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Подтверждение действий</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 rounded-lg p-6 shadow">
                <h3 className="text-lg font-semibold mb-2">Поведенческая карта</h3>
                <BehaviorHeatmap matrix={stream.heatmap} />
              </div>

              <div className="bg-white dark:bg-zinc-900 rounded-lg p-6 shadow">
                <h3 className="text-lg font-semibold mb-2">Распределение рисков</h3>
                <BehaviorRiskChart summary={riskSummary} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Зарегистрированные поведенческие паттерны</h2>
              <BehaviorPatternTable items={patterns ?? []} onSelect={handleSelect} />
            </section>
          </>
        )}

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          {selectedSessionId && <BehaviorDetailModal sessionId={selectedSessionId} />}
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default BehavioralAnalytics;
