// path: src/pages/AIOverrideDashboard.tsx

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Helmet } from "react-helmet";
import { Spinner } from "@/shared/components/Spinner";
import { Button } from "@/shared/components/Button";
import { Modal } from "@/shared/components/Modal";
import { toast } from "react-toastify";
import { useDebounce } from "@/shared/hooks/useDebounce";

import { useOverrideQuery, useOverrideStream } from "@/features/override/overrideAPI";
import { OverrideGroupStatus } from "@/features/override/components/OverrideGroupStatus";
import { OverrideSignalTable } from "@/features/override/components/OverrideSignalTable";
import { OverrideLogStream } from "@/features/override/components/OverrideLogStream";
import { OverrideRiskRadar } from "@/features/override/components/OverrideRiskRadar";
import { OverridePolicyPanel } from "@/features/override/components/OverridePolicyPanel";
import { OverrideSignalModal } from "@/features/override/components/OverrideSignalModal";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";

const AIOverrideDashboard = () => {
  const { user } = useAuth();
  const [selectedSignalId, setSelectedSignalId] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  const [filters, setFilters] = useState({
    agent: "all",
    severity: "all",
    status: "all",
    acked: false,
  });

  const debouncedFilters = useDebounce(filters, 400);
  const { data: signals, isLoading, refetch } = useOverrideQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useOverrideStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleSelectSignal = (id: string) => {
    setSelectedSignalId(id);
    setModalOpen(true);
  };

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(signals, null, 2));
      toast.success("Сигналы override экспортированы");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  const overrideStats = useMemo(() => {
    if (!signals) return { critical: 0, warning: 0, normal: 0 };
    return signals.reduce(
      (acc, s) => {
        if (s.severity === "CRITICAL") acc.critical++;
        else if (s.severity === "WARNING") acc.warning++;
        else acc.normal++;
        return acc;
      },
      { critical: 0, warning: 0, normal: 0 }
    );
  }, [signals]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.SAFETY_ENGINEER, ROLE.AI_GOVERNOR]}>
      <Helmet>
        <title>AI Override Panel | TeslaAI</title>
        <meta name="description" content="Панель контроля override-сигналов ИИ: вмешательство, аудит, ZK-подписи, риск, статус агентов." />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">AI Override Dashboard</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
          </div>
        </div>

        <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
          <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">ZK Подпись override-сигналов</h3>
            <ZKProofBadge verified={zkVerified} />
          </div>

          <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">Группы override-контроля</h3>
            <OverrideGroupStatus status={stream.groupStatus} />
          </div>

          <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">Риск override-сигналов</h3>
            <OverrideRiskRadar stats={overrideStats} />
          </div>
        </section>

        <section className="mb-10">
          <h2 className="text-xl font-semibold mb-4">Сценарии вмешательства</h2>
          <OverrideSignalTable signals={signals ?? []} onSelect={handleSelectSignal} />
        </section>

        <section className="mb-10">
          <h2 className="text-xl font-semibold mb-4">Live аудит действий</h2>
          <OverrideLogStream logs={stream.logs} />
        </section>

        <section className="mb-10">
          <h2 className="text-xl font-semibold mb-4">Политики override</h2>
          <OverridePolicyPanel policies={stream.policies} />
        </section>

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          {selectedSignalId && <OverrideSignalModal signalId={selectedSignalId} />}
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default AIOverrideDashboard;
