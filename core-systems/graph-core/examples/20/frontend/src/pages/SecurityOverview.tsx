// path: src/pages/SecurityOverview.tsx

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useThreatStream, useThreatQuery } from "@/features/security/securityAPI";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Helmet } from "react-helmet";
import { Spinner } from "@/shared/components/Spinner";
import { Button } from "@/shared/components/Button";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { toast } from "react-toastify";
import { SecurityRiskMap } from "@/features/security/components/SecurityRiskMap";
import { SecurityTimeline } from "@/features/security/components/SecurityTimeline";
import { ThreatFilterPanel } from "@/features/security/components/ThreatFilterPanel";
import { ThreatTable } from "@/features/security/components/ThreatTable";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { Modal } from "@/shared/components/Modal";
import { ThreatDetailModal } from "@/features/security/components/ThreatDetailModal";
import { RiskSummaryPanel } from "@/features/security/components/RiskSummaryPanel";

const SecurityOverview = () => {
  const { user } = useAuth();
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null);

  const [filters, setFilters] = useState({
    severity: "all",
    source: "all",
    affectedSystem: "all",
    tag: "",
  });

  const debouncedFilters = useDebounce(filters, 300);
  const { data: threats, isLoading, refetch } = useThreatQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useThreatStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleSelectThreat = (id: string) => {
    setSelectedThreatId(id);
    setModalOpen(true);
  };

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(threats, null, 2));
      toast.success("Данные экспортированы");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  const severityStats = useMemo(() => {
    if (!threats) return { critical: 0, high: 0, medium: 0, low: 0 };
    return threats.reduce(
      (acc, t) => {
        switch (t.severity) {
          case "CRITICAL": acc.critical++; break;
          case "HIGH": acc.high++; break;
          case "MEDIUM": acc.medium++; break;
          case "LOW": acc.low++; break;
        }
        return acc;
      },
      { critical: 0, high: 0, medium: 0, low: 0 }
    );
  }, [threats]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.SECOPS, ROLE.SECURITY]}>
      <Helmet>
        <title>Security Overview | TeslaAI NeuroCity</title>
        <meta name="description" content="Панель наблюдения за угрозами, зонами риска и событиями безопасности в реальном времени" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Обзор безопасности</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
          </div>
        </div>

        <div className="mb-6">
          <ThreatFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Проверка инцидентов</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Карта активных угроз</h3>
                <SecurityRiskMap data={stream.riskMap} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Сводка по критичности</h3>
                <RiskSummaryPanel stats={severityStats} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Хронология событий безопасности</h2>
              <SecurityTimeline data={stream.timeline} />
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Зарегистрированные угрозы</h2>
              <ThreatTable items={threats ?? []} onSelect={handleSelectThreat} />
            </section>
          </>
        )}

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          {selectedThreatId && <ThreatDetailModal threatId={selectedThreatId} />}
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default SecurityOverview;
