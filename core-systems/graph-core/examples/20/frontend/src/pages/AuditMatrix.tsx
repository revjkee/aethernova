// path: src/pages/AuditMatrix.tsx

import { useEffect, useMemo, useState } from "react";
import { Helmet } from "react-helmet";
import { toast } from "react-toastify";

import { AccessGuard } from "@/shared/components/AccessGuard";
import { Spinner } from "@/shared/components/Spinner";
import { Button } from "@/shared/components/Button";
import { Modal } from "@/shared/components/Modal";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useAuditMatrixQuery, useAuditMatrixStream } from "@/features/audit/auditAPI";
import { AuditMatrixTable } from "@/features/audit/components/AuditMatrixTable";
import { AuditMatrixFilterPanel } from "@/features/audit/components/AuditMatrixFilterPanel";
import { AuditRiskRadar } from "@/features/audit/components/AuditRiskRadar";
import { AuditLogStream } from "@/features/audit/components/AuditLogStream";
import { AuditMatrixHeatmap } from "@/features/audit/components/AuditMatrixHeatmap";
import { AuditEventDetailModal } from "@/features/audit/components/AuditEventDetailModal";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { ROLE } from "@/shared/constants/roles";

const AuditMatrix = () => {
  const { user } = useAuth();
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  const [filters, setFilters] = useState({
    actor: "all",
    subsystem: "all",
    action: "all",
    riskLevel: "all",
    anomalyOnly: false,
  });

  const debouncedFilters = useDebounce(filters, 300);
  const { data: auditMatrix, isLoading, refetch } = useAuditMatrixQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useAuditMatrixStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(auditMatrix, null, 2));
      toast.success("Матрица аудита экспортирована");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  const auditStats = useMemo(() => {
    if (!auditMatrix) return { critical: 0, high: 0, medium: 0, low: 0 };
    return auditMatrix.reduce(
      (acc, entry) => {
        switch (entry.risk) {
          case "CRITICAL":
            acc.critical++;
            break;
          case "HIGH":
            acc.high++;
            break;
          case "MEDIUM":
            acc.medium++;
            break;
          default:
            acc.low++;
        }
        return acc;
      },
      { critical: 0, high: 0, medium: 0, low: 0 }
    );
  }, [auditMatrix]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.AUDITOR, ROLE.SECURITY_OFFICER]}>
      <Helmet>
        <title>Audit Matrix | TeslaAI NeuroCity</title>
        <meta name="description" content="Промышленная панель аудита: действия, агенты, риски, ZK-верификация, сигналы отклонения." />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Audit Matrix</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
          </div>
        </div>

        <div className="mb-6">
          <AuditMatrixFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Проверка аудита</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Риск по уровням</h3>
                <AuditRiskRadar stats={auditStats} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Матрица событий</h3>
                <AuditMatrixHeatmap data={auditMatrix ?? []} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">События</h2>
              <AuditMatrixTable entries={auditMatrix ?? []} onSelect={setSelectedEventId} />
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Журнал аудита (Live)</h2>
              <AuditLogStream logs={stream.logs} />
            </section>
          </>
        )}

        <Modal open={!!selectedEventId} onClose={() => setSelectedEventId(null)}>
          {selectedEventId && <AuditEventDetailModal eventId={selectedEventId} />}
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default AuditMatrix;
