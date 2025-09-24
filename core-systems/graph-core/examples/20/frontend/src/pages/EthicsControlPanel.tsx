// path: src/pages/EthicsControlPanel.tsx

import { useEffect, useMemo, useState } from "react";
import { Helmet } from "react-helmet";
import { toast } from "react-toastify";

import { useAuth } from "@/features/auth/hooks/useAuth";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Button } from "@/shared/components/Button";
import { Spinner } from "@/shared/components/Spinner";
import { Modal } from "@/shared/components/Modal";
import { useDebounce } from "@/shared/hooks/useDebounce";

import { useEthicsPoliciesQuery, useEthicsStream } from "@/features/ethics/ethicsAPI";
import { EthicsPolicyTable } from "@/features/ethics/components/EthicsPolicyTable";
import { EthicsConflictRadar } from "@/features/ethics/components/EthicsConflictRadar";
import { EthicsLogStream } from "@/features/ethics/components/EthicsLogStream";
import { EthicsPolicyEditorModal } from "@/features/ethics/components/EthicsPolicyEditorModal";
import { EthicsFilterPanel } from "@/features/ethics/components/EthicsFilterPanel";
import { EthicsAIOverrideMap } from "@/features/ethics/components/EthicsAIOverrideMap";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";

const EthicsControlPanel = () => {
  const { user } = useAuth();
  const [selectedPolicyId, setSelectedPolicyId] = useState<string | null>(null);
  const [editModalOpen, setEditModalOpen] = useState(false);

  const [filters, setFilters] = useState({
    agent: "all",
    domain: "all",
    severity: "all",
    verified: true,
  });

  const debouncedFilters = useDebounce(filters, 300);
  const { data: policies, isLoading, refetch } = useEthicsPoliciesQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useEthicsStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(policies, null, 2));
      toast.success("Этические политики экспортированы");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  const policyStats = useMemo(() => {
    if (!policies) return { low: 0, medium: 0, high: 0, critical: 0 };
    return policies.reduce(
      (acc, policy) => {
        switch (policy.severity) {
          case "CRITICAL": acc.critical++; break;
          case "HIGH": acc.high++; break;
          case "MEDIUM": acc.medium++; break;
          default: acc.low++;
        }
        return acc;
      },
      { low: 0, medium: 0, high: 0, critical: 0 }
    );
  }, [policies]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.ETHICS_SUPERVISOR, ROLE.GOVERNANCE_AI]}>
      <Helmet>
        <title>Ethics Control Panel | TeslaAI</title>
        <meta name="description" content="Централизованная панель AI-этики: правила, конфликты, override, аудиты, ограничения" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Ethics Control Panel</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
            <Button onClick={() => setEditModalOpen(true)}>Добавить правило</Button>
          </div>
        </div>

        <div className="mb-6">
          <EthicsFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Подтверждение политик</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Radar конфликтов</h3>
                <EthicsConflictRadar stats={policyStats} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Карта override конфликтов</h3>
                <EthicsAIOverrideMap overrides={stream.overrides} agents={stream.agents} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Правила морали</h2>
              <EthicsPolicyTable policies={policies ?? []} onSelect={setSelectedPolicyId} />
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Live журнал этических нарушений</h2>
              <EthicsLogStream logs={stream.logs} />
            </section>
          </>
        )}

        <Modal open={editModalOpen} onClose={() => setEditModalOpen(false)}>
          <EthicsPolicyEditorModal onClose={() => {
            setEditModalOpen(false);
            refetch();
          }} />
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default EthicsControlPanel;
