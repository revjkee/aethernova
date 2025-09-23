// path: src/pages/AgentSentinel.tsx

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

import { useSentinelAgentsQuery, useSentinelStream } from "@/features/agent/sentinelAPI";
import { SentinelAgentTable } from "@/features/agent/components/SentinelAgentTable";
import { SentinelThreatRadar } from "@/features/agent/components/SentinelThreatRadar";
import { SentinelLogStream } from "@/features/agent/components/SentinelLogStream";
import { SentinelAgentModal } from "@/features/agent/components/SentinelAgentModal";
import { SentinelFilterPanel } from "@/features/agent/components/SentinelFilterPanel";
import { SentinelNetworkMap } from "@/features/agent/components/SentinelNetworkMap";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";

const AgentSentinel = () => {
  const { user } = useAuth();
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);

  const [filters, setFilters] = useState({
    role: "all",
    status: "active",
    anomalyOnly: false,
    tactic: "all",
  });

  const debouncedFilters = useDebounce(filters, 300);
  const { data: agents, isLoading, refetch } = useSentinelAgentsQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useSentinelStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleSelect = (id: string) => {
    setSelectedAgentId(id);
  };

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(agents, null, 2));
      toast.success("Sentinel-агенты экспортированы");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  const agentStats = useMemo(() => {
    if (!agents) return { active: 0, inactive: 0, quarantined: 0, rogue: 0 };
    return agents.reduce(
      (acc, agent) => {
        switch (agent.status) {
          case "ACTIVE": acc.active++; break;
          case "INACTIVE": acc.inactive++; break;
          case "QUARANTINED": acc.quarantined++; break;
          case "ROGUE": acc.rogue++; break;
        }
        return acc;
      },
      { active: 0, inactive: 0, quarantined: 0, rogue: 0 }
    );
  }, [agents]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.SECURITY_OFFICER, ROLE.AI_GOVERNOR]}>
      <Helmet>
        <title>Agent Sentinel | TeslaAI</title>
        <meta name="description" content="Система стражевых агентов TeslaAI: мониторинг угроз, перехват аномалий, распределение ролей, аудит событий" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Agent Sentinel Dashboard</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
          </div>
        </div>

        <div className="mb-6">
          <SentinelFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Подпись агентов</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Карта перехвата</h3>
                <SentinelNetworkMap nodes={stream.networkNodes} threats={stream.detectedThreats} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Radar угроз</h3>
                <SentinelThreatRadar stats={agentStats} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Sentinel агенты</h2>
              <SentinelAgentTable agents={agents ?? []} onSelect={handleSelect} />
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Live журнал безопасности</h2>
              <SentinelLogStream logs={stream.logs} />
            </section>
          </>
        )}

        <Modal open={!!selectedAgentId} onClose={() => setSelectedAgentId(null)}>
          {selectedAgentId && <SentinelAgentModal agentId={selectedAgentId} />}
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default AgentSentinel;
