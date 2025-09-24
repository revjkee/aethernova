// path: src/pages/StrategicIntel.tsx

import { useEffect, useState, useMemo } from "react";
import { Helmet } from "react-helmet";
import { toast } from "react-toastify";

import { useAuth } from "@/features/auth/hooks/useAuth";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Spinner } from "@/shared/components/Spinner";
import { Button } from "@/shared/components/Button";
import { Modal } from "@/shared/components/Modal";

import { useIntelSourcesQuery, useIntelStream } from "@/features/intel/intelAPI";
import { IntelFeedTable } from "@/features/intel/components/IntelFeedTable";
import { IntelSourceSelector } from "@/features/intel/components/IntelSourceSelector";
import { IntelRiskRadar } from "@/features/intel/components/IntelRiskRadar";
import { IntelAlertPanel } from "@/features/intel/components/IntelAlertPanel";
import { IntelZKProofPanel } from "@/features/intel/components/IntelZKProofPanel";
import { StrategicMap } from "@/features/intel/components/StrategicMap";
import { RiskActionModal } from "@/features/intel/components/RiskActionModal";

const StrategicIntel = () => {
  const { user } = useAuth();
  const [selectedSource, setSelectedSource] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  const { data: sources, refetch } = useIntelSourcesQuery();
  const { stream, connect, disconnect, zkVerified, threats, locations } = useIntelStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const currentThreats = useMemo(() => threats?.filter(t => t.active) ?? [], [threats]);

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(threats, null, 2));
      toast.success("Разведданные экспортированы");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.INTEL_ANALYST, ROLE.STRATEGY_DIRECTOR]}>
      <Helmet>
        <title>Strategic Intel | TeslaAI NeuroCity</title>
        <meta name="description" content="AI-управляемая панель стратегической разведки, интегрированная с ядром intel-core и этическими модулями" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Strategic Intelligence</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
            <Button onClick={() => setModalOpen(true)}>Принять меры</Button>
          </div>
        </div>

        <div className="mb-6">
          <IntelSourceSelector sources={sources ?? []} selected={selectedSource} onSelect={setSelectedSource} />
        </div>

        <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
          <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">ZK-доказательства источников</h3>
            <IntelZKProofPanel verified={zkVerified} />
          </div>

          <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">Оценка угроз (AI Risk Map)</h3>
            <IntelRiskRadar threats={currentThreats} />
          </div>

          <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">AI-оповещения и сценарии</h3>
            <IntelAlertPanel alerts={stream.alerts} />
          </div>
        </section>

        <section className="mb-10">
          <h2 className="text-xl font-semibold mb-4">Карта стратегических угроз</h2>
          <StrategicMap markers={locations} />
        </section>

        <section className="mb-10">
          <h2 className="text-xl font-semibold mb-4">Поток разведданных</h2>
          <IntelFeedTable items={stream.feeds ?? []} />
        </section>

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          <RiskActionModal onClose={() => setModalOpen(false)} threats={currentThreats} />
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default StrategicIntel;
