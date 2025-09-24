// path: src/pages/TelegramAdmin.tsx

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useTelegramBotQuery, useTelegramStream } from "@/features/telegram/telegramAPI";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Helmet } from "react-helmet";
import { Spinner } from "@/shared/components/Spinner";
import { Button } from "@/shared/components/Button";
import { toast } from "react-toastify";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { Modal } from "@/shared/components/Modal";
import { TelegramUserTable } from "@/features/telegram/components/TelegramUserTable";
import { TelegramBotStatusPanel } from "@/features/telegram/components/TelegramBotStatusPanel";
import { TelegramWebhookMonitor } from "@/features/telegram/components/TelegramWebhookMonitor";
import { TelegramAdminFilterPanel } from "@/features/telegram/components/TelegramAdminFilterPanel";
import { TelegramUserModal } from "@/features/telegram/components/TelegramUserModal";
import { TelegramLogStream } from "@/features/telegram/components/TelegramLogStream";
import { BroadcastMessageModal } from "@/features/telegram/components/BroadcastMessageModal";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";

const TelegramAdmin = () => {
  const { user } = useAuth();
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [broadcastOpen, setBroadcastOpen] = useState(false);

  const [filters, setFilters] = useState({
    subscription: "all",
    isBanned: false,
    query: "",
  });

  const debouncedFilters = useDebounce(filters, 300);
  const { data: users, isLoading, refetch } = useTelegramBotQuery(debouncedFilters);
  const { stream, connect, disconnect, zkVerified } = useTelegramStream();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, []);

  const handleSelectUser = (id: string) => {
    setSelectedUserId(id);
    setModalOpen(true);
  };

  const handleExport = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(users, null, 2));
      toast.success("Список пользователей экспортирован");
    } catch {
      toast.error("Ошибка экспорта");
    }
  };

  const subscriptionStats = useMemo(() => {
    if (!users) return { active: 0, trial: 0, expired: 0, banned: 0 };
    return users.reduce(
      (acc, u) => {
        if (u.isBanned) acc.banned++;
        else if (u.subscription === "active") acc.active++;
        else if (u.subscription === "trial") acc.trial++;
        else acc.expired++;
        return acc;
      },
      { active: 0, trial: 0, expired: 0, banned: 0 }
    );
  }, [users]);

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.TG_ADMIN]}>
      <Helmet>
        <title>Telegram Admin | TeslaAI Genesis</title>
        <meta name="description" content="Интерфейс управления Telegram-ботом: пользователи, подписки, логи, WebApp, webhook, рассылки" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Telegram Админка</h1>
          <div className="flex gap-2">
            <Button onClick={refetch}>Обновить</Button>
            <Button onClick={handleExport}>Экспорт JSON</Button>
            <Button onClick={() => setBroadcastOpen(true)}>Рассылка</Button>
          </div>
        </div>

        <div className="mb-6">
          <TelegramAdminFilterPanel filters={filters} onChange={setFilters} />
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-[200px]">
            <Spinner />
          </div>
        ) : (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-10">
              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">ZK Подтверждение webhook-интеграции</h3>
                <ZKProofBadge verified={zkVerified} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Статус Telegram-бота</h3>
                <TelegramBotStatusPanel status={stream.botStatus} />
              </div>

              <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold mb-2">Мониторинг Webhook</h3>
                <TelegramWebhookMonitor webhookEvents={stream.webhooks} />
              </div>
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Пользователи</h2>
              <TelegramUserTable users={users ?? []} onSelect={handleSelectUser} />
            </section>

            <section className="mb-10">
              <h2 className="text-xl font-semibold mb-4">Лог активности</h2>
              <TelegramLogStream logs={stream.logs} />
            </section>
          </>
        )}

        <Modal open={modalOpen} onClose={() => setModalOpen(false)}>
          {selectedUserId && <TelegramUserModal userId={selectedUserId} />}
        </Modal>

        <Modal open={broadcastOpen} onClose={() => setBroadcastOpen(false)}>
          <BroadcastMessageModal onSent={refetch} />
        </Modal>
      </div>
    </AccessGuard>
  );
};

export default TelegramAdmin;
