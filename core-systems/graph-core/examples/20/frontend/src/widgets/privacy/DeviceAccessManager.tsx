import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Button } from '@/shared/components/Button';
import { Spinner } from '@/shared/components/Spinner';
import { ConfirmModal } from '@/shared/components/ConfirmModal';
import { AuditLogPanel } from '@/shared/components/AuditLogPanel';
import { toast } from 'react-hot-toast';
import { DeviceAccessItem } from '@/widgets/Privacy/components/DeviceAccessItem';
import { getDeviceAccessList, revokeDeviceAccess, trustDevice } from '@/services/api/deviceAPI';
import { usePermission } from '@/shared/hooks/usePermission';
import { DeviceSession } from '@/shared/types/privacy';
import { formatDistanceToNowStrict } from 'date-fns';
import { ShieldAlertIcon, Trash2Icon } from 'lucide-react';

interface Props {
  userId: string;
  allowRevoke?: boolean;
  showAudit?: boolean;
  limitToCurrentUser?: boolean;
}

const DeviceAccessManager: React.FC<Props> = ({
  userId,
  allowRevoke = true,
  showAudit = true,
  limitToCurrentUser = false,
}) => {
  const [selectedDevice, setSelectedDevice] = useState<DeviceSession | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const canRevoke = usePermission('device:revoke');

  const {
    data: devices,
    isLoading,
    isError,
    refetch,
  } = useQuery<DeviceSession[]>({
    queryKey: ['deviceAccessList', userId],
    queryFn: () => getDeviceAccessList(userId),
    staleTime: 1000 * 60 * 5,
  });

  const revokeMutation = useMutation({
    mutationFn: (deviceId: string) => revokeDeviceAccess(userId, deviceId),
    onSuccess: () => {
      toast.success('Доступ к устройству отозван');
      refetch();
    },
    onError: () => {
      toast.error('Ошибка при отзыве устройства');
    },
  });

  const trustMutation = useMutation({
    mutationFn: (deviceId: string) => trustDevice(userId, deviceId),
    onSuccess: () => {
      toast.success('Устройство помечено как доверенное');
      refetch();
    },
    onError: () => {
      toast.error('Ошибка при обновлении доверия к устройству');
    },
  });

  const filteredDevices = useMemo(() => {
    if (!devices) return [];
    return limitToCurrentUser
      ? devices.filter((d) => d.isCurrentSession)
      : devices;
  }, [devices, limitToCurrentUser]);

  const handleRevoke = useCallback((device: DeviceSession) => {
    setSelectedDevice(device);
    setConfirmOpen(true);
  }, []);

  const confirmRevoke = () => {
    if (selectedDevice) {
      revokeMutation.mutate(selectedDevice.deviceId);
    }
    setConfirmOpen(false);
  };

  const handleTrust = (deviceId: string) => {
    trustMutation.mutate(deviceId);
  };

  return (
    <div className="w-full p-4 rounded-lg border bg-white dark:bg-zinc-900 shadow-sm">
      <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
        <ShieldAlertIcon size={20} />
        Менеджер доступа к устройствам
      </h2>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <Spinner />
        </div>
      ) : isError ? (
        <div className="text-red-600 text-sm">Ошибка загрузки данных</div>
      ) : filteredDevices.length === 0 ? (
        <div className="text-muted-foreground text-sm">Нет активных устройств</div>
      ) : (
        <div className="flex flex-col gap-4">
          {filteredDevices.map((device) => (
            <DeviceAccessItem
              key={device.deviceId}
              device={device}
              onRevoke={() => handleRevoke(device)}
              onTrust={() => handleTrust(device.deviceId)}
              canRevoke={canRevoke && allowRevoke}
            />
          ))}
        </div>
      )}

      {showAudit && (
        <div className="mt-6">
          <AuditLogPanel resource={`privacy:devices:${userId}`} maxEntries={10} />
        </div>
      )}

      <ConfirmModal
        isOpen={confirmOpen}
        title="Отозвать доступ к устройству?"
        description={`Вы действительно хотите отозвать доступ к устройству: ${selectedDevice?.deviceName}? Это завершит все его активные сессии.`}
        onCancel={() => setConfirmOpen(false)}
        onConfirm={confirmRevoke}
        icon={<Trash2Icon className="text-red-600" size={24} />}
      />
    </div>
  );
};

export default React.memo(DeviceAccessManager);
