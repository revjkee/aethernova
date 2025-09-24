import React, { useEffect, useState } from 'react';
import { useUserRole } from '@/shared/hooks/useUserRole';
import { useZKIdentity } from '@/shared/hooks/useZKIdentity';
import { useAuditLogger } from '@/shared/hooks/useAuditLogger';
import { AlertBanner } from '@/shared/components/AlertBanner';
import { ShieldLockIcon } from '@/shared/components/icons/ShieldLockIcon';
import { Loader } from '@/shared/components/Loader';
import { AccessStatusTag } from '@/shared/components/AccessStatusTag';
import { RoleDisplay } from '@/shared/components/RoleDisplay';
import { getAccessRestrictions } from '@/services/governance/accessControlService';
import { getTimeAgo } from '@/utils/timeUtils';

type VotingAccessDeniedProps = {
  userAddress: string;
  proposalId: string;
};

type AccessRestriction = {
  reason: string;
  enforcedBy: 'System' | 'Admin' | 'PolicyEngine';
  enforcedAt: string;
  recoverable: boolean;
  instructions: string;
  zkRequired: boolean;
};

export const VotingAccessDenied: React.FC<VotingAccessDeniedProps> = ({
  userAddress,
  proposalId
}) => {
  const [restriction, setRestriction] = useState<AccessRestriction | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const { role } = useUserRole(userAddress);
  const { zkProofAvailable, identityHash } = useZKIdentity(userAddress);
  const logAudit = useAuditLogger();

  useEffect(() => {
    const loadRestriction = async () => {
      try {
        const res = await getAccessRestrictions(userAddress, proposalId);
        setRestriction(res);
        logAudit({
          type: 'ACCESS_DENIED_VIEWED',
          user: userAddress,
          proposalId,
          identityHash,
          role,
          restrictionReason: res.reason,
          enforcedBy: res.enforcedBy,
          zkVerified: zkProofAvailable
        });
      } catch (err) {
        setError('Ошибка при получении ограничений доступа.');
        logAudit({
          type: 'ACCESS_DENIED_ERROR',
          user: userAddress,
          proposalId,
          error: err.message
        });
      } finally {
        setLoading(false);
      }
    };

    loadRestriction();
  }, [userAddress, proposalId]);

  if (loading) {
    return <Loader label="Проверка политики доступа..." />;
  }

  if (error || !restriction) {
    return (
      <AlertBanner
        type="error"
        title="Ошибка доступа"
        message={error ?? 'Ограничение не найдено. Обратитесь к администратору.'}
      />
    );
  }

  return (
    <div className="bg-white dark:bg-gray-900 border border-red-500 dark:border-red-700 rounded-lg p-6 shadow-md">
      <div className="flex items-center gap-3 mb-4">
        <ShieldLockIcon className="w-6 h-6 text-red-600 dark:text-red-400" />
        <h3 className="text-lg font-semibold text-red-800 dark:text-red-300">
          Доступ к голосованию заблокирован
        </h3>
      </div>

      <div className="text-sm text-gray-600 dark:text-gray-400 mb-4">
        Блокировка установлена: <strong>{restriction.enforcedBy}</strong><br />
        Время: {getTimeAgo(restriction.enforcedAt)}<br />
        Роль пользователя: <RoleDisplay role={role} /><br />
        ZK подтверждение: {zkProofAvailable ? 'да' : 'нет'}
      </div>

      <AccessStatusTag level="denied" reason={restriction.reason} />

      <div className="mt-4">
        <h4 className="text-md font-semibold text-gray-800 dark:text-gray-200">Причина</h4>
        <p className="text-sm text-gray-700 dark:text-gray-300 mt-1">
          {restriction.reason}
        </p>
      </div>

      {restriction.zkRequired && (
        <AlertBanner
          type="warning"
          title="Требуется Zero-Knowledge доказательство"
          message="Для восстановления доступа необходимо пройти ZK-подтверждение личности."
        />
      )}

      {restriction.instructions && (
        <div className="mt-5">
          <h4 className="text-md font-semibold text-gray-800 dark:text-gray-200">Что можно сделать</h4>
          <p className="text-sm text-gray-700 dark:text-gray-300 mt-1">
            {restriction.instructions}
          </p>
        </div>
      )}

      {!restriction.recoverable && (
        <AlertBanner
          type="error"
          title="Доступ невозможно восстановить"
          message="Это блокировка без возможности восстановления. Обратитесь в DAO-контроль."
        />
      )}
    </div>
  );
};

export default VotingAccessDenied;
