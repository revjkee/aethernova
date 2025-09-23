import React, { useEffect, useState, useMemo } from 'react';
import { getDelegationData, getVoteStatus, fetchDelegateMetadata } from '@/services/blockchain/votingRegistry';
import { useAuditLogger } from '@/shared/hooks/useAuditLogger';
import { useZKIdentity } from '@/shared/hooks/useZKIdentity';
import { useNotification } from '@/shared/hooks/useNotification';
import { verifyDelegationSignature } from '@/utils/crypto/delegationValidator';
import { Loader } from '@/shared/components/Loader';
import { Badge } from '@/shared/components/Badge';
import { truncateAddress } from '@/utils/formatters';
import { getRoleLabel } from '@/utils/governance/roleUtils';
import { DelegationStatus } from '@/types/governance';
import { getTimeAgo } from '@/utils/timeUtils';

type DelegatedVoteStatusProps = {
  userAddress: string;
  proposalId: string;
};

export const DelegatedVoteStatus: React.FC<DelegatedVoteStatusProps> = ({ userAddress, proposalId }) => {
  const [delegation, setDelegation] = useState<DelegationStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const { identityHash } = useZKIdentity(userAddress);
  const logAudit = useAuditLogger();
  const notify = useNotification();

  const loadDelegation = useMemo(() => async () => {
    try {
      setLoading(true);
      const delegationData = await getDelegationData(userAddress, proposalId);

      if (delegationData && verifyDelegationSignature(delegationData)) {
        const delegateMeta = await fetchDelegateMetadata(delegationData.delegateAddress);

        const enrichedDelegation: DelegationStatus = {
          ...delegationData,
          delegateRole: delegateMeta.role,
          delegateActivity: delegateMeta.participationScore,
          lastAction: delegateMeta.lastVoteTime
        };

        setDelegation(enrichedDelegation);
        logAudit({
          type: 'DELEGATION_STATUS_VIEWED',
          user: userAddress,
          identityHash,
          proposalId,
          delegate: delegationData.delegateAddress
        });
      } else {
        setDelegation(null);
      }
    } catch (err) {
      console.error('Delegation load error:', err);
      notify.error('Не удалось загрузить статус делегирования.');
      logAudit({
        type: 'DELEGATION_STATUS_ERROR',
        user: userAddress,
        proposalId,
        error: err.message
      });
    } finally {
      setLoading(false);
    }
  }, [userAddress, proposalId]);

  useEffect(() => {
    loadDelegation();
  }, [loadDelegation]);

  if (loading) {
    return <Loader label="Загрузка статуса делегирования..." />;
  }

  if (!delegation) {
    return (
      <div className="text-sm text-gray-500 italic">
        Голосование не делегировано. Вы участвуете напрямую.
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 shadow-sm">
      <h4 className="text-md font-semibold text-gray-900 dark:text-white mb-2">Статус делегирования</h4>
      <div className="flex items-center gap-3">
        <div className="flex flex-col text-sm text-gray-700 dark:text-gray-300">
          <span className="font-medium">Делегат:</span>
          <span>{truncateAddress(delegation.delegateAddress)}</span>

          <span className="font-medium mt-2">Роль:</span>
          <span>{getRoleLabel(delegation.delegateRole)}</span>

          <span className="font-medium mt-2">Активность:</span>
          <span>{Math.round(delegation.delegateActivity * 100)}%</span>

          <span className="font-medium mt-2">Последнее действие:</span>
          <span>{getTimeAgo(delegation.lastAction)}</span>
        </div>
        <div className="ml-auto">
          <Badge type="success" label="Делегирование активно" />
        </div>
      </div>
    </div>
  );
};

export default DelegatedVoteStatus;
