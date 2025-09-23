import React, { useEffect, useState } from 'react';
import { useZKIdentity } from '@/shared/hooks/useZKIdentity';
import { useAuditLogger } from '@/shared/hooks/useAuditLogger';
import { validateAnonVotingEligibility } from '@/services/privacy/zkVotingGuard';
import { setAnonVotePreference } from '@/services/governance/userPreferences';
import { Tooltip } from '@/shared/components/Tooltip';
import { ToggleSwitch } from '@/shared/components/ToggleSwitch';
import { ShieldIcon } from '@/shared/components/icons/ShieldIcon';
import { LockIcon } from '@/shared/components/icons/LockIcon';
import { AlertBanner } from '@/shared/components/AlertBanner';
import { Loader } from '@/shared/components/Loader';
import { AnonVoteStatusBadge } from '@/shared/components/AnonVoteStatusBadge';

type AnonymousVoteToggleProps = {
  userAddress: string;
  proposalId: string;
};

const AnonymousVoteToggle: React.FC<AnonymousVoteToggleProps> = ({ userAddress, proposalId }) => {
  const [enabled, setEnabled] = useState(false);
  const [eligible, setEligible] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { identityHash, zkProofAvailable } = useZKIdentity(userAddress);
  const logAudit = useAuditLogger();

  useEffect(() => {
    const checkEligibility = async () => {
      setLoading(true);
      try {
        const result = await validateAnonVotingEligibility(userAddress, proposalId);
        setEligible(result.eligible);
        setEnabled(result.currentPreference);
        logAudit({
          type: 'ANON_ELIGIBILITY_CHECKED',
          user: userAddress,
          identityHash,
          proposalId,
          eligible: result.eligible,
        });
      } catch (err) {
        setError('Ошибка проверки возможности анонимного голосования.');
        logAudit({
          type: 'ANON_ELIGIBILITY_FAILED',
          user: userAddress,
          proposalId,
          error: err.message,
        });
      } finally {
        setLoading(false);
      }
    };

    checkEligibility();
  }, [userAddress, proposalId]);

  const handleToggle = async () => {
    if (!eligible) return;
    try {
      setLoading(true);
      await setAnonVotePreference(userAddress, proposalId, !enabled);
      setEnabled((prev) => !prev);
      logAudit({
        type: 'ANON_VOTE_PREFERENCE_CHANGED',
        user: userAddress,
        proposalId,
        newValue: !enabled,
        identityHash,
      });
    } catch (err) {
      setError('Не удалось изменить настройку анонимности.');
      logAudit({
        type: 'ANON_VOTE_PREFERENCE_CHANGE_FAILED',
        user: userAddress,
        proposalId,
        error: err.message,
      });
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <Loader label="Проверка параметров ZK-приватности..." />;
  }

  return (
    <div className="bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg p-5 shadow-sm">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-md font-semibold text-gray-800 dark:text-white">
          Анонимное голосование
        </h3>
        <AnonVoteStatusBadge enabled={enabled} zkVerified={zkProofAvailable} />
      </div>

      <div className="flex items-center gap-4">
        <Tooltip label="Ваш голос будет скрыт. Валидация осуществляется через ZK-доказательство без раскрытия личности.">
          <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
            <ShieldIcon className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
            <span>Включить приватность (ZK-анонимность)</span>
          </div>
        </Tooltip>

        <ToggleSwitch
          checked={enabled}
          onChange={handleToggle}
          disabled={!eligible}
        />
      </div>

      {!eligible && (
        <AlertBanner
          type="warning"
          title="Анонимное голосование недоступно"
          message="Ваш ZK-профиль не соответствует условиям приватного голосования для этого предложения. Обратитесь к DAO или обновите доказательство участия."
          icon={<LockIcon className="w-5 h-5 text-red-600" />}
        />
      )}

      {error && (
        <AlertBanner
          type="error"
          title="Ошибка"
          message={error}
        />
      )}
    </div>
  );
};

export default AnonymousVoteToggle;
