import React, { useMemo, useEffect, useState } from 'react';
import { fetchUserTokenBalance, fetchUserRoleWeight, fetchDelegationInfo } from '@/services/blockchain/tokenVotingService';
import { getBonusMultiplier, getParticipationScore } from '@/services/governance/engagementTracker';
import { useZKIdentity } from '@/shared/hooks/useZKIdentity';
import { useCache } from '@/shared/hooks/useCache';
import { useAuditLogger } from '@/shared/hooks/useAuditLogger';
import { verifyDelegationSignature } from '@/utils/crypto/delegationValidator';
import { applyRoleModifiers, normalizeWeight } from '@/utils/voting/votingWeightUtils';

type VoterWeightCalculatorProps = {
  userAddress: string;
  proposalId: string;
  onWeightCalculated: (weight: number) => void;
};

const VoterWeightCalculator: React.FC<VoterWeightCalculatorProps> = ({ userAddress, proposalId, onWeightCalculated }) => {
  const [calculatedWeight, setCalculatedWeight] = useState<number>(0);
  const { getCached, setCached } = useCache();
  const { identityHash, zkProof } = useZKIdentity(userAddress);
  const logAudit = useAuditLogger();

  const computeWeight = useMemo(() => async () => {
    const cacheKey = `${userAddress}-${proposalId}-weight`;
    const cached = getCached<number>(cacheKey);
    if (cached !== undefined) {
      onWeightCalculated(cached);
      return cached;
    }

    try {
      const [
        tokenBalance,
        roleWeight,
        delegation,
        bonusMultiplier,
        participationScore
      ] = await Promise.all([
        fetchUserTokenBalance(userAddress),
        fetchUserRoleWeight(userAddress),
        fetchDelegationInfo(userAddress),
        getBonusMultiplier(userAddress),
        getParticipationScore(userAddress)
      ]);

      let rawWeight = tokenBalance * 1.0;

      if (delegation && delegation.isDelegated && verifyDelegationSignature(delegation)) {
        rawWeight += delegation.delegatedWeight;
      }

      const roleAdjusted = applyRoleModifiers(rawWeight, roleWeight);
      const participationAdjusted = roleAdjusted * participationScore;
      const finalWeight = normalizeWeight(participationAdjusted * bonusMultiplier);

      logAudit({
        type: 'WEIGHT_CALCULATION',
        user: userAddress,
        proposal: proposalId,
        weight: finalWeight,
        identityHash,
        zkProof
      });

      setCached(cacheKey, finalWeight, 60 * 5); // 5 минут

      setCalculatedWeight(finalWeight);
      onWeightCalculated(finalWeight);
      return finalWeight;
    } catch (error) {
      console.error('Weight calculation error:', error);
      logAudit({
        type: 'WEIGHT_CALCULATION_ERROR',
        user: userAddress,
        proposal: proposalId,
        error: error.message
      });
      return 0;
    }
  }, [userAddress, proposalId]);

  useEffect(() => {
    computeWeight();
  }, [computeWeight]);

  return (
    <div className="text-sm text-gray-700">
      <span>Ваш вес голоса: </span>
      <strong>{calculatedWeight.toFixed(2)}</strong>
    </div>
  );
};

export default VoterWeightCalculator;
