// src/widgets/Voting/ZKProofVerifier.tsx

import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { verifyProof } from '@/entities/zk/zkVerifier';
import { Spinner } from '@/shared/ui/Spinner';
import { Badge } from '@/shared/ui/Badge';
import { Alert } from '@/shared/ui/Alert';
import { formatHash } from '@/shared/lib/format';
import { ZKProof } from '@/entities/zk/types';
import { useProposalZKProofs } from '@/entities/zk/hooks/useProposalZKProofs';
import styles from './styles/ZKProofVerifier.module.css';

interface ZKProofVerifierProps {
  proposalId: string;
}

export const ZKProofVerifier: React.FC<ZKProofVerifierProps> = ({ proposalId }) => {
  const { t } = useTranslation();
  const [statusMap, setStatusMap] = useState<Record<string, 'valid' | 'invalid' | 'pending'>>({});
  const { proofs, isLoading } = useProposalZKProofs(proposalId);

  useEffect(() => {
    const verifyAll = async () => {
      const results: Record<string, 'valid' | 'invalid' | 'pending'> = {};
      for (const proof of proofs) {
        results[proof.id] = 'pending';
        const isValid = await verifyProof(proof);
        results[proof.id] = isValid ? 'valid' : 'invalid';
      }
      setStatusMap(results);
    };

    if (proofs.length > 0) verifyAll();
  }, [proofs]);

  if (isLoading) {
    return (
      <div className={styles.loading}>
        <Spinner size="lg" />
      </div>
    );
  }

  if (proofs.length === 0) {
    return (
      <Alert type="info">
        {t('zk.noProofs')}
      </Alert>
    );
  }

  return (
    <div className={styles.container}>
      <h3 className={styles.heading}>{t('zk.verificationTitle')}</h3>
      <table className={styles.table}>
        <thead>
          <tr>
            <th>{t('zk.proofId')}</th>
            <th>{t('zk.voterHash')}</th>
            <th>{t('zk.timestamp')}</th>
            <th>{t('zk.status')}</th>
          </tr>
        </thead>
        <tbody>
          {proofs.map((proof: ZKProof) => (
            <tr key={proof.id}>
              <td>{formatHash(proof.id, 10)}</td>
              <td>{formatHash(proof.voterCommitment, 10)}</td>
              <td>{new Date(proof.timestamp).toLocaleString()}</td>
              <td>
                {statusMap[proof.id] === 'valid' && <Badge type="success">{t('zk.valid')}</Badge>}
                {statusMap[proof.id] === 'invalid' && <Badge type="error">{t('zk.invalid')}</Badge>}
                {statusMap[proof.id] === 'pending' && <Spinner size="sm" />}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
