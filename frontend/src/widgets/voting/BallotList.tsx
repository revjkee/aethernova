// src/widgets/Voting/BallotList.tsx

import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { getBallots } from '@/entities/governance/api/getBallots';
import { BallotCard } from '@/entities/governance/ui/BallotCard';
import { BallotFilterPanel } from '@/widgets/Voting/BallotFilterPanel';
import { useAccount } from '@/entities/wallet/hooks/useAccount';
import { Spinner } from '@/shared/ui/Spinner';
import { EmptyState } from '@/shared/ui/EmptyState';
import { ErrorBanner } from '@/shared/ui/ErrorBanner';
import { notifyError } from '@/shared/lib/notifications';
import { Ballot, BallotStatus } from '@/shared/types/governance';
import { classifyBallotsWithAI } from '@/entities/ai/services/classifier';
import styles from './styles/BallotList.module.css';

export const BallotList: React.FC = () => {
  const { address } = useAccount();
  const [ballots, setBallots] = useState<Ballot[]>([]);
  const [filtered, setFiltered] = useState<Ballot[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<BallotStatus | 'all'>('all');
  const [search, setSearch] = useState('');
  const [prioritized, setPrioritized] = useState<Ballot[]>([]);

  const fetchBallots = useCallback(async () => {
    try {
      setLoading(true);
      const data = await getBallots(address);
      const prioritized = await classifyBallotsWithAI(data);
      setBallots(data);
      setPrioritized(prioritized);
    } catch (err) {
      console.error(err);
      setError('Ошибка загрузки бюллетеней');
      notifyError('Не удалось загрузить бюллетени');
    } finally {
      setLoading(false);
    }
  }, [address]);

  useEffect(() => {
    fetchBallots();
  }, [fetchBallots]);

  useEffect(() => {
    let result = [...ballots];

    if (statusFilter !== 'all') {
      result = result.filter(b => b.status === statusFilter);
    }

    if (search.trim()) {
      const s = search.toLowerCase();
      result = result.filter(b =>
        b.title.toLowerCase().includes(s) ||
        b.description.toLowerCase().includes(s)
      );
    }

    setFiltered(result);
  }, [ballots, statusFilter, search]);

  const renderContent = () => {
    if (loading) return <Spinner />;
    if (error) return <ErrorBanner message={error} />;
    if (filtered.length === 0) return <EmptyState message="Нет доступных бюллетеней" />;

    return (
      <div className={styles.grid}>
        {filtered.map(ballot => (
          <BallotCard key={ballot.id} ballot={ballot} highlight={prioritized.includes(ballot)} />
        ))}
      </div>
    );
  };

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h1>Бюллетени для голосования</h1>
        <BallotFilterPanel
          status={statusFilter}
          onStatusChange={setStatusFilter}
          search={search}
          onSearchChange={setSearch}
        />
      </header>
      <main className={styles.main}>{renderContent()}</main>
    </div>
  );
};
