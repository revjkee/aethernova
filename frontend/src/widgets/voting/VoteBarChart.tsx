// src/widgets/Voting/VoteBarChart.tsx

import React, { useMemo } from 'react';
import { ResponsiveBar } from '@nivo/bar';
import { useTranslation } from 'react-i18next';
import { useVoteTally } from '@/entities/voting/hooks/useVoteTally';
import { ChartWrapper } from '@/shared/ui/ChartWrapper';
import { Spinner } from '@/shared/ui/Spinner';
import { quorumThreshold } from '@/config/governance';
import styles from './styles/VoteBarChart.module.css';

interface VoteBarChartProps {
  proposalId: string;
  maxHeight?: number;
}

export const VoteBarChart: React.FC<VoteBarChartProps> = ({ proposalId, maxHeight = 360 }) => {
  const { t } = useTranslation();
  const { isLoading, yesVotes, noVotes, abstainVotes, totalEligiblePower } = useVoteTally(proposalId);

  const data = useMemo(() => {
    const total = yesVotes + noVotes + abstainVotes || 1;
    const toPercent = (v: number) => (v / total) * 100;

    return [
      {
        id: 'yes',
        label: t('votes.yes'),
        value: yesVotes,
        percentage: toPercent(yesVotes),
        color: '#27ae60',
      },
      {
        id: 'no',
        label: t('votes.no'),
        value: noVotes,
        percentage: toPercent(noVotes),
        color: '#e74c3c',
      },
      {
        id: 'abstain',
        label: t('votes.abstain'),
        value: abstainVotes,
        percentage: toPercent(abstainVotes),
        color: '#f1c40f',
      },
    ];
  }, [yesVotes, noVotes, abstainVotes, t]);

  if (isLoading) {
    return (
      <div className={styles.loading}>
        <Spinner size="lg" />
      </div>
    );
  }

  return (
    <ChartWrapper title={t('votes.chartTitle')}>
      <div className={styles.chartContainer} style={{ height: maxHeight }}>
        <ResponsiveBar
          data={data}
          keys={['value']}
          indexBy="label"
          margin={{ top: 30, right: 20, bottom: 50, left: 60 }}
          padding={0.3}
          colors={({ data }) => data.color}
          layout="horizontal"
          valueScale={{ type: 'linear' }}
          indexScale={{ type: 'band', round: true }}
          borderRadius={6}
          enableLabel
          labelSkipWidth={20}
          labelSkipHeight={12}
          labelTextColor="#ffffff"
          axisTop={null}
          axisRight={null}
          axisBottom={{
            tickSize: 5,
            tickPadding: 5,
            legend: t('votes.votePower'),
            legendPosition: 'middle',
            legendOffset: 40,
          }}
          axisLeft={{
            tickSize: 5,
            tickPadding: 5,
            legend: t('votes.voteType'),
            legendPosition: 'middle',
            legendOffset: -50,
          }}
          tooltip={({ data }) => (
            <div className={styles.tooltip}>
              <strong>{data.label}</strong>
              <div>{t('votes.rawVotes')}: {data.value.toLocaleString()}</div>
              <div>{t('votes.percent')}: {data.percentage.toFixed(1)}%</div>
            </div>
          )}
          role="application"
          ariaLabel="Vote Bar Chart"
          barAriaLabel={e => `${e.data.label}: ${e.data.value} (${e.data.percentage.toFixed(1)}%)`}
        />
      </div>
      <div className={styles.meta}>
        <div className={styles.metaItem}>
          {t('votes.totalEligiblePower')}: {totalEligiblePower.toLocaleString()}
        </div>
        <div className={styles.metaItem}>
          {t('votes.quorumThreshold')}: {quorumThreshold}%
        </div>
      </div>
    </ChartWrapper>
  );
};
