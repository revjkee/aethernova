import React, { useMemo } from 'react';
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts';

import styles from './styles/VoteResultChart.module.css';
import classNames from 'classnames';

type VoteOption = 'yes' | 'no' | 'abstain' | 'veto';

interface VoteResultChartProps {
  data: Record<VoteOption, number>;
  totalVotes: number;
  title?: string;
}

const COLORS: Record<VoteOption, string> = {
  yes: 'var(--color-success)',
  no: 'var(--color-danger)',
  abstain: 'var(--color-warning)',
  veto: 'var(--color-accent)'
};

const LABELS: Record<VoteOption, string> = {
  yes: 'За',
  no: 'Против',
  abstain: 'Воздержался',
  veto: 'Вето'
};

const VoteResultChart: React.FC<VoteResultChartProps> = ({ data, totalVotes, title }) => {
  const chartData = useMemo(() => {
    return (Object.entries(data) as [VoteOption, number][])
      .map(([option, count]) => ({
        name: LABELS[option],
        value: count,
        option
      }))
      .filter(entry => entry.value > 0);
  }, [data]);

  return (
    <div className={styles.wrapper}>
      {title && <h3 className={styles.title}>{title}</h3>}
      <ResponsiveContainer width="100%" height={300}>
        <PieChart>
          <Pie
            data={chartData}
            innerRadius={70}
            outerRadius={110}
            paddingAngle={4}
            dataKey="value"
            nameKey="name"
            label={({ name, percent }) =>
              `${name}: ${(percent * 100).toFixed(1)}%`
            }
          >
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[entry.option]} />
            ))}
          </Pie>
          <Tooltip
            formatter={(value: number, name: string) =>
              [`${value} голосов`, name]
            }
          />
          <Legend verticalAlign="bottom" height={36} />
        </PieChart>
      </ResponsiveContainer>
      <div className={styles.total}>
        Всего голосов: <strong>{totalVotes}</strong>
      </div>
    </div>
  );
};

export default VoteResultChart;
