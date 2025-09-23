import React, { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { ArcElement, Chart as ChartJS, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

interface Props {
  completedPercent: number; // 0-100
  inProgressPercent: number; // 0-100
  notStartedPercent: number; // 0-100
  size?: number; // размер диаграммы в пикселях
  className?: string;
}

const EduProgressDonutChart: React.FC<Props> = ({
  completedPercent,
  inProgressPercent,
  notStartedPercent,
  size = 160,
  className,
}) => {
  const { t } = useTranslation();

  // Валидируем суммы процентов
  const total = completedPercent + inProgressPercent + notStartedPercent;
  const normCompleted = (completedPercent / total) * 100;
  const normInProgress = (inProgressPercent / total) * 100;
  const normNotStarted = (notStartedPercent / total) * 100;

  const data = useMemo(() => ({
    labels: [
      t('edu.progressDonut.completed'),
      t('edu.progressDonut.inProgress'),
      t('edu.progressDonut.notStarted'),
    ],
    datasets: [
      {
        data: [normCompleted, normInProgress, normNotStarted],
        backgroundColor: ['#10B981', '#3B82F6', '#D1D5DB'],
        hoverBackgroundColor: ['#059669', '#2563EB', '#9CA3AF'],
        borderWidth: 2,
        borderColor: '#1F2937',
        cutout: '75%',
        spacing: 2,
      },
    ],
  }), [normCompleted, normInProgress, normNotStarted, t]);

  const options = useMemo(() => ({
    responsive: false,
    animation: {
      animateRotate: true,
      duration: 1000,
      easing: 'easeOutQuart',
    },
    plugins: {
      legend: {
        display: true,
        position: 'bottom',
        labels: {
          color: '#374151',
          font: { size: 14 },
          padding: 16,
          usePointStyle: true,
          pointStyle: 'circle',
        },
      },
      tooltip: {
        callbacks: {
          label: (context: any) => {
            const label = context.label || '';
            const value = context.parsed || 0;
            return `${label}: ${value.toFixed(1)}%`;
          },
        },
      },
    },
  }), []);

  return (
    <div
      className={className}
      role="img"
      aria-label={t('edu.progressDonut.ariaLabel', {
        completed: completedPercent.toFixed(1),
        inProgress: inProgressPercent.toFixed(1),
        notStarted: notStartedPercent.toFixed(1),
      })}
      style={{ width: size, height: size }}
    >
      <Doughnut data={data} options={options} width={size} height={size} />
      <div
        className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 text-center select-none pointer-events-none"
        aria-hidden="true"
      >
        <span className="block text-2xl font-semibold text-gray-900 dark:text-gray-100">
          {completedPercent.toFixed(0)}%
        </span>
        <span className="block text-xs text-muted-foreground">{t('edu.progressDonut.completed')}</span>
      </div>
    </div>
  );
};

export default React.memo(EduProgressDonutChart);
