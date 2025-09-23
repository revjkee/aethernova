import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchMotivationMetrics } from '@/services/api/motivationAPI';
import { useTranslation } from 'react-i18next';
import { Line } from 'react-chartjs-2';
import { ChartOptions, ChartData } from 'chart.js';
import { Spinner } from '@/shared/components/Spinner';

interface MotivationMetrics {
  timestamps: string[]; // ISO даты/времена
  engagementScores: number[]; // 0-100, активность пользователя
  motivationLevels: number[]; // 0-100, оценка мотивации
  breakDurations: number[]; // в минутах
}

interface Props {
  userId: string;
  courseId: string;
}

const MotivationTracker: React.FC<Props> = ({ userId, courseId }) => {
  const { t } = useTranslation();
  const { data, isLoading, error } = useQuery(
    ['motivationMetrics', userId, courseId],
    () => fetchMotivationMetrics(userId, courseId),
    {
      staleTime: 60000,
      refetchInterval: 120000,
      refetchOnWindowFocus: false,
    }
  );

  const chartData: ChartData<'line'> = useMemo(() => {
    if (!data) return { labels: [], datasets: [] };

    return {
      labels: data.timestamps.map((ts) => new Date(ts).toLocaleTimeString()),
      datasets: [
        {
          label: t('edu.motivationTracker.engagement'),
          data: data.engagementScores,
          borderColor: '#3B82F6',
          backgroundColor: 'rgba(59, 130, 246, 0.3)',
          yAxisID: 'y',
          tension: 0.3,
          fill: true,
          pointRadius: 2,
        },
        {
          label: t('edu.motivationTracker.motivation'),
          data: data.motivationLevels,
          borderColor: '#10B981',
          backgroundColor: 'rgba(16, 185, 129, 0.3)',
          yAxisID: 'y1',
          tension: 0.3,
          fill: true,
          pointRadius: 2,
        },
        {
          label: t('edu.motivationTracker.breaks'),
          data: data.breakDurations,
          borderColor: '#F59E0B',
          backgroundColor: 'rgba(245, 158, 11, 0.3)',
          yAxisID: 'y2',
          tension: 0.3,
          fill: true,
          pointRadius: 2,
        },
      ],
    };
  }, [data, t]);

  const options: ChartOptions<'line'> = useMemo(() => ({
    responsive: true,
    interaction: {
      mode: 'nearest',
      intersect: false,
    },
    stacked: false,
    scales: {
      x: {
        display: true,
        title: {
          display: true,
          text: t('edu.motivationTracker.time'),
        },
        ticks: {
          maxRotation: 45,
          minRotation: 30,
          color: '#6B7280',
        },
        grid: {
          color: '#E5E7EB',
        },
      },
      y: {
        type: 'linear',
        display: true,
        position: 'left',
        min: 0,
        max: 100,
        title: {
          display: true,
          text: t('edu.motivationTracker.engagementScore'),
        },
        ticks: {
          color: '#3B82F6',
        },
        grid: {
          drawOnChartArea: true,
          color: '#E5E7EB',
        },
      },
      y1: {
        type: 'linear',
        display: true,
        position: 'right',
        min: 0,
        max: 100,
        title: {
          display: true,
          text: t('edu.motivationTracker.motivationLevel'),
        },
        grid: {
          drawOnChartArea: false,
        },
        ticks: {
          color: '#10B981',
        },
      },
      y2: {
        type: 'linear',
        display: true,
        position: 'right',
        min: 0,
        max: Math.max(...(data?.breakDurations || [10, 20, 30])) * 1.5,
        offset: true,
        title: {
          display: true,
          text: t('edu.motivationTracker.breakDurationMin'),
        },
        grid: {
          drawOnChartArea: false,
        },
        ticks: {
          color: '#F59E0B',
        },
      },
    },
    plugins: {
      legend: {
        position: 'top',
        labels: {
          color: '#374151',
          font: { size: 14 },
        },
      },
      tooltip: {
        mode: 'nearest',
        intersect: false,
        callbacks: {
          label: (context) => `${context.dataset.label}: ${context.parsed.y}`,
        },
      },
    },
  }), [t, data]);

  if (isLoading) {
    return (
      <div className="flex justify-center py-20">
        <Spinner size="xl" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="text-center text-red-600 dark:text-red-400">
        {t('edu.motivationTracker.loadError')}
      </div>
    );
  }

  return (
    <section
      aria-label={t('edu.motivationTracker.ariaLabel')}
      className="max-w-6xl mx-auto p-6 bg-white dark:bg-zinc-900 rounded-md shadow-md"
    >
      <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-6">
        {t('edu.motivationTracker.title')}
      </h2>

      <div style={{ position: 'relative', height: '400px' }}>
        <Line data={chartData} options={options} />
      </div>
    </section>
  );
};

export default React.memo(MotivationTracker);
