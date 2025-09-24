import React, { useEffect, useState, useMemo, useCallback, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchKnowledgeGapData } from '@/services/api/analyticsAPI';
import { useTranslation } from 'react-i18next';
import { Radar } from 'react-chartjs-2';
import { ChartOptions } from 'chart.js';
import { Spinner } from '@/shared/components/Spinner';

interface KnowledgeGapDataPoint {
  topic: string;
  score: number; // 0-100 (чем ниже, тем слабее)
}

interface Props {
  studentId: string;
  courseId: string;
}

const KnowledgeGapRadar: React.FC<Props> = ({ studentId, courseId }) => {
  const { t } = useTranslation();
  const { data, isLoading, error } = useQuery(
    ['knowledgeGapData', studentId, courseId],
    () => fetchKnowledgeGapData(studentId, courseId),
    {
      staleTime: 120000,
      refetchOnWindowFocus: false,
    }
  );

  const radarData = useMemo(() => {
    if (!data || data.length === 0) return null;

    const labels = data.map((d) => d.topic);
    const scores = data.map((d) => 100 - d.score); // для радара: высокие значения — слабые зоны

    return {
      labels,
      datasets: [
        {
          label: t('edu.knowledgeGapRadar.label'),
          data: scores,
          backgroundColor: 'rgba(239, 68, 68, 0.3)',
          borderColor: 'rgba(239, 68, 68, 0.8)',
          borderWidth: 2,
          pointBackgroundColor: 'rgba(220, 38, 38, 1)',
          fill: true,
          tension: 0.4,
        },
      ],
    };
  }, [data, t]);

  const options: ChartOptions<'radar'> = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      r: {
        beginAtZero: true,
        max: 100,
        ticks: {
          stepSize: 20,
          color: '#9ca3af',
        },
        grid: {
          color: '#374151',
        },
        angleLines: {
          color: '#4b5563',
        },
        pointLabels: {
          color: '#d1d5db',
          font: { size: 14 },
        },
      },
    },
    plugins: {
      legend: {
        display: true,
        labels: {
          color: '#f87171',
          font: { size: 14 },
        },
      },
      tooltip: {
        callbacks: {
          label: (ctx) => `${t('edu.knowledgeGapRadar.tooltipPrefix')} ${100 - (ctx.parsed.r ?? 0)}%`,
        },
      },
    },
  };

  if (isLoading) {
    return (
      <div className="flex justify-center py-16">
        <Spinner size="lg" />
      </div>
    );
  }

  if (error || !radarData) {
    return (
      <div className="text-center text-red-600 dark:text-red-400">
        {t('edu.knowledgeGapRadar.loadError')}
      </div>
    );
  }

  return (
    <section
      aria-label={t('edu.knowledgeGapRadar.ariaLabel')}
      className="relative w-full max-w-4xl h-[420px] mx-auto bg-zinc-900 rounded-lg p-6 shadow-lg"
    >
      <Radar data={radarData} options={options} />
    </section>
  );
};

export default React.memo(KnowledgeGapRadar);
