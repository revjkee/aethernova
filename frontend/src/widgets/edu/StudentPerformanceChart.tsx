import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchStudentPerformance } from '@/services/api/analyticsAPI';
import { Line } from 'react-chartjs-2';
import { ChartOptions } from 'chart.js';
import { Spinner } from '@/shared/components/Spinner';
import { useTranslation } from 'react-i18next';
import { Select } from '@/shared/components/Select';
import { cn } from '@/shared/utils/cn';

interface PerformanceDataPoint {
  topic: string;
  date: string;
  score: number; // 0-100
  averageGroupScore?: number;
}

interface Props {
  studentId: string;
  courseId: string;
}

const topicsFilterOptions = (topics: string[]) =>
  topics.map((topic) => ({ label: topic, value: topic }));

const StudentPerformanceChart: React.FC<Props> = ({ studentId, courseId }) => {
  const { t } = useTranslation();
  const [selectedTopics, setSelectedTopics] = useState<string[]>([]);
  const { data, isLoading, error } = useQuery(
    ['studentPerformance', studentId, courseId],
    () => fetchStudentPerformance(studentId, courseId),
    { staleTime: 60000 }
  );

  // Извлечь уникальные темы из данных
  const topics = useMemo(() => {
    if (!data) return [];
    const unique = new Set(data.map((d) => d.topic));
    return Array.from(unique);
  }, [data]);

  // Установить дефолтный фильтр при загрузке
  useEffect(() => {
    if (topics.length > 0 && selectedTopics.length === 0) {
      setSelectedTopics([topics[0]]);
    }
  }, [topics, selectedTopics.length]);

  // Фильтруем данные по выбранным темам
  const filteredData = useMemo(() => {
    if (!data) return [];
    return data.filter((d) => selectedTopics.includes(d.topic));
  }, [data, selectedTopics]);

  // Формируем данные для ChartJS
  const chartData = useMemo(() => {
    if (filteredData.length === 0) return { labels: [], datasets: [] };

    // Сгруппировать данные по дате
    const dates = Array.from(new Set(filteredData.map((d) => d.date))).sort();
    // По каждой теме построить массив баллов по датам
    const datasets = selectedTopics.map((topic, idx) => {
      const topicData = filteredData.filter((d) => d.topic === topic);
      const scoresByDate = dates.map((date) => {
        const point = topicData.find((d) => d.date === date);
        return point ? point.score : null;
      });
      const groupScoresByDate = dates.map((date) => {
        const point = topicData.find((d) => d.date === date);
        return point && point.averageGroupScore !== undefined ? point.averageGroupScore : null;
      });

      return [
        {
          label: `${topic} (${t('studentPerformance.student')})`,
          data: scoresByDate,
          borderColor: `hsl(${(idx * 70) % 360}, 70%, 50%)`,
          backgroundColor: `hsla(${(idx * 70) % 360}, 70%, 50%, 0.3)`,
          fill: false,
          tension: 0.3,
          pointRadius: 4,
          pointHoverRadius: 6,
          yAxisID: 'y',
        },
        {
          label: `${topic} (${t('studentPerformance.groupAvg')})`,
          data: groupScoresByDate,
          borderColor: `hsl(${(idx * 70) % 360}, 70%, 30%)`,
          backgroundColor: 'transparent',
          borderDash: [5, 5],
          fill: false,
          tension: 0.3,
          pointRadius: 2,
          pointHoverRadius: 4,
          yAxisID: 'y',
        },
      ];
    }).flat();

    return {
      labels: dates,
      datasets,
    };
  }, [filteredData, selectedTopics, t]);

  const chartOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: {
      mode: 'nearest',
      axis: 'x',
      intersect: false,
    },
    scales: {
      x: {
        type: 'time',
        time: { unit: 'day', tooltipFormat: 'PP' },
        title: { display: true, text: t('studentPerformance.time') },
      },
      y: {
        min: 0,
        max: 100,
        title: { display: true, text: t('studentPerformance.score') },
      },
    },
    plugins: {
      legend: { position: 'bottom', labels: { boxWidth: 12, padding: 10 } },
      tooltip: { mode: 'nearest', intersect: false },
    },
  };

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <Spinner size="lg" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="text-center text-red-600">
        {t('studentPerformance.loadError')}
      </div>
    );
  }

  return (
    <section aria-label={t('studentPerformance.chartTitle')} className="p-4 bg-white dark:bg-zinc-900 rounded-lg shadow-md max-w-7xl mx-auto">
      <h2 className="text-2xl font-semibold mb-4">{t('studentPerformance.chartTitle')}</h2>

      <div className="mb-4 max-w-sm">
        <Select
          label={t('studentPerformance.selectTopics')}
          options={topicsFilterOptions(topics)}
          value={selectedTopics}
          onChange={setSelectedTopics}
          isMulti
          closeMenuOnSelect={false}
          classNamePrefix="react-select"
          placeholder={t('studentPerformance.selectTopicsPlaceholder')}
        />
      </div>

      <div className="h-[400px]">
        <Line data={chartData} options={chartOptions} />
      </div>
    </section>
  );
};

export default React.memo(StudentPerformanceChart);
