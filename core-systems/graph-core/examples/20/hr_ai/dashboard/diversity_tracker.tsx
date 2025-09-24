import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend } from 'recharts';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { fetchDiversityStats } from '@/services/api';
import { Badge } from '@/components/ui/badge';

const COLORS = ['#34D399', '#60A5FA', '#F472B6', '#FCD34D', '#A78BFA', '#F87171'];

type DiversityDataItem = {
  label: string;
  value: number;
};

const DiversityTracker: React.FC = () => {
  const {
    data: genderData,
    isLoading: loadingGender,
    error: genderError,
  } = useQuery(['diversity', 'gender'], () => fetchDiversityStats('gender'));

  const {
    data: ethnicityData,
    isLoading: loadingEthnicity,
    error: ethnicityError,
  } = useQuery(['diversity', 'ethnicity'], () => fetchDiversityStats('ethnicity'));

  const renderChart = (data: DiversityDataItem[], title: string) => (
    <div className="w-full md:w-1/2 p-4">
      <h3 className="text-md font-semibold mb-2">{title}</h3>
      <ResponsiveContainer width="100%" height={240}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            outerRadius={80}
            fill="#8884d8"
            dataKey="value"
            label
          >
            {data.map((_, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );

  const fallbackGenderData: DiversityDataItem[] = [
    { label: 'Мужчины', value: 52 },
    { label: 'Женщины', value: 45 },
    { label: 'Небинарные', value: 3 },
  ];

  const fallbackEthnicityData: DiversityDataItem[] = [
    { label: 'Европейское происхождение', value: 40 },
    { label: 'Азиатское происхождение', value: 30 },
    { label: 'Африканское происхождение', value: 15 },
    { label: 'Латиноамериканское происхождение', value: 10 },
    { label: 'Другое', value: 5 },
  ];

  return (
    <Card className="col-span-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-semibold">Диверсификация команды</h2>
          <Badge variant="outline" className="text-xs">
            XAI Monitored
          </Badge>
        </div>
        <p className="text-muted-foreground text-sm">
          Гендер и этническое разнообразие — на основе текущих кандидатов.
        </p>
      </CardHeader>
      <CardContent className="flex flex-col md:flex-row justify-around items-center">
        {loadingGender || loadingEthnicity || genderError || ethnicityError ? (
          <Skeleton className="h-[240px] w-full" />
        ) : (
          <>
            {renderChart(genderData || fallbackGenderData, 'Гендерное распределение')}
            {renderChart(ethnicityData || fallbackEthnicityData, 'Этническое разнообразие')}
          </>
        )}
      </CardContent>
    </Card>
  );
};

export default DiversityTracker;
