import React from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { FunnelChart, Funnel, LabelList, Tooltip, ResponsiveContainer } from 'recharts';
import { useQuery } from '@tanstack/react-query';
import { fetchFunnelData } from '@/services/api';

type FunnelStage = {
  stage: string;
  count: number;
  ratio: number;
};

const FunnelView: React.FC = () => {
  const {
    data: funnelData,
    isLoading,
    error
  } = useQuery(['funnelData'], fetchFunnelData, {
    staleTime: 60000,
    refetchOnWindowFocus: false,
  });

  const fallbackData: FunnelStage[] = [
    { stage: 'Заявки получены', count: 1000, ratio: 1.0 },
    { stage: 'Прошли фильтр CV', count: 600, ratio: 0.6 },
    { stage: 'Проверка softskills', count: 420, ratio: 0.42 },
    { stage: 'Интервью', count: 280, ratio: 0.28 },
    { stage: 'Оффер отправлен', count: 90, ratio: 0.09 },
    { stage: 'Оффер принят', count: 55, ratio: 0.055 },
  ];

  const processedData = funnelData || fallbackData;

  return (
    <Card className="col-span-full">
      <CardHeader>
        <h2 className="text-xl font-semibold">Воронка кандидатов</h2>
        <p className="text-muted-foreground text-sm">
          От общего потока до оффера. Обновляется в реальном времени.
        </p>
      </CardHeader>
      <CardContent>
        {isLoading || error ? (
          <Skeleton className="h-[360px] w-full" />
        ) : (
          <ResponsiveContainer width="100%" height={360}>
            <FunnelChart>
              <Tooltip />
              <Funnel
                dataKey="count"
                data={processedData}
                isAnimationActive
              >
                <LabelList
                  dataKey="stage"
                  position="right"
                  fill="#333"
                  stroke="none"
                  style={{ fontWeight: '600' }}
                />
              </Funnel>
            </FunnelChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
};

export default FunnelView;
