import React, { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { useQuery } from '@tanstack/react-query';
import { fetchAnalytics, fetchCandidates, fetchViolations } from '@/services/api';
import { LineChart, Line, CartesianGrid, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { useToast } from '@/components/ui/use-toast';
import { CandidateTable } from './partials/CandidateTable';
import { ViolationTable } from './partials/ViolationTable';
import { PerformanceGauge } from './partials/PerformanceGauge';

const Dashboard: React.FC = () => {
  const { toast } = useToast();
  const [selectedCandidateId, setSelectedCandidateId] = useState<string | null>(null);

  const {
    data: analytics,
    isLoading: loadingAnalytics,
    error: analyticsError
  } = useQuery(['analytics'], fetchAnalytics);

  const {
    data: candidates,
    isLoading: loadingCandidates,
    error: candidatesError
  } = useQuery(['candidates'], fetchCandidates);

  const {
    data: violations,
    isLoading: loadingViolations,
    error: violationsError
  } = useQuery(['violations'], fetchViolations);

  useEffect(() => {
    if (analyticsError || candidatesError || violationsError) {
      toast({
        variant: 'destructive',
        title: 'Ошибка при загрузке данных',
        description: 'Проверьте соединение или повторите позже.',
      });
    }
  }, [analyticsError, candidatesError, violationsError, toast]);

  return (
    <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3 p-6">
      {/* KPI Gauges */}
      <Card className="col-span-full">
        <CardHeader>
          <h2 className="text-xl font-semibold">Общая производительность системы</h2>
        </CardHeader>
        <CardContent className="flex justify-between gap-6 flex-wrap">
          <PerformanceGauge
            title="Средняя точность"
            value={analytics?.average_accuracy || 0}
            suffix="%"
            loading={loadingAnalytics}
          />
          <PerformanceGauge
            title="Cтатус соответствия политикам"
            value={analytics?.policy_compliance || 0}
            suffix="%"
            loading={loadingAnalytics}
          />
          <PerformanceGauge
            title="Скорость обработки"
            value={analytics?.avg_processing_time || 0}
            suffix="мс"
            loading={loadingAnalytics}
          />
        </CardContent>
      </Card>

      {/* Line Chart */}
      <Card className="col-span-full lg:col-span-2">
        <CardHeader>
          <h2 className="text-lg font-medium">Динамика производительности</h2>
        </CardHeader>
        <CardContent>
          {loadingAnalytics ? (
            <Skeleton className="h-[300px] w-full" />
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={analytics?.performance_over_time || []}>
                <Line type="monotone" dataKey="score" stroke="#8884d8" />
                <CartesianGrid stroke="#ccc" />
                <XAxis dataKey="date" />
                <YAxis domain={[0, 100]} />
                <Tooltip />
              </LineChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>

      {/* Candidate Table */}
      <Card className="col-span-full">
        <CardHeader>
          <h2 className="text-lg font-medium">Последние кандидаты</h2>
        </CardHeader>
        <CardContent>
          <CandidateTable
            data={candidates || []}
            loading={loadingCandidates}
            onSelect={(id) => setSelectedCandidateId(id)}
            selectedId={selectedCandidateId}
          />
        </CardContent>
      </Card>

      {/* Violations */}
      <Card className="col-span-full">
        <CardHeader>
          <h2 className="text-lg font-medium">Нарушения политик</h2>
        </CardHeader>
        <CardContent>
          <ViolationTable
            data={violations || []}
            loading={loadingViolations}
            selectedCandidateId={selectedCandidateId}
          />
        </CardContent>
      </Card>
    </div>
  );
};

export default Dashboard;
