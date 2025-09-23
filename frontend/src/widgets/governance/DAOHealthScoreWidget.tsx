// src/widgets/Governance/DAOHealthScoreWidget.tsx

import React, { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { ProgressCircle } from '@/components/ui/progress-circle';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { fetchDAOHealthScore } from '@/services/governance/daoHealthService';
import {
  HeartPulse,
  ShieldCheck,
  Users,
  LineChart,
  Zap,
  Activity,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';

interface DAOHealthMetric {
  label: string;
  value: number;
  icon: React.ReactNode;
  risk?: 'low' | 'medium' | 'high';
  description: string;
}

export default function DAOHealthScoreWidget() {
  const [loading, setLoading] = useState(true);
  const [score, setScore] = useState<number>(0);
  const [metrics, setMetrics] = useState<DAOHealthMetric[]>([]);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      const { score, metrics } = await fetchDAOHealthScore();
      setScore(score);
      setMetrics(metrics);
      setLoading(false);
    };
    load();
  }, []);

  if (loading) {
    return (
      <Card className="p-6 rounded-2xl w-full">
        <CardHeader className="text-lg font-semibold">Состояние DAO</CardHeader>
        <CardContent className="flex flex-col md:flex-row items-center gap-6">
          <Skeleton className="w-[120px] h-[120px] rounded-full" />
          <div className="space-y-3 flex-1">
            {[...Array(4)].map((_, i) => (
              <Skeleton key={i} className="h-6 w-full" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="p-6 rounded-2xl w-full border shadow-md bg-background">
      <CardHeader className="text-lg font-semibold text-primary mb-4 flex items-center gap-2">
        <HeartPulse className="w-5 h-5 text-primary" />
        Интегральное здоровье DAO: <span className="text-foreground">{score}%</span>
      </CardHeader>

      <CardContent className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <div className="flex justify-center items-center">
          <ProgressCircle
            value={score}
            size={160}
            strokeWidth={10}
            color={score > 80 ? 'green' : score > 60 ? 'orange' : 'red'}
            label={`${score}%`}
            description="Общий индекс"
          />
        </div>

        {metrics.map((metric, index) => (
          <div key={index} className="flex items-start gap-4 p-4 border rounded-xl bg-muted">
            <div className="text-primary mt-1">{metric.icon}</div>
            <div className="flex-1">
              <div className="flex justify-between items-center mb-1">
                <h4 className="text-sm font-semibold">{metric.label}</h4>
                {metric.risk && (
                  <Badge
                    variant={
                      metric.risk === 'low'
                        ? 'success'
                        : metric.risk === 'medium'
                        ? 'warning'
                        : 'destructive'
                    }
                  >
                    {metric.risk === 'low' && <CheckCircle2 className="w-4 h-4 mr-1" />}
                    {metric.risk === 'medium' && <AlertTriangle className="w-4 h-4 mr-1" />}
                    {metric.risk === 'high' && <AlertTriangle className="w-4 h-4 mr-1" />}
                    {metric.risk.toUpperCase()}
                  </Badge>
                )}
              </div>
              <p className="text-sm text-muted-foreground">{metric.description}</p>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
