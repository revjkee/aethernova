import React, { useEffect, useState, useRef } from 'react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Skeleton } from '@/components/ui/skeleton';
import { AlertTriangle } from 'lucide-react';

type AnalyticsDataPoint = {
  timestamp: string;
  applications: number;
  interviews: number;
  hires: number;
};

const MAX_POINTS = 100;

const LiveAnalytics: React.FC = () => {
  const [data, setData] = useState<AnalyticsDataPoint[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const socket = new WebSocket('wss://api.hr-ai.local/ws/analytics/stream');

    wsRef.current = socket;

    socket.onopen = () => {
      setConnected(true);
      setError(null);
    };

    socket.onerror = () => {
      setConnected(false);
      setError('Ошибка соединения с live-аналитикой.');
    };

    socket.onclose = () => {
      setConnected(false);
    };

    socket.onmessage = (event) => {
      const incoming: AnalyticsDataPoint = JSON.parse(event.data);
      setData(prev =>
        [...prev.slice(-MAX_POINTS + 1), incoming]
      );
    };

    return () => {
      socket.close();
    };
  }, []);

  return (
    <Card className="col-span-full">
      <CardHeader>
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-xl font-semibold">Live HR-аналитика</h2>
            <p className="text-muted-foreground text-sm">
              Потоковая визуализация активности найма.
            </p>
          </div>
          <Badge variant={connected ? 'success' : 'destructive'}>
            {connected ? 'Подключено' : 'Отключено'}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="h-[320px]">
        {error ? (
          <div className="flex items-center text-destructive text-sm gap-2">
            <AlertTriangle className="w-4 h-4" />
            {error}
          </div>
        ) : data.length === 0 ? (
          <Skeleton className="h-full w-full" />
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="timestamp" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line type="monotone" dataKey="applications" stroke="#3B82F6" name="Заявки" />
              <Line type="monotone" dataKey="interviews" stroke="#F59E0B" name="Интервью" />
              <Line type="monotone" dataKey="hires" stroke="#10B981" name="Принятые" />
            </LineChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
};

export default LiveAnalytics;
