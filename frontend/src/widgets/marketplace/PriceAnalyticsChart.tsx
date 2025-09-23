// src/widgets/Marketplace/PriceAnalyticsChart.tsx

import React, { FC, useMemo } from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  ReferenceLine,
  Area,
  AreaChart,
  Legend,
  ReferenceDot,
} from 'recharts';
import { useTheme } from '@/shared/hooks/useTelegramTheme';
import { useTelemetry } from '@/shared/hooks/useTelemetry';
import { cn } from '@/shared/utils/classNames';
import { formatCurrency, formatShortDate } from '@/shared/utils/formatters';
import { Skeleton } from '@/components/ui/skeleton';
import { TagType } from '@/shared/constants/tags';

interface PricePoint {
  timestamp: number;
  value: number;
  predicted?: number;
  anomaly?: boolean;
  minRange?: number;
  maxRange?: number;
  tag?: TagType;
}

interface PriceAnalyticsChartProps {
  data: PricePoint[];
  isLoading: boolean;
  showForecast?: boolean;
  showRange?: boolean;
  showAnomalies?: boolean;
  className?: string;
}

export const PriceAnalyticsChart: FC<PriceAnalyticsChartProps> = ({
  data,
  isLoading,
  showForecast = true,
  showRange = true,
  showAnomalies = true,
  className,
}) => {
  const theme = useTheme();
  const telemetry = useTelemetry();

  const processedData = useMemo(() => {
    return data.map((d) => ({
      ...d,
      date: formatShortDate(d.timestamp),
    }));
  }, [data]);

  const primaryColor = theme === 'dark' ? '#00E4B0' : '#007AFF';
  const forecastColor = theme === 'dark' ? '#D9D9D9' : '#7B7B7B';
  const anomalyColor = '#FF4D4F';
  const rangeColor = theme === 'dark' ? '#007AFF20' : '#007AFF10';

  if (isLoading || data.length === 0) {
    return <Skeleton className="w-full h-64 rounded-xl" />;
  }

  return (
    <div className={cn('w-full h-72 p-2', className)}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart
          data={processedData}
          onClick={() =>
            telemetry.send({ type: 'chart_click', context: 'price_analytics' })
          }
          margin={{ top: 20, right: 30, left: 10, bottom: 20 }}
        >
          <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.1} />

          <XAxis
            dataKey="date"
            tick={{ fontSize: 11 }}
            stroke={theme === 'dark' ? '#ccc' : '#444'}
          />

          <YAxis
            domain={['auto', 'auto']}
            tickFormatter={formatCurrency}
            stroke={theme === 'dark' ? '#ccc' : '#444'}
            width={60}
          />

          <Tooltip
            contentStyle={{
              backgroundColor: theme === 'dark' ? '#1f1f1f' : '#fff',
              border: '1px solid #ccc',
              fontSize: '12px',
            }}
            formatter={(value: number) => formatCurrency(value)}
            labelStyle={{ fontWeight: 600 }}
          />

          <Legend
            verticalAlign="top"
            iconType="circle"
            wrapperStyle={{ fontSize: '12px' }}
          />

          {/* Основная линия цен */}
          <Line
            type="monotone"
            dataKey="value"
            stroke={primaryColor}
            strokeWidth={2}
            dot={false}
            name="Цена"
          />

          {/* Прогноз */}
          {showForecast && (
            <Line
              type="monotone"
              dataKey="predicted"
              stroke={forecastColor}
              strokeDasharray="5 5"
              strokeWidth={2}
              dot={false}
              name="Прогноз"
            />
          )}

          {/* Диапазон */}
          {showRange && (
            <Area
              type="monotone"
              dataKey="maxRange"
              stroke="none"
              fill={rangeColor}
              fillOpacity={1}
              name="Диапазон (макс)"
            />
          )}
          {showRange && (
            <Area
              type="monotone"
              dataKey="minRange"
              stroke="none"
              fill="#FFFFFF00"
              fillOpacity={0}
              name="Диапазон (мин)"
            />
          )}

          {/* Аномалии */}
          {showAnomalies &&
            processedData
              .filter((d) => d.anomaly)
              .map((point, idx) => (
                <ReferenceDot
                  key={`anomaly-${idx}`}
                  x={point.date}
                  y={point.value}
                  r={5}
                  fill={anomalyColor}
                  stroke="white"
                  strokeWidth={1}
                  label={{
                    value: 'Аномалия',
                    position: 'top',
                    fill: anomalyColor,
                    fontSize: 10,
                  }}
                />
              ))}

          {/* Последняя линия отметки */}
          <ReferenceLine
            x={processedData[processedData.length - 1].date}
            stroke="#999"
            strokeDasharray="3 3"
            label={{
              value: 'Текущий момент',
              position: 'insideTopRight',
              fontSize: 10,
              fill: theme === 'dark' ? '#aaa' : '#555',
            }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};
