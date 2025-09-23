import { FC, useMemo, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useHRKPI } from "@/features/hr-core/hooks/useHRKPI";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { cn } from "@/lib/utils";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { Button } from "@/components/ui/button";
import { DownloadIcon, RefreshCcwIcon } from "lucide-react";
import { saveAs } from "file-saver";
import html2canvas from "html2canvas";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import { useHRKPIXAI } from "@/features/xai/hooks/useHRKPIXAI";

interface Props {
  compact?: boolean;
}

export const HRKPIWidget: FC<Props> = ({ compact = false }) => {
  const { can } = usePermission();
  const { kpis, trendData, loading, refetch } = useHRKPI();
  const { explanation, loading: xaiLoading } = useHRKPIXAI();
  const [exporting, setExporting] = useState(false);
  const containerRef = useState<HTMLDivElement | null>(null)[0];

  const handleExport = async () => {
    if (!containerRef) return;
    setExporting(true);
    try {
      const canvas = await html2canvas(containerRef);
      canvas.toBlob((blob) => {
        if (blob) saveAs(blob, "hr_kpi_dashboard.png");
      });
    } finally {
      setExporting(false);
    }
  };

  const getKPIColor = (value: number, threshold: number): string => {
    if (value < threshold * 0.75) return "text-red-500";
    if (value < threshold) return "text-yellow-500";
    return "text-green-600";
  };

  const formattedKPIs = useMemo(() => {
    if (!kpis) return [];
    return [
      {
        key: "avgHiringTime",
        label: "Среднее время закрытия вакансии",
        value: `${kpis.avgHiringTime} дней`,
        numeric: kpis.avgHiringTime,
        threshold: 30
      },
      {
        key: "retentionRate",
        label: "Удержание персонала (12 мес)",
        value: `${kpis.retentionRate}%`,
        numeric: kpis.retentionRate,
        threshold: 85
      },
      {
        key: "engagementScore",
        label: "Индекс вовлечённости",
        value: `${kpis.engagementScore}/100`,
        numeric: kpis.engagementScore,
        threshold: 75
      },
      {
        key: "turnoverRate",
        label: "Текучесть персонала",
        value: `${kpis.turnoverRate}%`,
        numeric: kpis.turnoverRate,
        threshold: 15
      }
    ];
  }, [kpis]);

  if (loading || !kpis) {
    return (
      <Card className={cn("w-full", compact && "max-w-2xl")}>
        <CardHeader>
          <Skeleton className="h-6 w-64 mb-2" />
          <Skeleton className="h-4 w-32" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[300px] w-full" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={cn("transition-shadow hover:shadow-md", compact && "max-w-2xl")}>
      <CardHeader className="flex flex-col md:flex-row justify-between md:items-center">
        <div>
          <CardTitle className="text-xl">Метрики HR эффективности</CardTitle>
          <p className="text-sm text-muted-foreground">AI-драйверы, тренды и показатели удержания</p>
        </div>
        <div className="flex gap-2 mt-4 md:mt-0">
          <Button variant="outline" size="sm" onClick={refetch}>
            <RefreshCcwIcon className="w-4 h-4 mr-1" /> Обновить
          </Button>
          <Button variant="outline" size="sm" onClick={handleExport} disabled={exporting}>
            <DownloadIcon className="w-4 h-4 mr-1" />
            {exporting ? "Экспорт..." : "Сохранить PNG"}
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-6" ref={containerRef}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {formattedKPIs.map((item) => (
            <div key={item.key} className="flex justify-between">
              <span className="text-sm text-muted-foreground">{item.label}</span>
              <span className={cn("font-semibold", getKPIColor(item.numeric, item.threshold))}>
                {item.value}
              </span>
            </div>
          ))}
        </div>

        {trendData && (
          <div className="h-[280px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="month" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="retention" stroke="#10b981" name="Удержание" />
                <Line type="monotone" dataKey="turnover" stroke="#ef4444" name="Текучесть" />
                <Line type="monotone" dataKey="engagement" stroke="#6366f1" name="Вовлечённость" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}

        {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
          <div className="mt-6">
            <XAIExplanation
              explanation={explanation}
              title="AI-пояснение динамики HR-метрик"
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
