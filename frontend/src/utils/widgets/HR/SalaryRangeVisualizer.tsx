import { FC, useMemo, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { useSalaryAnalytics } from "@/features/hr-core/hooks/useSalaryAnalytics";
import { cn } from "@/lib/utils";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine } from "recharts";
import { DownloadIcon, Loader2Icon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { XAIExplanation } from "@/features/xai/components/XAIExplanation";
import { useSalaryXAI } from "@/features/xai/hooks/useSalaryXAI";
import html2canvas from "html2canvas";
import { saveAs } from "file-saver";

interface Props {
  positionId: string;
  compact?: boolean;
}

export const SalaryRangeVisualizer: FC<Props> = ({ positionId, compact = false }) => {
  const { can } = usePermission();
  const { salaryData, loading, refetch } = useSalaryAnalytics(positionId);
  const { explanation, loading: xaiLoading } = useSalaryXAI(positionId);
  const [exporting, setExporting] = useState(false);
  const containerRef = useState<HTMLDivElement | null>(null)[0];

  const handleExport = async () => {
    if (!containerRef) return;
    setExporting(true);
    try {
      const canvas = await html2canvas(containerRef);
      canvas.toBlob(blob => {
        if (blob) saveAs(blob, `salary_range_${positionId}.png`);
      });
    } finally {
      setExporting(false);
    }
  };

  const metrics = useMemo(() => {
    if (!salaryData) return null;
    return {
      min: salaryData.min,
      max: salaryData.max,
      median: salaryData.median,
      companyAvg: salaryData.companyAvg,
      marketAvg: salaryData.marketAvg
    };
  }, [salaryData]);

  const chartData = useMemo(() => {
    if (!salaryData?.distribution) return [];
    return salaryData.distribution.map(d => ({
      range: `${d.rangeStart}–${d.rangeEnd}`,
      count: d.count
    }));
  }, [salaryData]);

  if (loading || !salaryData || !metrics) {
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
          <CardTitle className="text-xl">Диапазон зарплат</CardTitle>
          <p className="text-sm text-muted-foreground">Сравнение с рынком и внутри компании</p>
        </div>
        <div className="flex gap-2 mt-4 md:mt-0">
          <Button variant="outline" size="sm" onClick={refetch}>
            <Loader2Icon className="w-4 h-4 mr-2 animate-spin" />
            Обновить
          </Button>
          {can(Role.SUPERVISOR) && (
            <Button variant="outline" size="sm" onClick={handleExport} disabled={exporting}>
              <DownloadIcon className="w-4 h-4 mr-2" />
              {exporting ? "Экспорт…" : "Сохранить PNG"}
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent ref={containerRef} className="space-y-6">
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
          <div>
            <p className="text-sm text-muted-foreground">Мин. зарплата</p>
            <p className="font-semibold text-green-600">${metrics.min.toLocaleString()}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Макс. зарплата</p>
            <p className="font-semibold text-red-500">${metrics.max.toLocaleString()}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Медиана</p>
            <p className="font-semibold text-blue-600">${metrics.median.toLocaleString()}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Средняя по компании</p>
            <p className="font-semibold">${metrics.companyAvg.toLocaleString()}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Средняя по рынку</p>
            <p className="font-semibold">${metrics.marketAvg.toLocaleString()}</p>
          </div>
        </div>

        <div className="h-[320px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="range" angle={-35} textAnchor="end" height={60} />
              <YAxis />
              <Tooltip />
              <ReferenceLine y={metrics.median} stroke="#2563eb" strokeDasharray="3 3" label="Медиана" />
              <Bar dataKey="count" fill="#10b981" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {can(Role.SUPERVISOR) && explanation && !xaiLoading && (
          <div className="mt-6">
            <XAIExplanation
              explanation={explanation}
              title="AI-пояснение диапазона зарплат"
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
};
