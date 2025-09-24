import React, { useEffect, useMemo, useState } from "react";
import { DataTable } from "@/components/ui/data-table";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { usePrivacyViolations } from "@/hooks/privacy/usePrivacyViolations";
import { PrivacyViolationRecord, ViolationSeverity } from "@/types/privacy";
import { formatDistanceToNowStrict } from "date-fns";
import { ShieldAlert, AlarmWarning, ScanLine, EyeOff, GhostIcon } from "lucide-react";
import { motion } from "framer-motion";
import { useAutoScroll } from "@/hooks/system/useAutoScroll";

const severityColor = {
  LOW: "bg-green-600 text-white",
  MEDIUM: "bg-yellow-600 text-black",
  HIGH: "bg-orange-600 text-white",
  CRITICAL: "bg-red-700 text-white",
};

const severityIcon = {
  LOW: <EyeOff className="w-4 h-4" />,
  MEDIUM: <ScanLine className="w-4 h-4" />,
  HIGH: <ShieldAlert className="w-4 h-4" />,
  CRITICAL: <AlarmWarning className="w-4 h-4 animate-pulse" />,
};

const columns = [
  {
    accessorKey: "timestamp",
    header: "Время",
    cell: ({ getValue }: any) => (
      <span className="text-xs text-muted-foreground">
        {formatDistanceToNowStrict(new Date(getValue() as string), { addSuffix: true })}
      </span>
    ),
  },
  {
    accessorKey: "source",
    header: "Источник",
    cell: ({ getValue }: any) => (
      <span className="text-sm font-medium text-foreground">
        {getValue() || "—"}
      </span>
    ),
  },
  {
    accessorKey: "action",
    header: "Действие",
    cell: ({ getValue }: any) => (
      <span className="text-sm text-muted-foreground">{getValue()}</span>
    ),
  },
  {
    accessorKey: "violationType",
    header: "Тип нарушения",
    cell: ({ getValue }: any) => {
      const value = getValue() as string;
      return <Badge variant="outline">{value}</Badge>;
    },
  },
  {
    accessorKey: "severity",
    header: "Уровень",
    cell: ({ getValue }: any) => {
      const level = getValue() as ViolationSeverity;
      return (
        <motion.div
          className={`flex items-center gap-1 px-2 py-1 rounded-full text-xs font-bold ${severityColor[level]}`}
          initial={{ scale: 0.9 }}
          animate={{ scale: 1 }}
          transition={{ duration: 0.2 }}
        >
          {severityIcon[level]}
          <span>{level}</span>
        </motion.div>
      );
    },
  },
  {
    accessorKey: "details",
    header: "Подробности",
    cell: ({ getValue }: any) => (
      <span className="text-xs break-words max-w-[300px] text-foreground">
        {getValue()}
      </span>
    ),
  },
];

export const PrivacyViolationLogViewer: React.FC = () => {
  const { violations, refetch, loading } = usePrivacyViolations();
  const containerRef = useAutoScroll({ triggerKey: violations?.length || 0 });

  const sortedData = useMemo(() => {
    return [...(violations || [])].sort(
      (a: PrivacyViolationRecord, b: PrivacyViolationRecord) =>
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }, [violations]);

  useEffect(() => {
    const interval = setInterval(() => {
      refetch(); // Автообновление
    }, 15000);
    return () => clearInterval(interval);
  }, [refetch]);

  return (
    <Card className="w-full max-w-full h-full">
      <CardHeader>
        <div className="flex items-center gap-3">
          <GhostIcon className="w-5 h-5 text-red-500" />
          <CardTitle className="text-lg font-semibold text-foreground">
            Лог нарушений приватности
          </CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        <div ref={containerRef} className="overflow-y-auto max-h-[580px] border rounded-md">
          <DataTable
            columns={columns}
            data={sortedData}
            isLoading={loading}
            enableSorting
            autoHeight
            striped
            compact
          />
        </div>
      </CardContent>
    </Card>
  );
};

PrivacyViolationLogViewer.displayName = "PrivacyViolationLogViewer";
