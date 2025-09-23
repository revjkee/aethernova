import React, { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getAIDataUsage } from '@/services/api/aiInsightsAPI';
import { DataUsageEntry } from '@/shared/types/privacy';
import { Card } from '@/shared/components/Card';
import { Badge } from '@/shared/components/Badge';
import { Tooltip } from '@/shared/components/Tooltip';
import { Spinner } from '@/shared/components/Spinner';
import { Timeline } from '@/shared/components/Timeline';
import { DonutChart } from '@/shared/components/DonutChart';
import { TraceButton } from '@/widgets/Privacy/components/TraceButton';
import { RiskLevelBadge } from '@/widgets/Privacy/components/RiskLevelBadge';
import { AiIcon, BrainCircuitIcon, ShieldAlertIcon } from 'lucide-react';
import { AuditLogPanel } from '@/shared/components/AuditLogPanel';
import { FilterDropdown } from '@/shared/components/FilterDropdown';

interface Props {
  userId: string;
  showAudit?: boolean;
}

const AIDataUsageVisualizer: React.FC<Props> = ({ userId, showAudit = true }) => {
  const { t } = useTranslation();
  const [usageData, setUsageData] = useState<DataUsageEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedPurpose, setSelectedPurpose] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    getAIDataUsage(userId)
      .then((data) => setUsageData(data))
      .catch(() => setUsageData([]))
      .finally(() => setLoading(false));
  }, [userId]);

  const purposes = useMemo(() => {
    const unique = new Set(usageData.map((entry) => entry.purpose));
    return Array.from(unique);
  }, [usageData]);

  const filteredData = useMemo(() => {
    return selectedPurpose
      ? usageData.filter((entry) => entry.purpose === selectedPurpose)
      : usageData;
  }, [usageData, selectedPurpose]);

  const purposeStats = useMemo(() => {
    const groups = filteredData.reduce<Record<string, number>>((acc, entry) => {
      acc[entry.purpose] = (acc[entry.purpose] || 0) + 1;
      return acc;
    }, {});
    return Object.entries(groups).map(([label, value]) => ({ label, value }));
  }, [filteredData]);

  return (
    <div className="w-full p-4 border rounded-lg bg-white dark:bg-zinc-900 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-semibold flex items-center gap-2">
          <BrainCircuitIcon size={20} />
          {t('privacy.aiUsage.title')}
        </h2>
        <FilterDropdown
          options={purposes.map((p) => ({ label: t(`privacy.aiUsage.purpose.${p}`), value: p }))}
          selected={selectedPurpose}
          onChange={setSelectedPurpose}
          placeholder={t('privacy.aiUsage.filterByPurpose')}
          allowClear
        />
      </div>

      {loading ? (
        <div className="flex justify-center py-12">
          <Spinner />
        </div>
      ) : filteredData.length === 0 ? (
        <div className="text-muted-foreground text-sm">
          {t('privacy.aiUsage.noData')}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <Card title={t('privacy.aiUsage.distribution')}>
              <DonutChart data={purposeStats} />
            </Card>
            <Card title={t('privacy.aiUsage.timeline')}>
              <Timeline
                events={filteredData.map((entry) => ({
                  label: t(`privacy.aiUsage.purpose.${entry.purpose}`),
                  timestamp: entry.timestamp,
                  icon: <AiIcon size={16} />,
                  extra: (
                    <Tooltip content={entry.module}>
                      <Badge>{entry.module}</Badge>
                    </Tooltip>
                  ),
                }))}
              />
            </Card>
          </div>

          <div className="space-y-3">
            {filteredData.map((entry) => (
              <div
                key={entry.id}
                className="border p-4 rounded-lg bg-zinc-50 dark:bg-zinc-800 flex flex-col md:flex-row justify-between items-start md:items-center gap-3"
              >
                <div className="flex flex-col gap-1">
                  <div className="text-sm text-muted-foreground">
                    {t(`privacy.aiUsage.purpose.${entry.purpose}`)}
                  </div>
                  <div className="text-base font-medium">
                    {entry.dataType}
                  </div>
                  <div className="text-xs">
                    {t('privacy.aiUsage.moduleUsed')}: {entry.module}
                  </div>
                </div>
                <div className="flex items-center gap-2 mt-2 md:mt-0">
                  <RiskLevelBadge level={entry.riskLevel} />
                  <TraceButton traceId={entry.traceId} />
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {showAudit && (
        <div className="mt-6">
          <AuditLogPanel resource={`ai:data-usage:${userId}`} />
        </div>
      )}
    </div>
  );
};

export default React.memo(AIDataUsageVisualizer);
