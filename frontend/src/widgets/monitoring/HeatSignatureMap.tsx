import React, { useEffect, useMemo, useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { HeatMapGrid } from 'react-grid-heatmap';
import { getHeatSignatureData, HeatZoneData } from '@/services/monitoring/heatSignature';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useTranslation } from 'react-i18next';

export const HeatSignatureMap: React.FC = () => {
  const { t } = useTranslation();
  const [heatData, setHeatData] = useState<HeatZoneData[]>([]);
  const [refreshing, setRefreshing] = useState(false);

  const fetchData = useCallback(async () => {
    setRefreshing(true);
    const data = await getHeatSignatureData();
    setHeatData(data);
    setRefreshing(false);
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 20000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const zones = useMemo(() => {
    return [...new Set(heatData.map(d => d.zone))];
  }, [heatData]);

  const systems = useMemo(() => {
    return [...new Set(heatData.map(d => d.system))];
  }, [heatData]);

  const matrix = useMemo(() => {
    return zones.map(zone =>
      systems.map(system => {
        const match = heatData.find(d => d.zone === zone && d.system === system);
        return match ? match.intensity : 0;
      })
    );
  }, [zones, systems, heatData]);

  return (
    <Card className="w-full h-full border border-orange-700 shadow-md rounded-xl">
      <CardHeader className="flex justify-between items-center space-y-0">
        <CardTitle className="text-base font-semibold flex items-center gap-2 text-orange-800">
          {t('monitoring.heat_signature_map', 'Heat Signature Map')}
        </CardTitle>
        <Button
          size="sm"
          variant="ghost"
          onClick={fetchData}
          disabled={refreshing}
          className="text-xs text-orange-700 hover:bg-orange-100"
        >
          <RefreshCw className={cn("w-4 h-4 mr-1", refreshing && "animate-spin")} />
          {t('common.refresh')}
        </Button>
      </CardHeader>
      <CardContent className="h-[420px]">
        <ScrollArea className="h-full">
          <div className="overflow-auto">
            <HeatMapGrid
              data={matrix}
              xLabels={systems}
              yLabels={zones}
              cellStyle={(x, y, value) => ({
                background: `rgba(255, 85, 0, ${Math.min(1, value / 100)})`,
                fontSize: "0.75rem",
                color: value > 60 ? "#fff" : "#000",
                border: "1px solid rgba(0,0,0,0.1)"
              })}
              cellRender={(x, y, value) => (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div>{value}</div>
                  </TooltipTrigger>
                  <TooltipContent side="top">
                    <div className="text-xs">
                      {t('monitoring.zone')}: <strong>{zones[y]}</strong><br />
                      {t('monitoring.system')}: <strong>{systems[x]}</strong><br />
                      {t('monitoring.intensity')}: <strong>{value}</strong>
                    </div>
                  </TooltipContent>
                </Tooltip>
              )}
            />
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

export default HeatSignatureMap;
