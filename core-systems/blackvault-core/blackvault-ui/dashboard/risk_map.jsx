import React, { useEffect, useState } from "react";
import { MapPin, Flame, ShieldAlert, CircleAlert } from "lucide-react";
import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { fetchRiskMapData } from "@/lib/api/risk";
import { cn } from "@/lib/utils";

const RiskMarker = ({ risk }) => {
  const color =
    risk.level === "critical"
      ? "bg-red-600"
      : risk.level === "high"
      ? "bg-orange-500"
      : risk.level === "medium"
      ? "bg-yellow-400"
      : "bg-green-400";

  return (
    <div className="relative group cursor-pointer">
      <div className={cn("w-4 h-4 rounded-full", color)} />
      <div className="absolute z-50 top-6 left-0 w-56 bg-black text-white text-xs p-2 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200 shadow-lg">
        <div><strong>Источник:</strong> {risk.source}</div>
        <div><strong>Уровень:</strong> {risk.level}</div>
        <div><strong>Угроза:</strong> {risk.description}</div>
        <div><strong>Координаты:</strong> [{risk.x}, {risk.y}]</div>
      </div>
    </div>
  );
};

export default function RiskMap() {
  const [risks, setRisks] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;

    async function loadRisks() {
      try {
        const data = await fetchRiskMapData();
        if (active) setRisks(data);
      } catch (err) {
        console.error("Ошибка загрузки карты рисков", err);
      } finally {
        if (active) setLoading(false);
      }
    }

    loadRisks();
    const interval = setInterval(loadRisks, 7000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <Card className="rounded-2xl shadow-xl bg-zinc-900 border border-slate-700 text-white overflow-hidden">
      <CardHeader className="flex items-center gap-2 text-lg font-bold">
        <ShieldAlert className="w-5 h-5 text-red-500" />
        Карта Рисков
      </CardHeader>
      <CardContent className="relative h-[400px] bg-gradient-to-br from-slate-900 to-slate-800 p-4">
        {loading || !risks ? (
          <>
            <Skeleton className="w-full h-16 mb-4" />
            <Skeleton className="w-3/4 h-12 mb-4" />
            <Skeleton className="w-1/2 h-10" />
          </>
        ) : (
          <div className="relative w-full h-full grid grid-cols-12 grid-rows-8 gap-2">
            {risks.map((risk, index) => (
              <div
                key={index}
                style={{
                  gridColumnStart: Math.min(risk.x + 1, 12),
                  gridRowStart: Math.min(risk.y + 1, 8),
                }}
                className="flex items-center justify-center"
              >
                <RiskMarker risk={risk} />
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
