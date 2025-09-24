import React, { useEffect, useState } from "react";
import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { AlertTriangle, ShieldCheck, Activity, Cpu } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { fetchLiveBattleFeed } from "@/lib/api/battleFeed";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";

const ThreatBadge = ({ threat }) => {
  const colors = {
    high: "bg-red-600 text-white",
    medium: "bg-yellow-500 text-black",
    low: "bg-green-600 text-white",
    unknown: "bg-gray-400 text-white",
  };

  return (
    <Badge className={cn("text-xs px-2", colors[threat.level || "unknown"])}>
      {threat.level?.toUpperCase() || "UNKNOWN"}
    </Badge>
  );
};

const BattleEvent = ({ event }) => (
  <div className="border-b py-2 flex justify-between items-center">
    <div className="space-y-1 max-w-[70%]">
      <p className="text-sm font-medium">{event.description}</p>
      <p className="text-xs text-muted-foreground">{event.timestamp}</p>
    </div>
    <div className="flex items-center gap-2">
      <ThreatBadge threat={event.threat} />
      {event.defended ? (
        <ShieldCheck className="text-green-600 w-4 h-4" />
      ) : (
        <AlertTriangle className="text-red-600 w-4 h-4" />
      )}
    </div>
  </div>
);

export default function BattleView() {
  const [events, setEvents] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;

    async function loadData() {
      try {
        const data = await fetchLiveBattleFeed();
        if (mounted) {
          setEvents(data);
        }
      } catch (err) {
        console.error("Failed to fetch battle feed:", err);
      } finally {
        if (mounted) setLoading(false);
      }
    }

    loadData();
    const interval = setInterval(loadData, 7000); // обновление каждые 7 секунд
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <Card className="shadow-xl rounded-2xl border border-slate-700 bg-black text-white">
      <CardHeader className="text-lg font-bold flex items-center gap-2">
        <Cpu className="w-5 h-5 text-blue-400" />
        Боевой Мониторинг
      </CardHeader>
      <CardContent className="h-[400px] p-2 overflow-hidden">
        {loading ? (
          <div className="space-y-2">
            <Skeleton className="h-5 w-full" />
            <Skeleton className="h-5 w-4/5" />
            <Skeleton className="h-5 w-3/5" />
          </div>
        ) : events?.length > 0 ? (
          <ScrollArea className="h-full pr-2">
            {events.map((event, idx) => (
              <BattleEvent key={idx} event={event} />
            ))}
          </ScrollArea>
        ) : (
          <p className="text-muted-foreground text-sm">Нет активных инцидентов.</p>
        )}
      </CardContent>
    </Card>
  );
}
