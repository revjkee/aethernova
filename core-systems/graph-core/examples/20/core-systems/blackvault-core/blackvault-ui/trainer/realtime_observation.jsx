import React, { useState, useEffect, useRef } from "react";
import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { fetchRealtimeStream } from "@/lib/api/agi";
import { TerminalSquare, Eye, EyeOff } from "lucide-react";

export default function RealtimeObservation() {
  const [log, setLog] = useState([]);
  const [connected, setConnected] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const logEndRef = useRef(null);
  const wsRef = useRef(null);

  useEffect(() => {
    if (!connected) return;

    wsRef.current = fetchRealtimeStream();

    wsRef.current.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        setLog((prev) => [...prev.slice(-499), payload]);
      } catch (err) {
        console.warn("Ошибка разбора потока:", err);
      }
    };

    wsRef.current.onclose = () => {
      setConnected(false);
    };

    return () => {
      wsRef.current?.close();
    };
  }, [connected]);

  useEffect(() => {
    if (autoScroll && logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [log, autoScroll]);

  const toggleConnection = () => {
    if (connected) {
      wsRef.current?.close();
    } else {
      setConnected(true);
    }
  };

  const classify = (entry) => {
    if (entry.type === "anomaly") return "text-red-400";
    if (entry.type === "memory") return "text-yellow-300";
    if (entry.type === "reasoning") return "text-blue-400";
    if (entry.type === "input") return "text-emerald-400";
    return "text-slate-300";
  };

  return (
    <Card className="bg-black border border-slate-700 shadow-2xl rounded-2xl text-white h-full flex flex-col">
      <CardHeader className="text-xl font-bold flex justify-between items-center">
        <span>Наблюдение за AGI</span>
        <Switch
          checked={connected}
          onCheckedChange={toggleConnection}
          className="data-[state=checked]:bg-green-600"
        >
          {connected ? <Eye className="w-4 h-4 ml-2" /> : <EyeOff className="w-4 h-4 ml-2" />}
        </Switch>
      </CardHeader>

      <CardContent className="flex-1 overflow-hidden flex flex-col">
        <ScrollArea className="flex-1 overflow-y-auto px-2 bg-zinc-900 border border-slate-800 rounded-xl p-4 text-sm font-mono tracking-tight">
          {log.map((entry, idx) => (
            <div key={idx} className={`${classify(entry)} whitespace-pre-wrap`}>
              [{entry.timestamp}] {entry.type.toUpperCase()}: {entry.content}
            </div>
          ))}
          <div ref={logEndRef} />
        </ScrollArea>

        <div className="flex justify-between items-center text-xs text-slate-400 mt-3">
          <div>
            Сообщений: <Badge variant="secondary">{log.length}</Badge>
          </div>
          <div className="flex gap-2 items-center">
            Автопрокрутка:
            <Switch
              checked={autoScroll}
              onCheckedChange={setAutoScroll}
              className="data-[state=checked]:bg-indigo-600"
            />
          </div>
        </div>

        <Separator className="mt-4 mb-2 border-slate-700" />

        <div className="text-xs text-slate-500">
          Поток обновляется в реальном времени. Обнаружение конфликтов мышления и слепков памяти выполняется на ядре `core-agents`.
        </div>
      </CardContent>
    </Card>
  );
}
