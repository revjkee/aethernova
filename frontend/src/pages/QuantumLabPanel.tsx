// frontend/src/pages/QuantumLabPanel.tsx
import React, {
  useCallback,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
  Suspense,
} from "react";
import { motion } from "framer-motion";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Activity,
  AlertCircle,
  Check,
  Cpu,
  Flame,
  Gauge,
  Loader2,
  Play,
  Plus,
  RefreshCw,
  Save,
  Search,
  Server,
  Settings,
  StopCircle,
  Trash2,
  Wifi,
  Wind,
  Zap,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import {
  Table,
  TableBody,
  TableCell,
  TableCaption,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/ui/use-toast";

// --------------------------------------
// Типы
// --------------------------------------

type ExperimentStatus = "queued" | "running" | "completed" | "failed" | "canceled";

type Experiment = {
  id: string;
  name: string;
  backend: "AWS_Braket" | "IonQ" | "Rigetti" | "Simulator";
  shots: number;
  depth: number;
  width: number;
  createdAt: string; // ISO
  updatedAt: string; // ISO
  status: ExperimentStatus;
  progress: number; // 0..100
  owner: string;
  tags: string[];
  etaSec?: number;
};

type TelemetryPoint = {
  t: number; // epoch ms
  qpuTempK?: number;
  decoherenceUs?: number;
  queue?: number;
  errors?: number;
  latencyMs?: number;
  successRate?: number;
};

type StreamEvent =
  | { type: "telemetry"; payload: TelemetryPoint }
  | { type: "experiment:update"; payload: Experiment }
  | { type: "experiment:deleted"; payload: { id: string } }
  | { type: "heartbeat"; payload: { ts: number } }
  | { type: "error"; payload: { message: string } };

type Filters = {
  qpu: "ALL" | "AWS_Braket" | "IonQ" | "Rigetti" | "Simulator";
  status: "ALL" | ExperimentStatus;
  query: string;
  onlyMine: boolean;
  realtime: boolean;
};

// --------------------------------------
// Константы и утилиты
// --------------------------------------

const API_BASE =
  (import.meta as any)?.env?.VITE_API_BASE?.toString() ||
  (typeof process !== "undefined" && (process as any)?.env?.VITE_API_BASE) ||
  "/api";

const STREAM_URL = `${API_BASE}/quantum/lab/stream`;
const EXPERIMENTS_URL = `${API_BASE}/quantum/lab/experiments`;
const TELEMETRY_URL = `${API_BASE}/quantum/lab/telemetry`;

const DEFAULT_FILTERS: Filters = {
  qpu: "ALL",
  status: "ALL",
  query: "",
  onlyMine: false,
  realtime: true,
};

const fmtTime = (ts: string | number) => {
  const d = new Date(typeof ts === "string" ? ts : ts);
  return d.toLocaleString();
};

const clamp = (v: number, min = 0, max = 100) => Math.max(min, Math.min(max, v));

// --------------------------------------
// Редьюсер состояния
// --------------------------------------

type State = {
  experiments: Record<string, Experiment>;
  telemetry: TelemetryPoint[];
  connected: boolean;
  connecting: boolean;
  lastHeartbeat?: number;
  latencyMs?: number;
  offlineCacheAt?: number;
};

type Action =
  | { type: "connect:start" }
  | { type: "connect:ok" }
  | { type: "connect:fail" }
  | { type: "heartbeat"; ts: number }
  | { type: "latency"; ms: number }
  | { type: "telemetry:push"; point: TelemetryPoint }
  | { type: "experiments:bulk"; list: Experiment[] }
  | { type: "experiment:upsert"; item: Experiment }
  | { type: "experiment:delete"; id: string }
  | { type: "offline:restore"; cache: Partial<State> };

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case "connect:start":
      return { ...state, connecting: true };
    case "connect:ok":
      return { ...state, connecting: false, connected: true };
    case "connect:fail":
      return { ...state, connecting: false, connected: false };
    case "heartbeat":
      return { ...state, lastHeartbeat: action.ts };
    case "latency":
      return { ...state, latencyMs: action.ms };
    case "telemetry:push": {
      const telemetry = [...state.telemetry, action.point].slice(-600); // ~10 мин при 1Hz
      return { ...state, telemetry };
    }
    case "experiments:bulk": {
      const map: Record<string, Experiment> = { ...state.experiments };
      for (const e of action.list) map[e.id] = e;
      return { ...state, experiments: map };
    }
    case "experiment:upsert": {
      return {
        ...state,
        experiments: { ...state.experiments, [action.item.id]: action.item },
      };
    }
    case "experiment:delete": {
      const next = { ...state.experiments };
      delete next[action.id];
      return { ...state, experiments: next };
    }
    case "offline:restore": {
      return {
        ...state,
        ...action.cache,
      };
    }
    default:
      return state;
  }
}

// --------------------------------------
// Хук URL-фильтров
// --------------------------------------

function useUrlFilters(initial: Filters = DEFAULT_FILTERS) {
  const [filters, setFilters] = useState<Filters>(() => {
    const params = new URLSearchParams(window.location.search);
    const qpu = (params.get("qpu") as Filters["qpu"]) || initial.qpu;
    const status = (params.get("status") as Filters["status"]) || initial.status;
    const query = params.get("q") || initial.query;
    const onlyMine = params.get("mine") === "1" ? true : initial.onlyMine;
    const realtime = params.get("rt") !== "0";
    return { qpu, status, query, onlyMine, realtime };
  });

  const persist = useCallback((f: Filters) => {
    const params = new URLSearchParams(window.location.search);
    params.set("qpu", f.qpu);
    params.set("status", f.status);
    params.set("q", f.query);
    params.set("mine", f.onlyMine ? "1" : "0");
    params.set("rt", f.realtime ? "1" : "0");
    const url = `${window.location.pathname}?${params.toString()}`;
    window.history.replaceState(null, "", url);
  }, []);

  useEffect(() => {
    persist(filters);
  }, [filters, persist]);

  return { filters, setFilters };
}

// --------------------------------------
// Клиент API
// --------------------------------------

async function fetchJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    ...init,
  });
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    throw new Error(`HTTP ${r.status}: ${text || r.statusText}`);
  }
  return (await r.json()) as T;
}

// --------------------------------------
// Основной компонент
// --------------------------------------

export default function QuantumLabPanel() {
  const { toast } = useToast();
  const { filters, setFilters } = useUrlFilters();
  const [state, dispatch] = useReducer(reducer, {
    experiments: {},
    telemetry: [],
    connected: false,
    connecting: false,
  } as State);

  // офлайн кэш
  useEffect(() => {
    const cache = localStorage.getItem("quantum-lab:state");
    if (cache) {
      try {
        const parsed = JSON.parse(cache) as Partial<State>;
        dispatch({ type: "offline:restore", cache: parsed });
      } catch {
        // ignore
      }
    }
  }, []);
  useEffect(() => {
    const snapshot: Partial<State> = {
      experiments: state.experiments,
      telemetry: state.telemetry.slice(-120), // храним компактно
      offlineCacheAt: Date.now(),
    };
    localStorage.setItem("quantum-lab:state", JSON.stringify(snapshot));
  }, [state.experiments, state.telemetry]);

  // первичная загрузка
  useEffect(() => {
    let aborted = false;
    (async () => {
      try {
        const [exps] = await Promise.all([
          fetchJSON<Experiment[]>(`${EXPERIMENTS_URL}?limit=500`),
        ]);
        if (aborted) return;
        dispatch({ type: "experiments:bulk", list: exps });
      } catch (e: any) {
        toast({
          title: "Ошибка загрузки",
          description: e?.message || "Не удалось загрузить эксперименты",
          variant: "destructive",
        });
      }
    })();
    return () => {
      aborted = true;
    };
  }, [toast]);

  // стрим: SSE -> WS фейловер
  useEffect(() => {
    if (!filters.realtime) return;
    let closed = false;
    let retry = 0;
    let ws: WebSocket | null = null;
    let es: EventSource | null = null;

    const connectSSE = () => {
      dispatch({ type: "connect:start" });
      const url = `${STREAM_URL}?v=1`;
      es = new EventSource(url, { withCredentials: true });
      const t0 = performance.now();

      es.onopen = () => {
        dispatch({ type: "connect:ok" });
        dispatch({ type: "latency", ms: Math.round(performance.now() - t0) });
        retry = 0;
      };
      es.onerror = () => {
        es?.close();
        if (!closed) connectWS();
      };
      es.onmessage = (ev) => {
        try {
          const evt = JSON.parse(ev.data) as StreamEvent;
          handleEvent(evt);
        } catch {
          // ignore
        }
      };
    };

    const connectWS = () => {
      dispatch({ type: "connect:start" });
      const url = STREAM_URL.replace(/^http/, "ws") + "?v=1";
      const t0 = performance.now();
      ws = new WebSocket(url);
      ws.onopen = () => {
        dispatch({ type: "connect:ok" });
        dispatch({ type: "latency", ms: Math.round(performance.now() - t0) });
        retry = 0;
      };
      ws.onmessage = (ev) => {
        try {
          const evt = JSON.parse(ev.data) as StreamEvent;
          handleEvent(evt);
        } catch {
          // ignore
        }
      };
      ws.onerror = ws.onclose = () => {
        if (closed) return;
        dispatch({ type: "connect:fail" });
        const timeout = Math.min(1000 * Math.pow(2, retry++), 15000);
        setTimeout(connectSSE, timeout);
      };
    };

    const handleEvent = (evt: StreamEvent) => {
      if (evt.type === "telemetry") {
        dispatch({ type: "telemetry:push", point: evt.payload });
      } else if (evt.type === "experiment:update") {
        dispatch({ type: "experiment:upsert", item: evt.payload });
      } else if (evt.type === "experiment:deleted") {
        dispatch({ type: "experiment:delete", id: evt.payload.id });
      } else if (evt.type === "heartbeat") {
        dispatch({ type: "heartbeat", ts: evt.payload.ts });
      } else if (evt.type === "error") {
        toast({
          title: "Стрим-ошибка",
          description: evt.payload.message,
          variant: "destructive",
        });
      }
    };

    connectSSE();
    return () => {
      closed = true;
      es?.close();
      ws?.close();
    };
  }, [filters.realtime, toast]);

  // периодический пуллинг телеметрии (fallback и backfill)
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const data = await fetchJSON<TelemetryPoint[]>(`${TELEMETRY_URL}?limit=60`);
        if (!alive) return;
        for (const p of data) dispatch({ type: "telemetry:push", point: p });
      } catch {
        // ignore
      } finally {
        if (alive) setTimeout(tick, 15000);
      }
    };
    tick();
    return () => {
      alive = false;
    };
  }, []);

  // отфильтрованные эксперименты
  const experiments = useMemo(() => {
    const arr = Object.values(state.experiments);
    return arr
      .filter((e) => (filters.qpu === "ALL" ? true : e.backend === filters.qpu))
      .filter((e) => (filters.status === "ALL" ? true : e.status === filters.status))
      .filter((e) =>
        filters.query
          ? (e.name + " " + e.id + " " + e.tags.join(" ")).toLowerCase().includes(filters.query.toLowerCase())
          : true
      )
      .filter((e) => (filters.onlyMine ? e.owner === "me" : true))
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }, [state.experiments, filters]);

  // агрегаты телеметрии
  const telemetryView = useMemo(() => {
    const data = state.telemetry.slice(-300);
    const toFixed = (v?: number, n = 2) => (typeof v === "number" ? Number(v.toFixed(n)) : undefined);
    return data.map((p) => ({
      t: p.t,
      qpuTempK: toFixed(p.qpuTempK),
      latencyMs: p.latencyMs,
      successRate: toFixed(p.successRate, 3),
      decoherenceUs: toFixed(p.decoherenceUs),
      queue: p.queue,
      errors: p.errors,
    }));
  }, [state.telemetry]);

  // операции
  const runExperiment = useCallback(
    async (payload: Partial<Experiment>) => {
      const tempId = `tmp_${Date.now()}`;
      const optimistic: Experiment = {
        id: tempId,
        name: payload.name || "New Experiment",
        backend: (payload.backend || "Simulator") as Experiment["backend"],
        shots: payload.shots || 100,
        depth: payload.depth || 8,
        width: payload.width || 4,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        status: "queued",
        progress: 0,
        owner: "me",
        tags: payload.tags || [],
      };
      dispatch({ type: "experiment:upsert", item: optimistic });
      try {
        const real = await fetchJSON<Experiment>(EXPERIMENTS_URL, {
          method: "POST",
          body: JSON.stringify(payload),
        });
        dispatch({ type: "experiment:upsert", item: real });
        toast({ title: "Задача поставлена", description: real.name, icon: <Check /> as any });
      } catch (e: any) {
        dispatch({ type: "experiment:delete", id: tempId });
        toast({
          title: "Не удалось запустить эксперимент",
          description: e?.message || "",
          variant: "destructive",
        });
      }
    },
    [toast]
  );

  const cancelExperiment = useCallback(
    async (id: string) => {
      const prev = state.experiments[id];
      if (!prev) return;
      const optimistic = { ...prev, status: "canceled" as ExperimentStatus, progress: prev.progress || 0 };
      dispatch({ type: "experiment:upsert", item: optimistic });
      try {
        await fetchJSON<void>(`${EXPERIMENTS_URL}/${id}`, { method: "DELETE" });
        toast({ title: "Отменено", description: prev.name });
      } catch (e: any) {
        dispatch({ type: "experiment:upsert", item: prev });
        toast({
          title: "Ошибка отмены",
          description: e?.message || "",
          variant: "destructive",
        });
      }
    },
    [state.experiments, toast]
  );

  const refresh = useCallback(async () => {
    try {
      const exps = await fetchJSON<Experiment[]>(`${EXPERIMENTS_URL}?limit=500&ts=${Date.now()}`);
      dispatch({ type: "experiments:bulk", list: exps });
      toast({ title: "Обновлено", icon: <RefreshCw /> as any });
    } catch (e: any) {
      toast({ title: "Ошибка обновления", description: e?.message || "", variant: "destructive" });
    }
  }, [toast]);

  // хоткеи
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        const el = document.getElementById("qlab-search") as HTMLInputElement | null;
        el?.focus();
        e.preventDefault();
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "r") {
        refresh();
        e.preventDefault();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [refresh]);

  // UI helpers
  const statusBadge = (s: ExperimentStatus) => {
    const palette: Record<ExperimentStatus, string> = {
      queued: "bg-muted text-foreground",
      running: "bg-blue-600 text-white",
      completed: "bg-emerald-600 text-white",
      failed: "bg-red-600 text-white",
      canceled: "bg-amber-600 text-white",
    };
    return <Badge className={palette[s]}>{s}</Badge>;
  };

  // форма запуска
  const [openNew, setOpenNew] = useState(false);
  const [form, setForm] = useState<Partial<Experiment>>({
    backend: "Simulator",
    shots: 100,
    depth: 8,
    width: 4,
    name: "QLab experiment",
    tags: [],
  });
  const formValid =
    (form.name || "").trim().length >= 3 &&
    (form.shots || 0) > 0 &&
    (form.depth || 0) > 0 &&
    (form.width || 0) > 0;

  // скелеты
  const loadingSkeleton = (
    <div className="grid grid-cols-12 gap-4">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="col-span-12 lg:col-span-6">
          <Card className="h-40 animate-pulse">
            <CardContent className="h-full" />
          </Card>
        </div>
      ))}
    </div>
  );

  return (
    <div className="p-4 md:p-6 lg:p-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <motion.div
            initial={{ rotate: -10, scale: 0.9 }}
            animate={{ rotate: 0, scale: 1 }}
            transition={{ type: "spring", stiffness: 200, damping: 12 }}
            className="p-2 rounded-2xl bg-primary/10"
          >
            <Cpu className="w-6 h-6" />
          </motion.div>
          <div>
            <h1 className="text-2xl md:text-3xl font-semibold">Quantum Lab Panel</h1>
            <p className="text-muted-foreground text-sm">
              Управление квантовыми экспериментами и телеметрией в реальном времени
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={refresh}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Обновить
          </Button>
          <Dialog open={openNew} onOpenChange={setOpenNew}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="w-4 h-4 mr-2" />
                Новый эксперимент
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[520px]">
              <DialogHeader>
                <DialogTitle>Запуск эксперимента</DialogTitle>
                <DialogDescription>
                  Определите параметры квантовой задачи и отправьте на выполнение.
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3">
                  <div className="col-span-2">
                    <Label htmlFor="name">Название</Label>
                    <Input
                      id="name"
                      value={form.name || ""}
                      onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                      placeholder="Напр. VQE LiH"
                    />
                  </div>
                  <div>
                    <Label>Бэкенд</Label>
                    <Select
                      value={form.backend as string}
                      onValueChange={(v) => setForm((f) => ({ ...f, backend: v as any }))}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Выберите QPU" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          <SelectLabel>QPU</SelectLabel>
                          <SelectItem value="AWS_Braket">AWS Braket</SelectItem>
                          <SelectItem value="IonQ">IonQ</SelectItem>
                          <SelectItem value="Rigetti">Rigetti</SelectItem>
                          <SelectItem value="Simulator">Simulator</SelectItem>
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label htmlFor="shots">Shots</Label>
                    <Input
                      id="shots"
                      type="number"
                      min={1}
                      value={form.shots || 0}
                      onChange={(e) => setForm((f) => ({ ...f, shots: Number(e.target.value) }))}
                    />
                  </div>
                  <div>
                    <Label htmlFor="depth">Depth</Label>
                    <Input
                      id="depth"
                      type="number"
                      min={1}
                      value={form.depth || 0}
                      onChange={(e) => setForm((f) => ({ ...f, depth: Number(e.target.value) }))}
                    />
                  </div>
                  <div>
                    <Label htmlFor="width">Width</Label>
                    <Input
                      id="width"
                      type="number"
                      min={1}
                      value={form.width || 0}
                      onChange={(e) => setForm((f) => ({ ...f, width: Number(e.target.value) }))}
                    />
                  </div>
                  <div className="col-span-2 flex items-center justify-between border rounded-xl p-3">
                    <div className="flex items-center gap-2">
                      <Checkbox
                        id="tag-vqe"
                        checked={(form.tags || []).includes("vqe")}
                        onCheckedChange={(v) =>
                          setForm((f) => {
                            const tags = new Set(f.tags || []);
                            v ? tags.add("vqe") : tags.delete("vqe");
                            return { ...f, tags: Array.from(tags) };
                          })
                        }
                      />
                      <Label htmlFor="tag-vqe">VQE</Label>
                    </div>
                    <div className="flex items-center gap-2">
                      <Checkbox
                        id="tag-qaoa"
                        checked={(form.tags || []).includes("qaoa")}
                        onCheckedChange={(v) =>
                          setForm((f) => {
                            const tags = new Set(f.tags || []);
                            v ? tags.add("qaoa") : tags.delete("qaoa");
                            return { ...f, tags: Array.from(tags) };
                          })
                        }
                      />
                      <Label htmlFor="tag-qaoa">QAOA</Label>
                    </div>
                    <div className="flex items-center gap-2">
                      <Checkbox
                        id="tag-benchmark"
                        checked={(form.tags || []).includes("benchmark")}
                        onCheckedChange={(v) =>
                          setForm((f) => {
                            const tags = new Set(f.tags || []);
                            v ? tags.add("benchmark") : tags.delete("benchmark");
                            return { ...f, tags: Array.from(tags) };
                          })
                        }
                      />
                      <Label htmlFor="tag-benchmark">Benchmark</Label>
                    </div>
                  </div>
                </div>
              </div>

              <DialogFooter className="gap-2">
                <Button
                  variant="outline"
                  onClick={() => setOpenNew(false)}
                >
                  Отмена
                </Button>
                <Button
                  onClick={async () => {
                    if (!formValid) return;
                    await runExperiment(form);
                    setOpenNew(false);
                  }}
                  disabled={!formValid}
                >
                  <Play className="w-4 h-4 mr-2" />
                  Запустить
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Controls */}
      <Card>
        <CardContent className="py-4">
          <div className="grid grid-cols-12 gap-3 items-end">
            <div className="col-span-12 md:col-span-4">
              <Label>QPU</Label>
              <Select
                value={filters.qpu}
                onValueChange={(v) => setFilters((f) => ({ ...f, qpu: v as Filters["qpu"] }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Любой QPU" />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="ALL">Все</SelectItem>
                    <SelectItem value="AWS_Braket">AWS Braket</SelectItem>
                    <SelectItem value="IonQ">IonQ</SelectItem>
                    <SelectItem value="Rigetti">Rigetti</SelectItem>
                    <SelectItem value="Simulator">Simulator</SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
            <div className="col-span-12 md:col-span-3">
              <Label>Статус</Label>
              <Select
                value={filters.status}
                onValueChange={(v) =>
                  setFilters((f) => ({ ...f, status: v as Filters["status"] }))
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="Любой статус" />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="ALL">Все</SelectItem>
                    <SelectItem value="queued">queued</SelectItem>
                    <SelectItem value="running">running</SelectItem>
                    <SelectItem value="completed">completed</SelectItem>
                    <SelectItem value="failed">failed</SelectItem>
                    <SelectItem value="canceled">canceled</SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
            <div className="col-span-12 md:col-span-3">
              <Label htmlFor="qlab-search">Поиск</Label>
              <div className="relative">
                <Search className="w-4 h-4 absolute left-2 top-1/2 -translate-y-1/2 opacity-60" />
                <Input
                  id="qlab-search"
                  className="pl-8"
                  placeholder="id, имя, теги"
                  value={filters.query}
                  onChange={(e) => setFilters((f) => ({ ...f, query: e.target.value }))}
                />
              </div>
            </div>
            <div className="col-span-6 md:col-span-1 flex items-center gap-2">
              <Switch
                id="mine"
                checked={filters.onlyMine}
                onCheckedChange={(v) => setFilters((f) => ({ ...f, onlyMine: !!v }))}
              />
              <Label htmlFor="mine">Мои</Label>
            </div>
            <div className="col-span-6 md:col-span-1 flex items-center gap-2">
              <Switch
                id="rt"
                checked={filters.realtime}
                onCheckedChange={(v) => setFilters((f) => ({ ...f, realtime: !!v }))}
              />
              <Label htmlFor="rt">Realtime</Label>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* KPIs */}
      <div className="grid grid-cols-12 gap-4">
        <KpiCard
          title="Подключение"
          value={state.connected ? "online" : "offline"}
          icon={state.connected ? <Wifi /> : <AlertCircle />}
          foot={
            state.latencyMs != null ? `latency ~ ${state.latencyMs} ms` : "нет данных"
          }
        />
        <KpiCard
          title="Очередь"
          value={telemetryView.at(-1)?.queue ?? 0}
          icon={<Gauge />}
          foot={`обновлено: ${state.lastHeartbeat ? fmtTime(state.lastHeartbeat) : "—"}`}
        />
        <KpiCard
          title="Ошибки"
          value={telemetryView.at(-1)?.errors ?? 0}
          icon={<AlertCircle />}
          foot="за последний интервал"
        />
        <KpiCard
          title="Успех"
          value={`${Math.round((telemetryView.at(-1)?.successRate ?? 0) * 100)} %`}
          icon={<Check />}
          foot="успешность запусков"
        />
      </div>

      {/* Graphs */}
      <div className="grid grid-cols-12 gap-4">
        <Card className="col-span-12 lg:col-span-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Flame className="w-5 h-5" />
              QPU Temperature (K)
            </CardTitle>
            <CardDescription>Тепловой профиль криостата</CardDescription>
          </CardHeader>
          <CardContent className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={telemetryView}>
                <defs>
                  <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopOpacity={0.3} />
                    <stop offset="100%" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                  dataKey="t"
                  tickFormatter={(v) => new Date(v).toLocaleTimeString()}
                />
                <YAxis />
                <RechartsTooltip
                  labelFormatter={(v) => new Date(v).toLocaleTimeString()}
                />
                <Area
                  type="monotone"
                  dataKey="qpuTempK"
                  strokeOpacity={1}
                  fill="url(#g1)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card className="col-span-12 lg:col-span-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap className="w-5 h-5" />
              Latency / Decoherence
            </CardTitle>
            <CardDescription>Задержки и времена когерентности</CardDescription>
          </CardHeader>
          <CardContent className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={telemetryView}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                  dataKey="t"
                  tickFormatter={(v) => new Date(v).toLocaleTimeString()}
                />
                <YAxis />
                <Legend />
                <RechartsTooltip
                  labelFormatter={(v) => new Date(v).toLocaleTimeString()}
                />
                <Line type="monotone" dataKey="latencyMs" dot={false} />
                <Line type="monotone" dataKey="decoherenceUs" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Experiments */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="w-5 h-5" />
            Эксперименты
          </CardTitle>
          <CardDescription>Живая таблица задач и их статусы</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>id</TableHead>
                  <TableHead>Имя</TableHead>
                  <TableHead>QPU</TableHead>
                  <TableHead>Shots</TableHead>
                  <TableHead>Параметры</TableHead>
                  <TableHead>Статус</TableHead>
                  <TableHead>Прогресс</TableHead>
                  <TableHead>Обновлено</TableHead>
                  <TableHead className="text-right">Действия</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {experiments.map((e) => (
                  <TableRow key={e.id} className="hover:bg-muted/40">
                    <TableCell className="font-mono text-xs">{e.id}</TableCell>
                    <TableCell className="font-medium">{e.name}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Server className="w-4 h-4" />
                        {e.backend}
                      </div>
                    </TableCell>
                    <TableCell>{e.shots}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      depth={e.depth}, width={e.width}
                      {e.tags?.length ? (
                        <span className="ml-2 space-x-1">
                          {e.tags.map((t) => (
                            <Badge key={t} variant="outline">
                              {t}
                            </Badge>
                          ))}
                        </span>
                      ) : null}
                    </TableCell>
                    <TableCell>{statusBadge(e.status)}</TableCell>
                    <TableCell className="w-44">
                      <div className="flex items-center gap-2">
                        <Progress value={clamp(e.progress ?? 0)} className="h-2" />
                        <span className="text-xs whitespace-nowrap">{clamp(e.progress ?? 0)}%</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-xs">{fmtTime(e.updatedAt)}</TableCell>
                    <TableCell className="text-right">
                      {e.status === "running" || e.status === "queued" ? (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => cancelExperiment(e.id)}
                        >
                          <StopCircle className="w-4 h-4 mr-1" />
                          Отмена
                        </Button>
                      ) : (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() =>
                            runExperiment({
                              name: `${e.name} (rerun)`,
                              backend: e.backend,
                              shots: e.shots,
                              depth: e.depth,
                              width: e.width,
                              tags: e.tags,
                            })
                          }
                        >
                          <Play className="w-4 h-4 mr-1" />
                          Повтор
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
              {experiments.length === 0 && (
                <TableCaption>Нет данных по текущим фильтрам</TableCaption>
              )}
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Loading placeholder if needed */}
      <Suspense fallback={loadingSkeleton}></Suspense>
    </div>
  );
}

// --------------------------------------
// KPI Card
// --------------------------------------

function KpiCard({
  title,
  value,
  foot,
  icon,
}: {
  title: string;
  value: React.ReactNode;
  foot?: React.ReactNode;
  icon?: React.ReactNode;
}) {
  return (
    <Card className="col-span-12 sm:col-span-6 lg:col-span-3">
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          {icon}
          {title}
        </CardTitle>
        <CardDescription>{foot}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold">{value}</div>
      </CardContent>
    </Card>
  );
}
