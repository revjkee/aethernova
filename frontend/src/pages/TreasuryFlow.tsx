import React, { useEffect, useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Cell,
} from "recharts";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import {
  ArrowDownRight,
  ArrowUpRight,
  CalendarRange,
  Download,
  Filter,
  Loader2,
  RefreshCw,
  Search,
  Shield,
  Wallet,
} from "lucide-react";

// ----------------------------------------------
// Types
// ----------------------------------------------

type ChainId = "ETH" | "BSC" | "TON" | "SOL" | "POL";
type FlowType = "inflow" | "outflow";

type Tx = {
  id: string;
  ts: number; // epoch ms
  chain: ChainId;
  token: string; // symbol
  amount: number; // positive numeric
  type: FlowType;
  counterparty: string;
  hash: string;
  memo?: string;
};

type DailyAgg = {
  date: string; // yyyy-MM-dd
  inflow: number;
  outflow: number;
  pnl: number; // inflow - outflow
};

// ----------------------------------------------
// Mocked data provider (replace with real fetch)
// ----------------------------------------------

const TOKENS = ["USDT", "USDC", "ETH", "TON", "BTC"] as const;
const CHAINS: ChainId[] = ["ETH", "BSC", "TON", "SOL", "POL"];

function random(seed: number) {
  let x = Math.sin(seed) * 10000;
  return x - Math.floor(x);
}

function generateMockTxs(count = 420): Tx[] {
  const start = Date.now() - 1000 * 60 * 60 * 24 * 120; // 120d
  return Array.from({ length: count }).map((_, i) => {
    const ts = start + i * 1000 * 60 * 60 * (0.5 + random(i) * 6);
    const chain = CHAINS[Math.floor(random(i + 1) * CHAINS.length)];
    const token = TOKENS[Math.floor(random(i + 2) * TOKENS.length)];
    const type: FlowType = random(i + 3) > 0.48 ? "inflow" : "outflow";
    const magnitude = Math.floor(random(i + 4) * 10_000) / 100;
    const counterparty = `ctr_${Math.floor(random(i + 5) * 200).toString().padStart(3, "0")}`;
    return {
      id: `tx_${i.toString().padStart(6, "0")}`,
      ts,
      chain,
      token,
      type,
      amount: magnitude === 0 ? 10 : magnitude,
      counterparty,
      hash: `0x${Math.floor(random(i + 6) * 1e16).toString(16).padEnd(16, "a")}`,
      memo: random(i + 7) > 0.85 ? "Ops payout" : undefined,
    };
  });
}

async function fetchTreasuryData(signal?: AbortSignal): Promise<Tx[]> {
  // Simulate latency and support cancellation
  await new Promise((r) => setTimeout(r, 450));
  if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
  return generateMockTxs();
}

// ----------------------------------------------
// Helpers
// ----------------------------------------------

// Simple date formatting function to replace date-fns
function formatDate(timestamp: number, formatStr: string): string {
  const date = new Date(timestamp);
  
  if (formatStr === "yyyy-MM-dd") {
    return date.toISOString().split('T')[0];
  }
  
  if (formatStr === "HH:mm:ss") {
    return date.toTimeString().split(' ')[0];
  }
  
  if (formatStr === "yyyy-MM-dd HH:mm:ss") {
    return date.toISOString().replace('T', ' ').split('.')[0];
  }
  
  // Fallback
  return date.toISOString();
}

function toDateKey(ts: number) {
  return formatDate(ts, "yyyy-MM-dd");
}

function sum(arr: number[]) {
  return arr.reduce((a, b) => a + b, 0);
}

function downloadCsv(filename: string, rows: string[][]) {
  const csv = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function paginate<T>(items: T[], page: number, size: number) {
  const start = (page - 1) * size;
  return items.slice(start, start + size);
}

// Palette without hardcoding specific colors for charts (let Recharts choose)
const PIE_SLICE_COUNT = 8;

// ----------------------------------------------
// Filters & State
// ----------------------------------------------

type Filters = {
  chain: ChainId | "ALL";
  token: string | "ALL";
  flow: FlowType | "ALL";
  range: "7D" | "30D" | "90D" | "ALL";
  query: string;
};

const DEFAULT_FILTERS: Filters = {
  chain: "ALL",
  token: "ALL",
  flow: "ALL",
  range: "30D",
  query: "",
};

// ----------------------------------------------
// TreasuryFlow Page
// ----------------------------------------------

const useAbortable = () => {
  const ctrl = useRef<AbortController | null>(null);
  useEffect(() => () => ctrl.current?.abort(), []);
  return () => {
    ctrl.current?.abort();
    ctrl.current = new AbortController();
    return ctrl.current.signal;
  };
};

const numberFmt = new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 });

export default function TreasuryFlow() {
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [allTx, setAllTx] = useState<Tx[]>([]);

  const [page, setPage] = useState(1);
  const pageSize = 12;

  const nextSignal = useAbortable();

  const reload = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchTreasuryData(nextSignal());
      setAllTx(data);
    } catch (e: any) {
      if (e?.name !== "AbortError") setError(e?.message ?? "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Derived
  const now = Date.now();
  const minTs = useMemo(() => {
    switch (filters.range) {
      case "7D":
        return now - 1000 * 60 * 60 * 24 * 7;
      case "30D":
        return now - 1000 * 60 * 60 * 24 * 30;
      case "90D":
        return now - 1000 * 60 * 60 * 24 * 90;
      default:
        return 0;
    }
  }, [filters.range, now]);

  const filteredTx = useMemo(() => {
    const q = filters.query.trim().toLowerCase();
    return allTx
      .filter((t) => t.ts >= minTs)
      .filter((t) => (filters.chain === "ALL" ? true : t.chain === filters.chain))
      .filter((t) => (filters.token === "ALL" ? true : t.token === filters.token))
      .filter((t) => (filters.flow === "ALL" ? true : t.type === filters.flow))
      .filter((t) =>
        q
          ? t.counterparty.toLowerCase().includes(q) ||
            t.token.toLowerCase().includes(q) ||
            t.hash.toLowerCase().includes(q)
          : true
      )
      .sort((a, b) => b.ts - a.ts);
  }, [allTx, filters, minTs]);

  useEffect(() => setPage(1), [filters]);

  const totals = useMemo(() => {
    const inflow = sum(filteredTx.filter((t) => t.type === "inflow").map((t) => t.amount));
    const outflow = sum(filteredTx.filter((t) => t.type === "outflow").map((t) => t.amount));
    const pnl = inflow - outflow;
    const balance = sum(
      TOKENS.map((sym) =>
        sum(
          filteredTx
            .filter((t) => t.token === sym)
            .map((t) => (t.type === "inflow" ? t.amount : -t.amount))
        )
      )
    );
    return { inflow, outflow, pnl, balance };
  }, [filteredTx]);

  const dailyAgg: DailyAgg[] = useMemo(() => {
    const map = new Map<string, { inflow: number; outflow: number }>();
    for (const t of filteredTx) {
      const key = toDateKey(t.ts);
      const prev = map.get(key) ?? { inflow: 0, outflow: 0 };
      if (t.type === "inflow") prev.inflow += t.amount;
      else prev.outflow += t.amount;
      map.set(key, prev);
    }
    const arr = Array.from(map.entries())
      .map(([date, { inflow, outflow }]) => ({ date, inflow, outflow, pnl: inflow - outflow }))
      .sort((a, b) => a.date.localeCompare(b.date));
    return arr;
  }, [filteredTx]);

  const tokenSplit = useMemo(() => {
    const map = new Map<string, number>();
    for (const t of filteredTx) {
      const prev = map.get(t.token) ?? 0;
      map.set(t.token, prev + (t.type === "inflow" ? t.amount : -t.amount));
    }
    const arr = Array.from(map.entries()).map(([name, value]) => ({ name, value: Math.max(value, 0.0001) }));
    return arr;
  }, [filteredTx]);

  const chainBar = useMemo(() => {
    const map = new Map<ChainId, { inflow: number; outflow: number }>();
    for (const c of CHAINS) map.set(c, { inflow: 0, outflow: 0 });
    for (const t of filteredTx) {
      const row = map.get(t.chain)!;
      if (t.type === "inflow") row.inflow += t.amount;
      else row.outflow += t.amount;
    }
    return CHAINS.map((c) => ({ chain: c, ...map.get(c)! }));
  }, [filteredTx]);

  const paged = useMemo(() => paginate(filteredTx, page, pageSize), [filteredTx, page]);

  const exportCsv = () => {
    const header = ["id", "timestamp", "date", "chain", "token", "type", "amount", "counterparty", "hash", "memo"];
    const rows = filteredTx.map((t) => [
      t.id,
      String(t.ts),
      formatDate(t.ts, "yyyy-MM-dd HH:mm:ss"),
      t.chain,
      t.token,
      t.type,
      String(t.amount),
      t.counterparty,
      t.hash,
      t.memo ?? "",
    ]);
    downloadCsv("treasury_flow.csv", [header, ...rows]);
  };

  const empty = !loading && filteredTx.length === 0;

  return (
    <div className="p-6 md:p-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-semibold tracking-tight">Treasury Flow</h1>
          <p className="text-sm text-muted-foreground">Мониторинг потоков казначейства: входящие, исходящие, PnL и распределение активов</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={reload} aria-label="Обновить">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            <span className="ml-2 hidden sm:inline">Обновить</span>
          </Button>
          <Button onClick={exportCsv} aria-label="Экспорт CSV">
            <Download className="h-4 w-4" />
            <span className="ml-2 hidden sm:inline">Экспорт CSV</span>
          </Button>
        </div>
      </div>

      {/* Filters */}
      <Card className="border-border/60">
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Фильтры</CardTitle>
          <CardDescription>Отфильтруйте данные по сети, токену, периоду и типу потока</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            <Select
              value={filters.chain}
              onValueChange={(v) => setFilters((f) => ({ ...f, chain: v as Filters["chain"] }))}
            >
              <SelectTrigger aria-label="Сеть">
                <SelectValue placeholder="Сеть" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ALL">Все сети</SelectItem>
                {CHAINS.map((c) => (
                  <SelectItem key={c} value={c}>
                    {c}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select
              value={filters.token}
              onValueChange={(v) => setFilters((f) => ({ ...f, token: v as Filters["token"] }))}
            >
              <SelectTrigger aria-label="Токен">
                <SelectValue placeholder="Токен" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ALL">Все токены</SelectItem>
                {TOKENS.map((t) => (
                  <SelectItem key={t} value={t}>
                    {t}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select
              value={filters.flow}
              onValueChange={(v) => setFilters((f) => ({ ...f, flow: v as Filters["flow"] }))}
            >
              <SelectTrigger aria-label="Тип потока">
                <SelectValue placeholder="Тип потока" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ALL">In/Out</SelectItem>
                <SelectItem value="inflow">Inflow</SelectItem>
                <SelectItem value="outflow">Outflow</SelectItem>
              </SelectContent>
            </Select>

            <Select
              value={filters.range}
              onValueChange={(v) => setFilters((f) => ({ ...f, range: v as Filters["range"] }))}
            >
              <SelectTrigger aria-label="Период">
                <CalendarRange className="mr-2 h-4 w-4" />
                <SelectValue placeholder="Период" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="7D">7 дней</SelectItem>
                <SelectItem value="30D">30 дней</SelectItem>
                <SelectItem value="90D">90 дней</SelectItem>
                <SelectItem value="ALL">Всё время</SelectItem>
              </SelectContent>
            </Select>

            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  value={filters.query}
                  onChange={(e) => setFilters((f) => ({ ...f, query: e.target.value }))}
                  placeholder="Поиск: контрагент / хеш / токен"
                  aria-label="Поиск"
                  className="pl-8"
                />
              </div>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline">
                    <Filter className="h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56">
                  <DropdownMenuLabel>Быстрые фильтры</DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuCheckboxItem
                    checked={filters.flow === "inflow"}
                    onCheckedChange={(v) => setFilters((f) => ({ ...f, flow: v ? "inflow" : "ALL" }))}
                  >
                    Только inflow
                  </DropdownMenuCheckboxItem>
                  <DropdownMenuCheckboxItem
                    checked={filters.flow === "outflow"}
                    onCheckedChange={(v) => setFilters((f) => ({ ...f, flow: v ? "outflow" : "ALL" }))}
                  >
                    Только outflow
                  </DropdownMenuCheckboxItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* KPI */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <KpiCard
          title="Inflow"
          icon={<ArrowDownRight className="h-4 w-4" />}
          value={`$${numberFmt.format(totals.inflow)}`}
          help="Сумма входящих за период"
        />
        <KpiCard
          title="Outflow"
          icon={<ArrowUpRight className="h-4 w-4" />}
          value={`$${numberFmt.format(totals.outflow)}`}
          help="Сумма исходящих за период"
        />
        <KpiCard
          title="PnL"
          icon={<Shield className="h-4 w-4" />}
          value={`${totals.pnl >= 0 ? "+" : ""}$${numberFmt.format(totals.pnl)}`}
          help="Inflow − Outflow"
          trend={totals.pnl >= 0 ? "up" : "down"}
        />
        <KpiCard
          title="Net Balance"
          icon={<Wallet className="h-4 w-4" />}
          value={`$${numberFmt.format(totals.balance)}`}
          help="Суммарный чистый баланс по фильтрам"
        />
      </div>

      {/* Charts */}
      <Tabs defaultValue="pnl" className="space-y-4">
        <TabsList className="w-full md:w-auto">
          <TabsTrigger value="pnl">Дневной PnL</TabsTrigger>
          <TabsTrigger value="io">Inflow/Outflow по сетям</TabsTrigger>
          <TabsTrigger value="split">Распределение по токенам</TabsTrigger>
        </TabsList>
        <TabsContent value="pnl">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Дневной PnL</CardTitle>
              <CardDescription>PnL по дням за выбранный период</CardDescription>
            </CardHeader>
            <CardContent className="h-72">
              {loading ? (
                <Skeleton className="h-full w-full" />
              ) : (
                <ResponsiveContainer>
                  <AreaChart data={dailyAgg} margin={{ left: 8, right: 8, top: 8, bottom: 8 }}>
                    <defs>
                      <linearGradient id="pnl" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopOpacity={0.4} />
                        <stop offset="95%" stopOpacity={0.05} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" tickLine={false} minTickGap={24} />
                    <YAxis tickLine={false} width={60} />
                    <Tooltip formatter={(v: any) => `$${numberFmt.format(v)}`} />
                    <Area type="monotone" dataKey="pnl" fill="url(#pnl)" fillOpacity={1} strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="io">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Inflow / Outflow по сетям</CardTitle>
              <CardDescription>Сравнение объёмов по блокчейнам</CardDescription>
            </CardHeader>
            <CardContent className="h-72">
              {loading ? (
                <Skeleton className="h-full w-full" />
              ) : (
                <ResponsiveContainer>
                  <BarChart data={chainBar} margin={{ left: 8, right: 8, top: 8, bottom: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="chain" tickLine={false} />
                    <YAxis tickLine={false} width={60} />
                    <Tooltip formatter={(v: any) => `$${numberFmt.format(v)}`} />
                    <Legend />
                    <Bar dataKey="inflow" stackId="a" />
                    <Bar dataKey="outflow" stackId="a" />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="split">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Распределение по токенам</CardTitle>
              <CardDescription>Чистая позиция по каждому активу</CardDescription>
            </CardHeader>
            <CardContent className="h-72">
              {loading ? (
                <Skeleton className="h-full w-full" />
              ) : (
                <ResponsiveContainer>
                  <PieChart>
                    <Tooltip formatter={(v: any) => `$${numberFmt.format(v)}`} />
                    <Pie data={tokenSplit} dataKey="value" nameKey="name" outerRadius={110}>
                      {tokenSplit.slice(0, PIE_SLICE_COUNT).map((_, i) => (
                        <Cell key={`cell-${i}`} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Table */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base">Транзакции</CardTitle>
              <CardDescription>
                Найдено: <span className="font-medium">{filteredTx.length}</span>
              </CardDescription>
            </div>
            {empty && (
              <Badge variant="secondary">Нет данных по выбранным фильтрам</Badge>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <TxTableSkeleton />
          ) : empty ? (
            <EmptyState />
          ) : (
            <div className="w-full overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[120px]">Дата</TableHead>
                    <TableHead>Сеть</TableHead>
                    <TableHead>Токен</TableHead>
                    <TableHead>Тип</TableHead>
                    <TableHead className="text-right">Сумма</TableHead>
                    <TableHead>Контрагент</TableHead>
                    <TableHead>Хеш</TableHead>
                    <TableHead>Метка</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {paged.map((t) => (
                    <motion.tr
                      key={t.id}
                      initial={{ opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.2 }}
                      className={cn("[&>td]:py-3 border-b", t.type === "inflow" ? "bg-emerald-50/20" : "bg-rose-50/10")}
                    >
                      <TableCell>
                        <div className="flex flex-col">
                          <span className="font-medium">{formatDate(t.ts, "yyyy-MM-dd")}</span>
                          <span className="text-xs text-muted-foreground">{formatDate(t.ts, "HH:mm:ss")}</span>
                        </div>
                      </TableCell>
                      <TableCell>{t.chain}</TableCell>
                      <TableCell>{t.token}</TableCell>
                      <TableCell>
                        <Badge variant={t.type === "inflow" ? "default" : "destructive"}>
                          {t.type}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right font-medium">${numberFmt.format(t.amount)}</TableCell>
                      <TableCell>{t.counterparty}</TableCell>
                      <TableCell>
                        <code className="text-xs">{t.hash.slice(0, 10)}…</code>
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate">{t.memo ?? ""}</TableCell>
                    </motion.tr>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}

          {/* Pagination */}
          {!loading && !empty && (
            <div className="flex items-center justify-between mt-4">
              <div className="text-sm text-muted-foreground">
                Страница {page} из {Math.max(1, Math.ceil(filteredTx.length / pageSize))}
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  Назад
                </Button>
                <Button
                  variant="outline"
                  disabled={page >= Math.ceil(filteredTx.length / pageSize)}
                  onClick={() => setPage((p) => Math.min(Math.ceil(filteredTx.length / pageSize), p + 1))}
                >
                  Вперед
                </Button>
              </div>
            </div>
          )}

          {/* Error state */}
          {error && (
            <div className="mt-4 p-3 rounded-md bg-destructive/10 text-destructive text-sm">
              Ошибка загрузки: {error}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ----------------------------------------------
// Subcomponents
// ----------------------------------------------

type KpiProps = {
  title: string;
  value: string;
  icon?: React.ReactNode;
  help?: string;
  trend?: "up" | "down";
};

function KpiCard({ title, value, icon, help, trend }: KpiProps) {
  return (
    <motion.div initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}>
      <Card className="h-full">
        <CardHeader className="pb-2 flex flex-row items-center justify-between space-y-0">
          <CardTitle className="text-sm font-medium">{title}</CardTitle>
          {icon}
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{value}</div>
          {help && (
            <p className="text-xs text-muted-foreground mt-1">
              {help}
            </p>
          )}
          {trend && (
            <p className={cn("text-xs mt-1", trend === "up" ? "text-emerald-600" : "text-rose-600")}>{
              trend === "up" ? "Положительная динамика" : "Отрицательная динамика"
            }</p>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}

function TxTableSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 6 }).map((_, i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
    </div>
  );
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      <div className="mb-2 text-lg font-medium">Данных нет</div>
      <p className="text-sm text-muted-foreground max-w-md">
        Попробуйте изменить фильтры, период или строку поиска — сейчас под выбранные условия транзакции не найдены.
      </p>
    </div>
  );
}
