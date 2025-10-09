// frontend/src/pages/MarketplaceAdmin.tsx
import React, { useEffect, useMemo, useRef, useState, useTransition } from "react";
import { z } from "zod";
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog";
import {
  Tabs, TabsContent, TabsList, TabsTrigger,
} from "@/components/ui/tabs";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import {
  DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/components/ui/use-toast";
import { cn } from "@/lib/utils";
import {
  CheckCircle2, CircleSlash2, Clock3, Download, Edit3, FileText, Filter, Loader2, MoreHorizontal, Package, Plus, RefreshCw, Search, Trash2, Users, Wallet, XCircle, ShieldCheck, ShieldAlert, ChevronLeft, ChevronRight, ArrowUpDown, UploadCloud, DollarSign, Store, ListOrdered, Grid3X3,
} from "lucide-react";

// ====================== Domain Types & Constants ======================
type ID = string;

type ProductStatus = "draft" | "active" | "archived";
type OrderStatus = "pending" | "paid" | "shipped" | "delivered" | "refunded" | "canceled";
type VendorStatus = "pending" | "verified" | "suspended";
type PayoutStatus = "queued" | "processing" | "done" | "failed";

type Money = { currency: "USD" | "EUR" | "RUB" | "TON"; amount: number };

type Product = {
  id: ID;
  title: string;
  sku: string;
  price: Money;
  stock: number;
  status: ProductStatus;
  vendorId: ID;
  tags: string[];
  updatedAt: string;
  createdAt: string;
};

type Order = {
  id: ID;
  productId: ID;
  vendorId: ID;
  qty: number;
  total: Money;
  status: OrderStatus;
  buyerEmail: string;
  createdAt: string;
  updatedAt: string;
};

type Vendor = {
  id: ID;
  name: string;
  email: string;
  status: VendorStatus;
  rating: number; // 0..5
  createdAt: string;
  updatedAt: string;
};

type Payout = {
  id: ID;
  vendorId: ID;
  amount: Money;
  status: PayoutStatus;
  txRef?: string;
  createdAt: string;
  updatedAt: string;
};

type AdminStats = {
  grossSales: Money;
  ordersToday: number;
  activeProducts: number;
  vendorsVerified: number;
};

// Default currency
const CUR: Money["currency"] = "USD";

// ====================== Local Persistence Adapter ======================
const LS_KEY = "marketplace_admin_seed_v1";

function uid(prefix = ""): ID {
  return `${prefix}${Math.random().toString(36).slice(2, 8)}${Date.now().toString(36).slice(-4)}`;
}

function nowISO(): string {
  return new Date().toISOString();
}

// Seed demo dataset if empty
type DB = { products: Product[]; orders: Order[]; vendors: Vendor[]; payouts: Payout[] };

function seedDB(): DB {
  const vendorA: Vendor = {
    id: uid("v_"),
    name: "Acme Studio",
    email: "ops@acme.studio",
    status: "verified",
    rating: 4.6,
    createdAt: nowISO(),
    updatedAt: nowISO(),
  };
  const vendorB: Vendor = {
    id: uid("v_"),
    name: "Nova Labs",
    email: "hello@novalabs.dev",
    status: "pending",
    rating: 4.1,
    createdAt: nowISO(),
    updatedAt: nowISO(),
  };

  const products: Product[] = [
    {
      id: uid("p_"),
      title: "Pro Keyboard",
      sku: "KEY-PRO-001",
      price: { currency: CUR, amount: 12900 },
      stock: 48,
      status: "active",
      vendorId: vendorA.id,
      tags: ["accessories", "pro"],
      createdAt: nowISO(),
      updatedAt: nowISO(),
    },
    {
      id: uid("p_"),
      title: "Ergo Chair",
      sku: "CHA-ERGO-002",
      price: { currency: CUR, amount: 34900 },
      stock: 12,
      status: "active",
      vendorId: vendorB.id,
      tags: ["furniture"],
      createdAt: nowISO(),
      updatedAt: nowISO(),
    },
    {
      id: uid("p_"),
      title: "Studio Lamp",
      sku: "LMP-STU-003",
      price: { currency: CUR, amount: 8900 },
      stock: 0,
      status: "draft",
      vendorId: vendorA.id,
      tags: ["lighting"],
      createdAt: nowISO(),
      updatedAt: nowISO(),
    },
  ];

  const orders: Order[] = [
    {
      id: uid("o_"),
      productId: products[0].id,
      vendorId: vendorA.id,
      qty: 2,
      total: { currency: CUR, amount: 25800 },
      status: "paid",
      buyerEmail: "alex@example.com",
      createdAt: nowISO(),
      updatedAt: nowISO(),
    },
    {
      id: uid("o_"),
      productId: products[1].id,
      vendorId: vendorB.id,
      qty: 1,
      total: { currency: CUR, amount: 34900 },
      status: "pending",
      buyerEmail: "kate@example.com",
      createdAt: nowISO(),
      updatedAt: nowISO(),
    },
  ];

  const payouts: Payout[] = [
    {
      id: uid("pay_"),
      vendorId: vendorA.id,
      amount: { currency: CUR, amount: 150000 },
      status: "done",
      txRef: "TX-ACME-001",
      createdAt: nowISO(),
      updatedAt: nowISO(),
    },
  ];

  return { products, orders, vendors: [vendorA, vendorB], payouts };
}

function readDB(): DB {
  const raw = localStorage.getItem(LS_KEY);
  if (!raw) {
    const seeded = seedDB();
    localStorage.setItem(LS_KEY, JSON.stringify(seeded));
    return seeded;
  }
  try {
    return JSON.parse(raw) as DB;
  } catch {
    const seeded = seedDB();
    localStorage.setItem(LS_KEY, JSON.stringify(seeded));
    return seeded;
  }
}

function writeDB(db: DB) {
  localStorage.setItem(LS_KEY, JSON.stringify(db));
}

// Simulated async adapter
const api = {
  async getStats(): Promise<AdminStats> {
    const db = readDB();
    const gross = db.orders.reduce((s, o) => s + o.total.amount, 0);
    const today = new Date().toISOString().slice(0, 10);
    const ordersToday = db.orders.filter((o) => o.createdAt.slice(0, 10) === today).length;
    const activeProducts = db.products.filter((p) => p.status === "active").length;
    const vendorsVerified = db.vendors.filter((v) => v.status === "verified").length;
    await sleep(120);
    return {
      grossSales: { currency: CUR, amount: gross },
      ordersToday,
      activeProducts,
      vendorsVerified,
    };
  },
  async listProducts(): Promise<Product[]> {
    await sleep(120);
    return readDB().products.slice().sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  },
  async upsertProduct(payload: Omit<Product, "id" | "createdAt" | "updatedAt"> & Partial<Pick<Product, "id">>): Promise<Product> {
    const db = readDB();
    let product: Product;
    if (payload.id) {
      const idx = db.products.findIndex((p) => p.id === payload.id);
      if (idx >= 0) {
        product = { ...db.products[idx], ...payload, updatedAt: nowISO() } as Product;
        db.products[idx] = product;
      } else {
        product = { ...(payload as Product), id: payload.id, createdAt: nowISO(), updatedAt: nowISO() };
        db.products.push(product);
      }
    } else {
      product = { ...(payload as Product), id: uid("p_"), createdAt: nowISO(), updatedAt: nowISO() };
      db.products.push(product);
    }
    writeDB(db);
    await sleep(120);
    return product;
  },
  async deleteProducts(ids: ID[]): Promise<void> {
    const db = readDB();
    db.products = db.products.filter((p) => !ids.includes(p.id));
    writeDB(db);
    await sleep(120);
  },
  async listOrders(): Promise<Order[]> {
    await sleep(120);
    return readDB().orders.slice().sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  },
  async updateOrderStatus(id: ID, status: OrderStatus): Promise<Order> {
    const db = readDB();
    const idx = db.orders.findIndex((o) => o.id === id);
    if (idx < 0) throw new Error("Order not found");
    db.orders[idx] = { ...db.orders[idx], status, updatedAt: nowISO() };
    writeDB(db);
    await sleep(120);
    return db.orders[idx];
  },
  async listVendors(): Promise<Vendor[]> {
    await sleep(120);
    return readDB().vendors.slice().sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  },
  async setVendorStatus(id: ID, status: VendorStatus): Promise<Vendor> {
    const db = readDB();
    const idx = db.vendors.findIndex((v) => v.id === id);
    if (idx < 0) throw new Error("Vendor not found");
    db.vendors[idx] = { ...db.vendors[idx], status, updatedAt: nowISO() };
    writeDB(db);
    await sleep(120);
    return db.vendors[idx];
  },
  async listPayouts(): Promise<Payout[]> {
    await sleep(120);
    return readDB().payouts.slice().sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  },
  async createPayout(vendorId: ID, amount: Money): Promise<Payout> {
    const db = readDB();
    const payout: Payout = {
      id: uid("pay_"),
      vendorId,
      amount,
      status: "queued",
      createdAt: nowISO(),
      updatedAt: nowISO(),
    };
    db.payouts.push(payout);
    writeDB(db);
    await sleep(120);
    return payout;
  },
};

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function formatMoney(m: Money): string {
  const base = (m.amount / 100).toFixed(2);
  switch (m.currency) {
    case "USD": return `$${base}`;
    case "EUR": return `€${base}`;
    case "RUB": return `${base} ₽`;
    case "TON": return `${base} TON`;
    default: return `${base}`;
  }
}

// ====================== Validation Schemas ======================
const productSchema = z.object({
  id: z.string().optional(),
  title: z.string().min(2, "Минимум 2 символа"),
  sku: z.string().min(2, "Минимум 2 символа"),
  price: z.coerce.number().min(0, "Цена не может быть отрицательной"),
  currency: z.enum(["USD", "EUR", "RUB", "TON"]).default(CUR),
  stock: z.coerce.number().min(0, "Склад не может быть отрицательным"),
  status: z.enum(["draft", "active", "archived"]).default("draft"),
  vendorId: z.string().min(1, "Выберите продавца"),
  tags: z.array(z.string()).optional(),
});

type ProductForm = z.infer<typeof productSchema>;

const payoutSchema = z.object({
  vendorId: z.string().min(1, "Выберите продавца"),
  amount: z.coerce.number().min(1, "Сумма должна быть > 0"),
  currency: z.enum(["USD", "EUR", "RUB", "TON"]).default(CUR),
});
type PayoutForm = z.infer<typeof payoutSchema>;

// ====================== Hooks & Utilities ======================
function useAsync<T>(fn: () => Promise<T>, deps: React.DependencyList) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  useEffect(() => {
    let mounted = true;
    setLoading(true);
    setError(null);
    fn()
      .then((res) => mounted && setData(res))
      .catch((e) => mounted && setError(e as Error))
      .finally(() => mounted && setLoading(false));
    return () => { mounted = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return { data, loading, error, reload: () => fn().then(setData) };
}

function useHotkeys(map: Record<string, (e: KeyboardEvent) => void>) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const key = [];
      if (e.ctrlKey || e.metaKey) key.push("mod");
      if (e.shiftKey) key.push("shift");
      key.push(e.key.toLowerCase());
      const combo = key.join("+");
      if (map[combo]) {
        e.preventDefault();
        map[combo](e);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [map]);
}

function paginate<T>(arr: T[], page: number, perPage: number) {
  const start = (page - 1) * perPage;
  const end = start + perPage;
  return { slice: arr.slice(start, end), total: arr.length, pages: Math.max(1, Math.ceil(arr.length / perPage)) };
}

// ====================== Main Page ======================
export default function MarketplaceAdmin() {
  const { toast } = useToast();
  const [tab, setTab] = useState<"overview" | "products" | "orders" | "vendors" | "payouts">("overview");
  const [{ data: stats, loading: loadingStats }, setStats] = [useAsync(api.getStats, [tab]), (v: AdminStats) => v];
  const [isPending, startTransition] = useTransition();

  useHotkeys({
    "mod+k": () => setTab("products"),
    "mod+o": () => setTab("orders"),
    "mod+v": () => setTab("vendors"),
    "mod+p": () => setTab("payouts"),
    "mod+g": () => setTab("overview"),
  });

  return (
    <div className="px-6 py-6 space-y-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Marketplace Admin</h1>
          <p className="text-sm text-muted-foreground">Управление товарами, заказами, продавцами и выплатами</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => window.location.reload()}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Обновить
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline">
                <MoreHorizontal className="mr-2 h-4 w-4" />
                Действия
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Экспорт</DropdownMenuLabel>
              <DropdownMenuItem onClick={() => exportJSON()}>
                <Download className="mr-2 h-4 w-4" />
                Экспортировать JSON
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => { localStorage.removeItem(LS_KEY); window.location.reload(); }}>
                <Trash2 className="mr-2 h-4 w-4" />
                Reset demo данных
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>

      <Tabs value={tab} onValueChange={(v) => setTab(v as any)}>
        <TabsList className="grid grid-cols-5 w-full sm:w-auto">
          <TabsTrigger value="overview">Обзор</TabsTrigger>
          <TabsTrigger value="products">Товары</TabsTrigger>
          <TabsTrigger value="orders">Заказы</TabsTrigger>
          <TabsTrigger value="vendors">Продавцы</TabsTrigger>
          <TabsTrigger value="payouts">Выплаты</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <StatsGrid />
        </TabsContent>

        <TabsContent value="products" className="space-y-6">
          <ProductsPanel onChange={() => startTransition(() => {
            api.getStats().then(newStats => setStats(newStats));
          })} />
        </TabsContent>

        <TabsContent value="orders" className="space-y-6">
          <OrdersPanel />
        </TabsContent>

        <TabsContent value="vendors" className="space-y-6">
          <VendorsPanel />
        </TabsContent>

        <TabsContent value="payouts" className="space-y-6">
          <PayoutsPanel />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ====================== Overview / Stats ======================
function StatCard({ title, value, icon, hint }: { title: string; value: string; icon: React.ReactNode; hint?: string }) {
  return (
    <Card className="h-full">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        {icon}
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        {hint && <p className="text-xs text-muted-foreground mt-1">{hint}</p>}
      </CardContent>
    </Card>
  );
}

function StatsGrid() {
  const { data, loading, error, reload } = useAsync(api.getStats, []);
  if (loading) return <SkeletonStats />;
  if (error) return <ErrorBlock onRetry={reload} message="Не удалось загрузить статистику" />;
  if (!data) return null;

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      <StatCard title="Валовая выручка" value={formatMoney(data.grossSales)} icon={<DollarSign className="h-4 w-4 text-muted-foreground" />} hint="Сумма оплаченных заказов" />
      <StatCard title="Заказов за сегодня" value={String(data.ordersToday)} icon={<ListOrdered className="h-4 w-4 text-muted-foreground" />} />
      <StatCard title="Активных товаров" value={String(data.activeProducts)} icon={<Package className="h-4 w-4 text-muted-foreground" />} />
      <StatCard title="Проверенных продавцов" value={String(data.vendorsVerified)} icon={<ShieldCheck className="h-4 w-4 text-muted-foreground" />} />
    </div>
  );
}

function SkeletonStats() {
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {[0, 1, 2, 3].map((i) => (
        <Card key={i}>
          <CardHeader className="pb-2">
            <div className="h-4 w-24 bg-muted rounded" />
          </CardHeader>
          <CardContent>
            <div className="h-8 w-32 bg-muted rounded" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ====================== Products Panel ======================
function ProductsPanel({ onChange }: { onChange?: () => void }) {
  const { toast } = useToast();
  const { data: vendors } = useAsync(api.listVendors, []);
  const { data, loading, error, reload } = useAsync(api.listProducts, []);
  const [selected, setSelected] = useState<Set<ID>>(new Set());
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<ProductStatus | "all">("all");
  const [sortKey, setSortKey] = useState<"updatedAt" | "price" | "stock" | "title">("updatedAt");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [view, setView] = useState<"table" | "grid">("table");
  const [page, setPage] = useState(1);
  const PER_PAGE = 10;

  useHotkeys({
    "mod+a": () => setSelected(new Set(filtered.map((p) => p.id))),
    "mod+d": () => setSelected(new Set()),
  });

  const filtered = useMemo(() => {
    const items = (data ?? []).filter((p) => {
      const q = query.trim().toLowerCase();
      const okQ = !q || [p.title, p.sku, ...p.tags].some((x) => x.toLowerCase().includes(q));
      const okS = status === "all" || p.status === status;
      return okQ && okS;
    });
    const sorted = items.sort((a, b) => {
      const dir = sortDir === "asc" ? 1 : -1;
      switch (sortKey) {
        case "price": return dir * (a.price.amount - b.price.amount);
        case "stock": return dir * (a.stock - b.stock);
        case "title": return dir * a.title.localeCompare(b.title);
        default: return dir * a.updatedAt.localeCompare(b.updatedAt);
      }
    });
    return sorted;
  }, [data, query, status, sortKey, sortDir]);

  const { slice, pages, total } = paginate(filtered, page, PER_PAGE);

  async function removeSelected() {
    const ids = Array.from(selected);
    if (ids.length === 0) return;
    const prev = data ?? [];
    try {
      // optimistic
      (data as Product[]).splice(0, (data as Product[]).length, ...(prev.filter((p) => !ids.includes(p.id))));
      await api.deleteProducts(ids);
      setSelected(new Set());
      toast({ title: "Удалено", description: `Товаров: ${ids.length}` });
      await reload();
      onChange?.();
    } catch (e: any) {
      toast({ variant: "destructive", title: "Ошибка удаления", description: e.message });
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Package className="h-4 w-4" /> Товары</CardTitle>
          <CardDescription>Поиск, фильтрация, массовые операции и управление карточками товара</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-col sm:flex-row gap-2">
            <div className="relative w-full sm:max-w-sm">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input value={query} onChange={(e) => { setPage(1); setQuery(e.target.value); }} placeholder="Поиск по названию, SKU, тегам..." className="pl-8" />
            </div>
            <Select value={status} onValueChange={(v) => { setPage(1); setStatus(v as any); }}>
              <SelectTrigger className="w-full sm:w-48">
                <SelectValue placeholder="Статус" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Все статусы</SelectItem>
                <SelectItem value="active">Активные</SelectItem>
                <SelectItem value="draft">Черновики</SelectItem>
                <SelectItem value="archived">Архив</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" onClick={() => { setSortDir(sortDir === "asc" ? "desc" : "asc"); }}>
              <ArrowUpDown className="mr-2 h-4 w-4" />
              Сортировка: {sortKey} {sortDir === "asc" ? "↑" : "↓"}
            </Button>
            <Select value={sortKey} onValueChange={(v) => setSortKey(v as any)}>
              <SelectTrigger className="w-full sm:w-48">
                <SelectValue placeholder="Поле сортировки" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="updatedAt">Обновлено</SelectItem>
                <SelectItem value="price">Цена</SelectItem>
                <SelectItem value="stock">Склад</SelectItem>
                <SelectItem value="title">Название</SelectItem>
              </SelectContent>
            </Select>
            <div className="ml-auto flex gap-2">
              <ToggleView view={view} setView={setView} />
              <CreateProductModal vendors={vendors ?? []} onSaved={async () => { await reload(); onChange?.(); }} />
              <Button variant="destructive" disabled={selected.size === 0} onClick={removeSelected}>
                <Trash2 className="mr-2 h-4 w-4" />
                Удалить выбранные ({selected.size})
              </Button>
            </div>
          </div>

          <Separator />

          {loading ? (
            <LoadingBlock />
          ) : error ? (
            <ErrorBlock onRetry={reload} message="Не удалось загрузить товары" />
          ) : view === "table" ? (
            <ProductsTable
              rows={slice}
              vendors={vendors ?? []}
              selected={selected}
              setSelected={setSelected}
              onChange={async () => { await reload(); onChange?.(); }}
            />
          ) : (
            <ProductsGrid
              rows={slice}
              vendors={vendors ?? []}
              selected={selected}
              setSelected={setSelected}
              onChange={async () => { await reload(); onChange?.(); }}
            />
          )}

          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">Найдено: {total}</p>
            <Paginator page={page} pages={pages} onPage={setPage} />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function ToggleView({ view, setView }: { view: "table" | "grid"; setView: (v: "table" | "grid") => void }) {
  return (
    <div className="inline-flex rounded-md border p-1">
      <Button variant={view === "table" ? "default" : "ghost"} size="sm" onClick={() => setView("table")}>
        <ListOrdered className="mr-2 h-4 w-4" /> Таблица
      </Button>
      <Button variant={view === "grid" ? "default" : "ghost"} size="sm" onClick={() => setView("grid")}>
        <Grid3X3 className="mr-2 h-4 w-4" /> Сетка
      </Button>
    </div>
  );
}

function ProductsTable({
  rows, vendors, selected, setSelected, onChange,
}: {
  rows: Product[];
  vendors: Vendor[];
  selected: Set<ID>;
  setSelected: (s: Set<ID>) => void;
  onChange: () => void;
}) {
  const { toast } = useToast();
  const toggle = (id: ID) => {
    const next = new Set(selected);
    next.has(id) ? next.delete(id) : next.add(id);
    setSelected(next);
  };
  const vendorName = (id: ID) => vendors.find((v) => v.id === id)?.name ?? "—";

  return (
    <div className="rounded-lg border">
      <div className="grid grid-cols-12 gap-2 px-4 py-2 text-xs text-muted-foreground">
        <div className="col-span-1">Выб.</div>
        <div className="col-span-3">Название</div>
        <div className="col-span-2">Продавец</div>
        <div className="col-span-2">Цена</div>
        <div className="col-span-1">Склад</div>
        <div className="col-span-1">Статус</div>
        <div className="col-span-2 text-right">Действия</div>
      </div>
      <Separator />
      <div className="divide-y">
        {rows.map((p) => (
          <div key={p.id} className="grid grid-cols-12 gap-2 px-4 py-3 items-center">
            <div className="col-span-1">
              <Checkbox checked={selected.has(p.id)} onCheckedChange={() => toggle(p.id)} />
            </div>
            <div className="col-span-3">
              <div className="font-medium">{p.title}</div>
              <div className="text-xs text-muted-foreground">SKU: {p.sku}</div>
            </div>
            <div className="col-span-2">{vendorName(p.vendorId)}</div>
            <div className="col-span-2">{formatMoney(p.price)}</div>
            <div className="col-span-1">{p.stock}</div>
            <div className="col-span-1">
              <Badge variant={statusBadgeVariant(p.status)}>{p.status}</Badge>
            </div>
            <div className="col-span-2 flex justify-end gap-2">
              <EditProductModal product={p} vendors={vendors} onSaved={onChange} />
              <Button
                variant={p.status !== "active" ? "default" : "outline"}
                size="sm"
                onClick={async () => {
                  const next = p.status === "active" ? "archived" : "active";
                  try {
                    await api.upsertProduct({
                      ...p,
                      status: next,
                    });
                    toast({ title: "Статус обновлен", description: `${p.title}: ${next}` });
                    onChange();
                  } catch (e: any) {
                    toast({ variant: "destructive", title: "Ошибка", description: e.message });
                  }
                }}
              >
                {p.status === "active" ? <CircleSlash2 className="mr-2 h-4 w-4" /> : <CheckCircle2 className="mr-2 h-4 w-4" />}
                {p.status === "active" ? "Деактивировать" : "Активировать"}
              </Button>
            </div>
          </div>
        ))}
        {rows.length === 0 && (
          <div className="px-4 py-8 text-center text-sm text-muted-foreground">Нет данных</div>
        )}
      </div>
    </div>
  );
}

function ProductsGrid({
  rows, vendors, selected, setSelected, onChange,
}: {
  rows: Product[];
  vendors: Vendor[];
  selected: Set<ID>;
  setSelected: (s: Set<ID>) => void;
  onChange: () => void;
}) {
  const vendorName = (id: ID) => vendors.find((v) => v.id === id)?.name ?? "—";
  const toggle = (id: ID) => {
    const next = new Set(selected);
    next.has(id) ? next.delete(id) : next.add(id);
    setSelected(next);
  };

  return (
    <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
      {rows.map((p) => (
        <Card key={p.id} className={cn("relative", selected.has(p.id) ? "ring-2 ring-primary" : "")}>
          <CardHeader className="pb-2">
            <div className="flex items-start justify-between gap-2">
              <div>
                <CardTitle className="text-base">{p.title}</CardTitle>
                <CardDescription>SKU: {p.sku}</CardDescription>
              </div>
              <Checkbox checked={selected.has(p.id)} onCheckedChange={() => toggle(p.id)} />
            </div>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Продавец</span>
              <span>{vendorName(p.vendorId)}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Цена</span>
              <span className="font-medium">{formatMoney(p.price)}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Склад</span>
              <span>{p.stock}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Статус</span>
              <Badge variant={statusBadgeVariant(p.status)}>{p.status}</Badge>
            </div>
            <div className="pt-2 flex gap-2">
              <EditProductModal product={p} vendors={vendors} onSaved={onChange} />
              <Button variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(p.id)}>
                <FileText className="mr-2 h-4 w-4" />
                ID
              </Button>
            </div>
          </CardContent>
        </Card>
      ))}
      {rows.length === 0 && (
        <div className="px-4 py-8 text-center text-sm text-muted-foreground">Нет данных</div>
      )}
    </div>
  );
}

function statusBadgeVariant(s: ProductStatus | VendorStatus | OrderStatus | PayoutStatus): "default" | "secondary" | "destructive" | "outline" {
  switch (s) {
    case "active":
    case "verified":
    case "paid":
    case "shipped":
    case "delivered":
    case "done":
      return "default";
    case "draft":
    case "pending":
    case "queued":
    case "processing":
      return "secondary";
    case "archived":
    case "suspended":
    case "canceled":
    case "failed":
    case "refunded":
      return "destructive";
    default:
      return "outline";
  }
}

function CreateProductModal({ vendors, onSaved }: { vendors: Vendor[]; onSaved: () => void }) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [formData, setFormData] = useState<ProductForm>({
    title: "",
    sku: "",
    price: 0,
    currency: CUR,
    stock: 0,
    status: "draft",
    vendorId: vendors[0]?.id ?? "",
    tags: [],
  });

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api.upsertProduct({
        title: formData.title,
        sku: formData.sku,
        price: { currency: formData.currency, amount: Math.round(formData.price * 100) },
        stock: formData.stock,
        status: formData.status,
        vendorId: formData.vendorId,
        tags: formData.tags ?? [],
        id: undefined,
      });
      toast({ title: "Товар создан" });
      setOpen(false);
      onSaved();
    } catch (e: any) {
      toast({ variant: "destructive", title: "Ошибка создания", description: e.message });
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="mr-2 h-4 w-4" />
          Новый товар
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Создать товар</DialogTitle>
          <DialogDescription>Заполните обязательные поля</DialogDescription>
        </DialogHeader>
        <form className="space-y-3" onSubmit={submit}>
          <div className="space-y-1">
            <Label>Название</Label>
            <Input value={formData.title} onChange={(e) => setFormData({...formData, title: e.target.value})} placeholder="Например, Ultra Mouse" />
          </div>
          <div className="space-y-1">
            <Label>SKU</Label>
            <Input value={formData.sku} onChange={(e) => setFormData({...formData, sku: e.target.value})} placeholder="ABC-123" />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label>Цена</Label>
              <Input type="number" step="0.01" value={formData.price} onChange={(e) => setFormData({...formData, price: parseFloat(e.target.value) || 0})} />
            </div>
            <div className="space-y-1">
              <Label>Валюта</Label>
              <Select value={formData.currency} onValueChange={(v) => setFormData({...formData, currency: v as any})}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="USD">USD</SelectItem>
                  <SelectItem value="EUR">EUR</SelectItem>
                  <SelectItem value="RUB">RUB</SelectItem>
                  <SelectItem value="TON">TON</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label>Склад</Label>
              <Input type="number" value={formData.stock} onChange={(e) => setFormData({...formData, stock: parseInt(e.target.value) || 0})} />
            </div>
            <div className="space-y-1">
              <Label>Статус</Label>
              <Select value={formData.status} onValueChange={(v) => setFormData({...formData, status: v as any})}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="draft">Черновик</SelectItem>
                  <SelectItem value="active">Активный</SelectItem>
                  <SelectItem value="archived">Архив</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="space-y-1">
            <Label>Продавец</Label>
            <Select value={formData.vendorId} onValueChange={(v) => setFormData({...formData, vendorId: v})}>
              <SelectTrigger><SelectValue placeholder="Выберите" /></SelectTrigger>
              <SelectContent>
                {vendors.map((v) => <SelectItem key={v.id} value={v.id}>{v.name}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <DialogFooter className="gap-2">
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Отмена
            </Button>
            <Button type="submit">
              <Plus className="mr-2 h-4 w-4" />
              Создать
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function EditProductModal({ product, vendors, onSaved }: { product: Product; vendors: Vendor[]; onSaved: () => void }) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [formData, setFormData] = useState<ProductForm>({
    id: product.id,
    title: product.title,
    sku: product.sku,
    price: product.price.amount / 100,
    currency: product.price.currency,
    stock: product.stock,
    status: product.status,
    vendorId: product.vendorId,
    tags: product.tags,
  });

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api.upsertProduct({
        id: product.id,
        title: formData.title,
        sku: formData.sku,
        price: { currency: formData.currency, amount: Math.round(formData.price * 100) },
        stock: formData.stock,
        status: formData.status,
        vendorId: formData.vendorId,
        tags: formData.tags ?? [],
      });
      toast({ title: "Товар обновлён" });
      setOpen(false);
      onSaved();
    } catch (e: any) {
      toast({ variant: "destructive", title: "Ошибка обновления", description: e.message });
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          <Edit3 className="mr-2 h-4 w-4" />
          Редактировать
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Редактирование товара</DialogTitle>
          <DialogDescription>ID: {product.id}</DialogDescription>
        </DialogHeader>
        <form className="space-y-3" onSubmit={submit}>
          <div className="space-y-1">
            <Label>Название</Label>
            <Input value={formData.title} onChange={(e) => setFormData({...formData, title: e.target.value})} />
          </div>
          <div className="space-y-1">
            <Label>SKU</Label>
            <Input value={formData.sku} onChange={(e) => setFormData({...formData, sku: e.target.value})} />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label>Цена</Label>
              <Input type="number" step="0.01" value={formData.price} onChange={(e) => setFormData({...formData, price: parseFloat(e.target.value) || 0})} />
            </div>
            <div className="space-y-1">
              <Label>Валюта</Label>
              <Select value={formData.currency} onValueChange={(v) => setFormData({...formData, currency: v as any})}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="USD">USD</SelectItem>
                  <SelectItem value="EUR">EUR</SelectItem>
                  <SelectItem value="RUB">RUB</SelectItem>
                  <SelectItem value="TON">TON</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label>Склад</Label>
              <Input type="number" value={formData.stock} onChange={(e) => setFormData({...formData, stock: parseInt(e.target.value) || 0})} />
            </div>
            <div className="space-y-1">
              <Label>Статус</Label>
              <Select value={formData.status} onValueChange={(v) => setFormData({...formData, status: v as any})}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="draft">Черновик</SelectItem>
                  <SelectItem value="active">Активный</SelectItem>
                  <SelectItem value="archived">Архив</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="space-y-1">
            <Label>Продавец</Label>
            <Select value={formData.vendorId} onValueChange={(v) => setFormData({...formData, vendorId: v})}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {vendors.map((v) => <SelectItem key={v.id} value={v.id}>{v.name}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <DialogFooter className="gap-2">
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>Отмена</Button>
            <Button type="submit">
              <CheckCircle2 className="mr-2 h-4 w-4" />
              Сохранить
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ====================== Orders Panel ======================
function OrdersPanel() {
  const { toast } = useToast();
  const { data: orders, loading, error, reload } = useAsync(api.listOrders, []);
  const { data: products } = useAsync(api.listProducts, []);
  const { data: vendors } = useAsync(api.listVendors, []);
  const [status, setStatus] = useState<OrderStatus | "all">("all");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const PER_PAGE = 10;

  const filtered = useMemo(() => {
    const list = (orders ?? []).filter((o) => {
      const okS = status === "all" || o.status === status;
      const q = query.trim().toLowerCase();
      const prod = products?.find((p) => p.id === o.productId);
      const ven = vendors?.find((v) => v.id === o.vendorId);
      const okQ = !q ||
        o.id.toLowerCase().includes(q) ||
        o.buyerEmail.toLowerCase().includes(q) ||
        prod?.title.toLowerCase().includes(q) ||
        ven?.name.toLowerCase().includes(q);
      return okS && okQ;
    });
    return list;
  }, [orders, products, vendors, status, query]);

  const { slice, pages, total } = paginate(filtered, page, PER_PAGE);

  async function updateStatus(id: ID, next: OrderStatus) {
    try {
      await api.updateOrderStatus(id, next);
      toast({ title: "Статус заказа обновлён", description: `${id} → ${next}` });
      await reload();
    } catch (e: any) {
      toast({ variant: "destructive", title: "Ошибка обновления", description: e.message });
    }
  }

  const productName = (id: ID) => products?.find((p) => p.id === id)?.title ?? "—";
  const vendorName = (id: ID) => vendors?.find((v) => v.id === id)?.name ?? "—";

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><FileText className="h-4 w-4" /> Заказы</CardTitle>
        <CardDescription>Управляйте статусами заказов и проверяйте детали</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-col sm:flex-row gap-2">
          <div className="relative w-full sm:max-w-sm">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input value={query} onChange={(e) => { setPage(1); setQuery(e.target.value); }} placeholder="Поиск по ID, email, товару, продавцу" className="pl-8" />
          </div>
          <Select value={status} onValueChange={(v) => { setPage(1); setStatus(v as any); }}>
            <SelectTrigger className="w-full sm:w-56">
              <SelectValue placeholder="Статус заказа" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Все</SelectItem>
              <SelectItem value="pending">Ожидает</SelectItem>
              <SelectItem value="paid">Оплачен</SelectItem>
              <SelectItem value="shipped">Отправлен</SelectItem>
              <SelectItem value="delivered">Доставлен</SelectItem>
              <SelectItem value="refunded">Возврат</SelectItem>
              <SelectItem value="canceled">Отменён</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <Separator />

        {loading ? (
          <LoadingBlock />
        ) : error ? (
          <ErrorBlock onRetry={reload} message="Не удалось загрузить заказы" />
        ) : (
          <div className="rounded-lg border">
            <div className="grid grid-cols-12 gap-2 px-4 py-2 text-xs text-muted-foreground">
              <div className="col-span-3">Заказ</div>
              <div className="col-span-3">Товар</div>
              <div className="col-span-2">Продавец</div>
              <div className="col-span-2">Сумма</div>
              <div className="col-span-2 text-right">Статус</div>
            </div>
            <Separator />
            <div className="divide-y">
              {slice.map((o) => (
                <div key={o.id} className="grid grid-cols-12 gap-2 px-4 py-3 items-center">
                  <div className="col-span-3">
                    <div className="font-medium">{o.id}</div>
                    <div className="text-xs text-muted-foreground">{o.buyerEmail}</div>
                  </div>
                  <div className="col-span-3">{productName(o.productId)}</div>
                  <div className="col-span-2">{vendorName(o.vendorId)}</div>
                  <div className="col-span-2">{formatMoney(o.total)}</div>
                  <div className="col-span-2 flex justify-end gap-2">
                    <Badge variant={statusBadgeVariant(o.status)}>{o.status}</Badge>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="outline" size="sm">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuLabel>Изменить статус</DropdownMenuLabel>
                        {(["pending", "paid", "shipped", "delivered", "refunded", "canceled"] as OrderStatus[]).map((s) => (
                          <DropdownMenuItem key={s} onClick={() => updateStatus(o.id, s)}>
                            {s}
                          </DropdownMenuItem>
                        ))}
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </div>
              ))}
              {slice.length === 0 && (
                <div className="px-4 py-8 text-center text-sm text-muted-foreground">Нет данных</div>
              )}
            </div>
          </div>
        )}

        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">Найдено: {total}</p>
          <Paginator page={page} pages={pages} onPage={setPage} />
        </div>
      </CardContent>
    </Card>
  );
}

// ====================== Vendors Panel ======================
function VendorsPanel() {
  const { toast } = useToast();
  const { data: vendors, loading, error, reload } = useAsync(api.listVendors, []);
  const [status, setStatus] = useState<VendorStatus | "all">("all");
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (vendors ?? []).filter((v) => {
      const okS = status === "all" || v.status === status;
      const okQ = !q || v.name.toLowerCase().includes(q) || v.email.toLowerCase().includes(q);
      return okS && okQ;
    });
  }, [vendors, status, query]);

  async function setVendor(v: Vendor, next: VendorStatus) {
    try {
      await api.setVendorStatus(v.id, next);
      toast({ title: "Статус продавца обновлён", description: `${v.name}: ${next}` });
      await reload();
    } catch (e: any) {
      toast({ variant: "destructive", title: "Ошибка", description: e.message });
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Store className="h-4 w-4" /> Продавцы
        </CardTitle>
        <CardDescription>Верификация и модерация продавцов</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-col sm:flex-row gap-2">
          <div className="relative w-full sm:max-w-sm">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Поиск по имени или email" className="pl-8" />
          </div>
          <Select value={status} onValueChange={(v) => setStatus(v as any)}>
            <SelectTrigger className="w-full sm:w-56">
              <SelectValue placeholder="Статус продавца" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Все</SelectItem>
              <SelectItem value="pending">Ожидает</SelectItem>
              <SelectItem value="verified">Проверен</SelectItem>
              <SelectItem value="suspended">Заблокирован</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <Separator />

        {loading ? (
          <LoadingBlock />
        ) : error ? (
          <ErrorBlock onRetry={reload} message="Не удалось загрузить продавцов" />
        ) : (
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {filtered.map((v) => (
              <Card key={v.id}>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">{v.name}</CardTitle>
                  <CardDescription>{v.email}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Рейтинг</span>
                    <span>{v.rating.toFixed(1)}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Статус</span>
                    <Badge variant={statusBadgeVariant(v.status)}>{v.status}</Badge>
                  </div>
                  <div className="flex gap-2 pt-2">
                    <Button size="sm" variant="default" onClick={() => setVendor(v, "verified")}>
                      <ShieldCheck className="mr-2 h-4 w-4" /> Верифицировать
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => setVendor(v, "suspended")}>
                      <ShieldAlert className="mr-2 h-4 w-4" /> Заблокировать
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
            {filtered.length === 0 && (
              <div className="px-4 py-8 text-center text-sm text-muted-foreground sm:col-span-2 lg:col-span-3 xl:col-span-4">Нет данных</div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ====================== Payouts Panel ======================
function PayoutsPanel() {
  const { toast } = useToast();
  const { data: payouts, loading, error, reload } = useAsync(api.listPayouts, []);
  const { data: vendors } = useAsync(api.listVendors, []);
  const [open, setOpen] = useState(false);

  const vendorName = (id: ID) => vendors?.find((v) => v.id === id)?.name ?? "—";

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><Wallet className="h-4 w-4" /> Выплаты</CardTitle>
        <CardDescription>Создание выплат продавцам и журнал операций</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex justify-end">
          <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
              <Button><Plus className="mr-2 h-4 w-4" /> Новая выплата</Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-md">
              <DialogHeader>
                <DialogTitle>Создать выплату</DialogTitle>
              </DialogHeader>
              <CreatePayoutForm
                vendors={vendors ?? []}
                onSubmit={async (values) => {
                  try {
                    await api.createPayout(values.vendorId, { currency: values.currency, amount: Math.round(values.amount * 100) });
                    toast({ title: "Выплата создана" });
                    setOpen(false);
                    await reload();
                  } catch (e: any) {
                    toast({ variant: "destructive", title: "Ошибка", description: e.message });
                  }
                }}
              />
            </DialogContent>
          </Dialog>
        </div>

        <Separator />

        {loading ? (
          <LoadingBlock />
        ) : error ? (
          <ErrorBlock onRetry={reload} message="Не удалось загрузить выплаты" />
        ) : (
          <div className="rounded-lg border overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted/50 text-muted-foreground">
                <tr>
                  <th className="text-left px-4 py-2">ID</th>
                  <th className="text-left px-4 py-2">Продавец</th>
                  <th className="text-left px-4 py-2">Сумма</th>
                  <th className="text-left px-4 py-2">Статус</th>
                  <th className="text-left px-4 py-2">TxRef</th>
                  <th className="text-right px-4 py-2">Дата</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {payouts?.map((p) => (
                  <tr key={p.id}>
                    <td className="px-4 py-2">{p.id}</td>
                    <td className="px-4 py-2">{vendorName(p.vendorId)}</td>
                    <td className="px-4 py-2">{formatMoney(p.amount)}</td>
                    <td className="px-4 py-2"><Badge variant={statusBadgeVariant(p.status)}>{p.status}</Badge></td>
                    <td className="px-4 py-2">{p.txRef ?? "—"}</td>
                    <td className="px-4 py-2 text-right">{new Date(p.createdAt).toLocaleString()}</td>
                  </tr>
                ))}
                {payouts && payouts.length === 0 && (
                  <tr><td className="px-4 py-8 text-center text-muted-foreground" colSpan={6}>Нет данных</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function CreatePayoutForm({ vendors, onSubmit }: { vendors: Vendor[]; onSubmit: (v: PayoutForm) => void }) {
  const [formData, setFormData] = useState<PayoutForm>({
    vendorId: vendors[0]?.id ?? "",
    amount: 0,
    currency: CUR,
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  return (
    <form className="space-y-3" onSubmit={handleSubmit}>
      <div className="space-y-1">
        <Label>Продавец</Label>
        <Select value={formData.vendorId} onValueChange={(v) => setFormData({...formData, vendorId: v})}>
          <SelectTrigger><SelectValue placeholder="Выберите" /></SelectTrigger>
          <SelectContent>
            {vendors.map((v) => <SelectItem key={v.id} value={v.id}>{v.name}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div className="space-y-1">
          <Label>Сумма</Label>
          <Input type="number" step="0.01" value={formData.amount} onChange={(e) => setFormData({...formData, amount: parseFloat(e.target.value) || 0})} />
        </div>
        <div className="space-y-1">
          <Label>Валюта</Label>
          <Select value={formData.currency} onValueChange={(v) => setFormData({...formData, currency: v as any})}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="USD">USD</SelectItem>
              <SelectItem value="EUR">EUR</SelectItem>
              <SelectItem value="RUB">RUB</SelectItem>
              <SelectItem value="TON">TON</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
      <DialogFooter className="gap-2">
        <Button type="submit">
          <UploadCloud className="mr-2 h-4 w-4" />
          Создать
        </Button>
      </DialogFooter>
    </form>
  );
}

// ====================== Shared UI ======================
function LoadingBlock() {
  return (
    <div className="flex items-center justify-center py-8 text-sm text-muted-foreground">
      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
      Загрузка...
    </div>
  );
}

function ErrorBlock({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex items-center justify-between rounded-md border px-4 py-3">
      <div className="flex items-center gap-2">
        <XCircle className="h-4 w-4 text-destructive" />
        <span className="text-sm">{message}</span>
      </div>
      {onRetry && <Button variant="outline" onClick={onRetry}><RefreshCw className="mr-2 h-4 w-4" /> Повторить</Button>}
    </div>
  );
}

function FormError({ msg }: { msg?: string }) {
  if (!msg) return null;
  return <p className="text-xs text-destructive">{msg}</p>;
}

function Paginator({ page, pages, onPage }: { page: number; pages: number; onPage: (p: number) => void }) {
  return (
    <div className="inline-flex items-center gap-2">
      <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>
        <ChevronLeft className="h-4 w-4" />
        Назад
      </Button>
      <span className="text-sm">Стр. {page} из {pages}</span>
      <Button variant="outline" size="sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>
        Вперед
        <ChevronRight className="h-4 w-4" />
      </Button>
    </div>
  );
}

function exportJSON() {
  const blob = new Blob([localStorage.getItem(LS_KEY) ?? "{}"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `marketplace_export_${new Date().toISOString().slice(0, 19)}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
