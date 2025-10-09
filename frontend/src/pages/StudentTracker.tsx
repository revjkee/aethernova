// frontend/src/pages/StudentTracker.tsx
import * as React from "react";
import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableHeader,
  TableRow,
  TableHead,
  TableBody,
  TableCell,
} from "@/components/ui/table";
import {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
} from "@/components/ui/tabs";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Tooltip,
  TooltipProvider,
  TooltipTrigger,
  TooltipContent,
} from "@/components/ui/tooltip";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/components/ui/use-toast";
import { cn } from "@/lib/utils";

import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip as RTooltip,
  CartesianGrid,
  BarChart,
  Bar,
} from "recharts";

import {
  Plus,
  Filter,
  Upload,
  Download,
  Search,
  Trash2,
  Edit,
  Eye,
  ChevronDown,
  AlertCircle,
} from "lucide-react";

import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";

// -------------------- Types & Schema --------------------

type AttendanceCell = 0 | 1; // 0 = absent, 1 = present

type ProgressPoint = {
  week: string;
  value: number; // 0..100
};

type Student = {
  id: string;
  name: string;
  group: string;
  email?: string;
  phone?: string;
  progress: number; // 0..100
  progressSeries: ProgressPoint[];
  attendance: AttendanceCell[]; // last 14 days
  tags: string[];
  active: boolean;
  updatedAt: string; // ISO
};

const formSchema = z.object({
  name: z.string().min(1, "Укажите имя"),
  group: z.string().min(1, "Укажите группу"),
  email: z.string().email("Некорректный email").optional().or(z.literal("")),
  phone: z
    .string()
    .regex(/^[\d+\-\s()]*$/, "Разрешены цифры и + - ( ) пробелы")
    .optional()
    .or(z.literal("")),
  progress: z
    .number({ invalid_type_error: "Процент должен быть числом" })
    .min(0, "Не меньше 0")
    .max(100, "Не больше 100"),
  tags: z
    .string()
    .transform((s) =>
      s
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean)
    )
    .optional()
    .or(z.literal("").transform(() => [])),
  active: z.boolean().default(true),
});

type FormValues = z.infer<typeof formSchema>;

// -------------------- Utilities --------------------

const STORAGE_KEY = "student-tracker:v1";

function uid() {
  return Math.random().toString(36).slice(2, 10);
}

function nowIso() {
  return new Date().toISOString();
}

function clamp(n: number, min: number, max: number) {
  return Math.min(Math.max(n, min), max);
}

function pctColor(p: number) {
  if (p >= 85) return "bg-emerald-500";
  if (p >= 70) return "bg-lime-500";
  if (p >= 50) return "bg-amber-500";
  return "bg-rose-500";
}

// Generate demo series for charts
function genSeries(base: number): ProgressPoint[] {
  const out: ProgressPoint[] = [];
  let v = clamp(base, 30, 95);
  for (let i = 1; i <= 12; i++) {
    v = clamp(v + (Math.random() * 14 - 7), 20, 98);
    out.push({ week: `W${i}`, value: Math.round(v) });
  }
  return out;
}

function genAttendance(n = 14): AttendanceCell[] {
  return Array.from({ length: n }, () => (Math.random() > 0.15 ? 1 : 0));
}

function loadFromStorage(): Student[] | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Student[];
    return parsed;
  } catch {
    return null;
  }
}

function saveToStorage(data: Student[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  } catch {
    // ignore
  }
}

// -------------------- Demo Seed --------------------

const SEED: Student[] = [
  {
    id: uid(),
    name: "Иван Петров",
    group: "JS-101",
    email: "ivan.petrov@example.com",
    phone: "+7 900 111-22-33",
    progress: 78,
    progressSeries: genSeries(75),
    attendance: genAttendance(),
    tags: ["frontend", "react"],
    active: true,
    updatedAt: nowIso(),
  },
  {
    id: uid(),
    name: "Анна Смирнова",
    group: "DS-202",
    email: "anna.smirnova@example.com",
    phone: "+7 921 555-66-77",
    progress: 91,
    progressSeries: genSeries(88),
    attendance: genAttendance(),
    tags: ["datascience", "python"],
    active: true,
    updatedAt: nowIso(),
  },
  {
    id: uid(),
    name: "Дмитрий Орлов",
    group: "JS-101",
    email: "d.orlov@example.com",
    phone: "",
    progress: 52,
    progressSeries: genSeries(55),
    attendance: genAttendance(),
    tags: ["frontend"],
    active: false,
    updatedAt: nowIso(),
  },
];

// -------------------- Main Page Component --------------------

type SortKey = "name" | "group" | "progress" | "updatedAt";
type SortDir = "asc" | "desc";

export default function StudentTracker() {
  const { toast } = useToast();

  const [students, setStudents] = useState<Student[]>(() => {
    return loadFromStorage() ?? SEED;
  });

  const [query, setQuery] = useState("");
  const [group, setGroup] = useState<string | "all">("all");
  const [status, setStatus] = useState<"all" | "active" | "inactive">("all");
  const [tag, setTag] = useState<string | "all">("all");

  const [sortKey, setSortKey] = useState<SortKey>("updatedAt");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const [detail, setDetail] = useState<Student | null>(null);
  const [openForm, setOpenForm] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);

  // Persist
  useEffect(() => {
    saveToStorage(students);
  }, [students]);

  // Derived filters
  const groups = useMemo(
    () => Array.from(new Set(students.map((s) => s.group))).sort(),
    [students]
  );
  const tags = useMemo(
    () => Array.from(new Set(students.flatMap((s) => s.tags))).sort(),
    [students]
  );

  const filtered = useMemo(() => {
    let data = [...students];

    if (query.trim()) {
      const q = query.toLowerCase();
      data = data.filter(
        (s) =>
          s.name.toLowerCase().includes(q) ||
          s.email?.toLowerCase().includes(q) ||
          s.group.toLowerCase().includes(q) ||
          s.tags.some((t) => t.toLowerCase().includes(q))
      );
    }

    if (group !== "all") data = data.filter((s) => s.group === group);
    if (status !== "all") {
      const active = status === "active";
      data = data.filter((s) => s.active === active);
    }
    if (tag !== "all") data = data.filter((s) => s.tags.includes(tag));

    data.sort((a, b) => {
      const dir = sortDir === "asc" ? 1 : -1;
      switch (sortKey) {
        case "name":
          return a.name.localeCompare(b.name) * dir;
        case "group":
          return a.group.localeCompare(b.group) * dir;
        case "progress":
          return (a.progress - b.progress) * dir;
        case "updatedAt":
          return (
            (new Date(a.updatedAt).getTime() - new Date(b.updatedAt).getTime()) *
            dir
          );
      }
    });

    return data;
  }, [students, query, group, status, tag, sortKey, sortDir]);

  // Selection (optional extensibility)
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const toggleSelect = (id: string) =>
    setSelected((prev) => {
      const n = new Set(prev);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });

  // CRUD Handlers
  const handleDelete = (id: string) => {
    setStudents((prev) => prev.filter((s) => s.id !== id));
    toast({ description: "Студент удален" });
    if (detail?.id === id) setDetail(null);
  };

  const handleCreate = (payload: FormValues) => {
    const s: Student = {
      id: uid(),
      name: payload.name,
      group: payload.group,
      email: payload.email || undefined,
      phone: payload.phone || undefined,
      progress: Math.round(payload.progress),
      progressSeries: genSeries(payload.progress),
      attendance: genAttendance(),
      tags: payload.tags ?? [],
      active: payload.active,
      updatedAt: nowIso(),
    };
    setStudents((prev) => [s, ...prev]);
    toast({ description: "Студент добавлен" });
  };

  const handleUpdate = (id: string, payload: FormValues) => {
    setStudents((prev) =>
      prev.map((s) =>
        s.id === id
          ? {
              ...s,
              name: payload.name,
              group: payload.group,
              email: payload.email || undefined,
              phone: payload.phone || undefined,
              progress: Math.round(payload.progress),
              progressSeries: genSeries(payload.progress),
              tags: payload.tags ?? [],
              active: payload.active,
              updatedAt: nowIso(),
            }
          : s
      )
    );
    toast({ description: "Данные обновлены" });
  };

  // Export / Import (JSON)
  const handleExport = () => {
    const blob = new Blob([JSON.stringify(students, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "students.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const fileRef = React.useRef<HTMLInputElement>(null);
  const handleImportClick = () => fileRef.current?.click();
  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const json = JSON.parse(text) as Student[];
      // minimal sanity check
      if (!Array.isArray(json)) throw new Error("Invalid format");
      setStudents(json);
      toast({ description: "Данные импортированы" });
    } catch (err) {
      toast({
        description: "Не удалось импортировать файл",
        variant: "destructive",
      });
    } finally {
      e.target.value = "";
    }
  };

  return (
    <TooltipProvider>
      <div className="p-6 md:p-8 space-y-6">
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35 }}
          className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between"
        >
          <div>
            <h1 className="text-2xl md:text-3xl font-bold tracking-tight">
              Student Tracker
            </h1>
            <p className="text-muted-foreground">
              Учет успеваемости и посещаемости, фильтры, графики и CRUD.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <Button
              onClick={() => {
                setEditId(null);
                setOpenForm(true);
              }}
            >
              <Plus className="mr-2 h-4 w-4" />
              Добавить
            </Button>

            <Input
              type="file"
              accept="application/json"
              className="hidden"
              ref={fileRef}
              onChange={handleImport}
            />
            <Button variant="outline" onClick={handleImportClick}>
              <Upload className="mr-2 h-4 w-4" />
              Импорт
            </Button>
            <Button variant="outline" onClick={handleExport}>
              <Download className="mr-2 h-4 w-4" />
              Экспорт
            </Button>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05, duration: 0.35 }}
        >
          <FiltersBar
            query={query}
            onQuery={setQuery}
            groups={groups}
            group={group}
            onGroup={setGroup}
            status={status}
            onStatus={setStatus}
            tags={tags}
            tag={tag}
            onTag={setTag}
            sortKey={sortKey}
            sortDir={sortDir}
            onSortKey={setSortKey}
            onSortDir={setSortDir}
          />
        </motion.div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1, duration: 0.35 }}
            className="xl:col-span-2"
          >
            <Card className="overflow-hidden">
              <CardHeader className="flex items-center justify-between gap-2 md:flex-row">
                <CardTitle className="text-lg md:text-xl">
                  Список студентов
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <StudentTable
                  data={filtered}
                  onOpen={(s) => setDetail(s)}
                  onEdit={(s) => {
                    setEditId(s.id);
                    setOpenForm(true);
                  }}
                  onDelete={(s) => handleDelete(s.id)}
                  selected={selected}
                  onToggleSelect={toggleSelect}
                />
              </CardContent>
            </Card>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.15, duration: 0.35 }}
            className="xl:col-span-1"
          >
            <OverviewPanel data={filtered} />
          </motion.div>
        </div>

        <StudentFormDialog
          open={openForm}
          onOpenChange={setOpenForm}
          initial={
            editId ? students.find((s) => s.id === editId) ?? null : null
          }
          onCreate={handleCreate}
          onUpdate={(payload) => {
            if (!editId) return;
            handleUpdate(editId, payload);
          }}
        />

        <StudentDetailsSheet
          student={detail}
          onOpenChange={(open) => !open && setDetail(null)}
        />
      </div>
    </TooltipProvider>
  );
}

// -------------------- Filters Bar --------------------

type FiltersProps = {
  query: string;
  onQuery: (v: string) => void;
  groups: string[];
  group: string | "all";
  onGroup: (v: string | "all") => void;
  status: "all" | "active" | "inactive";
  onStatus: (v: "all" | "active" | "inactive") => void;
  tags: string[];
  tag: string | "all";
  onTag: (v: string | "all") => void;
  sortKey: SortKey;
  sortDir: SortDir;
  onSortKey: (v: SortKey) => void;
  onSortDir: (v: SortDir) => void;
};

function FiltersBar(props: FiltersProps) {
  const {
    query,
    onQuery,
    groups,
    group,
    onGroup,
    status,
    onStatus,
    tags,
    tag,
    onTag,
    sortKey,
    sortDir,
    onSortKey,
    onSortDir,
  } = props;

  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Поиск по имени, email, тегам…"
              className="pl-9"
              value={query}
              onChange={(e) => onQuery(e.target.value)}
            />
          </div>

          <div className="flex gap-2">
            <Select
              value={group}
              onValueChange={(v) => onGroup(v as "all" | string)}
            >
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="Группа" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Все группы</SelectItem>
                {groups.map((g) => (
                  <SelectItem key={g} value={g}>
                    {g}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select
              value={status}
              onValueChange={(v) =>
                onStatus(v as "all" | "active" | "inactive")
              }
            >
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="Статус" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Все</SelectItem>
                <SelectItem value="active">Активные</SelectItem>
                <SelectItem value="inactive">Неактивные</SelectItem>
              </SelectContent>
            </Select>

            <Select
              value={tag}
              onValueChange={(v) => onTag(v as "all" | string)}
            >
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Тег" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Все теги</SelectItem>
                {tags.map((t) => (
                  <SelectItem key={t} value={t}>
                    {t}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select
              value={`${sortKey}:${sortDir}`}
              onValueChange={(v) => {
                const [k, d] = v.split(":") as [SortKey, SortDir];
                onSortKey(k);
                onSortDir(d);
              }}
            >
              <SelectTrigger className="w-[200px]">
                <div className="flex w-full items-center justify-between">
                  <span>Сортировка</span>
                  <ChevronDown className="h-4 w-4" />
                </div>
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="updatedAt:desc">Недавние (↓)</SelectItem>
                <SelectItem value="updatedAt:asc">Старые (↑)</SelectItem>
                <SelectItem value="name:asc">Имя A→Z</SelectItem>
                <SelectItem value="name:desc">Имя Z→A</SelectItem>
                <SelectItem value="group:asc">Группа A→Z</SelectItem>
                <SelectItem value="group:desc">Группа Z→A</SelectItem>
                <SelectItem value="progress:desc">Прогресс (высокий)</SelectItem>
                <SelectItem value="progress:asc">Прогресс (низкий)</SelectItem>
              </SelectContent>
            </Select>

            <Button variant="outline" className="hidden md:inline-flex">
              <Filter className="mr-2 h-4 w-4" />
              Фильтры
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// -------------------- Student Table --------------------

type StudentTableProps = {
  data: Student[];
  onOpen: (s: Student) => void;
  onEdit: (s: Student) => void;
  onDelete: (s: Student) => void;
  selected: Set<string>;
  onToggleSelect: (id: string) => void;
};

function StudentTable({
  data,
  onOpen,
  onEdit,
  onDelete,
  selected,
  onToggleSelect,
}: StudentTableProps) {
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-10"></TableHead>
            <TableHead>Студент</TableHead>
            <TableHead>Группа</TableHead>
            <TableHead>Прогресс</TableHead>
            <TableHead className="min-w-[220px]">Посещаемость (14 дн.)</TableHead>
            <TableHead>Теги</TableHead>
            <TableHead className="text-right pr-6">Действия</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.map((s) => (
            <TableRow key={s.id} className="hover:bg-muted/40">
              <TableCell>
                <input
                  aria-label="Select row"
                  type="checkbox"
                  checked={selected.has(s.id)}
                  onChange={() => onToggleSelect(s.id)}
                  className="h-4 w-4 accent-foreground"
                />
              </TableCell>
              <TableCell>
                <div className="flex flex-col">
                  <span className="font-medium">{s.name}</span>
                  <span className="text-xs text-muted-foreground">
                    {s.email || "—"}
                  </span>
                </div>
              </TableCell>
              <TableCell>
                <Badge variant="secondary">{s.group}</Badge>
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <div className="w-28 h-2 rounded-full bg-muted overflow-hidden">
                    <div
                      className={cn("h-full", pctColor(s.progress))}
                      style={{ width: `${s.progress}%` }}
                    />
                  </div>
                  <span className="text-sm tabular-nums">{s.progress}%</span>
                </div>
              </TableCell>
              <TableCell>
                <AttendanceStrip cells={s.attendance} />
              </TableCell>
              <TableCell className="max-w-[200px]">
                <div className="flex flex-wrap gap-1">
                  {s.tags.length ? (
                    s.tags.map((t) => (
                      <Badge key={t} variant="outline">
                        {t}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-xs text-muted-foreground">—</span>
                  )}
                </div>
              </TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-2">
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => onOpen(s)}
                        aria-label="Открыть детали"
                      >
                        <Eye className="h-4 w-4" />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>Детали</TooltipContent>
                  </Tooltip>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => onEdit(s)}
                        aria-label="Редактировать"
                      >
                        <Edit className="h-4 w-4" />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>Редактировать</TooltipContent>
                  </Tooltip>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => onDelete(s)}
                        aria-label="Удалить"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>Удалить</TooltipContent>
                  </Tooltip>
                </div>
              </TableCell>
            </TableRow>
          ))}
          {data.length === 0 && (
            <TableRow>
              <TableCell colSpan={7}>
                <div className="py-8 text-center text-muted-foreground">
                  Ничего не найдено. Измените фильтры или добавьте студента.
                </div>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  );
}

function AttendanceStrip({ cells }: { cells: AttendanceCell[] }) {
  return (
    <div className="flex items-center gap-1">
      {cells.map((c, i) => (
        <div
          key={i}
          className={cn(
            "h-4 w-3 rounded-sm border",
            c ? "bg-emerald-500/90 border-emerald-600" : "bg-muted border-border"
          )}
          title={c ? "Присутствовал" : "Отсутствовал"}
        />
      ))}
    </div>
  );
}

// -------------------- Overview Panel --------------------

function OverviewPanel({ data }: { data: Student[] }) {
  const total = data.length;
  const active = data.filter((s) => s.active).length;
  const avgProgress =
    total > 0
      ? Math.round(data.reduce((acc, s) => acc + s.progress, 0) / total)
      : 0;
  const attendanceRate =
    total > 0
      ? Math.round(
          (data.reduce(
            (acc, s) => acc + s.attendance.reduce((a, c) => a + c, 0),
            0
          ) /
            (data.length * data[0].attendance.length)) *
            100
        )
      : 0;

  const trendData = useMemo(() => {
    // merge average trend by week index across students (first 8 points)
    const points: { week: string; value: number }[] = [];
    for (let i = 0; i < 8; i++) {
      const vs = data.map((s) => s.progressSeries[i]?.value).filter(Boolean);
      const avg =
        vs.length > 0
          ? Math.round(vs.reduce((a, b) => a + b, 0) / vs.length)
          : 0;
      points.push({ week: `W${i + 1}`, value: avg });
    }
    return points;
  }, [data]);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Сводка</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4">
          <Kpi title="Всего" value={total} />
          <Kpi title="Активны" value={active} />
          <Kpi title="Средний прогресс" value={`${avgProgress}%`} />
          <Kpi title="Посещаемость" value={`${attendanceRate}%`} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Тренд прогресса (ср.)</CardTitle>
        </CardHeader>
        <CardContent className="h-48">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="week" />
              <YAxis domain={[0, 100]} />
              <RTooltip />
              <Line
                type="monotone"
                dataKey="value"
                dot={false}
                strokeWidth={2}
              />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Распределение по прогрессу</CardTitle>
        </CardHeader>
        <CardContent className="h-48">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={[
                {
                  label: "0–49",
                  value: data.filter((s) => s.progress < 50).length,
                },
                {
                  label: "50–69",
                  value: data.filter((s) => s.progress >= 50 && s.progress < 70)
                    .length,
                },
                {
                  label: "70–84",
                  value: data.filter((s) => s.progress >= 70 && s.progress < 85)
                    .length,
                },
                {
                  label: "85–100",
                  value: data.filter((s) => s.progress >= 85).length,
                },
              ]}
            >
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="label" />
              <YAxis allowDecimals={false} />
              <RTooltip />
              <Bar dataKey="value" />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  );
}

function Kpi({ title, value }: { title: string; value: React.ReactNode }) {
  return (
    <div className="rounded-2xl border p-4">
      <div className="text-xs text-muted-foreground">{title}</div>
      <div className="text-2xl font-semibold mt-1">{value}</div>
    </div>
  );
}

// -------------------- Details Sheet --------------------

function StudentDetailsSheet({
  student,
  onOpenChange,
}: {
  student: Student | null;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Sheet open={!!student} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-xl">
        {student && (
          <>
            <SheetHeader>
              <SheetTitle>{student.name}</SheetTitle>
            </SheetHeader>
            <div className="py-4 space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <Info label="Группа" value={student.group} />
                <Info label="Email" value={student.email || "—"} />
                <Info label="Телефон" value={student.phone || "—"} />
                <Info label="Статус" value={student.active ? "Активен" : "Неактивен"} />
                <Info
                  label="Обновлено"
                  value={new Date(student.updatedAt).toLocaleString()}
                />
              </div>

              <div>
                <Label className="mb-2 block">Теги</Label>
                <div className="flex flex-wrap gap-1">
                  {student.tags.length ? (
                    student.tags.map((t) => (
                      <Badge key={t} variant="outline">
                        {t}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-sm text-muted-foreground">—</span>
                  )}
                </div>
              </div>

              <div>
                <Label className="mb-2 block">График прогресса</Label>
                <div className="h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={student.progressSeries}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="week" />
                      <YAxis domain={[0, 100]} />
                      <RTooltip />
                      <Line
                        type="monotone"
                        dataKey="value"
                        dot={false}
                        strokeWidth={2}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div>
                <Label className="mb-2 block">Посещаемость (14 дн.)</Label>
                <AttendanceStrip cells={student.attendance} />
              </div>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

function Info({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-xl border p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-sm mt-1">{value}</div>
    </div>
  );
}

// -------------------- Create / Edit Dialog --------------------

type StudentFormDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  initial: Student | null;
  onCreate: (payload: FormValues) => void;
  onUpdate: (payload: FormValues) => void;
};

function StudentFormDialog({
  open,
  onOpenChange,
  initial,
  onCreate,
  onUpdate,
}: StudentFormDialogProps) {
  const isEdit = !!initial;

  const {
    register,
    handleSubmit,
    reset,
    setValue,
    formState: { errors, isSubmitting },
    watch,
  } = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      name: initial?.name ?? "",
      group: initial?.group ?? "",
      email: initial?.email ?? "",
      phone: initial?.phone ?? "",
      progress: initial?.progress ?? 50,
      tags: (initial?.tags ?? []).join(", "),
      active: initial?.active ?? true,
    } as any,
  });

  useEffect(() => {
    reset({
      name: initial?.name ?? "",
      group: initial?.group ?? "",
      email: initial?.email ?? "",
      phone: initial?.phone ?? "",
      progress: initial?.progress ?? 50,
      tags: (initial?.tags ?? []).join(", "),
      active: initial?.active ?? true,
    } as any);
  }, [initial, reset]);

  const onSubmit = (valuesRaw: any) => {
    // react-hook-form passes strings; coerce progress to number
    const values: FormValues = {
      ...valuesRaw,
      progress: Number(valuesRaw.progress),
    };
    if (isEdit) onUpdate(values);
    else onCreate(values);
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Редактирование" : "Новый студент"}</DialogTitle>
          <DialogDescription>
            Заполните обязательные поля. Прогресс указывается в процентах.
          </DialogDescription>
        </DialogHeader>

        <form
          className="space-y-4"
          onSubmit={handleSubmit(onSubmit)}
          autoComplete="off"
        >
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <Label>Имя</Label>
              <Input {...register("name")} placeholder="Иван Петров" />
              {errors.name && (
                <ErrorText text={errors.name.message as string} />
              )}
            </div>
            <div>
              <Label>Группа</Label>
              <Input {...register("group")} placeholder="JS-101" />
              {errors.group && (
                <ErrorText text={errors.group.message as string} />
              )}
            </div>
            <div>
              <Label>Email</Label>
              <Input {...register("email")} placeholder="name@example.com" />
              {errors.email && (
                <ErrorText text={errors.email.message as string} />
              )}
            </div>
            <div>
              <Label>Телефон</Label>
              <Input {...register("phone")} placeholder="+7 999 000-00-00" />
              {errors.phone && (
                <ErrorText text={errors.phone.message as string} />
              )}
            </div>
            <div>
              <Label>Прогресс (%)</Label>
              <Input
                type="number"
                step="1"
                min={0}
                max={100}
                {...register("progress", { valueAsNumber: true })}
              />
              {errors.progress && (
                <ErrorText text={errors.progress.message as string} />
              )}
            </div>
            <div>
              <Label>Теги (через запятую)</Label>
              <Input {...register("tags")} placeholder="react, typescript" />
            </div>
            <div className="flex items-center gap-2">
              <Switch
                checked={watch("active")}
                onCheckedChange={(v) => setValue("active", v)}
                id="active"
              />
              <Label htmlFor="active">Активен</Label>
            </div>
          </div>

          <DialogFooter className="gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              Отмена
            </Button>
            <Button type="submit" disabled={isSubmitting}>
              {isEdit ? "Сохранить" : "Добавить"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function ErrorText({ text }: { text: string }) {
  return (
    <div className="mt-1 flex items-center gap-1 text-sm text-rose-600">
      <AlertCircle className="h-3.5 w-3.5" />
      <span>{text}</span>
    </div>
  );
}
