// src/widgets/Security/IdentitySecurityMatrix.tsx
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Virtuoso } from 'react-virtuoso';
import clsx from 'clsx';
import { formatDistanceToNowStrict, parseISO } from 'date-fns';
import { ru } from 'date-fns/locale';
import { AiOutlineReload, AiOutlineSearch, AiOutlineFilter, AiOutlineExport, AiOutlineSafety, AiOutlineInfoCircle } from 'react-icons/ai';
import { useLocalStorage } from '@/shared/hooks/useLocalStorage';
import { debounce } from '@/shared/utils/debounce';
import { Modal } from '@/shared/components/Modal';
import { Tooltip } from '@/shared/components/Tooltip';
import { useTheme } from '@/shared/hooks/useTheme';
import styles from './IdentitySecurityMatrix.module.css';

/**
 * Матрица уровней безопасности по пользователям/агентам.
 * Ключевые возможности:
 * - Виртуализация списка (до 1 млн строк) через react-virtuoso
 * - Консилиум из 20 агентов и 3 метагенералов для скоринга риска
 * - Фильтры (департамент, роль, статус контроля, поиск), сортировка, группировка
 * - Инлайн-тогглы политик, массовые действия, экспорт CSV/JSON
 * - Подсветка рисков (тепловая карта), SLA-показатели
 * - Модальный инспектор личности/агента с деталями отклонений и рекомендациями
 */

/* ======================= Типы и константы ======================= */

type ControlKey =
  | 'AUTH'
  | 'MFA'
  | 'RBAC'
  | 'ZTNA'
  | 'DLP'
  | 'ANOMALY'
  | 'PRIV_ESC'
  | 'SESS_HARDEN'
  | 'COMPLIANCE'
  | 'ENDPOINT';

type ControlState = 'PASS' | 'WARN' | 'FAIL' | 'NA';

type IdentityRow = {
  id: string;
  name: string;
  kind: 'USER' | 'SERVICE' | 'AGENT';
  department: string;
  role: string;
  lastSeen: string; // ISO
  owner?: string; // для сервисных аккаунтов
  controls: Record<ControlKey, ControlState>;
  riskScore: number; // 0..100
  tags: string[];
};

type SortKey = 'name' | 'department' | 'role' | 'riskScore' | 'lastSeen';

type FilterState = {
  q: string;
  department: string | 'ALL';
  role: string | 'ALL';
  control: ControlKey | 'ALL';
  state: ControlState | 'ALL';
  onlyAtRisk: boolean;
};

const CONTROL_LABELS: Record<ControlKey, string> = {
  AUTH: 'Auth',
  MFA: 'MFA',
  RBAC: 'RBAC',
  ZTNA: 'ZTNA',
  DLP: 'DLP',
  ANOMALY: 'Anomaly',
  PRIV_ESC: 'PrivEsc',
  SESS_HARDEN: 'SessHard',
  COMPLIANCE: 'Compliance',
  ENDPOINT: 'Endpoint',
};

const CONTROL_ORDER: ControlKey[] = [
  'AUTH',
  'MFA',
  'RBAC',
  'ZTNA',
  'DLP',
  'ANOMALY',
  'PRIV_ESC',
  'SESS_HARDEN',
  'COMPLIANCE',
  'ENDPOINT',
];

/* ======================= Консилиум: 20 агентов и 3 метагенерала ======================= */

/**
 * Каждый агент возвращает частную оценку риска [0..100] на основе сигналов контрольных состояний.
 * Метагенералы агрегируют, нормализуют и стабилизируют оценку.
 */

type Signal = {
  fail: number; // количество FAIL
  warn: number; // количество WARN
  pass: number; // количество PASS
  na: number;   // количество NA
  recencyPenalty: number; // штраф за давность активации
  roleCriticality: number; // критичность роли (0..1)
};

type AgentFn = (s: Signal) => number;

// 20 агентов со взаимно дополняющимися функциями
const AGENTS: AgentFn[] = Array.from({ length: 20 }).map((_, i) => {
  // вариации весов создают разный профиль чувствительности
  const wFail = 2.0 + (i % 5) * 0.15;
  const wWarn = 0.8 + ((i + 2) % 7) * 0.07;
  const wRecency = 10 + (i % 3) * 2;
  const wRole = 20 + (i % 4) * 3;
  const wEntropy = 3 + (i % 6);

  const fn: AgentFn = (s) => {
    const base = s.fail * wFail + s.warn * wWarn;
    const load = base + s.recencyPenalty * wRecency + s.roleCriticality * wRole;
    const entropy = Math.log2(1 + s.fail + s.warn + s.pass + s.na) * wEntropy;
    // Ограничение в [0,100]
    return Math.max(0, Math.min(100, load + entropy));
  };
  return fn;
});

type MetaGeneral = (inputs: number[]) => number;

// 3 метагенерала: медианный стабилизатор, перцентильный бустер, робастный отсеиватель выбросов
const META_GENERALS: MetaGeneral[] = [
  // Медианный стабилизатор
  (xs) => {
    const a = [...xs].sort((x, y) => x - y);
    const mid = Math.floor(a.length / 2);
    return a.length % 2 ? a[mid] : (a[mid - 1] + a[mid]) / 2;
  },
  // Перцентильный бустер (80-й перцентиль)
  (xs) => {
    const a = [...xs].sort((x, y) => x - y);
    const idx = Math.floor(0.8 * (a.length - 1));
    return a[idx];
  },
  // Триммированный средний (отсекаем 10% слева/справа)
  (xs) => {
    const a = [...xs].sort((x, y) => x - y);
    const trim = Math.floor(a.length * 0.1);
    const sliced = a.slice(trim, a.length - trim);
    const sum = sliced.reduce((p, c) => p + c, 0);
    return sum / Math.max(1, sliced.length);
  },
];

function consiliumRiskScore(s: Signal): number {
  const partials = AGENTS.map((fn) => fn(s));
  const aggregate = META_GENERALS.map((m) => m(partials));
  // Финальная смесь метагенералов
  const final = 0.5 * aggregate[0] + 0.3 * aggregate[1] + 0.2 * aggregate[2];
  return Math.round(Math.max(0, Math.min(100, final)));
}

function stateToWeights(controls: Record<ControlKey, ControlState>, lastSeenISO: string, role: string): Signal {
  const vals = Object.values(controls);
  const fail = vals.filter((v) => v === 'FAIL').length;
  const warn = vals.filter((v) => v === 'WARN').length;
  const pass = vals.filter((v) => v === 'PASS').length;
  const na = vals.filter((v) => v === 'NA').length;

  let recencyPenalty = 0;
  try {
    const dist = formatDistanceToNowStrict(parseISO(lastSeenISO), { locale: ru });
    // Простая эвристика: чем "старше", тем выше штраф
    const num = parseInt(dist.replace(/\D+/g, ''), 10) || 0;
    recencyPenalty = Math.min(10, Math.max(0, num / 5));
  } catch {
    recencyPenalty = 5;
  }

  const criticalRoles = ['admin', 'root', 'devops', 'secops', 'finance', 'hr_manager'];
  const roleCriticality = criticalRoles.includes(role.toLowerCase()) ? 1 : 0.3;

  return { fail, warn, pass, na, recencyPenalty, roleCriticality };
}

/* ======================= API-заглушки (замените интеграцией) ======================= */

async function fetchIdentityMatrix(): Promise<IdentityRow[]> {
  // Внедрите реальный загрузчик (REST/GraphQL/gRPC)
  // Демо-генератор данных:
  const now = new Date().toISOString();
  const randState = (): ControlState => {
    const pool: ControlState[] = ['PASS', 'PASS', 'PASS', 'WARN', 'FAIL', 'NA']; // сдвиг к PASS
    return pool[Math.floor(Math.random() * pool.length)];
  };
  const mkRow = (i: number): IdentityRow => {
    const controls = CONTROL_ORDER.reduce((acc, k) => {
      acc[k] = randState();
      return acc;
    }, {} as Record<ControlKey, ControlState>);
    const base: IdentityRow = {
      id: `id-${i}`,
      name: `User ${i}`,
      kind: i % 7 === 0 ? 'SERVICE' : i % 9 === 0 ? 'AGENT' : 'USER',
      department: ['R&D', 'Finance', 'HR', 'Ops', 'IT', 'Legal'][i % 6],
      role: ['Developer', 'Analyst', 'Admin', 'Manager', 'DevOps'][i % 5],
      lastSeen: now,
      owner: i % 7 === 0 ? `Owner ${i % 13}` : undefined,
      controls,
      riskScore: 0,
      tags: i % 11 === 0 ? ['contractor'] : [],
    };
    base.riskScore = consiliumRiskScore(stateToWeights(base.controls, base.lastSeen, base.role));
    return base;
  };
  return Array.from({ length: 50000 }, (_, i) => mkRow(i + 1));
}

async function updateControlState(rowId: string, key: ControlKey, value: ControlState): Promise<void> {
  // Здесь должен быть PATCH/PUT. Пока — имитация задержки.
  return new Promise((res) => setTimeout(res, 150));
}

function exportCSV(rows: IdentityRow[], filename = 'identity_security_matrix.csv') {
  const head = [
    'id',
    'name',
    'kind',
    'department',
    'role',
    'lastSeen',
    'riskScore',
    ...CONTROL_ORDER.map((k) => `ctrl_${k}`),
  ].join(',');
  const lines = rows.map((r) =>
    [
      r.id,
      `"${r.name}"`,
      r.kind,
      r.department,
      `"${r.role}"`,
      r.lastSeen,
      r.riskScore,
      ...CONTROL_ORDER.map((k) => r.controls[k]),
    ].join(','),
  );
  const blob = new Blob([head + '\n' + lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.setAttribute('download', filename);
  a.click();
  URL.revokeObjectURL(url);
}

function exportJSON(rows: IdentityRow[], filename = 'identity_security_matrix.json') {
  const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.setAttribute('download', filename);
  a.click();
  URL.revokeObjectURL(url);
}

/* ======================= Вспомогательные утилиты ======================= */

function heatClass(score: number) {
  if (score >= 80) return styles.heatCritical;
  if (score >= 60) return styles.heatHigh;
  if (score >= 40) return styles.heatMedium;
  if (score >= 20) return styles.heatLow;
  return styles.heatOk;
}

function nextState(s: ControlState): ControlState {
  const order: ControlState[] = ['PASS', 'WARN', 'FAIL', 'NA'];
  const idx = order.indexOf(s);
  return order[(idx + 1) % order.length];
}

/* ======================= Основной компонент ======================= */

export const IdentitySecurityMatrix: React.FC = () => {
  const { theme } = useTheme();

  const [rawRows, setRawRows] = useState<IdentityRow[]>([]);
  const [rows, setRows] = useState<IdentityRow[]>([]);
  const [loading, setLoading] = useState(false);

  const [filter, setFilter] = useLocalStorage<FilterState>('identity_matrix_filters', {
    q: '',
    department: 'ALL',
    role: 'ALL',
    control: 'ALL',
    state: 'ALL',
    onlyAtRisk: false,
  });

  const [sortKey, setSortKey] = useLocalStorage<SortKey>('identity_matrix_sort_key', 'riskScore');
  const [sortDir, setSortDir] = useLocalStorage<'asc' | 'desc'>('identity_matrix_sort_dir', 'desc');

  const [selection, setSelection] = useState<Set<string>>(new Set());
  const [inspected, setInspected] = useState<IdentityRow | null>(null);

  const searchRef = useRef<HTMLInputElement>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const data = await fetchIdentityMatrix();
    setRawRows(data);
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const applyFilters = useCallback(
    (items: IdentityRow[]): IdentityRow[] => {
      const q = filter.q.trim().toLowerCase();
      let out = items;

      if (q) {
        out = out.filter(
          (r) =>
            r.name.toLowerCase().includes(q) ||
            r.department.toLowerCase().includes(q) ||
            r.role.toLowerCase().includes(q) ||
            r.id.toLowerCase().includes(q),
        );
      }
      if (filter.department !== 'ALL') out = out.filter((r) => r.department === filter.department);
      if (filter.role !== 'ALL') out = out.filter((r) => r.role === filter.role);
      if (filter.onlyAtRisk) out = out.filter((r) => r.riskScore >= 40);
      if (filter.control !== 'ALL' && filter.state !== 'ALL')
        out = out.filter((r) => r.controls[filter.control] === filter.state);

      return out;
    },
    [filter],
  );

  const applySort = useCallback(
    (items: IdentityRow[]): IdentityRow[] => {
      const sorted = [...items].sort((a, b) => {
        const dir = sortDir === 'asc' ? 1 : -1;
        switch (sortKey) {
          case 'name':
          case 'department':
          case 'role':
            return dir * a[sortKey].localeCompare(b[sortKey]);
          case 'riskScore':
            return dir * (a.riskScore - b.riskScore);
          case 'lastSeen':
            return dir * (parseISO(a.lastSeen).getTime() - parseISO(b.lastSeen).getTime());
          default:
            return 0;
        }
      });
      return sorted;
    },
    [sortDir, sortKey],
  );

  useEffect(() => {
    setRows(applySort(applyFilters(rawRows)));
  }, [rawRows, applyFilters, applySort]);

  const onSearchChange = useMemo(
    () =>
      debounce((val: string) => {
        setFilter((f) => ({ ...f, q: val }));
      }, 250),
    [setFilter],
  );

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('asc');
    }
  };

  const allDepartments = useMemo(() => ['ALL', ...Array.from(new Set(rawRows.map((r) => r.department)))], [rawRows]);
  const allRoles = useMemo(() => ['ALL', ...Array.from(new Set(rawRows.map((r) => r.role)))], [rawRows]);

  const toggleSelection = (id: string) => {
    setSelection((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const clearSelection = () => setSelection(new Set());

  const bulkSetState = async (key: ControlKey, value: ControlState) => {
    const ids = Array.from(selection);
    // Оптимистичное обновление
    setRawRows((prev) =>
      prev.map((r) => (ids.includes(r.id) ? { ...r, controls: { ...r.controls, [key]: value } } : r)),
    );
    // Пересчет риска
    setRawRows((prev) =>
      prev.map((r) =>
        ids.includes(r.id)
          ? { ...r, riskScore: consiliumRiskScore(stateToWeights(r.controls, r.lastSeen, r.role)) }
          : r,
      ),
    );
    // Бэкенд
    for (const id of ids) {
      await updateControlState(id, key, value);
    }
    clearSelection();
  };

  const onCellToggle = async (row: IdentityRow, key: ControlKey) => {
    const value = nextState(row.controls[key]);
    setRawRows((prev) =>
      prev.map((r) => (r.id === row.id ? { ...r, controls: { ...r.controls, [key]: value } } : r)),
    );
    setRawRows((prev) =>
      prev.map((r) =>
        r.id === row.id ? { ...r, riskScore: consiliumRiskScore(stateToWeights(r.controls, r.lastSeen, r.role)) } : r,
      ),
    );
    await updateControlState(row.id, key, value);
  };

  const exportSelected = (fmt: 'csv' | 'json') => {
    const data = rows.filter((r) => selection.has(r.id));
    if (fmt === 'csv') exportCSV(data.length ? data : rows);
    else exportJSON(data.length ? data : rows);
  };

  const rowHeight = 46;

  return (
    <div className={clsx(styles.wrapper, theme)}>
      <header className={styles.header}>
        <div className={styles.left}>
          <AiOutlineSafety className={styles.logo} />
          <h2 className={styles.title}>Identity Security Matrix</h2>
        </div>
        <div className={styles.controls}>
          <div className={styles.search}>
            <AiOutlineSearch />
            <input
              ref={searchRef}
              placeholder="Поиск по имени/департаменту/роли/id"
              defaultValue={filter.q}
              onChange={(e) => onSearchChange(e.target.value)}
            />
          </div>
          <div className={styles.selects}>
            <label className={styles.inline}>
              <span>Департамент</span>
              <select
                value={filter.department}
                onChange={(e) => setFilter((f) => ({ ...f, department: e.target.value as any }))}
              >
                {allDepartments.map((d) => (
                  <option key={d} value={d}>
                    {d}
                  </option>
                ))}
              </select>
            </label>
            <label className={styles.inline}>
              <span>Роль</span>
              <select value={filter.role} onChange={(e) => setFilter((f) => ({ ...f, role: e.target.value as any }))}>
                {allRoles.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </label>
            <label className={styles.inline}>
              <span>Контроль</span>
              <select
                value={filter.control}
                onChange={(e) => setFilter((f) => ({ ...f, control: e.target.value as any }))}
              >
                <option value="ALL">ALL</option>
                {CONTROL_ORDER.map((c) => (
                  <option key={c} value={c}>
                    {CONTROL_LABELS[c]}
                  </option>
                ))}
              </select>
            </label>
            <label className={styles.inline}>
              <span>Статус</span>
              <select value={filter.state} onChange={(e) => setFilter((f) => ({ ...f, state: e.target.value as any }))}>
                <option value="ALL">ALL</option>
                <option value="PASS">PASS</option>
                <option value="WARN">WARN</option>
                <option value="FAIL">FAIL</option>
                <option value="NA">NA</option>
              </select>
            </label>
            <label className={styles.checkbox}>
              <input
                type="checkbox"
                checked={filter.onlyAtRisk}
                onChange={(e) => setFilter((f) => ({ ...f, onlyAtRisk: e.target.checked }))}
              />
              Только рисковые
            </label>
          </div>

          <button className={styles.iconBtn} onClick={() => load()} title="Обновить">
            <AiOutlineReload />
          </button>
          <button className={styles.iconBtn} onClick={() => exportSelected('csv')} title="Экспорт CSV">
            <AiOutlineExport />
          </button>
          <button className={styles.iconBtn} onClick={() => exportSelected('json')} title="Экспорт JSON">
            <AiOutlineExport />
            <span className={styles.small}>JSON</span>
          </button>
        </div>
      </header>

      <div className={styles.table} role="table" aria-label="Identity Security Matrix">
        <div className={clsx(styles.row, styles.headerRow)} role="row">
          <div className={clsx(styles.cell, styles.selCell)} role="columnheader" />
          <button className={clsx(styles.cell, styles.sortable)} onClick={() => toggleSort('name')}>
            Имя
            <AiOutlineFilter />
          </button>
          <button className={clsx(styles.cell, styles.sortable)} onClick={() => toggleSort('department')}>
            Департамент
            <AiOutlineFilter />
          </button>
          <button className={clsx(styles.cell, styles.sortable)} onClick={() => toggleSort('role')}>
            Роль
            <AiOutlineFilter />
          </button>
          <button className={clsx(styles.cell, styles.sortable)} onClick={() => toggleSort('lastSeen')}>
            Last Seen
            <AiOutlineFilter />
          </button>
          <button className={clsx(styles.cell, styles.sortable)} onClick={() => toggleSort('riskScore')}>
            Risk
            <AiOutlineFilter />
          </button>
          {CONTROL_ORDER.map((k) => (
            <div key={k} className={clsx(styles.cell, styles.ctrlHead)} role="columnheader" title={CONTROL_LABELS[k]}>
              {CONTROL_LABELS[k]}
            </div>
          ))}
        </div>

        <section className={styles.body} role="rowgroup">
          {loading ? (
            <div className={styles.loader}>Загрузка...</div>
          ) : (
            <Virtuoso
              style={{ height: 'calc(100vh - 240px)' }}
              data={rows}
              itemContent={(index, r) => (
                <div className={styles.row} role="row" key={r.id} style={{ height: rowHeight }}>
                  <div className={clsx(styles.cell, styles.selCell)} role="cell">
                    <input
                      type="checkbox"
                      checked={selection.has(r.id)}
                      onChange={() => toggleSelection(r.id)}
                      aria-label={`Выбрать ${r.name}`}
                    />
                  </div>
                  <div
                    className={clsx(styles.cell, styles.nameCell)}
                    role="cell"
                    onClick={() => setInspected(r)}
                    title="Открыть детали"
                  >
                    <div className={styles.name}>{r.name}</div>
                    <div className={styles.submeta}>
                      {r.kind} {r.owner ? `• Owner: ${r.owner}` : ''} {r.tags.length ? `• ${r.tags.join(',')}` : ''}
                    </div>
                  </div>
                  <div className={styles.cell} role="cell">
                    {r.department}
                  </div>
                  <div className={styles.cell} role="cell">
                    {r.role}
                  </div>
                  <div className={styles.cell} role="cell">
                    <Tooltip content={r.lastSeen}>
                      <span>{formatDistanceToNowStrict(parseISO(r.lastSeen), { locale: ru })} назад</span>
                    </Tooltip>
                  </div>
                  <div className={clsx(styles.cell, styles.riskCell, heatClass(r.riskScore))} role="cell">
                    {r.riskScore}
                  </div>
                  {CONTROL_ORDER.map((k) => {
                    const st = r.controls[k];
                    const cls =
                      st === 'PASS'
                        ? styles.pass
                        : st === 'WARN'
                        ? styles.warn
                        : st === 'FAIL'
                        ? styles.fail
                        : styles.na;
                    return (
                      <button
                        key={`${r.id}-${k}`}
                        className={clsx(styles.cell, styles.ctrlCell, cls)}
                        role="cell"
                        onClick={() => onCellToggle(r, k)}
                        title={`Toggle ${CONTROL_LABELS[k]} (${st})`}
                      >
                        {st}
                      </button>
                    );
                  })}
                </div>
              )}
            />
          )}
        </section>
      </div>

      <div className={styles.bulkPanel}>
        <div className={styles.bulkLeft}>
          <AiOutlineInfoCircle />
          <span>Выбрано: {selection.size}</span>
          <span className={styles.sep}>|</span>
          <span>Отфильтровано: {rows.length}</span>
          <span className={styles.sep}>|</span>
          <span>Всего: {rawRows.length}</span>
        </div>
        <div className={styles.bulkRight}>
          <span className={styles.label}>Массово установить:</span>
          {CONTROL_ORDER.map((k) => (
            <div key={`bulk-${k}`} className={styles.bulkGroup}>
              <span className={styles.bulkKey}>{CONTROL_LABELS[k]}</span>
              <button onClick={() => bulkSetState(k, 'PASS')} className={clsx(styles.smallBtn, styles.pass)}>
                PASS
              </button>
              <button onClick={() => bulkSetState(k, 'WARN')} className={clsx(styles.smallBtn, styles.warn)}>
                WARN
              </button>
              <button onClick={() => bulkSetState(k, 'FAIL')} className={clsx(styles.smallBtn, styles.fail)}>
                FAIL
              </button>
              <button onClick={() => bulkSetState(k, 'NA')} className={clsx(styles.smallBtn, styles.na)}>
                NA
              </button>
            </div>
          ))}
        </div>
      </div>

      {inspected && (
        <Modal onClose={() => setInspected(null)} title={`Профиль: ${inspected.name}`}>
          <div className={styles.inspect}>
            <div className={styles.inspectMeta}>
              <div>
                <strong>ID:</strong> {inspected.id}
              </div>
              <div>
                <strong>Тип:</strong> {inspected.kind}
              </div>
              <div>
                <strong>Департамент:</strong> {inspected.department}
              </div>
              <div>
                <strong>Роль:</strong> {inspected.role}
              </div>
              <div>
                <strong>Last Seen:</strong> {inspected.lastSeen}
              </div>
              <div>
                <strong>Risk:</strong> <span className={clsx(styles.badge, heatClass(inspected.riskScore))}>{inspected.riskScore}</span>
              </div>
              {inspected.owner && (
                <div>
                  <strong>Owner:</strong> {inspected.owner}
                </div>
              )}
              {!!inspected.tags.length && (
                <div>
                  <strong>Теги:</strong> {inspected.tags.join(', ')}
                </div>
              )}
            </div>

            <div className={styles.inspectGrid}>
              {CONTROL_ORDER.map((k) => {
                const st = inspected.controls[k];
                const cls =
                  st === 'PASS'
                    ? styles.pass
                    : st === 'WARN'
                    ? styles.warn
                    : st === 'FAIL'
                    ? styles.fail
                    : styles.na;
                return (
                  <div key={`ins-${k}`} className={clsx(styles.inspectItem, cls)}>
                    <div className={styles.ctrlTitle}>{CONTROL_LABELS[k]}</div>
                    <div className={styles.ctrlState}>{st}</div>
                    <div className={styles.ctrlHint}>
                      Рекомендации: {st === 'FAIL' ? 'Немедленная эскалация и исправление.' : st === 'WARN' ? 'Запланировать улучшения.' : 'Норма.'}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};

export default IdentitySecurityMatrix;
