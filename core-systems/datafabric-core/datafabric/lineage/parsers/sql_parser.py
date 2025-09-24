# -*- coding: utf-8 -*-
"""
DataFabric | lineage | parsers | sql_parser.py

Промышленный модуль извлечения lineage из SQL:
- Поддержка SELECT / INSERT [INTO] ... SELECT / CREATE TABLE ... AS SELECT / MERGE (частично)
- CTE (WITH ... AS (...)), подзапросы, алиасы, UNION/UNION ALL, JOIN (ON/USING)
- Колонночная родословная: expr -> target_column с трассировкой до исходных столбцов
- Нормализация имён (catalog.schema.table, schema.table, table), кавычки, диалекты
- Графовое представление lineage (узлы/рёбра) и сериализация в dict/NDJSON
- Опциональная зависимость: sqlglot (рекомендуется). Fallback без зависимостей.
- Безопасный разбор нескольких стейтментов; устойчивость к пробелам/комментариям.

Совместимо с Python 3.10+.
"""

from __future__ import annotations

import dataclasses
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple, Union

# ------------------------------------------------------------
# Опциональная интеграция с sqlglot (если установлена)
# ------------------------------------------------------------
_SQLGLOT_AVAILABLE = False
try:
    import sqlglot
    from sqlglot import exp
    _SQLGLOT_AVAILABLE = True
except Exception:  # pragma: no cover - отсутствие зависимости не критично
    _SQLGLOT_AVAILABLE = False


# ------------------------------------------------------------
# Модели графа lineage
# ------------------------------------------------------------

@dataclass(frozen=True)
class ObjRef:
    catalog: Optional[str]
    schema: Optional[str]
    name: str
    alias: Optional[str] = None

    def fqn(self) -> str:
        parts = [p for p in [self.catalog, self.schema, self.name] if p]
        return ".".join(parts) if parts else self.name

    def key(self) -> str:
        return self.fqn()

    @staticmethod
    def from_parts(parts: List[str], alias: Optional[str] = None) -> "ObjRef":
        # parts может быть ["catalog","schema","table"] | ["schema","table"] | ["table"]
        if len(parts) >= 3:
            return ObjRef(parts[-3], parts[-2], parts[-1], alias)
        if len(parts) == 2:
            return ObjRef(None, parts[0], parts[1], alias)
        return ObjRef(None, None, parts[0], alias)


@dataclass(frozen=True)
class ColumnRef:
    table_key: Optional[str]  # fqn источника либо None (скаляр/функция)
    column: str

    def key(self) -> str:
        return f"{self.table_key}.{self.column}" if self.table_key else self.column


@dataclass(frozen=True)
class LineageEdge:
    source: ColumnRef
    target: ColumnRef
    kind: str = "projection"  # projection, join_key, predicate, merge, unknown
    expr: Optional[str] = None


@dataclass
class LineageGraph:
    nodes: Set[str] = field(default_factory=set)  # ключи таблиц (FQN)
    edges: List[LineageEdge] = field(default_factory=list)
    sources: Set[str] = field(default_factory=set)  # входные таблицы
    targets: Set[str] = field(default_factory=set)  # выходные таблицы

    def add_node(self, fqn: str) -> None:
        self.nodes.add(fqn)

    def add_edge(self, edge: LineageEdge) -> None:
        self.edges.append(edge)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": sorted(self.nodes),
            "sources": sorted(self.sources),
            "targets": sorted(self.targets),
            "edges": [
                {
                    "source": {"table": e.source.table_key, "column": e.source.column},
                    "target": {"table": e.target.table_key, "column": e.target.column},
                    "kind": e.kind,
                    "expr": e.expr,
                }
                for e in self.edges
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))


# ------------------------------------------------------------
# Результат разбора
# ------------------------------------------------------------

@dataclass(frozen=True)
class StatementLineage:
    statement_index: int
    sql: str
    graph: LineageGraph


@dataclass
class ParseResult:
    statements: List[StatementLineage]

    def combined_graph(self) -> LineageGraph:
        g = LineageGraph()
        for s in self.statements:
            g.nodes.update(s.graph.nodes)
            g.sources.update(s.graph.sources)
            g.targets.update(s.graph.targets)
            g.edges.extend(s.graph.edges)
        return g

    def to_json(self) -> str:
        return json.dumps(
            {
                "statements": [
                    {
                        "index": s.statement_index,
                        "graph": s.graph.to_dict(),
                    }
                    for s in self.statements
                ],
                "combined": self.combined_graph().to_dict(),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )


# ------------------------------------------------------------
# Помощники нормализации
# ------------------------------------------------------------

_IDENT_RE = re.compile(r'(?:"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|([A-Za-z_][A-Za-z0-9_$]*))')

def _split_identifiers(ident: str) -> List[str]:
    """
    Делит идентификатор catalog.schema.table с учётом кавычек.
    Простая, но надёжная версия для fallback.
    """
    parts: List[str] = []
    for m in _IDENT_RE.finditer(ident):
        val = next(g for g in m.groups() if g is not None)
        parts.append(val)
    if not parts:
        # последний шанс — грубый split
        parts = [p for p in re.split(r"\s*\.\s*", ident.strip()) if p]
    return parts

def _strip_sql_comments(sql: str) -> str:
    sql = re.sub(r"--[^\n]*", "", sql)
    sql = re.sub(r"/\*.*?\*/", "", sql, flags=re.S)
    return sql


# ------------------------------------------------------------
# Fallback-парсер (без зависимостей)
# Ограничения: поддерживает SELECT/INSERT...SELECT/CTE/CREATE TABLE AS SELECT/UNION ALL
# ------------------------------------------------------------

class _FallbackParser:
    _WITH_RE = re.compile(r"^\s*WITH\s", re.I | re.S)
    _INSERT_RE = re.compile(r"^\s*INSERT\s+(?:INTO\s+)?(?P<target>[^\s(]+)", re.I | re.S)
    _CREATE_AS_RE = re.compile(r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMP|TEMPORARY\s+)?TABLE\s+(?P<target>[^\s(]+)\s+AS\s+(?P<select>SELECT\b.*)$", re.I | re.S)
    _SELECT_RE = re.compile(r"\bSELECT\b", re.I)
    _FROM_RE = re.compile(r"\bFROM\b", re.I)
    _JOIN_RE = re.compile(r"\bJOIN\b\s+(?P<table>[^\s,(]+)", re.I)
    _UNION_SPLIT_RE = re.compile(r"\bUNION(?:\s+ALL)?\b", re.I)
    _CTE_RE = re.compile(r"^\s*WITH\s+(?P<ctes>.+?)\bSELECT\b", re.I | re.S)

    def parse(self, sql: str, stmt_index: int) -> StatementLineage:
        s = _strip_sql_comments(sql).strip().rstrip(";").strip()
        graph = LineageGraph()

        # CREATE TABLE ... AS SELECT ...
        m_create = self._CREATE_AS_RE.match(s)
        if m_create:
            target = m_create.group("target").strip()
            select_sql = m_create.group("select")
            target_ref = ObjRef.from_parts(_split_identifiers(target))
            graph.targets.add(target_ref.key())
            graph.add_node(target_ref.key())
            self._extract_from_select(select_sql, graph, target_ref)
            return StatementLineage(stmt_index, sql, graph)

        # INSERT INTO target ... SELECT ...
        m_ins = self._INSERT_RE.match(s)
        if m_ins and self._SELECT_RE.search(s):
            target = m_ins.group("target").strip()
            target_ref = ObjRef.from_parts(_split_identifiers(target))
            graph.targets.add(target_ref.key())
            graph.add_node(target_ref.key())
            # Берём часть после последнего SELECT
            select_sql = s[s.upper().rfind("SELECT") :]
            self._extract_from_select(select_sql, graph, target_ref)
            return StatementLineage(stmt_index, sql, graph)

        # Просто SELECT (возможно, CTE)
        self._extract_from_select(s, graph, None)
        return StatementLineage(stmt_index, sql, graph)

    def _extract_from_select(self, select_sql: str, graph: LineageGraph, target: Optional[ObjRef]) -> None:
        # Обработка CTE: WITH a AS ( ... ), b AS ( ... ) SELECT ...
        cte_map: Dict[str, str] = {}
        m_cte = self._CTE_RE.match(select_sql)
        body = select_sql
        if m_cte:
            ctes_blob = m_cte.group("ctes")
            # Грубый парсинг пар "name AS ( ... )"
            for name, body_sql in self._parse_ctes(ctes_blob):
                cte_map[name.lower()] = body_sql
            body = select_sql[select_sql.upper().rfind("SELECT") :]

        # Разбивка по UNION (каждую ветку разбираем отдельно)
        branches = self._UNION_SPLIT_RE.split(body)
        for branch in branches:
            self._extract_branch(branch.strip(), graph, target, cte_map)

    def _parse_ctes(self, ctes_blob: str) -> List[Tuple[str, str]]:
        items: List[Tuple[str, str]] = []
        depth = 0
        name = ""
        buf = []
        i = 0
        mode = "name"
        while i < len(ctes_blob):
            ch = ctes_blob[i]
            if mode == "name":
                if ch == "A" or ch == "a":
                    # ищем "AS("
                    j = ctes_blob.find("AS", i)
                    if j != -1:
                        name = ctes_blob[:j].strip().split(",")[-1].strip()
                        i = j + 2
                        mode = "body_wait"
                        continue
                i += 1
            elif mode == "body_wait":
                # ждём '('
                if ch == "(":
                    depth = 1
                    buf = []
                    mode = "body"
                i += 1
            elif mode == "body":
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        sql = "".join(buf).strip()
                        items.append((name, sql))
                        # обрезаем то, что прошло, и продолжаем поиск следующего CTE
                        rest = ctes_blob[i + 1 :]
                        # Рекурсивное извлечение оставшегося
                        items.extend(self._parse_ctes(rest))
                        return items
                buf.append(ch)
                i += 1
        return items

    def _extract_branch(
        self,
        select_branch_sql: str,
        graph: LineageGraph,
        target: Optional[ObjRef],
        cte_map: Mapping[str, str],
    ) -> None:
        # FROM таблица/CTE
        from_pos = self._FROM_RE.search(select_branch_sql)
        if not from_pos:
            return
        after_from = select_branch_sql[from_pos.end() :]

        # Список источников: первый FROM + JOIN
        first_src = after_from.split()[0].rstrip(",")
        sources: List[ObjRef] = []
        src_ref = self._resolve_source(first_src, cte_map)
        if src_ref:
            sources.append(src_ref)

        for m in self._JOIN_RE.finditer(after_from):
            t = m.group("table").strip().rstrip(",")
            ref = self._resolve_source(t, cte_map)
            if ref:
                sources.append(ref)

        for s in sources:
            # CTE считаем виртуальной таблицей, добавляем как node
            graph.add_node(s.key())
            graph.sources.add(s.key())

        # Грубое извлечение проекций: всё между SELECT и FROM
        proj_sql = select_branch_sql[: from_pos.start()]
        projections = self._split_projections(proj_sql)
        # Проставляем рёбра (каждая проекция → целевая колонка либо анонимная)
        for expr_text, out_alias in projections:
            # Пытаемся найти "table.column" ссылки
            for tkey, col in self._find_column_refs(expr_text, sources):
                src = ColumnRef(table_key=tkey, column=col)
                tgt = ColumnRef(table_key=target.key() if target else None, column=out_alias or expr_text.strip())
                graph.add_edge(LineageEdge(source=src, target=tgt, kind="projection", expr=expr_text.strip()))

    def _resolve_source(self, token: str, cte_map: Mapping[str, str]) -> Optional[ObjRef]:
        # Учитываем алиас: "schema.table AS t" | "schema.table t"
        tok = token
        # Удаляем возможные скобки/запятые
        tok = tok.strip().strip(",").strip()
        # Если это CTE
        base = tok.split()  # [name, alias?]
        name = base[0]
        alias = base[1] if len(base) > 1 and base[1].upper() != "AS" else (base[2] if len(base) > 2 else None)
        if name.lower() in cte_map:
            return ObjRef(None, None, name, alias=alias or name)
        # Иначе — таблица
        return ObjRef.from_parts(_split_identifiers(name), alias=alias)

    def _split_projections(self, proj_sql: str) -> List[Tuple[str, Optional[str]]]:
        # Упрощённое разбиение по запятым на верхнем уровне
        items: List[Tuple[str, Optional[str]]] = []
        depth = 0
        token = []
        for ch in proj_sql.strip()[len("SELECT") :]:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
            if ch == "," and depth == 0:
                items.append("".join(token).strip())
                token = []
            else:
                token.append(ch)
        if token:
            items.append("".join(token).strip())
        out: List[Tuple[str, Optional[str]]] = []
        for it in items:
            # expr [AS] alias
            m = re.match(r"(?P<expr>.+?)\s+(?:AS\s+)?(?P<alias>[A-Za-z_][A-Za-z0-9_$]*)$", it, flags=re.I)
            if m:
                out.append((m.group("expr").strip(), m.group("alias")))
            else:
                out.append((it, None))
        return out

    def _find_column_refs(self, expr_text: str, sources: List[ObjRef]) -> List[Tuple[Optional[str], str]]:
        """
        Возвращает пары (table_key|None, column) обнаруженные в выражении.
        Простейшее извлечение ссылок вида t.col или col (если единственный source).
        """
        refs: List[Tuple[Optional[str], str]] = []
        # t.col
        for m in re.finditer(r"(?:(?P<t>[A-Za-z_][A-Za-z0-9_$]*)\.)?(?P<c>[A-Za-z_][A-Za-z0-9_$]*)", expr_text):
            t, c = m.group("t"), m.group("c")
            if t:  # алиас или имя таблицы
                tkey = None
                for s in sources:
                    if (s.alias and s.alias == t) or s.name == t or s.fqn().endswith("." + t):
                        tkey = s.key()
                        break
                if tkey:
                    refs.append((tkey, c))
            else:
                # без таблицы: если ровно один источник — считаем его
                if len(sources) == 1:
                    refs.append((sources[0].key(), c))
        return refs


# ------------------------------------------------------------
# AST-парсер на базе sqlglot (если доступен)
# ------------------------------------------------------------

class _SqlglotParser:
    def __init__(self, dialect: Optional[str] = None):
        self.dialect = dialect

    def parse(self, sql: str, stmt_index: int) -> StatementLineage:
        graph = LineageGraph()
        # sqlglot.parse может вернуть список экспрессий (несколько стейтментов)
        trees = sqlglot.parse(sql, read=self.dialect)  # type: ignore[arg-type]
        if not trees:
            return StatementLineage(stmt_index, sql, graph)

        # Мы обрабатываем только соответствующее выражение (stmt_index), т.к. верхний уровень orchestration уже разбил на стейтменты
        tree = trees[0]
        self._extract_from_expr(tree, graph, current_target=None, cte_scope={})
        return StatementLineage(stmt_index, sql, graph)

    # Рекурсивный обход AST
    def _extract_from_expr(self, node: "exp.Expression", graph: LineageGraph, current_target: Optional[ObjRef], cte_scope: Dict[str, "exp.Expression"]) -> None:
        if isinstance(node, exp.Create):
            # CREATE TABLE AS SELECT
            target = self._object_ref(node)
            if target:
                graph.targets.add(target.key())
                graph.add_node(target.key())
            if node.this and isinstance(node.this, exp.Subqueryable):
                self._extract_from_expr(node.this, graph, current_target=target, cte_scope=cte_scope)
            return

        if isinstance(node, exp.Insert):
            target = self._object_ref(node.this) if node.this is not None else None
            if target:
                graph.targets.add(target.key())
                graph.add_node(target.key())
            if node.expression:
                self._extract_from_expr(node.expression, graph, current_target=target, cte_scope=cte_scope)
            return

        if isinstance(node, exp.With):
            # Регистрируем CTE
            scope = dict(cte_scope)
            for cte in node.expressions:
                name = cte.alias if isinstance(cte, exp.CTE) else cte.name
                name = name or ""
                scope[name.lower()] = cte.this
            self._extract_from_expr(node.this, graph, current_target=current_target, cte_scope=scope)
            return

        if isinstance(node, exp.Select) or isinstance(node, exp.Union):
            # Обрабатываем ветви UNION/SELECT
            if isinstance(node, exp.Union):
                self._extract_from_expr(node.left, graph, current_target, cte_scope)
                self._extract_from_expr(node.right, graph, current_target, cte_scope)
                return

            # FROM/JOIN источники
            sources: List[ObjRef] = []
            for src in self._iter_sources(node, cte_scope):
                graph.add_node(src.key())
                graph.sources.add(src.key())
                sources.append(src)

            # Проекции
            for proj in node.expressions or []:
                expr_str = proj.sql()
                target_col = (proj.alias or proj.name or expr_str).strip()
                for sref, col in self._iter_column_refs(proj, sources):
                    src = ColumnRef(table_key=sref.key() if sref else None, column=col)
                    tgt = ColumnRef(table_key=current_target.key() if current_target else None, column=target_col)
                    graph.add_edge(LineageEdge(source=src, target=tgt, kind="projection", expr=expr_str))
            return

        if isinstance(node, exp.Merge):
            # Частичная поддержка MERGE: источники/цели и join keys
            target = self._object_ref(node.this)
            source = self._object_ref(node.using)
            if target:
                graph.targets.add(target.key())
                graph.add_node(target.key())
            if source:
                graph.sources.add(source.key())
                graph.add_node(source.key())
            # JOIN condition → join_key edges
            if node.on:
                for sref, col in self._iter_column_refs(node.on, [r for r in [target, source] if r]):
                    src = ColumnRef(table_key=sref.key() if sref else None, column=col)
                    tgt = ColumnRef(table_key=target.key() if target else None, column=col)
                    graph.add_edge(LineageEdge(source=src, target=tgt, kind="join_key", expr=node.on.sql()))
            # WHEN MATCHED/NOT MATCHED — опустим для краткости, добавляется через projections при UPDATE/INSERT частях
            return

        # По умолчанию — спуск к потомкам
        for child in node.args.values():
            if isinstance(child, exp.Expression):
                self._extract_from_expr(child, graph, current_target, cte_scope)
            elif isinstance(child, list):
                for c in child:
                    if isinstance(c, exp.Expression):
                        self._extract_from_expr(c, graph, current_target, cte_scope)

    def _iter_sources(self, select_node: "exp.Select", cte_scope: Mapping[str, "exp.Expression"]) -> Iterable[ObjRef]:
        # FROM
        if select_node.from_:
            for src in select_node.from_.expressions:
                ref = self._resolve_source(src, cte_scope)
                if ref:
                    yield ref
        # JOIN
        for j in select_node.find_all(exp.Join):
            ref = self._resolve_source(j.this, cte_scope)
            if ref:
                yield ref

    def _resolve_source(self, node: "exp.Expression", cte_scope: Mapping[str, "exp.Expression"]) -> Optional[ObjRef]:
        if isinstance(node, exp.Subquery):
            # Подзапрос с алиасом — представим как виртуальную таблицу
            alias = (node.alias or "").strip() or "subq"
            return ObjRef(None, None, alias, alias=alias)
        if isinstance(node, exp.Table):
            parts = [p.name for p in node.find_all(exp.Identifier)]
            alias = (node.alias or "").strip() or None
            name_l = node.name.lower() if node.name else ""
            if name_l in cte_scope:
                return ObjRef(None, None, name_l, alias=alias or name_l)
            return ObjRef.from_parts(parts or [node.name], alias=alias)
        return None

    def _iter_column_refs(self, node: "exp.Expression", sources: List[ObjRef]) -> Iterable[Tuple[Optional[ObjRef], str]]:
        # Перебор Identifier/Column в выражении
        for col in node.find_all(exp.Column):
            tab = col.table
            col_name = col.name
            if tab:
                # Пытаемся сопоставить алиас
                for s in sources:
                    if s.alias == tab or s.name == tab or s.fqn().endswith("." + tab):
                        yield s, col_name
                        break
            else:
                if len(sources) == 1:
                    yield sources[0], col_name
                else:
                    # Неоднозначная колонка без таблицы — оставим без table_key
                    yield None, col_name

    def _object_ref(self, node: Optional["exp.Expression"]) -> Optional[ObjRef]:
        if not node:
            return None
        if isinstance(node, exp.Table):
            parts = [p.name for p in node.find_all(exp.Identifier)] or [node.name]
            return ObjRef.from_parts(parts)
        if isinstance(node, exp.Expression):
            # CREATE TABLE <ident> в sqlglot — иногда как exp.Schema / exp.Table
            t = node.find(exp.Table)
            if t:
                parts = [p.name for p in t.find_all(exp.Identifier)] or [t.name]
                return ObjRef.from_parts(parts)
        return None


# ------------------------------------------------------------
# Публичный API
# ------------------------------------------------------------

class SQLLineageParser:
    """
    Высокоуровневый фасад: выбирает sqlglot или fallback.
    """

    def __init__(self, dialect: Optional[str] = None):
        self.dialect = dialect
        self._impl = _SqlglotParser(dialect) if _SQLGLOT_AVAILABLE else _FallbackParser()

    def parse(self, sql: str) -> ParseResult:
        """
        Разбирает один SQL‑текст, потенциально содержащий несколько стейтментов, на отдельные lineage‑графы.
        """
        statements = self._split_statements(sql)
        out: List[StatementLineage] = []
        for idx, stmt in enumerate(statements):
            try:
                out.append(self._impl.parse(stmt, idx))
            except Exception as e:
                # Не прерываем общий разбор: добавляем пустой граф с сообщением в target None
                g = LineageGraph()
                out.append(StatementLineage(idx, stmt, g))
        return ParseResult(out)

    # ----------------- Вспомогательные методы -----------------

    def _split_statements(self, sql: str) -> List[str]:
        """
        Простой и безопасный сплит по ';' на верхнем уровне (без учёта ; внутри строк/скобок).
        Для промышленной версии достаточно статического сканера.
        """
        s = _strip_sql_comments(sql)
        stmts: List[str] = []
        buf: List[str] = []
        depth = 0
        in_str: Optional[str] = None
        esc = False
        for ch in s:
            if in_str:
                buf.append(ch)
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == in_str:
                    in_str = None
                continue
            if ch in ("'", '"', "`"):
                in_str = ch
                buf.append(ch)
                continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
            if ch == ";" and depth == 0:
                stmt = "".join(buf).strip()
                if stmt:
                    stmts.append(stmt)
                buf = []
            else:
                buf.append(ch)
        if buf:
            stmt = "".join(buf).strip()
            if stmt:
                stmts.append(stmt)
        return stmts


# ------------------------------------------------------------
# Быстрый прогон
# ------------------------------------------------------------

if __name__ == "__main__":
    examples = [
        # CTE + INSERT
        """
        WITH a AS (
            SELECT id, user_id, amount
            FROM sales s
            JOIN users u ON u.id = s.user_id
        ),
        b AS (
            SELECT user_id, sum(amount) AS total_amount
            FROM a
            GROUP BY user_id
        )
        INSERT INTO analytics.daily_sales (user_id, total_amount)
        SELECT user_id, total_amount FROM b;
        """,
        # CREATE TABLE AS SELECT
        """
        CREATE TABLE rpt.top_customers AS
        SELECT u.id AS uid, sum(s.amount) AS total
        FROM public.users u
        JOIN public.sales s ON s.user_id = u.id
        WHERE s.ts >= date_trunc('day', now()) - interval '1 day'
        GROUP BY u.id;
        """,
        # Простой SELECT UNION ALL
        """
        SELECT id, name FROM dim.products
        UNION ALL
        SELECT id, name FROM dim.products_backup;
        """,
    ]

    parser = SQLLineageParser(dialect=None)
    for i, ex in enumerate(examples):
        res = parser.parse(ex)
        combined = res.combined_graph().to_json()
        print(f"--- Example #{i+1} ---")
        print(combined)
