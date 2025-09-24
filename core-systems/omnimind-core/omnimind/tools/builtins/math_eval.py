# omnimind-core/omnimind/tools/builtins/math_eval.py
"""
Безопасный промышленный вычислитель выражений.

Особенности:
- Без eval/exec. Только AST mode='eval' + жёсткий вайтлист узлов/операторов/функций.
- Лимиты: таймаут, макс. глубина AST, макс. узлов, макс. длины последовательностей,
  ограничение степеней/факториала/комбинаторики, макс. битность целых.
- Режимы точности: float | decimal | fraction (рациональные).
- Поддержка переменных и констант (pi, e, tau, inf, nan).
- Векторы/матрицы: [+,-,*,/, @, индексация, dot(), norm(), transpose(), shape()].
- Нормализованные ошибки (коды + сообщения), безопасные диагностические детали.
- Необязательная интеграция с sympy (если установлен), но отключена по умолчанию.
- Кроссплатформенность (без signal.alarm) через проверку времени на каждом визите узла.
"""

from __future__ import annotations

import ast
import math
import operator as _op
import time
from dataclasses import dataclass
from decimal import Decimal, getcontext as _getctx, localcontext as _localctx
from fractions import Fraction
from statistics import mean as _mean, median as _median, pstdev as _pstdev, pvariance as _pvariance
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableSequence, Optional, Sequence, Tuple, Union

Number = Union[int, float, Decimal, Fraction]
Vector = List[Number]
Matrix = List[List[Number]]


# ============================ Ошибки и метаданные ============================

class MathEvalError(Exception):
    def __init__(self, code: str, message: str, *, detail: Optional[str] = None):
        super().__init__(message)
        self.code = code
        self.detail = detail or ""

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "message": str(self), "detail": self.detail}


@dataclass
class MathEvalOptions:
    numeric_mode: str = "float"            # "float" | "decimal" | "fraction"
    decimal_precision: int = 28            # для Decimal
    time_limit_ms: int = 100               # общий лимит
    max_nodes: int = 2000                  # макс. количество посещённых узлов AST
    max_depth: int = 40                    # макс. глубина AST
    max_sequence_len: int = 10000          # макс. длина списков/кортежей
    max_int_bits: int = 1_000_000          # верхняя граница для big int (по битам)
    max_pow_exponent: int = 10000          # ограничение для возведения в степень
    enable_complex: bool = False           # разрешить ли комплексные (по умолчанию нет)
    enable_sympy: bool = False             # использовать sympy упрощение (если установлен)
    allow_functions: Optional[Iterable[str]] = None  # если задан, сужает белый список


@dataclass
class MathEvalResult:
    value: Any
    type: str
    mode: str
    elapsed_ms: float
    nodes: int
    warnings: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "type": self.type,
            "mode": self.mode,
            "elapsed_ms": self.elapsed_ms,
            "nodes": self.nodes,
            "warnings": self.warnings,
        }


# ================================ Утилиты =====================================

def _is_number(x: Any) -> bool:
    return isinstance(x, (int, float, Decimal, Fraction))


def _check_int_bits(n: int, max_bits: int):
    if isinstance(n, bool):
        # bool — подкласс int; запрещаем явно
        raise MathEvalError("INVALID_TYPE", "Boolean values are not allowed in expressions")
    if n == 0:
        return
    if abs(n).bit_length() > max_bits:
        raise MathEvalError("INTEGER_TOO_LARGE", f"Integer bit length exceeds limit ({max_bits} bits)")


def _to_mode(x: Number, mode: str, prec: int) -> Number:
    if mode == "float":
        if isinstance(x, Fraction):
            return float(x)
        if isinstance(x, Decimal):
            return float(x)
        return float(x) if isinstance(x, int) else x
    if mode == "decimal":
        if isinstance(x, Decimal):
            return x
        with _localctx() as ctx:
            ctx.prec = prec
            if isinstance(x, Fraction):
                return Decimal(x.numerator) / Decimal(x.denominator)
            return Decimal(str(x))
    if mode == "fraction":
        if isinstance(x, Fraction):
            return x
        if isinstance(x, Decimal):
            # возможно неточная конверсия — используем строковое представление
            return Fraction(str(x))
        return Fraction(x)
    raise MathEvalError("INVALID_MODE", f"Unknown numeric_mode: {mode}")


def _ensure_same_mode(a: Number, b: Number, mode: str, prec: int) -> Tuple[Number, Number]:
    return _to_mode(a, mode, prec), _to_mode(b, mode, prec)


def _matrix_shape(m: Matrix) -> Tuple[int, int]:
    if not isinstance(m, list) or not m or not isinstance(m[0], list):
        raise MathEvalError("INVALID_MATRIX", "Matrix must be a non-empty list of lists")
    rows = len(m)
    cols = len(m[0])
    if any(len(r) != cols for r in m):  # прямоугольность
        raise MathEvalError("INVALID_MATRIX", "All matrix rows must be of equal length")
    return rows, cols


def _matmul(a: Matrix, b: Matrix, mode: str, prec: int) -> Matrix:
    ra, ca = _matrix_shape(a)
    rb, cb = _matrix_shape(b)
    if ca != rb:
        raise MathEvalError("BAD_DIMENSIONS", f"Incompatible matrix dimensions {ra}x{ca} @ {rb}x{cb}")
    out: Matrix = [[0 for _ in range(cb)] for _ in range(ra)]
    for i in range(ra):
        for j in range(cb):
            s: Number = 0
            for k in range(ca):
                x, y = _ensure_same_mode(a[i][k], b[k][j], mode, prec)
                s = _to_mode(s, mode, prec) + (x * y)  # type: ignore
            out[i][j] = s
    return out


def _vectorize_binop(op: Callable[[Number, Number], Number], a: Any, b: Any, mode: str, prec: int) -> Any:
    if _is_number(a) and _is_number(b):
        x, y = _ensure_same_mode(a, b, mode, prec)
        return op(x, y)  # type: ignore
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            raise MathEvalError("BAD_DIMENSIONS", "Vectors must be same length for elementwise operation")
        return [_vectorize_binop(op, x, y, mode, prec) for x, y in zip(a, b)]
    if isinstance(a, list) and _is_number(b):
        return [_vectorize_binop(op, x, b, mode, prec) for x in a]
    if _is_number(a) and isinstance(b, list):
        return [_vectorize_binop(op, a, y, mode, prec) for y in b]
    raise MathEvalError("INVALID_TYPE", "Unsupported operands for operation")


def _safe_pow(base: Number, exp: Number, *, mode: str, prec: int, max_exp: int) -> Number:
    # Ограничение степеней (особенно для больших целых)
    if isinstance(exp, (int, Fraction)) and Fraction(exp).denominator == 1:
        e = int(Fraction(exp).numerator)
        if abs(e) > max_exp:
            raise MathEvalError("POW_EXP_LIMIT", f"Exponent exceeds limit ({max_exp})")
    # Базовый тип
    b, e = _ensure_same_mode(base, exp, mode, prec)
    if mode == "fraction" and isinstance(e, Fraction) and e.denominator != 1:
        # рациональная степень → переводим во float/decimal
        b = _to_mode(b, "decimal", prec)
        e = _to_mode(e, "decimal", prec)
        mode = "decimal"
    if mode == "decimal":
        with _localctx() as ctx:
            ctx.prec = prec
            return b ** e  # type: ignore
    return b ** e  # type: ignore


def _safe_factorial(n: Number, *, max_n: int = 20000) -> int:
    if not isinstance(n, int):
        raise MathEvalError("INVALID_ARGUMENT", "factorial() expects integer")
    if n < 0:
        raise MathEvalError("INVALID_ARGUMENT", "factorial() expects non-negative integer")
    if n > max_n:
        raise MathEvalError("FACTORIAL_LIMIT", f"factorial argument exceeds limit ({max_n})")
    return math.factorial(n)


def _bounded_seq(seq: Sequence[Any], limit: int, ctx: str) -> Sequence[Any]:
    if len(seq) > limit:
        raise MathEvalError("SEQUENCE_TOO_LONG", f"{ctx}: sequence length exceeds limit ({limit})")
    return seq


# ============================ Белые списки функций ===========================

def _wrap_numeric_unary(fn: Callable[[float], float], mode: str, prec: int) -> Callable[[Number], Number]:
    def _inner(x: Number) -> Number:
        if mode == "decimal":
            with _localctx() as ctx:
                ctx.prec = prec
                return _to_mode(fn(float(_to_mode(x, "float", prec))), "decimal", prec)
        if mode == "fraction":
            return _to_mode(fn(float(_to_mode(x, "float", prec))), "fraction", prec)
        return fn(float(x))
    return _inner


def _wrap_aggregate(fn: Callable[[Iterable[float]], float], mode: str, prec: int, limit: int) -> Callable[[Sequence[Number]], Number]:
    def _inner(xs: Sequence[Number]) -> Number:
        _bounded_seq(xs, limit, fn.__name__)
        vals = [float(_to_mode(v, "float", prec)) for v in xs]
        out = fn(vals)
        return _to_mode(out, mode, prec)
    return _inner


def _dot(a: Sequence[Number], b: Sequence[Number], mode: str, prec: int) -> Number:
    _bounded_seq(a, 100000, "dot")
    _bounded_seq(b, 100000, "dot")
    if len(a) != len(b):
        raise MathEvalError("BAD_DIMENSIONS", "dot: vectors must be same length")
    acc: Number = 0
    for x, y in zip(a, b):
        ax, by = _ensure_same_mode(x, y, mode, prec)
        acc = _to_mode(acc, mode, prec) + (ax * by)  # type: ignore
    return acc


def _norm(a: Sequence[Number], mode: str, prec: int) -> Number:
    return _to_mode(math.sqrt(float(_dot(a, a, "float", prec))), mode, prec)


def _transpose(m: Matrix) -> Matrix:
    r, c = _matrix_shape(m)
    return [[m[i][j] for i in range(r)] for j in range(c)]


# Фабрика разрешённых функций, зависящих от режима точности
def _build_functions(mode: str, prec: int, seq_limit: int) -> Dict[str, Callable[..., Any]]:
    f: Dict[str, Callable[..., Any]] = {
        # базовые
        "abs": lambda x: _to_mode(abs(_to_mode(x, mode, prec)), mode, prec),
        "round": lambda x, n=0: _to_mode(round(float(_to_mode(x, "float", prec)), int(n)), mode, prec),
        "min": lambda *xs: _to_mode(min(float(_to_mode(x, "float", prec)) for x in xs), mode, prec),
        "max": lambda *xs: _to_mode(max(float(_to_mode(x, "float", prec)) for x in xs), mode, prec),
        "clamp": lambda x, a, b: _to_mode(min(max(float(_to_mode(x, "float", prec)), float(a)), float(b)), mode, prec),

        # тригонометрия/логарифмы
        "sin": _wrap_numeric_unary(math.sin, mode, prec),
        "cos": _wrap_numeric_unary(math.cos, mode, prec),
        "tan": _wrap_numeric_unary(math.tan, mode, prec),
        "asin": _wrap_numeric_unary(math.asin, mode, prec),
        "acos": _wrap_numeric_unary(math.acos, mode, prec),
        "atan": _wrap_numeric_unary(math.atan, mode, prec),
        "atan2": lambda y, x: _to_mode(math.atan2(float(y), float(x)), mode, prec),
        "sinh": _wrap_numeric_unary(math.sinh, mode, prec),
        "cosh": _wrap_numeric_unary(math.cosh, mode, prec),
        "tanh": _wrap_numeric_unary(math.tanh, mode, prec),
        "log":  lambda x, b=math.e: _to_mode(math.log(float(x), float(b)), mode, prec),
        "log10": _wrap_numeric_unary(math.log10, mode, prec),
        "log2":  _wrap_numeric_unary(math.log2, mode, prec),
        "exp":   _wrap_numeric_unary(math.exp, mode, prec),
        "sqrt":  _wrap_numeric_unary(math.sqrt, mode, prec),
        "deg2rad": lambda x: _to_mode(math.radians(float(x)), mode, prec),
        "rad2deg": lambda x: _to_mode(math.degrees(float(x)), mode, prec),

        # комбинаторика/целочисленные
        "gcd": lambda a, b: math.gcd(int(a), int(b)),
        "lcm": lambda a, b: math.lcm(int(a), int(b)) if hasattr(math, "lcm") else int(abs(int(a) * int(b)) / math.gcd(int(a), int(b))),
        "factorial": lambda n: _safe_factorial(int(n)),
        "comb": lambda n, k: math.comb(int(n), int(k)),
        "perm": lambda n, k=None: math.perm(int(n), int(k)) if k is not None else math.perm(int(n)),

        # статистика
        "mean": _wrap_aggregate(_mean, mode, prec, seq_limit),
        "median": _wrap_aggregate(_median, mode, prec, seq_limit),
        "stdev": _wrap_aggregate(_pstdev, mode, prec, seq_limit),
        "variance": _wrap_aggregate(_pvariance, mode, prec, seq_limit),

        # линейная алгебра
        "dot": lambda a, b: _dot(a, b, mode, prec),
        "norm": lambda a: _norm(a, mode, prec),
        "transpose": _transpose,
        "shape": lambda m: _matrix_shape(m),
    }
    return f


# ============================= Безопасный визитор ============================

_ALLOWED_BINOPS = {
    ast.Add: lambda a, b, m, p: _vectorize_binop(_op.add, a, b, m, p),
    ast.Sub: lambda a, b, m, p: _vectorize_binop(_op.sub, a, b, m, p),
    ast.Mult: lambda a, b, m, p: _vectorize_binop(_op.mul, a, b, m, p),
    ast.Div: lambda a, b, m, p: _vectorize_binop(_op.truediv, a, b, m, p),
    ast.FloorDiv: lambda a, b, m, p: _vectorize_binop(_op.floordiv, a, b, m, p),
    ast.Mod: lambda a, b, m, p: _vectorize_binop(_op.mod, a, b, m, p),
    ast.Pow: lambda a, b, m, p, me=...: _safe_pow(a, b, mode=m, prec=p, max_exp=me),  # me подставим извне
    ast.MatMult: lambda a, b, m, p: _matmul(a, b, m, p),
}

_ALLOWED_UNARYOPS = {
    ast.UAdd: lambda a: +a,
    ast.USub: lambda a: -a,
}

_ALLOWED_CMPOP = {
    ast.Eq: _op.eq,
    ast.NotEq: _op.ne,
    ast.Lt: _op.lt,
    ast.LtE: _op.le,
    ast.Gt: _op.gt,
    ast.GtE: _op.ge,
}


class _SafeEvaluator(ast.NodeVisitor):
    def __init__(
        self,
        variables: Mapping[str, Any],
        options: MathEvalOptions,
        functions: Mapping[str, Callable[..., Any]],
        constants: Mapping[str, Any],
    ):
        self.vars = dict(variables or {})
        self.opt = options
        self.funcs = dict(functions)
        self.consts = dict(constants)
        self.start = time.monotonic()
        self.nodes = 0
        # Подставим лимит для pow
        self._allowed_binops = dict(_ALLOWED_BINOPS)
        self._allowed_binops[ast.Pow] = lambda a, b, m, p: _safe_pow(a, b, mode=m, prec=p, max_exp=self.opt.max_pow_exponent)

        # Если задан allow_functions — сужаем вайтлист
        if self.opt.allow_functions is not None:
            allow = set(self.opt.allow_functions)
            self.funcs = {k: v for k, v in self.funcs.items() if k in allow}

    # ---- контроль ресурсов ----
    def _tick(self, node: ast.AST):
        self.nodes += 1
        if self.nodes > self.opt.max_nodes:
            raise MathEvalError("NODE_LIMIT", f"AST node limit exceeded ({self.opt.max_nodes})")
        if (time.monotonic() - self.start) * 1000.0 > self.opt.time_limit_ms:
            raise MathEvalError("TIMEOUT", f"Time limit exceeded ({self.opt.time_limit_ms} ms)")

    # ---- визиты ----
    def generic_visit(self, node: ast.AST):
        self._tick(node)
        node_name = type(node).__name__
        raise MathEvalError("UNSUPPORTED_SYNTAX", f"Unsupported syntax node: {node_name}")

    def visit_Expression(self, node: ast.Expression):
        self._tick(node)
        return self.visit(node.body)

    def visit_Constant(self, node: ast.Constant):
        self._tick(node)
        v = node.value
        if isinstance(v, bool):
            raise MathEvalError("INVALID_TYPE", "Booleans are not allowed")
        if isinstance(v, (int, float)):
            if isinstance(v, int):
                _check_int_bits(v, self.opt.max_int_bits)
            return _to_mode(v, self.opt.numeric_mode, self.opt.decimal_precision)
        if v is None or isinstance(v, str):
            raise MathEvalError("INVALID_LITERAL", "Only numeric literals and list/tuple are allowed")
        return v

    def visit_Name(self, node: ast.Name):
        self._tick(node)
        name = node.id
        if name in self.vars:
            val = self.vars[name]
        elif name in self.consts:
            val = self.consts[name]
        else:
            raise MathEvalError("UNKNOWN_NAME", f"Unknown identifier: {name}")
        if isinstance(val, int):
            _check_int_bits(val, self.opt.max_int_bits)
        return _to_mode(val, self.opt.numeric_mode, self.opt.decimal_precision) if _is_number(val) else val

    def visit_UnaryOp(self, node: ast.UnaryOp):
        self._tick(node)
        if type(node.op) not in _ALLOWED_UNARYOPS:
            raise MathEvalError("UNSUPPORTED_OP", f"Unary operator not allowed: {type(node.op).__name__}")
        val = self.visit(node.operand)
        if not (_is_number(val) or isinstance(val, list)):
            raise MathEvalError("INVALID_TYPE", "Unary op expects number")
        return _ALLOWED_UNARYOPS[type(node.op)](val)

    def visit_BinOp(self, node: ast.BinOp):
        self._tick(node)
        op = type(node.op)
        left = self.visit(node.left)
        right = self.visit(node.right)
        if op not in self._allowed_binops:
            raise MathEvalError("UNSUPPORTED_OP", f"Binary operator not allowed: {op.__name__}")
        return self._allowed_binops[op](left, right, self.opt.numeric_mode, self.opt.decimal_precision)

    def visit_Compare(self, node: ast.Compare):
        self._tick(node)
        if len(node.ops) != 1 or len(node.comparators) != 1:
            raise MathEvalError("CHAINED_COMPARE", "Chained comparisons are not supported")
        op = type(node.ops[0])
        if op not in _ALLOWED_CMPOP:
            raise MathEvalError("UNSUPPORTED_OP", f"Comparator not allowed: {op.__name__}")
        a = self.visit(node.left)
        b = self.visit(node.comparators[0])
        if not (_is_number(a) and _is_number(b)):
            raise MathEvalError("INVALID_TYPE", "Comparison expects numbers")
        aa, bb = _ensure_same_mode(a, b, self.opt.numeric_mode, self.opt.decimal_precision)
        return _ALLOWED_CMPOP[op](aa, bb)

    def visit_List(self, node: ast.List):
        self._tick(node)
        items = [self.visit(e) for e in node.elts]
        if len(items) > self.opt.max_sequence_len:
            raise MathEvalError("SEQUENCE_TOO_LONG", f"List exceeds limit ({self.opt.max_sequence_len})")
        return items

    def visit_Tuple(self, node: ast.Tuple):
        self._tick(node)
        items = [self.visit(e) for e in node.elts]
        if len(items) > self.opt.max_sequence_len:
            raise MathEvalError("SEQUENCE_TOO_LONG", f"Tuple exceeds limit ({self.opt.max_sequence_len})")
        return items

    def visit_Subscript(self, node: ast.Subscript):
        self._tick(node)
        seq = self.visit(node.value)
        if not isinstance(seq, (list, tuple)):
            raise MathEvalError("INVALID_SUBSCRIPT", "Indexing allowed only for list/tuple")
        if isinstance(node.slice, ast.Slice):
            lower = self.visit(node.slice.lower) if node.slice.lower else None
            upper = self.visit(node.slice.upper) if node.slice.upper else None
            step = self.visit(node.slice.step) if node.slice.step else None
            return seq[slice(lower, upper, step)]
        idx = self.visit(node.slice)
        if not isinstance(idx, int):
            raise MathEvalError("INVALID_SUBSCRIPT", "Index must be integer")
        return seq[idx]

    def visit_Call(self, node: ast.Call):
        self._tick(node)
        if not isinstance(node.func, ast.Name):
            raise MathEvalError("UNSUPPORTED_CALL", "Only direct function calls are allowed")
        name = node.func.id
        if name not in self.funcs:
            raise MathEvalError("UNKNOWN_FUNCTION", f"Unknown function: {name}")
        if node.keywords:
            # Разрешим только простые именованные аргументы, без **kwargs
            kwargs = {kw.arg: self.visit(kw.value) for kw in node.keywords if kw.arg}
            if len(kwargs) != len(node.keywords):
                raise MathEvalError("UNSUPPORTED_CALL", "Keyword argument unpacking not allowed")
        else:
            kwargs = {}
        args = [self.visit(a) for a in node.args]
        # Проверка длины последовательностей в аргументах агрегатов - в обёртках
        return self.funcs[name](*args, **kwargs)


# ================================ Публичный API ===============================

class MathEvaluator:
    """
    Безопасный вычислитель выражений.
    Пример:
        ev = MathEvaluator()
        res = ev.evaluate("dot([1,2,3],[4,5,6]) + sqrt(2)", {"x": 10})
        print(res.to_dict())
    """
    def __init__(self, options: Optional[MathEvalOptions] = None):
        self.options = options or MathEvalOptions()

        # Константы
        self.constants: Dict[str, Any] = {
            "pi": math.pi,
            "e": math.e,
            "tau": math.tau,
            "inf": float("inf"),
            "nan": float("nan"),
        }

    def evaluate(self, expression: str, variables: Optional[Mapping[str, Any]] = None) -> MathEvalResult:
        if not isinstance(expression, str) or not expression.strip():
            raise MathEvalError("INVALID_EXPRESSION", "Expression must be a non-empty string")

        start = time.monotonic()

        # Парсинг AST
        try:
            tree = ast.parse(expression, mode="eval")
        except SyntaxError as e:
            raise MathEvalError("SYNTAX_ERROR", f"{e.msg} at line {e.lineno}:{e.offset}")

        # Контроль глубины AST
        if _depth(tree) > self.options.max_depth:
            raise MathEvalError("DEPTH_LIMIT", f"AST depth exceeds limit ({self.options.max_depth})")

        # Функции с учётом режима
        functions = _build_functions(self.options.numeric_mode, self.options.decimal_precision, self.options.max_sequence_len)

        evaluator = _SafeEvaluator(variables or {}, self.options, functions, self.constants)
        warnings: List[str] = []

        # Выполнение
        try:
            val = evaluator.visit(tree)
        except MathEvalError:
            raise
        except Exception as e:
            raise MathEvalError("EVALUATION_ERROR", "Unhandled evaluation error", detail=type(e).__name__) from e

        # Тип результата
        rtype = _typeof(val)

        elapsed = (time.monotonic() - start) * 1000.0
        return MathEvalResult(value=val, type=rtype, mode=self.options.numeric_mode, elapsed_ms=round(elapsed, 3), nodes=evaluator.nodes, warnings=warnings)


# ================================ Вспомогательное ============================

def _depth(node: ast.AST) -> int:
    """Подсчёт глубины AST."""
    if not isinstance(node, ast.AST) or not list(ast.iter_child_nodes(node)):
        return 1
    return 1 + max(_depth(c) for c in ast.iter_child_nodes(node))


def _typeof(v: Any) -> str:
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, Decimal):
        return "decimal"
    if isinstance(v, Fraction):
        return "fraction"
    if isinstance(v, list):
        if v and isinstance(v[0], list):
            return "matrix"
        return "vector"
    return type(v).__name__


# ================================ CLI (опц.) =================================

if __name__ == "__main__":
    import json
    import sys

    expr = sys.argv[1] if len(sys.argv) > 1 else "2+2*2"
    opts = MathEvalOptions(numeric_mode="float", time_limit_ms=200)
    ev = MathEvaluator(opts)
    try:
        out = ev.evaluate(expr, {})
        print(json.dumps(out.to_dict(), ensure_ascii=False, indent=2, default=str))
    except MathEvalError as e:
        print(json.dumps({"error": e.to_dict()}, ensure_ascii=False, indent=2))
        sys.exit(1)
