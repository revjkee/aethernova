# neuroforge/registry/versioning.py
# SPDX-License-Identifier: Apache-2.0
"""
NeuroForge Versioning — промышленная реализация SemVer 2.0.0 и диапазонов.

Особенности:
- Строгий SemVer 2.0.0: MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
- Полная семантика пререлизов: сравнение идентификаторов, числовые < строковых
- Билд-метаданные учитываются при сериализации, но не влияют на сравнение
- Диапазоны: =, >, >=, <, <=, ^, ~, hyphen ("1.2.3 - 2.3.4"), групповое OR через '||'
- Утилиты: bump_major/minor/patch, bump_prerelease, finalize_release, next_free
- Matching: best_satisfying(), max_satisfying()
- Каналы: dev/alpha/beta/rc — генерация безопасных пререлизов
- CLI для CI: парсинг, сравнение, фильтрация по диапазону, бамп

Зависимости: только стандартная библиотека Python.

Пример:
    from neuroforge.registry.versioning import Version, VersionRange, bump_next

    v = Version.parse("1.2.3-beta.1+sha.abc")
    print(v.is_prerelease)  # True
    print(str(v.bump_patch()))  # 1.2.4

    rng = VersionRange.parse("^1.2 || 2.x")
    assert rng.contains(Version.parse("1.9.0"))
    assert rng.contains(Version.parse("2.5.0"))

    # Следующая свободная MINOR среди занятых:
    used = [Version.parse("1.3.0"), Version.parse("1.4.0")]
    print(bump_next(Version.parse("1.2.0"), used, strategy="minor"))  # 1.5.0
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from functools import total_ordering
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple


_SEMVER_RE = re.compile(
    r"""
    ^
    (?P<major>0|[1-9]\d*)
    \.
    (?P<minor>0|[1-9]\d*)
    \.
    (?P<patch>0|[1-9]\d*)
    (?:-(?P<prerelease>(?:[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)))?
    (?:\+(?P<build>(?:[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)))?
    $
    """,
    re.VERBOSE,
)

_PRERELEASE_ID_RE = re.compile(r"^(?:0|[1-9]\d*|[A-Za-z-][0-9A-Za-z-]*)$")


def _parse_ident_list(s: Optional[str]) -> Tuple[str, ...]:
    if not s:
        return ()
    parts = tuple(s.split("."))
    for p in parts:
        if not _PRERELEASE_ID_RE.match(p):
            raise ValueError(f"Invalid identifier: {p!r}")
    return parts


@total_ordering
@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    prerelease: Tuple[str, ...] = ()
    build: Tuple[str, ...] = ()

    # ---------------- Parsing / formatting ----------------

    @staticmethod
    def parse(text: str) -> "Version":
        m = _SEMVER_RE.match(text.strip())
        if not m:
            raise ValueError(f"Invalid semver: {text!r}")
        major = int(m.group("major"))
        minor = int(m.group("minor"))
        patch = int(m.group("patch"))
        pre = _parse_ident_list(m.group("prerelease"))
        build = _parse_ident_list(m.group("build"))
        return Version(major, minor, patch, pre, build)

    def __str__(self) -> str:
        s = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            s += "-" + ".".join(self.prerelease)
        if self.build:
            s += "+" + ".".join(self.build)
        return s

    # ---------------- Properties ----------------

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    @property
    def core(self) -> "Version":
        return Version(self.major, self.minor, self.patch)

    # ---------------- Comparison (SemVer precedence) ----------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return (
            self.major,
            self.minor,
            self.patch,
            self._pre_cmp_tuple(),
        ) == (
            other.major,
            other.minor,
            other.patch,
            other._pre_cmp_tuple(),
        )

    def __lt__(self, other: "Version") -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        a = (self.major, self.minor, self.patch)
        b = (other.major, other.minor, other.patch)
        if a != b:
            return a < b
        # Normal vs prerelease: normal > prerelease
        if not self.prerelease and other.prerelease:
            return False
        if self.prerelease and not other.prerelease:
            return True
        return self._pre_cmp_tuple() < other._pre_cmp_tuple()

    def _pre_cmp_tuple(self) -> Tuple:
        """
        Преобразует пререлиз в кортеж сравнимых элементов согласно SemVer:
        - Пустой пререлиз (нормальная версия) -> специальный маркер, который всегда "больше"
        - Числовые идентификаторы сравниваются как ints и всегда МЕНЬШЕ строковых
        - При равенстве префикса более длинная последовательность пререлиза имеет более высокий приоритет
        """
        if not self.prerelease:
            # Нормальная версия выигрывает у любого пререлиза
            return (float("inf"),)
        res: List[Tuple[int, object]] = []
        for ident in self.prerelease:
            if ident.isdigit():
                res.append((0, int(ident)))  # numeric group 0 (меньше строковых)
            else:
                res.append((1, ident))       # textual group 1
        # Длина пререлиза влияет: более длинный список ПОСЛЕ равного префикса — выше
        # Эмулируем это добавлением "длины" как последнего члена.
        res.append((2, len(self.prerelease)))
        return tuple(res)

    # ---------------- Bumps ----------------

    def bump_major(self, *, reset_prerelease: bool = True) -> "Version":
        v = Version(self.major + 1, 0, 0)
        return v if reset_prerelease else Version(v.major, v.minor, v.patch, self.prerelease, ())

    def bump_minor(self, *, reset_prerelease: bool = True) -> "Version":
        v = Version(self.major, self.minor + 1, 0)
        return v if reset_prerelease else Version(v.major, v.minor, v.patch, self.prerelease, ())

    def bump_patch(self, *, reset_prerelease: bool = True) -> "Version":
        v = Version(self.major, self.minor, self.patch + 1)
        return v if reset_prerelease else Version(v.major, v.minor, v.patch, self.prerelease, ())

    def bump_prerelease(self, label: str = "rc") -> "Version":
        """
        Увеличивает числовой суффикс у последнего идентификатора пререлиза данного label,
        либо создаёт "<label>.1", если пререлиз отсутствует или label отличается.
        """
        if not label or not _PRERELEASE_ID_RE.match(label) or label.isdigit():
            raise ValueError("Invalid prerelease label")
        if not self.prerelease or self.prerelease[0] != label:
            return Version(self.major, self.minor, self.patch, (label, "1"))
        ids = list(self.prerelease)
        # если второй идентификатор число — инкрементируем, иначе добавляем ".1"
        if len(ids) >= 2 and ids[1].isdigit():
            ids[1] = str(int(ids[1]) + 1)
        else:
            ids.append("1")
        return Version(self.major, self.minor, self.patch, tuple(ids))

    def with_prerelease(self, *ids: str) -> "Version":
        for p in ids:
            if not _PRERELEASE_ID_RE.match(p):
                raise ValueError(f"Invalid prerelease id: {p!r}")
        return Version(self.major, self.minor, self.patch, tuple(ids))

    def with_build(self, *ids: str) -> "Version":
        for p in ids:
            if not _PRERELEASE_ID_RE.match(p):
                raise ValueError(f"Invalid build id: {p!r}")
        return Version(self.major, self.minor, self.patch, self.prerelease, tuple(ids))

    def finalize_release(self) -> "Version":
        """Удаляет пререлиз/билд — «стабилизирует» версию."""
        return Version(self.major, self.minor, self.patch)


# ---------------- Version ranges ----------------

# Поддерживаем «шорткаты»: "1.2.x", "1.x", "x", "*"
_X_RE = re.compile(r"^(?:x|\*)$", re.I)

# Комбинаторы одного блока: =, <, <=, >, >=, ^, ~
_COMP_RE = re.compile(
    r"""
    ^
    (?P<op>\^|~|<=|>=|<|>|=)?
    \s*
    (?P<ver>
      (?:\d+|x|\*)                      # major
      (?:\.(?:\d+|x|\*)){0,2}           # .minor[.patch]
      (?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?  # prerelease
      (?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)? # build
    )
    $
    """,
    re.VERBOSE,
)


def _coerce_x(num: str) -> Optional[int]:
    return None if _X_RE.match(num) else int(num)


def _split_xyz(s: str) -> Tuple[Optional[int], Optional[int], Optional[int], str, str]:
    """
    Возвращает (major?, minor?, patch?, prerelease_str, build_str)
    """
    s = s.strip()
    build = ""
    pre = ""
    if "+" in s:
        s, build = s.split("+", 1)
    if "-" in s:
        s, pre = s.split("-", 1)
    parts = s.split(".")
    while len(parts) < 3:
        parts.append("x")
    major = _coerce_x(parts[0])
    minor = _coerce_x(parts[1])
    patch = _coerce_x(parts[2])
    return major, minor, patch, pre, build


@dataclass(frozen=True)
class Comparator:
    op: str  # one of: "=", "<", "<=", ">", ">=", "~", "^"
    ver: Version
    # Для масок x/* храним также «границы», вычисленные при интерпретации
    lower_inclusive: Optional[Version] = None
    upper_exclusive: Optional[Version] = None

    def contains(self, v: Version) -> bool:
        if self.op == "=":
            return v.core == self.ver.core and v.prerelease == self.ver.prerelease
        if self.op == "<":
            return v < self.ver
        if self.op == "<=":
            return v < self.ver or v == self.ver
        if self.op == ">":
            return v > self.ver
        if self.op == ">=":
            return v > self.ver or v == self.ver
        if self.op in ("~", "^"):
            # интерпретируем через границы
            assert self.lower_inclusive and self.upper_exclusive
            return self.lower_inclusive <= v < self.upper_exclusive
        raise ValueError(f"Unknown op: {self.op}")


@dataclass(frozen=True)
class RangeSet:
    """
    Конъюнкция компараторов: v должен удовлетворять всем.
    """
    comps: Tuple[Comparator, ...]

    def contains(self, v: Version) -> bool:
        return all(c.contains(v) for c in self.comps)


@dataclass(frozen=True)
class VersionRange:
    """
    Дизъюнкция наборов: (set1) || (set2) || ...
    """
    sets: Tuple[RangeSet, ...]

    @staticmethod
    def parse(text: str) -> "VersionRange":
        """
        Пример: "^1.2 || >=2.0.0 <3.0.0 || 3.x"
        """
        or_parts = [p.strip() for p in text.split("||") if p.strip()]
        range_sets: List[RangeSet] = []
        for part in or_parts:
            # Разбиваем по пробелам, но учитываем, что hyphen-диапазон — цельная конструкция
            # Сначала расширим "A - B" в ">=A <=B"
            hy = re.split(r"\s+-\s+", part)
            tokens: List[str] = []
            if len(hy) == 2:
                tokens.append(f">={hy[0].strip()}")
                tokens.append(f"<={hy[1].strip()}")
            else:
                tokens.extend(re.findall(r"(?:\^|~|<=|>=|<|>|=)?\s*[^ \t]+", part))

            comps: List[Comparator] = []
            for t in tokens:
                m = _COMP_RE.match(t.strip())
                if not m:
                    raise ValueError(f"Invalid comparator: {t!r}")
                op = m.group("op") or "="
                ver_text = m.group("ver")
                major, minor, patch, pre, build = _split_xyz(ver_text)

                # Интерпретация масок x/* — превращаем в полуинтервалы
                if op in ("^", "~") or any(x is None for x in (major, minor, patch)):
                    lower, upper = _interpret_mask_or_caret_tilde(op, major, minor, patch, pre)
                    comps.append(Comparator(op=op, ver=lower, lower_inclusive=lower, upper_exclusive=upper))
                else:
                    comps.append(Comparator(op=op, ver=Version.parse(f"{major}.{minor}.{patch}" + (f"-{pre}" if pre else "") + (f"+{build}" if build else ""))))
            range_sets.append(RangeSet(tuple(comps)))
        return VersionRange(tuple(range_sets))

    def contains(self, v: Version) -> bool:
        return any(s.contains(v) for s in self.sets)

    def max_satisfying(self, versions: Iterable[Version]) -> Optional[Version]:
        best: Optional[Version] = None
        for ver in versions:
            if self.contains(ver):
                if best is None or ver > best:
                    best = ver
        return best

    def best_satisfying(self, versions: Iterable[Version]) -> Optional[Version]:
        """
        Синоним max_satisfying для читабельности.
        """
        return self.max_satisfying(versions)


def _interpret_mask_or_caret_tilde(op: str, major: Optional[int], minor: Optional[int], patch: Optional[int], pre: str) -> Tuple[Version, Version]:
    """
    Возвращает нижнюю включительную и верхнюю исключительную границы для масок и операторов ^ и ~.
    Маски:
      1.x  => [1.0.0, 2.0.0)
      1.2.x => [1.2.0, 1.3.0)
      x     => [0.0.0, +inf)
    Операторы:
      ~1.2.3 => [1.2.3, 1.3.0)
      ~1.2   => [1.2.0, 1.3.0)
      ^1.2.3 => [1.2.3, 2.0.0)
      ^0.2.3 => [0.2.3, 0.3.0)  (MAJOR=0 — совместимость в пределах MINOR)
      ^0.0.3 => [0.0.3, 0.0.4)
    """
    # Нижняя граница
    lo = Version(major or 0, minor or 0, patch or 0).with_prerelease(*([pre] if pre else [])) if pre else Version(major or 0, minor or 0, patch or 0)

    def upper_for_mask() -> Version:
        if major is None:  # x
            return Version(sys.maxsize, 0, 0)
        if minor is None:
            return Version(major + 1, 0, 0)
        if patch is None:
            return Version(major, minor + 1, 0)
        # Полностью задано — верхняя = следующая patch (исключительная), но эквивалент "="; обработается компаратором
        return Version(major, minor, patch + 1)

    def upper_for_tilde() -> Version:
        if minor is None:
            return Version((major or 0) + 1, 0, 0)
        return Version(major or 0, (minor or 0) + 1, 0)

    def upper_for_caret() -> Version:
        mj, mn, pt = major or 0, minor or 0, patch or 0
        if mj > 0:
            return Version(mj + 1, 0, 0)
        if mn > 0:
            return Version(0, mn + 1, 0)
        return Version(0, 0, pt + 1)

    if op in ("^", "~"):
        hi = upper_for_caret() if op == "^" else upper_for_tilde()
    else:
        hi = upper_for_mask()
    # Если было указано пререлизное начало — верхнюю оставляем без пререлиза (стандартная практика)
    return lo, hi


# ---------------- Utilities for registries ----------------

def next_free(base: Version, used: Iterable[Version]) -> Version:
    """
    Возвращает базовую версию, если она свободна, иначе увеличивает patch, пока не найдёт свободную.
    """
    used_set = {u.core for u in used}  # игнорируем пререлизы при проверке «занятости» релиза
    v = base
    while v.core in used_set:
        v = v.bump_patch()
    return v


def bump_next(current: Version, used: Iterable[Version], *, strategy: str = "patch", prerelease_label: Optional[str] = None) -> Version:
    """
    Стратегии: "major" | "minor" | "patch" | "prerelease" | "finalize"
      - prerelease: увеличивает/создаёт пререлиз с заданной меткой (по умолчанию 'rc')
      - finalize: удаляет пререлиз
    """
    strategy = strategy.lower()
    if strategy == "major":
        return next_free(current.bump_major(), used)
    if strategy == "minor":
        return next_free(current.bump_minor(), used)
    if strategy == "patch":
        return next_free(current.bump_patch(), used)
    if strategy == "prerelease":
        label = prerelease_label or "rc"
        return current.bump_prerelease(label=label)
    if strategy == "finalize":
        return current.finalize_release()
    raise ValueError(f"Unknown strategy: {strategy}")


def channel_prerelease(base: Version, channel: str) -> Version:
    """
    Канальный пререлиз: dev -> alpha -> beta -> rc
    channel ∈ {"dev","alpha","beta","rc"}.
    """
    ch = channel.lower()
    if ch not in {"dev", "alpha", "beta", "rc"}:
        raise ValueError("channel must be one of: dev, alpha, beta, rc")
    return base.bump_prerelease(ch)


def max_satisfying(versions: Iterable[Version], range_expr: str) -> Optional[Version]:
    rng = VersionRange.parse(range_expr)
    return rng.max_satisfying(versions)


# ---------------- CLI ----------------

def _cli(argv: Sequence[str]) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="neuroforge-versioning", description="SemVer/Range utilities")
    sub = p.add_subparsers(dest="cmd", required=True)

    s_parse = sub.add_parser("parse", help="Parse and echo normalized version")
    s_parse.add_argument("version")

    s_cmp = sub.add_parser("cmp", help="Compare two versions: prints -1/0/1")
    s_cmp.add_argument("a")
    s_cmp.add_argument("b")

    s_satisfy = sub.add_parser("satisfy", help="Check if version satisfies range")
    s_satisfy.add_argument("version")
    s_satisfy.add_argument("range")

    s_max = sub.add_parser("max", help="Pick max satisfying from list")
    s_max.add_argument("range")
    s_max.add_argument("versions", nargs="+", help="Versions to consider")

    s_bump = sub.add_parser("bump", help="Bump version")
    s_bump.add_argument("version")
    s_bump.add_argument("--strategy", choices=["major", "minor", "patch", "prerelease", "finalize"], default="patch")
    s_bump.add_argument("--label", default="rc", help="Prerelease label for strategy=prerelease")

    args = p.parse_args(argv)

    if args.cmd == "parse":
        v = Version.parse(args.version)
        print(str(v))
        return 0

    if args.cmd == "cmp":
        a, b = Version.parse(args.a), Version.parse(args.b)
        print(-1 if a < b else 1 if a > b else 0)
        return 0

    if args.cmd == "satisfy":
        v = Version.parse(args.version)
        rng = VersionRange.parse(args.range)
        print("true" if rng.contains(v) else "false")
        return 0

    if args.cmd == "max":
        rng = VersionRange.parse(args.range)
        vs = [Version.parse(x) for x in args.versions]
        best = rng.max_satisfying(vs)
        print(str(best) if best else "")
        return 0

    if args.cmd == "bump":
        v = Version.parse(args.version)
        if args.strategy == "prerelease":
            print(str(v.bump_prerelease(args.label)))
        elif args.strategy == "finalize":
            print(str(v.finalize_release()))
        elif args.strategy == "major":
            print(str(v.bump_major()))
        elif args.strategy == "minor":
            print(str(v.bump_minor()))
        else:
            print(str(v.bump_patch()))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
