#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cybersecurity-core/cli/tools/generate_sbom.py

Промышленный генератор SBOM с поддержкой:
- Форматы вывода: CycloneDX 1.5 (JSON), SPDX 2.3 (JSON)
- Экосистемы и источники данных:
  * Python: requirements.txt, pyproject.toml, poetry.lock, Pipfile.lock
  * Node.js: package.json, package-lock.json
  * Go: go.mod
  * Rust: Cargo.lock
  * PHP: composer.lock
- Построение PURL (package-url) для поддерживаемых экосистем
- Хеширование файлов проекта (SHA-256) по маске
- Интеграция с Syft (subprocess), если доступен в PATH, как необязательный ускоритель/углубитель
- Без внешних зависимостей (используется только стандартная библиотека Python)

Аргументы CLI — см. `--help`.

Спецификации и ориентиры:
- CycloneDX (официальная спецификация и обзор): https://github.com/CycloneDX/specification , https://cyclonedx.org/specification/overview/
- SPDX 2.3: https://spdx.github.io/spdx-spec/v2.3/  (см. также общую страницу спецификаций https://spdx.dev/use/specifications/)
- PURL (package-url): https://github.com/package-url/purl-spec  (пример для npm scoped пакетов: см. рекомендации по URI-encoding '@' в пути) 
- Syft (генерация/конвертация SBOM): https://github.com/anchore/syft

ВНИМАНИЕ: данный инструмент формирует корректные структуры согласно базовым требованиям,
но формальная валидация JSON-схем внешними схемами не выполняется в оффлайн-режиме.

Автор: Aethernova / cybersecurity-core
Лицензия: Apache-2.0 (пример; при необходимости измените по политике проекта)
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import textwrap
import uuid
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union

# TOML поддержка: Python 3.11+ tomllib, иначе "мягкое" отключение TOML-парсинга
try:
    import tomllib  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    tomllib = None  # TOML-источники будут пропущены с предупреждением


# -------------------------------
# Утилиты логирования и ошибок
# -------------------------------

LOG = logging.getLogger("generate_sbom")

def setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


# -------------------------------
# Модель компонента и PURL
# -------------------------------

@dataclasses.dataclass
class Component:
    ecosystem: str
    name: str
    version: Optional[str] = None
    group: Optional[str] = None  # для maven/composer и т.п. (пока опционально)
    supplier: Optional[str] = None
    license_expression: Optional[str] = "NOASSERTION"
    hashes: Dict[str, str] = dataclasses.field(default_factory=dict)

    def bom_ref(self) -> str:
        """Детерминированный bom-ref для CycloneDX / SPDXID-совместимый якорь."""
        base = f"{self.ecosystem}:{self.group+'/' if self.group else ''}{self.name}@{self.version or 'NOASSERTION'}"
        return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, base)}"

    def purl(self) -> Optional[str]:
        """Сформировать purl по экосистеме. Минимально корректные варианты."""
        if not self.name:
            return None
        name = self.name
        version = self.version
        # Специфика пультов:
        # npm scoped: необходимо экранировать '@' в пути — '%40scope/name@version'
        # Источник (пример для scoped npm): Sonatype docs (URI-encoding '@' в purl пути).
        # https://help.sonatype.com/en/package-url-and-component-identifiers.html
        if self.ecosystem.lower() == "pypi":
            return f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}"
        if self.ecosystem.lower() == "npm":
            # Сохраняем scoped синтаксис в пути; '@' будет URL-экранирован.
            # Мы не используем отдельный namespace; допускается путь вида %40scope/name.
            # Экономим на сложной нормализации и следуем рекомендациям по URI-encoding.
            from urllib.parse import quote
            path = quote(name, safe="/")  # '@' -> '%40', '/' сохраняем
            return f"pkg:npm/{path}@{version}" if version else f"pkg:npm/{path}"
        if self.ecosystem.lower() == "golang":
            # go.mod использует полные module path, это корректно для purl: pkg:golang/<module>@<ver>
            return f"pkg:golang/{name}@{version}" if version else f"pkg:golang/{name}"
        if self.ecosystem.lower() == "cargo":
            return f"pkg:cargo/{name}@{version}" if version else f"pkg:cargo/{name}"
        if self.ecosystem.lower() == "composer":
            # Для composer обычно group/name, если group присутствует.
            path = f"{self.group}/{self.name}" if self.group else self.name
            return f"pkg:composer/{path}@{version}" if version else f"pkg:composer/{path}"
        # Универсальный fallback
        return f"pkg:generic/{name}@{version}" if version else f"pkg:generic/{name}"


# -------------------------------
# Файловые утилиты / хеширование
# -------------------------------

def sha256_file(path: Path, block_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(block_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def iter_files_for_hash(root: Path, include_globs: List[str], exclude_globs: List[str], max_size: int) -> Iterable[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        size = p.stat().st_size
        if size > max_size:
            continue
        # включения/исключения
        if include_globs and not any(p.match(g) for g in include_globs):
            continue
        if exclude_globs and any(p.match(g) for g in exclude_globs):
            continue
        yield p


# -------------------------------
# Парсеры зависимостей
# -------------------------------

def parse_requirements_txt(path: Path) -> List[Component]:
    comps: List[Component] = []
    rx = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*([<>=!~]=\s*[^#;\s]+)?")
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = rx.match(line)
            if not m:
                continue
            name = m.group(1)
            spec = (m.group(2) or "").replace(" ", "")
            version = None
            if spec.startswith("=="):
                version = spec[2:]
            elif spec.startswith("==="):
                version = spec[3:]
            # Для иных операторов версию не фиксируем
            comps.append(Component(ecosystem="pypi", name=name, version=version))
    return comps

def parse_pipfile_lock(path: Path) -> List[Component]:
    comps: List[Component] = []
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    for section in ("default", "develop"):
        deps = data.get(section, {}) or {}
        for name, meta in deps.items():
            version = None
            if isinstance(meta, dict):
                v = meta.get("version")
                if isinstance(v, str) and v.startswith("=="):
                    version = v[2:]
            elif isinstance(meta, str) and meta.startswith("=="):
                version = meta[2:]
            comps.append(Component(ecosystem="pypi", name=name, version=version))
    return comps

def parse_poetry_lock(path: Path) -> List[Component]:
    comps: List[Component] = []
    if not tomllib:
        LOG.warning("tomllib недоступен — пропускаю poetry.lock")
        return comps
    with path.open("rb") as f:
        data = tomllib.load(f)
    pkgs = data.get("package", []) or []
    for pkg in pkgs:
        name = pkg.get("name")
        version = pkg.get("version")
        if name:
            comps.append(Component(ecosystem="pypi", name=name, version=version))
    return comps

def parse_pyproject_toml(path: Path) -> Tuple[Optional[str], Optional[str], List[Component]]:
    project_name = None
    project_version = None
    deps: List[Component] = []
    if not tomllib:
        LOG.warning("tomllib недоступен — пропускаю pyproject.toml (meta/dep)")
        return project_name, project_version, deps
    with path.open("rb") as f:
        data = tomllib.load(f)
    proj = data.get("project") or {}
    project_name = proj.get("name")
    project_version = proj.get("version")
    # dependencies могут быть в виде списка строк "name[extras] >=1.2"
    for d in (proj.get("dependencies") or []):
        if not isinstance(d, str):
            continue
        # простейший парсинг "name==x.y"
        name = re.split(r"[<>=!~\s\[\];]", d, maxsplit=1)[0]
        version = None
        m = re.search(r"==\s*([^\s;]+)", d)
        if m:
            version = m.group(1)
        if name:
            deps.append(Component(ecosystem="pypi", name=name, version=version))
    return project_name, project_version, deps

def parse_package_json(path: Path) -> List[Component]:
    comps: List[Component] = []
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section, {}) or {}
        for name, spec in deps.items():
            version = None
            if isinstance(spec, str) and re.match(r"^\d", spec):
                version = spec
            comps.append(Component(ecosystem="npm", name=name, version=version))
    return comps

def parse_package_lock_json(path: Path) -> List[Component]:
    comps: List[Component] = []
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    # v2+ "packages" секция содержит объекты с "version"
    packages = data.get("packages") or {}
    for k, meta in packages.items():
        if not isinstance(meta, dict):
            continue
        name = meta.get("name")
        version = meta.get("version")
        if name:
            comps.append(Component(ecosystem="npm", name=name, version=version))
    # fallback: "dependencies" в корне (v1)
    if not comps:
        deps = data.get("dependencies") or {}
        def walk(node: Dict, prefix: str=""):
            for n, meta in node.items():
                v = meta.get("version") if isinstance(meta, dict) else None
                comps.append(Component(ecosystem="npm", name=n, version=v))
                if isinstance(meta, dict) and "dependencies" in meta:
                    walk(meta["dependencies"], prefix+n+"/")
        walk(deps)
    return dedup_components(comps)

def parse_go_mod(path: Path) -> List[Component]:
    comps: List[Component] = []
    content = path.read_text(encoding="utf-8", errors="ignore")
    # блок require (...) или одиночные require
    # пример строки: github.com/gorilla/mux v1.8.0
    rx = re.compile(r"^\s*([A-Za-z0-9\.\-_/]+)\s+v?([0-9][^\s]+)\s*$")
    in_block = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line.startswith(")"):
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        m = rx.match(line)
        if m:
            module = m.group(1)
            version = m.group(2)
            comps.append(Component(ecosystem="golang", name=module, version=version))
    return comps

def parse_cargo_lock(path: Path) -> List[Component]:
    comps: List[Component] = []
    if not tomllib:
        LOG.warning("tomllib недоступен — пропускаю Cargo.lock")
        return comps
    with path.open("rb") as f:
        data = tomllib.load(f)
    for pkg in data.get("package", []) or []:
        name = pkg.get("name")
        version = pkg.get("version")
        if name:
            comps.append(Component(ecosystem="cargo", name=name, version=version))
    return comps

def parse_composer_lock(path: Path) -> List[Component]:
    comps: List[Component] = []
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []) or []:
            name = pkg.get("name")
            version = pkg.get("version")
            group = None
            if name and "/" in name:
                group, short = name.split("/", 1)
                comps.append(Component(ecosystem="composer", name=short, group=group, version=version))
            elif name:
                comps.append(Component(ecosystem="composer", name=name, version=version))
    return comps

def dedup_components(components: List[Component]) -> List[Component]:
    # Приоритет — более «надёжные» lock-файлы позже в списке могут перекрыть версии
    acc: Dict[Tuple[str, str, Optional[str]], Component] = {}
    for c in components:
        key = (c.ecosystem, c.name, c.group)
        # если версия пустая — не затираем уже найденную
        if key in acc and (not c.version):
            continue
        acc[key] = c
    return list(acc.values())


# -------------------------------
# Сканирование проекта
# -------------------------------

@dataclasses.dataclass
class ScanResult:
    project_name: Optional[str]
    project_version: Optional[str]
    components: List[Component]
    artifacts_hashes: Dict[str, Dict[str, str]]  # путь -> {algo: hash}

LOCK_MANIFEST_PARSERS = (
    ("requirements.txt", parse_requirements_txt),
    ("Pipfile.lock", parse_pipfile_lock),
    ("poetry.lock", parse_poetry_lock),
    ("pyproject.toml", None),  # отдельная обработка для meta + deps
    ("package-lock.json", parse_package_lock_json),
    ("package.json", parse_package_json),
    ("go.mod", parse_go_mod),
    ("Cargo.lock", parse_cargo_lock),
    ("composer.lock", parse_composer_lock),
)

def scan_project(path: Path, hash_includes: List[str], hash_excludes: List[str], max_hash_size: int) -> ScanResult:
    components: List[Component] = []
    project_name: Optional[str] = None
    project_version: Optional[str] = None

    for fname, parser in LOCK_MANIFEST_PARSERS:
        fpath = path / fname
        if not fpath.exists():
            continue
        try:
            if fname == "pyproject.toml":
                pn, pv, deps = parse_pyproject_toml(fpath)
                project_name = project_name or pn
                project_version = project_version or pv
                components.extend(deps)
            else:
                comps = parser(fpath) if parser else []
                components.extend(comps)
            LOG.info("Parsed %s", fname)
        except Exception as e:
            LOG.warning("Ошибка парсинга %s: %s", fname, e)

    components = dedup_components(components)

    # Хеширование (по опциям)
    artifacts_hashes: Dict[str, Dict[str, str]] = {}
    if hash_includes:
        for f in iter_files_for_hash(path, hash_includes, hash_excludes, max_hash_size):
            try:
                artifacts_hashes[str(f.relative_to(path))] = {"SHA-256": sha256_file(f)}
            except Exception as e:
                LOG.debug("hash fail %s: %s", f, e)

    return ScanResult(
        project_name=project_name,
        project_version=project_version,
        components=components,
        artifacts_hashes=artifacts_hashes,
    )


# -------------------------------
# Генерация CycloneDX 1.5 JSON
# -------------------------------

def gen_cyclonedx_json(scan: ScanResult, project_name: Optional[str], project_version: Optional[str],
                       supplier: Optional[str], tool_name: str, tool_version: str) -> Dict:
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    serial = f"urn:uuid:{uuid.uuid4()}"

    root_name = project_name or scan.project_name or "unknown-project"
    root_version = project_version or scan.project_version or "0.0.0"

    # Корневой компонент (application)
    root_component_ref = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'root:{root_name}:{root_version}')}"
    root_component = {
        "bom-ref": root_component_ref,
        "type": "application",
        "name": root_name,
        "version": root_version,
    }
    if supplier:
        root_component["supplier"] = {"name": supplier}

    # Компоненты
    components_json = []
    for c in scan.components:
        comp = {
            "bom-ref": c.bom_ref(),
            "type": "library",
            "name": c.name,
        }
        if c.version:
            comp["version"] = c.version
        if c.group:
            comp["group"] = c.group
        purl = c.purl()
        if purl:
            comp["purl"] = purl
        if c.license_expression:
            comp["licenses"] = [{"expression": c.license_expression}]
        if c.hashes:
            comp["hashes"] = [{"alg": k, "content": v} for k, v in c.hashes.items()]
        components_json.append(comp)

    # Зависимости: root DEPENDS_ON каждую либу
    dependencies_json = [{"ref": root_component_ref, "dependsOn": [c["bom-ref"] for c in components_json]}]

    # Дополнительно: приложим хеши артефактов как evidence (attachments)
    properties = []
    if scan.artifacts_hashes:
        for rel, hv in scan.artifacts_hashes.items():
            for alg, h in hv.items():
                properties.append({"name": f"file-hash:{alg}:{rel}", "value": h})

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "Aethernova", "name": tool_name, "version": tool_version}],
            "component": root_component,
        },
        "components": components_json,
        "dependencies": dependencies_json,
    }
    if properties:
        bom["properties"] = properties
    return bom


# -------------------------------
# Генерация SPDX 2.3 JSON
# -------------------------------

def spdx_id_from(text: str) -> str:
    # SPDXID: допустимые символы — сделаем стабильный хеш
    return f"SPDXRef-{uuid.uuid5(uuid.NAMESPACE_URL, text)}"

def gen_spdx_json(scan: ScanResult, project_name: Optional[str], project_version: Optional[str],
                  supplier: Optional[str], tool_name: str, tool_version: str) -> Dict:
    created = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_name = f"{project_name or scan.project_name or 'unknown-project'}-SBOM"
    doc_spdx_id = "SPDXRef-DOCUMENT"
    root_name = project_name or scan.project_name or "unknown-project"
    root_version = project_version or scan.project_version or "0.0.0"
    root_pkg_id = spdx_id_from(f"{root_name}@{root_version}")

    creator_tool = f"Tool: {tool_name}/{tool_version}"

    packages = []
    relationships = []
    # Описываем документ
    relationships.append({"spdxElementId": doc_spdx_id, "relationshipType": "DESCRIBES", "relatedSpdxElement": root_pkg_id})

    # Корневой пакет
    root_pkg = {
        "name": root_name,
        "SPDXID": root_pkg_id,
        "versionInfo": root_version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "supplier": f"Organization: {supplier}" if supplier else "NOASSERTION",
    }
    packages.append(root_pkg)

    # Зависимости
    for c in scan.components:
        pid = spdx_id_from(c.bom_ref())
        pkg = {
            "name": c.name if not c.group else f"{c.group}/{c.name}",
            "SPDXID": pid,
            "versionInfo": c.version or "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": c.license_expression or "NOASSERTION",
            "licenseDeclared": c.license_expression or "NOASSERTION",
            "supplier": "NOASSERTION",
            "externalRefs": [],
        }
        purl = c.purl()
        if purl:
            pkg["externalRefs"].append({
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl
            })
        packages.append(pkg)
        relationships.append({"spdxElementId": root_pkg_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": pid})

    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": doc_spdx_id,
        "name": doc_name,
        "documentNamespace": f"urn:uuid:{uuid.uuid4()}",
        "creationInfo": {"creators": [creator_tool], "created": created},
        "packages": packages,
        "relationships": relationships,
    }
    return doc


# -------------------------------
# Интеграция с Syft (опционально)
# -------------------------------

def syft_available() -> bool:
    return shutil.which("syft") is not None

def syft_generate(path: Path, output_format: str) -> Optional[str]:
    """
    Попытка выполнить syft для генерации/конвертации SBOM.
    output_format: "cyclonedx-json" | "spdx-json"
    Возвращает содержимое SBOM (str) или None при ошибке.
    """
    if not syft_available():
        return None
    # syft dir:PATH -o <format>
    cmd = ["syft", f"dir:{str(path)}", "-o", output_format]
    try:
        LOG.info("Запуск syft: %s", " ".join(cmd))
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return out.decode("utf-8", errors="ignore")
    except subprocess.CalledProcessError as e:
        LOG.warning("Syft завершился с ошибкой (%s): %s", e.returncode, e.output.decode(errors="ignore"))
        return None
    except Exception as e:
        LOG.warning("Ошибка запуска syft: %s", e)
        return None


# -------------------------------
# CLI
# -------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="generate_sbom",
        description="Генератор SBOM (CycloneDX 1.5 / SPDX 2.3) для нескольких экосистем.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("path", type=str, help="Путь к корню проекта")
    p.add_argument("-o", "--output", type=str, default="-", help="Файл вывода SBOM или '-' для stdout")
    p.add_argument("--format", choices=["cyclonedx-json", "spdx-json"], default="cyclonedx-json", help="Формат вывода")
    p.add_argument("--project-name", type=str, default=None, help="Явно указать имя проекта (перекрывает pyproject)")
    p.add_argument("--project-version", type=str, default=None, help="Явно указать версию проекта (перекрывает pyproject)")
    p.add_argument("--supplier", type=str, default=None, help="Производитель/владелец (supplier)")
    p.add_argument("--include-hash", action="append", default=[], help="Глоб-маска для файлов, для которых считать SHA-256 (можно несколько)")
    p.add_argument("--exclude-hash", action="append", default=[], help="Глоб-маска файлов/папок для исключения из хеширования (можно несколько)")
    p.add_argument("--max-hash-size", type=int, default=5_000_000, help="Максимальный размер файла для хеширования, байт (по умолчанию 5 МБ)")
    p.add_argument("--use-syft", action="store_true", help="Попробовать использовать syft для генерации SBOM, если доступен")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Уровень подробности логирования (-v, -vv)")
    p.add_argument("--tool-name", default="aethernova-sbom-generator", help="Имя инструмента в metadata/tools")
    p.add_argument("--tool-version", default="1.0.0", help="Версия инструмента в metadata/tools")
    return p

def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    setup_logging(args.verbose)

    root = Path(args.path).resolve()
    if not root.exists() or not root.is_dir():
        LOG.error("Путь '%s' не существует или не является директорией", root)
        return 2

    # Ветка с Syft (по желанию)
    if args.use_syft:
        syft_fmt = {"cyclonedx-json": "cyclonedx-json", "spdx-json": "spdx-json"}[args.format]
        syft_out = syft_generate(root, syft_fmt)
        if syft_out:
            return write_output(args.output, syft_out)

    # Нативное сканирование
    scan = scan_project(
        root,
        hash_includes=args.include_hash or [],
        hash_excludes=args.exclude_hash or [],
        max_hash_size=args.max_hash_size,
    )

    if args.format == "cyclonedx-json":
        bom = gen_cyclonedx_json(scan, args.project_name, args.project_version, args.supplier, args.tool_name, args.tool_version)
    else:
        bom = gen_spdx_json(scan, args.project_name, args.project_version, args.supplier, args.tool_name, args.tool_version)

    text = json.dumps(bom, ensure_ascii=False, indent=2, sort_keys=False)
    return write_output(args.output, text)

def write_output(path: str, content: str) -> int:
    if path == "-" or path.strip() == "":
        sys.stdout.write(content)
        sys.stdout.write("\n")
        return 0
    outp = Path(path)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(content, encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        LOG.error("Прервано пользователем")
        sys.exit(130)
    except Exception as e:
        LOG.exception("Критическая ошибка: %s", e)
        sys.exit(1)
