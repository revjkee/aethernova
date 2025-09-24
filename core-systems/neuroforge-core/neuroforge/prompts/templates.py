# file: neuroforge-core/neuroforge/prompts/templates.py
from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
import re
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from string import Formatter
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)

# =====================================================================
# Публичные типы
# =====================================================================

@dataclass(frozen=True)
class TemplateMeta:
    name: str
    version: str = "1.0.0"
    locale: Optional[str] = None
    description: Optional[str] = None
    tags: Tuple[str, ...] = tuple()

@dataclass(frozen=True)
class RenderOptions:
    dedent: bool = True
    strip: bool = True
    collapse_whitespace: bool = False
    ensure_trailing_newline: bool = False
    max_chars: Optional[int] = None

class Role:
    system = "system"
    user = "user"
    assistant = "assistant"
    tool = "tool"

@dataclass(frozen=True)
class ChatMessage:
    role: str
    content: str

# =====================================================================
# Исключения
# =====================================================================

class TemplateError(Exception): ...
class MissingVariable(TemplateError): ...
class RenderLimitExceeded(TemplateError): ...
class InvalidTemplate(TemplateError): ...
class RegistryError(TemplateError): ...

# =====================================================================
# Утилиты
# =====================================================================

_SECRET_KEYS = re.compile(r"(api[_-]?key|authorization|token|secret|password|set-cookie)", re.IGNORECASE)

def redact_secrets(value: Any) -> Any:
    """
    Безопасная редакция секретов для логирования. Для строк заменяет ключевые слова,
    для dict — редактирует значения по ключам, для списков — поэлементно.
    """
    if isinstance(value, str):
        return _SECRET_KEYS.sub("[REDACTED]", value)
    if isinstance(value, Mapping):
        return {k: ("[REDACTED]" if _SECRET_KEYS.search(str(k) or "") else redact_secrets(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        t = [redact_secrets(v) for v in value]
        return type(value)(t) if not isinstance(value, list) else t
    return value

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _normalize_text(s: str, opt: RenderOptions) -> str:
    if opt.dedent:
        s = textwrap.dedent(s)
    if opt.strip:
        s = s.strip()
    if opt.collapse_whitespace:
        s = re.sub(r"[ \t]+", " ", s)
        s = re.sub(r"\n{3,}", "\n\n", s)
    if opt.ensure_trailing_newline and (not s.endswith("\n")):
        s = s + "\n"
    if opt.max_chars is not None and len(s) > opt.max_chars:
        raise RenderLimitExceeded(f"render length {len(s)} exceeds limit {opt.max_chars}")
    return s

def _stable_hash(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()

# =====================================================================
# Извлечение плейсхолдеров для встроенного движка
# =====================================================================

class _StrictFormatter(Formatter):
    """
    Строгий форматтер на базе str.format, который:
      - извлекает набор переменных
      - при подстановке требует наличие каждой переменной
    """

    @staticmethod
    def extract_keys(template: str) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
        fields, conversions = [], []
        for literal_text, field_name, format_spec, conversion in Formatter.parse(template):
            if field_name is not None and field_name != "":
                # поддержка сложных выражений a.b[0] не реализуется в strict-режиме
                key = str(field_name).split(".")[0].split("[")[0]
                fields.append(key)
            if conversion:
                conversions.append(conversion)
        return tuple(sorted(set(fields))), tuple(conversions)

    def vformat(self, format_string, args, kwargs):
        # Перекрываем поведение: KeyError -> MissingVariable с подробностями
        try:
            return super().vformat(format_string, args, kwargs)
        except KeyError as e:
            missing = str(e).strip("'")
            raise MissingVariable(f"variable '{missing}' not provided") from None

# =====================================================================
# Движки: встроенный и опциональный Jinja2 sandbox
# =====================================================================

class TemplateEngine:
    def render(self, template: str, context: Mapping[str, Any], options: RenderOptions) -> str:  # pragma: no cover - интерфейс
        raise NotImplementedError

    def required_vars(self, template: str) -> Tuple[str, ...]:  # pragma: no cover - интерфейс
        raise NotImplementedError

class BuiltinEngine(TemplateEngine):
    def __init__(self) -> None:
        self._fmt = _StrictFormatter()

    def render(self, template: str, context: Mapping[str, Any], options: RenderOptions) -> str:
        text = self._fmt.vformat(template, (), dict(context))
        return _normalize_text(text, options)

    def required_vars(self, template: str) -> Tuple[str, ...]:
        keys, _ = self._fmt.extract_keys(template)
        return keys

class JinjaEngine(TemplateEngine):
    """
    Опциональный Jinja2 Sandbox (используется, если jinja2 установлена).
    Поддерживает условные блоки/циклы, фильтры и т. п.
    """
    def __init__(self) -> None:
        try:
            from jinja2 import Environment, StrictUndefined, meta, sandbox  # type: ignore
        except Exception as e:  # pragma: no cover
            raise InvalidTemplate("jinja2 is not installed") from e
        self._jinja_env = sandbox.SandboxedEnvironment(
            undefined=StrictUndefined,
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._jinja_meta = meta

        # Безопасные фильтры
        self._jinja_env.filters.update({
            "json": lambda x: json.dumps(x, ensure_ascii=False),
            "upper": lambda s: str(s).upper(),
            "lower": lambda s: str(s).lower(),
            "title": lambda s: str(s).title(),
            "trim": lambda s: str(s).strip(),
        })

    @lru_cache(maxsize=256)
    def _compile(self, template: str):
        return self._jinja_env.from_string(template)

    def render(self, template: str, context: Mapping[str, Any], options: RenderOptions) -> str:
        t = self._compile(template)
        text = t.render(**dict(context))
        return _normalize_text(text, options)

    def required_vars(self, template: str) -> Tuple[str, ...]:
        ast = self._jinja_env.parse(template)
        # undeclared variables — это используемые имя-переменные
        names = tuple(sorted(self._jinja_meta.find_undeclared_variables(ast)))
        return names

def _select_engine(engine: str | None) -> TemplateEngine:
    name = (engine or "builtin").lower()
    if name == "builtin":
        return BuiltinEngine()
    if name == "jinja":
        try:
            return JinjaEngine()
        except InvalidTemplate as e:
            raise InvalidTemplate("Jinja2 engine requested but not available") from e
    raise InvalidTemplate(f"unknown engine '{engine}'")

# =====================================================================
# Шаблоны
# =====================================================================

@dataclass(frozen=True)
class PromptTemplate:
    content: str
    meta: TemplateMeta
    engine: str = "builtin"
    required: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self):
        # Авто-извлечение обязательных переменных при инициализации
        object.__setattr__(self, "required", self.required or _select_engine(self.engine).required_vars(self.content))

    def fingerprint(self) -> str:
        return _stable_hash(self.meta.name, self.meta.version, self.meta.locale or "-", self.engine, self.content)

    def validate(self, context: Mapping[str, Any]) -> None:
        missing = [k for k in self.required if k not in context]
        if missing:
            raise MissingVariable(f"missing variables: {', '.join(missing)}")

    def render(self, context: Mapping[str, Any], *, options: Optional[RenderOptions] = None) -> str:
        self.validate(context)
        eng = _select_engine(self.engine)
        text = eng.render(self.content, context, options or RenderOptions())
        return text

@dataclass(frozen=True)
class ChatPartTemplate:
    role: str
    template: PromptTemplate
    # Простое условие отображения: ключ должен существовать и быть truthy
    when_key_truthy: Optional[str] = None

    def should_include(self, context: Mapping[str, Any]) -> bool:
        if not self.when_key_truthy:
            return True
        v = context.get(self.when_key_truthy)
        return bool(v)

@dataclass(frozen=True)
class ChatTemplate:
    meta: TemplateMeta
    parts: Tuple[ChatPartTemplate, ...]
    engine: str = "builtin"

    def render(self, context: Mapping[str, Any], *, options: Optional[RenderOptions] = None) -> List[ChatMessage]:
        msgs: List[ChatMessage] = []
        for part in self.parts:
            if not part.should_include(context):
                continue
            # Принудительно используем движок части (если отличается от ChatTemplate.engine)
            tpl = part.template
            text = tpl.render(context, options=options)
            if text == "":
                continue
            msgs.append(ChatMessage(role=part.role, content=text))
        return msgs

    def fingerprint(self) -> str:
        h = hashlib.sha256()
        h.update(self.meta.name.encode())
        h.update(self.meta.version.encode())
        h.update((self.meta.locale or "-").encode())
        for p in self.parts:
            h.update(p.role.encode())
            h.update(p.template.fingerprint().encode())
        return h.hexdigest()

# =====================================================================
# Регистр шаблонов
# =====================================================================

Key = Tuple[str, str, Optional[str]]  # (name, version, locale)

class PromptRegistry:
    """
    Памятный регистр шаблонов. Потокобезопасность не обеспечивается — предполагается
    использование на этапе загрузки приложения.
    """
    def __init__(self) -> None:
        self._prompts: Dict[Key, PromptTemplate] = {}
        self._chats: Dict[Key, ChatTemplate] = {}

    @staticmethod
    def _key(meta_or_name: Union[TemplateMeta, str], version: Optional[str] = None, locale: Optional[str] = None) -> Key:
        if isinstance(meta_or_name, TemplateMeta):
            return (meta_or_name.name, meta_or_name.version, meta_or_name.locale)
        if version is None:
            raise RegistryError("version is required when keying by name")
        return (meta_or_name, version, locale)

    def register_prompt(self, tpl: PromptTemplate) -> None:
        k = self._key(tpl.meta)
        if k in self._prompts:
            raise RegistryError(f"prompt already registered: {k}")
        self._prompts[k] = tpl

    def register_chat(self, chat: ChatTemplate) -> None:
        k = self._key(chat.meta)
        if k in self._chats:
            raise RegistryError(f"chat template already registered: {k}")
        self._chats[k] = chat

    def get_prompt(self, name: str, version: str, locale: Optional[str] = None) -> PromptTemplate:
        k = (name, version, locale)
        if k not in self._prompts:
            raise RegistryError(f"prompt not found: {k}")
        return self._prompts[k]

    def get_chat(self, name: str, version: str, locale: Optional[str] = None) -> ChatTemplate:
        k = (name, version, locale)
        if k not in self._chats:
            raise RegistryError(f"chat template not found: {k}")
        return self._chats[k]

    def list_prompts(self) -> List[TemplateMeta]:
        return [p.meta for p in self._prompts.values()]

    def list_chats(self) -> List[TemplateMeta]:
        return [c.meta for c in self._chats.values()]

    # Загрузка из файлов .json / .yaml (если PyYAML установлен)
    def load_from_path(self, root: str) -> None:
        """
        Ожидаемые структуры:
          - prompt: {"type":"prompt","engine":"builtin|jinja","meta":{...},"content":"..."}
          - chat:   {"type":"chat","engine":"...","meta":{...},"parts":[{"role":"user","engine":"...","content":"...","when_key_truthy":"optional"}]}
        """
        import pathlib
        p = pathlib.Path(root)
        if not p.exists():
            raise RegistryError(f"path not found: {root}")
        for file in p.rglob("*"):
            if not file.is_file():
                continue
            if file.suffix.lower() in (".json", ".yaml", ".yml"):
                try:
                    data = _load_structured_file(str(file))
                    _register_from_dict(self, data)
                except Exception as e:
                    logger.warning("skip %s: %s", file, e)

def _load_structured_file(path: str) -> Mapping[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if path.endswith(".json"):
        return json.loads(text)
    # yaml — если доступен PyYAML
    try:
        import yaml  # type: ignore
    except Exception as e:
        raise RegistryError("PyYAML is not installed, cannot read YAML") from e
    return yaml.safe_load(text)

def _register_from_dict(reg: PromptRegistry, data: Mapping[str, Any]) -> None:
    t = (data.get("type") or "").lower()
    engine = (data.get("engine") or "builtin")
    meta_raw = data.get("meta") or {}
    meta = TemplateMeta(
        name=meta_raw.get("name"),
        version=meta_raw.get("version", "1.0.0"),
        locale=meta_raw.get("locale"),
        description=meta_raw.get("description"),
        tags=tuple(meta_raw.get("tags") or ()),
    )
    if t == "prompt":
        content = data.get("content", "")
        tpl = PromptTemplate(content=content, meta=meta, engine=engine)
        reg.register_prompt(tpl)
        return
    if t == "chat":
        parts_data = data.get("parts") or []
        parts: List[ChatPartTemplate] = []
        for pd in parts_data:
            p_engine = pd.get("engine") or engine
            p_meta = TemplateMeta(name=f"{meta.name}.{pd.get('role')}", version=meta.version, locale=meta.locale)
            pt = PromptTemplate(content=pd.get("content", ""), meta=p_meta, engine=p_engine)
            parts.append(ChatPartTemplate(role=pd.get("role"), template=pt, when_key_truthy=pd.get("when_key_truthy")))
        chat = ChatTemplate(meta=meta, parts=tuple(parts), engine=engine)
        reg.register_chat(chat)
        return
    raise RegistryError("unknown template type (expected 'prompt' or 'chat')")

# =====================================================================
# Примитивный «builder» для быстрого описания чат-шаблонов кодом
# =====================================================================

def chat_template(
    name: str,
    *,
    version: str = "1.0.0",
    locale: Optional[str] = None,
    system: Optional[str] = None,
    user: Optional[str] = None,
    assistant: Optional[str] = None,
    engine: str = "builtin",
    description: Optional[str] = None,
) -> ChatTemplate:
    parts: List[ChatPartTemplate] = []
    meta = TemplateMeta(name=name, version=version, locale=locale, description=description)
    if system:
        parts.append(ChatPartTemplate(role=Role.system, template=PromptTemplate(system, TemplateMeta(f"{name}.system", version, locale), engine)))
    if user:
        parts.append(ChatPartTemplate(role=Role.user, template=PromptTemplate(user, TemplateMeta(f"{name}.user", version, locale), engine)))
    if assistant:
        parts.append(ChatPartTemplate(role=Role.assistant, template=PromptTemplate(assistant, TemplateMeta(f"{name}.assistant", version, locale), engine)))
    return ChatTemplate(meta=meta, parts=tuple(parts), engine=engine)

# =====================================================================
# Пример готовых шаблонов (можно использовать как дефолтные)
# =====================================================================

DEFAULT_REGISTRY = PromptRegistry()

DEFAULT_REGISTRY.register_chat(
    chat_template(
        "generic.chat",
        system="You are a helpful assistant. Time: {now}.",
        user="{query}",
        version="1.0.0",
        engine="builtin",
        description="Базовый чат-шаблон для простых запросов",
    )
)

# =====================================================================
# Высокоуровневые удобные функции
# =====================================================================

def render_prompt(
    template: Union[PromptTemplate, str],
    context: Mapping[str, Any],
    *,
    meta: Optional[TemplateMeta] = None,
    engine: str = "builtin",
    options: Optional[RenderOptions] = None,
) -> str:
    """
    Быстрый рендер строки. Если передана raw-строка, будет создан PromptTemplate на лету.
    """
    if isinstance(template, PromptTemplate):
        tpl = template
    else:
        if meta is None:
            meta = TemplateMeta(name="adhoc.prompt", version="1.0.0")
        tpl = PromptTemplate(content=str(template), meta=meta, engine=engine)
    try:
        text = tpl.render({**context, "now": _now_iso()}, options=options)
        return text
    except TemplateError:
        raise
    except Exception as e:
        raise TemplateError(str(e)) from e

def render_chat(
    template: Union[ChatTemplate, str],
    context: Mapping[str, Any],
    *,
    registry: PromptRegistry = DEFAULT_REGISTRY,
    version: str = "1.0.0",
    locale: Optional[str] = None,
    engine: str = "builtin",
    options: Optional[RenderOptions] = None,
) -> List[ChatMessage]:
    """
    Быстрый рендер чат-сообщений.
    Если template — строка с именем ChatTemplate, будет получен из реестра.
    """
    if isinstance(template, ChatTemplate):
        chat = template
    else:
        chat = registry.get_chat(str(template), version, locale)
    ctx = {**context, "now": _now_iso()}
    try:
        msgs = chat.render(ctx, options=options)
        return msgs
    except TemplateError:
        raise
    except Exception as e:
        raise TemplateError(str(e)) from e

# =====================================================================
# Безопасное логирование контекста
# =====================================================================

def safe_context_for_log(ctx: Mapping[str, Any]) -> Mapping[str, Any]:
    return redact_secrets(ctx)

# =====================================================================
# Экспорт
# =====================================================================

__all__ = [
    # модели
    "TemplateMeta",
    "RenderOptions",
    "ChatMessage",
    "Role",
    # исключения
    "TemplateError",
    "MissingVariable",
    "RenderLimitExceeded",
    "InvalidTemplate",
    "RegistryError",
    # движки/шаблоны
    "PromptTemplate",
    "ChatPartTemplate",
    "ChatTemplate",
    "TemplateEngine",
    "BuiltinEngine",
    "JinjaEngine",
    # регистр
    "PromptRegistry",
    "DEFAULT_REGISTRY",
    # утилиты
    "render_prompt",
    "render_chat",
    "safe_context_for_log",
]
