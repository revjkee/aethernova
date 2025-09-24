# -*- coding: utf-8 -*-
"""
Mythos Core — Context Assembly for LLMs (industrial)

Назначение:
    Собирает «рабочий» контекст (messages + tools + citations) для вызова LLM с учётом:
    - системных инструкций/политик (system prompt / policy preamble)
    - окна диалога (последние ходы) и памяти (summary)
    - RAG-сниппетов с цитированием (retriever)
    - схемы инструментов (function calling / tools)
    - модерации и очистки PII
    - строгого бюджета по токенам и поэтапного ужатия
    - стабильного fingerprint для кэширования

Зависимости:
    Только стандартная библиотека Python 3.11+. Внешние реализации подключаются через протоколы.

Автор: Aethernova / Mythos Core Team
"""

from __future__ import annotations

import abc
import dataclasses
import hashlib
import json
import math
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import (
    Any,
    Deque,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
)

__all__ = [
    "Message",
    "Attachment",
    "ToolSpec",
    "Citation",
    "RAGSnippet",
    "TokenCount",
    "TokenCounter",
    "Retriever",
    "Summarizer",
    "ModerationFilter",
    "SafetyConfig",
    "BudgetConfig",
    "BuildDiagnostics",
    "BuiltContext",
    "ContextBuilder",
]


# =========================
# DTO / Core structures
# =========================

@dataclass(frozen=True)
class Message:
    """
    Единица контекста для LLM API (согласовано с OpenAI/Anthropic стилем).
    role: "system" | "user" | "assistant" | "tool"
    """
    role: str
    content: str
    name: Optional[str] = None
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclass(frozen=True)
class Attachment:
    """
    Лёгкая ссылка на вложение (например, превью, hash или путь в объектном хранилище).
    На этапе ужатия attachments отбрасываются первыми.
    """
    kind: str                   # "image"|"doc"|"code"|"other"
    ref: str                    # URI/ID/sha
    caption: Optional[str] = None


@dataclass(frozen=True)
class ToolSpec:
    """
    Схема инструмента для function calling. Хранится как agnostic JSON Schema.
    """
    name: str
    description: str
    parameters: Mapping[str, Any]


@dataclass(frozen=True)
class Citation:
    source_id: str
    title: Optional[str] = None
    url: Optional[str] = None
    locator: Optional[str] = None
    snippet: Optional[str] = None
    score: Optional[float] = None


@dataclass(frozen=True)
class RAGSnippet:
    text: str
    citations: Tuple[Citation, ...] = tuple()


@dataclass(frozen=True)
class TokenCount:
    """
    Унифицированная оценка токенов.
    """
    input_tokens: int
    output_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens


# =========================
# Protocols (plug-in points)
# =========================

class TokenCounter(Protocol):
    """
    Контракт счётчика токенов. Реализация может оборачивать tiktoken/transformers/вендорные SDK.
    """
    def count_messages(self, model: str, messages: Sequence[Message]) -> TokenCount: ...
    def count_text(self, model: str, text: str) -> int: ...


class Retriever(Protocol):
    """
    Контракт RAG-ретривера.
    """
    def retrieve(self, query: str, top_k: int = 6, min_score: float = 0.0) -> List[RAGSnippet]: ...


class Summarizer(Protocol):
    """
    Контракт свёртки истории при нехватке бюджета.
    """
    def summarize(self, turns: Sequence[Message], max_chars: int = 1200) -> str: ...


class ModerationFilter(Protocol):
    """
    Контракт модерации/PII-очистки. Возвращает очищенный текст и признак блокировки.
    """
    def scrub(self, text: str) -> Tuple[str, bool]: ...


# =========================
# Defaults (safe fallbacks)
# =========================

class NaiveTokenCounter:
    """
    Безопасный fallback: считает токены как ceil(len(chars)/4), типичный порядок для English/ru.
    Не точен, но стабилен для бюджетирования.
    """
    def __init__(self, chars_per_token: float = 4.0) -> None:
        self._cpt = max(1e-6, float(chars_per_token))

    def count_messages(self, model: str, messages: Sequence[Message]) -> TokenCount:
        size = sum(len(m.content) for m in messages)
        return TokenCount(input_tokens=int(math.ceil(size / self._cpt)))

    def count_text(self, model: str, text: str) -> int:
        return int(math.ceil(len(text) / self._cpt))


class BasicPIIModeration:
    """
    Лёгкая PII/тонирование текста регулярками. Не заменяет полноценную модерацию.
    """
    EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
    PHONE = re.compile(r"\b(?:\+?\d{1,3}[\s\-]?)?(?:\(?\d{2,4}\)?[\s\-]?)?\d{3}[\s\-]?\d{2,4}[\s\-]?\d{2,4}\b")
    IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    CREDIT = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

    def __init__(self, placeholder: str = "[REDACTED]") -> None:
        self.placeholder = placeholder

    def scrub(self, text: str) -> Tuple[str, bool]:
        redacted = text
        redacted = self.EMAIL.sub(self.placeholder, redacted)
        redacted = self.PHONE.sub(self.placeholder, redacted)
        redacted = self.IPV4.sub(self.placeholder, redacted)
        redacted = self.CREDIT.sub(self.placeholder, redacted)
        blocked = False
        return redacted, blocked


# =========================
# Configs & Results
# =========================

@dataclass(frozen=True)
class SafetyConfig:
    """
    Политики безопасности для сборки контекста (ввод/источники).
    """
    pii_filter: ModerationFilter = field(default_factory=BasicPIIModeration)
    ban_patterns: Tuple[re.Pattern, ...] = field(default_factory=tuple)
    redact_placeholder: str = "[REDACTED]"

    def apply(self, text: str) -> Tuple[str, bool]:
        t, blocked = self.pii_filter.scrub(text)
        if blocked:
            return t, True
        # Блокирующие паттерны (например, jailbreak)
        for p in self.ban_patterns:
            if p.search(t):
                return t, True
        return t, False


@dataclass(frozen=True)
class BudgetConfig:
    """
    Параметры бюджетирования токенов.
    """
    model: str
    max_input_tokens: int
    reserve_output_tokens: int = 800  # защитный резерв под ответ модели
    max_rag_snippets: int = 4
    max_citations_per_snippet: int = 2
    summary_max_chars: int = 1200


@dataclass(frozen=True)
class BuildDiagnostics:
    """
    Отладочные метрики процесса сборки.
    """
    started_at: float
    finished_at: float
    steps: Tuple[str, ...]
    tokens_before: int
    tokens_after: int
    reductions: Tuple[str, ...]
    rag_used: int
    citations_total: int
    fingerprint: str


@dataclass(frozen=True)
class BuiltContext:
    """
    Готовый к отправке контекст.
    """
    messages: Tuple[Message, ...]
    tools: Tuple[ToolSpec, ...]
    citations: Tuple[Citation, ...]
    token_count: TokenCount
    budget: BudgetConfig
    diagnostics: BuildDiagnostics


# =========================
# ContextBuilder
# =========================

class ContextBuilder:
    """
    Фасад для пошаговой сборки контекста LLM с управлением бюджетом и безопасностью.

    Сценарий использования:
        builder = ContextBuilder(budget, counter=..., retriever=..., summarizer=...)
        builder.add_system("Политика/роль ассистента")
        builder.add_preamble("Важные правила...")
        builder.add_memory("Краткое summary предыдущего диалога")
        builder.add_dialogue(turns)  # список Message
        builder.add_rag(query="...", enabled=True)
        builder.add_tools(tool_specs)
        ctx = builder.build()
    """

    def __init__(
        self,
        budget: BudgetConfig,
        *,
        counter: Optional[TokenCounter] = None,
        safety: Optional[SafetyConfig] = None,
        retriever: Optional[Retriever] = None,
        summarizer: Optional[Summarizer] = None,
        enable_function_calling: bool = True,
    ) -> None:
        self._budget = budget
        self._counter = counter or NaiveTokenCounter()
        self._safety = safety or SafetyConfig()
        self._retriever = retriever
        self._summarizer = summarizer
        self._enable_fc = bool(enable_function_calling)

        # Буферные контейнеры
        self._system: Deque[Message] = deque()
        self._preamble: Deque[Message] = deque()
        self._memory: Optional[Message] = None
        self._dialogue: Deque[Message] = deque()
        self._attachments: List[Attachment] = []
        self._tools: List[ToolSpec] = []
        self._rag_snippets: List[RAGSnippet] = []

        # Диагностика
        self._steps: List[str] = []
        self._reductions: List[str] = []

    # ------- Вкладки контента -------

    def add_system(self, text: str, *, name: Optional[str] = None) -> "ContextBuilder":
        clean, blocked = self._safety.apply(text)
        if not blocked:
            self._system.append(Message("system", clean, name=name))
            self._steps.append("add_system")
        return self

    def add_preamble(self, text: str) -> "ContextBuilder":
        if not text:
            return self
        clean, blocked = self._safety.apply(text)
        if not blocked:
            self._preamble.append(Message("system", clean))
            self._steps.append("add_preamble")
        return self

    def add_memory(self, summary_text: Optional[str]) -> "ContextBuilder":
        if not summary_text:
            return self
        clean, blocked = self._safety.apply(summary_text)
        if not blocked:
            self._memory = Message("system", f"[memory]\n{clean}")
            self._steps.append("add_memory")
        return self

    def add_dialogue(self, turns: Iterable[Message]) -> "ContextBuilder":
        for m in turns:
            # принимаем только допустимые роли
            if m.role not in {"user", "assistant", "tool"}:
                continue
            clean, blocked = self._safety.apply(m.content)
            if blocked:
                # Если модерация блокирует — заменим контент маркером
                clean = f"{self._safety.redact_placeholder}"
            self._dialogue.append(Message(m.role, clean, name=m.name, metadata=m.metadata))
        self._steps.append("add_dialogue")
        return self

    def add_tools(self, tools: Iterable[ToolSpec]) -> "ContextBuilder":
        if not self._enable_fc:
            return self
        self._tools.extend(tools)
        self._steps.append("add_tools")
        return self

    def add_attachments(self, items: Iterable[Attachment]) -> "ContextBuilder":
        self._attachments.extend(items)
        self._steps.append("add_attachments")
        return self

    def add_rag(self, *, query: Optional[str], top_k: Optional[int] = None, min_score: float = 0.0) -> "ContextBuilder":
        if not query or not self._retriever:
            return self
        k = min(self._budget.max_rag_snippets, max(1, top_k or self._budget.max_rag_snippets))
        snippets = self._retriever.retrieve(query=query, top_k=k, min_score=min_score) or []
        # обрежем цитаты на уровне сниппета
        normalized: List[RAGSnippet] = []
        for sn in snippets[: self._budget.max_rag_snippets]:
            cits = tuple(sn.citations[: self._budget.max_citations_per_snippet]) if sn.citations else tuple()
            normalized.append(RAGSnippet(text=sn.text, citations=cits))
        self._rag_snippets = normalized
        self._steps.append("add_rag")
        return self

    # ------- Сборка / бюджетирование -------

    def _compose_messages(self) -> List[Message]:
        msgs: List[Message] = []
        msgs.extend(list(self._system))
        msgs.extend(list(self._preamble))
        if self._memory:
            msgs.append(self._memory)

        # Встраиваем RAG как отдельный system-блок (чтобы не путать с ответами ассистента)
        if self._rag_snippets:
            sources = []
            flat_citations: List[Citation] = []
            for sn in self._rag_snippets:
                sources.append(f"- {sn.text}")
                flat_citations.extend(list(sn.citations))
            rag_block = "Доступные выдержки из источников:\n" + "\n".join(sources)
            msgs.append(Message("system", rag_block))
            # сохраним для диагностики/итога
            self._flat_citations = tuple(flat_citations)
        else:
            self._flat_citations = tuple()

        msgs.extend(list(self._dialogue))
        return msgs

    def _count(self, messages: Sequence[Message]) -> TokenCount:
        return self._counter.count_messages(self._budget.model, messages)

    def _shrink_until_fits(self, messages: List[Message]) -> Tuple[List[Message], Tuple[str, ...]]:
        """
        Пошаговое ужатие, пока не войдём в бюджет:
          1) убрать attachments (они учитываются вне messages — метаданные)
          2) сократить количество RAG-сниппетов/цитат (если >1)
          3) свёртка старых ходов в summary (если есть summarizer)
          4) усечение самых старых ходов
        """
        reductions: List[str] = []
        max_input = self._budget.max_input_tokens - max(0, self._budget.reserve_output_tokens)
        if max_input <= 0:
            return messages, tuple(reductions)

        def fits(msgs: Sequence[Message]) -> bool:
            return self._count(msgs).input_tokens <= max_input

        # Быстрый успех
        if fits(messages):
            return messages, tuple(reductions)

        # 1) attachments: просто отметим как отброшенные
        if self._attachments:
            self._attachments.clear()
            reductions.append("drop_attachments")
            if fits(messages):
                return messages, tuple(reductions)

        # 2) уменьшить RAG-блок (если присутствует среди system)
        if self._rag_snippets:
            step = max(1, len(self._rag_snippets) // 2)
            while self._rag_snippets and not fits(messages):
                self._rag_snippets = self._rag_snippets[:-step]
                # перегенерируем system RAG-блок
                msgs = []
                for m in messages:
                    if m.content.startswith("Доступные выдержки из источников:"):
                        # пропустим — восстановим ниже
                        continue
                    msgs.append(m)
                if self._rag_snippets:
                    sources = [f"- {sn.text}" for sn in self._rag_snippets]
                    msgs.insert(
                        len(self._system) + len(self._preamble) + (1 if self._memory else 0),
                        Message("system", "Доступные выдержки из источников:\n" + "\n".join(sources)),
                    )
                messages = msgs
            reductions.append("shrink_rag")
            if fits(messages):
                return messages, tuple(reductions)

        # 3) свёртка старых ходов
        if self._summarizer and len(self._dialogue) > 4:
            head = list(self._dialogue)[:-4]  # оставим последние 4 хода
            if head:
                summary_text = self._summarizer.summarize(head, max_chars=self._budget.summary_max_chars)
                # заменяем head единым summary-блоком
                msgs = []
                dropped = False
                for m in messages:
                    if not dropped and m in head:
                        continue
                    msgs.append(m)
                messages = msgs
                messages.insert(
                    len(self._system) + len(self._preamble) + (1 if self._memory else 0),
                    Message("system", f"[summary]\n{summary_text}"),
                )
                reductions.append("summarize_history")
                if fits(messages):
                    return messages, tuple(reductions)

        # 4) усечение самых старых ходов
        while len(messages) > 1 and not fits(messages):
            # Ищем самый ранний user/assistant блок после системных
            sys_len = len(self._system) + len(self._preamble) + (1 if self._memory else 0)
            # не трогаем первый системный блок
            cut_idx = None
            for i in range(sys_len, len(messages)):
                if messages[i].role in {"user", "assistant", "tool"}:
                    cut_idx = i
                    break
            if cut_idx is None:
                break
            messages.pop(cut_idx)
            reductions.append("drop_earliest_turn")
        return messages, tuple(reductions)

    # ------- Build -------

    def build(self) -> BuiltContext:
        t0 = time.time()

        # 1) слои → messages
        messages = self._compose_messages()

        # 2) подсчёт «до»
        before = self._count(messages).input_tokens

        # 3) ужатие до бюджета
        messages, reductions = self._shrink_until_fits(messages)

        # 4) итоговый подсчёт
        tc = self._count(messages)
        t1 = time.time()

        # 5) финальный fingerprint
        fp_payload = {
            "model": self._budget.model,
            "messages": [dataclasses.asdict(m) for m in messages],
            "tools": [dataclasses.asdict(t) for t in self._tools] if self._enable_fc else [],
            "cit": [dataclasses.asdict(c) for c in getattr(self, "_flat_citations", tuple())],
        }
        fp = hashlib.sha256(json.dumps(fp_payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()

        diag = BuildDiagnostics(
            started_at=t0,
            finished_at=t1,
            steps=tuple(self._steps),
            tokens_before=before,
            tokens_after=tc.input_tokens,
            reductions=reductions,
            rag_used=len(self._rag_snippets),
            citations_total=len(getattr(self, "_flat_citations", tuple())),
            fingerprint=fp,
        )

        return BuiltContext(
            messages=tuple(messages),
            tools=tuple(self._tools) if self._enable_fc else tuple(),
            citations=getattr(self, "_flat_citations", tuple()),
            token_count=tc,
            budget=self._budget,
            diagnostics=diag,
        )


# =========================
# Example / Reference usage
# =========================

if __name__ == "__main__":  # пример локальной проверки без внешних зависимостей
    # Настройка бюджета (пример: GPT-класс с 128k контекстом)
    budget = BudgetConfig(model="gpt-4o-mini", max_input_tokens=32000, reserve_output_tokens=1000)

    # Инициализация билдера со стандартными безопасными фолбэками
    builder = ContextBuilder(budget)

    # Системные инструкции/политики (упрощённый пример)
    builder.add_system("Ты — точный и лаконичный ассистент Mythos. Говори на языке пользователя.")
    builder.add_preamble("Соблюдай политику безопасности и канон. Если факт не подтверждён: I cannot verify this.")

    # Память/summary
    builder.add_memory("Пользователь интересуется лором вселенной Mythos; предпочитает краткие ответы.")

    # Диалог (окно из последних ходов)
    builder.add_dialogue(
        [
            Message("user", "Кто такой Адраст из эпохи Mythos Zero?"),
            Message("assistant", "Адраст — рыцарь Стражи, известный походом на север."),
        ]
    )

    # Инструменты (function calling)
    builder.add_tools(
        [
            ToolSpec(
                name="retrieve_documents",
                description="Поиск фрагментов канона",
                parameters={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
            )
        ]
    )

    # Сборка
    built = builder.build()
    print("Messages:", len(built.messages))
    print("Tokens (in):", built.token_count.input_tokens)
    print("Fingerprint:", built.diagnostics.fingerprint[:16])
