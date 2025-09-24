# engine-core/engine/tests/conformance/test_determinism_replay.py
# Конформационные тесты детерминизма реплея.
# Требования: pytest, pytest-asyncio
#
# По умолчанию тест ищет сессию:
#   ./tests/sessions/market_scene.jsonl.gz
# Можно переопределить путём установки переменной окружения:
#   REPLAY_SESSION=/abs/path/to/session.jsonl[.gz|.xz]
#
# Реплей берётся из: engine.tools.replay_session (из этого репозитория).
# Мы используем внутренний API (ReplayConfig, replay) для точного контроля
# над временем и приёмником (sink).

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

# --- Импорт SUT ---
try:
    from engine.tools.replay_session import ReplayConfig, replay  # type: ignore
except Exception as e:  # pragma: no cover
    pytest.skip(f"Не удалось импортировать engine.tools.replay_session: {e}", allow_module_level=True)


# --- Константы и локаторы ---
DEFAULT_SESSION = Path("tests/sessions/market_scene.jsonl.gz")
SESSION_PATH = Path(os.environ.get("REPLAY_SESSION", str(DEFAULT_SESSION))).resolve()


# --- Утилиты канонизации и хеширования ---
def canon_json_bytes(obj: Any) -> bytes:
    """Канонический JSON (UTF-8, сортировка ключей, компактный сепаратор)."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256_hex(blobs: List[bytes]) -> str:
    h = hashlib.sha256()
    for b in blobs:
        h.update(b)
    return h.hexdigest()


# --- Вспомогательный sink для захвата событий ---
class CaptureSink:
    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []

    async def emit(self, event: Dict[str, Any]) -> None:
        # Сохраняем только канонизованный JSON как dict; проверка идёт по хешу ниже
        self.items.append(event)

    async def close(self) -> None:
        # Ничего не требуется
        await asyncio.sleep(0)


# --- Фикстуры ---
@pytest.fixture(scope="session")
def session_file() -> Path:
    if not SESSION_PATH.exists():
        pytest.skip(f"Файл сессии не найден: {SESSION_PATH}")
    return SESSION_PATH


# --- Тесты детерминизма ---

@pytest.mark.asyncio
async def test_replay_is_bitwise_deterministic_across_speeds(session_file: Path):
    """
    При изменении скорости и отключении сна последовательность событий на выходе
    должна оставаться идентичной (считаем, что сами события независимы от реального времени).
    """
    cap1 = CaptureSink()
    cfg1 = ReplayConfig(
        input=session_file,
        sink=cap1,
        speed=1.0,
        no_sleep=True,          # без сна — чистая логика
        from_ts=None,
        to_ts=None,
        offset=0,
        filter_expr=None,
        selector=None,
        require_checksum=False,
        strict=True,
        metrics_json=None,
    )
    cap2 = CaptureSink()
    cfg2 = ReplayConfig(
        input=session_file,
        sink=cap2,
        speed=7.5,              # сильно быстрее
        no_sleep=True,          # одинаковая семантика
        from_ts=None,
        to_ts=None,
        offset=0,
        filter_expr=None,
        selector=None,
        require_checksum=False,
        strict=True,
        metrics_json=None,
    )

    m1, m2 = await replay(cfg1), await replay(cfg2)
    # Сравнение количества
    assert m1.emitted == m2.emitted > 0, "Количество эмиттованных событий должно совпадать и быть > 0"

    # Канонизованный поток → SHA-256
    blob1 = [canon_json_bytes(e) for e in cap1.items]
    blob2 = [canon_json_bytes(e) for e in cap2.items]
    assert sha256_hex(blob1) == sha256_hex(blob2), "Выходной поток должен быть бит‑в‑бит одинаковым при разной скорости"


@pytest.mark.asyncio
async def test_replay_time_window_is_stable_and_subset(session_file: Path):
    """
    Окно времени (from/to) должно давать стабильный поднабор полного потока.
    """
    # Полный прогон
    cap_full = CaptureSink()
    cfg_full = ReplayConfig(input=session_file, sink=cap_full, speed=1.0, no_sleep=True)
    await replay(cfg_full)

    # Берём границы по отметкам первого/последнего события
    first_ts = cap_full.items[0]["ts"]
    last_ts = cap_full.items[-1]["ts"]

    # Подокно (выкинем по 10% с каждой стороны, если возможно)
    def _num(x):  # ts может быть float или ISO string
        return float(x) if isinstance(x, (int, float)) else None

    f_num = _num(first_ts)
    l_num = _num(last_ts)
    if f_num is None or l_num is None or l_num <= f_num:
        pytest.skip("Метка времени не числовая или некорректна для выбора окна")

    span = l_num - f_num
    w_from = f_num + 0.1 * span
    w_to = l_num - 0.1 * span

    cap_win = CaptureSink()
    cfg_win = ReplayConfig(
        input=session_file, sink=cap_win, speed=3.0, no_sleep=True,
        from_ts=w_from, to_ts=w_to
    )
    await replay(cfg_win)

    # Подокно — подмножество полного потока и стабильно по хешу
    full_hex = sha256_hex([canon_json_bytes(e) for e in cap_full.items])
    win_hex = sha256_hex([canon_json_bytes(e) for e in cap_win.items])

    # Каждое событие из окна присутствует в полном наборе (по каноничному JSON)
    full_set = {canon_json_bytes(e) for e in cap_full.items}
    for e in cap_win.items:
        assert canon_json_bytes(e) in full_set

    # Стабильность повторного окна
    cap_win2 = CaptureSink()
    await replay(ReplayConfig(
        input=session_file, sink=cap_win2, speed=0.5, no_sleep=True,
        from_ts=w_from, to_ts=w_to
    ))
    win_hex2 = sha256_hex([canon_json_bytes(e) for e in cap_win2.items])
    assert win_hex == win_hex2, "Окно должно давать стабильный результат независимо от скорости"
    assert len(cap_win.items) <= len(cap_full.items)
    assert full_hex != win_hex or len(cap_win.items) != len(cap_full.items)  # чаще всего окно меньше полного


@pytest.mark.asyncio
async def test_resume_offset_produces_suffix_of_stream(session_file: Path):
    """
    Возобновление с offset=N должно давать суффикс полного потока (бит‑в‑бит для остатка).
    """
    cap_all = CaptureSink()
    await replay(ReplayConfig(input=session_file, sink=cap_all, speed=1.0, no_sleep=True))

    if len(cap_all.items) < 5:
        pytest.skip("Недостаточно событий для проверки offset")

    offset = len(cap_all.items) // 3  # треть лога
    cap_off = CaptureSink()
    await replay(ReplayConfig(input=session_file, sink=cap_off, speed=1.0, no_sleep=True, offset=offset))

    # Сравнение суффикса
    tail_full = [canon_json_bytes(e) for e in cap_all.items[offset:]]
    tail_off = [canon_json_bytes(e) for e in cap_off.items]
    assert sha256_hex(tail_full) == sha256_hex(tail_off), "Поток от offset должен совпадать с суффиксом полного"


@pytest.mark.asyncio
async def test_checksum_verification_behaviour(session_file: Path):
    """
    При включенном require_checksum события без поля checksum отфильтровываются.
    Если все события в трейсе без checksum — тест пометится skip.
    """
    # Реплей без требований к checksum
    cap_any = CaptureSink()
    m_any = await replay(ReplayConfig(input=session_file, sink=cap_any, speed=1.0, no_sleep=True, require_checksum=False))

    # Реплей с требованием checksum
    cap_req = CaptureSink()
    m_req = await replay(ReplayConfig(input=session_file, sink=cap_req, speed=1.0, no_sleep=True, require_checksum=True))

    if m_any.emitted == 0:
        pytest.skip("Сессия не содержит событий")

    if m_req.emitted == 0 and m_any.emitted > 0:
        # Допускаем полную фильтрацию, если в трейсе нет checksum
        pytest.skip("В трейсе нет событий с checksum — поведение корректно (все отброшены)")

    # Иначе ожидаем, что подмножество с checksum не расширяет множество без него
    assert m_req.emitted <= m_any.emitted
    # А поток при повторном запуске детерминирован
    cap_req2 = CaptureSink()
    m_req2 = await replay(ReplayConfig(input=session_file, sink=cap_req2, speed=4.0, no_sleep=True, require_checksum=True))
    assert m_req.emitted == m_req2.emitted
    assert sha256_hex([canon_json_bytes(e) for e in cap_req.items]) == sha256_hex([canon_json_bytes(e) for e in cap_req2.items])
