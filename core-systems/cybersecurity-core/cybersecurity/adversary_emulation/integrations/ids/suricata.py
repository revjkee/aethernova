# -*- coding: utf-8 -*-
"""
suricata.py — промышленная интеграция с Suricata для adversary emulation.

Содержимое:
  - SuricataEveTail: надёжное чтение EVE JSON с поддержкой ротации.
  - SuricataEventFilter: декларативная фильтрация событий (точное/regex/кастом).
  - SuricataCommandClient: управление Suricata через Unix/TCP сокет (JSON RPC-подобный обмен).
  - SuricataRulesManager: атомарное обновление rule-файла с бэкапом/валидацией.
  - SuricataIntegration: фасад для типовых сценариев (watch_alerts, wait_for_alert, reload_rules).

Примечание:
  Модуль не делает внешних утверждений и не требует источников.
  Все опасные операции (правила, перезагрузка) вынесены в явные методы.
"""

from __future__ import annotations

import json
import io
import os
import re
import time
import socket
import errno
import threading
import logging
import tempfile
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Generator, Iterable, List, Optional, Pattern, Tuple, Union


# ----------------------------- ЛОГИ ------------------------------------------

def _default_logger(name: str = "suricata_integration") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(threadName)s :: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


log = _default_logger()


# ----------------------- УТИЛИТЫ / БЕЗОПАСНЫЙ JSON ---------------------------

def _safe_json_loads(line: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(line)
    except Exception as e:
        log.warning("JSON decode error: %s; line=%r", e, line[:512])
        return None


def _deep_get(obj: Dict[str, Any], dotted: str, default: Any = None) -> Any:
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


# ----------------------------- EVE TAIL --------------------------------------

@dataclass
class SuricataEveTail:
    """
    Устойчивое к ротации чтение EVE JSON.

    Параметры:
      path: путь к eve.json (или иному EVE-файлу).
      start_at_end: начать чтение с конца файла (по умолчанию True).
      poll_interval: интервал ожидания новых строк (сек).
      reopen_on_rotate: включить переоткрытие при ротации по inode/size.
      open_timeout: сколько ждать появления файла при старте (сек), 0 — не ждать.

    Метод:
      follow() -> генератор событий (dict).
    """
    path: Union[str, Path]
    start_at_end: bool = True
    poll_interval: float = 0.5
    reopen_on_rotate: bool = True
    open_timeout: float = 30.0

    _stop_evt: threading.Event = field(default_factory=threading.Event, init=False)

    def stop(self) -> None:
        self._stop_evt.set()

    def follow(self) -> Generator[Dict[str, Any], None, None]:
        path = Path(self.path)
        start_deadline = time.time() + self.open_timeout
        f: Optional[io.TextIOBase] = None
        inode: Optional[int] = None
        size: int = 0

        while not self._stop_evt.is_set():
            if f is None:
                if not path.exists():
                    if self.open_timeout > 0 and time.time() < start_deadline:
                        time.sleep(min(0.25, self.poll_interval))
                        continue
                    else:
                        raise FileNotFoundError(f"EVE file not found: {path}")
                f = path.open("r", encoding="utf-8", errors="replace")
                try:
                    st = path.stat()
                    inode = getattr(st, "st_ino", None)
                    size = st.st_size
                except Exception:
                    inode, size = None, 0
                if self.start_at_end:
                    f.seek(0, io.SEEK_END)

            line = f.readline()
            if not line:
                # Проверка ротации
                if self.reopen_on_rotate:
                    try:
                        st = path.stat()
                        cur_inode = getattr(st, "st_ino", None)
                        cur_size = st.st_size
                        rotated = (inode is not None and cur_inode is not None and cur_inode != inode) or (
                            cur_size < size
                        )
                        if rotated:
                            try:
                                f.close()
                            except Exception:
                                pass
                            f = path.open("r", encoding="utf-8", errors="replace")
                            inode = cur_inode
                            size = cur_size
                            log.info("EVE file rotated; reopened: %s", path)
                    except FileNotFoundError:
                        # В окне ротации — подождать
                        time.sleep(self.poll_interval)
                time.sleep(self.poll_interval)
                continue

            size += len(line)
            evt = _safe_json_loads(line)
            if evt is not None:
                yield evt


# -------------------------- ФИЛЬТР СОБЫТИЙ -----------------------------------

@dataclass
class SuricataEventFilter:
    """
    Декларативная фильтрация EVE-событий.

    Можно задать:
      equals: точные совпадения по пути "dot.path" -> значение/набор значений
      regex:  словарь "dot.path" -> регулярное выражение (str или compiled Pattern)
      any_of_event_types: список допустимых event_type (ускоряет отбраковку)
      custom: callable(event: dict) -> bool для произвольной логики

    match(evt) -> bool
    """
    equals: Dict[str, Union[Any, Iterable[Any]]] = field(default_factory=dict)
    regex: Dict[str, Union[str, Pattern[str]]] = field(default_factory=dict)
    any_of_event_types: Optional[Iterable[str]] = None
    custom: Optional[Callable[[Dict[str, Any]], bool]] = None

    _compiled_regex: Dict[str, Pattern[str]] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        for k, v in self.regex.items():
            if isinstance(v, str):
                self._compiled_regex[k] = re.compile(v)
            else:
                self._compiled_regex[k] = v  # assume Pattern

    def match(self, evt: Dict[str, Any]) -> bool:
        if self.any_of_event_types is not None:
            et = evt.get("event_type")
            if et not in set(self.any_of_event_types):
                return False

        for k, expected in self.equals.items():
            val = _deep_get(evt, k, None)
            if isinstance(expected, (list, tuple, set, frozenset)):
                if val not in expected:
                    return False
            else:
                if val != expected:
                    return False

        for k, rgx in self._compiled_regex.items():
            val = _deep_get(evt, k, "")
            if val is None or not isinstance(val, str) or rgx.search(val) is None:
                return False

        if self.custom:
            try:
                if not self.custom(evt):
                    return False
            except Exception as e:
                log.warning("Custom filter error: %s", e)
                return False

        return True


# ---------------------- КОМАНДНЫЙ КЛИЕНТ SURICATA ----------------------------

class SuricataCommandClient:
    """
    Клиент команд Suricata через Unix domain socket или TCP.

    Протокол обмена — JSON-объекты (строка запроса -> строка ответа).
    Конкретные команды передаются как dict, напр. {"command": "version"}.

    Примечание: путь сокета/host/port задаются извне, модуль не предполагает
    фиксированных значений.
    """

    def __init__(
        self,
        unix_socket_path: Optional[Union[str, Path]] = None,
        tcp_host: Optional[str] = None,
        tcp_port: Optional[int] = None,
        timeout: float = 5.0,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        if not unix_socket_path and not (tcp_host and tcp_port):
            raise ValueError("Specify unix_socket_path or tcp_host+tcp_port")

        self.unix_socket_path = str(unix_socket_path) if unix_socket_path else None
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port
        self.timeout = timeout
        self.log = logger or log

    # --- низкоуровневое подключение/обмен ---

    def _connect(self) -> socket.socket:
        if self.unix_socket_path:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect(self.unix_socket_path)
            return s
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.tcp_host, int(self.tcp_port)))  # type: ignore[arg-type]
            return s

    def send_command(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        req = json.dumps(payload, separators=(",", ":")) + "\n"
        self.log.debug("Send command: %s", req.strip())
        try:
            with self._connect() as s:
                s.sendall(req.encode("utf-8"))
                # Чтение до перевода строки (простой протокол «строка-ответ»)
                chunks: List[bytes] = []
                while True:
                    try:
                        b = s.recv(4096)
                    except socket.timeout:
                        raise TimeoutError("Timeout waiting for Suricata reply")
                    if not b:
                        break
                    chunks.append(b)
                    if b.endswith(b"\n"):
                        break
                resp_line = b"".join(chunks).decode("utf-8", errors="replace").strip()
        except FileNotFoundError as e:
            raise ConnectionError(f"Unix socket not found: {self.unix_socket_path}") from e
        except OSError as e:
            if e.errno in (errno.ECONNREFUSED, errno.ENOENT):
                raise ConnectionError("Suricata command socket connection error") from e
            raise

        self.log.debug("Recv reply: %s", resp_line)
        try:
            return json.loads(resp_line) if resp_line else {}
        except Exception as e:
            self.log.warning("Non-JSON reply: %s (%s)", resp_line, e)
            return {"raw": resp_line}

    # --- удобные методы над send_command ---

    def version(self) -> Dict[str, Any]:
        return self.send_command({"command": "version"})

    def ruleset_reload(self) -> Dict[str, Any]:
        return self.send_command({"command": "ruleset-reload"})

    def shutdown(self) -> Dict[str, Any]:
        return self.send_command({"command": "shutdown"})


# ----------------------- МЕНЕДЖЕР ПРАВИЛ SURICATA ----------------------------

@dataclass
class SuricataRulesManager:
    """
    Безопасное атомарное обновление rule-файла.

    Параметры:
      rules_path: целевой rules-файл (например, custom.rules).
      backup_dir: каталог для бэкапов (по умолчанию рядом).
      newline: добавлять завершающий перевод строки.

    Методы:
      write_rules(lines: Iterable[str]) -> Path
      append_rule(rule: str) -> Path
      backup() -> Path

    Реализация:
      - запись во временный файл + os.replace для атомарной подмены
      - создание резервной копии с timestamp
    """
    rules_path: Union[str, Path]
    backup_dir: Optional[Union[str, Path]] = None
    newline: bool = True
    logger: logging.Logger = field(default_factory=lambda: log)

    def _ensure_parent(self) -> None:
        Path(self.rules_path).parent.mkdir(parents=True, exist_ok=True)
        if self.backup_dir is not None:
            Path(self.backup_dir).mkdir(parents=True, exist_ok=True)

    def backup(self) -> Path:
        self._ensure_parent()
        src = Path(self.rules_path)
        if not src.exists():
            raise FileNotFoundError(f"Rules file not found for backup: {src}")
        ts = time.strftime("%Y%m%d-%H%M%S")
        bdir = Path(self.backup_dir) if self.backup_dir else src.parent / "backup"
        bdir.mkdir(parents=True, exist_ok=True)
        dst = bdir / f"{src.name}.{ts}.bak"
        shutil.copy2(src, dst)
        self.logger.info("Backup created: %s", dst)
        return dst

    def write_rules(self, lines: Iterable[str]) -> Path:
        self._ensure_parent()
        dst = Path(self.rules_path)
        tmp_fd, tmp_path = tempfile.mkstemp(prefix=dst.name + ".", dir=str(dst.parent))
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8", newline="\n") as f:
                for line in lines:
                    if line is None:
                        continue
                    if self.newline and not line.endswith("\n"):
                        f.write(line + "\n")
                    else:
                        f.write(line)
            os.replace(tmp_path, dst)
            self.logger.info("Rules written atomically: %s", dst)
        except Exception:
            # Если провалились — убрать временный файл
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            raise
        return dst

    def append_rule(self, rule: str) -> Path:
        # Читаем текущее содержимое (если есть), добавляем правило и атомарно записываем
        dst = Path(self.rules_path)
        existing: List[str] = []
        if dst.exists():
            with dst.open("r", encoding="utf-8", errors="replace") as f:
                existing = f.readlines()
        existing.append(rule if rule.endswith("\n") or not self.newline else rule + "\n")
        return self.write_rules(existing)


# ---------------------------- ФАСАД ИНТЕГРАЦИИ -------------------------------

class SuricataIntegration:
    """
    Фасад для типичных сценариев:
      - watch_alerts: подписка на alert-события с фильтрами
      - wait_for_alert: ожидание конкретного совпадения с таймаутом
      - reload_rules: безопасная перезагрузка rules (с verify callback, опционально)
      - add_rule_and_reload: добавление правила и перезагрузка

    Примечание:
      Пользователь сам задаёт пути/адреса под свою среду.
    """

    def __init__(
        self,
        eve_path: Union[str, Path],
        command_client: Optional[SuricataCommandClient] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.eve_path = str(eve_path)
        self.cmd = command_client
        self.log = logger or log
        self._watch_thread: Optional[threading.Thread] = None
        self._watch_stop = threading.Event()

    # -------------------- WATCH / CALLBACK API --------------------

    def watch_alerts(
        self,
        event_filter: Optional[SuricataEventFilter],
        on_event: Callable[[Dict[str, Any]], None],
        start_at_end: bool = True,
        poll_interval: float = 0.5,
    ) -> None:
        """
        Запускает фоновую нить чтения EVE и вызова on_event(evt) для совпавших событий.
        Остановка: stop_watch().
        """
        if self._watch_thread and self._watch_thread.is_alive():
            raise RuntimeError("Watch already running")

        self._watch_stop.clear()

        def _run() -> None:
            tail = SuricataEveTail(
                path=self.eve_path,
                start_at_end=start_at_end,
                poll_interval=poll_interval,
                reopen_on_rotate=True,
                open_timeout=60.0,
            )
            try:
                for evt in tail.follow():
                    if self._watch_stop.is_set():
                        break
                    if event_filter is None or event_filter.match(evt):
                        try:
                            on_event(evt)
                        except Exception as e:
                            self.log.warning("on_event error: %s", e)
            except Exception as e:
                self.log.error("watch_alerts error: %s", e)

        self._watch_thread = threading.Thread(target=_run, name="SuricataWatch", daemon=True)
        self._watch_thread.start()
        self.log.info("Suricata watch started (eve=%s)", self.eve_path)

    def stop_watch(self, timeout: float = 5.0) -> None:
        self._watch_stop.set()
        if self._watch_thread and self._watch_thread.is_alive():
            self._watch_thread.join(timeout=timeout)
            self.log.info("Suricata watch stopped")

    # -------------------- WAIT FOR SINGLE MATCH -------------------

    def wait_for_alert(
        self,
        event_filter: SuricataEventFilter,
        timeout: float = 30.0,
        start_at_end: bool = True,
        poll_interval: float = 0.5,
    ) -> Optional[Dict[str, Any]]:
        """
        Блокирующее ожидание первого события, удовлетворяющего фильтру.
        Возвращает событие или None по таймауту.
        """
        deadline = time.time() + timeout
        tail = SuricataEveTail(
            path=self.eve_path,
            start_at_end=start_at_end,
            poll_interval=poll_interval,
            reopen_on_rotate=True,
            open_timeout=timeout,
        )
        for evt in tail.follow():
            if event_filter.match(evt):
                return evt
            if time.time() >= deadline:
                return None
        return None

    # -------------------- RULES / RELOAD --------------------------------

    def reload_rules(
        self,
        verify: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ) -> Dict[str, Any]:
        """
        Перезагрузка правил через командный клиент.
        verify(resp) -> bool может дополнительно валидировать ответ.
        """
        if not self.cmd:
            raise RuntimeError("Command client is not configured")
        resp = self.cmd.ruleset_reload()
        if verify and not verify(resp):
            raise RuntimeError(f"ruleset-reload verify failed: {resp}")
        self.log.info("Ruleset reloaded: %s", resp)
        return resp

    def add_rule_and_reload(
        self,
        rules_manager: SuricataRulesManager,
        rule: str,
        verify_reload: Optional[Callable[[Dict[str, Any]], bool]] = None,
        create_backup: bool = True,
    ) -> Dict[str, Any]:
        """
        Добавить правило atomically и выполнить ruleset-reload.
        """
        if create_backup and Path(rules_manager.rules_path).exists():
            rules_manager.backup()
        rules_manager.append_rule(rule)
        return self.reload_rules(verify=verify_reload)


# ------------------------------- ПРИМЕРЫ API ---------------------------------
# В данном модуле умышленно нет CLI/демонстрации запуска, чтобы избежать
# сторонних побочных эффектов при импортировании. Ниже — только тестовые
# шаблоны использования в виде функций, которые можно вызвать из вашего кода.

def example_build_filter_for_high_prio_alerts() -> SuricataEventFilter:
    """
    Пример конструирования фильтра alert-событий с высоким приоритетом.
    """
    return SuricataEventFilter(
        any_of_event_types=["alert"],
        equals={"alert.severity": 1},
        regex={"alert.signature": r".+"},
    )


def example_on_event(evt: Dict[str, Any]) -> None:
    """
    Пример колбэка обработки события: структурированное логирование.
    """
    sig = _deep_get(evt, "alert.signature", "")
    sid = _deep_get(evt, "alert.signature_id", "")
    src = f"{evt.get('src_ip')}:{evt.get('src_port')}"
    dst = f"{evt.get('dest_ip')}:{evt.get('dest_port')}"
    proto = evt.get("proto")
    log.info("ALERT: sig=%r sid=%r %s -> %s proto=%s", sig, sid, src, dst, proto)


__all__ = [
    "SuricataEveTail",
    "SuricataEventFilter",
    "SuricataCommandClient",
    "SuricataRulesManager",
    "SuricataIntegration",
    "example_build_filter_for_high_prio_alerts",
    "example_on_event",
]
