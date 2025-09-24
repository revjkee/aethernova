# automation-core/src/automation_core/compliance/robots.py
# -*- coding: utf-8 -*-
"""
Строгий комплаенс robots.txt (REP, RFC 9309) для парсинга и принятия решений can_fetch.

Нормативные требования, реализованные в модуле:
- Файл /robots.txt в корне authority, UTF-8, text/plain; URI вида scheme://authority/robots.txt.  # RFC 9309 §2.3  :contentReference[oaicite:1]{index=1}
- Группы и правила: user-agent + {allow|disallow}; объединение правил групп с тем же user-agent.   # RFC 9309 §2.1–2.2.1  :contentReference[oaicite:2]{index=2}
- Выбор группы "*", если точных групп нет.                                                          # RFC 9309 §2.2.1  :contentReference[oaicite:3]{index=3}
- Матчинг: начало с первого октета пути; регистрозависимый; наиболее специфичное совпадение
  (наибольшее число октетов); при эквивалентных allow/disallow предпочтителен allow.              # RFC 9309 §2.2.2, §5.2  :contentReference[oaicite:4]{index=4}
- Спецсимволы: поддержка "*" (любой символ, включая "/") и "$" (якорь конца).                      # RFC 9309 §2.2.3; Google wildcards  :contentReference[oaicite:5]{index=5}
- Редиректы при загрузке robots.txt: следовать не менее 5 переходов.                               # RFC 9309 §2.3.1.2  :contentReference[oaicite:6]{index=6}
- Статусы: 4xx (unavailable) → можно краулить; 5xx/сетевые (unreachable) → полностью запретить.    # RFC 9309 §2.3.1.3–2.3.1.4  :contentReference[oaicite:7]{index=7}
- Кэш: использовать HTTP кэш-заголовки (RFC 9111) и не хранить >24ч, если robots доступен.         # RFC 9309 §2.4; Google caching  :contentReference[oaicite:8]{index=8}
- Лимит разбора: минимум 500 KiB.                                                                   # RFC 9309 §2.5  :contentReference[oaicite:9]{index=9}

Замечания по расширениям:
- Поле "Sitemap:" допустимо как "other record" и не влияет на группировку; мы его извлекаем.
  (REP разрешает иные записи; пример — Sitemaps).                                                  # RFC 9309 §2.2.4; Google docs  :contentReference[oaicite:10]{index=10}
- Поле "Crawl-delay" не стандартизовано REP; Google его не поддерживает. Мы парсим опционально,
  но не полагаемся на него для can_fetch.                                                           # Google docs  :contentReference[oaicite:11]{index=11}
"""

from __future__ import annotations

import dataclasses
import io
import re
import time
import json
import threading
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple, Iterable
from urllib.parse import urlsplit, urlunsplit
from urllib.parse import unquote as url_unquote
import urllib.request
import urllib.error
import email.utils as eutils
import hashlib

# ----------------------------
# Константы и типы
# ----------------------------

_MAX_ROBOTS_BYTES = 512 * 1024  # ≥ 500 KiB по RFC 9309 §2.5  :contentReference[oaicite:12]{index=12}
_DEFAULT_CACHE_TTL = 24 * 3600  # по RFC 9309 §2.4 (не хранить >24 ч, если доступен)  :contentReference[oaicite:13]{index=13}
_MAX_REDIRECTS = 5              # по RFC 9309 §2.3.1.2  :contentReference[oaicite:14]{index=14}
_ROBOTS_PATH = "/robots.txt"

@dataclass(slots=True)
class Rule:
    allow: bool
    pattern: str
    regex: re.Pattern
    length: int  # кол-во символов в исходном паттерне (для "наиболее специфичного")

@dataclass(slots=True)
class Group:
    agents: List[str] = field(default_factory=list)  # нормализованные product tokens (нижний регистр)
    rules: List[Rule] = field(default_factory=list)

@dataclass(slots=True)
class RobotsData:
    groups: List[Group] = field(default_factory=list)
    sitemaps: List[str] = field(default_factory=list)
    crawl_delay: Optional[float] = None  # не стандарт REP; парсим как расширение (не используем в can_fetch)
    fetched_at: float = field(default_factory=time.time)

@dataclass(slots=True)
class CacheEntry:
    robots: Optional[RobotsData]  # None, если "полный запрет" из-за unreachable
    etag: Optional[str]
    last_modified: Optional[str]
    expire_at: float

# ----------------------------
# Исключения
# ----------------------------

class RobotsError(RuntimeError):
    pass

# ----------------------------
# Утилиты HTTP
# ----------------------------

class _NoAutoRedirect(urllib.request.HTTPRedirectHandler):
    """Запрещаем авторедиректы — обрабатываем вручную (ограничение до 5)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl=None):
        return None  # заставляет выкинуть HTTPError с кодом 3xx

def _build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoAutoRedirect)

def _parse_cache_ttl(headers: Dict[str, str]) -> Optional[int]:
    """
    Возвращает ttl (сек), если удалось извлечь из Cache-Control/Expires.
    По RFC 9309 допускается использование стандартного HTTP caching (RFC 9111).  :contentReference[oaicite:15]{index=15}
    """
    cc = headers.get("Cache-Control") or headers.get("cache-control")
    if cc:
        # простейший парсер max-age
        m = re.search(r"max-age\s*=\s*(\d+)", cc, flags=re.I)
        if m:
            try:
                return max(0, int(m.group(1)))
            except Exception:
                pass
    exp = headers.get("Expires") or headers.get("expires")
    if exp:
        try:
            dt = eutils.parsedate_to_datetime(exp)
            ttl = int(dt.timestamp() - time.time())
            return max(0, ttl)
        except Exception:
            pass
    return None

def _authority_from_url(url: str) -> Tuple[str, str, str]:
    """
    Возвращает (scheme, authority, robots_url).
    По RFC robots.txt находится по scheme://authority/robots.txt.  :contentReference[oaicite:16]{index=16}
    """
    sp = urlsplit(url)
    scheme, netloc = sp.scheme, sp.netloc
    robots_url = urlunsplit((scheme, netloc, _ROBOTS_PATH, "", ""))
    return scheme, netloc, robots_url

# ----------------------------
# Парсер REP (RFC 9309)
# ----------------------------

_USER_AGENT_RE = re.compile(r"^\s*user-agent\s*:\s*(.+?)\s*(?:#.*)?$", re.I)
_ALLOW_RE      = re.compile(r"^\s*allow\s*:\s*(.*)\s*(?:#.*)?$", re.I)
_DISALLOW_RE   = re.compile(r"^\s*disallow\s*:\s*(.*)\s*(?:#.*)?$", re.I)
_SITEMAP_RE    = re.compile(r"^\s*sitemap\s*:\s*(\S+)\s*(?:#.*)?$", re.I)  # "other record"  :contentReference[oaicite:17]{index=17}
_CRAWL_DELAY_RE= re.compile(r"^\s*crawl-delay\s*:\s*([0-9]+(?:\.[0-9]+)?)\s*(?:#.*)?$", re.I)  # не стандарт Google  :contentReference[oaicite:18]{index=18}

def _pattern_to_regex(pat: str) -> re.Pattern:
    """
    Трансляция path-pattern REP в regex:
      - '*' → '.*' (включая '/'); '$' в конце паттерна якорит конец строки.
      - матч начинается с начального '/' URL (включая возможный query '?...').
    Длина паттерна считаем по исходной строке (для "наиболее специфичного" выбора).  # RFC 9309 §2.2.2–2.2.3  :contentReference[oaicite:19]{index=19}
    """
    # Нормализуем проценты (RFC 9309 требует сравнивать по октетам/percent-encoding).
    # Здесь приводим паттерн к человекочитаемому виду, не влияя на сопоставление '*', '$'.
    src = url_unquote(pat)

    end_anchor = src.endswith("$")
    if end_anchor:
        src = src[:-1]

    # Экранируем спецсимволы regex, затем возвращаем семантику '*'
    esc = []
    for ch in src:
        if ch == "*":
            esc.append(".*")
        else:
            esc.append(re.escape(ch))
    body = "".join(esc)

    if end_anchor:
        rx = r"^" + body + r"$"
    else:
        rx = r"^" + body + r".*"

    return re.compile(rx)

def _parse_robots(text: str, fetched_at: float) -> RobotsData:
    groups: List[Group] = []
    sitemaps: List[str] = []
    crawl_delay: Optional[float] = None

    current_agents: List[str] = []  # накапливаем до первой правила-строки
    current_rules: List[Rule] = []

    def flush_group():
        nonlocal current_agents, current_rules
        if current_agents or current_rules:
            groups.append(Group(agents=current_agents, rules=current_rules))
        current_agents = []
        current_rules = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        m = _USER_AGENT_RE.match(line)
        if m:
            # новая группа начинается при первой user-agent
            if current_rules or current_agents:
                # если уже были агенты и/или правила — закрываем предыдущую группу
                flush_group()
            agent = m.group(1).strip().lower()
            current_agents = [agent]
            current_rules = []
            continue

        m = _ALLOW_RE.match(line)
        if m and current_agents:
            val = m.group(1).strip()
            # пустой allow: эквивалент отсутствию матчинга — по RFC он игнорируется (нет пути).
            if val == "":
                # пустое значение не добавляем как правило
                flush = False
            else:
                rgx = _pattern_to_regex(val)
                current_rules.append(Rule(True, val, rgx, len(val)))
            continue

        m = _DISALLOW_RE.match(line)
        if m and current_agents:
            val = m.group(1).strip()
            # пустой disallow = "разрешить всё" для этой группы (правило не нужно)
            if val == "":
                # Ничего не добавляем — отсутствие правила = разрешено.
                pass
            else:
                rgx = _pattern_to_regex(val)
                current_rules.append(Rule(False, val, rgx, len(val)))
            continue

        m = _SITEMAP_RE.match(line)
        if m:
            sitemaps.append(m.group(1).strip())
            continue

        m = _CRAWL_DELAY_RE.match(line)
        if m:
            try:
                crawl_delay = float(m.group(1))
            except Exception:
                pass
            continue

        # Прочие строки (доп. записи) игнорируются и не ломают группировку.  # RFC 9309 §2.2.4  :contentReference[oaicite:20]{index=20}

    # финальная группа
    flush_group()
    return RobotsData(groups=groups, sitemaps=sitemaps, crawl_delay=crawl_delay, fetched_at=fetched_at)

# ----------------------------
# Хранилище robots по authority
# ----------------------------

class RobotsCache:
    def __init__(self):
        self._lock = threading.RLock()
        self._map: Dict[str, CacheEntry] = {}

    def get(self, authority: str) -> Optional[CacheEntry]:
        with self._lock:
            ce = self._map.get(authority)
            if ce and ce.expire_at > time.time():
                return ce
            return ce  # просроченный возвращаем как "можно ре-валидировать"

    def put(self, authority: str, entry: CacheEntry) -> None:
        with self._lock:
            self._map[authority] = entry

# ----------------------------
# Загрузчик robots.txt с кэшем
# ----------------------------

class RobotsFetcher:
    def __init__(self, user_agent_token: str, timeout: float = 10.0):
        """
        user_agent_token — product token вашего краулера (например, 'MyBot'),
        используется для выбора группы в robots.txt (сопоставление без учета регистра).  # RFC 9309 §2.2.1  :contentReference[oaicite:21]{index=21}
        """
        if not re.match(r"^[A-Za-z_-]+$", user_agent_token):
            raise RobotsError("user_agent_token должен содержать только a-z, A-Z, '_' или '-' (RFC 9309).")
        self._ua_token = user_agent_token
        self._timeout = timeout
        self._cache = RobotsCache()
        self._opener = _build_opener()

    # -------- HTTP --------

    def _http_get(self, url: str, etag: Optional[str], last_mod: Optional[str]) -> Tuple[int, Dict[str, str], bytes]:
        headers = {
            "User-Agent": f"{self._ua_token}/1.0 (+robots.txt compliance RFC9309)",
            "Accept": "text/plain, */*;q=0.1",
        }
        if etag:
            headers["If-None-Match"] = etag
        if last_mod:
            headers["If-Modified-Since"] = last_mod

        req = urllib.request.Request(url, headers=headers, method="GET")

        try:
            with self._opener.open(req, timeout=self._timeout) as resp:
                status = getattr(resp, "status", resp.getcode())
                data = resp.read(_MAX_ROBOTS_BYTES + 1)
                return int(status), dict(resp.headers.items()), data
        except urllib.error.HTTPError as e:
            # Если это редирект — перехватим в _fetch_with_redirects
            if 300 <= e.code < 400:
                raise
            data = b""
            try:
                if e.fp:
                    data = e.fp.read(_MAX_ROBOTS_BYTES + 1)
            except Exception:
                pass
            return int(e.code), dict(e.headers.items()), data
        except urllib.error.URLError as e:
            # Сетевые ошибки → unreachable
            raise

    def _fetch_with_redirects(self, url: str, etag: Optional[str], last_mod: Optional[str]) -> Tuple[int, Dict[str, str], bytes]:
        hops = 0
        cur = url
        while True:
            try:
                return self._http_get(cur, etag, last_mod)
            except urllib.error.HTTPError as e:
                # manual redirect handling
                if e.code in (301, 302, 303, 307, 308):
                    loc = e.headers.get("Location") or e.headers.get("location")
                    if not loc:
                        # нет Location — трактуем как 404 (unavailable)
                        return 404, dict(e.headers.items()), b""
                    hops += 1
                    if hops > _MAX_REDIRECTS:
                        # >5 → считать robots "unavailable" (разрешено)  # RFC 9309 §2.3.1.2  :contentReference[oaicite:22]{index=22}
                        return 404, dict(e.headers.items()), b""
                    # абсолютные/относительные URL — доверяем urllib.request для построения
                    cur = urllib.parse.urljoin(cur, loc)
                    continue
                else:
                    # Прочие HTTP ошибки обрабатываются выше
                    raise

    # -------- Основное API --------

    def load_for(self, any_url: str) -> CacheEntry:
        """
        Загружает/валидирует robots.txt для authority из any_url с учетом кэша и правил RFC 9309.
        """
        scheme, authority, robots_url = _authority_from_url(any_url)
        cached = self._cache.get(authority)

        etag = cached.etag if cached else None
        last_mod = cached.last_modified if cached else None

        # Если кэш ещё валиден — отдаём как есть
        if cached and cached.expire_at > time.time():
            return cached

        # Иначе валидируем/перезагружаем
        try:
            status, headers, body = self._fetch_with_redirects(robots_url, etag, last_mod)
        except urllib.error.URLError:
            # unreachable → MUST assume complete disallow           # RFC 9309 §2.3.1.4  :contentReference[oaicite:23]{index=23}
            # при наличии кэша можно продолжать его использовать дольше 24 ч
            if cached:
                # продлеваем срок, если недоступен
                return CacheEntry(robots=cached.robots, etag=cached.etag,
                                  last_modified=cached.last_modified,
                                  expire_at=time.time() + _DEFAULT_CACHE_TTL)
            return CacheEntry(robots=None, etag=None, last_modified=None,
                              expire_at=time.time() + _DEFAULT_CACHE_TTL)

        # 304 Not Modified → продлеваем по кэшу
        if status == 304 and cached:
            ttl = _parse_cache_ttl(headers)
            expire_at = time.time() + (ttl if ttl is not None else _DEFAULT_CACHE_TTL)
            entry = CacheEntry(robots=cached.robots,
                               etag=headers.get("ETag") or headers.get("Etag") or cached.etag,
                               last_modified=headers.get("Last-Modified") or headers.get("last-modified") or cached.last_modified,
                               expire_at=expire_at)
            self._cache.put(authority, entry)
            return entry

        # 2xx: читаем тело
        if 200 <= status < 300:
            data = body[:_MAX_ROBOTS_BYTES]
            text = data.decode("utf-8", errors="ignore")
            robots = _parse_robots(text, fetched_at=time.time())

            ttl = _parse_cache_ttl(headers)
            expire_at = time.time() + (ttl if ttl is not None else _DEFAULT_CACHE_TTL)
            entry = CacheEntry(
                robots=robots,
                etag=headers.get("ETag") or headers.get("Etag"),
                last_modified=headers.get("Last-Modified") or headers.get("last-modified"),
                expire_at=expire_at,
            )
            self._cache.put(authority, entry)
            return entry

        # 4xx (unavailable) → MAY access any resources (как будто robots.txt нет)  # RFC 9309 §2.3.1.3  :contentReference[oaicite:24]{index=24}
        if 400 <= status < 500:
            entry = CacheEntry(robots=RobotsData(groups=[], sitemaps=[], crawl_delay=None, fetched_at=time.time()),
                               etag=None, last_modified=None,
                               expire_at=time.time() + _DEFAULT_CACHE_TTL)
            self._cache.put(authority, entry)
            return entry

        # 5xx → unreachable → полный запрет                         # RFC 9309 §2.3.1.4  :contentReference[oaicite:25]{index=25}
        entry = CacheEntry(robots=None, etag=None, last_modified=None,
                           expire_at=time.time() + _DEFAULT_CACHE_TTL)
        self._cache.put(authority, entry)
        return entry

# ----------------------------
# Матчинг правил
# ----------------------------

def _select_group_rules(robots: RobotsData, ua_token: str) -> List[Rule]:
    """
    Возвращает консолидированный список правил для данного user-agent token.
    - Если есть одна/несколько групп с этим токеном → объединить их правила.     # RFC 9309 §2.2.1  :contentReference[oaicite:26]{index=26}
    - Иначе, если есть группа '*' → её правила.
    - Иначе правил нет (allow all).
    """
    ua = ua_token.lower()
    exact: List[Rule] = []
    star: List[Rule] = []
    for g in robots.groups:
        if any(a == ua for a in g.agents):
            exact.extend(g.rules)
        if any(a == "*" for a in g.agents):
            star.extend(g.rules)
    if exact:
        return exact
    if star:
        return star
    return []

def _path_for_matching(url: str) -> str:
    """
    Google трактует шаблоны с учетом ограниченной поддержки wildcard и примеров с '?'.
    Здесь используем path + ('?' + query) для согласованности с примерами Google.  # Google wildcards/examples  :contentReference[oaicite:27]{index=27}
    """
    sp = urlsplit(url)
    if sp.query:
        return sp.path + "?" + sp.query
    return sp.path or "/"

def _decide_allowed(rules: List[Rule], url: str) -> bool:
    """
    Алгоритм: найти все совпадающие правила; выбрать самое специфичное (наибольшая длина).
    При равной специфичности allow предпочтительнее disallow.                       # RFC 9309 §2.2.2; Google precedence  :contentReference[oaicite:28]{index=28}
    Если правил нет → разрешить; /robots.txt разрешен всегда.                        # RFC 9309 §2.2.2  :contentReference[oaicite:29]{index=29}
    """
    path = _path_for_matching(url)
    if path == _ROBOTS_PATH:
        return True  # /robots.txt всегда разрешен по RFC
    best: Tuple[int, Optional[bool]] = ( -1, None )  # (длина, allow?)
    for r in rules:
        if r.regex.match(path):
            l = r.length
            if l > best[0]:
                best = (l, r.allow)
            elif l == best[0] and best[1] is not None and r.allow and best[1] is False:
                # tie → выбираем allow
                best = (l, True)
    if best[1] is None:
        return True
    return bool(best[1])

# ----------------------------
# Публичное API
# ----------------------------

class RobotsChecker:
    """
    Высокоуровневый интерфейс:
      - can_fetch(url) → bool
      - crawl_delay(url) → Optional[float]  (не стандарт REP; парсится опционально; Google игнорирует)  # :contentReference[oaicite:30]{index=30}
      - sitemaps(url) → List[str]
    """
    def __init__(self, user_agent_token: str, timeout: float = 10.0):
        self._ua = user_agent_token
        self._fetcher = RobotsFetcher(user_agent_token, timeout=timeout)

    def can_fetch(self, url: str) -> bool:
        entry = self._fetcher.load_for(url)
        if entry.robots is None:
            # unreachable → полное запрещение (MUST)                         # RFC 9309 §2.3.1.4  :contentReference[oaicite:31]{index=31}
            return False
        rules = _select_group_rules(entry.robots, self._ua)
        return _decide_allowed(rules, url)

    def crawl_delay(self, url: str) -> Optional[float]:
        """
        Возвращает Crawl-delay, если встречается (де-факто расширение; Google не поддерживает).  # :contentReference[oaicite:32]{index=32}
        """
        entry = self._fetcher.load_for(url)
        if entry.robots is None:
            return None
        return entry.robots.crawl_delay

    def sitemaps(self, url: str) -> List[str]:
        """
        Возвращает список Sitemap-URL, если присутствуют (как "прочие записи" REP).  # RFC 9309 §2.2.4; Google docs  :contentReference[oaicite:33]{index=33}
        """
        entry = self._fetcher.load_for(url)
        if entry.robots is None:
            return []
        return list(entry.robots.sitemaps)

# ----------------------------
# Пример локального теста
# ----------------------------
if __name__ == "__main__":  # простой self-check
    rc = RobotsChecker("ExampleBot", timeout=10.0)
    test_url = "https://www.example.com/"
    print("can_fetch:", rc.can_fetch(test_url))
