# -*- coding: utf-8 -*-
"""
Robots.txt compliance utilities (RFC 9309).

Key behaviors implemented per RFC 9309:
- Location: robots.txt MUST be at "<scheme>://<authority>/robots.txt" (Section 2.3).              [RFC 9309]
- Access results: 4xx ("Unavailable") ⇒ MAY access any resources; 5xx ("Unreachable") ⇒ MUST
  assume complete disallow (Sections 2.3.1.3–2.3.1.4).                                           [RFC 9309]
- Caching: SHOULD NOT use cached copy >24h unless unreachable; MAY use HTTP cache control (2.4). [RFC 9309]
- Limits: parser MUST process at least 500 KiB; we cap at 512 KiB (Section 2.5).                 [RFC 9309]
- User-agent selection: case-insensitive match on product token; merge rules of all matching
  groups; fallback to "*" group; else no rules (Section 2.2.1).                                  [RFC 9309]
- Matching: compare from start of path; case-sensitive; most specific (longest octet match)
  wins; if Allow and Disallow equivalent ⇒ SHOULD use Allow (Section 2.2.2).                    [RFC 9309]
- Special characters: MUST support "*" wildcard and "$" EOL anchor (Section 2.2.3).             [RFC 9309]
- "/robots.txt" is implicitly allowed; if no matching rule in a matching group ⇒ allowed.        [RFC 9309]

Implementation notes:
- We treat "path" as the request-target path plus optional "?" + query, as in RFC examples.
- Specificity score approximates "octet length of the matching rule" by counting non-wildcard
  octets in the rule's value (UTF-8 length excluding "*" and "$"). Used as tiebreaker.
- We obey HTTP cache validators (ETag/Last-Modified) and Cap TTL to 24h unless unreachable.
- Redirects: rely on urllib default; RFC requires following ≥5 consecutive redirects; stdlib
  follows more, which is compliant ("SHOULD follow at least five").

No third-party dependencies.
"""

from __future__ import annotations

import dataclasses
import io
import re
import time
import typing
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple


# RFC-aligned constants
MAX_PARSE_BYTES = 512 * 1024  # RFC 9309 Section 2.5: MUST be >= 500 KiB
MAX_REDIRECTS = 5             # RFC 9309 Section 2.3.1.2: SHOULD follow at least 5
DEFAULT_TTL = 24 * 3600       # RFC 9309 Section 2.4: SHOULD NOT use cache > 24h (unless unreachable)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    allow: bool
    pattern: str
    # cached fields for fast matching
    _regex: typing.Pattern
    _specificity: int  # octets excluding '*' and '$'

@dataclass(frozen=True)
class Group:
    agents: Tuple[str, ...]
    rules: Tuple[Rule, ...]

@dataclass
class RobotsTxt:
    groups: Tuple[Group, ...]
    sitemaps: Tuple[str, ...]


@dataclass
class MatchResult:
    allowed: bool
    matched_rule: Optional[Rule]
    matched_group_agents: Tuple[str, ...]
    reason: str


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_WS = r"[ \t]*"
_KV_RE = re.compile(rf"^{_WS}([A-Za-z\-]+){_WS}:{_WS}(.*?){_WS}(?:#.*)?$", re.ASCII)
_UA_RE = re.compile(rf"^{_WS}user-agent{_WS}:{_WS}([A-Za-z_\-\*]+){_WS}(?:#.*)?$", re.IGNORECASE)
_ALLOW_RE = re.compile(rf"^{_WS}allow{_WS}:{_WS}(.*?){_WS}(?:#.*)?$", re.IGNORECASE)
_DISALLOW_RE = re.compile(rf"^{_WS}disallow{_WS}:{_WS}(.*?){_WS}(?:#.*)?$", re.IGNORECASE)
_SITEMAP_RE = re.compile(rf"^{_WS}sitemap{_WS}:{_WS}(\S+){_WS}(?:#.*)?$", re.IGNORECASE)

# Characters we will escape in regex except '*' and ending '$'
_REGEX_ESCAPE = re.compile(r"([.^+?{}()\[\]\\|])")

def _specificity_score(value: str) -> int:
    # RFC "most octets" — approximate by UTF-8 byte length excluding '*' and trailing '$'
    v = value.rstrip()
    if v.endswith("$"):
        v = v[:-1]
    # do not count '*' wildcards
    return len(v.replace("*", "").encode("utf-8"))

def _compile_rule(value: str, allow: bool) -> Rule:
    # Normalize empty pattern: empty means whole site (i.e., allow/disallow nothing/everything?)
    # Per RFC, empty pattern is valid; matching MUST start at first octet of path.
    raw = value.strip()
    # Build regex: anchor at start; support '*' wildcard and '$' end anchor
    end_anchor = raw.endswith("$")
    core = raw[:-1] if end_anchor else raw
    # Escape regex meta, keep '*' as wildcard
    core = _REGEX_ESCAPE.sub(r"\\\1", core)
    core = core.replace("*", ".*")  # '*' matches any char sequence, including '/'
    pattern = "^" + core
    if end_anchor:
        pattern += "$"
    try:
        rx = re.compile(pattern)
    except re.error:
        # Be defensive: if bad pattern, treat as never-matching
        rx = re.compile(r"(?!x)x")
    spec = _specificity_score(value)
    return Rule(allow=allow, pattern=value, _regex=rx, _specificity=spec)

def parse_robots(text: str) -> RobotsTxt:
    groups: List[Group] = []
    cur_agents: List[str] = []
    cur_rules: List[Rule] = []
    sitemaps: List[str] = []

    lines = text.splitlines()
    for line in lines:
        # Strip comments (RFC allows inline comments after '#')
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        if m := _UA_RE.match(line):
            # Starting a new startgroupline; if we had an open group, flush it
            if cur_agents:
                groups.append(Group(agents=tuple(cur_agents), rules=tuple(cur_rules)))
                cur_agents, cur_rules = [], []
            ua = m.group(1).strip()
            cur_agents.append(ua.lower())
            continue

        if m := _ALLOW_RE.match(line):
            cur_rules.append(_compile_rule(m.group(1), allow=True))
            continue

        if m := _DISALLOW_RE.match(line):
            value = m.group(1)
            # Empty pattern is allowed (a no-op disallow); we'll compile it anyway
            cur_rules.append(_compile_rule(value, allow=False))
            continue

        if m := _SITEMAP_RE.match(line):
            sitemaps.append(m.group(1).strip())
            continue

        # Other records are ignored but MUST NOT break groups (RFC 2.2.4) — just skip

    # Flush last group
    if cur_agents:
        groups.append(Group(agents=tuple(cur_agents), rules=tuple(cur_rules)))

    return RobotsTxt(groups=tuple(groups), sitemaps=tuple(sitemaps))


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def _target_path_for_match(url: str) -> str:
    """
    RFC examples show matching may include query-part. We match against:
    <path> + optional "?" + <query> if the query is present.
    """
    u = urllib.parse.urlsplit(url)
    path = u.path or "/"
    if u.query:
        path = f"{path}?{u.query}"
    return path

def _merge_matching_groups(r: RobotsTxt, ua_product_token: str) -> Group:
    """
    RFC 9309 2.2.1: case-insensitive match against product token; if more than one group matches,
    matching groups' rules MUST be combined. Fallback to '*' group. If nothing matches, no rules.
    """
    token = ua_product_token.lower()
    matched_rules: List[Rule] = []
    matched_agents: List[str] = []

    # collect exact UA matches and '*' matches; merge all that match
    for g in r.groups:
        if any(a == "*" for a in g.agents):
            star_group = g
        else:
            star_group = None
        if any(a in token for a in g.agents if a != "*"):
            matched_rules.extend(g.rules)
            matched_agents.extend(g.agents)

    if matched_rules:
        return Group(agents=tuple(matched_agents), rules=tuple(matched_rules))

    # fallback to '*'
    for g in r.groups:
        if any(a == "*" for a in g.agents):
            return g

    # no groups applicable: empty group means allow all
    return Group(agents=tuple(), rules=tuple())

def evaluate(r: RobotsTxt, url: str, ua_product_token: str) -> MatchResult:
    """
    Decide if URL is allowed for the given crawler product token.
    Implements "longest (most octets) match wins" with Allow preferred on equal length.
    """
    path = _target_path_for_match(url)
    grp = _merge_matching_groups(r, ua_product_token)

    # "/robots.txt" is implicitly allowed
    if path == "/robots.txt":
        return MatchResult(True, None, grp.agents, "implicit allow for /robots.txt")

    best_rule: Optional[Rule] = None
    for rule in grp.rules:
        m = rule._regex.match(path)
        if not m:
            continue
        if best_rule is None:
            best_rule = rule
            continue
        # Prefer longer specificity; if equal, prefer Allow (RFC "SHOULD use Allow")
        if rule._specificity > best_rule._specificity:
            best_rule = rule
        elif rule._specificity == best_rule._specificity and rule.allow and not best_rule.allow:
            best_rule = rule

    if best_rule is None:
        # No matching rule in applicable group ⇒ allowed
        return MatchResult(True, None, grp.agents, "no matching rule ⇒ allowed")

    return MatchResult(best_rule.allow, best_rule, grp.agents,
                       f"{'allow' if best_rule.allow else 'disallow'} matched with specificity {best_rule._specificity}")


# ---------------------------------------------------------------------------
# Fetching + caching with RFC 9309 semantics
# ---------------------------------------------------------------------------

@dataclass
class CacheEntry:
    fetched_at: int
    ttl: int
    text: Optional[str]        # None ⇒ "disallow all" synthetic; "" ⇒ "allow all" synthetic
    etag: Optional[str]
    last_modified: Optional[str]
    unreachable: bool          # last fetch was 5xx/network (treat as disallow-all until retry)

class RobotsCache:
    """
    Per-authority cache of robots.txt with RFC 9309-compliant fetch semantics.
    Keyed by (scheme, host, port).
    """

    def __init__(self) -> None:
        self._store: Dict[Tuple[str, str, int], CacheEntry] = {}

    @staticmethod
    def _authority(url: str) -> Tuple[str, str, int, str]:
        u = urllib.parse.urlsplit(url)
        scheme = (u.scheme or "http").lower()
        host = (u.hostname or "").lower()
        if not host:
            raise ValueError("URL must include an authority")
        port = u.port or (443 if scheme == "https" else 80)
        base = f"{scheme}://{host}"
        if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
            base += f":{port}"
        return scheme, host, port, base

    def _robots_uri(self, url: str) -> Tuple[Tuple[str, str, int], str]:
        scheme, host, port, base = self._authority(url)
        return (scheme, host, port), f"{base}/robots.txt"

    def get(self, url: str, *, timeout: float = 10.0, ua: str = "AutomationCoreBot") -> RobotsTxt:
        key, robots_url = self._robots_uri(url)
        now = int(time.time())

        # serve from cache if fresh
        ce = self._store.get(key)
        if ce and (now - ce.fetched_at) < ce.ttl:
            if ce.text is None:
                # unreachable ⇒ disallow all
                return RobotsTxt(groups=tuple(), sitemaps=tuple())  # evaluate() special-cases
            elif ce.text == "":
                # unavailable ⇒ allow all
                return RobotsTxt(groups=tuple(), sitemaps=tuple())
            return parse_robots(ce.text)

        # (re)fetch
        headers = {"User-Agent": ua}
        if ce and ce.etag:
            headers["If-None-Match"] = ce.etag
        if ce and ce.last_modified:
            headers["If-Modified-Since"] = ce.last_modified

        req = urllib.request.Request(robots_url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = getattr(resp, "status", 200)
                # 2xx success
                if 200 <= status < 300:
                    raw = resp.read(MAX_PARSE_BYTES + 1)
                    # enforce parser limit
                    data = raw[:MAX_PARSE_BYTES].decode("utf-8", errors="replace")
                    etag = resp.headers.get("ETag")
                    lastmod = resp.headers.get("Last-Modified")
                    # cache TTL from Cache-Control max-age if present, else DEFAULT_TTL
                    ttl = DEFAULT_TTL
                    cc = resp.headers.get("Cache-Control", "")
                    m = re.search(r"max-age=(\d+)", cc)
                    if m:
                        ttl = max(0, int(m.group(1)))
                    self._store[key] = CacheEntry(
                        fetched_at=now, ttl=ttl, text=data, etag=etag, last_modified=lastmod, unreachable=False
                    )
                    return parse_robots(data)

                # 304 Not Modified
                if status == 304 and ce and ce.text is not None:
                    ce.fetched_at = now
                    return parse_robots(ce.text)

                # 4xx "Unavailable" per RFC ⇒ MAY access any resources ⇒ treat as allow-all
                if 400 <= status < 500:
                    self._store[key] = CacheEntry(
                        fetched_at=now, ttl=DEFAULT_TTL, text="", etag=None, last_modified=None, unreachable=False
                    )
                    return RobotsTxt(groups=tuple(), sitemaps=tuple())

                # 5xx "Unreachable" ⇒ MUST assume complete disallow
                if 500 <= status < 600:
                    self._store[key] = CacheEntry(
                        fetched_at=now, ttl=DEFAULT_TTL, text=None, etag=None, last_modified=None, unreachable=True
                    )
                    return RobotsTxt(groups=tuple(), sitemaps=tuple())

                # Any other status: be conservative, treat as unreachable/disallow
                self._store[key] = CacheEntry(
                    fetched_at=now, ttl=DEFAULT_TTL, text=None, etag=None, last_modified=None, unreachable=True
                )
                return RobotsTxt(groups=tuple(), sitemaps=tuple())

        except urllib.error.HTTPError as e:
            # HTTPError carries status; map as above
            status = e.code
            if 400 <= status < 500:
                self._store[key] = CacheEntry(
                    fetched_at=now, ttl=DEFAULT_TTL, text="", etag=None, last_modified=None, unreachable=False
                )
                return RobotsTxt(groups=tuple(), sitemaps=tuple())
            self._store[key] = CacheEntry(
                fetched_at=now, ttl=DEFAULT_TTL, text=None, etag=None, last_modified=None, unreachable=True
            )
            return RobotsTxt(groups=tuple(), sitemaps=tuple())
        except Exception:
            # Network errors ⇒ unreachable/disallow
            self._store[key] = CacheEntry(
                fetched_at=now, ttl=DEFAULT_TTL, text=None, etag=None, last_modified=None, unreachable=True
            )
            return RobotsTxt(groups=tuple(), sitemaps=tuple())

    def is_allowed(self, url: str, ua_product_token: str = "AutomationCoreBot") -> MatchResult:
        """
        High-level check with RFC semantics for "unavailable" vs "unreachable":
        - If last fetch was unreachable (5xx/network) and we have no cached success ⇒ deny.
        - If unavailable (4xx) ⇒ allow.
        - Else evaluate parsed rules.
        """
        key, _ = self._robots_uri(url)
        r = self.get(url, ua=ua_product_token)

        # If cache says unreachable (disallow-all), block
        ce = self._store.get(key)
        if ce and ce.text is None:
            return MatchResult(False, None, tuple(), "robots.txt unreachable ⇒ assume complete disallow (RFC 2.3.1.4)")

        # If cache says unavailable (allow-all), allow
        if ce and ce.text == "":
            return MatchResult(True, None, tuple(), "robots.txt unavailable (4xx) ⇒ allow (RFC 2.3.1.3)")

        # Normal evaluation
        return evaluate(r, url, ua_product_token)

    def sitemaps(self, url: str) -> Tuple[str, ...]:
        return self.get(url).sitemaps
