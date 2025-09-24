# automation-core/src/automation_core/parsers/bs4_parser.py
"""
Industrial BeautifulSoup-based HTML parser utilities.

Design goals
------------
- Deterministic parser selection with graceful fallback: lxml -> html5lib -> html.parser.
- Standards-aware URL resolution: RFC 3986 + respect for <base href> per HTML spec.
- Zero network side-effects; pure parsing/querying helpers.
- Robust extraction: text, links, meta (incl. OpenGraph), JSON-LD, tables.
- Optional safe HTML sanitization via Bleach (if installed).

References (authoritative)
--------------------------
- Beautiful Soup docs (purpose, parsers): https://www.crummy.com/software/BeautifulSoup/bs4/doc/           # bs4
- lxml parsing docs: https://lxml.de/parsing.html                                                           # lxml
- Python urllib.parse (urljoin, urlsplit): https://docs.python.org/3/library/urllib.parse.html             # urllib.parse
- RFC 3986 (URI syntax & reference resolution): https://datatracker.ietf.org/doc/html/rfc3986              # RFC 3986
- WHATWG HTML: <base> element & document base URL: https://html.spec.whatwg.org/multipage/                 # HTML Standard
- Bleach (HTML5-sanitation, allowlist): https://bleach.readthedocs.io/en/latest/clean.html                 # Bleach
- JSON-LD 1.1 (W3C): https://www.w3.org/TR/json-ld11/                                                      # JSON-LD

Note
----
- Beautiful Soup is a parsing/navigating library; it is NOT a security sanitizer. Use Bleach for sanitization.  # See refs above.

"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union
from bs4 import BeautifulSoup, SoupStrainer
import json
import re
import hashlib
from urllib.parse import urljoin, urlsplit, urlunsplit
from html import unescape

# ------------------------------ Parser selection ------------------------------

_PARSER_PREFERENCE: Sequence[str] = ("lxml", "html5lib", "html.parser")


def _choose_parser(preference: Optional[Sequence[str]] = None) -> str:
    """
    Pick the first available parser from the preference list.
    - 'lxml' (fast, lenient HTML parser via lxml)      # lxml docs
    - 'html5lib' (browser-grade HTML5 algorithm)       # Bleach relies on HTML5 parsing as well
    - 'html.parser' (Python stdlib)
    """
    prefs = tuple(preference or _PARSER_PREFERENCE)
    for name in prefs:
        try:
            # BeautifulSoup will raise LookupError if parser is unavailable
            BeautifulSoup("<html></html>", name)
            return name
        except Exception:
            continue
    # Fallback to stdlib; BeautifulSoup guarantees availability
    return "html.parser"


# ------------------------------ Core wrapper ----------------------------------

@dataclass(frozen=True)
class Link:
    url: str               # absolute, RFC 3986-resolved
    href_raw: str          # original attribute value
    text: str
    rel: Tuple[str, ...]
    attrs: Dict[str, str]


class BS4Parser:
    """
    Thin, standards-aware wrapper around BeautifulSoup for common extraction tasks.
    """

    def __init__(
        self,
        html: Union[str, bytes],
        *,
        base_url: Optional[str] = None,
        parser_preference: Optional[Sequence[str]] = None,
        parse_only: Optional[SoupStrainer] = None,
    ) -> None:
        parser = _choose_parser(parser_preference)
        self._soup = BeautifulSoup(html, parser, parse_only=parse_only)
        self._parser_name = parser
        self._explicit_base = base_url

    # ---------------------- Base URL resolution (RFC 3986 + <base>) ----------------------

    def _document_base(self) -> Optional[str]:
        """
        Determine base URL: explicit argument takes precedence; otherwise use <base href>.
        WHATWG HTML defines <base> to establish the document base URL for resolving relative URLs.  # HTML Standard
        """
        if self._explicit_base:
            return self._explicit_base
        base = self._soup.find("base", href=True)
        if not base:
            return None
        href = base.get("href", "").strip()
        return href or None

    def _resolve_url(self, href: str) -> Optional[str]:
        """
        Resolve a potentially relative URL against the effective base using urllib.parse.urljoin,
        which implements RFC 3986 reference resolution semantics.                                      # urllib.parse / RFC 3986
        Returns absolute URL string or None when href is empty/invalid/unwanted scheme.
        """
        if not href:
            return None
        href = href.strip()
        # Drop dangerous or non-navigation schemes
        if re.match(r"(?i)^(javascript|data|vbscript):", href):
            return None
        base = self._document_base()
        try:
            abs_url = urljoin(base or "", href)
        except Exception:
            return None
        # Normalize: strip fragments by default; keep scheme+netloc+path+query
        parts = urlsplit(abs_url)
        if not parts.scheme or not parts.netloc:
            return None
        return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))

    # ---------------------- Text extraction ----------------------

    def text(self, *, separator: str = " ", strip: bool = True, collapse_ws: bool = True) -> str:
        """
        Extract visible text: concatenates text nodes with separator.
        """
        txt = self._soup.get_text(separator=separator, strip=strip)
        if collapse_ws:
            txt = " ".join(txt.split())
        return txt

    def content_hash(self) -> str:
        """
        SHA-256 hash of normalized visible text (useful for change detection).
        """
        return hashlib.sha256(self.text().encode("utf-8")).hexdigest()

    # ---------------------- Metadata & JSON-LD ----------------------

    def title(self) -> Optional[str]:
        t = self._soup.title.string if self._soup.title and self._soup.title.string else None
        return t.strip() if t else None

    def meta(self) -> Dict[str, str]:
        """
        Extract useful meta entries: name/content and property/content (incl. Open Graph).
        """
        out: Dict[str, str] = {}
        for m in self._soup.find_all("meta"):
            name = (m.get("name") or m.get("property") or "").strip()
            content = (m.get("content") or "").strip()
            if name and content:
                out[name.lower()] = content
        return out

    def json_ld(self) -> List[Dict[str, Any]]:
        """
        Parse <script type="application/ld+json"> blocks (JSON-LD 1.1).                 # W3C JSON-LD 1.1
        Invalid JSON snippets are ignored.
        """
        items: List[Dict[str, Any]] = []
        for s in self._soup.find_all("script", attrs={"type": re.compile(r"(?i)^application/ld\+json$")}):
            raw = s.string or s.get_text()
            if not raw:
                continue
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    items.append(data)
                elif isinstance(data, list):
                    items.extend([x for x in data if isinstance(x, dict)])
            except Exception:
                continue
        return items

    # ---------------------- Links ----------------------

    def links(self, *, allow_schemes: Tuple[str, ...] = ("http", "https")) -> List[Link]:
        """
        Extract anchor links, resolve to absolute URLs per RFC 3986 & <base>, filter schemes.
        """
        out: List[Link] = []
        for a in self._soup.find_all("a", href=True):
            href_raw = a.get("href", "")
            url = self._resolve_url(href_raw)
            if not url:
                continue
            scheme = urlsplit(url).scheme.lower()
            if scheme not in allow_schemes:
                continue
            text = " ".join((a.get_text(" ", strip=True) or "").split())
            rel_tokens = tuple(sorted(set((a.get("rel") or []))))
            # Collect safe string attributes for debugging/auditing
            attrs = {k: v for k, v in a.attrs.items() if isinstance(v, str)}
            out.append(Link(url=url, href_raw=href_raw, text=text, rel=rel_tokens, attrs=attrs))
        return out

    # ---------------------- CSS selection helpers ----------------------

    def select_text(self, css: str, *, joiner: str = " ", limit: Optional[int] = None) -> str:
        """
        Get concatenated text for nodes matching CSS selector (first 'limit' nodes).
        """
        nodes = self._soup.select(css)
        if limit is not None:
            nodes = nodes[:limit]
        parts = []
        for n in nodes:
            parts.append(" ".join(n.get_text(" ", strip=True).split()))
        return joiner.join(parts)

    # ---------------------- Tables ----------------------

    def tables(self) -> List[List[Dict[str, str]]]:
        """
        Extract tables as list of rows, where each row is a dict {header: cell_text}.
        Header detection: <th> in first row; otherwise first <tr> as header.
        """
        all_tables: List[List[Dict[str, str]]] = []
        for tbl in self._soup.find_all("table"):
            rows = tbl.find_all("tr")
            if not rows:
                continue
            # Build header
            header_cells = rows[0].find_all(["th", "td"])
            headers = [self._cell_text(c) or f"col{idx+1}" for idx, c in enumerate(header_cells)]
            # Data rows
            data: List[Dict[str, str]] = []
            for tr in rows[1:] if header_cells else rows:
                cells = tr.find_all(["td", "th"])
                values = [self._cell_text(c) for c in cells]
                # Align
                while len(values) < len(headers):
                    values.append("")
                row = {headers[i]: values[i] for i in range(len(headers))}
                data.append(row)
            all_tables.append(data)
        return all_tables

    @staticmethod
    def _cell_text(tag) -> str:
        return " ".join((tag.get_text(" ", strip=True) or "").split())

    # ---------------------- Sanitization (optional) ----------------------

    def sanitize_html(
        self,
        *,
        allowed_tags: Optional[Iterable[str]] = None,
        allowed_attrs: Optional[Dict[str, Iterable[str]]] = None,
        strip: bool = True,
    ) -> str:
        """
        Sanitize HTML using Bleach if available. Falls back to ValueError otherwise.
        Bleach applies the HTML5 parsing algorithm and allowlist-based filtering.       # Bleach
        """
        try:
            import bleach  # type: ignore
        except Exception as e:
            raise ValueError("Bleach is required for HTML sanitization but is not installed") from e

        tags = list(allowed_tags or [])
        attrs = {k: list(v) for k, v in (allowed_attrs or {}).items()}
        return bleach.clean(str(self._soup), tags=tags, attributes=attrs, strip=strip)

    # ---------------------- Misc ----------------------

    @property
    def parser_name(self) -> str:
        return self._parser_name


# ------------------------------ Convenience API --------------------------------

def parse_html(
    html: Union[str, bytes],
    *,
    base_url: Optional[str] = None,
    parser_preference: Optional[Sequence[str]] = None,
) -> BS4Parser:
    """
    Factory to create BS4Parser with deterministic parser selection.
    """
    return BS4Parser(html, base_url=base_url, parser_preference=parser_preference)


__all__ = [
    "BS4Parser",
    "Link",
    "parse_html",
]
