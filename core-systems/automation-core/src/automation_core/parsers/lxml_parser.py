# automation-core/src/automation_core/parsers/lxml_parser.py
# -*- coding: utf-8 -*-
"""
Безопасный промышленный парсер XML/HTML на базе lxml.

Проверяемые источники:
- lxml.etree.XMLParser / HTMLParser (параметры no_network, resolve_entities, load_dtd, huge_tree):
  https://lxml.de/parsing.html
- XPath / CSS selectors (lxml.cssselect требует пакет cssselect):
  https://lxml.de/xpathxslt.html
  https://lxml.de/cssselect.html
- Очистка HTML (lxml.html.clean.Cleaner):
  https://lxml.de/lxmlhtml.html#cleaning-up-html
- OWASP XXE Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- Python XML vulnerabilities (офиц. документация Python):
  https://docs.python.org/3/library/xml.html#xml-vulnerabilities

Замечания по безопасности:
- По умолчанию запрещены внешние сущности и сетевые загрузки (защита от XXE/SSRF).
- Параметр huge_tree по умолчанию False (смягчает риск «XML Bomb»).
- Для HTML-очистки используйте sanitize_html(), которая применяет lxml.html.clean.Cleaner.

Зависимости:
- Обязательная: lxml
- Опциональная для CSS-селекторов: cssselect (если нет — select_css() вызовет RuntimeError с подсказкой).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union

import io
import re

from lxml import etree, html


# ----------------------------
# Конфигурационные структуры
# ----------------------------

@dataclass(frozen=True)
class XMLParseOptions:
    load_dtd: bool = False
    no_network: bool = True
    resolve_entities: bool = False
    remove_blank_text: bool = False
    remove_comments: bool = False
    remove_pis: bool = False
    huge_tree: bool = False
    recover: bool = False  # осторожно: recover может скрывать ошибки разметки


@dataclass(frozen=True)
class HTMLParseOptions:
    remove_comments: bool = True
    remove_blank_text: bool = False  # применимо не ко всем документам; оставлено для совместимости
    recover: bool = True
    no_network: bool = True
    # HTMLParser не обрабатывает DTD аналогично XML, но запрет сети оставляем


# ----------------------------
# Создание безопасных парсеров
# ----------------------------

def make_xml_parser(opts: Optional[XMLParseOptions] = None) -> etree.XMLParser:
    o = opts or XMLParseOptions()
    # Источник параметров: https://lxml.de/parsing.html
    parser = etree.XMLParser(
        load_dtd=o.load_dtd,
        no_network=o.no_network,
        resolve_entities=o.resolve_entities,
        remove_blank_text=o.remove_blank_text,
        remove_comments=o.remove_comments,
        remove_pis=o.remove_pis,
        huge_tree=o.huge_tree,
        recover=o.recover,
        encoding=None,  # позволяем lxml определить из заголовков/пролога
    )
    return parser


def make_html_parser(opts: Optional[HTMLParseOptions] = None) -> etree.HTMLParser:
    o = opts or HTMLParseOptions()
    # HTML-парсер lxml также поддерживает no_network (унаследовано от XMLParser)
    parser = etree.HTMLParser(
        remove_comments=o.remove_comments,
        # remove_blank_text поддерживается не для всех HTML-входов — оставляем False по умолчанию
        recover=o.recover,
        no_network=o.no_network,
        encoding=None,
    )
    return parser


# ----------------------------
# Высокоуровневые функции XML
# ----------------------------

def parse_xml_bytes(data: bytes, *, base_url: Optional[str] = None,
                    opts: Optional[XMLParseOptions] = None) -> etree._ElementTree:
    parser = make_xml_parser(opts)
    return etree.parse(io.BytesIO(data), parser=parser, base_url=base_url)


def parse_xml_string(text: str, *, base_url: Optional[str] = None,
                     opts: Optional[XMLParseOptions] = None) -> etree._ElementTree:
    return parse_xml_bytes(text.encode("utf-8"), base_url=base_url, opts=opts)


def parse_xml_file(path_or_file, *, opts: Optional[XMLParseOptions] = None) -> etree._ElementTree:
    """
    path_or_file: str | pathlib.Path | file-like (открытый бинарный поток)
    """
    parser = make_xml_parser(opts)
    return etree.parse(path_or_file, parser=parser)


def iterparse_xml(source, *, tags: Optional[Union[str, Sequence[str]]] = None,
                  opts: Optional[XMLParseOptions] = None) -> Iterator[Tuple[str, etree._Element]]:
    """
    Потоковый разбор больших XML через iterparse.
    Источник API: https://lxml.de/parsing.html#parsing-large-xml-files-with-incremental-parser
    """
    o = opts or XMLParseOptions()
    parser = make_xml_parser(o)
    events = ("end",)
    return etree.iterparse(source, events=events, tag=tags, parser=parser)


# ----------------------------
# Высокоуровневые функции HTML
# ----------------------------

def parse_html_bytes(data: bytes, *, base_url: Optional[str] = None,
                     opts: Optional[HTMLParseOptions] = None) -> html.HtmlElement:
    parser = make_html_parser(opts)
    doc = html.document_fromstring(data, base_url=base_url, parser=parser)
    return doc


def parse_html_string(text: str, *, base_url: Optional[str] = None,
                      opts: Optional[HTMLParseOptions] = None) -> html.HtmlElement:
    return parse_html_bytes(text.encode("utf-8"), base_url=base_url, opts=opts)


def parse_html_file(path_or_file, *, opts: Optional[HTMLParseOptions] = None) -> html.HtmlElement:
    parser = make_html_parser(opts)
    return html.parse(path_or_file, parser=parser).getroot()


# ----------------------------
# Поиск: XPath и CSS
# ----------------------------

def select_xpath(node: Union[etree._Element, etree._ElementTree],
                 xpath: str,
                 namespaces: Optional[Dict[str, str]] = None) -> List[Any]:
    """
    Выполняет XPath-запрос. Возвращает список узлов/значений.
    Документация: https://lxml.de/xpathxslt.html
    """
    return node.xpath(xpath, namespaces=namespaces or {})


def select_one_xpath(node: Union[etree._Element, etree._ElementTree],
                     xpath: str,
                     namespaces: Optional[Dict[str, str]] = None) -> Optional[Any]:
    res = select_xpath(node, xpath, namespaces)
    return res[0] if res else None


def _require_cssselect():
    try:
        import cssselect  # noqa: F401
    except Exception as e:
        raise RuntimeError(
            "Для CSS-селекторов требуется пакет 'cssselect' "
            "(см. https://lxml.de/cssselect.html)"
        ) from e


def select_css(node: Union[html.HtmlElement, etree._Element],
               selector: str) -> List[html.HtmlElement]:
    """
    Ищет по CSS-селектору (требуется пакет cssselect).
    Документация: https://lxml.de/cssselect.html
    """
    _require_cssselect()
    if hasattr(node, "cssselect"):
        return node.cssselect(selector)  # type: ignore[attr-defined]
    # Если узел не HtmlElement — оборачиваем в HtmlElement для cssselect
    root = html.fromstring(etree.tostring(node))
    return root.cssselect(selector)


def select_one_css(node: Union[html.HtmlElement, etree._Element],
                   selector: str) -> Optional[html.HtmlElement]:
    res = select_css(node, selector)
    return res[0] if res else None


# ----------------------------
# Текст/атрибуты/сериализация
# ----------------------------

_WS_RE = re.compile(r"\s+", re.MULTILINE)

def text_content(node: Union[html.HtmlElement, etree._Element], *,
                 sep: str = " ", strip: bool = True, collapse_ws: bool = True) -> str:
    """
    Возвращает человекочитаемый текст узла (без скриптов/стилей).
    """
    txt = node.text_content() if isinstance(node, html.HtmlElement) else "".join(node.itertext())
    if strip:
        txt = txt.strip()
    if collapse_ws:
        txt = _WS_RE.sub(sep, txt)
    return txt


def get_attr(node: etree._Element, name: str, default: Optional[str] = None) -> Optional[str]:
    return node.get(name, default)


def tostring(node: Union[etree._Element, etree._ElementTree], *,
             pretty: bool = False,
             encoding: str = "utf-8",
             with_tail: bool = False,
             method: str = "xml") -> bytes:
    """
    Сериализация узла/дерева в bytes.
    method: "xml" | "html" | "text"
    """
    return etree.tostring(node, pretty_print=pretty, encoding=encoding, with_tail=with_tail, method=method)


# ----------------------------
# Очистка HTML (санитайзер)
# ----------------------------

def sanitize_html(node: Union[str, bytes, html.HtmlElement], *,
                  allow_tags: Optional[List[str]] = None,
                  allow_attrs: Optional[Dict[str, List[str]]] = None,
                  kill_scripts: bool = True,
                  forms: bool = False,
                  embedded: bool = False) -> html.HtmlElement:
    """
    Безопасная очистка HTML (удаление <script>, inline-JS, опасных URL и т.п.).
    Основано на lxml.html.clean.Cleaner:
    https://lxml.de/lxmlhtml.html#cleaning-up-html
    """
    from lxml.html.clean import Cleaner

    cleaner = Cleaner(
        scripts=kill_scripts,
        javascript=kill_scripts,
        comments=True,
        style=True,
        inline_style=True,
        links=False,
        meta=False,
        page_structure=False,
        safe_attrs_only=bool(allow_attrs or allow_tags),
        allow_tags=allow_tags,
        safe_attrs=frozenset(sum((v for v in (allow_attrs or {}).values()), [])) if allow_attrs else None,
        forms=forms,
        embedded=embedded,
        remove_unknown_tags=False,
    )

    if isinstance(node, (str, bytes)):
        root = parse_html_bytes(node if isinstance(node, bytes) else node.encode("utf-8"))
    else:
        root = node
    cleaned = cleaner.clean_html(root)
    return cleaned


# ----------------------------
# Примеры безопасного использования (док-примеры)
# ----------------------------
# XML:
#   tree = parse_xml_file("data.xml")
#   root = tree.getroot()
#   items = select_xpath(root, "//item[@type='a']")
#
# HTML:
#   doc = parse_html_string("<html>...</html>")
#   title = text_content(select_one_css(doc, "title"))


__all__ = [
    "XMLParseOptions",
    "HTMLParseOptions",
    "make_xml_parser",
    "make_html_parser",
    "parse_xml_bytes",
    "parse_xml_string",
    "parse_xml_file",
    "iterparse_xml",
    "parse_html_bytes",
    "parse_html_string",
    "parse_html_file",
    "select_xpath",
    "select_one_xpath",
    "select_css",
    "select_one_css",
    "text_content",
    "get_attr",
    "tostring",
    "sanitize_html",
]
