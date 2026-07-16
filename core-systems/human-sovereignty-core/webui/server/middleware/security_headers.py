# human-sovereignty-core/webui/server/middleware/security_headers.py
from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from typing import Any, Callable, Mapping, MutableMapping, Optional

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response
except Exception:  # pragma: no cover
    BaseHTTPMiddleware = object  # type: ignore[misc,assignment]
    Request = object  # type: ignore[misc,assignment]
    Response = object  # type: ignore[misc,assignment]


class SecurityHeadersError(RuntimeError):
    pass


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _truthy(v: Any) -> bool:
    return bool(v) is True


def _to_str(v: Any) -> str:
    return "" if v is None else str(v)


def _ensure_dict(v: Any) -> dict[str, Any]:
    if v is None:
        return {}
    if isinstance(v, dict):
        return v
    return dict(v)  # type: ignore[arg-type]


def _set_header_if_absent(headers: MutableMapping[str, str], name: str, value: str) -> None:
    if not value:
        return
    key = name.lower()
    for existing in list(headers.keys()):
        if existing.lower() == key:
            return
    headers[name] = value


def _set_header_override(headers: MutableMapping[str, str], name: str, value: str) -> None:
    if not value:
        return
    to_del = []
    key = name.lower()
    for existing in list(headers.keys()):
        if existing.lower() == key:
            to_del.append(existing)
    for k in to_del:
        del headers[k]
    headers[name] = value


def _build_permissions_policy(pp: Any) -> str:
    d = _ensure_dict(pp)
    parts: list[str] = []
    for k, v in d.items():
        k_str = _to_str(k).strip()
        v_str = _to_str(v).strip()
        if not k_str or not v_str:
            continue
        parts.append(f"{k_str}={v_str}")
    return ", ".join(parts)


def _build_hsts(cfg: Mapping[str, Any]) -> str:
    enabled = _truthy(cfg.get("enabled"))
    if not enabled:
        return ""
    max_age = int(cfg.get("max_age_seconds", 0) or 0)
    if max_age <= 0:
        max_age = 31536000
    include_sub = _truthy(cfg.get("include_subdomains"))
    preload = _truthy(cfg.get("preload"))
    parts = [f"max-age={max_age}"]
    if include_sub:
        parts.append("includeSubDomains")
    if preload:
        parts.append("preload")
    return "; ".join(parts)


def _normalize_csp_value(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    s = str(v).strip()
    if not s:
        return []
    return [s]


def _build_csp_directives(
    directives: Mapping[str, Any],
    *,
    use_nonces: bool,
    nonce: Optional[str],
) -> str:
    parts: list[str] = []

    for key, value in directives.items():
        name = str(key).strip().replace("_", "-")
        if not name:
            continue

        items = _normalize_csp_value(value)
        if not items:
            continue

        if use_nonces and nonce and name in {"script-src", "style-src"}:
            has_nonce = any(i.startswith("'nonce-") for i in items)
            if not has_nonce:
                items.append(f"'nonce-{nonce}'")

        parts.append(f"{name} " + " ".join(items))

    return "; ".join(parts)


def _should_apply_hsts(request: Any) -> bool:
    try:
        if getattr(request, "url", None) is None:
            return False
        scheme = getattr(request.url, "scheme", "")
        return scheme == "https"
    except Exception:
        return False


@dataclass(frozen=True, slots=True)
class SecurityHeadersConfig:
    enabled: bool = True

    x_content_type_options: str = "nosniff"
    x_frame_options: str = "DENY"
    referrer_policy: str = "no-referrer"

    cross_origin_opener_policy: str = "same-origin"
    cross_origin_resource_policy: str = "same-origin"
    cross_origin_embedder_policy: str = "require-corp"

    permissions_policy: Mapping[str, Any] | None = None

    cache_control_enabled: bool = True
    cache_control_value: str = "no-store"

    hsts_enabled: bool = True
    hsts_value: str = "max-age=31536000; includeSubDomains"

    csp_enabled: bool = True
    csp_report_only: bool = False
    csp_use_nonces: bool = True
    csp_directives: Mapping[str, Any] | None = None
    csp_report_to: str | None = None
    csp_report_uri: str | None = None


def config_from_webui_security_yaml(root: Mapping[str, Any]) -> SecurityHeadersConfig:
    """
    Extracts only security header related config from a loaded webui_security.yaml dict.
    Caller is responsible for YAML parsing.
    """
    sh = _ensure_dict(root.get("security_headers"))
    csp = _ensure_dict(root.get("csp"))
    hsts = _ensure_dict(sh.get("strict_transport_security"))
    cache_ctl = _ensure_dict(sh.get("cache_control"))

    cfg = SecurityHeadersConfig(
        enabled=_truthy(sh.get("enabled", True)),
        x_content_type_options=_to_str(sh.get("x_content_type_options", "nosniff")) or "nosniff",
        x_frame_options=_to_str(sh.get("x_frame_options", "DENY")) or "DENY",
        referrer_policy=_to_str(sh.get("referrer_policy", "no-referrer")) or "no-referrer",
        cross_origin_opener_policy=_to_str(sh.get("cross_origin_opener_policy", "same-origin")) or "same-origin",
        cross_origin_resource_policy=_to_str(sh.get("cross_origin_resource_policy", "same-origin")) or "same-origin",
        cross_origin_embedder_policy=_to_str(sh.get("cross_origin_embedder_policy", "require-corp")) or "require-corp",
        permissions_policy=_ensure_dict(sh.get("permissions_policy")) or None,
        cache_control_enabled=_truthy(cache_ctl.get("enabled", True)),
        cache_control_value=_to_str(cache_ctl.get("value", "no-store")) or "no-store",
        hsts_enabled=_truthy(hsts.get("enabled", True)),
        hsts_value=_build_hsts(hsts) or "max-age=31536000; includeSubDomains",
        csp_enabled=_truthy(csp.get("enabled", True)),
        csp_report_only=_truthy(csp.get("report_only", False)),
        csp_use_nonces=_truthy(csp.get("use_nonces", True)),
        csp_directives=_ensure_dict(csp.get("directives")) or None,
        csp_report_to=_to_str(csp.get("report_to")) or None,
        csp_report_uri=_to_str(csp.get("report_uri")) or None,
    )
    return cfg


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Starlette/FastAPI middleware for security headers.

    Behavior:
    - Adds headers if absent (non-destructive), except Cache-Control which is overridden when enabled
    - HSTS is applied only for HTTPS requests
    - CSP supports per-request nonce (request.state.csp_nonce)
    """

    def __init__(self, app: Any, *, config: SecurityHeadersConfig) -> None:
        super().__init__(app)
        self._cfg = config

    async def dispatch(self, request: Any, call_next: Callable[[Any], Any]) -> Any:
        response = await call_next(request)
        if not self._cfg.enabled:
            return response

        headers = response.headers  # type: ignore[assignment]

        _set_header_if_absent(headers, "X-Content-Type-Options", self._cfg.x_content_type_options)
        _set_header_if_absent(headers, "X-Frame-Options", self._cfg.x_frame_options)
        _set_header_if_absent(headers, "Referrer-Policy", self._cfg.referrer_policy)

        _set_header_if_absent(headers, "Cross-Origin-Opener-Policy", self._cfg.cross_origin_opener_policy)
        _set_header_if_absent(headers, "Cross-Origin-Resource-Policy", self._cfg.cross_origin_resource_policy)
        _set_header_if_absent(headers, "Cross-Origin-Embedder-Policy", self._cfg.cross_origin_embedder_policy)

        if self._cfg.permissions_policy:
            pp = _build_permissions_policy(self._cfg.permissions_policy)
            _set_header_if_absent(headers, "Permissions-Policy", pp)

        if self._cfg.cache_control_enabled:
            _set_header_override(headers, "Cache-Control", self._cfg.cache_control_value)

        if self._cfg.hsts_enabled and _should_apply_hsts(request):
            _set_header_if_absent(headers, "Strict-Transport-Security", self._cfg.hsts_value)

        if self._cfg.csp_enabled and self._cfg.csp_directives:
            nonce: Optional[str] = None
            if self._cfg.csp_use_nonces:
                nonce = self._get_or_create_nonce(request)
            csp_value = _build_csp_directives(
                self._cfg.csp_directives,
                use_nonces=self._cfg.csp_use_nonces,
                nonce=nonce,
            )
            if csp_value:
                header_name = "Content-Security-Policy-Report-Only" if self._cfg.csp_report_only else "Content-Security-Policy"
                _set_header_if_absent(headers, header_name, csp_value)

            if self._cfg.csp_report_to:
                _set_header_if_absent(headers, "Report-To", self._cfg.csp_report_to)
            if self._cfg.csp_report_uri:
                _set_header_if_absent(headers, "Reporting-Endpoints", self._cfg.csp_report_uri)

        return response

    @staticmethod
    def _get_or_create_nonce(request: Any) -> str:
        try:
            st = getattr(request, "state", None)
            if st is None:
                return _b64u(secrets.token_bytes(16))
            existing = getattr(st, "csp_nonce", None)
            if isinstance(existing, str) and existing:
                return existing
            nonce = _b64u(secrets.token_bytes(16))
            setattr(st, "csp_nonce", nonce)
            return nonce
        except Exception:
            return _b64u(secrets.token_bytes(16))


def build_security_headers_middleware(
    *,
    webui_security_config: Mapping[str, Any],
) -> tuple[type[SecurityHeadersMiddleware], dict[str, Any]]:
    """
    Helper for FastAPI/Starlette registration style:

    app.add_middleware(SecurityHeadersMiddleware, config=cfg)

    Returns middleware class and kwargs dict.
    """
    cfg = config_from_webui_security_yaml(webui_security_config)
    return SecurityHeadersMiddleware, {"config": cfg}


__all__ = [
    "SecurityHeadersError",
    "SecurityHeadersConfig",
    "config_from_webui_security_yaml",
    "SecurityHeadersMiddleware",
    "build_security_headers_middleware",
]
