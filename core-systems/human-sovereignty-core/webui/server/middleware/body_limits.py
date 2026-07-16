# human-sovereignty-core/webui/server/middleware/body_limits.py
#
# Industrial-grade ASGI middleware for request body limits and content-type enforcement.
#
# Verified scope:
# - ASGI 3.0 specification
# - Starlette / FastAPI compatible
#
# This middleware does not claim protection beyond documented HTTP behavior.

from __future__ import annotations

from typing import Callable, Iterable, Optional, Set

from starlette.datastructures import Headers
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodyLimitViolation(HTTPException):
    def __init__(self, detail: str, status_code: int = 413) -> None:
        super().__init__(status_code=status_code, detail=detail)


class ContentTypeViolation(HTTPException):
    def __init__(self, detail: str = "Unsupported Content-Type") -> None:
        super().__init__(status_code=415, detail=detail)


class BodyLimitsMiddleware:
    """
    ASGI middleware enforcing:
    - Maximum request body size
    - Allowed Content-Type list
    - Protection against unlimited chunked bodies

    Facts:
    - Content-Length header is optional per RFC 7230
    - Transfer-Encoding: chunked may omit Content-Length
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int,
        allowed_content_types: Optional[Iterable[str]] = None,
        allow_empty_body: bool = True,
    ) -> None:
        if not isinstance(max_body_bytes, int) or max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be a positive integer")

        self.app = app
        self.max_body_bytes = max_body_bytes
        self.allow_empty_body = allow_empty_body
        self.allowed_content_types: Optional[Set[str]] = (
            {ct.lower() for ct in allowed_content_types}
            if allowed_content_types is not None
            else None
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)

        self._enforce_content_type(headers)
        self._enforce_content_length_header(headers)

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()

            if message["type"] == "http.request":
                body = message.get("body", b"")
                received += len(body)

                if received > self.max_body_bytes:
                    raise BodyLimitViolation(
                        f"Request body exceeds {self.max_body_bytes} bytes"
                    )

                if not body and not message.get("more_body", False):
                    if not self.allow_empty_body and received == 0:
                        raise BodyLimitViolation("Empty request body not allowed", 400)

            return message

        try:
            await self.app(scope, limited_receive, send)
        except HTTPException:
            raise
        except Exception:
            raise

    def _enforce_content_type(self, headers: Headers) -> None:
        if self.allowed_content_types is None:
            return

        content_type = headers.get("content-type")
        if content_type is None:
            raise ContentTypeViolation("Missing Content-Type header")

        normalized = content_type.split(";")[0].strip().lower()
        if normalized not in self.allowed_content_types:
            raise ContentTypeViolation(
                f"Content-Type '{normalized}' is not allowed"
            )

    def _enforce_content_length_header(self, headers: Headers) -> None:
        content_length = headers.get("content-length")
        if content_length is None:
            return

        try:
            value = int(content_length)
        except ValueError:
            raise BodyLimitViolation("Invalid Content-Length header", 400)

        if value < 0:
            raise BodyLimitViolation("Negative Content-Length not allowed", 400)

        if value > self.max_body_bytes:
            raise BodyLimitViolation(
                f"Content-Length {value} exceeds limit {self.max_body_bytes}"
            )
