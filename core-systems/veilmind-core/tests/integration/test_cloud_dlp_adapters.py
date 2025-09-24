# veilmind-core/tests/integration/test_cloud_dlp_adapters.py
# -*- coding: utf-8 -*-
"""
Integration-like tests for cloud DLP adapters (Azure PII) using httpx + respx.

Dependencies:
  pip install pytest respx httpx
Async tests require:
  pip install pytest-asyncio

These tests do not perform real network calls.
"""

from __future__ import annotations

import json
import hashlib
import typing as t
import pytest

# --- Skip gracefully if adapter or tools are missing ---

azure_mod = pytest.importorskip("veilmind.adapters.azure_pii_adapter")
httpx_mod = pytest.importorskip("httpx")
respx_mod = pytest.importorskip("respx")

from veilmind.adapters.azure_pii_adapter import (
    AzurePIIConfig,
    AzurePIIAdapter,
    AsyncAzurePIIAdapter,
    PIIEntity,
    PIIResult,
)

import respx
from httpx import Response, Request


# ------------------------- Helpers -------------------------

def _sha256_of(obj: t.Any) -> str:
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _assert_basic_headers(req: Request, cfg: AzurePIIConfig) -> None:
    # Auth header: either api-key or bearer
    if cfg.api_key:
        assert req.headers.get("Ocp-Apim-Subscription-Key") == cfg.api_key
    if cfg.bearer_token:
        assert req.headers.get("Authorization", "").startswith("Bearer ")
    # Content type and integrity
    assert req.headers.get("Content-Type") == "application/json"
    assert "Content-SHA256" in req.headers
    # Basic UA and accept
    assert req.headers.get("Accept", "").startswith("application/json")


def _build_service_response(entities: list[dict], *, redacted_text: str | None = None) -> dict:
    doc = {"id": "1", "entities": entities}
    if redacted_text is not None:
        doc["redactedText"] = redacted_text
    return {"documents": [doc], "errors": []}


# ------------------------- Fixtures -------------------------

@pytest.fixture
def cfg_key() -> AzurePIIConfig:
    return AzurePIIConfig(
        endpoint="https://example.cognitiveservices.azure.com",
        pii_path="/text/analytics/v3.2/entities/recognition/pii",
        api_key="test-key",
        default_language="en",
        string_index_type="UnicodeCodePoint",
        local_redact=True,
        batch_size=2,  # to exercise chunking
        log_requests=False,
    )


@pytest.fixture
def cfg_bearer() -> AzurePIIConfig:
    return AzurePIIConfig(
        endpoint="https://example.cognitiveservices.azure.com",
        pii_path="/text/analytics/v3.2/entities/recognition/pii",
        bearer_token="test-token",
        default_language=None,
        local_redact=True,
        log_requests=False,
    )


# ------------------------- Tests: single call -------------------------

@respx.mock
def test_azure_single_success_normalization_and_headers(cfg_key: AzurePIIConfig):
    adapter = AzurePIIAdapter(cfg_key)
    route = respx.post(cfg_key.endpoint + cfg_key.pii_path)

    def _handler(req: Request) -> Response:
        # Headers
        _assert_basic_headers(req, cfg_key)
        # Body shape and options
        payload = req.json()
        assert "documents" in payload and isinstance(payload["documents"], list) and payload["documents"]
        # options should include stringIndexType, because configured
        assert "options" in payload and payload["options"].get("stringIndexType") == "UnicodeCodePoint"
        # Integrity: Content-SHA256 must match full payload, not only documents
        assert req.headers["Content-SHA256"] == _sha256_of(payload)
        # Return a recognizable entity set
        entities = [
            {"category": "Email", "text": "john.doe@example.org", "offset": 11, "length": 20, "confidenceScore": 0.98},
            {"category": "CreditCardNumber", "text": "4111 1111 1111 1111", "offset": 40, "length": 19, "confidenceScore": 0.99},
        ]
        body = _build_service_response(entities, redacted_text="My email is ******************** and card **** **** **** ****")
        return Response(200, json=body)

    route.mock(side_effect=_handler)

    text = "My email is john.doe@example.org and card 4111 1111 1111 1111"
    result: PIIResult = adapter.recognize_pii(text)
    adapter.close()

    # Service-provided redacted text is preserved in raw_redacted_text_from_service;
    # local redaction should not override it
    assert result.raw_redacted_text_from_service
    # Entities normalized
    kinds = {e.kind for e in result.entities}
    assert "EMAIL" in kinds and "CREDIT_CARD" in kinds
    # Hashed values present but source text not returned
    for e in result.entities:
        assert isinstance(e.offset, int) and isinstance(e.length, int)
        if e.kind in {"EMAIL", "CREDIT_CARD"}:
            assert e.hashed_value and len(e.hashed_value) == 64


@respx.mock
def test_azure_retries_on_429_then_success(cfg_bearer: AzurePIIConfig):
    cfg_bearer.retries = 2
    adapter = AzurePIIAdapter(cfg_bearer)

    route = respx.post(cfg_bearer.endpoint + cfg_bearer.pii_path)
    call_counter = {"n": 0}

    def _handler(req: Request) -> Response:
        call_counter["n"] += 1
        if call_counter["n"] == 1:
            return Response(429, json={"error": {"code": "TooManyRequests"}})
        entities = [{"category": "Email", "text": "a@b.com", "offset": 0, "length": 6, "confidenceScore": 0.9}]
        return Response(200, json=_build_service_response(entities, redacted_text="******"))

    route.mock(side_effect=_handler)

    res = adapter.recognize_pii("a@b.com", language="en")
    adapter.close()

    assert call_counter["n"] == 2
    assert res.entities and res.entities[0].kind == "EMAIL"


# ------------------------- Tests: batch & filtering -------------------------

@respx.mock
def test_azure_batch_chunking_and_category_filter(cfg_key: AzurePIIConfig):
    # Allow only Email in result
    cfg_key.categories_allow = ["Email"]
    cfg_key.batch_size = 2
    adapter = AzurePIIAdapter(cfg_key)

    base = cfg_key.endpoint + cfg_key.pii_path

    # First batch (2 docs)
    def _handler_batch1(req: Request) -> Response:
        payload = req.json()
        docs = payload["documents"]
        assert len(docs) == 2
        # Return mixed categories, filter should keep only Email
        ents = [
            {"id": "1", "entities": [
                {"category": "Email", "text": "x@y.com", "offset": 0, "length": 7, "confidenceScore": 0.9},
                {"category": "PhoneNumber", "text": "+1 555 123 1234", "offset": 10, "length": 14, "confidenceScore": 0.8},
            ]},
            {"id": "2", "entities": [
                {"category": "CreditCardNumber", "text": "4111 1111 1111 1111", "offset": 0, "length": 19, "confidenceScore": 0.99},
            ]},
        ]
        return Response(200, json={"documents": ents, "errors": []})

    # Second batch (1 doc)
    def _handler_batch2(req: Request) -> Response:
        payload = req.json()
        docs = payload["documents"]
        assert len(docs) == 1
        ents = [{"id": "1", "entities": [
            {"category": "Email", "text": "a@b.com", "offset": 0, "length": 6, "confidenceScore": 0.95}
        ]}]
        return Response(200, json={"documents": ents, "errors": []})

    calls = respx.Route()
    respx.post(base).mock(side_effect=[_handler_batch1, _handler_batch2])

    items = [
        ("x@y.com and phone +1 555 123 1234", "en"),
        ("4111 1111 1111 1111", "en"),
        ("a@b.com", None),
    ]
    results = adapter.batch_recognize_pii(items)
    adapter.close()

    assert len(results) == 3
    # Only Email should remain
    kinds = [ [e.kind for e in r.entities] for r in results ]
    assert kinds[0] == ["EMAIL"]
    assert kinds[1] == []  # credit card filtered out
    assert kinds[2] == ["EMAIL"]


# ------------------------- Tests: local redaction fallback -------------------------

@respx.mock
def test_azure_local_redaction_when_service_not_providing_redacted_text(cfg_bearer: AzurePIIConfig):
    cfg_bearer.local_redact = True
    cfg_bearer.mask_char = "*"
    cfg_bearer.keep_left = 1
    cfg_bearer.keep_right = 1
    adapter = AzurePIIAdapter(cfg_bearer)

    route = respx.post(cfg_bearer.endpoint + cfg_bearer.pii_path)

    def _handler(req: Request) -> Response:
        # Return entities without redactedText from service
        ents = [{"category": "Email", "text": "john.doe@example.org", "offset": 11, "length": 20, "confidenceScore": 0.99}]
        return Response(200, json=_build_service_response(ents, redacted_text=None))

    route.mock(side_effect=_handler)

    text = "My email is john.doe@example.org"
    res = adapter.recognize_pii(text)
    adapter.close()

    assert res.redacted_text is not None
    # Should mask email span, keeping 1 char on both sides
    assert "j" in res.redacted_text and "g" in res.redacted_text
    # but the middle should be masked
    assert "*" * 3 in res.redacted_text


# ------------------------- Tests: async client -------------------------

pytestmark = pytest.mark.asyncio


@respx.mock
async def test_async_adapter_success(cfg_key: AzurePIIConfig):
    adapter = AsyncAzurePIIAdapter(cfg_key)

    route = respx.post(cfg_key.endpoint + cfg_key.pii_path)

    def _handler(req: Request) -> Response:
        ents = [{"category": "Email", "text": "a@b.com", "offset": 0, "length": 6, "confidenceScore": 0.95}]
        return Response(200, json=_build_service_response(ents, redacted_text="******"))

    route.mock(side_effect=_handler)

    result = await adapter.recognize_pii("a@b.com")
    await adapter.aclose()

    assert result.entities and result.entities[0].kind == "EMAIL"
    assert result.raw_redacted_text_from_service == "******"


# ------------------------- Tests: config validation -------------------------

def test_config_validation_missing_auth_fails():
    with pytest.raises(ValueError):
        AzurePIIConfig(
            endpoint="https://example.cognitiveservices.azure.com",
            pii_path="/text/analytics/v3.2/entities/recognition/pii",
            # neither api_key nor bearer_token nor custom headers
        )

def test_config_validation_endpoint_and_path_format():
    with pytest.raises(ValueError):
        AzurePIIConfig(endpoint="example.com", pii_path="/text/analytics/v3.2/entities/recognition/pii", api_key="k")
    with pytest.raises(ValueError):
        AzurePIIConfig(endpoint="https://example.com", pii_path="pii", api_key="k")
