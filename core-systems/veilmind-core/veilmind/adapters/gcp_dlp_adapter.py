# path: veilmind-core/veilmind/adapters/gcp_dlp_adapter.py
from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

# Опциональные зависимости GCP
try:
    from google.cloud import dlp_v2
    from google.cloud.dlp_v2 import types as dlp_types
    from google.api_core import exceptions as gapi_exceptions
    from google.api_core.client_options import ClientOptions
except Exception:  # pragma: no cover
    dlp_v2 = None  # type: ignore
    dlp_types = None  # type: ignore
    gapi_exceptions = None  # type: ignore
    ClientOptions = None  # type: ignore


Likelihood = Literal[
    "VERY_UNLIKELY", "UNLIKELY", "POSSIBLE", "LIKELY", "VERY_LIKELY"
]

@dataclass(frozen=True)
class DlpFinding:
    info_type: str
    likelihood: Likelihood
    quote: Optional[str]
    byte_offset: int
    byte_length: int


@dataclass(frozen=True)
class DlpInspectResult:
    findings: Tuple[DlpFinding, ...]
    findings_truncated: bool
    item_size_bytes: int


@dataclass(frozen=True)
class DlpDeidentifyResult:
    text: str
    findings: Tuple[DlpFinding, ...]
    item_size_bytes: int


class DlpNotAvailable(RuntimeError):
    pass


class DlpRequestError(RuntimeError):
    pass


def _require_lib() -> None:
    if dlp_v2 is None:
        raise DlpNotAvailable("google-cloud-dlp не установлен или недоступен в окружении")


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name, default)
    return v if v is not None and v != "" else default


def _normalize_likelihood(v: Any) -> Likelihood:
    # Нормализация enum в читаемую строку
    if v is None:
        return "POSSIBLE"
    s = str(v)
    # Возможные формы: <Likelihood.VERY_LIKELY: 5>, VERY_LIKELY, 5
    if s.isdigit():
        mapping = {
            "1": "VERY_UNLIKELY",
            "2": "UNLIKELY",
            "3": "POSSIBLE",
            "4": "LIKELY",
            "5": "VERY_LIKELY",
        }
        return mapping.get(s, "POSSIBLE")  # type: ignore[return-value]
    upper = s.split(".")[-1].upper()
    allowed: Tuple[Likelihood, ...] = (
        "VERY_UNLIKELY", "UNLIKELY", "POSSIBLE", "LIKELY", "VERY_LIKELY"
    )
    return upper if upper in allowed else "POSSIBLE"  # type: ignore[return-value]


def _to_min_likelihood(v: Optional[str]) -> int:
    # DLP ждёт целочисленный enum; упростим отображение
    order = {
        "VERY_UNLIKELY": 1,
        "UNLIKELY": 2,
        "POSSIBLE": 3,
        "LIKELY": 4,
        "VERY_LIKELY": 5,
    }
    return order.get((v or "POSSIBLE").upper(), 3)


def _default_info_types() -> List[Dict[str, str]]:
    # Подборка распространённых инфо‑типов (GCP DLP)
    names = [
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD_NUMBER",
        "IBAN_CODE",
        "US_SOCIAL_SECURITY_NUMBER",
        "IP_ADDRESS",
        "MAC_ADDRESS",
        "PERSON_NAME",
        "AGE",
        "DATE_OF_BIRTH",
        "DRIVER_LICENSE_NUMBER",
        "PASSPORT",
        "LOCATION",
        "ORGANIZATION_NAME",
        "MEDICAL_RECORD_NUMBER",
        "ETHNIC_GROUP",
        "RACE",
        "GENDER",
        "JWT",
        "PASSWORD",
        "AUTH_TOKEN",
        "GCP_API_KEY",
        "AWS_ACCESS_KEY",
    ]
    return [{"name": n} for n in names]


# Максимальный размер контента в одном ContentItem — ориентир 512 KiB (с запасом ниже лимита DLP ~1 MiB)
_CHUNK_SIZE = int(_env("DLP_MAX_CHUNK_BYTES", str(512 * 1024)) or 0) or (512 * 1024)


def _chunk_bytes(b: bytes, size: int) -> List[Tuple[int, bytes]]:
    out: List[Tuple[int, bytes]] = []
    i = 0
    while i < len(b):
        out.append((i, b[i : i + size]))
        i += size
    return out


class GcpDlpAdapter:
    """
    Промышленный адаптер GCP DLP для задач инспекции и де‑идентификации текста.
    Безопасно создаёт клиента, выполняет ретраи, бьёт большие тела на чанки, нормализует результаты.
    """

    def __init__(
        self,
        project_id: Optional[str] = None,
        location_id: Optional[str] = None,
        *,
        request_timeout_s: float = 6.0,
        max_retries: int = 3,
        initial_backoff_s: float = 0.2,
        backoff_multiplier: float = 2.0,
    ) -> None:
        _require_lib()
        self.project_id = project_id or _env("GCP_PROJECT") or _env("GOOGLE_CLOUD_PROJECT")
        if not self.project_id:
            raise ValueError("Не указан project_id (GCP_PROJECT/GOOGLE_CLOUD_PROJECT).")
        self.location_id = location_id or _env("GCP_LOCATION", "global")
        self.parent = f"projects/{self.project_id}/locations/{self.location_id}"

        self.request_timeout_s = request_timeout_s
        self.max_retries = max_retries
        self.initial_backoff_s = initial_backoff_s
        self.backoff_multiplier = backoff_multiplier

        opts = ClientOptions(api_endpoint=f"{self.location_id}-dlp.googleapis.com" if self.location_id != "global" else None)
        self._client = dlp_v2.DlpServiceClient(client_options=opts)

    # -----------------------
    # Публичные высокоуровневые методы
    # -----------------------

    def inspect_text(
        self,
        text: str,
        *,
        info_types: Optional[Sequence[str]] = None,
        include_quotes: bool = True,
        min_likelihood: Likelihood = "POSSIBLE",
        max_findings: int = 1000,
        hotword_regex: Optional[str] = None,
    ) -> DlpInspectResult:
        """
        Инспекция текста. Для больших тел выполняет чанкинг и агрегирует результаты.
        """
        b = text.encode("utf-8", errors="ignore")
        chunks = _chunk_bytes(b, _CHUNK_SIZE)
        findings: List[DlpFinding] = []
        total = 0
        truncated = False

        for base_offset, data in chunks:
            total += len(data)
            res = self._inspect_chunk(
                data,
                info_types=info_types,
                include_quotes=include_quotes,
                min_likelihood=min_likelihood,
                max_findings=max_findings - len(findings),
                hotword_regex=hotword_regex,
            )
            for f in res.findings:
                findings.append(
                    DlpFinding(
                        info_type=f.info_type,
                        likelihood=f.likelihood,
                        quote=f.quote,
                        byte_offset=f.byte_offset + base_offset,
                        byte_length=f.byte_length,
                    )
                )
            truncated = truncated or res.findings_truncated
            if len(findings) >= max_findings:
                truncated = True
                break

        return DlpInspectResult(
            findings=tuple(findings),
            findings_truncated=truncated,
            item_size_bytes=len(b),
        )

    def deidentify_text(
        self,
        text: str,
        *,
        info_types: Optional[Sequence[str]] = None,
        mask_char: str = "*",
        number_to_mask: int = 0,  # 0 = маскировать всё; иначе ограничить число символов
        replace_with_info_type: bool = False,
        min_likelihood: Likelihood = "POSSIBLE",
    ) -> DlpDeidentifyResult:
        """
        Де‑идентификация текста. Для больших тел работает по чанкам и склеивает.
        """
        b = text.encode("utf-8", errors="ignore")
        chunks = _chunk_bytes(b, _CHUNK_SIZE)
        parts: List[str] = []
        all_findings: List[DlpFinding] = []
        total = 0

        for base_offset, data in chunks:
            total += len(data)
            res = self._deidentify_chunk(
                data,
                info_types=info_types,
                mask_char=mask_char,
                number_to_mask=number_to_mask,
                replace_with_info_type=replace_with_info_type,
                min_likelihood=min_likelihood,
            )
            parts.append(res.text)
            for f in res.findings:
                all_findings.append(
                    DlpFinding(
                        info_type=f.info_type,
                        likelihood=f.likelihood,
                        quote=f.quote,
                        byte_offset=f.byte_offset + base_offset,
                        byte_length=f.byte_length,
                    )
                )

        return DlpDeidentifyResult(
            text="".join(parts),
            findings=tuple(all_findings),
            item_size_bytes=len(b),
        )

    # Асинхронные обёртки
    async def ainspect_text(self, *args, **kwargs) -> DlpInspectResult:
        return await asyncio.to_thread(self.inspect_text, *args, **kwargs)

    async def adeidentify_text(self, *args, **kwargs) -> DlpDeidentifyResult:
        return await asyncio.to_thread(self.deidentify_text, *args, **kwargs)

    # -----------------------
    # Низкоуровневые вызовы чанков
    # -----------------------

    def _inspect_chunk(
        self,
        data: bytes,
        *,
        info_types: Optional[Sequence[str]],
        include_quotes: bool,
        min_likelihood: Likelihood,
        max_findings: int,
        hotword_regex: Optional[str],
    ) -> DlpInspectResult:
        req = self._build_inspect_request(
            content_bytes=data,
            info_types=info_types,
            include_quotes=include_quotes,
            min_likelihood=min_likelihood,
            max_findings=max_findings,
            hotword_regex=hotword_regex,
        )
        resp = self._call_with_retries(self._client.inspect_content, request=req)
        findings = []
        for f in getattr(resp.result, "findings", []):  # type: ignore[attr-defined]
            findings.append(
                DlpFinding(
                    info_type=f.info_type.name if f.info_type else "UNKNOWN",
                    likelihood=_normalize_likelihood(f.likelihood),
                    quote=(f.quote if include_quotes else None),
                    byte_offset=int(getattr(f.location.byte_range, "start", 0) or 0),
                    byte_length=int((getattr(f.location.byte_range, "end", 0) or 0) - (getattr(f.location.byte_range, "start", 0) or 0)),
                )
            )
        truncated = bool(getattr(resp.result, "findings_truncated", False))  # type: ignore[attr-defined]
        return DlpInspectResult(findings=tuple(findings), findings_truncated=truncated, item_size_bytes=len(data))

    def _deidentify_chunk(
        self,
        data: bytes,
        *,
        info_types: Optional[Sequence[str]],
        mask_char: str,
        number_to_mask: int,
        replace_with_info_type: bool,
        min_likelihood: Likelihood,
    ) -> DlpDeidentifyResult:
        req = self._build_deidentify_request(
            content_bytes=data,
            info_types=info_types,
            mask_char=mask_char,
            number_to_mask=number_to_mask,
            replace_with_info_type=replace_with_info_type,
            min_likelihood=min_likelihood,
        )
        resp = self._call_with_retries(self._client.deidentify_content, request=req)
        text_out = resp.item.value  # type: ignore[attr-defined]
        # Параллельно извлечём findings через инспект‑часть ответа (если присутствует)
        findings: List[DlpFinding] = []
        inspect_res = getattr(resp, "overview", None)  # deidentify_content может не возвращать детальные оффсеты
        if inspect_res and getattr(inspect_res, "transformed_bytes", 0):  # best-effort
            pass  # агрегировать нечего; оффсеты не возвращаются детально
        return DlpDeidentifyResult(text=text_out, findings=tuple(findings), item_size_bytes=len(data))

    # -----------------------
    # Построители запросов
    # -----------------------

    def _build_inspect_request(
        self,
        *,
        content_bytes: bytes,
        info_types: Optional[Sequence[str]],
        include_quotes: bool,
        min_likelihood: Likelihood,
        max_findings: int,
        hotword_regex: Optional[str],
    ) -> Dict[str, Any]:
        _require_lib()
        # InfoTypes
        its = [{"name": n} for n in info_types] if info_types else _default_info_types()

        limits = dlp_types.InspectConfig.FindingLimits(
            max_findings_per_request=max_findings if max_findings > 0 else 0
        )
        hotword_rules = []
        if hotword_regex:
            hotword_rules = [
                dlp_types.CustomInfoType.DetectionRule.HotwordRule(
                    hotword_regex=dlp_types.CustomInfoType.Regex(pattern=hotword_regex),
                    proximity=dlp_types.CustomInfoType.DetectionRule.Proximity(
                        window_before=50, window_after=50
                    ),
                )
            ]

        inspect_config = dlp_types.InspectConfig(
            info_types=[dlp_types.InfoType(**d) for d in its],
            include_quote=include_quotes,
            min_likelihood=_to_min_likelihood(min_likelihood),
            limits=limits,
            rule_set=[
                dlp_types.InspectionRuleSet(
                    info_types=[dlp_types.InfoType(**d) for d in its],
                    rules=[dlp_types.InspectionRule(hotword_rule=hotword_rules[0])] if hotword_rules else [],
                )
            ] if hotword_rules else []
        )

        item = dlp_types.ContentItem(byte_item=dlp_types.ByteContentItem(value=content_bytes))
        return {"parent": self.parent, "inspect_config": inspect_config, "item": item}

    def _build_deidentify_request(
        self,
        *,
        content_bytes: bytes,
        info_types: Optional[Sequence[str]],
        mask_char: str,
        number_to_mask: int,
        replace_with_info_type: bool,
        min_likelihood: Likelihood,
    ) -> Dict[str, Any]:
        _require_lib()
        its = [{"name": n} for n in info_types] if info_types else _default_info_types()

        if replace_with_info_type:
            primitive = dlp_types.PrimitiveTransformation(
                replace_with_info_type_config=dlp_types.ReplaceWithInfoTypeConfig()
            )
        else:
            primitive = dlp_types.PrimitiveTransformation(
                character_mask_config=dlp_types.CharacterMaskConfig(
                    masking_character=mask_char or "*",
                    number_to_mask=number_to_mask if number_to_mask > 0 else 0,
                )
            )

        trans = dlp_types.InfoTypeTransformations(
            transformations=[
                dlp_types.InfoTypeTransformations.InfoTypeTransformation(
                    info_types=[dlp_types.InfoType(**d) for d in its],
                    primitive_transformation=primitive,
                )
            ]
        )

        deidentify_config = dlp_types.DeidentifyConfig(info_type_transformations=trans)

        inspect_config = dlp_types.InspectConfig(
            info_types=[dlp_types.InfoType(**d) for d in its],
            min_likelihood=_to_min_likelihood(min_likelihood),
            include_quote=False,
        )

        item = dlp_types.ContentItem(byte_item=dlp_types.ByteContentItem(value=content_bytes))
        return {
            "parent": self.parent,
            "deidentify_config": deidentify_config,
            "inspect_config": inspect_config,
            "item": item,
        }

    # -----------------------
    # Вызов с ретраями
    # -----------------------

    def _call_with_retries(self, func, *, request: Dict[str, Any]):
        attempt = 0
        delay = self.initial_backoff_s
        last_exc: Optional[Exception] = None
        deadline = time.time() + max(self.request_timeout_s, 0.5)

        while attempt <= self.max_retries:
            try:
                # Дополнительный таймаут на уровень API‑ядра
                return func(request=request, timeout=max(0.2, deadline - time.time()))
            except Exception as e:  # pragma: no cover
                last_exc = e
                retryable = self._is_retryable(e)
                attempt += 1
                if attempt > self.max_retries or not retryable or time.time() + delay > deadline:
                    break
                time.sleep(delay * (0.5 + os.urandom(1)[0] / 255.0))  # jitter
                delay *= self.backoff_multiplier

        raise DlpRequestError(f"DLP request failed after {self.max_retries} retries: {last_exc}")

    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        if gapi_exceptions is None:
            return False
        if isinstance(exc, (gapi_exceptions.TooManyRequests, gapi_exceptions.DeadlineExceeded, gapi_exceptions.ServiceUnavailable)):
            return True
        # Ошибки транспорта/временная сеть
        if isinstance(exc, (gapi_exceptions.GoogleAPICallError, gapi_exceptions.RetryError)):
            return True
        return False


# -----------------------
# Пример использования (локальный smoke‑test)
# -----------------------
if __name__ == "__main__":  # pragma: no cover
    sample = "Меня зовут Иван Петров, email ivan.petrov@example.com, телефон +1 (650) 253-0000, карта 4111-1111-1111-1111."
    try:
        adapter = GcpDlpAdapter()
    except Exception as e:
        print(f"DLP unavailable: {e}")
        raise SystemExit(0)

    res = adapter.inspect_text(sample)
    print("Findings:", len(res.findings))
    for f in res.findings:
        print(f"- {f.info_type} [{f.likelihood}] at {f.byte_offset}+{f.byte_length} quote={f.quote!r}")

    deid = adapter.deidentify_text(sample, replace_with_info_type=True)
    print("Deidentified:", deid.text)
