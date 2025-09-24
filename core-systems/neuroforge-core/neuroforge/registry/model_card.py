# File: neuroforge-core/neuroforge/registry/model_card.py
# Промышленная карточка модели (Model Card) для реестра neuroforge-core.
# Возможности:
# - Pydantic-схемы с валидацией (Pydantic v2; graceful-фоллбек некоторых функций при v1)
# - Экспорт/импорт JSON и (опционально) YAML
# - Экспорт Markdown представления
# - Привязка отчётов об оценках (eval) и проверка порогов политики
# - Канонический дайджест содержимого (SHA-256) и опциональная подпись/проверка (Ed25519, cryptography)
# - CLI: validate|render-md|schema|sign|verify

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import UUID, uuid4

# ------------------------- Опциональные зависимости -------------------------

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:  # pragma: no cover
    _HAS_YAML = False

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )  # type: ignore
    from cryptography.hazmat.primitives import serialization  # type: ignore

    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False

# Pydantic v2 приоритетно; минимальная совместимость с v1
try:
    from pydantic import BaseModel, Field, field_validator, ConfigDict
    _PYDANTIC_V2 = True
except Exception:  # pragma: no cover
    from pydantic import BaseModel, Field, validator as field_validator  # type: ignore
    _PYDANTIC_V2 = False


MODEL_CARD_SCHEMA_VERSION = "1.0.0"


# ------------------------- Перечисления и типы -------------------------

class Modality(str, Enum):
    text = "text"
    image = "image"
    audio = "audio"
    video = "video"
    tabular = "tabular"
    multimodal = "multimodal"


class TaskType(str, Enum):
    classification = "classification"
    regression = "regression"
    translation = "translation"
    summarization = "summarization"
    generation = "generation"
    embedding = "embedding"
    object_detection = "object_detection"
    segmentation = "segmentation"
    speech_to_text = "speech_to_text"
    text_to_speech = "text_to_speech"
    retrieval = "retrieval"
    reinforcement = "reinforcement"


class LicenseId(str, Enum):
    apache_2 = "Apache-2.0"
    mit = "MIT"
    bsd_3 = "BSD-3-Clause"
    gpl_3 = "GPL-3.0-only"
    agpl_3 = "AGPL-3.0-only"
    proprietary = "Proprietary"
    other = "Other"


class GoalDirection(str, Enum):
    higher_better = "higher_better"
    lower_better = "lower_better"
    target_range = "target_range"


# ------------------------- Модели карточки -------------------------

class Contact(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    email: Optional[str] = Field(None, max_length=320)
    role: Optional[str] = Field(None, max_length=120)


class ArtifactRef(BaseModel):
    kind: str = Field(..., description="weights|tokenizer|container|code|index|other")
    uri: str = Field(..., description="Ссылка на артефакт (oci://, s3://, https://, file://)")
    digest: Optional[str] = Field(None, description="sha256:<hex>")
    size_bytes: Optional[int] = Field(None, ge=0)
    sbom_ref: Optional[str] = Field(None, description="Ссылка на SBOM (CycloneDX/SPDX)")
    slsa_provenance_ref: Optional[str] = Field(None, description="Ссылка на SLSA provenance (in-toto)")

    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid")

    @field_validator("digest")
    @classmethod
    def _chk_digest(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not v.startswith("sha256:") or len(v) != len("sha256:") + 64:
            raise ValueError("digest must be 'sha256:<64-hex>'")
        return v


class DatasetRef(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    version: Optional[str] = Field(None, max_length=100)
    uri: Optional[str] = Field(None, description="s3://, gs://, hf://, https:// …")
    split_coverage: Optional[Dict[str, float]] = Field(
        None, description="Напр., {'train': 0.8, 'val': 0.1, 'test': 0.1}"
    )
    description: Optional[str] = None

    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid")


class TrainingConfig(BaseModel):
    framework: str = Field(..., description="torch|tensorflow|jax|…")
    framework_version: Optional[str] = None
    python_version: Optional[str] = None
    hardware: Optional[Dict[str, Union[str, int]]] = Field(
        None, description="Напр., {'accelerator':'A100','count':4,'memory_gb':80}"
    )
    epochs: Optional[int] = Field(None, ge=0)
    batch_size: Optional[int] = Field(None, ge=1)
    optimizer: Optional[str] = None
    loss: Optional[str] = None
    hyperparams: Optional[Dict[str, Union[str, float, int]]] = None

    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid")


class RiskConsiderations(BaseModel):
    data_risks: Optional[List[str]] = Field(default_factory=list)
    ethical_risks: Optional[List[str]] = Field(default_factory=list)
    bias_mitigation: Optional[List[str]] = Field(default_factory=list)
    safety_constraints: Optional[List[str]] = Field(default_factory=list)
    privacy_notes: Optional[str] = None

    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid")


class UsagePolicy(BaseModel):
    allowed: List[str] = Field(default_factory=list)
    disallowed: List[str] = Field(default_factory=list)
    sensitive_content_policy: Optional[str] = None
    compliance_notes: Optional[str] = None

    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid")


class EvaluationMetric(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    value: float = Field(..., description="Числовое значение метрики")
    unit: Optional[str] = Field(None, max_length=32)
    goal: GoalDirection = Field(GoalDirection.higher_better)
    threshold: Optional[float] = Field(None, description="Порог, если задан политикой")
    target_range: Optional[Tuple[float, float]] = Field(
        None, description="Используется при goal=target_range"
    )

    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid")

    @field_validator("target_range")
    @classmethod
    def _chk_range(cls, v: Optional[Tuple[float, float]], info: Any) -> Optional[Tuple[float, float]]:
        if v and v[0] > v[1]:
            raise ValueError("target_range must be (min <= max)")
        return v


class EvaluationReport(BaseModel):
    eval_id: Optional[UUID] = Field(default_factory=uuid4)
    dataset: Union[str, DatasetRef] = Field(..., description="Имя датасета или ссылка")
    started_at: Optional[dt.datetime] = None
    completed_at: Optional[dt.datetime] = None
    metrics: List[EvaluationMetric] = Field(default_factory=list)
    evidence_uri: Optional[str] = Field(None, description="Ссылка на подробный отчёт/артефакты")
    passed: Optional[bool] = Field(None, description="Итог прохождения порогов")
    notes: Optional[str] = None

    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid")


class Signature(BaseModel):
    alg: str = Field("ed25519")
    signer: Optional[str] = Field(None, description="Идентификатор ключа/субъекта")
    signature_b64: str = Field(..., description="Подпись по каноническим байтам карточки, base64")

    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid")


class ModelCard(BaseModel):
    schema_version: str = Field(MODEL_CARD_SCHEMA_VERSION, description="Версия схемы карточки")
    model_id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=4000)
    modality: Modality = Field(Modality.text)
    tasks: List[TaskType] = Field(default_factory=list)
    languages: Optional[List[str]] = Field(default_factory=list, description="BCP-47 коды, напр., ['en','ru']")
    license: LicenseId = Field(LicenseId.apache_2)
    version: str = Field("0.1.0")
    owners: List[Contact] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    artifacts: List[ArtifactRef] = Field(default_factory=list)
    datasets: List[DatasetRef] = Field(default_factory=list)
    training: Optional[TrainingConfig] = None
    risks: Optional[RiskConsiderations] = None
    usage: Optional[UsagePolicy] = None

    evaluations: List[EvaluationReport] = Field(default_factory=list)

    created_at: dt.datetime = Field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))
    updated_at: dt.datetime = Field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))

    # Происхождение/внешние ссылки
    repository: Optional[str] = Field(None, description="VCS/репозиторий")
    homepage: Optional[str] = None
    documentation: Optional[str] = None

    # Подписи
    signatures: List[Signature] = Field(default_factory=list)

    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid")

    # --------------------- Бизнес-методы ---------------------

    def canonical_bytes(self) -> bytes:
        """
        Каноническое представление JSON для дайджеста/подписи:
        - исключает поле signatures
        - сортирует ключи
        - ISO-время в UTC
        """
        def _ser(obj: Any) -> Any:
            if isinstance(obj, dt.datetime):
                return obj.astimezone(dt.timezone.utc).isoformat()
            return obj

        data = self.model_dump() if _PYDANTIC_V2 else self.dict()  # type: ignore
        data = {k: v for k, v in data.items() if k != "signatures"}
        return json.dumps(data, default=_ser, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest_sha256(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()

    def check_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Простая проверка политики раскатки/приёма модели.
        Ожидаемый формат policy (пример):
        {
          "required_metrics": {
             "accuracy": {"goal":"higher_better","min":0.9},
             "latency_p95_ms": {"goal":"lower_better","max":250}
          },
          "allowed_licenses": ["Apache-2.0","MIT","Proprietary"],
          "deny_tags": ["experimental"]
        }
        """
        violations: List[str] = []

        # Лицензия
        allowed = policy.get("allowed_licenses")
        if allowed and str(self.license) not in set(allowed):
            violations.append(f"license {self.license} not in allowed set")

        # Запрещенные теги
        deny_tags = set(policy.get("deny_tags", []))
        bad_tags = [t for t in self.tags if t in deny_tags]
        if bad_tags:
            violations.append(f"deny_tags present: {bad_tags}")

        # Метрики
        req = policy.get("required_metrics", {})
        metrics_map: Dict[str, float] = {}
        for rep in self.evaluations:
            for m in rep.metrics:
                metrics_map.setdefault(m.name, m.value)

        for mname, cfg in req.items():
            if mname not in metrics_map:
                violations.append(f"metric '{mname}' is missing")
                continue
            val = metrics_map[mname]
            goal = cfg.get("goal", "higher_better")
            if goal == "higher_better" and "min" in cfg and val < float(cfg["min"]):
                violations.append(f"metric '{mname}'={val} < min {cfg['min']}")
            if goal == "lower_better" and "max" in cfg and val > float(cfg["max"]):
                violations.append(f"metric '{mname}'={val} > max {cfg['max']}")

        return {
            "ok": len(violations) == 0,
            "violations": violations,
            "digest": self.digest_sha256(),
        }

    def attach_eval_report(self, report: EvaluationReport) -> None:
        self.evaluations.append(report)
        self.updated_at = dt.datetime.now(dt.timezone.utc)

    # --------------------- Подпись/проверка ---------------------

    def sign_ed25519(self, private_key_pem: bytes, signer_id: Optional[str] = None) -> Signature:
        """
        Создать подпись по каноническим байтам карточки.
        Требует cryptography; при отсутствии вызывает исключение.
        """
        if not _HAS_CRYPTO:
            raise RuntimeError("cryptography not installed; signing unavailable")

        priv = Ed25519PrivateKey.from_private_bytes(
            serialization.load_pem_private_key(private_key_pem, password=None).private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        )
        sig = priv.sign(self.canonical_bytes())
        import base64
        s = Signature(alg="ed25519", signer=signer_id, signature_b64=base64.b64encode(sig).decode("ascii"))
        self.signatures.append(s)
        self.updated_at = dt.datetime.now(dt.timezone.utc)
        return s

    def verify_ed25519(self, public_key_pem: bytes) -> bool:
        """
        Проверить хотя бы одну подпись ed25519.
        """
        if not _HAS_CRYPTO:
            raise RuntimeError("cryptography not installed; verification unavailable")

        pub_raw = serialization.load_pem_public_key(public_key_pem).public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        pub = Ed25519PublicKey.from_public_bytes(pub_raw)

        import base64
        payload = self.canonical_bytes()
        ok_any = False
        for sig in self.signatures:
            if sig.alg != "ed25519":
                continue
            try:
                pub.verify(base64.b64decode(sig.signature_b64.encode("ascii")), payload)
                ok_any = True
            except Exception:
                continue
        return ok_any

    # --------------------- Сериализация ---------------------

    def to_json(self) -> str:
        def _ser(obj: Any) -> Any:
            if isinstance(obj, dt.datetime):
                return obj.astimezone(dt.timezone.utc).isoformat()
            return obj
        data = self.model_dump() if _PYDANTIC_V2 else self.dict()  # type: ignore
        return json.dumps(data, default=_ser, ensure_ascii=False, indent=2)

    def to_yaml(self) -> str:
        if not _HAS_YAML:
            raise RuntimeError("PyYAML not installed")
        data = self.model_dump() if _PYDANTIC_V2 else self.dict()  # type: ignore
        return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)

    @staticmethod
    def from_path(path: str) -> "ModelCard":
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        if path.endswith((".yml", ".yaml")):
            if not _HAS_YAML:
                raise RuntimeError("PyYAML not installed")
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)
        return ModelCard(**data)

    def save(self, path: str) -> None:
        if path.endswith((".yml", ".yaml")):
            out = self.to_yaml()
        else:
            out = self.to_json()
        with open(path, "w", encoding="utf-8") as f:
            f.write(out)

    # --------------------- Markdown-рендер ---------------------

    def to_markdown(self) -> str:
        """
        Компактная, печатаемая карточка для документации/портала.
        """
        def dtfmt(x: Optional[dt.datetime]) -> str:
            return x.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ") if x else "-"

        lines: List[str] = []
        lines.append(f"# {self.name} (v{self.version})")
        lines.append("")
        lines.append(f"Schema: {self.schema_version} | Model ID: `{self.model_id}` | Digest: `{self.digest_sha256()}`")
        lines.append("")
        if self.description:
            lines.append(self.description)
            lines.append("")
        lines.append("## Overview")
        lines.append(f"- Modality: **{self.modality}**")
        lines.append(f"- Tasks: {', '.join(t.value for t in self.tasks) if self.tasks else '-'}")
        lines.append(f"- Languages: {', '.join(self.languages or []) or '-'}")
        lines.append(f"- License: **{self.license}**")
        lines.append(f"- Tags: {', '.join(self.tags) if self.tags else '-'}")
        lines.append("")
        if self.owners:
            lines.append("## Owners")
            for c in self.owners:
                who = c.name + (f" <{c.email}>" if c.email else "")
                role = f" ({c.role})" if c.role else ""
                lines.append(f"- {who}{role}")
            lines.append("")
        if self.artifacts:
            lines.append("## Artifacts")
            for a in self.artifacts:
                dig = a.digest or "-"
                lines.append(f"- {a.kind}: {a.uri}  (digest: `{dig}`)")
            lines.append("")
        if self.datasets:
            lines.append("## Datasets")
            for dref in self.datasets:
                ver = f" v{dref.version}" if dref.version else ""
                uri = f" [{dref.uri}]({dref.uri})" if dref.uri else ""
                lines.append(f"- {dref.name}{ver}{uri}")
            lines.append("")
        if self.training:
            t = self.training
            lines.append("## Training")
            lines.append(f"- Framework: {t.framework} {t.framework_version or ''} | Python {t.python_version or ''}".strip())
            if t.hardware:
                lines.append(f"- Hardware: {json.dumps(t.hardware, ensure_ascii=False)}")
            if t.hyperparams:
                lines.append(f"- Hyperparams: {json.dumps(t.hyperparams, ensure_ascii=False)}")
            lines.append("")
        if self.evaluations:
            lines.append("## Evaluations")
            for rep in self.evaluations:
                ds = rep.dataset.name if isinstance(rep.dataset, DatasetRef) else str(rep.dataset)
                lines.append(f"### {ds} [{rep.eval_id}]")
                lines.append(f"- Window: {dtfmt(rep.started_at)} — {dtfmt(rep.completed_at)}")
                lines.append(f"- Evidence: {rep.evidence_uri or '-'}")
                if rep.metrics:
                    lines.append("")
                    lines.append("| Metric | Value | Unit |")
                    lines.append("|---|---:|---|")
                    for m in rep.metrics:
                        v = f"{m.value:.6g}"
                        lines.append(f"| {m.name} | {v} | {m.unit or ''} |")
                    lines.append("")
        if self.usage:
            lines.append("## Usage Policy")
            if self.usage.allowed:
                lines.append("- Allowed:")
                for it in self.usage.allowed:
                    lines.append(f"  - {it}")
            if self.usage.disallowed:
                lines.append("- Disallowed:")
                for it in self.usage.disallowed:
                    lines.append(f"  - {it}")
            lines.append("")
        if self.risks:
            lines.append("## Risks")
            for label, arr in [
                ("Data risks", self.risks.data_risks or []),
                ("Ethical risks", self.risks.ethical_risks or []),
                ("Bias mitigation", self.risks.bias_mitigation or []),
                ("Safety constraints", self.risks.safety_constraints or []),
            ]:
                if arr:
                    lines.append(f"- {label}:")
                    for it in arr:
                        lines.append(f"  - {it}")
            if self.risks.privacy_notes:
                lines.append(f"- Privacy: {self.risks.privacy_notes}")
            lines.append("")
        lines.append("## Timestamps")
        lines.append(f"- Created: {dtfmt(self.created_at)}")
        lines.append(f"- Updated: {dtfmt(self.updated_at)}")
        return "\n".join(lines)


# ------------------------- JSON Schema экспорт -------------------------

def model_card_json_schema() -> Dict[str, Any]:
    # Pydantic v2
    if _PYDANTIC_V2:
        return ModelCard.model_json_schema()  # type: ignore
    # v1 (примерная совместимость)
    return ModelCard.schema()  # type: ignore


# ------------------------- CLI -------------------------

def _cmd_validate(args: argparse.Namespace) -> int:
    card = ModelCard.from_path(args.path)
    result = {"ok": True, "digest": card.digest_sha256(), "model_id": str(card.model_id)}
    if args.policy:
        with open(args.policy, "r", encoding="utf-8") as f:
            pdata = yaml.safe_load(f) if args.policy.endswith((".yml", ".yaml")) and _HAS_YAML else json.load(f)
        check = card.check_policy(pdata)
        result["policy"] = check
        result["ok"] = result["ok"] and bool(check["ok"])
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 2


def _cmd_render_md(args: argparse.Namespace) -> int:
    card = ModelCard.from_path(args.path)
    md = card.to_markdown()
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(md)
    else:
        print(md)
    return 0


def _cmd_schema(args: argparse.Namespace) -> int:
    schema = model_card_json_schema()
    if args.format == "yaml":
        if not _HAS_YAML:
            raise RuntimeError("PyYAML not installed")
        print(yaml.safe_dump(schema, sort_keys=False, allow_unicode=True))
    else:
        print(json.dumps(schema, ensure_ascii=False, indent=2))
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography not installed")
    card = ModelCard.from_path(args.path)
    with open(args.key, "rb") as f:
        pem = f.read()
    card.sign_ed25519(pem, signer_id=args.signer)
    out = args.out or args.path
    card.save(out)
    print(json.dumps({"ok": True, "out": out, "digest": card.digest_sha256()}, ensure_ascii=False))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography not installed")
    card = ModelCard.from_path(args.path)
    with open(args.key, "rb") as f:
        pem = f.read()
    ok = card.verify_ed25519(pem)
    print(json.dumps({"ok": ok, "digest": card.digest_sha256()}, ensure_ascii=False))
    return 0 if ok else 3


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="model-card", description="Model Card tool for neuroforge-core")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_val = sub.add_parser("validate", help="Validate model card (and optional policy)")
    p_val.add_argument("path", help="Path to model card (json|yaml)")
    p_val.add_argument("--policy", help="Policy file (json|yaml)", default=None)
    p_val.set_defaults(func=_cmd_validate)

    p_md = sub.add_parser("render-md", help="Render Markdown model card")
    p_md.add_argument("path")
    p_md.add_argument("--out", help="Output file (default stdout)")
    p_md.set_defaults(func=_cmd_render_md)

    p_schema = sub.add_parser("schema", help="Print JSON Schema")
    p_schema.add_argument("--format", choices=["json", "yaml"], default="json")
    p_schema.set_defaults(func=_cmd_schema)

    p_sign = sub.add_parser("sign", help="Sign model card (ed25519, cryptography)")
    p_sign.add_argument("path")
    p_sign.add_argument("--key", required=True, help="Private key PEM (ed25519)")
    p_sign.add_argument("--signer", help="Signer id")
    p_sign.add_argument("--out", help="Output path (default overwrite input)")
    p_sign.set_defaults(func=_cmd_sign)

    p_verify = sub.add_parser("verify", help="Verify model card signature (ed25519)")
    p_verify.add_argument("path")
    p_verify.add_argument("--key", required=True, help="Public key PEM (ed25519)")
    p_verify.set_defaults(func=_cmd_verify)

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
