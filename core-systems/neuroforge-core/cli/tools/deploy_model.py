#!/usr/bin/env python3
# neuroforge-core/cli/tools/deploy_model.py
# Industrial-grade CLI for packaging, verifying, pushing, and deploying ML models.
from __future__ import annotations

import argparse
import asyncio
import base64
import dataclasses
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------
# Optional deps (loaded lazily)
# ---------------------------
try:
    import boto3  # type: ignore
    _BOTO3 = True
except Exception:
    _BOTO3 = False

JSON_LOG_FMT = '{{"ts":"{ts}","level":"{lvl}","event":"{evt}","data":{data}}}'


def jlog(level: str, event: str, data: Dict[str, Any] | None = None) -> None:
    payload = JSON_LOG_FMT.format(
        ts=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        lvl=level.upper(),
        evt=event,
        data=json.dumps(data or {}, ensure_ascii=False),
    )
    print(payload, file=sys.stderr)


# ---------------------------
# Config
# ---------------------------
@dataclass(frozen=True)
class DeployConfig:
    # Packaging
    artifact_dir: str = field(default_factory=lambda: os.getenv("NF_ARTIFACT_DIR", "dist"))
    sbom_kind: str = field(default_factory=lambda: os.getenv("NF_SBOM_KIND", "cyclonedx-json"))  # informational
    gpg_sign: bool = field(default_factory=lambda: os.getenv("NF_GPG_SIGN", "0") == "1")
    gpg_key_id: Optional[str] = field(default_factory=lambda: os.getenv("NF_GPG_KEY_ID"))
    gpg_bin: str = field(default_factory=lambda: os.getenv("NF_GPG_BIN", "gpg"))

    # Push
    s3_region: Optional[str] = field(default_factory=lambda: os.getenv("NF_S3_REGION"))
    s3_endpoint: Optional[str] = field(default_factory=lambda: os.getenv("NF_S3_ENDPOINT"))
    s3_acl: Optional[str] = field(default_factory=lambda: os.getenv("NF_S3_ACL"))  # e.g. "private"

    # Deploy
    kubectl_bin: str = field(default_factory=lambda: os.getenv("NF_KUBECTL_BIN", "kubectl"))
    k8s_namespace: str = field(default_factory=lambda: os.getenv("NF_K8S_NAMESPACE", "default"))

    # Misc
    log_level: str = field(default_factory=lambda: os.getenv("NF_LOG_LEVEL", "INFO"))


# ---------------------------
# Utilities
# ---------------------------
def sha256_file(path: Path, bufsize: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(bufsize)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def ensure_executable(bin_name: str) -> None:
    if shutil.which(bin_name) is None:
        raise RuntimeError(f"required binary not found in PATH: {bin_name}")


def parse_kv(items: Iterable[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for it in items:
        if "=" not in it:
            raise ValueError(f"invalid key=value: {it}")
        k, v = it.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def run(cmd: List[str], check: bool = True, capture: bool = True, env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    proc = subprocess.run(cmd, check=False, capture_output=capture, text=True, env=env)
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\nstdout: {proc.stdout}\nstderr: {proc.stderr}")
    return proc.returncode, proc.stdout, proc.stderr


async def arun(cmd: List[str], check: bool = True, env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
    out_b, err_b = await proc.communicate()
    out, err = out_b.decode(), err_b.decode()
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\nstdout: {out}\nstderr: {err}")
    return proc.returncode, out, err


def maybe_b64(file_path: Path) -> str:
    try:
        raw = file_path.read_bytes()
        return base64.b64encode(raw).decode()
    except Exception:
        return ""


# ---------------------------
# SBOM (minimal CycloneDX-like JSON)
# ---------------------------
def generate_min_sbom(component_name: str, version: str, files: List[Path]) -> Dict[str, Any]:
    comps = []
    for p in files:
        comps.append({
            "name": str(p.name),
            "type": "file",
            "hashes": [{"alg": "SHA-256", "content": sha256_file(p)}],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "component": {
                "name": component_name,
                "version": version,
                "type": "application",
            },
            "tools": [{"vendor": "neuroforge", "name": "deploy_model", "version": "1.0"}],
        },
        "components": comps,
    }


# ---------------------------
# Packaging
# ---------------------------
@dataclass
class PackageMeta:
    name: str
    version: str
    description: str
    license: Optional[str]
    extra: Dict[str, Any]


def create_artifact(model_dir: Path, out_dir: Path, meta: PackageMeta, include_readme: Optional[Path]) -> Tuple[Path, Path, Path]:
    if not model_dir.is_dir():
        raise RuntimeError(f"model_dir does not exist: {model_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)

    artifact_name = f"{meta.name}-{meta.version}.tar.gz"
    artifact_path = out_dir / artifact_name
    meta_path = out_dir / f"{meta.name}-{meta.version}.metadata.json"
    sbom_path = out_dir / f"{meta.name}-{meta.version}.sbom.json"

    # Write metadata
    metadata = {
        "name": meta.name,
        "version": meta.version,
        "description": meta.description,
        "license": meta.license,
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "extra": meta.extra,
    }
    write_text(meta_path, json.dumps(metadata, indent=2, ensure_ascii=False))

    # Create tar.gz
    with tarfile.open(artifact_path, "w:gz") as tar:
        for p in sorted(model_dir.rglob("*")):
            if p.is_file():
                tar.add(p, arcname=str(p.relative_to(model_dir)))
        # embed metadata/readme inside archive too
        with tempfile.TemporaryDirectory() as td:
            tmpd = Path(td)
            tmp_meta = tmpd / "METADATA.json"
            write_text(tmp_meta, json.dumps(metadata, indent=2, ensure_ascii=False))
            tar.add(tmp_meta, arcname="METADATA.json")
            if include_readme and include_readme.is_file():
                tar.add(include_readme, arcname="README.md")

    # SBOM (cover all files in model_dir + artifact itself + metadata)
    files_for_sbom = [artifact_path, meta_path] + [p for p in model_dir.rglob("*") if p.is_file()]
    sbom = generate_min_sbom(meta.name, meta.version, files_for_sbom)
    write_text(sbom_path, json.dumps(sbom, indent=2, ensure_ascii=False))

    jlog("info", "package_created", {
        "artifact": str(artifact_path),
        "metadata": str(meta_path),
        "sbom": str(sbom_path),
        "model_files": len([p for p in model_dir.rglob('*') if p.is_file()]),
    })
    return artifact_path, meta_path, sbom_path


def write_checksums(paths: List[Path]) -> List[Path]:
    out: List[Path] = []
    for p in paths:
        digest = sha256_file(p)
        chk = p.with_suffix(p.suffix + ".sha256")
        write_text(chk, f"{digest}  {p.name}\n")
        out.append(chk)
        jlog("info", "checksum_written", {"file": str(p), "sha256": digest})
    return out


def gpg_sign_files(paths: List[Path], key_id: Optional[str], gpg_bin: str) -> List[Path]:
    signed: List[Path] = []
    if shutil.which(gpg_bin) is None:
        raise RuntimeError("gpg not found in PATH")
    for p in paths:
        asc = p.with_suffix(p.suffix + ".asc")
        cmd = [gpg_bin, "--armor", "--batch", "--yes", "--detach-sign", "-o", str(asc)]
        if key_id:
            cmd += ["--local-user", key_id]
        cmd += [str(p)]
        run(cmd, check=True, capture=True)
        signed.append(asc)
        jlog("info", "gpg_signed", {"file": str(p), "asc": str(asc), "key_id": key_id or ""})
    return signed


def verify_artifact(artifact: Path, checksum_file: Optional[Path], signature_file: Optional[Path], gpg_bin: str) -> None:
    if not artifact.is_file():
        raise RuntimeError(f"artifact not found: {artifact}")

    # Verify checksum
    if checksum_file and checksum_file.is_file():
        expected = checksum_file.read_text(encoding="utf-8").split()[0].strip()
        actual = sha256_file(artifact)
        if expected != actual:
            raise RuntimeError(f"checksum mismatch: expected {expected}, actual {actual}")
        jlog("info", "checksum_ok", {"artifact": str(artifact)})

    # Verify signature
    if signature_file and signature_file.is_file():
        ensure_executable(gpg_bin)
        code, out, err = run([gpg_bin, "--verify", str(signature_file), str(artifact)], check=False)
        if code != 0:
            raise RuntimeError(f"gpg verify failed: {err or out}")
        jlog("info", "signature_ok", {"artifact": str(artifact)})


# ---------------------------
# Storage backends
# ---------------------------
class StorageBackend:
    async def push(self, local_files: List[Path], target: str) -> None:
        raise NotImplementedError


class LocalFSBackend(StorageBackend):
    async def push(self, local_files: List[Path], target: str) -> None:
        # target: local:///abs/or/relative/dir
        if not target.startswith("local://"):
            raise ValueError("LocalFSBackend needs target starting with local://")
        dst_dir = Path(target.replace("local://", "", 1)).expanduser().resolve()
        dst_dir.mkdir(parents=True, exist_ok=True)
        for p in local_files:
            shutil.copy2(p, dst_dir / p.name)
            jlog("info", "pushed_local", {"src": str(p), "dst": str(dst_dir / p.name)})


class S3Backend(StorageBackend):
    def __init__(self, region: Optional[str], endpoint: Optional[str], acl: Optional[str]):
        if not _BOTO3:
            raise RuntimeError("boto3 not installed; cannot use s3 backend")
        self.session = boto3.session.Session(region_name=region)
        self.endpoint = endpoint
        self.acl = acl

    async def push(self, local_files: List[Path], target: str) -> None:
        # target: s3://bucket/prefix/
        if not target.startswith("s3://"):
            raise ValueError("S3Backend needs target starting with s3://")
        _, _, rest = target.partition("s3://")
        bucket, _, prefix = rest.partition("/")
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        s3 = self.session.client("s3", endpoint_url=self.endpoint)
        for p in local_files:
            key = f"{prefix}{p.name}" if prefix else p.name
            extra: Dict[str, Any] = {"ACL": self.acl} if self.acl else {}
            s3.upload_file(str(p), bucket, key, ExtraArgs=extra or None)
            jlog("info", "pushed_s3", {"bucket": bucket, "key": key})


def get_storage_backend(target: str, cfg: DeployConfig) -> StorageBackend:
    if target.startswith("local://"):
        return LocalFSBackend()
    if target.startswith("s3://"):
        return S3Backend(cfg.s3_region, cfg.s3_endpoint, cfg.s3_acl)
    raise ValueError(f"unsupported target: {target}")


# ---------------------------
# Kubernetes deployer (kubectl)
# ---------------------------
class KubectlDeployer:
    def __init__(self, kubectl_bin: str, namespace: str):
        self.kubectl_bin = kubectl_bin
        self.namespace = namespace

    async def apply(self, manifest_path: Path) -> None:
        ensure_executable(self.kubectl_bin)
        await arun([self.kubectl_bin, "-n", self.namespace, "apply", "-f", str(manifest_path)], check=True)
        jlog("info", "k8s_apply_ok", {"namespace": self.namespace, "manifest": str(manifest_path)})

    async def status(self, deployment: str, timeout: str = "120s") -> None:
        ensure_executable(self.kubectl_bin)
        await arun([self.kubectl_bin, "-n", self.namespace, "rollout", "status", f"deployment/{deployment}", f"--timeout={timeout}"], check=True)
        jlog("info", "k8s_rollout_ok", {"namespace": self.namespace, "deployment": deployment})

    async def rollback(self, deployment: str, to_revision: Optional[int]) -> None:
        ensure_executable(self.kubectl_bin)
        cmd = [self.kubectl_bin, "-n", self.namespace, "rollout", "undo", f"deployment/{deployment}"]
        if to_revision is not None:
            cmd.append(f"--to-revision={to_revision}")
        await arun(cmd, check=True)
        jlog("info", "k8s_rollback_ok", {"namespace": self.namespace, "deployment": deployment, "revision": to_revision})


# ---------------------------
# Manifest rendering (JSON accepted by kubectl)
# ---------------------------
def render_k8s_manifest_json(
    name: str,
    image: str,
    replicas: int,
    env: Dict[str, str],
    resources: Dict[str, Any],
    ports: List[int],
    labels: Dict[str, str],
    annotations: Dict[str, str],
) -> Dict[str, Any]:
    # Deployment + Service
    labels = {"app": name, **(labels or {})}
    container = {
        "name": name,
        "image": image,
        "imagePullPolicy": "IfNotPresent",
        "env": [{"name": k, "value": v} for k, v in (env or {}).items()],
        "ports": [{"containerPort": p} for p in ports],
        "resources": resources or {},
        "livenessProbe": {
            "httpGet": {"path": "/healthz", "port": ports[0] if ports else 8081},
            "initialDelaySeconds": 10,
            "periodSeconds": 10,
        },
        "readinessProbe": {
            "httpGet": {"path": "/readyz", "port": ports[0] if ports else 8081},
            "initialDelaySeconds": 5,
            "periodSeconds": 5,
        },
    }
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "labels": labels, "annotations": annotations or {}},
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels},
                "spec": {"containers": [container]},
            },
            "strategy": {"type": "RollingUpdate"},
        },
    }
    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": f"{name}-svc", "labels": labels},
        "spec": {
            "selector": labels,
            "ports": [{"name": f"p{p}", "port": p, "targetPort": p} for p in ports] or [{"name": "http", "port": 80, "targetPort": ports[0] if ports else 8081}],
            "type": "ClusterIP",
        },
    }
    return {"apiVersion": "v1", "kind": "List", "items": [deployment, service]}


# ---------------------------
# CLI Commands
# ---------------------------
def cmd_package(args: argparse.Namespace, cfg: DeployConfig) -> None:
    model_dir = Path(args.model_dir).resolve()
    out_dir = Path(args.out_dir or cfg.artifact_dir).resolve()
    meta = PackageMeta(
        name=args.name,
        version=args.version,
        description=args.description or "",
        license=args.license,
        extra=parse_kv(args.meta or []),
    )
    readme = Path(args.readme).resolve() if args.readme else None
    artifact, meta_file, sbom_file = create_artifact(model_dir, out_dir, meta, readme)
    written = [artifact, meta_file, sbom_file]
    chks = write_checksums(written)
    if cfg.gpg_sign or args.gpg_sign:
        signed = gpg_sign_files(written + chks, cfg.gpg_key_id, cfg.gpg_bin)
        jlog("info", "package_signed", {"files": [str(p) for p in signed]})
    jlog("info", "package_done", {"outputs": [str(p) for p in written + chks]})


def cmd_verify(args: argparse.Namespace, cfg: DeployConfig) -> None:
    artifact = Path(args.artifact).resolve()
    checksum = Path(args.checksum).resolve() if args.checksum else artifact.with_suffix(artifact.suffix + ".sha256")
    sig = Path(args.signature).resolve() if args.signature else artifact.with_suffix(artifact.suffix + ".asc")
    verify_artifact(artifact, checksum if checksum.exists() else None, sig if sig.exists() else None, cfg.gpg_bin)
    jlog("info", "verify_ok", {"artifact": str(artifact)})


def cmd_push(args: argparse.Namespace, cfg: DeployConfig) -> None:
    files = [Path(p).resolve() for p in args.files]
    target = args.target
    backend = get_storage_backend(target, cfg)
    asyncio.run(backend.push(files, target))
    jlog("info", "push_done", {"count": len(files), "target": target})


def cmd_render_manifest(args: argparse.Namespace, cfg: DeployConfig) -> None:
    env = parse_kv(args.env or [])
    labels = parse_kv(args.labels or [])
    annotations = parse_kv(args.annotations or [])
    resources = json.loads(args.resources) if args.resources else {
        "requests": {"cpu": "100m", "memory": "256Mi"},
        "limits": {"cpu": "1", "memory": "1Gi"},
    }
    manifest = render_k8s_manifest_json(
        name=args.name,
        image=args.image,
        replicas=args.replicas,
        env=env,
        resources=resources,
        ports=args.port or [8081],
        labels=labels,
        annotations=annotations,
    )
    out = Path(args.out).resolve() if args.out else None
    text = json.dumps(manifest, indent=2, ensure_ascii=False)
    if out:
        write_text(out, text)
        jlog("info", "manifest_written", {"path": str(out)})
    else:
        print(text)


def cmd_deploy(args: argparse.Namespace, cfg: DeployConfig) -> None:
    manifest_path = Path(args.manifest).resolve()
    dep = KubectlDeployer(cfg.kubectl_bin, args.namespace or cfg.k8s_namespace)
    asyncio.run(dep.apply(manifest_path))
    if args.wait:
        asyncio.run(dep.status(args.deployment or args.name, timeout=args.timeout))


def cmd_status(args: argparse.Namespace, cfg: DeployConfig) -> None:
    dep = KubectlDeployer(cfg.kubectl_bin, args.namespace or cfg.k8s_namespace)
    asyncio.run(dep.status(args.deployment or args.name, timeout=args.timeout))


def cmd_rollback(args: argparse.Namespace, cfg: DeployConfig) -> None:
    dep = KubectlDeployer(cfg.kubectl_bin, args.namespace or cfg.k8s_namespace)
    rev = int(args.revision) if args.revision is not None else None
    asyncio.run(dep.rollback(args.deployment or args.name, rev))


# ---------------------------
# Argument parser
# ---------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="deploy_model",
        description="NeuroForge model packaging and deployment CLI (industrial edition)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # package
    sp = sub.add_parser("package", help="Package a model directory into tar.gz with metadata and SBOM")
    sp.add_argument("--model-dir", required=True, help="Path to model directory (files to include)")
    sp.add_argument("--name", required=True, help="Model name")
    sp.add_argument("--version", required=True, help="Model version (e.g., 1.2.3)")
    sp.add_argument("--description", default="", help="Short description")
    sp.add_argument("--license", default=None, help="SPDX license id (optional)")
    sp.add_argument("--meta", nargs="*", help="Extra metadata key=value")
    sp.add_argument("--readme", default=None, help="README.md to embed (optional)")
    sp.add_argument("--out-dir", default=None, help="Output directory (default: NF_ARTIFACT_DIR or ./dist)")
    sp.add_argument("--gpg-sign", action="store_true", help="Sign outputs with GPG (or NF_GPG_SIGN=1)")
    sp.set_defaults(func=cmd_package)

    # verify
    sv = sub.add_parser("verify", help="Verify artifact checksum and signature")
    sv.add_argument("--artifact", required=True, help="Path to artifact (.tar.gz)")
    sv.add_argument("--checksum", default=None, help="Path to .sha256 (optional)")
    sv.add_argument("--signature", default=None, help="Path to .asc (optional)")
    sv.set_defaults(func=cmd_verify)

    # push
    su = sub.add_parser("push", help="Push files to storage (local:// or s3://)")
    su.add_argument("--target", required=True, help="Destination, e.g. local:///repo/artifacts or s3://bucket/prefix")
    su.add_argument("files", nargs="+", help="Files to upload")
    su.set_defaults(func=cmd_push)

    # render-manifest
    sm = sub.add_parser("render-manifest", help="Render Kubernetes manifest (JSON) for kubectl")
    sm.add_argument("--name", required=True, help="App/Deployment name")
    sm.add_argument("--image", required=True, help="Container image (e.g. registry/app:tag)")
    sm.add_argument("--replicas", type=int, default=2, help="Replica count")
    sm.add_argument("--env", nargs="*", help="Env vars as key=value")
    sm.add_argument("--resources", default=None, help='Resources JSON, default {"requests":{"cpu":"100m","memory":"256Mi"},"limits":{"cpu":"1","memory":"1Gi"}}')
    sm.add_argument("--port", type=int, nargs="*", default=[8081], help="Container ports")
    sm.add_argument("--labels", nargs="*", help="Extra labels key=value")
    sm.add_argument("--annotations", nargs="*", help="Annotations key=value")
    sm.add_argument("--out", default=None, help="Write to file (otherwise print)")
    sm.set_defaults(func=cmd_render_manifest)

    # deploy
    sd = sub.add_parser("deploy", help="kubectl apply -f manifest and wait for rollout")
    sd.add_argument("--manifest", required=True, help="Path to manifest JSON")
    sd.add_argument("--name", required=False, help="App name (for --wait)")
    sd.add_argument("--deployment", required=False, help="Deployment name override")
    sd.add_argument("--namespace", default=None, help="K8s namespace (default NF_K8S_NAMESPACE)")
    sd.add_argument("--wait", action="store_true", help="Wait for rollout status")
    sd.add_argument("--timeout", default="180s", help="Rollout timeout")
    sd.set_defaults(func=cmd_deploy)

    # status
    ss = sub.add_parser("status", help="kubectl rollout status")
    ss.add_argument("--name", required=False, help="App/Deployment name")
    ss.add_argument("--deployment", required=False, help="Deployment name override")
    ss.add_argument("--namespace", default=None, help="K8s namespace")
    ss.add_argument("--timeout", default="120s", help="Timeout")
    ss.set_defaults(func=cmd_status)

    # rollback
    sr = sub.add_parser("rollback", help="kubectl rollout undo (optionally to specific revision)")
    sr.add_argument("--name", required=False, help="App/Deployment name")
    sr.add_argument("--deployment", required=False, help="Deployment name override")
    sr.add_argument("--namespace", default=None, help="K8s namespace")
    sr.add_argument("--revision", default=None, help="Target revision (int), optional")
    sr.set_defaults(func=cmd_rollback)

    return p


# ---------------------------
# Main
# ---------------------------
def main(argv: Optional[List[str]] = None) -> None:
    # Graceful termination
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: sys.exit(130))

    cfg = DeployConfig()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args, cfg)  # type: ignore[attr-defined]
    except Exception as e:
        jlog("error", "command_failed", {"cmd": args.cmd, "error": str(e)})
        sys.exit(1)


if __name__ == "__main__":
    main()
