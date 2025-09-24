# physical-integration-core/cli/tools/push_firmware.py
"""
Production-grade OTA firmware CLI for Physical Integration Core.

Commands:
  package create   -> build signed package (.picfw zip) with manifest + sha256 + optional ed25519 signature
  package verify   -> verify package integrity and signature
  upload http      -> upload package/firmware to HTTP(S) endpoint (PUT/POST) with streaming
  push instruct    -> publish OTA command over MQTT (device fetches from URL)
  push stream      -> stream package over MQTT in chunks with ACK/resume

Dependencies (Python >= 3.10):
  typer>=0.9
  rich>=13           # pretty logs (optional but recommended)
  requests>=2.31
  asyncio-mqtt>=0.16
  cryptography>=42   # optional, for Ed25519 signing/verification
  tqdm>=4            # optional, for progress bars

Environment (MQTT defaults; can be overridden by flags):
  PIC_MQTT_HOST, PIC_MQTT_PORT=8883, PIC_MQTT_USERNAME, PIC_MQTT_PASSWORD
  PIC_MQTT_TLS_ENABLED=true, PIC_MQTT_TLS_INSECURE=false, PIC_MQTT_TLS_CA, PIC_MQTT_TLS_CERT, PIC_MQTT_TLS_KEY
  PIC_MQTT_CLIENT_ID=pic-fw-<rand>

Security notes:
- Prefer 'push instruct' with HTTPS URL and manifest signature.
- 'push stream' requires device-side support of the simple session protocol (begin/ack/chunk/commit).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import hashlib
import json
import logging
import os
import ssl
import sys
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, List, Tuple

import requests
import typer

try:
    from rich.logging import RichHandler  # type: ignore
    _USE_RICH = True
except Exception:
    _USE_RICH = False

try:
    from tqdm import tqdm  # type: ignore
except Exception:  # pragma: no cover
    tqdm = None  # type: ignore

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey  # type: ignore
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PublicFormat  # type: ignore
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

try:
    from asyncio_mqtt import Client, MqttError  # type: ignore
except Exception as e:
    raise SystemExit("asyncio-mqtt is required: pip install asyncio-mqtt") from e

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Physical Integration Core Firmware CLI")

# ---------------------- Logging ----------------------
LOG = logging.getLogger("pic.cli.fw")

def _setup_logging(verbose: bool) -> None:
    LOG.setLevel(logging.DEBUG if verbose else logging.INFO)
    if _USE_RICH:
        handler = RichHandler(markup=False, show_time=True, show_level=True, show_path=False, rich_tracebacks=False)
        fmt = "%(message)s"
    else:
        handler = logging.StreamHandler(sys.stdout)
        fmt = "%(asctime)s %(levelname)s %(name)s %(message)s"
    handler.setFormatter(logging.Formatter(fmt=fmt))
    LOG.handlers.clear()
    LOG.addHandler(handler)

# ---------------------- Manifest ----------------------
@dataclass
class FirmwareManifest:
    version: str
    vendor: str
    model: str
    device_class: str
    build_id: str
    created_at: float
    size_bytes: int
    sha256: str
    mime: str = "application/octet-stream"
    notes: Optional[str] = None
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)
    signature: Optional[str] = None  # base64 ed25519 over the JSON without 'signature'
    pubkey: Optional[str] = None     # base64 raw 32 bytes (optional, for convenience)

    def to_json(self, include_signature: bool = True) -> str:
        obj = dataclasses.asdict(self)
        if not include_signature:
            obj.pop("signature", None)
            obj.pop("pubkey", None)
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def sign_manifest(man: FirmwareManifest, priv_pem: Optional[bytes]) -> FirmwareManifest:
    if not priv_pem:
        return man
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography is required for signing")
    key = load_pem_private_key(priv_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("private key must be Ed25519 (PEM)")
    payload = man.to_json(include_signature=False).encode("utf-8")
    sig = key.sign(payload)
    man.signature = base64.b64encode(sig).decode("ascii")
    pub = key.public_key()
    man.pubkey = base64.b64encode(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")
    return man

def verify_manifest(man: FirmwareManifest, pub_pem: Optional[bytes]) -> bool:
    if not man.signature:
        LOG.warning("manifest has no signature")
        return False if pub_pem else True
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography is required for signature verification")
    key = load_pem_public_key(pub_pem) if pub_pem else None
    if key and not isinstance(key, Ed25519PublicKey):
        raise RuntimeError("public key must be Ed25519 (PEM)")
    payload = man.to_json(include_signature=False).encode("utf-8")
    sig = base64.b64decode(man.signature.encode("ascii"))
    if key:
        key.verify(sig, payload)  # raises on failure
        return True
    # fallback to embedded pubkey
    if man.pubkey:
        pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(man.pubkey))
        pk.verify(sig, payload)
        return True
    return False

# ---------------------- Packaging ----------------------
@app.command("package")
def package_cmd():
    """Top-level for 'package'."""
    pass

@package_cmd.command("create")
def package_create(
    firmware: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(..., help="Output .picfw path"),
    version: str = typer.Option(...),
    vendor: str = typer.Option(...),
    model: str = typer.Option(...),
    device_class: str = typer.Option(..., help="e.g., 'edge-sensor'"),
    notes: Optional[str] = typer.Option(None),
    build_id: str = typer.Option(uuid.uuid4().hex, help="Build identifier"),
    sign_key: Optional[Path] = typer.Option(None, help="PEM Ed25519 private key to sign manifest"),
    metadata: Optional[str] = typer.Option(None, help="JSON string with extra metadata"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """
    Create a signed firmware package (.picfw = ZIP with manifest.json, firmware.bin).
    """
    _setup_logging(verbose)
    sha = sha256_file(firmware)
    size = firmware.stat().st_size
    man = FirmwareManifest(
        version=version,
        vendor=vendor,
        model=model,
        device_class=device_class,
        build_id=build_id,
        created_at=time.time(),
        size_bytes=size,
        sha256=sha,
        notes=notes,
        metadata=json.loads(metadata) if metadata else {},
    )
    if sign_key:
        man = sign_manifest(man, sign_key.read_bytes())
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.writestr("manifest.json", man.to_json(include_signature=True))
        # store firmware as 'firmware.bin'
        with firmware.open("rb") as f:
            z.writestr("firmware.bin", f.read())
    LOG.info("package_created path=%s sha256=%s size=%d", out, sha, size)

@package_cmd.command("verify")
def package_verify(
    package: Path = typer.Argument(..., exists=True, readable=True),
    pubkey: Optional[Path] = typer.Option(None, help="PEM Ed25519 public key"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """
    Verify package integrity (sha256) and optional signature.
    """
    _setup_logging(verbose)
    with zipfile.ZipFile(package, "r") as z:
        man = json.loads(z.read("manifest.json").decode("utf-8"))
        fm = FirmwareManifest(**man)
        fw = z.read("firmware.bin")
    sha = hashlib.sha256(fw).hexdigest()
    if sha != fm.sha256:
        raise typer.Exit(code=2)
    ok_sig = True
    if pubkey:
        ok_sig = verify_manifest(fm, pubkey.read_bytes())
    LOG.info("package_ok signature=%s sha256=%s size=%d", ok_sig, sha, len(fw))

# ---------------------- HTTP upload ----------------------
@app.command("upload")
def upload_cmd():
    """Top-level for 'upload'."""
    pass

@upload_cmd.command("http")
def upload_http(
    source: Path = typer.Argument(..., exists=True, readable=True),
    url: str = typer.Option(..., help="PUT/POST to this URL"),
    method: str = typer.Option("PUT", help="PUT or POST"),
    header: List[str] = typer.Option([], help="Extra headers, e.g. 'Authorization: Bearer ...'"),
    timeout: float = typer.Option(60.0),
    chunk_size: int = typer.Option(1024 * 1024),
    verify_tls: bool = typer.Option(True),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """
    Upload package/firmware to HTTP(S) endpoint with streaming.
    """
    _setup_logging(verbose)
    headers = {}
    for h in header:
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    size = source.stat().st_size
    def gen():
        with source.open("rb") as f:
            if tqdm:
                bar = tqdm(total=size, unit="B", unit_scale=True, desc="upload")
            else:
                bar = None
            while True:
                b = f.read(chunk_size)
                if not b:
                    break
                yield b
                if bar:
                    bar.update(len(b))
    LOG.info("upload_start method=%s url=%s size=%d", method, url, size)
    resp = requests.request(method.upper(), url, data=gen(), headers=headers, timeout=timeout, verify=verify_tls)
    resp.raise_for_status()
    LOG.info("upload_ok status=%s", resp.status_code)

# ---------------------- MQTT helpers ----------------------
@dataclass
class MqttConf:
    host: str = os.getenv("PIC_MQTT_HOST", "localhost")
    port: int = int(os.getenv("PIC_MQTT_PORT", "8883"))
    username: Optional[str] = os.getenv("PIC_MQTT_USERNAME")
    password: Optional[str] = os.getenv("PIC_MQTT_PASSWORD")
    client_id: str = os.getenv("PIC_MQTT_CLIENT_ID", f"pic-fw-{uuid.uuid4().hex[:8]}")
    tls_enabled: bool = os.getenv("PIC_MQTT_TLS_ENABLED", "true").lower() == "true"
    tls_insecure: bool = os.getenv("PIC_MQTT_TLS_INSECURE", "false").lower() == "true"
    tls_ca: Optional[str] = os.getenv("PIC_MQTT_TLS_CA")
    tls_cert: Optional[str] = os.getenv("PIC_MQTT_TLS_CERT")
    tls_key: Optional[str] = os.getenv("PIC_MQTT_TLS_KEY")
    keepalive: int = 30

def _tls_context(conf: MqttConf) -> Optional[ssl.SSLContext]:
    if not conf.tls_enabled:
        return None
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=conf.tls_ca)
    if conf.tls_cert and conf.tls_key:
        ctx.load_cert_chain(conf.tls_cert, conf.tls_key)
    if conf.tls_insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

async def _mqtt_connect(conf: MqttConf) -> Client:
    client = Client(
        hostname=conf.host,
        port=conf.port,
        username=conf.username,
        password=conf.password,
        client_id=conf.client_id,
        tls_context=_tls_context(conf),
        keepalive=conf.keepalive,
    )
    await client.connect()
    return client

# ---------------------- MQTT: instruct mode ----------------------
@app.command("push")
def push_cmd():
    """Top-level for 'push'."""
    pass

@push_cmd.command("instruct")
def push_instruct(
    device_id: str = typer.Option(..., help="Target device id"),
    url: str = typer.Option(..., help="Firmware URL accessible by the device"),
    sha256: str = typer.Option(..., help="SHA256 of the firmware content"),
    version: str = typer.Option(..., help="Firmware version"),
    channel: str = typer.Option("stable", help="Release channel (stable/beta/canary)"),
    topic: str = typer.Option(None, help="Commands topic. Default: commands/{device_id}"),
    qos: int = typer.Option(1),
    retain: bool = typer.Option(False),
    timeout: float = typer.Option(10.0),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """
    Publish OTA command so the device fetches firmware from URL.

    Expected device handler (example):
      { "type":"command", "id":"...", "command":"ota.update",
        "params": { "uri": "...", "sha256":"...", "version":"...", "channel":"stable" } }
    """
    _setup_logging(verbose)
    conf = MqttConf()
    topic = topic or f"commands/{device_id}"
    cmd = {
        "type": "command",
        "id": uuid.uuid4().hex,
        "command": "ota.update",
        "params": {"uri": url, "sha256": sha256, "version": version, "channel": channel},
        "priority": "HIGH",
        "ts": time.time(),
    }

    async def run():
        client = await _mqtt_connect(conf)
        try:
            payload = json.dumps(cmd, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            await client.publish(topic, payload, qos=qos, retain=retain)
            LOG.info("mqtt_publish_ok topic=%s bytes=%d", topic, len(payload))
        finally:
            await client.disconnect()

    asyncio.run(asyncio.wait_for(run(), timeout=timeout))

# ---------------------- MQTT: stream mode with resume ----------------------
@push_cmd.command("stream")
def push_stream(
    package: Path = typer.Option(..., exists=True, readable=True, help=".picfw or raw firmware file"),
    device_id: str = typer.Option(...),
    base_topic: str = typer.Option(None, help="Base OTA topic. Default: ota/{device_id}"),
    chunk_size: int = typer.Option(128 * 1024, help="Chunk size in bytes"),
    ack_every: int = typer.Option(16, help="Require ACK every N chunks"),
    max_inflight: int = typer.Option(32, help="Max chunks in flight"),
    send_rps: float = typer.Option(200.0, help="Send messages per second (rate limit)"),
    timeout: float = typer.Option(120.0, help="Overall timeout"),
    qos: int = typer.Option(1),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """
    Stream package over MQTT with a simple session protocol:

      control topic: {base}/control
        -> begin: { "type":"begin", "session":"...", "size":.., "sha256":"..", "total":.. }
        <- ack_begin: { "type":"ack_begin", "session":"...", "last_seq":-1|n }
        -> commit: { "type":"commit", "session":"...", "total":.., "sha256":".." }
        <- done: { "type":"done", "session":"...", "status":"ok" }

      data topic: {base}/chunks
        -> binary payload of chunks; MQTT properties or JSON envelope are avoided for efficiency.
           Each chunk is prefixed with 12 bytes header: [session[:8] ascii hex][4-bytes seq big-endian]

      ack topic: {base}/ack
        <- { "type":"ack", "session":"...", "seq": n }

    Device side must implement this protocol.
    """
    _setup_logging(verbose)
    conf = MqttConf()
    base = base_topic or f"ota/{device_id}"
    t_control = f"{base}/control"
    t_chunks = f"{base}/chunks"
    t_ack = f"{base}/ack"

    # Load data: if .picfw, stream the whole file; compute SHA256 for integrity
    data_path = package
    size = data_path.stat().st_size
    sha = sha256_file(data_path)
    total = (size + chunk_size - 1) // chunk_size
    session = uuid.uuid4().hex[:8]

    rate_interval = 1.0 / max(1.0, send_rps)

    async def run():
        nonlocal total
        client = await _mqtt_connect(conf)
        # subscribe to acks
        await client.subscribe(t_ack, qos=1)
        last_seq = -1
        inflight: Dict[int, float] = {}
        inflight_order: List[int] = []

        @contextlib.asynccontextmanager
        async def messages():
            async with client.unfiltered_messages() as msgs:
                yield msgs

        async with messages() as msgs:
            # send begin
            begin = {"type": "begin", "session": session, "size": size, "sha256": sha, "total": total}
            await client.publish(t_control, json.dumps(begin, separators=(",", ":")).encode("utf-8"), qos=qos, retain=False)
            LOG.info("begin_sent session=%s size=%d total=%d sha256=%s", session, size, total, sha)

            # wait for ack_begin or infer resume after small grace
            started = time.monotonic()
            while True:
                try:
                    msg = await asyncio.wait_for(msgs.__anext__(), timeout=3.0)
                except asyncio.TimeoutError:
                    break
                if msg.topic != t_ack:
                    continue
                try:
                    o = json.loads(msg.payload.decode("utf-8"))
                except Exception:
                    continue
                if o.get("type") == "ack_begin" and o.get("session") == session:
                    last_seq = int(o.get("last_seq", -1))
                    break
            LOG.info("resume_from last_seq=%d", last_seq)

            # data loop
            sent = last_seq + 1
            next_ack_target = sent + ack_every - 1
            if tqdm:
                bar = tqdm(total=total, initial=sent, unit="chunk", desc="stream")
            else:
                bar = None

            with data_path.open("rb") as f:
                # skip to resume offset
                f.seek(sent * chunk_size)
                seq = sent
                last_send_ts = 0.0

                async def handle_acks():
                    nonlocal last_seq, next_ack_target
                    while True:
                        try:
                            msg = await msgs.__anext__()
                        except Exception:
                            return
                        if msg.topic != t_ack:
                            continue
                        try:
                            o = json.loads(msg.payload.decode("utf-8"))
                        except Exception:
                            continue
                        if o.get("session") != session:
                            continue
                        if o.get("type") == "ack":
                            ack_seq = int(o.get("seq", -1))
                            if ack_seq >= last_seq:
                                last_seq = ack_seq
                                # drop inflight entries <= ack_seq
                                while inflight_order and inflight_order[0] <= ack_seq:
                                    inflight.pop(inflight_order.pop(0), None)
                                if bar:
                                    bar.n = last_seq + 1
                                    bar.refresh()
                ack_task = asyncio.create_task(handle_acks())

                try:
                    while seq < total:
                        # rate limit
                        now = time.monotonic()
                        if now - last_send_ts < rate_interval:
                            await asyncio.sleep(rate_interval - (now - last_send_ts))
                        # flow control: max_inflight
                        if len(inflight) >= max_inflight:
                            await asyncio.sleep(0.005)
                            continue
                        # read
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        # header: 8 ascii hex of session + 4-byte big-endian seq
                        header = session.encode("ascii") + seq.to_bytes(4, "big")
                        payload = header + chunk
                        await client.publish(t_chunks, payload, qos=qos, retain=False)
                        inflight[seq] = time.monotonic()
                        inflight_order.append(seq)
                        last_send_ts = time.monotonic()
                        # expect ack on boundaries
                        if seq >= next_ack_target:
                            # wait until last_seq >= seq
                            lim = time.time() + 10.0  # 10s ack boundary timeout
                            while last_seq < seq and time.time() < lim:
                                await asyncio.sleep(0.01)
                            if last_seq < seq:
                                # retransmit last window
                                LOG.warning("ack_timeout window=%d..%d retransmit", next_ack_target - ack_every + 1, seq)
                                # retransmit from last_seq+1
                                back_to = last_seq + 1
                                f.seek(back_to * chunk_size)
                                seq = back_to
                                inflight.clear()
                                inflight_order.clear()
                                next_ack_target = seq + ack_every - 1
                                continue
                            next_ack_target = seq + ack_every
                        seq += 1

                finally:
                    ack_task.cancel()
                    with contextlib.suppress(Exception):
                        await ack_task

            # commit
            commit = {"type": "commit", "session": session, "total": total, "sha256": sha}
            await client.publish(t_control, json.dumps(commit, separators=(",", ":")).encode("utf-8"), qos=qos, retain=False)
            LOG.info("commit_sent session=%s", session)

            # wait for done
            done_ok = False
            end_wait = time.time() + 30.0
            while time.time() < end_wait:
                try:
                    msg = await asyncio.wait_for(msgs.__anext__(), timeout=2.0)
                except asyncio.TimeoutError:
                    continue
                if msg.topic != t_ack:
                    continue
                try:
                    o = json.loads(msg.payload.decode("utf-8"))
                except Exception:
                    continue
                if o.get("type") == "done" and o.get("session") == session and o.get("status") == "ok":
                    done_ok = True
                    break
            if not done_ok:
                LOG.warning("no_done_ack_received session=%s", session)
        await client.disconnect()

    asyncio.run(asyncio.wait_for(run(), timeout=timeout))
    LOG.info("stream_finished session=%s total=%d sha256=%s", session, total, sha)

# ---------------------- Entry ----------------------
if __name__ == "__main__":
    app()
