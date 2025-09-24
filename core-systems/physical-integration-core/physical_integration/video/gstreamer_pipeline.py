# SPDX-License-Identifier: Apache-2.0
"""
physical_integration/video/gstreamer_pipeline.py

Промышленный менеджер видеопотока на GStreamer:
- Источники: RTSP, файл, тест-генератор
- Ветви вывода: RTP/UDP (H.264/H.265), запись сегментами (splitmuxsink), Appsink (для ИИ)
- Программная сборка пайплайна с rtspsrc pad-added и автоматическим депейлоудом H264/H265
- Очереди с backpressure и leaky в "живых" ветвях
- Аппаратные/софт энкодеры с авто-подбором и откатом (fallback)
- Автопереподключение с экспоненциальным backoff
- Метрики: кадров/сек, байты, ошибки (внутренние счетчики; опционально Prometheus)
- Безопасная остановка, обработка EOS/ERROR на шине

Зависимости:
  - PyGObject (gi): GStreamer >= 1.18
  - (опц.) prometheus_client для экспорта метрик (если установлен — включится автоматически)
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Literal, Optional, Tuple

import gi  # type: ignore
gi.require_version("Gst", "1.0")
gi.require_version("GObject", "2.0")
from gi.repository import Gst, GObject, GLib  # type: ignore

# Инициализация GStreamer
GObject.threads_init()
Gst.init(None)

log = logging.getLogger(__name__)
logging.basicConfig(
    level=os.getenv("PIC_VIDEO_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

try:
    # Опциональные метрики (прозрачно отключаются при отсутствии пакета)
    from prometheus_client import Counter, Gauge, start_http_server  # type: ignore

    _PROM_AVAILABLE = True
except Exception:
    _PROM_AVAILABLE = False


# =========================
# Конфиги
# =========================

@dataclass
class SourceConfig:
    kind: Literal["rtsp", "file", "testsrc"] = "rtsp"
    uri: str = ""                  # rtsp://..., file:///..., /path/to/file
    user: Optional[str] = None     # для RTSP
    password: Optional[str] = None
    latency_ms: int = 200          # буферизация RTSP (баланс латентность/стабильность)
    tcp: bool = True               # RTSP поверх TCP
    drop_on_latency: bool = True   # отбрасывать кадры при превышении задержки
    timeout_ms: int = 5000         # сетевые таймауты (RTSP)
    max_fps: Optional[int] = None  # ограничение частоты кадров после decode
    width: Optional[int] = None    # масштабирование после decode
    height: Optional[int] = None

@dataclass
class EncoderConfig:
    codec: Literal["h264", "h265"] = "h264"
    bitrate_kbps: int = 4000
    keyint: int = 60               # GOP/keyint (в кадрах)
    tune_zero_latency: bool = True
    speed_preset: Literal["ultrafast","superfast","veryfast","faster","fast","medium","slow","slower","veryslow"] = "veryfast"
    hw_priority: Tuple[str, ...] = ("nvv4l2", "vaapi")  # порядок опробования HW энкодеров

@dataclass
class RtpSinkConfig:
    enabled: bool = True
    host: str = "239.0.0.1"        # может быть unicast/multicast
    port: int = 5004
    pt: int = 96
    ttl: int = 64

@dataclass
class RecordingSinkConfig:
    enabled: bool = False
    location_pattern: str = "/var/lib/pic/records/%Y%m%d/%H/pic-%Y%m%d-%H%M%S-%05d.mp4"
    segment_seconds: int = 300     # длина сегмента
    max_size_mb: int = 1024        # ограничение на размер сегмента
    fast_start: bool = True        # mp4: быстрая запись заголовков

@dataclass
class AppSinkConfig:
    enabled: bool = False
    name: str = "inference"
    emit_signals: bool = False     # если True — испускать сигналы new-sample

@dataclass
class PipelineConfig:
    source: SourceConfig = field(default_factory=SourceConfig)
    encoder: EncoderConfig = field(default_factory=EncoderConfig)
    rtp: RtpSinkConfig = field(default_factory=RtpSinkConfig)
    recording: RecordingSinkConfig = field(default_factory=RecordingSinkConfig)
    appsink: AppSinkConfig = field(default_factory=AppSinkConfig)
    metrics_port: Optional[int] = 9109  # если None — не поднимать HTTP метрики
    name: str = "video-pipeline"


# =========================
# Вспомогательные функции
# =========================

def _make_or_raise(factory: str, name: Optional[str] = None) -> Gst.Element:
    el = Gst.ElementFactory.make(factory, name)
    if not el:
        raise RuntimeError(f"GStreamer element '{factory}' is not available")
    return el

def _try_make(factory: str, name: Optional[str] = None) -> Optional[Gst.Element]:
    return Gst.ElementFactory.make(factory, name)

def _set_if(el: Gst.Element, **kwargs):
    for k, v in kwargs.items():
        if v is not None:
            el.set_property(k, v)

def _caps_raw(width: Optional[int], height: Optional[int], fps: Optional[int]) -> Gst.Caps:
    caps = Gst.Caps.from_string("video/x-raw,format=NV12")
    s = caps.get_structure(0)
    if width and height:
        s.set_value("width", width)
        s.set_value("height", height)
    if fps:
        s.set_value("framerate", Gst.Fraction(fps, 1))
    return caps


# =========================
# Ветви-бины (удобно подключать к tee)
# =========================

def build_rtp_branch(cfg: PipelineConfig) -> Gst.Bin:
    """Собирает бин: queue -> encoder -> pay -> udpsink. Возвращает Bin с ghost sink pad 'sink'."""
    b = Gst.Bin.new("branch_rtp")

    q = _make_or_raise("queue", "rtp_queue")
    q.set_property("leaky", 2)  # 2 = LEAK_DOWNSTREAM
    q.set_property("max-size-buffers", 0)
    q.set_property("max-size-time", 2_000_000_000)  # 2s
    q.set_property("silent", True)

    enc = select_encoder(cfg.encoder, name="rtp_encoder")

    if cfg.encoder.codec == "h264":
        pay = _make_or_raise("rtph264pay", "rtp_pay")
        pay.set_property("config-interval", 1)
        pay.set_property("pt", cfg.rtp.pt)
    else:
        pay = _make_or_raise("rtph265pay", "rtp_pay")
        pay.set_property("pt", cfg.rtp.pt)

    sink = _make_or_raise("udpsink", "rtp_sink")
    _set_if(sink, host=cfg.rtp.host, port=cfg.rtp.port, ttl=cfg.rtp.ttl, sync=False, async_=False)

    for el in (q, enc, pay, sink):
        b.add(el)
    Gst.Element.link_many(q, enc, pay, sink)

    # GhostPad входа
    sinkpad = q.get_static_pad("sink")
    b.add_pad(Gst.GhostPad.new("sink", sinkpad))
    return b


def build_record_branch(cfg: PipelineConfig) -> Gst.Bin:
    """Бин: queue -> encoder -> splitmuxsink(mp4). Возвращает Bin с ghost sink pad 'sink'."""
    b = Gst.Bin.new("branch_record")

    q = _make_or_raise("queue", "rec_queue")
    q.set_property("leaky", 0)
    q.set_property("max-size-buffers", 0)
    q.set_property("max-size-time", 0)
    q.set_property("silent", True)

    enc = select_encoder(cfg.encoder, name="rec_encoder")

    mp4mux = _make_or_raise("mp4mux", "mp4_mux")
    if cfg.recording.fast_start:
        _set_if(mp4mux, faststart=True, streamable=True, fragment-duration=cfg.recording.segment_seconds * 1000)

    split = _make_or_raise("splitmuxsink", "splitmux")
    _set_if(
        split,
        muxer=mp4mux,
        location=cfg.recording.location_pattern,
        max-size-time=cfg.recording.segment_seconds * 1_000_000_000,
        max-size-bytes=cfg.recording.max_size_mb * 1024 * 1024,
        async_=False,
    )

    for el in (q, enc, split):
        b.add(el)
    Gst.Element.link_many(q, enc, split)

    sinkpad = q.get_static_pad("sink")
    b.add_pad(Gst.GhostPad.new("sink", sinkpad))
    return b


def build_appsink_branch(cfg: PipelineConfig) -> Gst.Bin:
    """Бин: queue -> appsink (для интеграции с ИИ). Возвращает Bin с ghost sink pad 'sink'."""
    b = Gst.Bin.new("branch_appsink")

    q = _make_or_raise("queue", "app_queue")
    q.set_property("leaky", 2)
    q.set_property("max-size-time", 2_000_000_000)
    q.set_property("silent", True)

    app = _make_or_raise("appsink", cfg.appsink.name)
    app.set_property("emit-signals", cfg.appsink.emit_signals)
    app.set_property("sync", False)
    # При необходимости можно ограничить caps для ИИ:
    # app.set_property("caps", Gst.Caps.from_string("video/x-raw,format=NV12"))

    for el in (q, app):
        b.add(el)
    Gst.Element.link_many(q, app)

    sinkpad = q.get_static_pad("sink")
    b.add_pad(Gst.GhostPad.new("sink", sinkpad))
    return b


def select_encoder(enc_cfg: EncoderConfig, name: str) -> Gst.Element:
    """Подбор энкодера с учетом hw_priority и откатом на софт. Возвращает настроенный элемент."""
    codec = enc_cfg.codec

    def _setup_common(e: Gst.Element):
        # Унифицированные параметры
        if codec == "h264":
            # Для x264enc
            if e.get_factory().get_name() == "x264enc":
                e.set_property("bitrate", enc_cfg.bitrate_kbps)
                e.set_property("key-int-max", enc_cfg.keyint)
                e.set_property("speed-preset", enc_cfg.speed_preset)
                if enc_cfg.tune_zero_latency:
                    e.set_property("tune", "zerolatency")
            # Для ваариантов HW (набор свойств может различаться — применяем осторожно)
            for prop, val in (
                ("bitrate", enc_cfg.bitrate_kbps * 1000),  # некоторые плагины ожидают bps
                ("iframeinterval", enc_cfg.keyint),
                ("control-rate", 1),  # VBR/CQP/CBR — 1 обычно CBR/VBR в зав-ти от плагина
                ("preset-level", 1),
                ("zerolatency", enc_cfg.tune_zero_latency),
            ):
                try:
                    e.set_property(prop, val)
                except Exception:
                    pass
        else:
            # h265
            if e.get_factory().get_name() == "x265enc":
                e.set_property("bitrate", enc_cfg.bitrate_kbps * 1000)
                e.set_property("key-int-max", enc_cfg.keyint)
                if enc_cfg.tune_zero_latency:
                    e.set_property("tune", "zerolatency")
            for prop, val in (
                ("bitrate", enc_cfg.bitrate_kbps * 1000),
                ("iframeinterval", enc_cfg.keyint),
                ("zerolatency", enc_cfg.tune_zero_latency),
            ):
                try:
                    e.set_property(prop, val)
                except Exception:
                    pass

    # Порядок проб: HW -> SW
    candidates: Tuple[Tuple[str, str], ...]
    if codec == "h264":
        candidates = tuple(
            (impl, f"{impl}h264enc") for impl in enc_cfg.hw_priority
        ) + (("x264", "x264enc"),)
    else:
        candidates = tuple(
            (impl, f"{impl}h265enc") for impl in enc_cfg.hw_priority
        ) + (("x265", "x265enc"),)

    last_err: Optional[Exception] = None
    for impl, factory in candidates:
        el = _try_make(factory, name)
        if el:
            _setup_common(el)
            log.info("Using encoder: %s (%s)", factory, impl)
            return el
        else:
            last_err = RuntimeError(f"Encoder '{factory}' not available")

    # Если ничего не подошло — ошибка (лучше явная, чем молчаливое снижение качества)
    raise last_err or RuntimeError("No suitable encoder found")


# =========================
# Основной класс пайплайна
# =========================

class VideoPipeline:
    def __init__(self, cfg: PipelineConfig):
        self.cfg = cfg
        self.pipeline: Optional[Gst.Pipeline] = None
        self.loop: Optional[GLib.MainLoop] = None
        self.thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._restart_backoff_s = 1.0
        self._metrics = self._init_metrics(cfg.metrics_port)

        # Счетчики на кадры/байты
        self._frames_total = 0
        self._bytes_total = 0

    # ---------- Публичный API ----------

    def start(self):
        """Запуск пайплайна в отдельном GLib-потоке."""
        if self.thread and self.thread.is_alive():
            log.info("Pipeline already running")
            return

        self._stop_flag.clear()
        self.loop = GLib.MainLoop()
        self.pipeline = Gst.Pipeline.new(self.cfg.name)

        self._build_static_sinks()  # заранее добавим ветви вывода
        src = self._build_source()  # rtspsrc/file/testsrc
        self.pipeline.add(src)

        # Обработчик bus
        bus = self.pipeline.get_bus()
        bus.add_signal_watch()
        bus.connect("message", self._on_bus_message)

        # Запуск GLib в отдельном потоке
        def _runner():
            try:
                log.info("Starting pipeline...")
                self.pipeline.set_state(Gst.State.PLAYING)
                self.loop.run()
            finally:
                log.info("Stopping pipeline thread; setting state to NULL")
                if self.pipeline:
                    self.pipeline.set_state(Gst.State.NULL)

        self.thread = threading.Thread(target=_runner, name=f"{self.cfg.name}-thread", daemon=True)
        self.thread.start()

        # Ожидание прогона до PAUSED/PLAYING
        self._wait_for_state(Gst.State.PLAYING, timeout=10.0)
        log.info("Pipeline started")

    def stop(self):
        """Останов пайплайна и GLib-цикла."""
        self._stop_flag.set()
        if self.loop:
            self.loop.quit()
        if self.thread:
            self.thread.join(timeout=5.0)
        self.thread = None
        self.loop = None
        self.pipeline = None
        log.info("Pipeline stopped")

    def restart(self, reason: str = "manual"):
        """Перезапуск с backoff."""
        log.warning("Pipeline restart requested: %s", reason)
        self.stop()
        time.sleep(min(self._restart_backoff_s, 10.0))
        self._restart_backoff_s = min(self._restart_backoff_s * 2, 30.0)
        self.start()

    # ---------- Конструирование ----------

    def _build_source(self) -> Gst.Element:
        s = self.cfg.source
        if s.kind == "rtsp":
            src = _make_or_raise("rtspsrc", "src")
            _set_if(src, location=s.uri, latency=s.latency_ms, drop_on_latency=s.drop_on_latency, timeout=s.timeout_ms * 1000)
            if s.user:
                src.set_property("user-id", s.user)
            if s.password:
                src.set_property("user-pw", s.password)
            # Привязка динамических пэдов
            src.connect("pad-added", self._on_rtsp_pad_added)
            src.connect("pad-removed", self._on_rtsp_pad_removed)
            return src

        if s.kind == "file":
            # uridecodebin упрощает работу с файлами любых форматов
            u = _make_or_raise("uridecodebin", "src")
            # Преобразуем путь в URI, если нужно
            uri = s.uri if s.uri.startswith("file://") else f"file://{s.uri}"
            u.set_property("uri", uri)
            u.connect("pad-added", self._on_decodebin_pad_added)
            return u

        if s.kind == "testsrc":
            src = _make_or_raise("videotestsrc", "src")
            _set_if(src, is_live=True, pattern=0)
            # Чтобы соблюсти интерфейс pad-added, обернем через identity
            idn = _make_or_raise("identity", "id_src")
            self.pipeline.add(src)
            self.pipeline.add(idn)
            Gst.Element.link_many(src, idn)
            # Создадим фиктивный decodebin-подобный сигнал
            pad = idn.get_static_pad("src")
            self._attach_post_decode_chain(pad)
            return idn

        raise ValueError(f"Unsupported source kind: {s.kind}")

    def _build_static_sinks(self):
        """Создает и добавляет в пайплайн заранее все ветви-бины для подключения к tee."""
        assert self.pipeline is not None

        self._branches = []

        if self.cfg.rtp.enabled:
            rtpb = build_rtp_branch(self.cfg)
            self.pipeline.add(rtpb)
            self._branches.append(rtpb)

        if self.cfg.recording.enabled:
            recb = build_record_branch(self.cfg)
            self.pipeline.add(recb)
            self._branches.append(recb)

        if self.cfg.appsink.enabled:
            appb = build_appsink_branch(self.cfg)
            self.pipeline.add(appb)
            self._branches.append(appb)

    # ---------- Динамическое построение после decode ----------

    def _on_rtsp_pad_added(self, src: Gst.Element, pad: Gst.Pad):
        """Вызывается при появлении нового пэда у rtspsrc. Подключаем depay/parse/decode."""
        caps = pad.get_current_caps()
        s = caps.to_string() if caps else "unknown"
        log.info("RTSP pad-added with caps: %s", s)

        # Выбор depay/parse на основе encoding-name
        encoding = None
        if caps and caps.get_size() > 0:
            st = caps.get_structure(0)
            encoding = st.get_string("encoding-name")

        if encoding == "H264":
            depay = _make_or_raise("rtph264depay", "depay")
            parse = _make_or_raise("h264parse", "parse")
        elif encoding == "H265":
            depay = _make_or_raise("rtph265depay", "depay")
            parse = _make_or_raise("h265parse", "parse")
        else:
            log.error("Unsupported/unknown RTSP encoding: %s", encoding)
            return

        decode = _make_or_raise("decodebin", "decode")
        decode.connect("pad-added", self._on_decodebin_pad_added)

        # Включаем в пайплайн и линкуем
        assert self.pipeline is not None
        for el in (depay, parse, decode):
            self.pipeline.add(el)
            el.sync_state_with_parent()

        if not pad.link(depay.get_static_pad("sink")) == Gst.PadLinkReturn.OK:
            log.error("Failed to link rtspsrc->depay")
            return

        if not Gst.Element.link_many(depay, parse, decode):
            log.error("Failed to link depay->parse->decode")
            return

    def _on_rtsp_pad_removed(self, src: Gst.Element, pad: Gst.Pad):
        log.warning("RTSP pad removed; source may have disconnected")

    def _on_decodebin_pad_added(self, decodebin: Gst.Element, pad: Gst.Pad):
        """Когда появляется сырой видео-пад после декодирования — строим пост-обработку и подключаем tee."""
        caps = pad.get_current_caps()
        if not caps or not caps.to_string().startswith("video/"):
            return
        self._attach_post_decode_chain(pad)

    def _attach_post_decode_chain(self, src_pad: Gst.Pad):
        assert self.pipeline is not None
        s = self.cfg.source

        # Пост-обработка: очереди -> видеоконвертация -> выравнивание формата -> fps/scale -> tee
        q_pre = _make_or_raise("queue", "q_pre")
        q_pre.set_property("leaky", 2 if s.drop_on_latency else 0)
        q_pre.set_property("max-size-time", 2_000_000_000)

        convert = _make_or_raise("videoconvert", "convert")
        scale = _make_or_raise("videoscale", "scale")
        rate = _make_or_raise("videorate", "rate")

        capsf = _make_or_raise("capsfilter", "capsf")
        capsf.set_property("caps", _caps_raw(s.width, s.height, s.max_fps))

        tee = _make_or_raise("tee", "tee")

        for el in (q_pre, convert, scale, rate, capsf, tee):
            self.pipeline.add(el)
            el.sync_state_with_parent()

        if src_pad.link(q_pre.get_static_pad("sink")) != Gst.PadLinkReturn.OK:
            log.error("Failed to link post-decode source to q_pre")
            return
        if not Gst.Element.link_many(q_pre, convert, scale, rate, capsf, tee):
            log.error("Failed to link post-decode chain")
            return

        # Подключаем все заранее созданные ветви к tee
        for idx, br in enumerate(getattr(self, "_branches", [])):
            q = _make_or_raise("queue", f"q_branch_{idx}")
            q.set_property("leaky", 2 if self.cfg.rtp.enabled else 0)
            q.set_property("max-size-time", 2_000_000_000 if self.cfg.rtp.enabled else 0)
            self.pipeline.add(q)
            q.sync_state_with_parent()

            tee_src = tee.get_request_pad("src_%u")
            if not tee_src:
                log.error("Failed to get tee src pad")
                continue

            if not tee_src.link(q.get_static_pad("sink")) == Gst.PadLinkReturn.OK:
                log.error("Failed to link tee->queue for branch %s", br.get_name())
                continue

            if not Gst.Element.link_many(q, br):
                log.error("Failed to link queue -> branch %s", br.get_name())

    # ---------- Шина и события ----------

    def _on_bus_message(self, bus: Gst.Bus, msg: Gst.Message):
        t = msg.type
        if t == Gst.MessageType.ERROR:
            err, dbg = msg.parse_error()
            log.error("GStreamer ERROR: %s; debug: %s", err, dbg)
            self._observe_error()
            self._schedule_restart("gst-error")
        elif t == Gst.MessageType.EOS:
            log.warning("GStreamer EOS")
            self._schedule_restart("eos")
        elif t == Gst.MessageType.STATE_CHANGED:
            if msg.src == self.pipeline:
                old, new, pending = msg.parse_state_changed()
                log.debug("Pipeline state: %s -> %s", old.value_nick, new.value_nick)
                if new == Gst.State.PLAYING:
                    self._restart_backoff_s = 1.0
        elif t == Gst.MessageType.ELEMENT:
            # Можно обработать статистику с элементов (например, splitmuxsink или encoders)
            pass

    def _schedule_restart(self, reason: str):
        if self._stop_flag.is_set():
            return
        # Безопасно дернуть рестарт из другого потока
        threading.Thread(target=self.restart, args=(reason,), daemon=True).start()

    def _wait_for_state(self, target: Gst.State, timeout: float = 5.0):
        if not self.pipeline:
            return
        start = time.time()
        while time.time() - start < timeout:
            st, _ = self.pipeline.get_state(0.1)
            if st == target:
                return

    # ---------- Метрики ----------

    def _init_metrics(self, port: Optional[int]):
        if not _PROM_AVAILABLE or port is None:
            return None
        try:
            start_http_server(port)
            m = {
                "frames_total": Counter("pic_video_frames_total", "Total frames processed", ["pipeline"]),
                "errors_total": Counter("pic_video_errors_total", "Total GST errors", ["pipeline"]),
                "restarts_total": Counter("pic_video_restarts_total", "Pipeline restarts", ["pipeline"]),
                "state": Gauge("pic_video_state", "Pipeline state (0=down,1=up)", ["pipeline"]),
            }
            m["state"].labels(self.cfg.name).set(0)
            log.info("Prometheus metrics exported on :%d", port)
            return m
        except Exception as e:
            log.warning("Failed to start metrics exporter: %s", e)
            return None

    def _observe_error(self):
        if self._metrics:
            self._metrics["errors_total"].labels(self.cfg.name).inc()

    # Можно вызывать из обработчиков Appsink (new-sample) для увеличения счетчиков
    def observe_frame(self, bytes_len: int = 0):
        self._frames_total += 1
        self._bytes_total += bytes_len
        if self._metrics:
            self._metrics["frames_total"].labels(self.cfg.name).inc()

# =========================
# Пример запуска (как библиотека)
# =========================

if __name__ == "__main__":
    # Пример конфигурации: RTSP -> RTP/UDP + запись MP4 сегментами + Appsink для ИИ
    cfg = PipelineConfig(
        source=SourceConfig(
            kind=os.getenv("PIC_SRC_KIND", "rtsp"),
            uri=os.getenv("PIC_SRC_URI", "rtsp://10.0.0.10:8554/stream"),
            user=os.getenv("PIC_SRC_USER"),
            password=os.getenv("PIC_SRC_PASS"),
            latency_ms=int(os.getenv("PIC_SRC_LATENCY_MS", "200")),
            drop_on_latency=os.getenv("PIC_SRC_DROP_ON_LATENCY", "true").lower() == "true",
            max_fps=int(os.getenv("PIC_SRC_MAX_FPS", "0") or "0") or None,
            width=int(os.getenv("PIC_SRC_WIDTH", "0") or "0") or None,
            height=int(os.getenv("PIC_SRC_HEIGHT", "0") or "0") or None,
        ),
        encoder=EncoderConfig(
            codec=os.getenv("PIC_ENC_CODEC", "h264"),  # h264|h265
            bitrate_kbps=int(os.getenv("PIC_ENC_BITRATE_KBPS", "4000")),
            keyint=int(os.getenv("PIC_ENC_KEYINT", "60")),
            speed_preset=os.getenv("PIC_ENC_SPEED", "veryfast"),
            hw_priority=tuple((os.getenv("PIC_ENC_HW_PRIORITY", "nvv4l2,vaapi")).split(",")),
        ),
        rtp=RtpSinkConfig(
            enabled=os.getenv("PIC_RTP_ENABLED", "true").lower() == "true",
            host=os.getenv("PIC_RTP_HOST", "239.0.0.1"),
            port=int(os.getenv("PIC_RTP_PORT", "5004")),
            pt=int(os.getenv("PIC_RTP_PT", "96")),
        ),
        recording=RecordingSinkConfig(
            enabled=os.getenv("PIC_REC_ENABLED", "false").lower() == "true",
            location_pattern=os.getenv("PIC_REC_LOCATION", "/var/lib/pic/records/%Y%m%d/%H/pic-%Y%m%d-%H%M%S-%05d.mp4"),
            segment_seconds=int(os.getenv("PIC_REC_SEG_SEC", "300")),
            max_size_mb=int(os.getenv("PIC_REC_MAX_MB", "1024")),
        ),
        appsink=AppSinkConfig(
            enabled=os.getenv("PIC_APP_ENABLED", "false").lower() == "true",
            name=os.getenv("PIC_APP_NAME", "inference"),
            emit_signals=os.getenv("PIC_APP_EMIT", "false").lower() == "true",
        ),
        metrics_port=int(os.getenv("PIC_METRICS_PORT", "9109")),
        name=os.getenv("PIC_PIPELINE_NAME", "video-pipeline"),
    )

    vp = VideoPipeline(cfg)
    try:
        vp.start()
        # Блокируем основной поток; завершение — по Ctrl+C
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        vp.stop()
