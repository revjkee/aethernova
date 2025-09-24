# file: neuroforge-core/neuroforge/training/trainers.py
from __future__ import annotations

import abc
import contextlib
import dataclasses
import json
import logging
import math
import os
import random
import shutil
import signal
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple, Union

logger = logging.getLogger(__name__)

# =========================
# Общие утилиты
# =========================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def set_global_seed(seed: int) -> None:
    random.seed(seed)
    try:
        import numpy as np  # type: ignore
        np.random.seed(seed)
    except Exception:
        pass
    try:
        import torch  # type: ignore
        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)  # type: ignore
        torch.backends.cudnn.deterministic = True  # type: ignore
        torch.backends.cudnn.benchmark = False  # type: ignore
    except Exception:
        pass

def human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    return f"{f:.1f} {units[i]}"

# =========================
# Конфигурации
# =========================

@dataclass
class DeviceConfig:
    prefer_gpu: bool = True
    allow_bfloat16: bool = True
    allow_fp16: bool = True

@dataclass
class OptimConfig:
    name: str = "adamw"
    lr: float = 3e-4
    weight_decay: float = 0.01
    betas: Tuple[float, float] = (0.9, 0.999)
    eps: float = 1e-8

@dataclass
class SchedulerConfig:
    name: Optional[str] = None  # "linear", "cosine", ...
    warmup_steps: int = 0

@dataclass
class CheckpointConfig:
    dir: Union[str, Path] = "checkpoints"
    save_best_metric: Optional[str] = None   # например "val_loss" или "f1"
    mode: str = "min"                        # "min" | "max"
    every_n_steps: int = 0                   # 0 = никогда по шагам
    every_n_epochs: int = 1                  # 0 = никогда по эпохам
    keep_last: int = 3
    atomic: bool = True
    artifact_prefix: str = "model"

@dataclass
class EarlyStoppingConfig:
    metric: Optional[str] = None  # например "val_loss"
    mode: str = "min"             # "min" | "max"
    patience: int = 5
    min_delta: float = 0.0
    cooldown_epochs: int = 0

@dataclass
class TrainingConfig:
    epochs: int = 3
    batch_size: int = 32
    grad_accum_steps: int = 1
    max_steps: Optional[int] = None
    clip_grad_norm: Optional[float] = 1.0
    mixed_precision: Optional[str] = None  # "bf16"|"fp16"|None (auto if None)
    log_every_n_steps: int = 20
    val_every_n_steps: Optional[int] = None  # если None, валидируем по эпохам
    seed: int = 42
    timeout_seconds: Optional[int] = None  # общий таймаут fit()

# =========================
# События обучения (совместимо с вашей Avro-схемой)
# =========================

def _uuid() -> str:
    return str(uuid.uuid4())

def build_training_event(
    type_: str,
    run_id: str,
    env: str,
    producer: str,
    source: str,
    payload: Mapping[str, Any],
    dataset_id: Optional[str] = None,
    dataset_version: Optional[str] = None,
    model_id: Optional[str] = None,
    model_version: Optional[str] = None,
    tenant: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "event_id": _uuid(),
        "event_time": utc_now_iso(),
        "type": type_,
        "environment": env,
        "producer": producer,
        "source": source,
        "correlation_id": correlation_id,
        "trace_id": None,
        "span_id": None,
        "tenant": tenant,
        "run": {
            "run_id": run_id,
            "project": "neuroforge-core",
            "experiment": None,
            "user": None,
        },
        "context": {
            "dataset_id": dataset_id,
            "dataset_version": dataset_version,
            "model_id": model_id,
            "model_version": model_version,
        },
        "payload": dict(payload),
    }

# =========================
# Эмиттеры событий
# =========================

class EventEmitter(Protocol):
    def emit(self, event: Mapping[str, Any]) -> None: ...

class NullEmitter:
    def emit(self, event: Mapping[str, Any]) -> None:
        logger.debug("event(drop): %s", event.get("type"))

class HttpEmitter:
    def __init__(self, url: str, headers: Optional[Mapping[str, str]] = None, timeout: float = 5.0) -> None:
        self.url = url
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.timeout = timeout
        try:
            import requests  # type: ignore
            self._requests = requests
        except Exception:
            self._requests = None
            logger.warning("requests не установлен; HttpEmitter будет неактивным")

    def emit(self, event: Mapping[str, Any]) -> None:
        if not self._requests:
            return
        try:
            r = self._requests.post(self.url, data=json.dumps(event), headers=self.headers, timeout=self.timeout)
            if r.status_code >= 400:
                logger.warning("event http %s -> %s", r.status_code, r.text[:256])
        except Exception as e:
            logger.warning("event http error: %s", e)

class KafkaEmitter:
    def __init__(self, topic: str, config: Optional[Mapping[str, str]] = None) -> None:
        self.topic = topic
        self._producer = None
        try:
            from confluent_kafka import Producer  # type: ignore
            self._producer = Producer(config or {})
        except Exception:
            logger.warning("confluent_kafka не установлен; KafkaEmitter будет неактивным")

    def emit(self, event: Mapping[str, Any]) -> None:
        if not self._producer:
            return
        try:
            self._producer.produce(self.topic, json.dumps(event).encode("utf-8"))
            self._producer.poll(0)
        except Exception as e:
            logger.warning("kafka emit error: %s", e)

# =========================
# Checkpoint IO
# =========================

class CheckpointIO(Protocol):
    def save(self, path: Union[str, Path], data: Mapping[str, Any]) -> None: ...
    def load(self, path: Union[str, Path]) -> Mapping[str, Any]: ...

class LocalCheckpointIO:
    def save(self, path: Union[str, Path], data: Mapping[str, Any]) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(tempfile.mkstemp(prefix=path.name, dir=str(path.parent))[1])
        try:
            with open(tmp, "wb") as f:
                f.write(json.dumps(data).encode("utf-8"))
            if path.exists():
                if path.is_file():
                    path.unlink()
            shutil.move(str(tmp), str(path))
        finally:
            with contextlib.suppress(Exception):
                tmp.unlink(missing_ok=True)  # type: ignore

    def load(self, path: Union[str, Path]) -> Mapping[str, Any]:
        with open(path, "rb") as f:
            return json.loads(f.read().decode("utf-8"))

# =========================
# Колбэки
# =========================

class Callback(Protocol):
    def on_train_start(self, trainer: "BaseTrainer") -> None: ...
    def on_epoch_start(self, trainer: "BaseTrainer", epoch: int) -> None: ...
    def on_after_train_step(self, trainer: "BaseTrainer", step: int, metrics: Mapping[str, float]) -> None: ...
    def on_validation_end(self, trainer: "BaseTrainer", epoch: int, metrics: Mapping[str, float]) -> None: ...
    def on_checkpoint(self, trainer: "BaseTrainer", path: Union[str, Path], metrics: Mapping[str, float]) -> None: ...
    def on_exception(self, trainer: "BaseTrainer", exc: BaseException) -> None: ...
    def on_train_end(self, trainer: "BaseTrainer", result: Mapping[str, Any]) -> None: ...

class LoggingCallback:
    def on_train_start(self, trainer: "BaseTrainer") -> None:
        logger.info("training started: run_id=%s epochs=%d", trainer.run_id, trainer.cfg.epochs)

    def on_epoch_start(self, trainer: "BaseTrainer", epoch: int) -> None:
        logger.info("epoch %d/%d", epoch, trainer.cfg.epochs)

    def on_after_train_step(self, trainer: "BaseTrainer", step: int, metrics: Mapping[str, float]) -> None:
        if step % trainer.cfg.log_every_n_steps == 0:
            items = " ".join(f"{k}={v:.4f}" for k, v in metrics.items())
            logger.info("step %d %s", step, items)

    def on_validation_end(self, trainer: "BaseTrainer", epoch: int, metrics: Mapping[str, float]) -> None:
        items = " ".join(f"{k}={v:.4f}" for k, v in metrics.items())
        logger.info("val epoch %d %s", epoch, items)

    def on_checkpoint(self, trainer: "BaseTrainer", path: Union[str, Path], metrics: Mapping[str, float]) -> None:
        logger.info("checkpoint saved: %s (%s)", path, trainer.best_summary())

    def on_exception(self, trainer: "BaseTrainer", exc: BaseException) -> None:
        logger.exception("training failed: %s", exc)

    def on_train_end(self, trainer: "BaseTrainer", result: Mapping[str, Any]) -> None:
        logger.info("training completed: %s", result)

class EarlyStoppingCallback:
    def __init__(self, cfg: EarlyStoppingConfig) -> None:
        self.cfg = cfg
        self.best: Optional[float] = None
        self.bad_epochs = 0
        self.cooldown_left = 0

    def _is_better(self, value: float) -> bool:
        if self.best is None:
            return True
        if self.cfg.mode == "min":
            return value < self.best - self.cfg.min_delta
        return value > self.best + self.cfg.min_delta

    def on_train_start(self, trainer: "BaseTrainer") -> None: ...
    def on_epoch_start(self, trainer: "BaseTrainer", epoch: int) -> None: ...
    def on_after_train_step(self, trainer: "BaseTrainer", step: int, metrics: Mapping[str, float]) -> None: ...

    def on_validation_end(self, trainer: "BaseTrainer", epoch: int, metrics: Mapping[str, float]) -> None:
        metric = self.cfg.metric
        if not metric or metric not in metrics:
            return
        val = float(metrics[metric])
        if self._is_better(val):
            self.best = val
            self.bad_epochs = 0
            self.cooldown_left = self.cfg.cooldown_epochs
        else:
            if self.cooldown_left > 0:
                self.cooldown_left -= 1
            else:
                self.bad_epochs += 1
                if self.bad_epochs > self.cfg.patience:
                    trainer.request_stop(reason=f"early_stopping({metric}) best={self.best} last={val}")

    def on_checkpoint(self, trainer: "BaseTrainer", path: Union[str, Path], metrics: Mapping[str, float]) -> None: ...
    def on_exception(self, trainer: "BaseTrainer", exc: BaseException) -> None: ...
    def on_train_end(self, trainer: "BaseTrainer", result: Mapping[str, Any]) -> None: ...

# =========================
# Базовый тренер
# =========================

class BaseTrainer(abc.ABC):
    def __init__(
        self,
        cfg: TrainingConfig,
        device: DeviceConfig | None = None,
        optimizer: OptimConfig | None = None,
        scheduler: SchedulerConfig | None = None,
        checkpoint: CheckpointConfig | None = None,
        early_stopping: EarlyStoppingConfig | None = None,
        emitter: Optional[EventEmitter] = None,
        checkpoint_io: Optional[CheckpointIO] = None,
        callbacks: Optional[List[Callback]] = None,
        env: str = os.getenv("ENV", "dev"),
        producer: str = os.getenv("SERVICE_NAME", "neuroforge-core"),
        dataset_id: Optional[str] = None,
        dataset_version: Optional[str] = None,
        model_id: Optional[str] = None,
        model_version: Optional[str] = None,
        correlation_id: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> None:
        self.cfg = cfg
        self.dev_cfg = device or DeviceConfig()
        self.opt_cfg = optimizer or OptimConfig()
        self.sched_cfg = scheduler or SchedulerConfig()
        self.ckpt_cfg = checkpoint or CheckpointConfig()
        self.es_cfg = early_stopping or EarlyStoppingConfig()
        self.emitter = emitter or NullEmitter()
        self.ckpt_io = checkpoint_io or LocalCheckpointIO()
        self.callbacks = callbacks or [LoggingCallback(), EarlyStoppingCallback(self.es_cfg)]
        self.env = env
        self.producer = producer
        self.dataset_id = dataset_id
        self.dataset_version = dataset_version
        self.model_id = model_id
        self.model_version = model_version
        self.correlation_id = correlation_id
        self.run_id = run_id or _uuid()
        self._should_stop = False
        self._stop_reason = ""
        self._best_metric_value: Optional[float] = None
        self._best_metric_step: Optional[int] = None
        self._best_ckpt_path: Optional[Path] = None
        self._global_step = 0
        self._epoch = 0
        self._start_time = time.time()

        # SIGTERM/SIGINT мягкое завершение
        self._install_signal_handlers()

    # --------- жизненный цикл ---------

    def _install_signal_handlers(self) -> None:
        def _handler(signum, frame):  # type: ignore[no-untyped-def]
            logger.warning("signal %s caught, requesting graceful stop...", signum)
            self.request_stop(reason=f"signal_{signum}")
        with contextlib.suppress(Exception):
            signal.signal(signal.SIGTERM, _handler)
            signal.signal(signal.SIGINT, _handler)

    def request_stop(self, reason: str) -> None:
        self._should_stop = True
        self._stop_reason = reason

    def best_summary(self) -> str:
        if self._best_metric_value is None:
            return "no_best_metric"
        return f"{self.ckpt_cfg.save_best_metric}={self._best_metric_value:.6f}@{self._best_metric_step}"

    # --------- абстрактная часть (реализуется бэкендом) ---------

    @abc.abstractmethod
    def setup(self) -> None:
        """Подготовка модели/данных/оптимизатора."""

    @abc.abstractmethod
    def train_step(self, batch: Any, step: int, epoch: int) -> Mapping[str, float]:
        """Один тренировочный шаг. Возвращает метрики шага."""

    @abc.abstractmethod
    def train_dataloader(self) -> Iterable[Any]:
        """Итератор по тренировочным батчам."""

    @abc.abstractmethod
    def validate(self) -> Mapping[str, float]:
        """Валидация; возвращает метрики валидации."""

    @abc.abstractmethod
    def save_state(self) -> Mapping[str, Any]:
        """Снимок состояния для чекпоинта."""

    @abc.abstractmethod
    def load_state(self, state: Mapping[str, Any]) -> None:
        """Восстановление состояния из чекпоинта."""

    # --------- служебное ---------

    def _emit(self, type_: str, payload: Mapping[str, Any]) -> None:
        evt = build_training_event(
            type_=type_,
            run_id=self.run_id,
            env=self.env,
            producer=self.producer,
            source=self.__class__.__name__,
            payload=payload,
            dataset_id=self.dataset_id,
            dataset_version=self.dataset_version,
            model_id=self.model_id,
            model_version=self.model_version,
            correlation_id=self.correlation_id,
        )
        self.emitter.emit(evt)

    def _maybe_mixed_precision(self) -> Optional[str]:
        if self.cfg.mixed_precision is not None:
            return self.cfg.mixed_precision
        # авто-выбор
        try:
            import torch  # type: ignore
            if torch.cuda.is_available():  # type: ignore
                if self.dev_cfg.allow_bfloat16 and hasattr(torch.cuda, "is_bf16_supported") and torch.cuda.is_bf16_supported():  # type: ignore
                    return "bf16"
                if self.dev_cfg.allow_fp16:
                    return "fp16"
        except Exception:
            pass
        return None

    # --------- основной цикл ---------

    def fit(self) -> Mapping[str, Any]:
        start_ts = time.time()
        set_global_seed(self.cfg.seed)
        self.setup()

        for cb in self.callbacks:
            with contextlib.suppress(Exception):
                cb.on_train_start(self)

        self._emit("TRAINING_STARTED", {
            "hyperparams": {**dataclasses.asdict(self.opt_cfg), **dataclasses.asdict(self.cfg)},
            "resources_planned": {},
            "estimated_duration_seconds": None,
        })

        timeout = self.cfg.timeout_seconds
        last_val_metrics: Mapping[str, float] = {}
        steps_in_epoch = 0

        try:
            for epoch in range(1, self.cfg.epochs + 1):
                if self._should_stop:
                    break
                self._epoch = epoch
                for cb in self.callbacks:
                    with contextlib.suppress(Exception):
                        cb.on_epoch_start(self, epoch)

                for batch in self.train_dataloader():
                    if self._should_stop:
                        break
                    self._global_step += 1
                    steps_in_epoch += 1

                    step_metrics = dict(self.train_step(batch, self._global_step, epoch))

                    for cb in self.callbacks:
                        with contextlib.suppress(Exception):
                            cb.on_after_train_step(self, self._global_step, step_metrics)

                    if self.cfg.max_steps and self._global_step >= self.cfg.max_steps:
                        self.request_stop(reason="max_steps")

                    if timeout and (time.time() - start_ts) > timeout:
                        self.request_stop(reason="timeout")

                    # периодическая валидация по шагам
                    if self.cfg.val_every_n_steps and (self._global_step % self.cfg.val_every_n_steps == 0):
                        last_val_metrics = self.validate()
                        for cb in self.callbacks:
                            with contextlib.suppress(Exception):
                                cb.on_validation_end(self, epoch, last_val_metrics)
                        self._handle_checkpoint(last_val_metrics)

                # валидация по эпохам
                if not self.cfg.val_every_n_steps and not self._should_stop:
                    last_val_metrics = self.validate()
                    for cb in self.callbacks:
                        with contextlib.suppress(Exception):
                            cb.on_validation_end(self, epoch, last_val_metrics)
                    self._handle_checkpoint(last_val_metrics)

                if self._should_stop:
                    logger.info("stopping requested: %s", self._stop_reason)
                    break

            result = {
                "run_id": self.run_id,
                "status": "succeeded" if not self._should_stop or self._stop_reason in ("max_steps",) else "stopped",
                "best": {
                    "metric": self.ckpt_cfg.save_best_metric,
                    "value": self._best_metric_value,
                    "step": self._best_metric_step,
                    "path": str(self._best_ckpt_path) if self._best_ckpt_path else None,
                },
                "duration_seconds": round(time.time() - self._start_time, 3),
                "final_val_metrics": last_val_metrics,
            }
            self._emit("TRAINING_COMPLETED", {
                "final_metrics": last_val_metrics,
                "model_uri": self._best_ckpt_path.as_posix() if self._best_ckpt_path else None,
                "artifacts": [],
            })
            for cb in self.callbacks:
                with contextlib.suppress(Exception):
                    cb.on_train_end(self, result)
            return result

        except BaseException as e:
            self._emit("TRAINING_FAILED", {
                "error_code": e.__class__.__name__,
                "error_message": str(e),
                "retryable": False,
                "stacktrace": None,
            })
            for cb in self.callbacks:
                with contextlib.suppress(Exception):
                    cb.on_exception(self, e)
            raise

    # --------- чекпоинтинг ---------

    def _handle_checkpoint(self, metrics: Mapping[str, float]) -> None:
        save = False
        path = self._ckpt_path(f"epoch{self._epoch}_step{self._global_step}.ckpt")

        metric_name = self.ckpt_cfg.save_best_metric
        if metric_name and metric_name in metrics:
            val = float(metrics[metric_name])
            if self._best_metric_value is None:
                save = True
            else:
                better = (val < self._best_metric_value) if self.ckpt_cfg.mode == "min" else (val > self._best_metric_value)
                if better:
                    save = True
            if save:
                self._best_metric_value = val
                self._best_metric_step = self._global_step
                self._best_ckpt_path = path

        if self.ckpt_cfg.every_n_epochs and (self._epoch % self.ckpt_cfg.every_n_epochs == 0):
            save = True
        if self.ckpt_cfg.every_n_steps and (self._global_step % self.ckpt_cfg.every_n_steps == 0):
            save = True

        if not save:
            return

        state = self.save_state()
        payload = {
            "meta": {
                "run_id": self.run_id,
                "epoch": self._epoch,
                "step": self._global_step,
                "created_at": utc_now_iso(),
                "val_metrics": dict(metrics),
            },
            "state": state,
        }
        self.ckpt_io.save(path, payload)
        self._rotate_checkpoints()

        for cb in self.callbacks:
            with contextlib.suppress(Exception):
                cb.on_checkpoint(self, path, metrics)

        self._emit("CHECKPOINT_SAVED", {
            "step": self._global_step,
            "epoch": self._epoch,
            "checkpoint_uri": str(path),
            "size_bytes": Path(path).stat().st_size if Path(path).exists() else 0,
            "metrics": dict(metrics),
            "artifacts": [],
        })

    def _rotate_checkpoints(self) -> None:
        keep = max(1, self.ckpt_cfg.keep_last)
        ckpt_dir = Path(self.ckpt_cfg.dir)
        if not ckpt_dir.exists():
            return
        files = sorted(ckpt_dir.glob("*.ckpt"), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in files[keep:]:
            with contextlib.suppress(Exception):
                old.unlink()

    def _ckpt_path(self, name: str) -> Path:
        p = Path(self.ckpt_cfg.dir) / f"{self.ckpt_cfg.artifact_prefix}-{name}"
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

# =========================
# PyTorch-реализация (опционально)
# =========================

class TorchTrainer(BaseTrainer):
    """
    Реализация для PyTorch. Требует torch. Пример инициализации:
      trainer = TorchTrainer(cfg, model=model, train_loader=..., val_fn=..., loss_fn=..., optimizer_ctor=..., scheduler_ctor=...)
    """

    def __init__(
        self,
        cfg: TrainingConfig,
        *,
        model: Any,
        train_loader: Iterable[Any],
        val_fn: Optional[CallableVal] = None,
        loss_fn: Optional[Any] = None,
        optimizer_ctor: Optional[Any] = None,
        scheduler_ctor: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(cfg, **kwargs)
        try:
            import torch  # type: ignore
            self.torch = torch
        except Exception as e:  # pragma: no cover
            raise RuntimeError("PyTorch не установлен") from e

        self.model = model
        self.train_loader = train_loader
        self.loss_fn = loss_fn
        self.optimizer_ctor = optimizer_ctor
        self.scheduler_ctor = scheduler_ctor
        self.optimizer = None
        self.scheduler = None
        self.autocast_dtype = None
        self.scaler = None

    def setup(self) -> None:
        torch = self.torch
        device = self._select_device()
        self.model.to(device)

        if self.optimizer_ctor:
            self.optimizer = self.optimizer_ctor(self.model.parameters())
        else:
            self.optimizer = torch.optim.AdamW(self.model.parameters(), lr=self.opt_cfg.lr, betas=self.opt_cfg.betas, eps=self.opt_cfg.eps, weight_decay=self.opt_cfg.weight_decay)

        if self.scheduler_ctor:
            self.scheduler = self.scheduler_ctor(self.optimizer)

        mp = self._maybe_mixed_precision()
        if mp == "bf16":
            self.autocast_dtype = torch.bfloat16
        elif mp == "fp16":
            self.autocast_dtype = torch.float16
        else:
            self.autocast_dtype = None
        if self.autocast_dtype == torch.float16:
            self.scaler = torch.cuda.amp.GradScaler(enabled=True) if torch.cuda.is_available() else None  # type: ignore

        self._emit("TRAINING_PROGRESS", {"step": 0, "epoch": 0, "metrics": {"params": float(self._param_count())}})

    def _param_count(self) -> int:
        return sum(p.numel() for p in self.model.parameters())

    def _select_device(self) -> Any:
        torch = self.torch
        if self.dev_cfg.prefer_gpu and torch.cuda.is_available():
            return torch.device("cuda")
        return torch.device("cpu")

    def train_dataloader(self) -> Iterable[Any]:
        return self.train_loader

    def train_step(self, batch: Any, step: int, epoch: int) -> Mapping[str, float]:
        torch = self.torch
        device = self._select_device()
        self.model.train()

        if isinstance(batch, (list, tuple)) and len(batch) == 2:
            x, y = batch
        else:
            # ожидаем, что бэкенд перегрузит при другом формате
            x, y = batch[0], batch[1]  # type: ignore

        x = _move_to_device(x, device)
        y = _move_to_device(y, device)

        self.optimizer.zero_grad(set_to_none=True)  # type: ignore

        if self.autocast_dtype is not None:
            with torch.autocast(device_type=device.type, dtype=self.autocast_dtype):  # type: ignore
                y_pred = self.model(x)
                loss = self._loss(y_pred, y)
            if self.scaler:
                self.scaler.scale(loss).backward()
                if self.cfg.clip_grad_norm:
                    self.scaler.unscale_(self.optimizer)  # type: ignore
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.cfg.clip_grad_norm)
                self.scaler.step(self.optimizer)  # type: ignore
                self.scaler.update()
            else:
                loss.backward()
                if self.cfg.clip_grad_norm:
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.cfg.clip_grad_norm)
                self.optimizer.step()  # type: ignore
        else:
            y_pred = self.model(x)
            loss = self._loss(y_pred, y)
            loss.backward()
            if self.cfg.clip_grad_norm:
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.cfg.clip_grad_norm)
            self.optimizer.step()  # type: ignore

        if self.scheduler:
            with contextlib.suppress(Exception):
                self.scheduler.step()

        metrics = {"loss": float(loss.detach().item())}
        if step % max(1, self.cfg.log_every_n_steps // 2) == 0:
            self._emit("TRAINING_PROGRESS", {
                "step": step,
                "epoch": epoch,
                "metrics": metrics,
                "samples_processed": None,
                "eta_seconds": None,
                "resource_usage": None,
            })
        return metrics

    def _loss(self, y_pred: Any, y_true: Any) -> Any:
        if self.loss_fn is not None:
            return self.loss_fn(y_pred, y_true)
        # по умолчанию — MSE
        return self.torch.nn.functional.mse_loss(y_pred, y_true)

    def validate(self) -> Mapping[str, float]:
        torch = self.torch
        device = self._select_device()
        self.model.eval()
        loss_sum = 0.0
        n = 0
        with torch.no_grad():
            for batch in getattr(self, "val_loader", []):  # type: ignore[attr-defined]
                if isinstance(batch, (list, tuple)) and len(batch) == 2:
                    x, y = batch
                else:
                    x, y = batch[0], batch[1]  # type: ignore
                x = _move_to_device(x, device)
                y = _move_to_device(y, device)
                y_pred = self.model(x)
                loss = self._loss(y_pred, y)
                loss_sum += float(loss.detach().item())
                n += 1
        val_loss = loss_sum / max(1, n)
        return {"val_loss": val_loss}

    def save_state(self) -> Mapping[str, Any]:
        torch = self.torch
        device = self._select_device()
        state = {
            "model": self.model.state_dict(),
            "optimizer": self.optimizer.state_dict() if self.optimizer else None,  # type: ignore
            "scheduler": self.scheduler.state_dict() if self.scheduler else None,  # type: ignore
            "meta": {
                "device": str(device),
                "epoch": self._epoch,
                "step": self._global_step,
                "time": utc_now_iso(),
            },
        }
        # модель может быть на GPU; сохраняем CPU-совместимо
        # (json-чекпоинт хранит тензоры не напрямую; ответственность на внешнем слое)
        # Для промышленного варианта можно реализовать TorchCheckpointIO (pt-файл).
        return state

    def load_state(self, state: Mapping[str, Any]) -> None:
        torch = self.torch
        self.model.load_state_dict(state["model"])
        if self.optimizer and state.get("optimizer"):
            self.optimizer.load_state_dict(state["optimizer"])  # type: ignore
        if self.scheduler and state.get("scheduler"):
            self.scheduler.load_state_dict(state["scheduler"])  # type: ignore

# =========================
# Вспомогательное
# =========================

from typing import Callable as _Callable  # noqa
CallableVal = _Callable[[], Mapping[str, float]]

def _move_to_device(obj: Any, device: Any) -> Any:
    try:
        import torch  # type: ignore
    except Exception:
        return obj
    if hasattr(obj, "to"):
        return obj.to(device)
    if isinstance(obj, (list, tuple)):
        return type(obj)(_move_to_device(o, device) for o in obj)
    if isinstance(obj, dict):
        return {k: _move_to_device(v, device) for k, v in obj.items()}
    return obj

# =========================
# Резюме модуля
# =========================
__all__ = [
    # конфиги
    "DeviceConfig", "OptimConfig", "SchedulerConfig", "CheckpointConfig", "EarlyStoppingConfig", "TrainingConfig",
    # события/эмиттеры
    "EventEmitter", "NullEmitter", "HttpEmitter", "KafkaEmitter", "build_training_event",
    # чекпоинты
    "CheckpointIO", "LocalCheckpointIO",
    # колбэки
    "Callback", "LoggingCallback", "EarlyStoppingCallback",
    # тренеры
    "BaseTrainer", "TorchTrainer",
    # утилиты
    "set_global_seed",
]
