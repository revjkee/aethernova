"""
Metrics Collection Module
Сбор метрик из различных источников для анализа
"""

import logging
import asyncio
import psutil
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from enum import Enum

logger = logging.getLogger("predictive-maintenance.metrics")


class MetricType(str, Enum):
    """Типы метрик"""
    SYSTEM = "system"  # CPU, память, диск
    APPLICATION = "application"  # Специфичные для приложения
    NETWORK = "network"  # Сетевые метрики
    DATABASE = "database"  # Метрики БД
    CUSTOM = "custom"  # Пользовательские


@dataclass
class Metric:
    """Представление метрики"""
    name: str
    value: float
    unit: str
    metric_type: MetricType
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразование в словарь"""
        return {
            "name": self.name,
            "value": self.value,
            "unit": self.unit,
            "type": self.metric_type.value,
            "timestamp": self.timestamp.isoformat(),
            "labels": self.labels,
            "metadata": self.metadata
        }


class MetricsCollector:
    """
    Сборщик метрик из различных источников
    
    Поддерживаемые источники:
    - System metrics (psutil)
    - Application metrics (custom collectors)
    - Network metrics
    - Database metrics
    - External APIs
    """
    
    def __init__(
        self,
        collection_interval: float = 60.0,
        retention_period: int = 86400,  # 24 часа в секундах
        enable_system_metrics: bool = True,
        enable_network_metrics: bool = True
    ):
        self.collection_interval = collection_interval
        self.retention_period = retention_period
        self.enable_system_metrics = enable_system_metrics
        self.enable_network_metrics = enable_network_metrics
        
        # Хранилище метрик (в памяти)
        self.metrics_storage: Dict[str, List[Metric]] = defaultdict(list)
        
        # Пользовательские коллекторы
        self.custom_collectors: Dict[str, Callable] = {}
        
        # Статус сбора
        self.is_collecting = False
        self._collection_task: Optional[asyncio.Task] = None
        
        logger.info(
            f"MetricsCollector initialized: "
            f"interval={collection_interval}s, "
            f"retention={retention_period}s"
        )
    
    async def start_collection(self) -> None:
        """Запуск автоматического сбора метрик"""
        if self.is_collecting:
            logger.warning("Collection already running")
            return
        
        self.is_collecting = True
        self._collection_task = asyncio.create_task(self._collection_loop())
        logger.info("Metrics collection started")
    
    async def stop_collection(self) -> None:
        """Остановка сбора метрик"""
        if not self.is_collecting:
            return
        
        self.is_collecting = False
        if self._collection_task:
            self._collection_task.cancel()
            try:
                await self._collection_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Metrics collection stopped")
    
    async def _collection_loop(self) -> None:
        """Основной цикл сбора метрик"""
        while self.is_collecting:
            try:
                await self.collect_all()
                await self._cleanup_old_metrics()
                await asyncio.sleep(self.collection_interval)
            except Exception as e:
                logger.error(f"Error in collection loop: {e}", exc_info=True)
                await asyncio.sleep(5)
    
    async def collect_all(self) -> Dict[str, List[Metric]]:
        """Сбор всех метрик из всех источников"""
        all_metrics = {}
        
        tasks = []
        
        if self.enable_system_metrics:
            tasks.append(("system", self.collect_system_metrics()))
        
        if self.enable_network_metrics:
            tasks.append(("network", self.collect_network_metrics()))
        
        # Пользовательские коллекторы
        for name, collector in self.custom_collectors.items():
            tasks.append((f"custom_{name}", self._run_custom_collector(collector)))
        
        results = await asyncio.gather(*[task[1] for task in tasks], return_exceptions=True)
        
        for (name, _), result in zip(tasks, results):
            if isinstance(result, Exception):
                logger.error(f"Error collecting {name}: {result}")
                continue
            
            all_metrics[name] = result
            
            # Сохранение в хранилище
            for metric in result:
                self.metrics_storage[metric.name].append(metric)
        
        return all_metrics
    
    async def collect_system_metrics(self) -> List[Metric]:
        """Сбор системных метрик (CPU, память, диск)"""
        timestamp = datetime.now()
        metrics = []
        
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=0.1)
            metrics.append(Metric(
                name="system.cpu.usage",
                value=cpu_percent,
                unit="percent",
                metric_type=MetricType.SYSTEM,
                timestamp=timestamp,
                labels={"source": "psutil"}
            ))
            
            # CPU по ядрам
            cpu_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
            for i, usage in enumerate(cpu_per_core):
                metrics.append(Metric(
                    name="system.cpu.core_usage",
                    value=usage,
                    unit="percent",
                    metric_type=MetricType.SYSTEM,
                    timestamp=timestamp,
                    labels={"source": "psutil", "core": str(i)}
                ))
            
            # Память
            memory = psutil.virtual_memory()
            metrics.extend([
                Metric(
                    name="system.memory.usage",
                    value=memory.percent,
                    unit="percent",
                    metric_type=MetricType.SYSTEM,
                    timestamp=timestamp,
                    labels={"source": "psutil"}
                ),
                Metric(
                    name="system.memory.available",
                    value=memory.available / (1024**3),  # GB
                    unit="gigabytes",
                    metric_type=MetricType.SYSTEM,
                    timestamp=timestamp,
                    labels={"source": "psutil"}
                ),
                Metric(
                    name="system.memory.used",
                    value=memory.used / (1024**3),  # GB
                    unit="gigabytes",
                    metric_type=MetricType.SYSTEM,
                    timestamp=timestamp,
                    labels={"source": "psutil"}
                )
            ])
            
            # Диск
            disk = psutil.disk_usage('/')
            metrics.extend([
                Metric(
                    name="system.disk.usage",
                    value=disk.percent,
                    unit="percent",
                    metric_type=MetricType.SYSTEM,
                    timestamp=timestamp,
                    labels={"source": "psutil", "mount": "/"}
                ),
                Metric(
                    name="system.disk.free",
                    value=disk.free / (1024**3),  # GB
                    unit="gigabytes",
                    metric_type=MetricType.SYSTEM,
                    timestamp=timestamp,
                    labels={"source": "psutil", "mount": "/"}
                )
            ])
            
            # I/O диска
            disk_io = psutil.disk_io_counters()
            if disk_io:
                metrics.extend([
                    Metric(
                        name="system.disk.read_bytes",
                        value=disk_io.read_bytes / (1024**2),  # MB
                        unit="megabytes",
                        metric_type=MetricType.SYSTEM,
                        timestamp=timestamp,
                        labels={"source": "psutil"}
                    ),
                    Metric(
                        name="system.disk.write_bytes",
                        value=disk_io.write_bytes / (1024**2),  # MB
                        unit="megabytes",
                        metric_type=MetricType.SYSTEM,
                        timestamp=timestamp,
                        labels={"source": "psutil"}
                    )
                ])
            
            # Процессы
            metrics.append(Metric(
                name="system.processes.count",
                value=len(psutil.pids()),
                unit="count",
                metric_type=MetricType.SYSTEM,
                timestamp=timestamp,
                labels={"source": "psutil"}
            ))
            
            # Load average (только Unix)
            try:
                load_avg = psutil.getloadavg()
                for i, period in enumerate(["1m", "5m", "15m"]):
                    metrics.append(Metric(
                        name="system.load_average",
                        value=load_avg[i],
                        unit="load",
                        metric_type=MetricType.SYSTEM,
                        timestamp=timestamp,
                        labels={"source": "psutil", "period": period}
                    ))
            except (AttributeError, OSError):
                pass  # Not available on this platform
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}", exc_info=True)
        
        return metrics
    
    async def collect_network_metrics(self) -> List[Metric]:
        """Сбор сетевых метрик"""
        timestamp = datetime.now()
        metrics = []
        
        try:
            # Сетевой I/O
            net_io = psutil.net_io_counters()
            metrics.extend([
                Metric(
                    name="network.bytes_sent",
                    value=net_io.bytes_sent / (1024**2),  # MB
                    unit="megabytes",
                    metric_type=MetricType.NETWORK,
                    timestamp=timestamp,
                    labels={"source": "psutil"}
                ),
                Metric(
                    name="network.bytes_received",
                    value=net_io.bytes_recv / (1024**2),  # MB
                    unit="megabytes",
                    metric_type=MetricType.NETWORK,
                    timestamp=timestamp,
                    labels={"source": "psutil"}
                ),
                Metric(
                    name="network.packets_sent",
                    value=net_io.packets_sent,
                    unit="count",
                    metric_type=MetricType.NETWORK,
                    timestamp=timestamp,
                    labels={"source": "psutil"}
                ),
                Metric(
                    name="network.packets_received",
                    value=net_io.packets_recv,
                    unit="count",
                    metric_type=MetricType.NETWORK,
                    timestamp=timestamp,
                    labels={"source": "psutil"}
                ),
                Metric(
                    name="network.errors_in",
                    value=net_io.errin,
                    unit="count",
                    metric_type=MetricType.NETWORK,
                    timestamp=timestamp,
                    labels={"source": "psutil"}
                ),
                Metric(
                    name="network.errors_out",
                    value=net_io.errout,
                    unit="count",
                    metric_type=MetricType.NETWORK,
                    timestamp=timestamp,
                    labels={"source": "psutil"}
                )
            ])
            
            # Соединения
            connections = psutil.net_connections(kind='inet')
            connection_states = defaultdict(int)
            for conn in connections:
                connection_states[conn.status] += 1
            
            for state, count in connection_states.items():
                metrics.append(Metric(
                    name="network.connections",
                    value=count,
                    unit="count",
                    metric_type=MetricType.NETWORK,
                    timestamp=timestamp,
                    labels={"source": "psutil", "state": state}
                ))
            
        except Exception as e:
            logger.error(f"Error collecting network metrics: {e}", exc_info=True)
        
        return metrics
    
    async def collect_database_metrics(
        self,
        db_connector: Optional[Callable] = None
    ) -> List[Metric]:
        """
        Сбор метрик базы данных
        
        Args:
            db_connector: Функция для подключения к БД
        """
        timestamp = datetime.now()
        metrics = []
        
        if not db_connector:
            return metrics
        
        try:
            # Пример сбора метрик из PostgreSQL
            # В production здесь будет реальный запрос к БД
            metrics.extend([
                Metric(
                    name="database.connections.active",
                    value=10,  # Заглушка
                    unit="count",
                    metric_type=MetricType.DATABASE,
                    timestamp=timestamp,
                    labels={"source": "postgres"}
                ),
                Metric(
                    name="database.connections.idle",
                    value=5,  # Заглушка
                    unit="count",
                    metric_type=MetricType.DATABASE,
                    timestamp=timestamp,
                    labels={"source": "postgres"}
                ),
                Metric(
                    name="database.transactions.commits",
                    value=1000,  # Заглушка
                    unit="count",
                    metric_type=MetricType.DATABASE,
                    timestamp=timestamp,
                    labels={"source": "postgres"}
                ),
                Metric(
                    name="database.cache.hit_ratio",
                    value=95.5,  # Заглушка
                    unit="percent",
                    metric_type=MetricType.DATABASE,
                    timestamp=timestamp,
                    labels={"source": "postgres"}
                )
            ])
        except Exception as e:
            logger.error(f"Error collecting database metrics: {e}", exc_info=True)
        
        return metrics
    
    async def _run_custom_collector(
        self,
        collector: Callable
    ) -> List[Metric]:
        """Запуск пользовательского коллектора"""
        try:
            if asyncio.iscoroutinefunction(collector):
                result = await collector()
            else:
                result = collector()
            
            # Преобразование в объекты Metric если нужно
            if not isinstance(result, list):
                result = [result]
            
            metrics = []
            for item in result:
                if isinstance(item, Metric):
                    metrics.append(item)
                elif isinstance(item, dict):
                    # Создание Metric из словаря
                    metrics.append(Metric(
                        name=item.get("name", "custom.metric"),
                        value=item.get("value", 0.0),
                        unit=item.get("unit", "count"),
                        metric_type=MetricType.CUSTOM,
                        timestamp=datetime.now(),
                        labels=item.get("labels", {}),
                        metadata=item.get("metadata", {})
                    ))
            
            return metrics
        except Exception as e:
            logger.error(f"Error running custom collector: {e}", exc_info=True)
            return []
    
    def register_collector(
        self,
        name: str,
        collector: Callable
    ) -> None:
        """
        Регистрация пользовательского коллектора
        
        Args:
            name: Имя коллектора
            collector: Функция-коллектор (sync или async)
        """
        self.custom_collectors[name] = collector
        logger.info(f"Registered custom collector: {name}")
    
    def unregister_collector(self, name: str) -> None:
        """Удаление коллектора"""
        if name in self.custom_collectors:
            del self.custom_collectors[name]
            logger.info(f"Unregistered collector: {name}")
    
    def get_metrics(
        self,
        metric_name: str,
        limit: Optional[int] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Metric]:
        """
        Получение метрик по имени с фильтрацией
        
        Args:
            metric_name: Имя метрики
            limit: Максимальное количество записей
            start_time: Начало периода
            end_time: Конец периода
        """
        metrics = self.metrics_storage.get(metric_name, [])
        
        # Фильтрация по времени
        if start_time:
            metrics = [m for m in metrics if m.timestamp >= start_time]
        if end_time:
            metrics = [m for m in metrics if m.timestamp <= end_time]
        
        # Ограничение количества
        if limit:
            metrics = metrics[-limit:]
        
        return metrics
    
    def get_latest_metrics(
        self,
        metric_names: Optional[List[str]] = None
    ) -> Dict[str, Metric]:
        """Получение последних значений метрик"""
        result = {}
        
        if metric_names is None:
            metric_names = list(self.metrics_storage.keys())
        
        for name in metric_names:
            metrics = self.metrics_storage.get(name, [])
            if metrics:
                result[name] = metrics[-1]
        
        return result
    
    def get_metric_values(
        self,
        metric_name: str,
        limit: Optional[int] = None
    ) -> List[float]:
        """Получение только значений метрик (для анализа)"""
        metrics = self.get_metrics(metric_name, limit=limit)
        return [m.value for m in metrics]
    
    async def _cleanup_old_metrics(self) -> None:
        """Очистка старых метрик"""
        cutoff_time = datetime.now().timestamp() - self.retention_period
        
        removed_count = 0
        for name in list(self.metrics_storage.keys()):
            original_length = len(self.metrics_storage[name])
            
            self.metrics_storage[name] = [
                m for m in self.metrics_storage[name]
                if m.timestamp.timestamp() >= cutoff_time
            ]
            
            removed = original_length - len(self.metrics_storage[name])
            removed_count += removed
            
            # Удаление пустых списков
            if not self.metrics_storage[name]:
                del self.metrics_storage[name]
        
        if removed_count > 0:
            logger.debug(f"Cleaned up {removed_count} old metrics")
    
    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики коллектора"""
        total_metrics = sum(len(metrics) for metrics in self.metrics_storage.values())
        
        return {
            "is_collecting": self.is_collecting,
            "unique_metrics": len(self.metrics_storage),
            "total_data_points": total_metrics,
            "custom_collectors": len(self.custom_collectors),
            "collection_interval": self.collection_interval,
            "retention_period": self.retention_period
        }
    
    def export_metrics(
        self,
        format: str = "dict"
    ) -> Any:
        """
        Экспорт метрик в различные форматы
        
        Args:
            format: Формат экспорта (dict, prometheus, json)
        """
        if format == "dict":
            return {
                name: [m.to_dict() for m in metrics]
                for name, metrics in self.metrics_storage.items()
            }
        elif format == "prometheus":
            # Формат Prometheus
            lines = []
            for name, metrics in self.metrics_storage.items():
                if metrics:
                    latest = metrics[-1]
                    labels = ",".join([
                        f'{k}="{v}"' for k, v in latest.labels.items()
                    ])
                    lines.append(
                        f"{name}{{{labels}}} {latest.value}"
                    )
            return "\n".join(lines)
        else:
            raise ValueError(f"Unsupported format: {format}")
