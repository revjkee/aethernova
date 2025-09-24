import subprocess
import time
import logging

logger = logging.getLogger("latency_injection")

DEFAULT_INTERFACE = "lo"


def inject_latency(interface: str = DEFAULT_INTERFACE, delay_ms: int = 100, duration: int = 10):
    """
    Инъекция задержки в сетевые пакеты на заданном интерфейсе.
    :param interface: интерфейс (например, eth0)
    :param delay_ms: задержка в миллисекундах
    :param duration: длительность в секундах
    """
    try:
        logger.info(f"[latency_injection] Запуск задержки {delay_ms}ms на интерфейсе {interface} на {duration}с")
        # Добавление задержки
        subprocess.run([
            "tc", "qdisc", "add", "dev", interface, "root", "netem", "delay", f"{delay_ms}ms"
        ], check=True)

        time.sleep(duration)

    except subprocess.CalledProcessError as e:
        logger.error(f"Ошибка при добавлении задержки: {e}")

    finally:
        try:
            # Удаление правила задержки
            subprocess.run([
                "tc", "qdisc", "del", "dev", interface, "root", "netem"
            ], check=True)
            logger.info(f"[latency_injection] Задержка успешно удалена с интерфейса {interface}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Ошибка при удалении задержки: {e}")


def register_event(engine):
    engine.register("latency_injection", inject_latency)
