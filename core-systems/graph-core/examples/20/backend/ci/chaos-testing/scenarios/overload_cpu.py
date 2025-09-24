import logging
import multiprocessing
import time
import os

logger = logging.getLogger("chaos_scenario_cpu")
logger.setLevel(logging.INFO)


def cpu_stressor(duration_sec: int = 30, workers: int = 4):
    """
    Запускает многопроцессорную нагрузку на CPU в течение указанного времени.
    """
    logger.info(f"Starting CPU stressor: duration={duration_sec}s, workers={workers}")

    def burn():
        end_time = time.time() + duration_sec
        while time.time() < end_time:
            pass  # активная нагрузка

    processes = []
    for _ in range(workers):
        p = multiprocessing.Process(target=burn)
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

    logger.info("CPU stressor completed")


def execute():
    """
    Выполняет сценарий перегрузки CPU как хаос-инжиниринг эвент.
    """
    logger.info("Executing CPU overload scenario")
    cpu_stressor()
    logger.info("CPU overload scenario finished")


def rollback():
    """
    Откат не предусмотрен, но метод определён для совместимости с ChaosEngine.
    """
    logger.info("Rollback not implemented for CPU overload scenario")


# Сценарий можно регистрировать в ChaosEngine следующим образом:
# engine.register_event(ChaosEvent(name="overload_cpu", action=execute, rollback=rollback))
