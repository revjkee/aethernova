# /plugins/health_check.py

import importlib
import logging
import pkgutil
import threading
import time

logger = logging.getLogger(__name__)

class PluginHealthCheck:
    def __init__(self, plugin_package):
        self.plugin_package = plugin_package
        self.plugins = {}
        self.lock = threading.Lock()

    def discover_plugins(self):
        """Динамически ищет плагины в указанном пакете."""
        with self.lock:
            self.plugins.clear()
            package = importlib.import_module(self.plugin_package)
            for _, mod_name, is_pkg in pkgutil.iter_modules(package.__path__):
                if not is_pkg:
                    try:
                        full_name = f"{self.plugin_package}.{mod_name}"
                        module = importlib.import_module(full_name)
                        if hasattr(module, "health_check"):
                            self.plugins[mod_name] = module
                            logger.debug(f"Plugin loaded: {full_name}")
                    except Exception as e:
                        logger.error(f"Ошибка загрузки плагина {mod_name}: {e}")

    def check_all(self):
        """Запускает проверку состояния всех найденных плагинов."""
        results = {}
        with self.lock:
            for name, module in self.plugins.items():
                try:
                    # Предполагается, что у каждого плагина есть функция health_check() -> bool
                    status = module.health_check()
                    results[name] = status
                    logger.info(f"Плагин {name} статус: {'OK' if status else 'FAIL'}")
                except Exception as e:
                    logger.error(f"Ошибка проверки плагина {name}: {e}")
                    results[name] = False
        return results

    def start_periodic_check(self, interval_sec=60):
        """Запускает фоновый поток с периодической проверкой плагинов."""
        def run():
            while True:
                self.discover_plugins()
                self.check_all()
                time.sleep(interval_sec)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()

# Инициализация и запуск мониторинга плагинов из пакета 'plugins.available'
health_checker = PluginHealthCheck("plugins.available")
health_checker.start_periodic_check(interval_sec=300)

# Экспорт функции для внешнего вызова
def run_health_check():
    return health_checker.check_all()
