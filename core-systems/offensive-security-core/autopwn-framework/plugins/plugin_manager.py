# autopwn-framework/plugins/plugin_manager.py
"""
Модуль управления внешними расширениями (плагинами).

Отвечает за загрузку, активацию, деактивацию и управление жизненным циклом плагинов.
Обеспечивает изоляцию и безопасное подключение стороннего функционала.
"""

import importlib
import os
import sys
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class PluginManager:
    def __init__(self, plugins_dir: str):
        """
        Инициализация менеджера плагинов.

        :param plugins_dir: Путь к директории с плагинами
        """
        self.plugins_dir = plugins_dir
        self.plugins: Dict[str, Any] = {}

        if not os.path.exists(self.plugins_dir):
            logger.warning(f"Папка плагинов не найдена: {self.plugins_dir}")
            os.makedirs(self.plugins_dir)

        sys.path.insert(0, self.plugins_dir)

    def load_plugins(self):
        """
        Загрузить все плагины из директории plugins_dir.
        Плагины — это модули Python с методом init_plugin().
        """
        for filename in os.listdir(self.plugins_dir):
            if filename.endswith(".py") and not filename.startswith("_"):
                plugin_name = filename[:-3]
                try:
                    module = importlib.import_module(plugin_name)
                    if hasattr(module, "init_plugin") and callable(module.init_plugin):
                        self.plugins[plugin_name] = module
                        module.init_plugin()
                        logger.info(f"Плагин загружен и инициализирован: {plugin_name}")
                    else:
                        logger.warning(f"В плагине {plugin_name} отсутствует метод init_plugin()")
                except Exception as e:
                    logger.error(f"Ошибка загрузки плагина {plugin_name}: {e}")

    def activate_plugin(self, plugin_name: str):
        """
        Активировать плагин, вызвав метод activate(), если он есть.
        """
        plugin = self.plugins.get(plugin_name)
        if plugin and hasattr(plugin, "activate") and callable(plugin.activate):
            try:
                plugin.activate()
                logger.info(f"Плагин активирован: {plugin_name}")
            except Exception as e:
                logger.error(f"Ошибка активации плагина {plugin_name}: {e}")

    def deactivate_plugin(self, plugin_name: str):
        """
        Деактивировать плагин, вызвав метод deactivate(), если он есть.
        """
        plugin = self.plugins.get(plugin_name)
        if plugin and hasattr(plugin, "deactivate") and callable(plugin.deactivate):
            try:
                plugin.deactivate()
                logger.info(f"Плагин деактивирован: {plugin_name}")
            except Exception as e:
                logger.error(f"Ошибка деактивации плагина {plugin_name}: {e}")

    def unload_plugin(self, plugin_name: str):
        """
        Выгрузить плагин из менеджера.
        """
        if plugin_name in self.plugins:
            self.deactivate_plugin(plugin_name)
            del self.plugins[plugin_name]
            logger.info(f"Плагин выгружен: {plugin_name}")

    def list_plugins(self):
        """
        Вернуть список всех загруженных плагинов.
        """
        return list(self.plugins.keys())
