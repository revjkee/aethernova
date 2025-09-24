# Configuration file for the Sphinx documentation builder.

import os
import sys
from datetime import datetime

# Добавляем корень проекта в sys.path для автодокументации
sys.path.insert(0, os.path.abspath('..'))

# -- Project information -----------------------------------------------------

project = 'TeslaAI Genesis 2.0'
author = 'TeslaAI Team'
copyright = f'{datetime.now().year}, TeslaAI Team'
release = '2.0.0'

# -- General configuration ---------------------------------------------------

extensions = [
    'sphinx.ext.autodoc',        # Автоматическая документация из docstring
    'sphinx.ext.napoleon',       # Поддержка Google и NumPy стиля docstring
    'sphinx.ext.viewcode',       # Ссылка на исходный код
    'sphinx.ext.todo',           # Поддержка TODO в документации
    'sphinx.ext.coverage',       # Отчеты покрытия документации
]

templates_path = ['_templates']

exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------

html_theme = 'sphinx_rtd_theme'

html_static_path = ['_static']

# Настройка todo
todo_include_todos = True
