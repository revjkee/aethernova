import os
import subprocess
from pathlib import Path

class PayloadLoader:
    """
    Менеджер загрузки и запуска пользовательских payloads.
    Поддерживает скрипты и бинарники.
    """

    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir) if base_dir else Path(__file__).parent
        self.scripts_dir = self.base_dir / 'scripts'
        self.binaries_dir = self.base_dir / 'binaries'

    def list_payloads(self):
        """Возвращает структуру доступных payloads"""
        payloads = {
            'scripts': {},
            'binaries': {}
        }

        for lang_dir in self.scripts_dir.iterdir():
            if lang_dir.is_dir():
                payloads['scripts'][lang_dir.name] = [f.name for f in lang_dir.iterdir() if f.is_file()]

        for platform_dir in self.binaries_dir.iterdir():
            if platform_dir.is_dir():
                payloads['binaries'][platform_dir.name] = [f.name for f in platform_dir.iterdir() if f.is_file()]

        return payloads

    def run_script(self, script_path: Path):
        """Запуск скрипта с определением интерпретатора по расширению"""
        ext = script_path.suffix.lower()
        if ext == '.py':
            cmd = ['python3', str(script_path)]
        elif ext == '.sh':
            cmd = ['bash', str(script_path)]
        elif ext == '.ps1':
            cmd = ['pwsh', str(script_path)]
        else:
            raise RuntimeError(f'Неизвестный тип скрипта: {ext}')
        return subprocess.run(cmd, capture_output=True, text=True)

    def run_binary(self, binary_path: Path):
        """Запуск бинарника напрямую"""
        if not os.access(binary_path, os.X_OK):
            # Делает файл исполняемым
            binary_path.chmod(binary_path.stat().st_mode | 0o111)
        return subprocess.run([str(binary_path)], capture_output=True, text=True)

    def run_payload(self, category: str, subcategory: str, name: str):
        """
        Запуск payload
        category: 'scripts' или 'binaries'
        subcategory: язык скрипта или платформа бинарника
        name: имя файла
        """
        if category == 'scripts':
            path = self.scripts_dir / subcategory / name
            if not path.exists():
                raise FileNotFoundError(f'Скрипт не найден: {path}')
            result = self.run_script(path)
        elif category == 'binaries':
            path = self.binaries_dir / subcategory / name
            if not path.exists():
                raise FileNotFoundError(f'Бинарник не найден: {path}')
            result = self.run_binary(path)
        else:
            raise ValueError(f'Неизвестная категория: {category}')
        return result

if __name__ == "__main__":
    loader = PayloadLoader()
    payloads = loader.list_payloads()
    print("Доступные payloads:")
    for cat, subs in payloads.items():
        print(f"{cat}:")
        for subcat, files in subs.items():
            print(f"  {subcat}: {files}")
