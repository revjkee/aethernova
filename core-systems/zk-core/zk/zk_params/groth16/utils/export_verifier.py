import json
import os

def export_verifier(zkey_path: str, output_path: str) -> None:
    """
    Экспортирует публичный ключ и проверочные данные из zkey файла в JSON формат.

    :param zkey_path: путь к .zkey файлу с trusted setup
    :param output_path: путь для сохранения экспортированного JSON файла
    """
    if not os.path.exists(zkey_path):
        raise FileNotFoundError(f"Файл {zkey_path} не найден")

    # Загрузка данных .zkey
    with open(zkey_path, 'rb') as f:
        zkey_data = f.read()

    # Парсинг .zkey и извлечение verifier данных
    # В реальном сценарии используется специализированная библиотека, здесь пример-заглушка
    verifier_data = {
        "protocol": "groth16",
        "version": 1,
        "verifier_key": zkey_data.hex()[:1024],  # усечённый пример
    }

    # Сохранение в JSON
    with open(output_path, 'w') as out_file:
        json.dump(verifier_data, out_file, indent=4)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Использование: python export_verifier.py <path_to_zkey> <output_json>")
        sys.exit(1)
    export_verifier(sys.argv[1], sys.argv[2])
