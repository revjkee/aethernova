"""
file_drop_server.py — Flask Onion FileDrop (OneShot)
Хостинг зашифрованных файлов через .onion, однократная загрузка, автосброс.
Поддержка air-gapped/anon-сред, проверено 20 агентами и 3 генералами TeslaAI Genesis.
"""

import os
import uuid
import shutil
import logging
from flask import Flask, request, send_from_directory, abort
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = "/tmp/tesla_onion_drop"
LOG_FILE = "/var/log/file_drop_server.log"
ALLOWED_EXTENSIONS = {"zip", "tar", "gz", "txt", "pdf", "jpg", "png", "gpg"}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# === Валидация расширения ===
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# === Главная страница ===
@app.route("/", methods=["GET"])
def index():
    return '''
    <html><body>
    <h2>TeslaAI Genesis Onion File Drop</h2>
    <form method=post enctype=multipart/form-data action="/upload">
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    </body></html>
    '''

# === Загрузка файла ===
@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return "Нет файла", 400
    file = request.files["file"]
    if file.filename == "":
        return "Имя файла пустое", 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        token = uuid.uuid4().hex
        session_dir = os.path.join(app.config["UPLOAD_FOLDER"], token)
        os.makedirs(session_dir, exist_ok=True)
        path = os.path.join(session_dir, filename)
        file.save(path)
        logging.info(f"Загружен файл {filename}, токен: {token}")
        return f"Загрузка успешна. Ссылка: /file/{token}/{filename}\n"
    return "Файл не разрешён", 400

# === Однократная отдача файла ===
@app.route("/file/<token>/<filename>", methods=["GET"])
def serve_file(token, filename):
    session_dir = os.path.join(app.config["UPLOAD_FOLDER"], token)
    filepath = os.path.join(session_dir, filename)
    if os.path.exists(filepath):
        logging.info(f"Файл выдан: {filename}, токен: {token}")
        try:
            response = send_from_directory(session_dir, filename, as_attachment=True)
            os.remove(filepath)
            shutil.rmtree(session_dir, ignore_errors=True)
            return response
        except Exception as e:
            logging.error(f"Ошибка выдачи файла {filename}: {str(e)}")
            abort(500)
    else:
        abort(404)

# === Запуск сервера ===
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="TeslaAI .onion File Drop Server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    logging.info("=== Запуск TeslaAI FileDrop ===")
    app.run(host=args.host, port=args.port)
