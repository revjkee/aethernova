# file: security-core/tests/integration/test_mtls_handshake.py
import contextlib
import json
import socket
import ssl
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

import pytest

# Обязательные зависимости для теста
requests = pytest.importorskip("requests")
trustme = pytest.importorskip("trustme")


@pytest.fixture(scope="session")
def pki(tmp_path_factory):
    """
    Генерирует PKI для тестов:
      - ca_main        : корень, которым подписаны сервер и валидный клиент
      - ca_other       : другой корень для невалидного клиента
      - server_cert    : серверный сертификат (SAN: DNS:localhost)
      - client_good    : клиентский сертификат от ca_main
      - client_bad     : клиентский сертификат от ca_other
    Возвращает пути к PEM-файлам.
    """
    workdir = tmp_path_factory.mktemp("pki")

    ca_main = trustme.CA()
    ca_other = trustme.CA()

    # Серверный сертификат только для "localhost" — позволит проверять SNI/SAN.
    server_cert = ca_main.issue_cert(u"localhost")

    # Клиентские сертификаты (для mTLS достаточно обычного выпускного; многие серверы EKU не проверяют)
    client_good = ca_main.issue_cert(u"client-good")
    client_bad = ca_other.issue_cert(u"client-bad")

    # Записываем в файлы (requests работает с путями)
    server_cert_file = workdir / "server_cert.pem"
    server_key_file = workdir / "server_key.pem"
    client_good_cert_file = workdir / "client_good_cert.pem"
    client_good_key_file = workdir / "client_good_key.pem"
    client_bad_cert_file = workdir / "client_bad_cert.pem"
    client_bad_key_file = workdir / "client_bad_key.pem"
    ca_main_file = workdir / "ca_main.pem"
    ca_other_file = workdir / "ca_other.pem"

    server_cert.cert_chain_pems[0].write_to_path(server_cert_file)
    server_cert.private_key_pem.write_to_path(server_key_file)

    client_good.cert_chain_pems[0].write_to_path(client_good_cert_file)
    client_good.private_key_pem.write_to_path(client_good_key_file)

    client_bad.cert_chain_pems[0].write_to_path(client_bad_cert_file)
    client_bad.private_key_pem.write_to_path(client_bad_key_file)

    ca_main.cert_pem.write_to_path(ca_main_file)
    ca_other.cert_pem.write_to_path(ca_other_file)

    return {
        "server_cert": server_cert_file,
        "server_key": server_key_file,
        "client_good_cert": client_good_cert_file,
        "client_good_key": client_good_key_file,
        "client_bad_cert": client_bad_cert_file,
        "client_bad_key": client_bad_key_file,
        "ca_main": ca_main_file,
        "ca_other": ca_other_file,
        "ca_main_obj": ca_main,  # пригодится для настройки доверия в SSLContext
    }


class _Handler(BaseHTTPRequestHandler):
    """
    Минимальный обработчик, который возвращает JSON c CN клиента и флагом mTLS.
    До этого момента соединение уже прошло TLS‑рукопожатие.
    """

    server_version = "TestMTLS/1.0"

    def do_GET(self):
        try:
            # self.connection — это ssl.SSLSocket после wrap_socket()
            peercert = {}
            with contextlib.suppress(Exception):
                peercert = self.connection.getpeercert() or {}

            # Попробуем извлечь CN клиента (если есть)
            client_cn = None
            subj = peercert.get("subject", [])
            for item in subj:
                for (k, v) in item:
                    if k.lower() == "commonName".lower():
                        client_cn = v

            body = {
                "ok": True,
                "mtls": bool(peercert),
                "client_cn": client_cn,
                "server_sni": getattr(self.connection, "server_hostname", None),
            }
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            msg = ("error:" + str(e)).encode("utf-8")
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

    # Без шумных логов в stderr
    def log_message(self, format, *args):
        return


def _make_server_ssl_context(pki: dict) -> ssl.SSLContext:
    """
    Создаёт SSLContext для сервера:
      - сертификат сервера
      - требование клиентского сертификата (mTLS)
      - доверие к ca_main (для проверки клиента)
      - TLS 1.2+ и безопасные шифры по умолчанию
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Минимальная версия TLS для прод-профиля
    with contextlib.suppress(AttributeError):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Серверный сертификат
    ctx.load_cert_chain(certfile=str(pki["server_cert"]), keyfile=str(pki["server_key"]))

    # Требуем клиентский сертификат и доверяем ca_main
    ctx.verify_mode = ssl.CERT_REQUIRED
    # trustme.CA также умеет напрямую настраивать доверие, но тут читаем из файла
    ctx.load_verify_locations(cafile=str(pki["ca_main"]))

    # Отключим компрессию (mitigate CRIME/BREACH; обычно уже выключена)
    with contextlib.suppress(AttributeError):
        ctx.options |= ssl.OP_NO_COMPRESSION

    return ctx


@contextlib.contextmanager
def _run_https_server(ssl_context: ssl.SSLContext):
    """
    Поднимает HTTPS сервер на 127.0.0.1:0 и возвращает (base_url, server, thread).
    """
    # Привязываемся к loopback (IPv4). Для SNI/hostname‑проверки будем ходить на https://localhost:port
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)

    # Оборачиваем сокет в SSL
    srv.socket = ssl_context.wrap_socket(srv.socket, server_side=True)

    host, port = srv.server_address
    base_url = f"https://localhost:{port}"  # важно: hostname=localhost совпадает с SAN у сервера

    th = threading.Thread(target=srv.serve_forever, name="mtls-test-httpd", daemon=True)
    th.start()
    try:
        # Небольшая пауза чтобы сокет начал слушать
        time.sleep(0.05)
        yield base_url, srv, th
    finally:
        with contextlib.suppress(Exception):
            srv.shutdown()
        with contextlib.suppress(Exception):
            srv.server_close()
        th.join(timeout=3.0)


@pytest.fixture(scope="function")
def mtls_server(pki):
    """
    Фикстура: запускает сервер с mTLS и отдаёт base_url и полезные пути к файлам.
    """
    ctx = _make_server_ssl_context(pki)
    with _run_https_server(ctx) as (base_url, srv, th):
        yield {
            "base_url": base_url,
            "server": srv,
            "thread": th,
            "pki": pki,
        }


# -----------------------------
# ТЕСТЫ
# -----------------------------

def test_mtls_success(mtls_server):
    """
    Успешное рукопожатие mTLS: верный CA у клиента, валидный клиентский сертификат.
    Ожидаем HTTP 200 и mtls=true.
    """
    base = mtls_server["base_url"]
    pki = mtls_server["pki"]

    resp = requests.get(
        base + "/",
        verify=str(pki["ca_main"]),  # доверяем серверу
        cert=(str(pki["client_good_cert"]), str(pki["client_good_key"])),  # предъявляем клиентский сертификат
        timeout=5,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["mtls"] is True
    assert data["client_cn"] == "client-good"


def test_mtls_no_client_cert_fails(mtls_server):
    """
    Без клиентского сертификата сервер должен разорвать TLS-рукопожатие (verify_mode=CERT_REQUIRED).
    Ожидаем исключение SSL на стороне клиента ещё до HTTP-уровня.
    """
    base = mtls_server["base_url"]
    pki = mtls_server["pki"]

    with pytest.raises((requests.exceptions.SSLError, requests.exceptions.ConnectionError)):
        requests.get(
            base + "/",
            verify=str(pki["ca_main"]),
            timeout=5,
        )


def test_mtls_wrong_client_ca_rejected(mtls_server):
    """
    Клиентский сертификат подписан чужим CA (не ca_main). Сервер его не доверяет.
    Ожидаем отказ на уровне TLS.
    """
    base = mtls_server["base_url"]
    pki = mtls_server["pki"]

    with pytest.raises((requests.exceptions.SSLError, requests.exceptions.ConnectionError)):
        requests.get(
            base + "/",
            verify=str(pki["ca_main"]),  # сервер всё равно доверен
            cert=(str(pki["client_bad_cert"]), str(pki["client_bad_key"])),  # но клиентский — от другого CA
            timeout=5,
        )


def test_hostname_mismatch_rejected(mtls_server):
    """
    Несовпадение имени хоста: серверный сертификат выписан на 'localhost',
    попытка подключения по IP 127.0.0.1 должна завершиться ошибкой проверки хоста.
    """
    # Собираем базовый URL с IP вместо имени
    srv = mtls_server["server"]
    port = srv.server_address[1]
    ip_url = f"https://127.0.0.1:{port}/"

    pki = mtls_server["pki"]

    with pytest.raises((requests.exceptions.SSLError, requests.exceptions.ConnectionError)):
        requests.get(
            ip_url,
            verify=str(pki["ca_main"]),
            cert=(str(pki["client_good_cert"]), str(pki["client_good_key"])),
            timeout=5,
        )
