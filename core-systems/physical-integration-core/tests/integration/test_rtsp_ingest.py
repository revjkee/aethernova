import json
import os
import socket
import time
from contextlib import closing
from typing import Optional

import pytest

# Ленивая загрузка testcontainers и docker; если недоступны — скипаем все тесты модуля.
tc = None
docker = None
try:
    from testcontainers.core.container import DockerContainer  # type: ignore
    from testcontainers.core.waiting_utils import wait_for_logs  # type: ignore
    tc = True
except Exception:
    tc = False

try:
    import docker as docker_sdk  # type: ignore
    docker = docker_sdk.from_env()
    # Быстрый ping к демону
    docker.ping()
except Exception:
    docker = None


pytestmark = [
    pytest.mark.integration,
    pytest.mark.rtsp,
    pytest.mark.skipif(not tc or docker is None, reason="Docker or testcontainers not available"),
]

# ----------------------------
# Конфигурация через окружение
# ----------------------------
RTSP_IMAGE = os.getenv("RTSP_IMAGE", "bluenviron/mediamtx:latest")  # совместимо с rtsp-simple-server v0.22+
FFMPEG_IMAGE = os.getenv("FFMPEG_IMAGE", "ghcr.io/jrottenberg/ffmpeg:6.0-ubuntu")
RTSP_TCP_PORT = int(os.getenv("RTSP_TCP_PORT", "8554"))
STREAM_NAME = os.getenv("RTSP_STREAM_NAME", "test")
STREAM_URL_TEMPLATE = os.getenv("RTSP_URL_TEMPLATE", "rtsp://{host}:{port}/%s" % STREAM_NAME)
TEST_FPS = float(os.getenv("RTSP_TEST_FPS", "30"))
TEST_DUR_S = float(os.getenv("RTSP_TEST_DUR_S", "5"))
READY_TIMEOUT_S = float(os.getenv("RTSP_READY_TIMEOUT_S", "20"))
PROBE_TIMEOUT_S = float(os.getenv("RTSP_PROBE_TIMEOUT_S", "15"))
PUBLISH_VBITRATE = os.getenv("RTSP_PUBLISH_VBITRATE", "1500k")
PUBLISH_SIZE = os.getenv("RTSP_PUBLISH_SIZE", "1280x720")

# ----------------------------
# Вспомогательные утилиты
# ----------------------------

def _wait_port_open(host: str, port: int, timeout: float) -> None:
    deadline = time.time() + timeout
    last_err: Optional[Exception] = None
    while time.time() < deadline:
        try:
            with closing(socket.create_connection((host, port), timeout=1.0)):
                return
        except Exception as e:
            last_err = e
            time.sleep(0.2)
    raise TimeoutError(f"port {host}:{port} not open within {timeout}s; last_err={last_err}")


def _json_out(container) -> str:
    """Собирает stdout/stderr контейнера в текст (best-effort)."""
    try:
        logs = container.logs().decode("utf-8", errors="ignore")
    except Exception:
        logs = ""
    return logs


# ----------------------------
# Фикстуры: RTSP сервер и паблишер
# ----------------------------

@pytest.fixture(scope="module")
def rtsp_server():
    """
    Поднимает RTSP сервер (MediaMTX) и пробрасывает порт 8554 на хост.
    Конфигурацию можно задавать через переменные окружения.
    """
    # Минимальная конфигурация через env: разрешаем публикацию/просмотр без аутентификации.
    # MediaMTX автоматически стартует без конфига; протоколы TCP/UDP выбираются по умолчанию.
    server = DockerContainer(RTSP_IMAGE)
    # Жёстко пробрасываем 8554/tcp -> динамический порт на хосте
    server.with_exposed_ports(RTSP_TCP_PORT)
    # Forcing TCP only may improve determinism in CI. Uncomment if нужно:
    # server.with_env("MTX_PROTOCOLS", "tcp")

    server.start()
    try:
        host = server.get_container_host_ip()
        port = int(server.get_exposed_port(RTSP_TCP_PORT))
        # Ждём лог или порт
        try:
            wait_for_logs(server, "mediamtx", timeout=READY_TIMEOUT_S)  # строка встречается в логе MediaMTX
        except Exception:
            # Фоллбэк — ждём открытие порта
            _wait_port_open(host, port, READY_TIMEOUT_S)

        yield {"host": host, "port": port, "container": server}
    finally:
        try:
            server.stop()
        except Exception:
            pass


@pytest.fixture()
def rtsp_publisher(rtsp_server):
    """
    Паблишер синтетического потока в RTSP сервер с помощью ffmpeg контейнера.
    Генератор: lavfi testsrc2, H.264 (libx264), постоянный фреймрейт.
    """
    host = rtsp_server["host"]
    port = rtsp_server["port"]
    url = STREAM_URL_TEMPLATE.format(host=host, port=port)

    # Команда ffmpeg: бесконечная генерация, но ограничиваемся временем теста через SIGTERM.
    cmd = (
        f"-re -stream_loop -1 -f lavfi -i testsrc2=size={PUBLISH_SIZE}:rate={TEST_FPS} "
        f"-pix_fmt yuv420p -c:v libx264 -preset veryfast -tune zerolatency -x264-params keyint=30:min-keyint=30:scenecut=0 "
        f"-b:v {PUBLISH_VBITRATE} -maxrate {PUBLISH_VBITRATE} -bufsize {PUBLISH_VBITRATE} "
        f"-rtsp_transport tcp -f rtsp {url}"
    )

    pub = DockerContainer(FFMPEG_IMAGE).with_command(f"sh -c 'ffmpeg {cmd}'")
    # Нужна сеть до хоста; testcontainers по умолчанию публикует порт на 127.0.0.1 хоста,
    # ffmpeg контейнер увидит его по адресу host.docker.internal (Linux Docker Desktop) или gateway IP.
    # Универсальный путь: публикуемся на IP хоста из контейнера: используем host.docker.internal, если доступен.
    # Сформируем команду уже с рассчитанным URL (выше).
    pub.start()

    # Дадим издателю несколько секунд для установления сессии
    time.sleep(2.0)

    try:
        yield {"url": url, "container": pub}
    finally:
        try:
            pub.stop()
        except Exception:
            pass


# ----------------------------
# Вспомогательные действия: ffprobe/подсчёт кадров
# ----------------------------

def _ffprobe_json(rtsp_url: str, timeout_s: float = PROBE_TIMEOUT_S) -> dict:
    """
    Выполняет ffprobe внутри контейнера и возвращает JSON-дескриптор потоков.
    """
    probe_cmd = (
        "ffprobe -v error -print_format json "
        "-show_streams -select_streams v:0 "
        f"-rtsp_transport tcp -timeout {int(timeout_s*1e6)} -i {rtsp_url}"
    )
    c = DockerContainer(FFMPEG_IMAGE).with_command(f"sh -c \"{probe_cmd}\"")
    c.start()
    try:
        # Ждём завершения и собираем логи
        exit_code = c.get_wrapped_container().wait()["StatusCode"]
        logs = _json_out(c)
        if exit_code != 0:
            raise AssertionError(f"ffprobe failed: exit={exit_code}, logs={logs[:4000]}")
        try:
            return json.loads(logs.strip().split("\n")[-1])
        except Exception:
            # Иногда ffprobe пишет JSON один; если в логах есть чистый JSON, найдём первую '{'
            idx = logs.find("{")
            if idx >= 0:
                return json.loads(logs[idx:])
            raise
    finally:
        try:
            c.stop()
        except Exception:
            pass


def _ffprobe_count_packets(rtsp_url: str, duration_s: float, timeout_s: float = PROBE_TIMEOUT_S) -> int:
    """
    Считает количество прочитанных пакетов за заданный интервал.
    Использует ffprobe с read_intervals и count_packets.
    """
    # Для лайв-потока используем read_intervals 0%+{duration} и count_packets.
    probe_cmd = (
        "ffprobe -v error -print_format json "
        "-count_packets -read_intervals 0%%+{dur} "
        "-select_streams v:0 -show_entries stream=nb_read_packets "
        "-rtsp_transport tcp -timeout {to} -i {url}"
    ).format(dur=int(duration_s), to=int(timeout_s * 1e6), url=rtsp_url)

    c = DockerContainer(FFMPEG_IMAGE).with_command(f"sh -c \"{probe_cmd}\"")
    c.start()
    try:
        exit_code = c.get_wrapped_container().wait()["StatusCode"]
        logs = _json_out(c)
        if exit_code != 0:
            raise AssertionError(f"ffprobe count failed: exit={exit_code}, logs={logs[:4000]}")
        data = json.loads(logs[logs.find("{"):])
        streams = data.get("streams") or []
        if not streams:
            return 0
        nb = streams[0].get("nb_read_packets")
        try:
            return int(nb)
        except Exception:
            return 0
    finally:
        try:
            c.stop()
        except Exception:
            pass


# ----------------------------
# Сами тесты
# ----------------------------

def test_rtsp_ingest_basic(rtsp_server, rtsp_publisher):
    """
    Проверяет, что RTSP-поток доступен и имеет видеодорожку с кодеком h264.
    """
    url = rtsp_publisher["url"]
    info = _ffprobe_json(url, timeout_s=PROBE_TIMEOUT_S)
    streams = info.get("streams") or []
    assert streams, f"no streams: {info}"
    v = streams[0]
    # Минимальные ожидания: видео, h264, валидные ширина/высота
    codec = v.get("codec_name")
    width = v.get("width", 0)
    height = v.get("height", 0)
    assert codec in ("h264", "libx264", "h265", "hevc"), f"unexpected codec: {codec}"
    assert width >= 320 and height >= 240, f"unexpected size: {width}x{height}"


def test_rtsp_ingest_frame_rate(rtsp_server, rtsp_publisher):
    """
    Оценивает FPS по числу пакетов за фиксированное окно времени.
    Допускается отклонение ±30%.
    """
    url = rtsp_publisher["url"]
    # Дадим потоку стабилизироваться
    time.sleep(1.0)
    pkts = _ffprobe_count_packets(url, duration_s=TEST_DUR_S, timeout_s=PROBE_TIMEOUT_S + TEST_DUR_S + 5)
    # Для H.264 NAL/packet != frame строго; однако при zerolatency и CBR соотношение ~1:1 допустимо для грубой оценки.
    fps_est = pkts / max(TEST_DUR_S, 0.001)
    lower = TEST_FPS * 0.7
    upper = TEST_FPS * 1.3
    assert lower <= fps_est <= upper, f"fps estimate {fps_est:.2f} not in [{lower:.2f}, {upper:.2f}] (pkts={pkts})"


def test_rtsp_ingest_survives_restart(rtsp_server, rtsp_publisher):
    """
    Проверяет, что после перезапуска RTSP сервера поток снова становится доступен.
    """
    url = rtsp_publisher["url"]

    # 1) Базовая доступность до перезапуска
    info1 = _ffprobe_json(url, timeout_s=PROBE_TIMEOUT_S)
    assert (info1.get("streams") or []), "stream not available before restart"

    # 2) Перезапуск сервера
    srv = rtsp_server["container"]
    try:
        srv.restart()
    except Exception as e:
        pytest.skip(f"cannot restart RTSP server container: {e}")

    host = rtsp_server["host"]
    port = int(rtsp_server["port"])
    _wait_port_open(host, port, READY_TIMEOUT_S)

    # 3) Повторная проверка доступности
    # Дадим сервису подняться и паблишеру восстановить сессию (ffmpeg переподключится).
    time.sleep(3.0)
    info2 = _ffprobe_json(url, timeout_s=PROBE_TIMEOUT_S)
    assert (info2.get("streams") or []), "stream not available after restart"
