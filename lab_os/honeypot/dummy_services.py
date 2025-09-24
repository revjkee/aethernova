import socket
import threading
import logging

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')

class DummyService(threading.Thread):
    def __init__(self, host: str, port: int, response: bytes):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.response = response
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self):
        try:
            self._sock.bind((self.host, self.port))
            self._sock.listen(5)
            logging.info(f'Dummy service started on {self.host}:{self.port}')
            while True:
                client, addr = self._sock.accept()
                logging.info(f'Connection from {addr} on port {self.port}')
                client.recv(1024)  # читаем данные, но не используем
                client.sendall(self.response)
                client.close()
        except Exception as e:
            logging.error(f'Error on port {self.port}: {e}')
        finally:
            self._sock.close()

def main():
    services = [
        DummyService('0.0.0.0', 21, b'220 Fake FTP service\r\n'),
        DummyService('0.0.0.0', 22, b'SSH-2.0-OpenSSH_7.4\r\n'),
        DummyService('0.0.0.0', 80, b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'),
    ]

    for service in services:
        service.start()

    # Ожидаем завершения (работаем бесконечно)
    try:
        while True:
            pass
    except KeyboardInterrupt:
        logging.info('Shutting down dummy services.')

if __name__ == '__main__':
    main()
