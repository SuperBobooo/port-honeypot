from __future__ import annotations

import json
import socket
import struct
from typing import Any

from .crypto import FrameCrypto


MAX_FRAME_SIZE = 8 * 1024 * 1024


class ProtocolError(RuntimeError):
    pass


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("socket closed while receiving frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_message(sock: socket.socket, crypto: FrameCrypto) -> dict[str, Any]:
    header = _recv_exact(sock, 4)
    (size,) = struct.unpack("!I", header)
    if size <= 0 or size > MAX_FRAME_SIZE:
        raise ProtocolError(f"invalid frame size: {size}")
    encrypted = _recv_exact(sock, size)
    plaintext = crypto.decrypt(encrypted)
    value = json.loads(plaintext.decode("utf-8"))
    if not isinstance(value, dict):
        raise ProtocolError("message must be a JSON object")
    return value


def write_message(sock: socket.socket, crypto: FrameCrypto, message: dict[str, Any]) -> None:
    payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    encrypted = crypto.encrypt(payload)
    sock.sendall(struct.pack("!I", len(encrypted)) + encrypted)
