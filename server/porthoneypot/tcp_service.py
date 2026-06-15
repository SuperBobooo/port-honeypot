from __future__ import annotations

import socket
import socketserver
import threading
from typing import Any

from .alerts import AlertManager
from .crypto import FrameCrypto
from .database import Database
from .protocol import ProtocolError, read_message, write_message


class ClientHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: "HoneypotTcpServer" = self.server  # type: ignore[assignment]
        sock: socket.socket = self.request
        sock.settimeout(120)
        peer_ip = self.client_address[0]
        node_id = ""
        try:
            while server.running.is_set():
                message = read_message(sock, server.crypto)
                msg_type = str(message.get("type", ""))
                if msg_type == "register":
                    node_id = str(message.get("node_id", ""))
                    if not node_id:
                        raise ProtocolError("register message missing node_id")
                    server.database.upsert_node(message, peer_ip)
                    server.database.log("INFO", f"node registered: {node_id} from {peer_ip}")
                    write_message(sock, server.crypto, {"type": "ack", "message": "registered"})
                elif msg_type == "heartbeat":
                    node_id = str(message.get("node_id", node_id))
                    server.database.heartbeat(node_id, peer_ip, message.get("listen_ports"))
                    commands = server.database.pop_pending_commands(node_id)
                    write_message(sock, server.crypto, {"type": "ack", "message": "heartbeat", "commands": commands})
                elif msg_type == "events":
                    node_id = str(message.get("node_id", node_id))
                    events = message.get("events") or []
                    for event in events:
                        event["node_id"] = node_id
                    count = server.database.insert_events(node_id, events)
                    for event in events:
                        server.alerts.attack(event)
                    write_message(sock, server.crypto, {"type": "ack", "received": count})
                elif msg_type == "status_log":
                    level = str(message.get("level", "INFO"))
                    text = str(message.get("message", ""))
                    server.database.log(level, f"{node_id or peer_ip}: {text}")
                    write_message(sock, server.crypto, {"type": "ack", "message": "logged"})
                else:
                    write_message(sock, server.crypto, {"type": "error", "message": f"unknown type {msg_type}"})
        except EOFError:
            server.database.log("INFO", f"client disconnected: {node_id or peer_ip}")
        except Exception as exc:
            server.database.log("WARN", f"client handler error from {peer_ip}: {exc}")


class HoneypotTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        crypto: FrameCrypto,
        database: Database,
        alerts: AlertManager,
    ):
        super().__init__(address, ClientHandler)
        self.crypto = crypto
        self.database = database
        self.alerts = alerts
        self.running = threading.Event()
        self.running.set()


class TcpService:
    def __init__(self, host: str, port: int, crypto: FrameCrypto, database: Database, alerts: AlertManager):
        self.host = host
        self.port = port
        self.crypto = crypto
        self.database = database
        self.alerts = alerts
        self._server: HoneypotTcpServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()

    @property
    def is_running(self) -> bool:
        return self._server is not None

    def start(self) -> None:
        with self._lock:
            if self._server is not None:
                return
            self._server = HoneypotTcpServer((self.host, self.port), self.crypto, self.database, self.alerts)
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            self.database.log("INFO", f"TCP service started at {self.host}:{self.port}")

    def stop(self) -> None:
        with self._lock:
            if self._server is None:
                return
            self._server.running.clear()
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._thread = None
            self.database.log("INFO", "TCP service stopped")

    def status(self) -> dict[str, Any]:
        return {"running": self.is_running, "host": self.host, "port": self.port}
