from __future__ import annotations

import socket
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server.porthoneypot.app import HoneypotApp
from server.porthoneypot.config import ServerConfig, save_config
from server.porthoneypot.protocol import read_message, write_message


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def main() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cfg = ServerConfig()
        cfg.shared_key_hex = "33" * 32
        cfg.database_path = str(root / "honeypot.db")
        cfg.log_dir = str(root / "logs")
        cfg.tcp.host = "127.0.0.1"
        cfg.tcp.port = free_port()
        cfg.web.host = "127.0.0.1"
        cfg.web.port = free_port()
        cfg.alerts.local_sound = False
        cfg.alerts.rate_limit_seconds = 0
        cfg.build.package_output_dir = str(root / "packages")
        cfg.build.prebuilt_binary_dir = str(root / "bin")
        config_path = root / "server_config.json"
        save_config(cfg, config_path)

        app = HoneypotApp(config_path)
        app.start()
        try:
            with socket.create_connection(("127.0.0.1", cfg.tcp.port), timeout=5) as sock:
                write_message(
                    sock,
                    app.crypto,
                    {
                        "type": "register",
                        "node_id": "smoke-node",
                        "hostname": "smoke",
                        "os": "test",
                        "arch": "x64",
                        "version": "smoke",
                        "listen_ports": [8022],
                        "stealth_mode": False,
                    },
                )
                assert read_message(sock, app.crypto)["type"] == "ack"
                app.database.enqueue_command("smoke-node", "set_ports", {"listen_ports": [8022, 8088]})
                write_message(sock, app.crypto, {"type": "heartbeat", "node_id": "smoke-node", "listen_ports": [8022]})
                heartbeat_ack = read_message(sock, app.crypto)
                assert heartbeat_ack["type"] == "ack"
                assert heartbeat_ack["commands"][0]["command"] == "set_ports"
                write_message(
                    sock,
                    app.crypto,
                    {
                        "type": "events",
                        "node_id": "smoke-node",
                        "events": [
                            {
                                "ts": int(time.time()),
                                "source_ip": "127.0.0.1",
                                "source_port": 54321,
                                "target_port": 8022,
                                "mode": "general",
                                "content": "hello",
                            }
                        ],
                    },
                )
                assert read_message(sock, app.crypto)["received"] == 1
            assert app.database.stats()["events"] == 1
            with urllib.request.urlopen(f"http://127.0.0.1:{cfg.web.port}/api/status", timeout=5) as resp:
                assert resp.status == 200
                assert b"smoke-node" in resp.read()
            print("smoke test passed")
        finally:
            app.stop()


if __name__ == "__main__":
    main()
