from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server.porthoneypot.app import HoneypotApp
from server.porthoneypot.config import ServerConfig, save_config


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_until(predicate, timeout: float, label: str) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    raise TimeoutError(label)


def can_connect(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def main() -> None:
    exe = ROOT / "dist" / "client-bin" / "windows-x64" / "porthoneypot-client.exe"
    if not exe.exists():
        raise SystemExit(f"client binary not found: {exe}")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        server_tcp_port = free_port()
        web_port = free_port()
        honey_port = free_port()
        cfg = ServerConfig()
        cfg.shared_key_hex = "44" * 32
        cfg.database_path = str(root / "honeypot.db")
        cfg.log_dir = str(root / "server-logs")
        cfg.tcp.host = "127.0.0.1"
        cfg.tcp.port = server_tcp_port
        cfg.web.host = "127.0.0.1"
        cfg.web.port = web_port
        cfg.alerts.local_sound = False
        cfg.alerts.rate_limit_seconds = 0
        cfg.build.package_output_dir = str(root / "packages")
        cfg.build.prebuilt_binary_dir = str(root / "bin")
        config_path = root / "server_config.json"
        save_config(cfg, config_path)

        client_dir = root / "client"
        client_dir.mkdir()
        client_config = {
            "server_host": "127.0.0.1",
            "server_port": server_tcp_port,
            "shared_key_hex": cfg.shared_key_hex,
            "node_id": "rust-integration-node",
            "listen_ports": [honey_port],
            "stealth_mode": False,
            "stealth_fallback_to_tcp": True,
            "autostart": False,
            "hidden": True,
            "heartbeat_interval_secs": 1,
            "flush_interval_secs": 1,
            "max_payload_bytes": 1024,
            "spool_path": "data/client_spool.jsonl",
            "log_path": "logs/client.log",
            "update_enabled": False,
            "update_interval_secs": 300,
            "update_base_url": f"http://127.0.0.1:{web_port}",
        }
        (client_dir / "client_config.json").write_text(json.dumps(client_config), encoding="utf-8")

        app = HoneypotApp(config_path)
        proc: subprocess.Popen | None = None
        app.start()
        try:
            app.update_manager.publish("windows-x64", "9.9.9", str(exe), "integration update")
            check = subprocess.run(
                [str(exe), "check-update"],
                cwd=client_dir,
                check=True,
                capture_output=True,
                text=True,
            )
            assert "update_available=true" in check.stdout

            proc = subprocess.Popen([str(exe), "run"], cwd=client_dir)
            wait_until(lambda: any(n["node_id"] == "rust-integration-node" for n in app.database.list_nodes()), 10, "node registration")

            with socket.create_connection(("127.0.0.1", honey_port), timeout=3) as sock:
                sock.sendall(b"hello from integration")
            wait_until(lambda: app.database.stats()["events"] >= 1, 10, "event upload")

            app.database.enqueue_command("rust-integration-node", "stop_all", {})
            wait_until(lambda: app.database.pending_command_count("rust-integration-node") == 0, 10, "command delivery")
            time.sleep(1.5)
            if can_connect(honey_port):
                raise AssertionError("honeypot port still accepts connections after stop_all command")
            print("rust client integration passed")
        finally:
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            app.stop()


if __name__ == "__main__":
    main()
