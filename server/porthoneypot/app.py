from __future__ import annotations

import argparse
import json
import signal
import threading
import time
from pathlib import Path

from .alerts import AlertManager
from .client_builder import ClientBuilder
from .config import DEFAULT_CONFIG_PATH, load_config, save_config
from .crypto import FrameCrypto
from .database import Database
from .tcp_service import TcpService
from .update_manager import UpdateManager
from .web_service import WebService


class HoneypotApp:
    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH):
        self.config_path = config_path
        self.config = load_config(config_path)
        self.crypto = FrameCrypto(self.config.shared_key_hex)
        self.database = Database(
            self.config.database_path,
            self.crypto,
            Path(self.config.log_dir) / "server.log",
            self.config.log_max_bytes,
            self.config.log_backup_count,
        )
        self.alerts = AlertManager(self.config.alerts, self.database)
        self.tcp_service = TcpService(
            self.config.tcp.host,
            self.config.tcp.port,
            self.crypto,
            self.database,
            self.alerts,
        )
        self.client_builder = ClientBuilder(self.config)
        self.update_manager = UpdateManager(self.config)
        self.web_service = WebService(
            self.config.web.host,
            self.config.web.port,
            self.database,
            self.alerts,
            self.tcp_service,
            self.client_builder,
            self.update_manager,
        )
        self._stop = threading.Event()
        self._monitor_thread = threading.Thread(target=self._monitor_stale_nodes, daemon=True)

    def start(self) -> None:
        self.tcp_service.start()
        self.web_service.start()
        self._monitor_thread.start()
        self.database.log("INFO", "honeypot app started")

    def stop(self) -> None:
        self._stop.set()
        self.web_service.stop()
        self.tcp_service.stop()
        self.database.log("INFO", "honeypot app stopped")
        self.database.close()

    def wait(self) -> None:
        while not self._stop.is_set():
            time.sleep(0.5)

    def _monitor_stale_nodes(self) -> None:
        timeout = self.config.tcp.heartbeat_timeout_seconds
        while not self._stop.is_set():
            try:
                stale_nodes = self.database.mark_stale_nodes_offline(timeout)
                for node in stale_nodes:
                    self.alerts.node_disconnect(node)
            except Exception as exc:
                self.database.log("WARN", f"stale node monitor failed: {exc}")
            self._stop.wait(10)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="轻量端口蜜罐服务端")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="配置文件路径")
    parser.add_argument("--init-config", action="store_true", help="生成默认配置后退出")
    parser.add_argument("--print-config", action="store_true", help="打印当前配置后退出")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config_path = Path(args.config)
    config = load_config(config_path)
    save_config(config, config_path)
    if args.print_config:
        print(json.dumps(config, default=lambda o: o.__dict__, ensure_ascii=False, indent=2))
        return
    if args.init_config:
        print(f"配置已生成: {config_path}")
        return

    app = HoneypotApp(config_path)

    def request_stop(signum: int, _frame: object) -> None:
        app.database.log("INFO", f"received signal {signum}, shutting down")
        app._stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    app.start()
    print(f"Web 管理台: http://{app.config.web.host}:{app.config.web.port}")
    print(f"TCP 接入: {app.config.tcp.host}:{app.config.tcp.port}")
    try:
        app.wait()
    finally:
        app.stop()


if __name__ == "__main__":
    main()
