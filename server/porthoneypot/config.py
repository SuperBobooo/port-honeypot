from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_PATH = Path("data/server_config.json")


@dataclass
class TcpConfig:
    host: str = "0.0.0.0"
    port: int = 9443
    heartbeat_timeout_seconds: int = 90


@dataclass
class WebConfig:
    host: str = "127.0.0.1"
    port: int = 8088


@dataclass
class EmailConfig:
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 465
    username: str = ""
    password: str = ""
    sender: str = ""
    receivers: list[str] = field(default_factory=list)
    use_ssl: bool = True


@dataclass
class WebhookConfig:
    enabled: bool = False
    url: str = ""
    secret: str = ""


@dataclass
class AlertConfig:
    enabled: bool = True
    rate_limit_seconds: int = 60
    event_types: list[str] = field(
        default_factory=lambda: ["attack", "node_disconnect", "abnormal_probe"]
    )
    abnormal_probe_window_seconds: int = 120
    abnormal_probe_distinct_ports: int = 4
    abnormal_probe_min_events: int = 6
    local_sound: bool = True
    email: EmailConfig = field(default_factory=EmailConfig)
    dingtalk: WebhookConfig = field(default_factory=WebhookConfig)
    feishu: WebhookConfig = field(default_factory=WebhookConfig)
    wecom: WebhookConfig = field(default_factory=WebhookConfig)


@dataclass
class BuildConfig:
    client_source_dir: str = "client"
    package_output_dir: str = "data/packages"
    prebuilt_binary_dir: str = "dist/client-bin"
    update_dir: str = "data/updates"


@dataclass
class ServerConfig:
    shared_key_hex: str = field(default_factory=lambda: secrets.token_hex(32))
    database_path: str = "data/honeypot.db"
    log_dir: str = "logs"
    log_max_bytes: int = 2 * 1024 * 1024
    log_backup_count: int = 5
    tcp: TcpConfig = field(default_factory=TcpConfig)
    web: WebConfig = field(default_factory=WebConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    build: BuildConfig = field(default_factory=BuildConfig)


def _merge_dataclass(instance: Any, raw: dict[str, Any]) -> Any:
    for key, value in raw.items():
        if not hasattr(instance, key):
            continue
        current = getattr(instance, key)
        if hasattr(current, "__dataclass_fields__") and isinstance(value, dict):
            _merge_dataclass(current, value)
        else:
            setattr(instance, key, value)
    return instance


def ensure_parent_dirs(config: ServerConfig) -> None:
    Path(config.database_path).parent.mkdir(parents=True, exist_ok=True)
    Path(config.log_dir).mkdir(parents=True, exist_ok=True)
    Path(config.build.package_output_dir).mkdir(parents=True, exist_ok=True)
    Path(config.build.prebuilt_binary_dir).mkdir(parents=True, exist_ok=True)
    Path(config.build.update_dir).mkdir(parents=True, exist_ok=True)


def load_config(path: Path | str = DEFAULT_CONFIG_PATH) -> ServerConfig:
    path = Path(path)
    if not path.exists():
        config = ServerConfig()
        save_config(config, path)
        ensure_parent_dirs(config)
        return config

    raw = json.loads(path.read_text(encoding="utf-8"))
    config = _merge_dataclass(ServerConfig(), raw)
    ensure_parent_dirs(config)
    return config


def save_config(config: ServerConfig, path: Path | str = DEFAULT_CONFIG_PATH) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(asdict(config), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
