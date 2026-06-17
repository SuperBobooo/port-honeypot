from __future__ import annotations

import json
import shutil
import time
import zipfile
from pathlib import Path
from typing import Any

from .config import BuildConfig, ServerConfig


TARGETS = {
    "windows-x64": "x86_64-pc-windows-msvc",
    "linux-x64": "x86_64-unknown-linux-gnu",
    "linux-arm64": "aarch64-unknown-linux-gnu",
    "macos-x64": "x86_64-apple-darwin",
}


def default_client_config(server_config: ServerConfig) -> dict[str, Any]:
    return {
        "server_host": "127.0.0.1",
        "server_port": server_config.tcp.port,
        "shared_key_hex": server_config.shared_key_hex,
        "node_id": "",
        "listen_ports": [21, 22, 23, 80, 445, 3389],
        "stealth_mode": True,
        "stealth_fallback_to_tcp": True,
        "autostart": True,
        "hidden": True,
        "heartbeat_interval_secs": 20,
        "flush_interval_secs": 10,
        "max_payload_bytes": 1024,
        "spool_path": "data/client_spool.jsonl",
        "log_path": "logs/client.log",
        "log_max_bytes": 2 * 1024 * 1024,
        "log_backup_count": 5,
        "update_enabled": True,
        "update_interval_secs": 300,
        "update_base_url": f"http://127.0.0.1:{server_config.web.port}",
    }


class ClientBuilder:
    def __init__(self, server_config: ServerConfig):
        self.server_config = server_config
        self.build_config: BuildConfig = server_config.build
        self.output_dir = Path(self.build_config.package_output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def build_package(
        self,
        server_host: str,
        server_port: int,
        listen_ports: list[int],
        stealth_mode: bool,
        platforms: list[str],
    ) -> dict[str, Any]:
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        name = f"porthoneypot-client-{timestamp}"
        package_path = self.output_dir / f"{name}.zip"
        config = default_client_config(self.server_config)
        config.update(
            {
                "server_host": server_host,
                "server_port": int(server_port),
                "listen_ports": listen_ports,
                "stealth_mode": bool(stealth_mode),
                "update_base_url": f"http://{server_host}:{self.server_config.web.port}",
            }
        )

        included_binaries: list[str] = []
        with zipfile.ZipFile(package_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{name}/client_config.json", json.dumps(config, ensure_ascii=False, indent=2))
            zf.writestr(f"{name}/README.txt", self._package_readme(platforms))
            zf.writestr(f"{name}/build_targets.txt", "\n".join(TARGETS[p] for p in platforms if p in TARGETS))
            client_gui = Path("tools/client_gui.ps1")
            if any(platform.startswith("windows") for platform in platforms) and client_gui.exists():
                zf.write(client_gui, f"{name}/tools/client_gui.ps1")

            source_dir = Path(self.build_config.client_source_dir)
            if source_dir.exists():
                for path in source_dir.rglob("*"):
                    if path.is_file() and "target" not in path.parts and path.suffix != ".bak":
                        rel = path.relative_to(source_dir)
                        zf.write(path, f"{name}/source/client/{rel.as_posix()}")

            prebuilt_root = Path(self.build_config.prebuilt_binary_dir)
            for platform_name in platforms:
                binary_name = "porthoneypot-client.exe" if platform_name.startswith("windows") else "porthoneypot-client"
                candidate = prebuilt_root / platform_name / binary_name
                if candidate.exists():
                    zf.write(candidate, f"{name}/bin/{platform_name}/{binary_name}")
                    included_binaries.append(platform_name)
                for runtime in windivert_runtime_files(platform_name):
                    zf.write(runtime, f"{name}/bin/{platform_name}/{runtime.name}")
                license_path = windivert_license_file(platform_name)
                if license_path is not None:
                    zf.write(license_path, f"{name}/third_party/WinDivert-LICENSE.txt")

        return {
            "ok": True,
            "package": str(package_path),
            "platforms": platforms,
            "included_binaries": included_binaries,
            "note": "预编译二进制存在时已打包；否则包内包含源码与内置配置，可用 tools/build_clients.py 编译。",
        }

    @staticmethod
    def _package_readme(platforms: list[str]) -> str:
        return f"""轻量端口蜜罐客户端分发包

目标平台: {", ".join(platforms)}

使用方式:
1. 若 bin/ 目录中存在当前平台二进制，直接运行 porthoneypot-client。
2. 若未包含二进制，进入 source/client，将 client_config.json 复制为 config/default_client.json 后执行 cargo build --release。
3. client_config.json 中的 server_host、server_port、shared_key_hex 会在编译后内置进客户端；分发部署时请不要随意泄露。
4. Windows 平台可运行 tools/client_gui.ps1 打开客户端桌面管理器和托盘菜单。

隐身模式说明:
Windows 隐身模式需要管理员权限，并要求 porthoneypot-client.exe 同目录存在 WinDivert.dll 与 WinDivert64.sys。
Linux 隐身模式需要 root/CAP_NET_RAW 与 RST 阻断规则。
默认启用 stealth_fallback_to_tcp，未检测到后端时会降级为普通 TCP 诱捕监听。
"""


def copy_embedded_config(client_source: str | Path, config: dict[str, Any]) -> Path:
    source = Path(client_source)
    target = source / "config" / "default_client.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        backup = target.with_suffix(".json.bak")
        shutil.copy2(target, backup)
    target.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    return target


def windivert_runtime_files(platform: str) -> list[Path]:
    if platform != "windows-x64":
        return []
    roots = [
        Path("third_party") / "WinDivert-2.2.2-A" / "WinDivert-2.2.2-A" / "x64",
        Path("third_party") / "WinDivert-2.2.2-A" / "x64",
    ]
    for root in roots:
        dll = root / "WinDivert.dll"
        sys = root / "WinDivert64.sys"
        if dll.exists() and sys.exists():
            return [dll, sys]
    return []


def windivert_license_file(platform: str) -> Path | None:
    if platform != "windows-x64":
        return None
    roots = [
        Path("third_party") / "WinDivert-2.2.2-A" / "WinDivert-2.2.2-A",
        Path("third_party") / "WinDivert-2.2.2-A",
    ]
    for root in roots:
        candidate = root / "LICENSE"
        if candidate.exists():
            return candidate
    return None
