from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server.porthoneypot.client_builder import TARGETS, copy_embedded_config
from server.porthoneypot.config import load_config


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Rust honeypot clients")
    parser.add_argument("--config", default="data/server_config.json", help="server config path")
    parser.add_argument("--server-host", default="127.0.0.1", help="embedded server host")
    parser.add_argument("--web-port", type=int, help="server web management port for auto-update")
    parser.add_argument("--disable-update", action="store_true", help="disable client auto-update in embedded config")
    parser.add_argument("--ports", default="21,22,23,80,445,3389", help="listen ports")
    parser.add_argument("--stealth", action="store_true", default=True, help="enable stealth mode in embedded config")
    parser.add_argument("--target", choices=sorted(TARGETS), help="single package target")
    parser.add_argument("--all", action="store_true", help="build all known targets")
    parser.add_argument("--target-dir", default="build-target", help="cargo target directory, relative to project root")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server_config = load_config(args.config)
    targets = sorted(TARGETS) if args.all else [args.target or current_platform()]
    listen_ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    client_config = {
        "server_host": args.server_host,
        "server_port": server_config.tcp.port,
        "shared_key_hex": server_config.shared_key_hex,
        "node_id": "",
        "listen_ports": listen_ports,
        "stealth_mode": bool(args.stealth),
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
        "update_enabled": not args.disable_update,
        "update_interval_secs": 300,
        "update_base_url": f"http://{args.server_host}:{args.web_port or server_config.web.port}",
    }
    cargo = shutil.which("cargo")
    if not cargo:
        userprofile = Path.home()
        candidate = userprofile / ".cargo" / "bin" / "cargo.exe"
        if candidate.exists():
            cargo = str(candidate)
    if not cargo:
        raise SystemExit("cargo not found; install Rust toolchain first")

    out_root = ROOT / "dist" / "client-bin"
    build_root = (ROOT / args.target_dir).resolve()
    embedded_config = ROOT / "client" / "config" / "default_client.json"
    original_config = embedded_config.read_text(encoding="utf-8") if embedded_config.exists() else None
    copy_embedded_config(ROOT / "client", client_config)
    try:
        for name in targets:
            rust_target = TARGETS[name]
            print(f"building {name} ({rust_target})")
            subprocess.run(
                [cargo, "build", "--release", "--target", rust_target, "--target-dir", str(build_root)],
                cwd=ROOT / "client",
                check=True,
            )
            exe = ".exe" if name.startswith("windows") else ""
            binary = build_root / rust_target / "release" / f"porthoneypot-client{exe}"
            target_dir = out_root / name
            target_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(binary, target_dir / binary.name)
            for runtime in windivert_runtime_files(name):
                shutil.copy2(runtime, target_dir / runtime.name)
            license_file = windivert_license_file(name)
            if license_file is not None:
                shutil.copy2(license_file, target_dir / "WinDivert-LICENSE.txt")
            (target_dir / "client_config.json").write_text(
                json.dumps(client_config, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            print(f"wrote {target_dir / binary.name}")
    finally:
        if original_config is not None:
            embedded_config.write_text(original_config, encoding="utf-8")


def current_platform() -> str:
    if sys.platform.startswith("win"):
        return "windows-x64"
    if sys.platform == "darwin":
        return "macos-x64"
    return "linux-x64"


def windivert_runtime_files(platform: str) -> list[Path]:
    if platform != "windows-x64":
        return []
    roots = [
        ROOT / "third_party" / "WinDivert-2.2.2-A" / "WinDivert-2.2.2-A" / "x64",
        ROOT / "third_party" / "WinDivert-2.2.2-A" / "x64",
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
        ROOT / "third_party" / "WinDivert-2.2.2-A" / "WinDivert-2.2.2-A",
        ROOT / "third_party" / "WinDivert-2.2.2-A",
    ]
    for root in roots:
        candidate = root / "LICENSE"
        if candidate.exists():
            return candidate
    return None


if __name__ == "__main__":
    main()
