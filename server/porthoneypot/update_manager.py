from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Any

from .config import ServerConfig


PLATFORM_BINARY_NAMES = {
    "windows-x64": "porthoneypot-client.exe",
    "linux-x64": "porthoneypot-client",
    "linux-arm64": "porthoneypot-client",
    "macos-x64": "porthoneypot-client",
}


class UpdateManager:
    def __init__(self, config: ServerConfig):
        self.config = config
        self.update_root = Path(config.build.update_dir)
        self.update_root.mkdir(parents=True, exist_ok=True)

    def manifest(self, platform: str) -> dict[str, Any]:
        path = self._manifest_path(platform)
        if not path.exists():
            return {"available": False, "platform": platform}
        value = json.loads(path.read_text(encoding="utf-8"))
        value["available"] = True
        return value

    def binary_path(self, platform: str) -> Path | None:
        manifest = self.manifest(platform)
        if not manifest.get("available"):
            return None
        candidate = self.update_root / platform / str(manifest["file"])
        if candidate.exists():
            return candidate
        return None

    def publish(self, platform: str, version: str, source: str | None = None, notes: str = "") -> dict[str, Any]:
        binary_name = PLATFORM_BINARY_NAMES.get(platform)
        if not binary_name:
            raise ValueError(f"unsupported platform: {platform}")
        source_path = Path(source) if source else Path(self.config.build.prebuilt_binary_dir) / platform / binary_name
        if not source_path.exists():
            raise FileNotFoundError(f"client binary not found: {source_path}")
        target_dir = self.update_root / platform
        target_dir.mkdir(parents=True, exist_ok=True)
        target_name = binary_name
        target_path = target_dir / target_name
        shutil.copy2(source_path, target_path)
        digest = sha256_file(target_path)
        manifest = {
            "available": True,
            "platform": platform,
            "version": version,
            "file": target_name,
            "size": target_path.stat().st_size,
            "sha256": digest,
            "published_at": int(time.time()),
            "notes": notes,
            "download_path": f"/api/client-updates/{platform}/download",
        }
        self._manifest_path(platform).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return manifest

    def _manifest_path(self, platform: str) -> Path:
        return self.update_root / platform / "manifest.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
