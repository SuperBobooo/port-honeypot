from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server.porthoneypot.config import load_config
from server.porthoneypot.update_manager import UpdateManager


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Publish a client binary as an offline update")
    parser.add_argument("--config", default="data/server_config.json")
    parser.add_argument("--platform", default="windows-x64")
    parser.add_argument("--version", default="0.1.0")
    parser.add_argument("--source", help="optional explicit client binary path")
    parser.add_argument("--notes", default="")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manager = UpdateManager(load_config(args.config))
    manifest = manager.publish(args.platform, args.version, args.source, args.notes)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
