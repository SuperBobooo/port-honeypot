import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from server.porthoneypot.config import ServerConfig
from server.porthoneypot.update_manager import UpdateManager


class UpdateManagerTests(unittest.TestCase):
    def test_publish_manifest_and_binary(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            cfg = ServerConfig()
            cfg.build.prebuilt_binary_dir = str(root / "bin")
            cfg.build.update_dir = str(root / "updates")
            source_dir = root / "bin" / "windows-x64"
            source_dir.mkdir(parents=True)
            (source_dir / "porthoneypot-client.exe").write_bytes(b"binary")

            manager = UpdateManager(cfg)
            manifest = manager.publish("windows-x64", "9.9.9", notes="test")

            self.assertTrue(manifest["available"])
            self.assertEqual(manifest["version"], "9.9.9")
            self.assertEqual(manifest["size"], 6)
            self.assertEqual(manager.manifest("windows-x64")["sha256"], manifest["sha256"])
            self.assertTrue(manager.binary_path("windows-x64").exists())


if __name__ == "__main__":
    unittest.main()
