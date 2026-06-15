import unittest
import time

from server.porthoneypot.crypto import FrameCrypto
from server.porthoneypot.database import Database


class DatabaseTests(unittest.TestCase):
    def test_database_node_and_event_flow(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            db = Database(Path(td) / "honeypot.db", FrameCrypto("11" * 32))
            db.upsert_node(
                {
                    "node_id": "node-a",
                    "hostname": "host-a",
                    "os": "linux",
                    "arch": "x86_64",
                    "version": "test",
                    "listen_ports": [22, 80],
                    "stealth_mode": False,
                },
                "127.0.0.1",
            )
            self.assertTrue(db.list_nodes()[0]["online"])
            db.insert_events(
                "node-a",
                [
                    {
                        "ts": 1700000000,
                        "source_ip": "10.0.0.8",
                        "source_port": 55123,
                        "target_port": 22,
                        "mode": "general",
                        "content": "SSH-2.0-test",
                    }
                ],
            )
            rows = db.query_events({"source_ip": "10.0.0.8"})
            self.assertEqual(rows[0]["content"], "SSH-2.0-test")
            self.assertEqual(db.stats()["events"], 1)
            command_id = db.enqueue_command("node-a", "set_ports", {"listen_ports": [8080, 8443]})
            self.assertGreater(command_id, 0)
            self.assertEqual(db.pending_command_count("node-a"), 1)
            commands = db.pop_pending_commands("node-a")
            self.assertEqual(commands[0]["command"], "set_ports")
            self.assertEqual(commands[0]["payload"]["listen_ports"], [8080, 8443])
            self.assertEqual(db.pending_command_count("node-a"), 0)
            db.close()

    def test_probe_activity_and_file_log_rotation(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db = Database(
                root / "honeypot.db",
                FrameCrypto("22" * 32),
                root / "server.log",
                log_max_bytes=64 * 1024,
                log_backup_count=2,
            )
            now = int(time.time())
            db.insert_events(
                "node-b",
                [
                    {
                        "ts": now,
                        "source_ip": "10.0.0.9",
                        "source_port": 50000 + idx,
                        "target_port": port,
                        "mode": "general",
                        "content": "",
                    }
                    for idx, port in enumerate([21, 22, 23, 80, 443, 3389])
                ],
            )
            activity = db.probe_activity("10.0.0.9", 120)
            self.assertEqual(activity["event_count"], 6)
            self.assertEqual(activity["distinct_ports"], 6)

            db.log("INFO", "x" * 70000)
            db.log("INFO", "after rotation")
            self.assertTrue((root / "server.log").exists())
            self.assertTrue((root / "server.log.1").exists())
            db.close()


if __name__ == "__main__":
    unittest.main()
