import unittest

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


if __name__ == "__main__":
    unittest.main()
