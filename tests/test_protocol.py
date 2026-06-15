import socket
import unittest

from server.porthoneypot.crypto import FrameCrypto
from server.porthoneypot.protocol import read_message, write_message


class ProtocolTests(unittest.TestCase):
    def test_protocol_socketpair_roundtrip(self):
        crypto = FrameCrypto("22" * 32)
        left, right = socket.socketpair()
        try:
            write_message(left, crypto, {"type": "register", "node_id": "n1"})
            self.assertEqual(read_message(right, crypto), {"type": "register", "node_id": "n1"})
        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
