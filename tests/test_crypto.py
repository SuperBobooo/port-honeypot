import unittest

from server.porthoneypot.crypto import CryptoError, FrameCrypto


class CryptoTests(unittest.TestCase):
    def test_frame_crypto_roundtrip(self):
        crypto = FrameCrypto("00" * 32)
        payload = b'{"type":"heartbeat","node_id":"n1"}'
        frame = crypto.encrypt(payload)
        self.assertNotEqual(frame, payload)
        self.assertEqual(crypto.decrypt(frame), payload)

    def test_frame_crypto_rejects_tamper(self):
        crypto = FrameCrypto("00" * 32)
        frame = bytearray(crypto.encrypt(b"hello"))
        frame[-1] ^= 1
        with self.assertRaises(CryptoError):
            crypto.decrypt(bytes(frame))


if __name__ == "__main__":
    unittest.main()
