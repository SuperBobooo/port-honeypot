from __future__ import annotations

import hashlib
import hmac
import os


MAGIC = b"PHP1"
NONCE_SIZE = 16
TAG_SIZE = 32


class CryptoError(ValueError):
    pass


class FrameCrypto:
    """Small authenticated encryption layer for offline TCP transport.

    It uses HMAC-SHA256 as a deterministic keystream and a separate HMAC tag
    for integrity. The construction avoids non-stdlib dependencies on the
    Python server while still encrypting traffic on the wire.
    """

    def __init__(self, key_hex: str):
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            key = hashlib.sha256(key_hex.encode("utf-8")).digest()
        if len(key) < 32:
            key = hashlib.sha256(key).digest()
        self.master_key = key[:32]
        self.enc_key = hmac.new(self.master_key, b"enc", hashlib.sha256).digest()
        self.mac_key = hmac.new(self.master_key, b"mac", hashlib.sha256).digest()

    def _keystream(self, nonce: bytes, size: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < size:
            block = hmac.new(
                self.enc_key,
                nonce + counter.to_bytes(4, "big"),
                hashlib.sha256,
            ).digest()
            out.extend(block)
            counter += 1
        return bytes(out[:size])

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(NONCE_SIZE)
        stream = self._keystream(nonce, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
        body = MAGIC + nonce + ciphertext
        tag = hmac.new(self.mac_key, body, hashlib.sha256).digest()
        return body + tag

    def decrypt(self, frame: bytes) -> bytes:
        min_size = len(MAGIC) + NONCE_SIZE + TAG_SIZE
        if len(frame) < min_size:
            raise CryptoError("encrypted frame is too short")
        if not frame.startswith(MAGIC):
            raise CryptoError("encrypted frame magic mismatch")
        tag = frame[-TAG_SIZE:]
        body = frame[:-TAG_SIZE]
        expected = hmac.new(self.mac_key, body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise CryptoError("encrypted frame authentication failed")
        nonce = frame[len(MAGIC) : len(MAGIC) + NONCE_SIZE]
        ciphertext = frame[len(MAGIC) + NONCE_SIZE : -TAG_SIZE]
        stream = self._keystream(nonce, len(ciphertext))
        return bytes(a ^ b for a, b in zip(ciphertext, stream))
