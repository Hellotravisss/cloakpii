"""Chunked streaming encryption — additive format, auto-detected on decrypt."""

import os
import tempfile
import unittest
from pathlib import Path

from cloakpii.crypto import (
    CryptoError,
    decrypt_file,
    decrypt_file_stream_with_key,
    decrypt_file_with_key,
    derive_key,
    encrypt_file,
    encrypt_file_stream_with_key,
    is_stream_file,
)


class TestStreamFormat(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.salt = os.urandom(16)
        self.key = derive_key("pw", self.salt)
        # ~2.5 MiB → spans multiple 1 MiB chunks + a partial one
        self.data = os.urandom(2 * 1024 * 1024 + 777)
        self.src = self.tmp / "big.bin"
        self.src.write_bytes(self.data)

    def _enc(self):
        enc = self.tmp / "big.enc"
        encrypt_file_stream_with_key(self.src, enc, self.key, self.salt)
        return enc

    def test_round_trip_multichunk(self):
        enc = self._enc()
        self.assertTrue(is_stream_file(enc))
        dec = self.tmp / "out.bin"
        decrypt_file_stream_with_key(enc, dec, self.key)
        self.assertEqual(dec.read_bytes(), self.data)

    def test_auto_detect_with_key(self):
        enc = self._enc()
        dec = self.tmp / "out2.bin"
        decrypt_file_with_key(enc, dec, self.key)  # auto-detects stream
        self.assertEqual(dec.read_bytes(), self.data)

    def test_auto_detect_with_password(self):
        enc = self._enc()
        dec = self.tmp / "out3.bin"
        decrypt_file(enc, dec, "pw")  # derives key from header salt
        self.assertEqual(dec.read_bytes(), self.data)

    def test_wrong_password(self):
        enc = self._enc()
        with self.assertRaises(CryptoError):
            decrypt_file(enc, self.tmp / "x", "wrong")

    def test_truncation_detected(self):
        enc = self._enc()
        raw = enc.read_bytes()
        trunc = self.tmp / "t.enc"
        trunc.write_bytes(raw[: len(raw) - 40])  # drop the final chunk
        with self.assertRaises(CryptoError):
            decrypt_file_stream_with_key(trunc, self.tmp / "y", self.key)

    def test_tamper_detected(self):
        enc = self._enc()
        b = bytearray(enc.read_bytes())
        b[60] ^= 0x01  # flip a byte inside the first ciphertext chunk
        tampered = self.tmp / "tm.enc"
        tampered.write_bytes(bytes(b))
        with self.assertRaises(CryptoError):
            decrypt_file_stream_with_key(tampered, self.tmp / "z", self.key)


class TestLegacyStillWorks(unittest.TestCase):
    def test_legacy_round_trip_and_not_flagged_as_stream(self):
        tmp = Path(tempfile.mkdtemp())
        src = tmp / "f.bin"
        src.write_bytes(b"hello legacy" * 100)
        enc = tmp / "f.enc"
        encrypt_file(src, enc, "pw")
        self.assertFalse(is_stream_file(enc))
        dec = tmp / "f.dec"
        decrypt_file(enc, dec, "pw")
        self.assertEqual(dec.read_bytes(), b"hello legacy" * 100)


class TestStreamingMigration(unittest.TestCase):
    def test_migrate_then_decrypt_all_streamed(self):
        import cloakpii.migrate as m
        orig = m.STREAM_THRESHOLD
        m.STREAM_THRESHOLD = 1024  # force streaming for small test files
        try:
            tmp = Path(tempfile.mkdtemp())
            src = tmp / "src"
            src.mkdir()
            out = tmp / "out"
            (src / "u.csv").write_text("email,phone\n" + "alice@x.com,138-1234-5678\n" * 200)
            m.run_migration(source_dir=src, output_dir=out, password="pw",
                            show_progress=False, generate_manifest=False)
            enc = out / "encrypted" / "u.csv.enc"
            self.assertTrue(is_stream_file(enc))
            dec = tmp / "dec"
            rep = m.decrypt_tree(out / "encrypted", dec, "pw")
            self.assertEqual(rep["errors"], [])
            content = (dec / "u.csv").read_text()
            self.assertNotIn("alice@x.com", content)  # masked
        finally:
            m.STREAM_THRESHOLD = orig


if __name__ == "__main__":
    unittest.main()
