"""Adversarial security tests — regression guards for CloakPII's core
security properties. These assert *attacker-facing* behaviour: ciphertext
integrity, that PII never survives into output, SQL-injection neutralisation,
path-traversal rejection, secret handling, and decompression-bomb limits.

If any test here fails, a security property has regressed — do not ship.
"""

import gzip
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloakpii.crypto import (
    SALT_LEN,
    CryptoError,
    decrypt_data,
    derive_key,
    encrypt_data,
    encrypt_data_with_key,
)

LEAK = "alice@example.com"
NUM_LEAK = "13812345678"


class TestEncryptionSecurity(unittest.TestCase):
    def test_round_trip(self):
        blob = encrypt_data(b"secret-pii", "pw")
        self.assertEqual(decrypt_data(blob, "pw"), b"secret-pii")

    def test_wrong_password_rejected(self):
        blob = encrypt_data(b"secret-pii", "pw")
        with self.assertRaises(CryptoError):
            decrypt_data(blob, "wrong")

    def test_tampered_ciphertext_detected(self):
        blob = bytearray(encrypt_data(b"secret-pii", "pw"))
        blob[-1] ^= 0x01  # flip a bit in the GCM tag / ciphertext
        with self.assertRaises(CryptoError):
            decrypt_data(bytes(blob), "pw")

    def test_error_message_not_leaky(self):
        try:
            decrypt_data(b"tooshort", "pw")
        except CryptoError as exc:
            msg = str(exc).lower()
            self.assertNotIn("traceback", msg)
            self.assertNotIn("cryptography", msg)

    def test_per_file_nonce_unique(self):
        salt = os.urandom(SALT_LEN)
        key = derive_key("pw", salt)
        nonces = {
            encrypt_data_with_key(b"x", key, salt)[SALT_LEN:SALT_LEN + 12]
            for _ in range(500)
        }
        self.assertEqual(len(nonces), 500)


class TestNoPIILeak(unittest.TestCase):
    """The whole point of the tool: the original PII must never appear in output."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_csv(self):
        from cloakpii.pii import desensitize_csv
        s, o = self.tmp / "a.csv", self.tmp / "a.out.csv"
        s.write_text("email,phone\nalice@example.com,138-1234-5678\n")
        desensitize_csv(s, o)
        self.assertNotIn(LEAK, o.read_text())

    def test_tsv(self):
        from cloakpii.pii import desensitize_tsv
        s, o = self.tmp / "a.tsv", self.tmp / "a.out.tsv"
        s.write_text("email\tphone\nalice@example.com\t138-1234-5678\n")
        desensitize_tsv(s, o)
        self.assertNotIn(LEAK, o.read_text())

    def test_json_string_and_numeric(self):
        from cloakpii.pii import desensitize_json
        s, o = self.tmp / "a.json", self.tmp / "a.out.json"
        s.write_text(json.dumps({"email": "alice@example.com", "phone": 13812345678}))
        txt = (desensitize_json(s, o), o.read_text())[1]
        self.assertNotIn(LEAK, txt)
        self.assertNotIn(NUM_LEAK, txt)

    def test_xml_text_and_attribute(self):
        from cloakpii.pii import desensitize_xml
        s, o = self.tmp / "a.xml", self.tmp / "a.out.xml"
        s.write_text('<u email="alice@example.com"><phone>138-1234-5678</phone></u>')
        desensitize_xml(s, o)
        self.assertNotIn(LEAK, o.read_text())

    def test_sqlite_text_and_integer(self):
        from cloakpii.pii import desensitize_sqlite
        s, o = self.tmp / "a.db", self.tmp / "a.out.db"
        c = sqlite3.connect(s)
        c.execute("CREATE TABLE u(email TEXT, phone INTEGER)")
        c.execute("INSERT INTO u VALUES('alice@example.com', 13812345678)")
        c.commit()
        c.close()
        desensitize_sqlite(s, o)
        c = sqlite3.connect(o)
        row = str(c.execute("SELECT email, phone FROM u").fetchone())
        c.close()
        self.assertNotIn(LEAK, row)
        self.assertNotIn(NUM_LEAK, row)

    def test_parquet_string_and_int_column(self):
        import pyarrow as pa
        import pyarrow.parquet as pq
        from cloakpii.pii import desensitize_parquet
        s, o = self.tmp / "a.parquet", self.tmp / "a.out.parquet"
        pq.write_table(pa.table({
            "email": pa.array(["alice@example.com"]),
            "phone": pa.array([13812345678], type=pa.int64()),
        }), s)
        desensitize_parquet(s, o)
        vals = str(pq.read_table(o).to_pydict())
        self.assertNotIn(LEAK, vals)
        self.assertNotIn(NUM_LEAK, vals)


class TestSqlInjection(unittest.TestCase):
    def test_malicious_table_name_does_not_execute(self):
        from cloakpii.pii import desensitize_sqlite
        tmp = Path(tempfile.mkdtemp())
        s, o = tmp / "inj.db", tmp / "inj.out.db"
        c = sqlite3.connect(s)
        c.execute('CREATE TABLE "users" (email TEXT)')
        c.execute("INSERT INTO users VALUES('alice@example.com')")
        c.execute('CREATE TABLE "t--; DROP TABLE users;" (x TEXT)')
        c.commit()
        c.close()
        try:
            desensitize_sqlite(s, o)
            c = sqlite3.connect(o)
            survived = c.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='users'"
            ).fetchone()[0]
            c.close()
            self.assertEqual(survived, 1)  # users table not dropped
        except sqlite3.OperationalError:
            pass  # rejected outright is also acceptable — no injection executed


class TestPathTraversal(unittest.TestCase):
    def test_verify_rejects_absolute_and_parent_paths(self):
        from cloakpii.integrity import verify_manifest
        tmp = Path(tempfile.mkdtemp())
        d = tmp / "enc"
        d.mkdir()
        (d / "real.enc").write_bytes(b"x")
        secret = tmp / "outside.txt"
        secret.write_text("TOPSECRET")
        man = tmp / "m.json"
        man.write_text(json.dumps({"files": {
            str(secret): "deadbeef",
            "../outside.txt": "deadbeef",
        }}))
        results = verify_manifest(d, man)
        # No result line for an outside path may report a real content hash
        # (which would mean it was read). Only INVALID/MISSING are acceptable.
        for line in results:
            if "outside" in line:
                self.assertTrue("INVALID" in line or "MISSING" in line)


class TestSecretsNotOnDisk(unittest.TestCase):
    def test_password_not_written_to_config(self):
        from cloakpii.config import MigrationConfig, save_config
        tmp = Path(tempfile.mkdtemp())
        cfg = MigrationConfig()
        cfg.password = "topsecret"
        cfg.key_file = "/some/key"
        p = tmp / "c.yaml"
        save_config(cfg, p)
        text = p.read_text()
        self.assertNotIn("topsecret", text)
        self.assertNotIn("/some/key", text)


class TestTokenization(unittest.TestCase):
    def test_deterministic_reversible_and_hiding(self):
        from cloakpii.tokenize import Tokenizer
        tk = Tokenizer("pw")
        t1 = tk.tokenize(LEAK)
        t2 = tk.tokenize(LEAK)
        self.assertTrue(t1.startswith("tkz_"))
        self.assertEqual(t1, t2)            # deterministic (join-preserving)
        self.assertNotIn(LEAK, t1)          # original hidden
        self.assertEqual(tk.detokenize(t1), LEAK)  # reversible


class TestDecompressionBomb(unittest.TestCase):
    """Verified against a tiny cap so the test stays in-memory-cheap."""

    def test_oversized_payload_rejected(self):
        from cloakpii.migrate import _gunzip_bounded
        # 1 MiB of zeros compresses to a few KB; cap at 1 KiB → must refuse.
        payload = gzip.compress(b"\x00" * (1024 * 1024))
        with self.assertRaises(ValueError):
            _gunzip_bounded(payload, max_size=1024)

    def test_within_limit_ok(self):
        from cloakpii.migrate import _gunzip_bounded
        raw = b"hello world" * 10
        self.assertEqual(_gunzip_bounded(gzip.compress(raw), max_size=10_000), raw)


if __name__ == "__main__":
    unittest.main()
