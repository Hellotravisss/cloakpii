"""Per-field policy: mask / tokenize / drop / keep, overriding the global mode."""

import csv
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloakpii.pii import (
    desensitize_csv,
    desensitize_json,
    desensitize_sqlite,
    resolve_field_action,
)
from cloakpii.tokenize import Tokenizer


class TestResolveAction(unittest.TestCase):
    def test_case_insensitive_and_default_none(self):
        policies = {"email": "tokenize"}
        self.assertEqual(resolve_field_action("Email", policies), "tokenize")
        self.assertEqual(resolve_field_action(" email ", policies), "tokenize")
        self.assertIsNone(resolve_field_action("phone", policies))
        self.assertIsNone(resolve_field_action("email", None))


class TestCsvPolicies(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.src = self.tmp / "u.csv"
        self.out = self.tmp / "u.out.csv"
        self.src.write_text("email,phone,salary,user_id\nalice@x.com,138-1234-5678,99999,U1\n")

    def _rows(self):
        with open(self.out, newline="") as f:
            return list(csv.DictReader(f))

    def test_drop_removes_column(self):
        desensitize_csv(self.src, self.out, field_policies={"salary": "drop"})
        rows = self._rows()
        self.assertNotIn("salary", rows[0])
        self.assertNotIn("99999", self.out.read_text())

    def test_keep_leaves_value_untouched(self):
        desensitize_csv(self.src, self.out, field_policies={"user_id": "keep"})
        self.assertEqual(self._rows()[0]["user_id"], "U1")

    def test_tokenize_action(self):
        tk = Tokenizer("pw")
        desensitize_csv(self.src, self.out, tokenizer=tk, field_policies={"email": "tokenize"})
        val = self._rows()[0]["email"]
        self.assertTrue(val.startswith("tkz_"))
        self.assertEqual(tk.detokenize(val), "alice@x.com")

    def test_mask_forced_even_without_regex_match(self):
        # user_id "U1" matches no PII regex, but an explicit mask policy forces it
        desensitize_csv(self.src, self.out, field_policies={"user_id": "mask"})
        self.assertNotEqual(self._rows()[0]["user_id"], "U1")


class TestJsonPolicies(unittest.TestCase):
    def test_drop_key_and_keep(self):
        tmp = Path(tempfile.mkdtemp())
        src, out = tmp / "a.json", tmp / "a.out.json"
        src.write_text(json.dumps({"email": "a@x.com", "salary": 99999, "id": "X1"}))
        desensitize_json(src, out, field_policies={"salary": "drop", "id": "keep"})
        d = json.loads(out.read_text())
        self.assertNotIn("salary", d)
        self.assertEqual(d["id"], "X1")


class TestSqlitePolicies(unittest.TestCase):
    def test_drop_column_and_keep(self):
        tmp = Path(tempfile.mkdtemp())
        src, out = tmp / "d.db", tmp / "d.out.db"
        c = sqlite3.connect(src)
        c.execute("CREATE TABLE t(email TEXT, salary INTEGER, note TEXT)")
        c.execute("INSERT INTO t VALUES('bob@y.com', 88888, 'keep me')")
        c.commit()
        c.close()
        desensitize_sqlite(src, out, field_policies={"salary": "drop", "note": "keep"})
        c = sqlite3.connect(out)
        cols = [r[1] for r in c.execute('PRAGMA table_info("t")').fetchall()]
        note = c.execute("SELECT note FROM t").fetchone()[0]
        c.close()
        self.assertNotIn("salary", cols)
        self.assertEqual(note, "keep me")


class TestEndToEndAndConfig(unittest.TestCase):
    def test_migration_with_policies_and_invalid_action(self):
        from cloakpii.migrate import run_migration, decrypt_tree
        tmp = Path(tempfile.mkdtemp())
        src = tmp / "src"
        src.mkdir()
        out = tmp / "out"
        (src / "u.csv").write_text("email,salary\nalice@x.com,99999\n")
        run_migration(
            source_dir=src, output_dir=out, password="pw",
            show_progress=False, generate_manifest=False,
            field_policies={"salary": "drop", "email": "BOGUS"},  # invalid ignored
        )
        dec = tmp / "dec"
        decrypt_tree(out / "encrypted", dec, "pw")
        text = (dec / "u.csv").read_text()
        self.assertNotIn("99999", text)        # salary dropped
        self.assertNotIn("alice@x.com", text)  # email still auto-masked (invalid policy ignored)

    def test_config_roundtrip_keeps_policies(self):
        from cloakpii.config import MigrationConfig, save_config, load_config
        tmp = Path(tempfile.mkdtemp())
        cfg = MigrationConfig()
        cfg.field_policies = {"email": "tokenize", "salary": "drop"}
        p = tmp / "c.yaml"
        save_config(cfg, p)
        loaded = load_config(p)
        self.assertEqual(loaded.field_policies, {"email": "tokenize", "salary": "drop"})


if __name__ == "__main__":
    unittest.main()
