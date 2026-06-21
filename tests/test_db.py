"""Database source connectors (tested via the zero-dependency SQLite path)."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloakpii.db import DBError, _connect, export_database, list_tables


class TestSqliteExport(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db = self.tmp / "app.db"
        c = sqlite3.connect(self.db)
        c.execute("CREATE TABLE customers(email TEXT, phone TEXT)")
        c.executemany("INSERT INTO customers VALUES(?,?)",
                      [("alice@x.com", "138-1234-5678"), ("bob@y.com", "139-0000-1111")])
        c.execute("CREATE TABLE orders(id INTEGER, amount REAL)")
        c.execute("INSERT INTO orders VALUES(1, 9.9)")
        c.commit()
        c.close()
        self.url = f"sqlite:///{self.db}"

    def test_list_tables_excludes_internal(self):
        conn, scheme = _connect(self.url)
        try:
            tables = sorted(list_tables(conn, scheme))
        finally:
            conn.close()
        self.assertEqual(tables, ["customers", "orders"])

    def test_export_database_writes_csvs(self):
        out = self.tmp / "dump"
        summary = export_database(self.url, out)
        self.assertEqual(summary["total_rows"], 3)
        self.assertTrue((out / "customers.csv").exists())
        self.assertTrue((out / "orders.csv").exists())
        content = (out / "customers.csv").read_text()
        self.assertIn("email,phone", content)
        self.assertIn("alice@x.com", content)  # raw export; masking happens in migrate

    def test_export_then_migrate_masks(self):
        from cloakpii.migrate import run_migration, decrypt_tree
        out = self.tmp / "dump"
        export_database(self.url, out)
        safe = self.tmp / "safe"
        run_migration(source_dir=out, output_dir=safe, password="pw",
                      show_progress=False, generate_manifest=False)
        dec = self.tmp / "dec"
        decrypt_tree(safe / "encrypted", dec, "pw")
        masked = (dec / "customers.csv").read_text()
        self.assertNotIn("alice@x.com", masked)

    def test_selected_tables_only(self):
        out = self.tmp / "dump2"
        summary = export_database(self.url, out, tables=["orders"])
        self.assertEqual([t["table"] for t in summary["tables"]], ["orders"])
        self.assertFalse((out / "customers.csv").exists())


class TestErrors(unittest.TestCase):
    def test_unsupported_scheme(self):
        with self.assertRaises(DBError):
            _connect("oracle://user:pw@host/db")

    def test_missing_driver_message(self):
        # psycopg is not installed in the test env → helpful DBError, not ImportError
        try:
            import psycopg  # noqa: F401
            self.skipTest("psycopg is installed; cannot test the missing-driver path")
        except ImportError:
            pass
        with self.assertRaises(DBError):
            _connect("postgresql://user:pw@localhost/db")


if __name__ == "__main__":
    unittest.main()
