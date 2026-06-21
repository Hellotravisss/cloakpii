"""Detection confidence + audit mode."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloakpii.pii import (
    CONFIDENCE_HIGH,
    field_confidence,
    match_pii_type,
)


class TestMatchPiiType(unittest.TestCase):
    def test_known_types(self):
        self.assertEqual(match_pii_type("alice@example.com"), "email")
        self.assertEqual(match_pii_type("138-1234-5678"), "phone")
        self.assertEqual(match_pii_type("123-45-6789"), "ssn")

    def test_non_pii(self):
        self.assertIsNone(match_pii_type("Alice Wong"))
        self.assertIsNone(match_pii_type("10001"))
        self.assertIsNone(match_pii_type(""))

    def test_credit_card_requires_luhn(self):
        self.assertEqual(match_pii_type("4111111111111111"), "credit_card")  # valid Luhn
        # A Luhn-invalid 16-digit number is not classified as a credit card
        # (it still looks like a bank account, which is fine — just not a card).
        self.assertNotEqual(match_pii_type("1234567812345678"), "credit_card")


class TestFieldConfidence(unittest.TestCase):
    def test_high_confidence_when_values_match(self):
        r = field_confidence("contact", ["a@x.com", "b@y.com", "c@z.com"])
        self.assertEqual(r["type"], "email")
        self.assertEqual(r["confidence"], CONFIDENCE_HIGH)
        self.assertFalse(r["needs_review"])

    def test_needs_review_when_name_signals_but_values_dont_match(self):
        # column "full_name" with free-text names — the classic blind spot
        r = field_confidence("full_name", ["Alice Wong", "Bob Lee", "Wei Chen"])
        self.assertTrue(r["needs_review"])
        self.assertLess(r["confidence"], CONFIDENCE_HIGH)

    def test_no_pii_no_review(self):
        r = field_confidence("order_id", ["10001", "10002", "10003"])
        self.assertEqual(r["confidence"], 0.0)
        self.assertFalse(r["needs_review"])
        self.assertIsNone(r["type"])

    def test_empty_values(self):
        r = field_confidence("email", [])
        self.assertEqual(r["match_rate"], 0.0)


class TestAnalyzeFile(unittest.TestCase):
    def test_csv_breakdown_and_review(self):
        from cloakpii.migrate import analyze_file
        tmp = Path(tempfile.mkdtemp())
        f = tmp / "u.csv"
        f.write_text("email,full_name,order_id\n"
                     "a@x.com,Alice Wong,10001\n"
                     "b@y.com,Bob Lee,10002\n")
        result = analyze_file(f, "csv")
        by_field = {x["field"]: x for x in result["fields"]}
        self.assertEqual(by_field["email"]["confidence"], CONFIDENCE_HIGH)
        self.assertIn("full_name", result["needs_review"])
        self.assertNotIn("order_id", by_field)  # no PII signal → omitted

    def test_sqlite_breakdown(self):
        from cloakpii.migrate import analyze_file
        tmp = Path(tempfile.mkdtemp())
        db = tmp / "d.db"
        c = sqlite3.connect(db)
        c.execute("CREATE TABLE t(email TEXT, nickname TEXT)")
        c.execute("INSERT INTO t VALUES('a@x.com', 'Ace')")
        c.commit()
        c.close()
        result = analyze_file(db, "sqlite")
        fields = {x["field"]: x for x in result["fields"]}
        self.assertIn("t.email", fields)
        self.assertEqual(fields["t.email"]["confidence"], CONFIDENCE_HIGH)


if __name__ == "__main__":
    unittest.main()
