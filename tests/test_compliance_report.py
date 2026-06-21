"""Richer compliance artifacts — real statistics + computed PIPL threshold."""

import unittest

from cloakpii.compliance import (
    PIPL_ASSESSMENT_RECORD_THRESHOLD,
    generate_compliance_report,
    get_profile,
)


def _migration(records, files=1, pii=10):
    return {
        "files_processed": ["a"] * files,
        "files_encrypted": ["a"] * files,
        "total_pii_masked": pii,
        "total_bytes_processed": 1234,
        "pii_reports": {
            "a.csv": {"fields_masked": ["email", "phone"], "rows_processed": records},
        },
        "errors": [],
    }


class TestDataSummary(unittest.TestCase):
    def test_summary_reflects_real_stats(self):
        rep = generate_compliance_report(get_profile("pdpa"), _migration(records=50, pii=7))
        s = rep["data_summary"]
        self.assertEqual(s["records_processed"], 50)
        self.assertEqual(s["pii_values_masked"], 7)
        self.assertEqual(s["data_categories"], ["email", "phone"])
        self.assertEqual(s["files_processed"], 1)


class TestPiplThreshold(unittest.TestCase):
    def test_under_threshold(self):
        rep = generate_compliance_report(get_profile("pipl"), _migration(records=100))
        self.assertFalse(rep["large_volume_transfer"])

    def test_over_threshold_flags_assessment(self):
        big = PIPL_ASSESSMENT_RECORD_THRESHOLD + 1
        rep = generate_compliance_report(get_profile("pipl"), _migration(records=big))
        self.assertTrue(rep["large_volume_transfer"])
        joined = " ".join(rep["recommendations"]).lower()
        self.assertIn("required", joined)


if __name__ == "__main__":
    unittest.main()
