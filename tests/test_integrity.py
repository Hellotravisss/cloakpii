"""Tests for SHA-256 manifest integrity verification."""

import json
import tempfile
import unittest
from pathlib import Path

from cloakpii.integrity import verify_manifest, write_manifest


class TestManifestRoundTrip(unittest.TestCase):
    def test_matching_manifest_has_no_mismatches(self):
        tmp = Path(tempfile.mkdtemp())
        d = tmp / "enc"; d.mkdir()
        (d / "a.enc").write_bytes(b"hello")
        man = tmp / "m.json"
        write_manifest(d, man)
        self.assertEqual(verify_manifest(d, man), [])


class TestManifestPathTraversal(unittest.TestCase):
    """A manifest is untrusted input; absolute / '..' keys must not make
    verify read files outside the directory under verification."""

    def test_absolute_and_parent_keys_are_rejected_not_read(self):
        tmp = Path(tempfile.mkdtemp())
        d = tmp / "enc"; d.mkdir()
        (d / "real.enc").write_bytes(b"x")
        secret = tmp / "outside_secret.txt"
        secret.write_text("TOPSECRET")
        man = tmp / "m.json"
        man.write_text(json.dumps({"files": {
            str(secret): "deadbeef",            # absolute path
            "../outside_secret.txt": "deadbeef",  # parent traversal
            "real.enc": "deadbeef",
        }}))
        result = verify_manifest(d, man)
        # Out-of-directory entries are flagged, never hashed/read.
        self.assertTrue(any(m.startswith("INVALID PATH") and str(secret) in m for m in result))
        self.assertTrue(any(m.startswith("INVALID PATH") and "../outside_secret.txt" in m for m in result))
        # No entry should disclose a real hash of the outside file.
        self.assertFalse(any("outside_secret" in m and "INVALID PATH" not in m for m in result))


if __name__ == "__main__":
    unittest.main()
