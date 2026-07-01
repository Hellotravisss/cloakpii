"""Regression + gap tests for the v1.6.0 audit fixes."""

import os
import tempfile
import unittest
from pathlib import Path

from cloakpii import crypto
from cloakpii.crypto import (
    CryptoError,
    decrypt_file_stream_with_key,
    derive_key,
    encrypt_file_stream_with_key,
)
from cloakpii.pii import (
    CONFIDENCE_MEDIUM,
    desensitize_xml,
    field_confidence,
    mask_value,
    match_pii_type,
)


class TestDetectionAdditions(unittest.TestCase):
    def test_bare_cn_mobile_masked(self):
        self.assertNotEqual(mask_value("13812345678"), "13812345678")
        self.assertEqual(match_pii_type("13812345678"), "cn_mobile")

    def test_15_digit_chinese_id_masked(self):
        self.assertNotEqual(mask_value("110101900101123"), "110101900101123")
        self.assertEqual(match_pii_type("110101900101123"), "chinese_id")

    def test_ipv6_masked(self):
        for ip in ("2001:db8::8a2e:370:7334", "fe80::1", "::1"):
            self.assertNotEqual(mask_value(ip), ip, ip)
        self.assertEqual(match_pii_type("2001:db8::1"), "ipv6")

    def test_dob_now_actually_masked(self):
        # was defined but never wired into detection before v1.6.0
        self.assertEqual(mask_value("1990-01-15"), "****-**-15")
        self.assertEqual(match_pii_type("1990-01-15"), "date_of_birth")

    def test_mac_still_masks_as_mac_not_ipv6(self):
        self.assertEqual(mask_value("00:1B:44:11:3A:B7"), "00:1B:**:**:**:B7")

    def test_no_false_positives(self):
        # clock time, plain long number, software version — must NOT be masked
        for s in ("12:30:45", "20250101999", "10000000000"):
            self.assertEqual(mask_value(s), s, s)

    def test_new_keywords(self):
        from cloakpii.pii import _is_pii_field
        for kw in ("联系电话", "证件号", "卡号", "openid", "postcode"):
            self.assertTrue(_is_pii_field(kw), kw)


class TestXmlNamespaceDrop(unittest.TestCase):
    def test_namespaced_element_drop_policy_applies(self):
        tmp = Path(tempfile.mkdtemp())
        src = tmp / "in.xml"
        out = tmp / "out.xml"
        src.write_text('<root xmlns:p="http://ex.com/ns">'
                       '<p:salary>250000</p:salary><keep>ok</keep></root>')
        desensitize_xml(src, out, field_policies={"salary": "drop"})
        text = out.read_text()
        self.assertNotIn("250000", text)   # dropped, was leaking before
        self.assertIn("ok", text)


class TestStreamingHardening(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.salt = os.urandom(16)
        self.key = derive_key("pw", self.salt)

    def _enc(self, data, chunk_size=16):
        src = self.tmp / f"s{len(data)}.bin"
        src.write_bytes(data)
        enc = self.tmp / f"s{len(data)}.enc"
        encrypt_file_stream_with_key(src, enc, self.key, self.salt, chunk_size=chunk_size)
        return enc

    def test_empty_file_round_trip(self):
        enc = self._enc(b"")
        dec = self.tmp / "empty.dec"
        decrypt_file_stream_with_key(enc, dec, self.key)
        self.assertEqual(dec.read_bytes(), b"")

    def test_exact_chunk_boundary(self):
        data = b"A" * 32  # exactly 2 chunks of 16, no partial
        enc = self._enc(data, chunk_size=16)
        dec = self.tmp / "b.dec"
        decrypt_file_stream_with_key(enc, dec, self.key)
        self.assertEqual(dec.read_bytes(), data)

    def test_per_file_keys_independent(self):
        # same plaintext + same run key → different file_salt → different ciphertext
        data = b"X" * 100
        e1, e2 = self._enc(data), self._enc(data + b"!")
        self.assertNotEqual(e1.read_bytes()[24:40], e2.read_bytes()[24:40])

    def test_truncation_leaves_no_partial_plaintext(self):
        import glob
        enc = self._enc(b"Y" * 64, chunk_size=16)
        raw = enc.read_bytes()
        trunc = self.tmp / "t.enc"
        trunc.write_bytes(raw[: len(raw) - 30])  # drop terminator
        out = self.tmp / "t.out"
        with self.assertRaises(CryptoError):
            decrypt_file_stream_with_key(trunc, out, self.key)
        self.assertFalse(out.exists(), "partial plaintext left on disk")
        self.assertEqual(glob.glob(str(self.tmp / "*.dec.tmp")), [])

    def _records(self, raw):
        hdr = crypto._STREAM_HEADER_LEN
        header, body, recs = raw[:hdr], raw[hdr:], []
        i = 0
        while i < len(body):
            ln = int.from_bytes(body[i + 1:i + 5], "big")
            recs.append(body[i:i + 5 + ln])
            i += 5 + ln
        return header, recs

    def test_chunk_reorder_detected(self):
        enc = self._enc(b"Z" * 48, chunk_size=16)  # 3 data chunks + terminator
        header, recs = self._records(enc.read_bytes())
        recs[0], recs[1] = recs[1], recs[0]  # swap two data chunks
        bad = self.tmp / "reorder.enc"
        bad.write_bytes(header + b"".join(recs))
        with self.assertRaises(CryptoError):
            decrypt_file_stream_with_key(bad, self.tmp / "r.out", self.key)

    def test_fake_terminator_type_flip_detected(self):
        enc = self._enc(b"Q" * 48, chunk_size=16)
        header, recs = self._records(enc.read_bytes())
        recs[0] = b"\x01" + recs[0][1:]  # flip data chunk type to terminator
        bad = self.tmp / "flip.enc"
        bad.write_bytes(header + b"".join(recs))
        with self.assertRaises(CryptoError):
            decrypt_file_stream_with_key(bad, self.tmp / "f.out", self.key)


class TestDbQuote(unittest.TestCase):
    def test_quote_dialects(self):
        from cloakpii.db import DBError, _quote
        self.assertEqual(_quote("users", "mysql"), "`users`")
        self.assertEqual(_quote("users", "postgresql"), '"users"')
        self.assertEqual(_quote("users", "sqlite"), '"users"')
        with self.assertRaises(DBError):
            _quote("bad name", "sqlite")  # unsafe identifier


class TestConfidenceMediumBand(unittest.TestCase):
    def test_partial_match_is_medium(self):
        r = field_confidence("contact", ["a@x.com", "a@x.com", "plain", "text"])
        self.assertEqual(r["confidence"], CONFIDENCE_MEDIUM)


class TestTokenizeInMaskRun(unittest.TestCase):
    def test_per_field_tokenize_under_global_mask(self):
        from cloakpii.migrate import decrypt_tree, run_migration
        tmp = Path(tempfile.mkdtemp())
        src = tmp / "src"
        src.mkdir()
        out = tmp / "out"
        (src / "u.csv").write_text("email,phone\nwei@corp.cn,138-1234-5678\n")
        run_migration(source_dir=src, output_dir=out, password="pw", mode="mask",
                      field_policies={"email": "tokenize"},
                      show_progress=False, generate_manifest=False)
        dec = tmp / "dec"
        decrypt_tree(out / "encrypted", dec, "pw")
        content = (dec / "u.csv").read_text()
        self.assertIn("tkz_", content)          # email tokenized
        self.assertIn("*", content)             # phone masked
        self.assertNotIn("wei@corp.cn", content)


if __name__ == "__main__":
    unittest.main()
