"""Optional format backends (parquet/excel) — helpful error when missing."""

import subprocess
import sys
import unittest

from cloakpii._deps import require


class TestRequire(unittest.TestCase):
    def test_present_module_returns(self):
        mod = require("json", "parquet")  # json always exists
        self.assertTrue(hasattr(mod, "loads"))

    def test_missing_module_names_the_extra(self):
        with self.assertRaises(ImportError) as ctx:
            require("definitely_not_a_real_module_xyz", "parquet")
        msg = str(ctx.exception)
        self.assertIn("parquet", msg)
        self.assertIn("cloakpii[parquet]", msg)

    def test_base_import_is_lazy(self):
        # Fresh interpreter: importing the core modules must not eagerly pull the
        # heavy optional backends. (Checked in a subprocess so other tests that
        # already imported pyarrow/openpyxl don't pollute sys.modules.)
        code = (
            "import sys, cloakpii, cloakpii.pii, cloakpii.migrate, cloakpii.cli;"
            "print('pyarrow' in sys.modules, 'openpyxl' in sys.modules)"
        )
        out = subprocess.run([sys.executable, "-c", code],
                             capture_output=True, text=True, check=True).stdout
        self.assertEqual(out.strip(), "False False")


if __name__ == "__main__":
    unittest.main()
