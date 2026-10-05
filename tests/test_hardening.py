import contextlib
import io
import unittest
from unittest import mock

import main


class CompatibilityPolicyTests(unittest.TestCase):
    def test_runtime_is_gated_by_behaviour_not_version_strings(self):
        for reported in ("0.0.1", "2.0.0", "9.9.9rc1", "unknown"):
            with (
                self.subTest(version=reported),
                mock.patch.object(main.RNS, "__version__", reported),
            ):
                self.assertIn("crypto backend", main.validate_runtime_environment())

    def test_missing_reference_api_reports_cli_compatibility_error(self):
        for name in ("Identity", "Reticulum"):
            with (
                self.subTest(api=name),
                mock.patch.object(main.RNS, name, None),
                contextlib.redirect_stderr(io.StringIO()) as stderr,
            ):
                result = main.main(["--prefix=a", "--out=identity"])
            self.assertEqual(result, 2)
            self.assertIn("incompatible RNS", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_missing_or_incompatible_constants_fail_closed(self):
        for api, name, value in (
            (main.RNS.Identity, "KEYSIZE", None),
            (main.RNS.Identity, "KEYSIZE", 256),
            (main.RNS.Reticulum, "TRUNCATED_HASHLENGTH", None),
        ):
            with (
                self.subTest(constant=name, value=value),
                mock.patch.object(api, name, value),
            ):
                with self.assertRaisesRegex(ValueError, "incompatible RNS"):
                    main.validate_runtime_environment()

    def test_informational_backend_failure_does_not_gate_compatibility(self):
        with mock.patch.object(
            main.RNS.Cryptography, "backend", side_effect=AttributeError
        ):
            self.assertEqual(main.crypto_backend(), "unknown")
            self.assertIn("crypto backend", main.validate_runtime_environment())
