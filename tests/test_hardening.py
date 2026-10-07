import contextlib
import io
import os
import subprocess
import sys
import tempfile
import hashlib

import RNS
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


class PrivateVectorTests(unittest.TestCase):
    def test_private_compatibility_vector_matches_rfc_keys_and_formula(self):
        # RFC 7748 section 6.1 and RFC 8032 section 7.1 (TEST 1) public keys.
        self.assertEqual(
            main.COMPAT_PRIVATE_KEY_PUBLIC.hex(),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        identity = RNS.Identity.from_bytes(main.COMPAT_PRIVATE_KEY)
        self.assertEqual(identity.get_public_key(), main.COMPAT_PRIVATE_KEY_PUBLIC)
        identity_hash = hashlib.sha256(main.COMPAT_PRIVATE_KEY_PUBLIC).digest()[:16]
        name_hash = hashlib.sha256(b"lxmf.delivery").digest()[:10]
        expected = hashlib.sha256(name_hash + identity_hash).digest()[:16].hex()
        self.assertEqual(main.COMPAT_PRIVATE_KEY_LXMF_HASH, expected)
        self.assertEqual(main.lxmf_hash_hex_for_identity(identity), expected)

    def test_runtime_rejects_private_key_vector_regression(self):
        with mock.patch.object(main, "COMPAT_PRIVATE_KEY_PUBLIC", bytes(64)):
            with self.assertRaisesRegex(ValueError, "RFC 7748/8032"):
                main.validate_runtime_environment()


class ReferenceInteropTests(unittest.TestCase):
    def test_official_rnid_derives_the_same_address_from_the_saved_file(self):
        identity = RNS.Identity(create_keys=True)
        expected = main.lxmf_hash_hex_for_identity(identity)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity")
            staging = main.prepare_output_staging(path)
            try:
                staging.write_and_publish(identity.get_private_key(), expected)
                staging.finalize()
            finally:
                staging.cleanup()
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "RNS.Utilities.rnid",
                    "--config",
                    os.path.join(directory, "unused-rns-config"),
                    "-i",
                    path,
                    "-H",
                    "lxmf.delivery",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            output = completed.stdout + completed.stderr
            self.assertEqual(completed.returncode, 0, output)
            self.assertIn(f"<{expected}>", completed.stdout)
            # rnid must not have needed a Reticulum instance for this.
            self.assertEqual(os.listdir(directory), ["identity"])


class KeyGenerationTests(unittest.TestCase):
    def test_runtime_rejects_repeated_identity_halves_and_malformed_second_key(self):
        identity = RNS.Identity(create_keys=True)
        other = RNS.Identity(create_keys=True)
        key, other_key = identity.get_private_key(), other.get_private_key()
        cases = (
            ("whole identity", key, "repeated key material"),
            ("X25519 half", key[:32] + other_key[32:], "repeated key material"),
            ("Ed25519 half", other_key[:32] + key[32:], "repeated key material"),
            ("cross half", other_key[:32] + key[:32], "repeated key material"),
            ("short key", b"short", "64-byte key"),
            ("non-bytes key", None, "64-byte key"),
        )
        for label, second_key, message in cases:
            second = mock.Mock()
            second.get_private_key.return_value = second_key
            with (
                self.subTest(case=label),
                mock.patch.object(main, "gen_identity", side_effect=[identity, second]),
            ):
                with self.assertRaisesRegex(ValueError, message):
                    main.validate_runtime_environment()

    def test_workers_are_spawned_never_forked(self):
        handle = main.start_worker(0, "0" * 32, "")
        try:
            self.assertEqual(type(handle.process).__name__, "SpawnProcess")
        finally:
            state = main.SearchState()
            main.collect_worker_shutdown(
                [handle], state, "0" * 32, "", report_missing=False
            )
            handle.cancel.close()
            handle.messages.close()
            handle.process.close()
