import contextlib
import io
import os
import stat
import tempfile
import unittest

import RNS

import main


class PatternValidationTests(unittest.TestCase):
    def test_uppercase_is_normalized(self):
        self.assertEqual(
            main.normalize_and_validate_patterns("AB", "Cd"), ("ab", "cd")
        )

    def test_invalid_hex_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "hex characters only"):
            main.normalize_and_validate_patterns("0x12", "")

    def test_both_empty_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least one"):
            main.normalize_and_validate_patterns("", "")

    def test_individual_pattern_over_32_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "length must be"):
            main.normalize_and_validate_patterns("a" * 33, "")

    def test_combined_pattern_over_32_is_rejected_even_if_compatible(self):
        with self.assertRaisesRegex(ValueError, "combined prefix and postfix"):
            main.normalize_and_validate_patterns("a" * 32, "aa")

    def test_combined_pattern_of_32_is_accepted(self):
        prefix, postfix = main.normalize_and_validate_patterns("a" * 16, "B" * 16)
        self.assertEqual(len(prefix) + len(postfix), 32)

    def test_odd_nibble_patterns_are_supported(self):
        address = "a" + "0" * 30 + "f"
        self.assertTrue(main.matches_vanity(address, "a", "f"))

    def test_prefix_and_postfix_are_logical_and(self):
        matching = "ab" + "0" * 28 + "cd"
        wrong_postfix = "ab" + "0" * 28 + "ce"
        self.assertTrue(main.matches_vanity(matching, "ab", "cd"))
        self.assertFalse(main.matches_vanity(wrong_postfix, "ab", "cd"))

    def test_match_rejects_noncanonical_address_strings(self):
        self.assertFalse(main.matches_vanity("A" * 32, "a", ""))
        self.assertFalse(main.matches_vanity("a" * 31, "a", ""))
        self.assertFalse(main.matches_vanity("g" * 32, "", "g"))


class RNSCompatibilityTests(unittest.TestCase):
    def test_lxmf_hash_matches_both_official_helpers(self):
        identity = RNS.Identity(create_keys=True)
        expected = RNS.Destination.hash_from_name_and_identity(
            "lxmf.delivery", identity
        ).hex()
        actual = main.lxmf_hash_hex_for_identity(identity)
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 32)
        self.assertEqual(actual, actual.lower())

    def test_match_payload_is_independently_validated(self):
        identity = RNS.Identity(create_keys=True)
        private_key = identity.get_private_key()
        address = main.lxmf_hash_hex_for_identity(identity)
        validated = main.validate_match_payload(
            private_key, address, address[:2], address[-2:]
        )
        self.assertEqual(validated, (private_key, address))

        error = main.validate_match_payload(private_key, address, "ff", "")
        self.assertIsInstance(error, str)


class WorkerMessageTests(unittest.TestCase):
    def test_valid_match_wins_even_when_error_arrives_first(self):
        identity = RNS.Identity(create_keys=True)
        private_key = identity.get_private_key()
        address = main.lxmf_hash_hex_for_identity(identity)
        state = main.SearchState()

        main.record_worker_message(
            (main.MSG_ERROR, 1, "synthetic failure"), state, address[:1], address[-1:]
        )
        main.record_worker_message(
            (main.MSG_MATCH, 0, private_key, address),
            state,
            address[:1],
            address[-1:],
        )
        main.record_worker_message((main.MSG_PROGRESS, 0, 7), state, "", "")
        main.record_worker_message((main.MSG_DONE, 0), state, "", "")
        main.record_worker_message((main.MSG_DONE, 1), state, "", "")

        self.assertEqual(state.match_private_key, private_key)
        self.assertEqual(state.match_addr_hex, address)
        self.assertEqual(state.total_tries, 7)
        self.assertIn("synthetic failure", state.errors[0])
        self.assertEqual(state.done_workers, {0, 1})

    def test_malformed_and_duplicate_messages_are_errors(self):
        state = main.SearchState()
        main.record_worker_message((main.MSG_DONE, 0), state, "a", "")
        main.record_worker_message((main.MSG_DONE, 0), state, "a", "")
        main.record_worker_message(("unknown",), state, "a", "")
        self.assertEqual(len(state.errors), 2)


class SecureOutputTests(unittest.TestCase):
    def setUp(self):
        self.identity = RNS.Identity(create_keys=True)
        self.private_key = self.identity.get_private_key()

    def test_secure_write_is_mode_0600_and_rns_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity")
            saved = main.secure_write_identity(path, self.private_key)

            self.assertEqual(saved, path)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), self.private_key)

            reloaded = RNS.Identity.from_file(path)
            self.assertIsNotNone(reloaded)
            self.assertEqual(
                main.lxmf_hash_hex_for_identity(reloaded),
                main.lxmf_hash_hex_for_identity(self.identity),
            )
            self.assertEqual(os.listdir(directory), ["identity"])

    def test_secure_write_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity")
            main.secure_write_identity(path, self.private_key)
            with open(path, "rb") as handle:
                original = handle.read()

            other_key = RNS.Identity(create_keys=True).get_private_key()
            with self.assertRaisesRegex(RuntimeError, "Refusing to overwrite"):
                main.secure_write_identity(path, other_key)

            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), original)

    def test_secure_write_rejects_wrong_key_length(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity")
            with self.assertRaisesRegex(RuntimeError, "must be 64 bytes"):
                main.secure_write_identity(path, b"short")
            self.assertFalse(os.path.exists(path))


class OutputPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.identity = RNS.Identity(create_keys=True)
        self.private_key = self.identity.get_private_key()
        self.address = main.lxmf_hash_hex_for_identity(self.identity)

    def render(self, show_private):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            main.print_success(
                prefix_hex=self.address[:1],
                postfix_hex="",
                address_hex=self.address,
                private_key=self.private_key,
                saved_path="/tmp/identity",
                total_tries=1,
                count_exact=True,
                elapsed=1.0,
                show_private_import_strings=show_private,
            )
        return stream.getvalue()

    def test_private_key_encodings_are_hidden_by_default(self):
        output = self.render(False)
        self.assertNotIn(main.encode_base64(self.private_key), output)
        self.assertNotIn(main.encode_base32(self.private_key), output)
        self.assertNotIn("Generic private-key encodings", output)

    def test_private_key_encodings_require_explicit_opt_in(self):
        output = self.render(True)
        self.assertIn(main.encode_base64(self.private_key), output)
        self.assertIn(main.encode_base32(self.private_key), output)
        self.assertIn("do not log or share", output)


class CLITests(unittest.TestCase):
    def test_excessive_worker_count_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "range"):
            main.validate_workers(main.maximum_worker_count() + 1)

    def test_impractical_search_requires_force(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "identity")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = main.main(["--prefix", "a" * 9, "--out", output_path])
            self.assertEqual(result, 2)
            self.assertIn("Re-run with --force", stderr.getvalue())
            self.assertFalse(os.path.exists(output_path))

    def test_real_two_process_prefix_postfix_search_and_private_output_default(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "identity")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = main.main(
                    [
                        "--prefix",
                        "A",
                        "--postfix",
                        "F",
                        "--workers",
                        "2",
                        "--out",
                        output_path,
                    ]
                )

            self.assertEqual(result, 0, stderr.getvalue())
            reloaded = RNS.Identity.from_file(output_path)
            self.assertIsNotNone(reloaded)
            address = main.lxmf_hash_hex_for_identity(reloaded)
            self.assertTrue(address.startswith("a"))
            self.assertTrue(address.endswith("f"))
            self.assertNotIn(main.encode_base64(reloaded.get_private_key()), stdout.getvalue())
            self.assertNotIn(main.encode_base32(reloaded.get_private_key()), stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
