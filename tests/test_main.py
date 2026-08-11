import contextlib
import hashlib
import io
import os
import queue
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import RNS

import main


class PatternValidationTests(unittest.TestCase):
    def test_uppercase_is_normalized(self):
        self.assertEqual(main.normalize_and_validate_patterns("AB", "Cd"), ("ab", "cd"))

    def test_invalid_hex_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "hex characters only"):
            main.normalize_and_validate_patterns("0x12", "")

    def test_both_empty_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least one"):
            main.normalize_and_validate_patterns("", "")

    def test_individual_pattern_over_32_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "length must be"):
            main.normalize_and_validate_patterns("a" * 33, "")

    def test_compatible_overlapping_patterns_are_accepted(self):
        prefix, postfix = main.normalize_and_validate_patterns("a" * 24, "A" * 16)
        self.assertEqual(prefix, "a" * 24)
        self.assertEqual(postfix, "a" * 16)
        self.assertEqual(main.constrained_positions(prefix, postfix), 32)

    def test_contradictory_overlapping_patterns_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "contradictory.*overlap"):
            main.normalize_and_validate_patterns("a" * 24, "b" * 16)

    def test_full_overlapping_patterns_must_be_identical(self):
        pattern = "0123456789abcdef" * 2
        self.assertEqual(
            main.normalize_and_validate_patterns(pattern, pattern),
            (pattern, pattern),
        )
        with self.assertRaisesRegex(ValueError, "contradictory"):
            main.normalize_and_validate_patterns(pattern, "f" + pattern[1:])

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

    def test_lxmf_hash_matches_reference_formula(self):
        identity = RNS.Identity(create_keys=True)
        identity_hash = hashlib.sha256(identity.get_public_key()).digest()[:16]
        name_hash = hashlib.sha256(b"lxmf.delivery").digest()[:10]
        expected = hashlib.sha256(name_hash + identity_hash).digest()[:16].hex()
        self.assertEqual(identity.hash, identity_hash)
        self.assertEqual(main.lxmf_hash_hex_for_identity(identity), expected)

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

    def test_out_of_range_and_boolean_worker_ids_are_rejected(self):
        state = main.SearchState()
        main.record_worker_message(
            (main.MSG_PROGRESS, 2, 1), state, "a", "", worker_count=2
        )
        main.record_worker_message(
            (main.MSG_DONE, True), state, "a", "", worker_count=2
        )
        self.assertEqual(len(state.errors), 2)
        self.assertEqual(state.total_tries, 0)
        self.assertFalse(state.done_workers)


class SecureOutputTests(unittest.TestCase):
    def setUp(self):
        self.identity = RNS.Identity(create_keys=True)
        self.private_key = self.identity.get_private_key()

    def test_secure_write_is_mode_0600_and_rns_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity")
            saved = main.secure_write_identity(path, self.private_key)

            self.assertEqual(saved, path)
            if os.name == "posix":
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

    def test_long_valid_final_basename_uses_short_staging_name(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "x" * 242)
            saved = main.secure_write_identity(path, self.private_key)
            self.assertEqual(saved, path)
            self.assertEqual(
                RNS.Identity.from_file(saved).get_private_key(), self.private_key
            )
            self.assertEqual(os.listdir(directory), ["x" * 242])

    @unittest.skipUnless(hasattr(os, "pathconf"), "pathconf is not available")
    def test_overlong_final_basename_fails_during_preflight(self):
        with tempfile.TemporaryDirectory() as directory:
            name_max = os.pathconf(directory, "PC_NAME_MAX")
            path = os.path.join(directory, "x" * (name_max + 1))
            with self.assertRaisesRegex(ValueError, "could not prepare private output"):
                main.prepare_output_staging(path)
            self.assertEqual(os.listdir(directory), [])

    def test_output_race_preserves_winning_identity_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity")
            staging = main.prepare_output_staging(path)
            staging.write_private_key(self.private_key)

            competitor = b"competitor-owned output"
            with open(path, "wb") as handle:
                handle.write(competitor)

            with self.assertRaisesRegex(main.OutputWriteError, "preserved"):
                staging.publish()

            recovery_path = staging.cleanup()
            self.assertEqual(recovery_path, staging.staging_path)
            self.assertTrue(os.path.exists(recovery_path))
            self.assertEqual(
                RNS.Identity.from_file(recovery_path).get_private_key(),
                self.private_key,
            )
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), competitor)

    def test_hard_link_unsupported_uses_exclusive_copy_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity")
            with mock.patch.object(
                main, "_link_without_following", side_effect=OSError("unsupported")
            ):
                staging = main.prepare_output_staging(path)

            self.assertEqual(staging.publish_mode, main.PUBLISH_EXCLUSIVE_COPY)
            self.assertFalse(os.path.lexists(path))
            staging.write_private_key(self.private_key)
            self.assertEqual(staging.publish(), path)
            self.assertIsNone(staging.finalize())
            self.assertIsNone(staging.cleanup())
            self.assertEqual(
                RNS.Identity.from_file(path).get_private_key(), self.private_key
            )

    def test_preflight_never_places_marker_at_final_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity")
            observed_destinations = []
            original_link = main._link_without_following

            def observe_link(source, destination):
                self.assertFalse(os.path.lexists(path))
                self.assertNotEqual(destination, path)
                observed_destinations.append(destination)
                original_link(source, destination)

            with mock.patch.object(
                main, "_link_without_following", side_effect=observe_link
            ):
                staging = main.prepare_output_staging(path)

            self.assertTrue(observed_destinations)
            self.assertFalse(os.path.lexists(path))
            self.assertFalse(os.path.lexists(observed_destinations[0]))
            self.assertIsNone(staging.cleanup())

    def test_unused_staging_file_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity")
            staging = main.prepare_output_staging(path)
            staging_path = staging.staging_path
            self.assertTrue(os.path.exists(staging_path))
            self.assertFalse(os.get_inheritable(staging.fd))
            self.assertIsNone(staging.cleanup())
            self.assertFalse(os.path.exists(staging_path))
            self.assertFalse(os.path.exists(path))

    def test_failed_staging_cleanup_returns_path_for_operator_action(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity")
            staging = main.prepare_output_staging(path)
            with mock.patch.object(os, "unlink", side_effect=PermissionError("denied")):
                self.assertEqual(staging.cleanup(), staging.staging_path)

    def test_output_path_rejects_embedded_nul_cleanly(self):
        with self.assertRaisesRegex(ValueError, "NUL"):
            main.validate_output_path("invalid\0path")

    def test_output_path_rejects_terminal_control_characters(self):
        with self.assertRaisesRegex(ValueError, "control"):
            main.validate_output_path("invalid\npath")

    def test_interrupted_key_write_preserves_private_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity")
            staging = main.prepare_output_staging(path)
            original_write_all = main._write_all

            def write_then_interrupt(fd, data):
                original_write_all(fd, data)
                raise KeyboardInterrupt

            with mock.patch.object(
                main, "_write_all", side_effect=write_then_interrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    staging.write_private_key(self.private_key)

            recovery_path = staging.cleanup()
            self.assertEqual(recovery_path, staging.staging_path)
            self.assertFalse(os.path.exists(path))
            with open(recovery_path, "rb") as handle:
                self.assertEqual(handle.read(len(self.private_key)), self.private_key)

    def test_interrupted_hard_link_publication_rolls_back_final_name(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity")
            staging = main.prepare_output_staging(path)
            staging.write_private_key(self.private_key)
            if staging.publish_mode != main.PUBLISH_HARD_LINK:
                self.skipTest("secure hard-link publication is unavailable")

            def link_then_interrupt(source, destination):
                os.link(source, destination)
                raise KeyboardInterrupt

            with mock.patch.object(
                main, "_link_without_following", side_effect=link_then_interrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    staging.publish()

            self.assertFalse(os.path.exists(path))
            self.assertEqual(staging.cleanup(), staging.staging_path)

    def test_interrupted_exclusive_copy_removes_partial_final(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity")
            with mock.patch.object(
                main, "_link_without_following", side_effect=OSError("unsupported")
            ):
                staging = main.prepare_output_staging(path)
            staging.write_private_key(self.private_key)
            original_write_all = main._write_all

            def write_then_interrupt(fd, data):
                original_write_all(fd, data)
                raise KeyboardInterrupt

            with mock.patch.object(
                main, "_write_all", side_effect=write_then_interrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    staging.publish()

            self.assertFalse(os.path.exists(path))
            self.assertEqual(staging.cleanup(), staging.staging_path)

    @unittest.skipUnless(hasattr(os, "fchmod"), "fchmod is not available")
    def test_interrupted_exclusive_create_removes_owned_empty_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity")
            with mock.patch.object(os, "fchmod", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    main._exclusive_output_fd(path)
            self.assertFalse(os.path.lexists(path))

    def test_interrupted_finalize_keeps_staging_recoverable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity")
            staging = main.prepare_output_staging(path)
            staging.write_private_key(self.private_key)
            staging.publish()

            with mock.patch.object(os, "unlink", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    staging.finalize()

            self.assertTrue(os.path.exists(path))
            self.assertEqual(staging.cleanup(), staging.staging_path)


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

    def test_base64_encoding_is_rnid_url_safe(self):
        self.assertEqual(main.encode_base64(b"\xfb\xff"), "-_8=")


class CLITests(unittest.TestCase):
    def test_excessive_worker_count_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "range"):
            main.validate_workers(main.maximum_worker_count() + 1)
        with self.assertRaisesRegex(ValueError, "integer"):
            main.validate_workers(True)

    def test_high_cpu_default_uses_conservative_cap(self):
        with mock.patch.object(main, "available_cpu_count", return_value=512):
            args = main.build_parser().parse_args(["--prefix=a", "--out=identity"])
        self.assertEqual(args.workers, main.DEFAULT_MAX_WORKERS)

    def test_output_path_is_required_and_option_abbreviations_are_disabled(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaisesRegex(SystemExit, "2"):
                main.build_parser().parse_args(["--prefix=a"])
            with self.assertRaisesRegex(SystemExit, "2"):
                main.build_parser().parse_args(["--post=a", "--out=identity"])

    def test_runtime_accepts_compatible_public_api(self):
        description = main.validate_runtime_environment()
        self.assertIn("PyCA cryptography", description)

    def test_runtime_accepts_compatible_rns_update(self):
        with mock.patch.object(main, "rns_version", return_value="1.9.0"):
            description = main.validate_runtime_environment()
        self.assertIn("PyCA cryptography", description)

    def test_runtime_enforces_supported_version_ranges(self):
        with mock.patch.object(main, "rns_version", return_value="1.4.1"):
            with self.assertRaisesRegex(ValueError, "expected >=1.4.2,<2.0"):
                main.validate_runtime_environment()
        with mock.patch.object(main, "rns_version", return_value="2.0.0"):
            with self.assertRaisesRegex(ValueError, "expected >=1.4.2,<2.0"):
                main.validate_runtime_environment()
        with mock.patch.object(main, "cryptography_version", return_value="49.0.0"):
            with self.assertRaisesRegex(ValueError, "expected >=50.0.0"):
                main.validate_runtime_environment()

    def test_runtime_rejects_shadowed_rns_import(self):
        with mock.patch.object(main.RNS, "__file__", "/tmp/shadowed/RNS.py"):
            with self.assertRaisesRegex(ValueError, "does not come from"):
                main.validate_runtime_environment()

    def test_runtime_rejects_incompatible_hash_size(self):
        with mock.patch.object(main.RNS.Reticulum, "TRUNCATED_HASHLENGTH", 256):
            with self.assertRaisesRegex(ValueError, "expected 128 bits"):
                main.validate_runtime_environment()

    def test_runtime_rejects_incompatible_lxmf_derivation(self):
        with mock.patch.object(
            main, "lxmf_hash_hex_for_identity", return_value="0" * 32
        ):
            with self.assertRaisesRegex(ValueError, "derivation is incompatible"):
                main.validate_runtime_environment()

    def test_invalid_cli_is_reported_before_runtime_self_test(self):
        stderr = io.StringIO()
        with (
            mock.patch.object(
                main,
                "validate_runtime_environment",
                side_effect=AssertionError("runtime check should not run"),
            ),
            contextlib.redirect_stderr(stderr),
        ):
            result = main.main(["--prefix", "not-hex", "--out", "identity"])
        self.assertEqual(result, 2)
        self.assertIn("hex characters only", stderr.getvalue())

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

    def test_compatible_full_target_reaches_generation_when_forced(self):
        pattern = "0123456789abcdef" * 2
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "identity")
            with mock.patch.object(main, "run_generation", return_value=0) as run:
                result = main.main(
                    [
                        "--prefix",
                        pattern.upper(),
                        "--postfix",
                        pattern,
                        "--force",
                        "--out",
                        output_path,
                    ]
                )
        self.assertEqual(result, 0)
        self.assertEqual(run.call_args.args[1:3], (pattern, pattern))

    def test_real_two_process_prefix_postfix_search_and_private_output(self):
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
            self.assertNotIn(
                main.encode_base64(reloaded.get_private_key()), stdout.getvalue()
            )
            self.assertNotIn(
                main.encode_base32(reloaded.get_private_key()), stdout.getvalue()
            )

    def test_real_postfix_only_search(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "identity")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = main.main(
                    ["--postfix", "A", "--workers", "1", "--out", output_path]
                )
            self.assertEqual(result, 0, stderr.getvalue())
            identity = RNS.Identity.from_file(output_path)
            self.assertTrue(main.lxmf_hash_hex_for_identity(identity).endswith("a"))


class WorkerLifecycleTests(unittest.TestCase):
    class FakeProcess:
        def __init__(self, alive, exitcode):
            self._alive = alive
            self.exitcode = exitcode

        def is_alive(self):
            return self._alive

    class EmptyQueue:
        def get(self, timeout):
            raise queue.Empty

    class BusyQueue:
        def __init__(self):
            self.calls = 0

        def get(self, timeout):
            self.calls += 1
            return (main.MSG_PROGRESS, 1, 1)

    class StopEvent:
        def set(self):
            pass

    class UnstoppableProcess:
        name = "unstoppable"
        exitcode = None

        def is_alive(self):
            return True

        def join(self, timeout):
            pass

        def kill(self):
            pass

    def test_partial_hard_worker_exit_is_detected(self):
        state = main.SearchState()
        procs = [self.FakeProcess(False, 9), self.FakeProcess(True, None)]
        with mock.patch.object(main, "WORKER_EXIT_GRACE", 0):
            main.wait_for_search_trigger(
                procs,
                self.EmptyQueue(),
                state,
                "a",
                "",
                0.0,
                16,
            )
        self.assertRegex(state.errors[0], "worker 0 exited unexpectedly.*code 9")

    def test_hard_worker_exit_is_detected_while_queue_stays_busy(self):
        state = main.SearchState()
        procs = [self.FakeProcess(False, 9), self.FakeProcess(True, None)]
        busy_queue = self.BusyQueue()
        with (
            mock.patch.object(main, "WORKER_EXIT_GRACE", 0),
            mock.patch.object(main, "WORKER_HEALTH_INTERVAL", 0),
        ):
            main.wait_for_search_trigger(
                procs,
                busy_queue,
                state,
                "a",
                "",
                0.0,
                16,
            )
        self.assertEqual(busy_queue.calls, 1)
        self.assertRegex(state.errors[0], "worker 0 exited unexpectedly.*code 9")

    def test_shutdown_refuses_to_continue_with_live_worker(self):
        state = main.SearchState()
        with mock.patch.object(main, "SHUTDOWN_TIMEOUT", 0):
            with self.assertRaisesRegex(RuntimeError, "did not stop"):
                main.collect_worker_shutdown(
                    [self.UnstoppableProcess()],
                    self.StopEvent(),
                    self.EmptyQueue(),
                    state,
                    "a",
                    "",
                )


@unittest.skipUnless(os.name == "posix", "POSIX signal semantics required")
class SignalIntegrationTests(unittest.TestCase):
    def run_until_signal(self, requested_signal, expected_exit_code):
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "identity")
            process = subprocess.Popen(
                [
                    sys.executable,
                    os.path.abspath(main.__file__),
                    "--prefix",
                    "0" * 32,
                    "--force",
                    "--workers",
                    "1",
                    "--out",
                    output_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    staging_files = [
                        name
                        for name in os.listdir(directory)
                        if name.startswith(main.OUTPUT_STAGING_PREFIX)
                    ]
                    if staging_files:
                        break
                    if process.poll() is not None:
                        break
                    time.sleep(0.02)

                self.assertIsNone(process.poll(), "generator exited before signal")
                self.assertTrue(staging_files, "output preflight did not complete")
                process.send_signal(requested_signal)
                stdout, stderr = process.communicate(timeout=15)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

            self.assertEqual(
                process.returncode,
                expected_exit_code,
                f"stdout={stdout!r}\nstderr={stderr!r}",
            )
            self.assertFalse(os.path.lexists(output_path))
            self.assertFalse(
                any(
                    name.startswith(main.OUTPUT_STAGING_PREFIX)
                    for name in os.listdir(directory)
                )
            )

    def test_sigint_is_coordinated_and_returns_130(self):
        self.run_until_signal(signal.SIGINT, 130)

    def test_sigterm_is_coordinated_and_returns_143(self):
        self.run_until_signal(signal.SIGTERM, 143)


if __name__ == "__main__":
    unittest.main()
