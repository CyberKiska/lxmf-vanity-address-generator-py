import contextlib
import io
import errno
import os
import subprocess
import sys
import tempfile
from pathlib import Path
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


class CoreDumpTests(unittest.TestCase):
    def test_soft_core_limit_is_zeroed_without_lowering_hard_limit(self):
        resource = mock.Mock(RLIMIT_CORE=4)
        resource.getrlimit.return_value = (1024, 4096)
        with mock.patch.dict(sys.modules, {"resource": resource}):
            main.disable_core_dumps()
        resource.setrlimit.assert_called_once_with(4, (0, 4096))

    def test_unavailable_or_failed_resource_control_is_best_effort(self):
        with mock.patch.dict(sys.modules, {"resource": None}):
            main.disable_core_dumps()
        for error in (OSError("unavailable"), ValueError("unsupported limit")):
            resource = mock.Mock()
            resource.getrlimit.side_effect = error
            with mock.patch.dict(sys.modules, {"resource": resource}):
                main.disable_core_dumps()
            resource.getrlimit.side_effect = None
            resource.getrlimit.return_value = (1, 10)
            resource.setrlimit.side_effect = error
            with mock.patch.dict(sys.modules, {"resource": resource}):
                main.disable_core_dumps()

    @unittest.skipUnless(os.name == "posix", "POSIX resource limits required")
    def test_effective_limit_in_disposable_subprocess(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import resource, main; before = resource.getrlimit(resource.RLIMIT_CORE); main.disable_core_dumps(); after = resource.getrlimit(resource.RLIMIT_CORE); assert after == (0, before[1])",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_parent_and_worker_suppress_cores_before_generating_keys(self):
        with mock.patch.object(main, "disable_core_dumps") as disable:

            def check_startup():
                disable.assert_called_once()
                raise ValueError("stop before generation")

            with (
                mock.patch.object(
                    main, "validate_runtime_environment", side_effect=check_startup
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main.main(["--prefix=a", "--out=identity"]), 2)
        cancel = mock.Mock()
        cancel.poll.return_value = True
        with mock.patch.object(main, "disable_core_dumps") as disable:
            main.worker(0, "a", "", cancel, mock.Mock())
            disable.assert_called_once()


class FullFlushTests(unittest.TestCase):
    def test_full_flush_runs_after_fsync_on_macos_only(self):
        events = []
        fcntl = mock.Mock(F_FULLFSYNC=51)
        fcntl.fcntl.side_effect = lambda *args: events.append("full flush")
        for platform, expected in (
            ("darwin", ["fsync", "full flush"]),
            ("linux", ["fsync"]),
            ("win32", ["fsync"]),
        ):
            events.clear()
            with (
                self.subTest(platform=platform),
                mock.patch.object(main.sys, "platform", platform),
                mock.patch.object(main, "fcntl", fcntl, create=True),
                mock.patch.object(
                    os, "fsync", side_effect=lambda fd: events.append("fsync")
                ),
            ):
                main._flush_fd(42)
            self.assertEqual(events, expected)

    def test_absent_and_unsupported_full_flush_warn_after_fsync(self):
        for error in (None, errno.EINVAL, errno.ENOTSUP, errno.ENOSYS, errno.ENOTTY):
            fcntl = mock.Mock(F_FULLFSYNC=51) if error is not None else None
            if fcntl is not None:
                fcntl.fcntl.side_effect = OSError(error, "unsupported")
            with (
                self.subTest(errno=error),
                mock.patch.object(main.sys, "platform", "darwin"),
                mock.patch.object(main, "fcntl", fcntl, create=True),
                mock.patch.object(os, "fsync") as fsync,
                contextlib.redirect_stderr(io.StringIO()) as stderr,
            ):
                main._flush_fd(42)
            fsync.assert_called_once_with(42)
            self.assertIn("WARNING:", stderr.getvalue())

    def test_full_flush_io_errors_abort_preflight_without_leaving_files(self):
        for error in (errno.EIO, errno.ENOSPC):
            fcntl = mock.Mock(F_FULLFSYNC=51)
            fcntl.fcntl.side_effect = OSError(error, "full flush I/O failure")
            with (
                self.subTest(errno=error),
                tempfile.TemporaryDirectory() as directory,
                mock.patch.object(main.sys, "platform", "darwin"),
                mock.patch.object(main, "fcntl", fcntl, create=True),
            ):
                with self.assertRaisesRegex(ValueError, "full flush I/O failure"):
                    main.prepare_output_staging(directory + "/identity")
                self.assertEqual(os.listdir(directory), [])

    def test_full_flush_failure_during_copy_publication_preserves_winner(self):
        identity = RNS.Identity(create_keys=True)
        key, address = (
            identity.get_private_key(),
            main.lxmf_hash_hex_for_identity(identity),
        )
        for error in (errno.EIO, errno.ENOSPC):
            with self.subTest(errno=error), tempfile.TemporaryDirectory() as directory:
                staging = main.prepare_output_staging(directory + "/identity")
                try:
                    staging.write_private_key(key)
                    staging.publish_mode = main.PUBLISH_EXCLUSIVE_COPY
                    fcntl = mock.Mock(F_FULLFSYNC=51)
                    fcntl.fcntl.side_effect = OSError(error, "full flush I/O failure")
                    with (
                        mock.patch.object(main.sys, "platform", "darwin"),
                        mock.patch.object(main, "fcntl", fcntl, create=True),
                    ):
                        with self.assertRaisesRegex(
                            main.OutputWriteError, "full flush I/O failure"
                        ):
                            staging.write_and_publish(key, address)
                    self.assertFalse(os.path.lexists(directory + "/identity"))
                finally:
                    recovery = staging.cleanup()
                self.assertTrue(
                    RNS.Identity.from_file(recovery).get_private_key() == key,
                    "recovery key differs",
                )

    def test_ordinary_fsync_failure_prevents_full_flush(self):
        fcntl = mock.Mock(F_FULLFSYNC=51)
        with (
            mock.patch.object(main.sys, "platform", "darwin"),
            mock.patch.object(main, "fcntl", fcntl, create=True),
            mock.patch.object(
                os, "fsync", side_effect=OSError(errno.EIO, "I/O failure")
            ),
        ):
            with self.assertRaises(OSError):
                main._flush_fd(42)
        fcntl.fcntl.assert_not_called()

    def test_full_flush_failure_in_cli_keeps_recovery_without_success(self):
        for error in (errno.EIO, errno.ENOSPC):
            with self.subTest(errno=error), tempfile.TemporaryDirectory() as directory:
                fcntl = mock.Mock(F_FULLFSYNC=51)

                def fail_key_flush(fd, command):
                    if os.fstat(fd).st_size == 64:
                        raise OSError(error, "full flush I/O failure")

                fcntl.fcntl.side_effect = fail_key_flush
                stdout, stderr = io.StringIO(), io.StringIO()
                with (
                    mock.patch.object(main.sys, "platform", "darwin"),
                    mock.patch.object(main, "fcntl", fcntl),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    result = main.main(
                        [
                            "--prefix=a",
                            "--workers=1",
                            "--out=" + directory + "/identity",
                        ]
                    )
                self.assertEqual(result, 1)
                self.assertNotIn("Identity Found", stdout.getvalue())
                self.assertIn("RECOVERY:", stderr.getvalue())
                self.assertFalse(os.path.lexists(directory + "/identity"))
                recovery = list(Path(directory).glob("*.staging"))
                self.assertEqual(len(recovery), 1)
                self.assertIsNotNone(RNS.Identity.from_file(str(recovery[0])))
