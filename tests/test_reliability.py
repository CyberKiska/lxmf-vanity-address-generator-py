import contextlib
import errno
import io
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest import mock

import RNS
import main


class MatchPreservationTests(unittest.TestCase):
    """Handled shutdown/reporting failures must not discard a verified winner."""

    def run_main(self, directory, *patches, stdout=None, stderr=None):
        stdout = io.StringIO() if stdout is None else stdout
        stderr = io.StringIO() if stderr is None else stderr
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            stack.enter_context(contextlib.redirect_stdout(stdout))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            result = main.main(
                ["--prefix=a", "--workers=1", "--out=" + directory + "/identity"]
            )
        return result, stdout, stderr

    def assert_saved(self, directory):
        identity = RNS.Identity.from_file(os.path.join(directory, "identity"))
        self.assertIsNotNone(identity)
        self.assertTrue(main.lxmf_hash_hex_for_identity(identity).startswith("a"))
        self.assertEqual(os.listdir(directory), ["identity"])

    def test_shutdown_oserror_keeps_recovery_and_failure_status(self):
        real_collect = main.collect_worker_shutdown

        def collect_then_fail(*args, **kwargs):
            real_collect(*args, **kwargs)
            raise OSError(errno.EIO, "shutdown I/O failure")

        with tempfile.TemporaryDirectory() as directory:
            result, stdout, stderr = self.run_main(
                directory,
                mock.patch.object(
                    main, "collect_worker_shutdown", side_effect=collect_then_fail
                ),
            )
            self.assertEqual(result, 1)
            self.assertNotIn("Identity Found", stdout.getvalue())
            self.assertIn("RECOVERY:", stderr.getvalue())
            recovery = list(Path(directory).glob("*.staging"))
            self.assertEqual(len(recovery), 1)
            identity = RNS.Identity.from_file(str(recovery[0]))
            self.assertIsNotNone(identity)
            self.assertTrue(main.lxmf_hash_hex_for_identity(identity).startswith("a"))
            self.assertFalse(os.path.lexists(directory + "/identity"))

    def test_partial_staging_write_is_preserved_without_retry(self):
        real_write = main._write_all
        key_writes = 0

        def fail_key_write(fd, data):
            nonlocal key_writes
            if len(data) == 64:
                key_writes += 1
                os.write(fd, data[:8])
                raise OSError(errno.ENOSPC, "disk full")
            real_write(fd, data)

        with tempfile.TemporaryDirectory() as directory:
            result, stdout, stderr = self.run_main(
                directory,
                mock.patch.object(main, "_write_all", side_effect=fail_key_write),
            )
            self.assertEqual(result, 1)
            self.assertEqual(key_writes, 1)
            self.assertNotIn("Identity Found", stdout.getvalue())
            self.assertIn("RECOVERY: possible private-key staging", stderr.getvalue())
            self.assertEqual(len(list(Path(directory).glob("*.staging"))), 1)
            self.assertFalse(os.path.lexists(directory + "/identity"))

    def test_staging_flush_failure_keeps_complete_key_without_success(self):
        real_fsync = os.fsync

        def fail_key_flush(fd):
            if os.fstat(fd).st_size == 64:
                raise OSError(errno.EIO, "staging flush failed")
            real_fsync(fd)

        with tempfile.TemporaryDirectory() as directory:
            result, stdout, stderr = self.run_main(
                directory, mock.patch.object(os, "fsync", side_effect=fail_key_flush)
            )
            self.assertEqual(result, 1)
            self.assertNotIn("Identity Found", stdout.getvalue())
            self.assertIn("RECOVERY:", stderr.getvalue())
            recovery = list(Path(directory).glob("*.staging"))
            self.assertEqual(len(recovery), 1)
            self.assertIsNotNone(RNS.Identity.from_file(str(recovery[0])))

    def test_late_match_survives_handle_and_staging_close_failures(self):
        identity = RNS.Identity(create_keys=True)
        key, address = (
            identity.get_private_key(),
            main.lxmf_hash_hex_for_identity(identity),
        )
        handle = main.WorkerHandle(mock.Mock(), mock.Mock(), mock.Mock())
        handle.process.is_alive.return_value = False
        handle.process.close.side_effect = ValueError("process close failed")
        handle.messages.close.side_effect = OSError("pipe close failed")

        def late_match(workers, state, prefix, postfix, **kwargs):
            main.record_worker_message(
                (main.MSG_MATCH, 0, key, address), state, prefix, postfix, 1
            )

        real_close = main.OutputStaging._close_fd

        def close_then_fail(staging):
            real_close(staging)
            raise OSError("staging close failed")

        with tempfile.TemporaryDirectory() as directory:
            stdout, stderr = io.StringIO(), io.StringIO()
            with (
                mock.patch.object(main, "start_worker", return_value=handle),
                mock.patch.object(main, "receive_worker_messages"),
                mock.patch.object(
                    main, "wait_for_search_trigger", side_effect=KeyboardInterrupt
                ),
                mock.patch.object(
                    main, "collect_worker_shutdown", side_effect=late_match
                ),
                mock.patch.object(
                    main.OutputStaging,
                    "_close_fd",
                    side_effect=close_then_fail,
                    autospec=True,
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                result = main.main(
                    [
                        "--prefix=" + address,
                        "--force",
                        "--workers=1",
                        "--out=" + directory + "/identity",
                    ]
                )
            self.assertEqual(result, 130)
            self.assertNotIn("Identity Found", stdout.getvalue())
            self.assertIn("RECOVERY:", stderr.getvalue())
            recovery = list(Path(directory).glob("*.staging"))
            self.assertEqual(len(recovery), 1)
            self.assertTrue(
                RNS.Identity.from_file(str(recovery[0])).get_private_key() == key,
                "recovery key differs",
            )
            self.assertFalse(os.path.lexists(directory + "/identity"))

    def test_verified_staging_still_checks_publication_arguments(self):
        identity = RNS.Identity(create_keys=True)
        key, address = (
            identity.get_private_key(),
            main.lxmf_hash_hex_for_identity(identity),
        )
        other = RNS.Identity(create_keys=True).get_private_key()
        for supplied_key, supplied_address in ((other, address), (key, "0" * 32)):
            with (
                self.subTest(address=supplied_address),
                tempfile.TemporaryDirectory() as directory,
            ):
                staging = main.prepare_output_staging(directory + "/identity")
                try:
                    staging.write_private_key(key)
                    with self.assertRaisesRegex(
                        main.OutputWriteError, "winning key and address"
                    ):
                        staging.write_and_publish(supplied_key, supplied_address)
                    self.assertFalse(os.path.lexists(directory + "/identity"))
                finally:
                    recovery = staging.cleanup()
                self.assertTrue(
                    RNS.Identity.from_file(recovery).get_private_key() == key,
                    "staged winner was replaced",
                )

    # T1.1
    def test_worker_shutdown_failure_after_match_still_publishes(self):
        real_collect = main.collect_worker_shutdown
        fired = []

        def collect_then_fail(workers, state, *args, **kwargs):
            real_collect(workers, state, *args, **kwargs)
            if state.match_private_key is not None and not fired:
                fired.append(True)
                raise RuntimeError("worker processes did not stop: vanity-worker-0")

        with tempfile.TemporaryDirectory() as directory:
            result, _, stderr = self.run_main(
                directory,
                mock.patch.object(
                    main, "collect_worker_shutdown", side_effect=collect_then_fail
                ),
            )
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertTrue(fired)
            self.assertIn("WARNING: worker processes did not stop", stderr.getvalue())
            self.assert_saved(directory)

    # T1.1
    def test_signal_after_match_still_publishes(self):
        real_collect = main.collect_worker_shutdown
        fired = []

        def collect_then_signal(workers, state, *args, **kwargs):
            real_collect(workers, state, *args, **kwargs)
            if state.match_private_key is not None and not fired:
                fired.append(True)
                signal.raise_signal(signal.SIGTERM)

        with tempfile.TemporaryDirectory() as directory:
            result, _, stderr = self.run_main(
                directory,
                mock.patch.object(
                    main, "collect_worker_shutdown", side_effect=collect_then_signal
                ),
            )
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertTrue(fired)
            self.assertIn("termination signal arrived", stderr.getvalue())
            self.assert_saved(directory)

    # T1.1 (D4)
    def test_late_match_on_interrupt_path_is_preserved_for_recovery(self):
        identity = RNS.Identity(create_keys=True)
        key = identity.get_private_key()
        address = main.lxmf_hash_hex_for_identity(identity)
        prefix = address  # Full matching target; a spontaneous match is negligible.
        real_collect = main.collect_worker_shutdown

        def collect_with_late_match(workers, state, *args, **kwargs):
            # Exercise the real verification boundary, not an impossible state
            # containing a key that does not satisfy the requested pattern.
            main.record_worker_message(
                (main.MSG_MATCH, 0, key, address), state, prefix, "", 1
            )
            real_collect(workers, state, *args, **kwargs)

        def interrupt(*_args, **_kwargs):
            raise KeyboardInterrupt

        with tempfile.TemporaryDirectory() as directory:
            stderr = io.StringIO()
            with (
                mock.patch.object(
                    main, "wait_for_search_trigger", side_effect=interrupt
                ),
                mock.patch.object(
                    main, "collect_worker_shutdown", side_effect=collect_with_late_match
                ),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(stderr),
            ):
                result = main.main(
                    [
                        "--prefix=" + prefix,
                        "--force",
                        "--workers=1",
                        "--out=" + directory + "/identity",
                    ]
                )
            self.assertEqual(result, 130)
            self.assertIn("RECOVERY:", stderr.getvalue())
            staging = list(Path(directory).glob("*.staging"))
            self.assertEqual(len(staging), 1)
            self.assertTrue(
                RNS.Identity.from_file(str(staging[0])).get_private_key() == key,
                "recovery key differs from the verified winner",
            )
            self.assertFalse(os.path.lexists(os.path.join(directory, "identity")))
