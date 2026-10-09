import contextlib
import errno
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import RNS
import main


class _DeadStream(io.TextIOBase):
    """A text stream whose reader has gone away."""

    def writable(self):
        return True

    def write(self, _text):
        raise BrokenPipeError(errno.EPIPE, "Broken pipe")


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

    # T1.2
    def test_dead_status_stream_does_not_stop_the_search(self):
        with tempfile.TemporaryDirectory() as directory:
            result, stdout, _ = self.run_main(directory, stderr=_DeadStream())
            self.assertEqual(result, 0)
            self.assertIn("Identity Found", stdout.getvalue())
            self.assert_saved(directory)

    # T1.2
    def test_dead_result_stream_after_publication_is_still_success(self):
        with tempfile.TemporaryDirectory() as directory:
            result, _, stderr = self.run_main(directory, stdout=_DeadStream())
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertIn("could not be written to stdout", stderr.getvalue())
            self.assert_saved(directory)

    # T1.3
    def test_interrupted_wait_becomes_coordinated_sigint(self):
        real_wait = main.wait
        fired = []

        def interrupted_wait(object_list, timeout=None):
            if not fired:
                fired.append(True)
                # What CPython does on Windows when Ctrl+C lands in the wait.
                signal.raise_signal(signal.SIGINT)
                raise InterruptedError(errno.EINTR, "Interrupted function call")
            return real_wait(object_list, timeout)

        with tempfile.TemporaryDirectory() as directory:
            stderr = io.StringIO()
            with (
                mock.patch.object(main, "wait", side_effect=interrupted_wait),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(stderr),
            ):
                result = main.main(
                    [
                        "--prefix=" + "0" * 32,
                        "--force",
                        "--workers=1",
                        "--out=" + directory + "/identity",
                    ]
                )
            self.assertEqual(result, 130, stderr.getvalue())
            self.assertIn("Interrupted", stderr.getvalue())
            self.assertNotIn("ERROR", stderr.getvalue())
            self.assertEqual(os.listdir(directory), [])


class StreamReliabilityTests(unittest.TestCase):
    def test_real_closed_pipes_do_not_change_saved_success(self):
        for closed_name in ("stderr", "stdout"):
            with (
                self.subTest(stream=closed_name),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = directory + "/identity"
                process = subprocess.Popen(
                    [
                        sys.executable,
                        main.__file__,
                        "--prefix=a",
                        "--workers=1",
                        "--out=" + path,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                try:
                    closed = getattr(process, closed_name)
                    closed.close()
                    setattr(process, closed_name, None)
                    stdout, stderr = process.communicate(timeout=30)
                    self.assertEqual(process.returncode, 0, stderr)
                    identity = RNS.Identity.from_file(path)
                    self.assertIsNotNone(identity)
                    self.assertTrue(
                        main.lxmf_hash_hex_for_identity(identity).startswith("a")
                    )
                    self.assertEqual(os.listdir(directory), ["identity"])
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=5)

    def test_ascii_stdout_escapes_unicode_output_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = directory + "/ключ.identity"
            result = subprocess.run(
                [
                    sys.executable,
                    main.__file__,
                    "--prefix=a",
                    "--workers=1",
                    "--out=" + path,
                ],
                env={**os.environ, "PYTHONIOENCODING": "ascii"},
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b"\\u043a", result.stdout)
            self.assertIsNotNone(RNS.Identity.from_file(path))

    def test_closed_text_wrapper_does_not_abort_generation(self):
        stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
        stream.close()
        # Argparse probes the terminal unless colour is disabled; keep the
        # probe enabled so the result does not depend on the caller's shell.
        colour_env = {"TERM": "xterm-256color", "NO_COLOR": "", "PYTHON_COLORS": ""}
        with tempfile.TemporaryDirectory() as directory:
            stderr = io.StringIO()
            with (
                mock.patch.dict(os.environ, colour_env),
                contextlib.redirect_stdout(stream),
                contextlib.redirect_stderr(stderr),
            ):
                result = main.main(
                    ["--prefix=a", "--workers=1", "--out=" + directory + "/identity"]
                )
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertIsNotNone(RNS.Identity.from_file(directory + "/identity"))

    def test_missing_std_streams_keep_outputs_separate_and_succeed(self):
        for name in ("stdout", "stderr"):
            with self.subTest(stream=name), tempfile.TemporaryDirectory() as directory:
                other = io.StringIO()
                other_name = "stderr" if name == "stdout" else "stdout"
                with (
                    mock.patch.object(sys, name, None),
                    mock.patch.object(sys, other_name, other),
                ):
                    result = main.main(
                        [
                            "--prefix=a",
                            "--workers=1",
                            "--out=" + directory + "/identity",
                        ]
                    )
                self.assertEqual(result, 0, other.getvalue())
                self.assertIsNotNone(RNS.Identity.from_file(directory + "/identity"))
                if name == "stderr":
                    # Diagnostics must not fall back to the result stream.
                    self.assertNotIn("[ready]", other.getvalue())
                    self.assertIn("Identity Found", other.getvalue())

    def test_private_strings_to_non_terminal_stdout_are_warned_about(self):
        for show, expected in ((True, True), (False, False)):
            with self.subTest(show=show), tempfile.TemporaryDirectory() as directory:
                stdout, stderr = io.StringIO(), io.StringIO()
                argv = ["--prefix=a", "--workers=1", "--out=" + directory + "/id"]
                if show:
                    argv.append("--show-private-import-strings")
                with (
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    self.assertEqual(main.main(argv), 0, stderr.getvalue())
                self.assertEqual("non-terminal stdout" in stderr.getvalue(), expected)

    @unittest.skipUnless(os.name == "posix", "POSIX shell redirection required")
    def test_real_streams_closed_at_launch(self):
        for redirect in (">&-", "2>&-"):
            with (
                self.subTest(redirect=redirect),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = directory + "/identity"
                command = 'exec "$0" "$1" --prefix=a --workers=1 "--out=$2" ' + redirect
                result = subprocess.run(
                    ["/bin/sh", "-c", command, sys.executable, main.__file__, path],
                    capture_output=redirect == "2>&-",
                    env={**os.environ, "TERM": "xterm-256color", "NO_COLOR": ""},
                    timeout=60,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIsNotNone(RNS.Identity.from_file(path))
                if redirect == "2>&-":
                    self.assertNotIn(b"[ready]", result.stdout)
                    self.assertIn(b"Identity Found", result.stdout)

    def test_devnull_descriptor_reuse_does_not_close_repaired_descriptor(self):
        stream = mock.Mock()
        stream.fileno.return_value = 42
        with (
            mock.patch.object(os, "open", return_value=42),
            mock.patch.object(os, "dup2") as dup,
            mock.patch.object(os, "close") as close,
        ):
            main.silence_dead_stream(stream)
        dup.assert_not_called()
        close.assert_not_called()

    def test_silencing_unusable_fileno_is_best_effort(self):
        for stream in (object(), io.StringIO()):
            main.silence_dead_stream(stream)

    def test_diagnostic_encoding_failure_is_best_effort(self):
        with contextlib.redirect_stderr(_DeadStream()):
            main.print_diagnostic("status")
        stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
        try:
            with contextlib.redirect_stderr(stream):
                main.print_diagnostic("ключ")
        finally:
            stream.close()


class InterruptedWaitTests(unittest.TestCase):
    def test_eintr_without_signal_resumes_without_manufacturing_interrupt(self):
        context = main.mp.get_context("spawn")
        reader, writer = context.Pipe(duplex=False)
        handle = main.WorkerHandle(mock.Mock(), reader, mock.Mock())
        state = main.SearchState()
        try:
            main.send_worker_message(writer, (main.MSG_READY, 0))
            with mock.patch.object(
                main, "wait", side_effect=InterruptedError(errno.EINTR, "interrupted")
            ):
                main.receive_worker_messages([handle], state, "a", "", 0)
            self.assertFalse(state.ready_workers)
            main.receive_worker_messages([handle], state, "a", "", 1)
            self.assertEqual(state.ready_workers, {0})
            self.assertFalse(state.errors)
        finally:
            reader.close()
            writer.close()

    def test_other_wait_oserror_remains_fatal(self):
        handle = main.WorkerHandle(mock.Mock(), mock.Mock(closed=False), mock.Mock())
        with mock.patch.object(
            main, "wait", side_effect=OSError(errno.EIO, "I/O failure")
        ):
            with self.assertRaises(OSError):
                main.receive_worker_messages([handle], main.SearchState(), "a", "", 0)


class SignalHandlingTests(unittest.TestCase):
    def test_first_signal_wins_and_checkpoint_carries_its_number(self):
        state = main.SignalState()
        state.request(signal.SIGTERM, None)
        state.request(signal.SIGINT, None)
        self.assertEqual(state.signum, signal.SIGTERM)
        with self.assertRaises(main.TerminationRequested) as raised:
            state.raise_if_requested()
        self.assertEqual(raised.exception.signum, signal.SIGTERM)

    def test_handlers_are_restored_after_validation_failure(self):
        signals = [
            getattr(signal, name)
            for name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK")
            if hasattr(signal, name)
        ]
        before = {signum: signal.getsignal(signum) for signum in signals}
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main.main(["--prefix=not-hex", "--out=identity"]), 2)
        self.assertEqual(
            {signum: signal.getsignal(signum) for signum in signals}, before
        )

    def test_signal_before_generation_uses_128_plus_signal(self):
        for name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"):
            if not hasattr(signal, name):
                continue
            signum = getattr(signal, name)

            def request_signal():
                signal.raise_signal(signum)
                return "test backend"

            with (
                self.subTest(signal=name),
                mock.patch.object(
                    main, "validate_runtime_environment", side_effect=request_signal
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    main.main(["--prefix=a", "--out=identity"]), 128 + signum
                )

    def test_workers_ignore_every_handled_signal(self):
        cancel, messages = mock.Mock(), mock.Mock()
        cancel.poll.return_value = True
        with mock.patch.object(signal, "signal") as install:
            main.worker(0, "a", "", cancel, messages)
        for name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"):
            if hasattr(signal, name):
                install.assert_any_call(getattr(signal, name), signal.SIG_IGN)
