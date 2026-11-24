import contextlib
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import main


class WorkerLifecycleRegressionTests(unittest.TestCase):
    def test_ctrl_c_during_match_validation_preserves_late_winner(self):
        validate = main.validate_match_payload

        def interrupt_then_validate(*args):
            signal.raise_signal(signal.SIGINT)
            return validate(*args)

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(
                main, "validate_match_payload", side_effect=interrupt_then_validate
            ),
            contextlib.redirect_stdout(io.StringIO()) as stdout,
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            output = Path(directory, "winner")
            result = main.main(["--workers=1", "--prefix=a", f"--out={output}"])
            self.assertEqual(result, 130)
            self.assertFalse(output.exists())
            self.assertFalse(bool(stdout.getvalue()), "unexpected result output")
            (recovery,) = Path(directory).glob("*.staging")
            identity = main.RNS.Identity.from_file(str(recovery))
            self.assertIsNotNone(identity)
            address = main.RNS.Destination.hash(identity, "lxmf", "delivery").hex()
            self.assertTrue(address.startswith("a"))
            self.assertTrue("RECOVERY:" in stderr.getvalue(), "missing recovery notice")
            self.assertTrue(address in stderr.getvalue(), "missing recovery address")

    def test_key_provider_errors_do_not_enter_worker_diagnostics(self):
        # A public canary stands in for data echoed by a failing provider.
        canary = "provider-input-canary"

        def fail_generation():
            main.RNS.log(canary, main.RNS.LOG_ERROR)
            raise RuntimeError(canary)

        cancel = mock.Mock()
        cancel.poll.return_value = False
        loglevel = main.RNS.loglevel
        with (
            mock.patch.object(signal, "signal"),
            mock.patch.object(main, "gen_identity", side_effect=fail_generation),
            mock.patch.object(main, "send_worker_message") as send,
            contextlib.redirect_stdout(io.StringIO()) as stdout,
        ):
            main.worker(0, "a", "", cancel, mock.Mock())
        errors = [
            args[1] for args, _ in send.call_args_list if args[1][0] == main.MSG_ERROR
        ]
        self.assertEqual(errors, [(main.MSG_ERROR, 0, "RuntimeError")])
        self.assertFalse(stdout.getvalue())
        self.assertEqual(main.RNS.loglevel, loglevel)
        with mock.patch.object(
            main.RNS.Identity, "from_bytes", side_effect=ValueError(canary)
        ):
            error = main.validate_match_payload(bytes(64), "a" * 32, "a", "")
        self.assertEqual(error, "worker private-key validation failed: ValueError")

    def test_argparse_exit_status_with_closed_output_reader(self):
        for arguments, stream, expected in (
            (["--version"], "stdout", 0),
            (["--help"], "stdout", 0),
            ([], "stderr", 2),
        ):
            with self.subTest(args=arguments):
                reader, writer = os.pipe()
                os.close(reader)
                with os.fdopen(writer, "wb") as closed_pipe:
                    streams = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
                    streams[stream] = closed_pipe
                    result = subprocess.run(
                        [sys.executable, main.__file__, *arguments],
                        timeout=30,
                        **streams,
                    )
                self.assertEqual(result.returncode, expected)
                self.assertFalse(result.stdout or result.stderr)
