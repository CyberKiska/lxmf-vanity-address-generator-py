import errno
import os
import tempfile
import unittest
from unittest import mock

import RNS

import main


class OutputLifecycleTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX file mode required")
    def test_ineffective_chmod_fails_before_any_private_or_probe_write(self):
        chmod = os.fchmod
        for create in (main.prepare_output_staging, main._exclusive_output_fd):
            with (
                self.subTest(operation=create.__name__),
                tempfile.TemporaryDirectory() as directory,
                mock.patch.object(
                    os, "fchmod", side_effect=lambda fd, _: chmod(fd, 0o700)
                ),
                mock.patch.object(main, "_write_all") as write,
            ):
                with self.assertRaisesRegex((OSError, ValueError), "mode 0600"):
                    create(os.path.join(directory, "identity"))
                write.assert_not_called()
                self.assertEqual(os.listdir(directory), [])

    def test_interrupted_stage_contains_only_the_bytes_written(self):
        key = main.COMPAT_PRIVATE_KEY
        for size in (8, len(key)):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as directory:
                staging = main.prepare_output_staging(
                    os.path.join(directory, "identity")
                )

                def interrupt(fd, data):
                    os.write(fd, data[:size])
                    raise OSError(errno.ENOSPC, "storage full")

                try:
                    with mock.patch.object(main, "_write_all", side_effect=interrupt):
                        with self.assertRaises(main.OutputWriteError):
                            staging.write_private_key(key)
                finally:
                    recovery = staging.cleanup()
                self.assertFalse(os.path.lexists(staging.final_path))
                self.assertEqual(os.path.getsize(recovery), size)
                if size == len(key):
                    recovered = RNS.Identity.from_file(recovery)
                    self.assertEqual(
                        main.lxmf_hash_hex_for_identity(recovered),
                        main.COMPAT_PRIVATE_KEY_LXMF_HASH,
                    )

    def test_link_io_error_aborts_preflight(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(
                main,
                "_link_without_following",
                side_effect=OSError(errno.EIO, "link failed"),
            ):
                with self.assertRaisesRegex(ValueError, "link failed"):
                    main.prepare_output_staging(os.path.join(directory, "identity"))
            self.assertEqual(os.listdir(directory), [])

    def test_exclusive_probe_is_removed_even_if_write_and_close_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "probe")
            real_close = os.close
            closed = []

            def delayed_close(fd):
                closed.append(fd)
                if len(closed) == 1:
                    real_close(fd)
                raise OSError(errno.EIO, "close failed")

            with (
                mock.patch.object(os, "close", side_effect=delayed_close),
                mock.patch.object(
                    main,
                    "_write_all",
                    side_effect=OSError(errno.ENOSPC, "storage full"),
                ),
            ):
                with self.assertRaises(OSError):
                    main._preflight_exclusive_copy(path)
            self.assertEqual(len(closed), 1)
            self.assertFalse(os.path.lexists(path))

    def test_preflight_close_error_keeps_the_original_failure(self):
        real_close = os.close

        def delayed_close(fd):
            real_close(fd)
            raise OSError(errno.EIO, "close failed")

        for failure, expected in (
            (OSError(errno.ENOSPC, "storage full"), ValueError),
            (KeyboardInterrupt(), KeyboardInterrupt),
        ):
            with (
                self.subTest(failure=type(failure).__name__),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = os.path.join(directory, "identity")
                with (
                    mock.patch.object(os, "close", side_effect=delayed_close) as close,
                    mock.patch.object(main, "_write_all", side_effect=failure),
                ):
                    with self.assertRaises(expected) as caught:
                        main.prepare_output_staging(path)
                self.assertEqual(close.call_count, 1)
                self.assertNotIn("close failed", str(caught.exception))
                if expected is ValueError:
                    self.assertIn("storage full", str(caught.exception))
                self.assertEqual(os.listdir(directory), [])

    def test_private_reload_errors_do_not_repeat_provider_input(self):
        for step in ("staging", "final"):
            with self.subTest(step=step), tempfile.TemporaryDirectory() as directory:
                staging = main.prepare_output_staging(
                    os.path.join(directory, "identity")
                )
                try:
                    if step == "final":
                        staging.write_private_key(main.COMPAT_PRIVATE_KEY)
                    with mock.patch.object(
                        RNS.Identity,
                        "from_file",
                        side_effect=ValueError("private-input-placeholder"),
                    ):
                        with self.assertRaises(main.OutputWriteError) as caught:
                            staging.write_and_publish(
                                main.COMPAT_PRIVATE_KEY,
                                main.COMPAT_PRIVATE_KEY_LXMF_HASH,
                            )
                    self.assertNotIn("private-input-placeholder", str(caught.exception))
                    self.assertFalse(os.path.lexists(staging.final_path))
                finally:
                    recovery = staging.cleanup()
                self.assertEqual(
                    main.lxmf_hash_hex_for_identity(RNS.Identity.from_file(recovery)),
                    main.COMPAT_PRIVATE_KEY_LXMF_HASH,
                )

    def test_delayed_staging_close_error_identifies_verified_final_file(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = os.path.join(directory, "identity")
            staging = main.prepare_output_staging(destination)
            try:
                staging.write_and_publish(
                    main.COMPAT_PRIVATE_KEY, main.COMPAT_PRIVATE_KEY_LXMF_HASH
                )
                real_close = os.close

                def delayed_close(fd):
                    real_close(fd)
                    raise OSError(errno.EIO, "close failed")

                with mock.patch.object(os, "close", side_effect=delayed_close):
                    with self.assertRaises(main.OutputWriteError) as caught:
                        staging.finalize()
                self.assertIn(repr(destination), str(caught.exception))
            finally:
                recovery = staging.cleanup()
            for path in (destination, recovery):
                self.assertEqual(
                    main.lxmf_hash_hex_for_identity(RNS.Identity.from_file(path)),
                    main.COMPAT_PRIVATE_KEY_LXMF_HASH,
                )
