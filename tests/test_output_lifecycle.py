import errno
import os
import tempfile
import unittest
from unittest import mock

import RNS

import main


class OutputLifecycleTests(unittest.TestCase):
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
