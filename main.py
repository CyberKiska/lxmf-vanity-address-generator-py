"""Generate prefix/postfix vanity identities for RNS LXMF delivery addresses."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
import errno
from importlib.metadata import (
    PackageNotFoundError,
    distribution,
    version as distribution_version,
)
import multiprocessing as mp
import os
import queue
import signal
import sys
import tempfile
import time
from typing import Sequence

from packaging.version import InvalidVersion, Version

try:
    import RNS
except ImportError as exc:  # pragma: no cover - exercised without the dependency
    raise SystemExit(
        "ERROR: Reticulum is not installed. Install a supported version with "
        "'python -m pip install -r requirements.txt'."
    ) from exc


LXMF_APP_NAME = "lxmf"
LXMF_ASPECTS = ("delivery",)
MIN_RNS_VERSION = Version("1.4.2")
MAX_RNS_VERSION = Version("2.0")
MIN_CRYPTOGRAPHY_VERSION = Version("50.0.0")
DEST_HASH_HEX_LEN = RNS.Reticulum.TRUNCATED_HASHLENGTH // 4
HEX_ALPHABET = frozenset("0123456789abcdef")
PROGRESS_BATCH_SIZE = 1024
STATUS_INTERVAL = 1.0
SHUTDOWN_TIMEOUT = 5.0
QUEUE_FLUSH_GRACE = 0.25
WORKER_EXIT_GRACE = 1.0
WORKER_HEALTH_INTERVAL = 0.25
MAX_UNFORCED_CONSTRAINED_HEX = 6
DEFAULT_MAX_WORKERS = 32
ABSOLUTE_MAX_WORKERS = 256
OUTPUT_STAGING_PREFIX = ".lxmf-identity-"
OUTPUT_STAGING_SUFFIX = ".staging"
OUTPUT_STAGING_MARKER = (
    b"LXMF vanity identity staging file; no private identity is stored yet.\n"
).ljust(128, b"\0")

PUBLISH_HARD_LINK = "hard-link"
PUBLISH_EXCLUSIVE_COPY = "exclusive-copy"

MSG_PROGRESS = "progress"
MSG_MATCH = "match"
MSG_ERROR = "error"
MSG_DONE = "done"


class TerminationRequested(BaseException):
    """Raised in the parent process when SIGTERM requests clean shutdown."""


class OutputWriteError(RuntimeError):
    """Raised when private output cannot be staged or safely published."""


@dataclass
class SignalState:
    """Record the first termination signal for handling at a safe checkpoint."""

    signum: int | None = None

    def request(self, signum: int, _frame: object) -> None:
        if self.signum is None:
            self.signum = signum

    def raise_if_requested(self) -> None:
        if self.signum is None:
            return
        if self.signum == getattr(signal, "SIGINT", None):
            raise KeyboardInterrupt
        raise TerminationRequested


@dataclass
class SearchState:
    total_tries: int = 0
    match_private_key: bytes | None = None
    match_addr_hex: str | None = None
    errors: list[str] = field(default_factory=list)
    done_workers: set[int] = field(default_factory=set)
    attempt_count_exact: bool = True


def lxmf_hash_hex_for_identity(identity: RNS.Identity) -> str:
    """Return the final lowercase 32-character lxmf.delivery hash."""
    return RNS.Destination.hash(identity, LXMF_APP_NAME, *LXMF_ASPECTS).hex()


def gen_identity() -> RNS.Identity:
    """Generate keys exclusively through Reticulum's Identity API."""
    return RNS.Identity(create_keys=True)


def rns_version() -> str:
    """Return the installed RNS distribution version without private RNS APIs."""
    try:
        return distribution_version("rns")
    except PackageNotFoundError:
        return "unknown"


def cryptography_version() -> str:
    """Return the installed PyCA cryptography distribution version."""
    try:
        return distribution_version("cryptography")
    except PackageNotFoundError:
        return "unknown"


def validate_import_origin(
    distribution_name: str,
    imported_module: object,
    expected_relative_path: str,
) -> None:
    """Reject a local module shadowing the reviewed installed distribution."""
    try:
        installed_distribution = distribution(distribution_name)
    except PackageNotFoundError as exc:
        raise ValueError(
            f"installed distribution {distribution_name!r} could not be located"
        ) from exc

    imported_path = getattr(imported_module, "__file__", None)
    expected_path = installed_distribution.locate_file(expected_relative_path)
    if not isinstance(imported_path, str):
        raise ValueError(
            f"imported module for {distribution_name!r} has no filesystem origin"
        )
    try:
        origin_matches = os.path.samefile(imported_path, expected_path)
    except OSError:
        origin_matches = False
    if not origin_matches:
        raise ValueError(
            f"imported {distribution_name!r} module does not come from its "
            f"installed distribution: {imported_path!r}"
        )


def validate_runtime_environment() -> str:
    """Validate installed origins and the public RNS semantics we depend on."""
    validate_import_origin("rns", RNS, "RNS/__init__.py")
    installed_rns_text = rns_version()
    try:
        installed_rns = Version(installed_rns_text)
    except InvalidVersion as exc:
        raise ValueError(
            f"invalid installed RNS version {installed_rns_text!r}"
        ) from exc
    if not MIN_RNS_VERSION <= installed_rns < MAX_RNS_VERSION:
        raise ValueError(
            f"unsupported RNS version {installed_rns_text!r}; expected "
            f">={MIN_RNS_VERSION},<{MAX_RNS_VERSION}"
        )

    try:
        import cryptography
    except ImportError as exc:  # pragma: no cover - required dependency
        raise ValueError(
            "PyCA cryptography is not installed; install requirements.txt in "
            "the active Python environment"
        ) from exc
    validate_import_origin("cryptography", cryptography, "cryptography/__init__.py")
    installed_crypto_text = cryptography_version()
    try:
        installed_crypto = Version(installed_crypto_text)
    except InvalidVersion as exc:
        raise ValueError(
            f"invalid installed cryptography version {installed_crypto_text!r}"
        ) from exc
    if installed_crypto < MIN_CRYPTOGRAPHY_VERSION:
        raise ValueError(
            f"unsupported cryptography version {installed_crypto_text!r}; "
            f"expected >={MIN_CRYPTOGRAPHY_VERSION}"
        )

    if RNS.Reticulum.TRUNCATED_HASHLENGTH != 128:
        raise ValueError(
            "incompatible RNS destination hash length: expected 128 bits, got "
            f"{RNS.Reticulum.TRUNCATED_HASHLENGTH!r}"
        )
    if RNS.Identity.KEYSIZE != 512:
        raise ValueError(
            "incompatible RNS identity key size: expected 512 bits, got "
            f"{RNS.Identity.KEYSIZE!r}"
        )

    try:
        identity = RNS.Identity(create_keys=True)
        private_key = identity.get_private_key()
        if not isinstance(private_key, bytes) or len(private_key) != 64:
            raise ValueError("generated identity did not contain a 64-byte key")
        restored = RNS.Identity.from_bytes(private_key)
        if restored is None or restored.get_private_key() != private_key:
            raise ValueError("identity did not round-trip through RNS")
        derived = lxmf_hash_hex_for_identity(restored)
        official = RNS.Destination.hash_from_name_and_identity(
            "lxmf.delivery", restored
        ).hex()
        if derived != official or len(derived) != 32 or derived != derived.lower():
            raise ValueError("lxmf.delivery destination derivation is incompatible")
    except Exception as exc:
        raise ValueError(f"RNS public API compatibility check failed: {exc}") from exc

    return f"PyCA cryptography {installed_crypto_text}"


def normalize_hex_pattern(name: str, value: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string of hexadecimal characters.")
    normalized = value.lower()
    if normalized and any(ch not in HEX_ALPHABET for ch in normalized):
        raise ValueError(f"{name} must contain hex characters only [0-9a-f].")
    if len(normalized) > DEST_HASH_HEX_LEN:
        raise ValueError(
            f"{name} length must be 0..{DEST_HASH_HEX_LEN} hex characters "
            f"(max {DEST_HASH_HEX_LEN // 2} bytes)."
        )
    return normalized


def normalize_and_validate_patterns(prefix: str, postfix: str) -> tuple[str, str]:
    prefix_hex = normalize_hex_pattern("prefix", prefix)
    postfix_hex = normalize_hex_pattern("postfix", postfix)

    if not prefix_hex and not postfix_hex:
        raise ValueError("at least one of --prefix or --postfix must be provided.")

    overlap = max(0, len(prefix_hex) + len(postfix_hex) - DEST_HASH_HEX_LEN)
    if overlap and prefix_hex[-overlap:] != postfix_hex[:overlap]:
        raise ValueError(
            "prefix and postfix impose contradictory values in their "
            f"{overlap}-character overlap."
        )

    return prefix_hex, postfix_hex


def available_cpu_count() -> int:
    process_cpu_count = getattr(os, "process_cpu_count", None)
    if process_cpu_count is not None:
        count = process_cpu_count()
    elif hasattr(os, "sched_getaffinity"):
        try:
            count = len(os.sched_getaffinity(0))
        except OSError:
            count = os.cpu_count()
    else:
        count = os.cpu_count()
    return max(1, count or 1)


def maximum_worker_count(cpu_count: int | None = None) -> int:
    available = available_cpu_count() if cpu_count is None else max(1, cpu_count)
    return min(ABSOLUTE_MAX_WORKERS, max(1, available * 2))


def default_worker_count(cpu_count: int | None = None) -> int:
    available = available_cpu_count() if cpu_count is None else max(1, cpu_count)
    return min(available, maximum_worker_count(available), DEFAULT_MAX_WORKERS)


def validate_workers(raw_workers: int) -> int:
    if type(raw_workers) is not int:
        raise ValueError("workers must be an integer.")
    workers = raw_workers
    maximum = maximum_worker_count()
    if workers < 1 or workers > maximum:
        raise ValueError(f"workers must be an integer in the range 1..{maximum}.")
    return workers


def constrained_positions(prefix_hex: str, postfix_hex: str) -> int:
    return min(DEST_HASH_HEX_LEN, len(prefix_hex) + len(postfix_hex))


def expected_attempts(prefix_hex: str, postfix_hex: str) -> int:
    return 16 ** constrained_positions(prefix_hex, postfix_hex)


def encode_base64(private_key_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(private_key_bytes).decode("ascii")


def encode_base32(private_key_bytes: bytes) -> str:
    return base64.b32encode(private_key_bytes).decode("ascii")


def validate_output_path(path: str) -> str:
    if not isinstance(path, str) or not path:
        raise ValueError("output path must be a non-empty string.")
    if "\0" in path:
        raise ValueError("output path must not contain NUL characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise ValueError("output path must not contain control characters.")

    try:
        abs_path = os.path.abspath(path)
    except (OSError, ValueError) as exc:
        raise ValueError(f"invalid output path: {exc}") from exc
    parent = os.path.dirname(abs_path) or "."

    if not os.path.isdir(parent):
        raise ValueError(f"output directory does not exist: {parent!r}")
    if os.path.lexists(abs_path):
        raise ValueError(f"Refusing to overwrite existing file: {abs_path!r}")

    return abs_path


def _fsync_directory(path: str) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY

    try:
        directory_fd = os.open(path, flags)
    except OSError:
        return

    try:
        os.fsync(directory_fd)
    except OSError:
        # Some platforms and filesystems do not support directory fsync.
        pass
    finally:
        os.close(directory_fd)


def _validate_private_key_bytes(private_key_bytes: object) -> bytes:
    expected_key_length = RNS.Identity.KEYSIZE // 8
    if not isinstance(private_key_bytes, bytes):
        raise OutputWriteError("Identity private key must be bytes.")
    if len(private_key_bytes) != expected_key_length:
        raise OutputWriteError(
            f"Identity private key must be {expected_key_length} bytes; "
            f"got {len(private_key_bytes)}."
        )
    return private_key_bytes


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError(f"short write after {offset} of {len(view)} bytes")
        offset += written


def _read_exact(fd: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(fd, remaining)
        if not chunk:
            raise OSError(f"short read with {remaining} bytes remaining")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _link_without_following(source: str, destination: str) -> None:
    try:
        os.link(source, destination, follow_symlinks=False)
    except (NotImplementedError, TypeError) as exc:
        raise OSError(
            errno.ENOTSUP,
            "secure hard-link creation is unavailable on this platform",
        ) from exc


def _exclusive_output_fd(path: str) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    for flag_name in ("O_BINARY", "O_CLOEXEC", "O_NOFOLLOW"):
        flags |= getattr(os, flag_name, 0)
    fd = -1
    created_inode: tuple[int, int] | None = None
    try:
        fd = os.open(path, flags, 0o600)
        created_stat = os.fstat(fd)
        created_inode = created_stat.st_dev, created_stat.st_ino
        os.set_inheritable(fd, False)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        return fd
    except BaseException:
        if fd >= 0 and created_inode is None:
            try:
                created_stat = os.fstat(fd)
                created_inode = created_stat.st_dev, created_stat.st_ino
            except OSError:
                pass
        if fd >= 0:
            os.close(fd)
        _unlink_if_inode(path, created_inode)
        raise


def _inode_for_path(path: str) -> tuple[int, int] | None:
    try:
        file_stat = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    return file_stat.st_dev, file_stat.st_ino


def _unlink_if_inode(path: str, expected_inode: tuple[int, int] | None) -> bool:
    if expected_inode is None or _inode_for_path(path) != expected_inode:
        return False
    try:
        os.unlink(path)
        return True
    except OSError:
        return False


def _path_component_length(name: str) -> int:
    if os.name == "posix":
        return len(os.fsencode(name))
    return len(name)


def _new_output_probe_path(parent: str, minimum_name_length: int) -> str:
    """Return an absent probe path at least as long as the final basename."""
    padding_length = 0
    for _attempt in range(2):
        probe_fd = -1
        probe_path: str | None = None
        probe_inode: tuple[int, int] | None = None
        try:
            probe_fd, probe_path = tempfile.mkstemp(
                prefix=OUTPUT_STAGING_PREFIX,
                suffix=("x" * padding_length) + ".probe",
                dir=parent,
            )
            probe_stat = os.fstat(probe_fd)
            probe_inode = probe_stat.st_dev, probe_stat.st_ino
        finally:
            if probe_fd >= 0:
                os.close(probe_fd)

        if probe_path is None or not _unlink_if_inode(probe_path, probe_inode):
            raise OSError("could not prepare a temporary output publication probe")
        actual_length = _path_component_length(os.path.basename(probe_path))
        if actual_length >= minimum_name_length:
            return probe_path
        padding_length += minimum_name_length - actual_length

    raise OSError("could not create an output probe with the required name length")


def _preflight_exclusive_copy(probe_path: str) -> None:
    probe_fd = -1
    probe_inode: tuple[int, int] | None = None
    try:
        probe_fd = _exclusive_output_fd(probe_path)
        probe_stat = os.fstat(probe_fd)
        probe_inode = probe_stat.st_dev, probe_stat.st_ino
        _write_all(probe_fd, OUTPUT_STAGING_MARKER)
        os.fsync(probe_fd)
    except BaseException:
        if probe_fd >= 0 and probe_inode is None:
            try:
                probe_stat = os.fstat(probe_fd)
                probe_inode = probe_stat.st_dev, probe_stat.st_ino
            except OSError:
                pass
        if probe_fd >= 0:
            os.close(probe_fd)
            probe_fd = -1
        _unlink_if_inode(probe_path, probe_inode)
        raise
    finally:
        if probe_fd >= 0:
            os.close(probe_fd)

    if not _unlink_if_inode(probe_path, probe_inode):
        raise OSError(f"could not remove output preflight file {probe_path!r}")


@dataclass
class OutputStaging:
    """A preflighted, mode-0600 staging file for recoverable publication."""

    final_path: str
    staging_path: str
    fd: int
    publish_mode: str
    staging_inode: tuple[int, int]
    may_contain_private_key: bool = False
    private_key_verified: bool = False
    final_published: bool = False
    final_inode: tuple[int, int] | None = None
    finalized: bool = False

    @property
    def parent(self) -> str:
        return os.path.dirname(self.final_path) or "."

    def _close_fd(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def write_private_key(self, private_key_bytes: object) -> None:
        private_key = _validate_private_key_bytes(private_key_bytes)
        if self.fd < 0:
            raise OutputWriteError("private-key staging file is already closed")

        # From this point onward, any exceptional exit must preserve the file:
        # an asynchronous exception could arrive after some key bytes are
        # written but before Python regains control.
        self.may_contain_private_key = True
        try:
            os.lseek(self.fd, 0, os.SEEK_SET)
            _write_all(self.fd, private_key)
            os.ftruncate(self.fd, len(private_key))
            os.fsync(self.fd)
        except OSError as exc:
            raise OutputWriteError(
                f"Could not durably stage the identity: {exc}. A complete key "
                f"may be recoverable at {self.staging_path!r}."
            ) from exc

        try:
            reloaded = RNS.Identity.from_file(self.staging_path)
            if reloaded is None or reloaded.get_private_key() != private_key:
                raise ValueError("staged identity did not round-trip through RNS")
        except Exception as exc:
            raise OutputWriteError(
                "Staged private-key verification failed; the staging file was "
                f"preserved at {self.staging_path!r}: {exc}"
            ) from exc

        self.private_key_verified = True

    def publish(self) -> str:
        if not self.private_key_verified:
            raise OutputWriteError("refusing to publish an unverified staging file")

        if self.publish_mode == PUBLISH_HARD_LINK:
            try:
                _link_without_following(self.staging_path, self.final_path)
                final_inode = _inode_for_path(self.final_path)
                if final_inode != self.staging_inode:
                    raise OutputWriteError(
                        "published output did not retain the staging-file identity; "
                        f"the winning identity remains at {self.staging_path!r}"
                    )
                self.final_inode = final_inode
                self.final_published = True
            except FileExistsError as exc:
                raise OutputWriteError(
                    f"Refusing to overwrite existing file {self.final_path!r}; "
                    f"the winning identity was preserved at {self.staging_path!r}."
                ) from exc
            except (OSError, ValueError) as exc:
                raise OutputWriteError(
                    f"Could not publish output {self.final_path!r}: {exc}. "
                    f"The winning identity was preserved at {self.staging_path!r}."
                ) from exc
            except BaseException:
                if not self.final_published:
                    _unlink_if_inode(self.final_path, self.staging_inode)
                raise

        elif self.publish_mode == PUBLISH_EXCLUSIVE_COPY:
            output_fd = -1
            output_inode: tuple[int, int] | None = None
            publish_error: BaseException | None = None
            try:
                output_fd = _exclusive_output_fd(self.final_path)
                output_stat = os.fstat(output_fd)
                output_inode = output_stat.st_dev, output_stat.st_ino
                os.lseek(self.fd, 0, os.SEEK_SET)
                private_key = _read_exact(self.fd, RNS.Identity.KEYSIZE // 8)
                _write_all(output_fd, private_key)
                os.ftruncate(output_fd, len(private_key))
                os.fsync(output_fd)
                self.final_inode = output_inode
                self.final_published = True
            except BaseException as exc:
                publish_error = exc
            finally:
                if output_fd >= 0:
                    os.close(output_fd)
            if publish_error is not None:
                if _unlink_if_inode(self.final_path, output_inode):
                    self.final_published = False
                    self.final_inode = None
                if isinstance(publish_error, FileExistsError):
                    raise OutputWriteError(
                        f"Refusing to overwrite existing file {self.final_path!r}; "
                        "the winning identity was preserved at "
                        f"{self.staging_path!r}."
                    ) from publish_error
                if isinstance(publish_error, (OSError, ValueError)):
                    raise OutputWriteError(
                        f"Could not publish output {self.final_path!r}: "
                        f"{publish_error}. The winning identity was preserved at "
                        f"{self.staging_path!r}."
                    ) from publish_error
                raise publish_error

        else:  # pragma: no cover - construction prevents this state
            raise OutputWriteError(
                f"unknown output publication mode {self.publish_mode!r}"
            )

        _fsync_directory(self.parent)
        return self.final_path

    def remove_published_final(self) -> bool:
        if not self.final_published:
            return True
        removed = _unlink_if_inode(self.final_path, self.final_inode)
        if removed:
            self.final_published = False
            self.final_inode = None
            _fsync_directory(self.parent)
        return removed

    def finalize(self) -> str | None:
        """Remove the staging name after final output has been verified."""
        if not self.final_published:
            raise OutputWriteError("cannot finalize output before publication")
        self._close_fd()
        try:
            os.unlink(self.staging_path)
        except OSError:
            # The final output is already verified. Preserve both names rather
            # than risk deleting the final identity during error recovery.
            self.finalized = True
            return self.staging_path
        self.finalized = True
        self.staging_path = ""
        _fsync_directory(self.parent)
        return None

    def cleanup(self) -> str | None:
        """Remove non-secret staging, or return the preserved recovery path."""
        self._close_fd()
        if self.finalized:
            return None
        if self.may_contain_private_key and os.path.lexists(self.staging_path):
            return self.staging_path
        if self.staging_path:
            try:
                os.unlink(self.staging_path)
                _fsync_directory(self.parent)
            except OSError:
                if os.path.lexists(self.staging_path):
                    return self.staging_path
        return None


def prepare_output_staging(path: str) -> OutputStaging:
    """Preflight publication without ever placing marker data at the final path."""
    final_path = validate_output_path(path)
    parent = os.path.dirname(final_path) or "."
    fd = -1
    staging_path: str | None = None
    staging_inode: tuple[int, int] | None = None
    probe_path: str | None = None

    try:
        fd, staging_path = tempfile.mkstemp(
            prefix=OUTPUT_STAGING_PREFIX,
            suffix=OUTPUT_STAGING_SUFFIX,
            dir=parent,
        )
        os.set_inheritable(fd, False)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        staging_stat = os.fstat(fd)
        staging_inode = staging_stat.st_dev, staging_stat.st_ino
        _write_all(fd, OUTPUT_STAGING_MARKER)
        os.fsync(fd)
        probe_path = _new_output_probe_path(
            parent,
            _path_component_length(os.path.basename(final_path)),
        )

        try:
            _link_without_following(staging_path, probe_path)
        except (OSError, ValueError) as link_exc:
            try:
                _preflight_exclusive_copy(probe_path)
            except (OSError, ValueError) as copy_exc:
                raise ValueError(
                    f"output path cannot be created safely: {final_path!r}; "
                    f"hard-link publication failed ({link_exc}); exclusive "
                    f"publication failed ({copy_exc})"
                ) from copy_exc
            publish_mode = PUBLISH_EXCLUSIVE_COPY
        else:
            if not _unlink_if_inode(probe_path, staging_inode):
                raise ValueError(
                    f"could not remove output preflight link: {probe_path!r}"
                )
            publish_mode = PUBLISH_HARD_LINK
        probe_path = None

        _fsync_directory(parent)
        if staging_path is None or staging_inode is None:
            raise ValueError("output staging was not initialized")
        return OutputStaging(
            final_path,
            staging_path,
            fd,
            publish_mode,
            staging_inode,
        )
    except BaseException as exc:
        if probe_path is not None:
            _unlink_if_inode(probe_path, staging_inode)
        if fd >= 0:
            os.close(fd)
        if staging_path is not None:
            try:
                os.unlink(staging_path)
            except OSError:
                pass
        if isinstance(exc, ValueError):
            raise
        if isinstance(exc, OSError):
            raise ValueError(f"could not prepare private output: {exc}") from exc
        raise


def secure_write_identity(path: str, private_key_bytes: bytes) -> str:
    """Publish a mode-0600 RNS identity without overwrite or key loss."""
    private_key = _validate_private_key_bytes(private_key_bytes)
    try:
        staging = prepare_output_staging(path)
    except ValueError as exc:
        raise OutputWriteError(str(exc)) from exc

    try:
        staging.write_private_key(private_key)
        saved_path = staging.publish()
        reloaded = RNS.Identity.from_file(saved_path)
        if reloaded is None or reloaded.get_private_key() != private_key:
            removed = staging.remove_published_final()
            cleanup = "removed invalid output" if removed else "could not remove output"
            raise OutputWriteError(
                f"Published identity verification failed; {cleanup}."
            )
        staging.finalize()
        return saved_path
    except Exception as exc:
        recovery_path = staging.cleanup()
        recovery = (
            f" Private key preserved at {recovery_path!r}."
            if recovery_path is not None
            else ""
        )
        if isinstance(exc, OutputWriteError):
            raise OutputWriteError(f"{exc}{recovery}") from exc
        raise OutputWriteError(f"Could not save output: {exc}.{recovery}") from exc
    finally:
        staging.cleanup()


def _matches_patterns(addr_hex: str, prefix_hex: str, postfix_hex: str) -> bool:
    return (not prefix_hex or addr_hex.startswith(prefix_hex)) and (
        not postfix_hex or addr_hex.endswith(postfix_hex)
    )


def matches_vanity(addr_hex: str, prefix_hex: str, postfix_hex: str) -> bool:
    return (
        len(addr_hex) == DEST_HASH_HEX_LEN
        and addr_hex == addr_hex.lower()
        and all(ch in HEX_ALPHABET for ch in addr_hex)
        and _matches_patterns(addr_hex, prefix_hex, postfix_hex)
    )


def worker(
    worker_id: int,
    prefix_hex: str,
    postfix_hex: str,
    stop_evt: mp.Event,
    out_q: mp.Queue,
) -> None:
    for signal_name in ("SIGINT", "SIGTERM"):
        child_signal = getattr(signal, signal_name, None)
        if child_signal is not None:
            try:
                signal.signal(child_signal, signal.SIG_IGN)
            except (OSError, ValueError):
                pass

    local_tries = 0
    reported_tries = 0

    try:
        while not stop_evt.is_set():
            identity = gen_identity()
            addr_hex = lxmf_hash_hex_for_identity(identity)
            local_tries += 1

            # addr_hex comes directly from bytes.hex(), so it is already a
            # canonical lowercase hash. Avoid rescanning all 32 characters in
            # the hot loop; the parent performs full canonical validation.
            if _matches_patterns(addr_hex, prefix_hex, postfix_hex):
                out_q.put((MSG_MATCH, worker_id, identity.get_private_key(), addr_hex))
                stop_evt.set()
                break

            if local_tries - reported_tries >= PROGRESS_BATCH_SIZE:
                out_q.put((MSG_PROGRESS, worker_id, local_tries - reported_tries))
                reported_tries = local_tries
    except Exception as exc:
        out_q.put((MSG_ERROR, worker_id, f"{type(exc).__name__}: {exc}"))
        stop_evt.set()
    finally:
        leftover = local_tries - reported_tries
        if leftover:
            out_q.put((MSG_PROGRESS, worker_id, leftover))
        out_q.put((MSG_DONE, worker_id))


def validate_match_payload(
    private_key: object,
    claimed_addr_hex: object,
    prefix_hex: str,
    postfix_hex: str,
) -> tuple[bytes, str] | str:
    if not isinstance(private_key, bytes):
        return "worker returned a non-bytes private key"
    if not isinstance(claimed_addr_hex, str):
        return "worker returned a non-string destination hash"

    try:
        identity = RNS.Identity.from_bytes(private_key)
        if identity is None:
            return "worker returned an invalid RNS private key"
        derived_addr_hex = lxmf_hash_hex_for_identity(identity)
    except Exception as exc:
        return f"worker private-key validation failed: {type(exc).__name__}: {exc}"
    if derived_addr_hex != claimed_addr_hex:
        return "worker returned an inconsistent LXMF destination hash"
    if not matches_vanity(derived_addr_hex, prefix_hex, postfix_hex):
        return "worker result does not satisfy the requested vanity constraints"

    return private_key, derived_addr_hex


def record_worker_message(
    message: object,
    state: SearchState,
    prefix_hex: str,
    postfix_hex: str,
    worker_count: int | None = None,
) -> None:
    if not isinstance(message, tuple) or not message:
        state.errors.append("received a malformed worker message")
        return

    tag = message[0]

    def valid_worker_id(value: object) -> bool:
        return (
            type(value) is int
            and value >= 0
            and (worker_count is None or value < worker_count)
        )

    try:
        if tag == MSG_PROGRESS and len(message) == 3:
            worker_id, count = message[1], message[2]
            if not valid_worker_id(worker_id) or type(count) is not int or count < 0:
                raise ValueError("invalid progress payload")
            state.total_tries += count
        elif tag == MSG_MATCH and len(message) == 4:
            worker_id = message[1]
            if not valid_worker_id(worker_id):
                raise ValueError("invalid match worker id")
            validated = validate_match_payload(
                message[2], message[3], prefix_hex, postfix_hex
            )
            if isinstance(validated, str):
                state.errors.append(f"worker {worker_id}: {validated}")
            elif state.match_private_key is None:
                state.match_private_key, state.match_addr_hex = validated
        elif tag == MSG_ERROR and len(message) == 3:
            worker_id, error = message[1], message[2]
            if not valid_worker_id(worker_id) or not isinstance(error, str):
                raise ValueError("invalid error payload")
            state.errors.append(f"worker {worker_id}: {error}")
        elif tag == MSG_DONE and len(message) == 2:
            worker_id = message[1]
            if not valid_worker_id(worker_id):
                raise ValueError("invalid completion worker id")
            if worker_id in state.done_workers:
                raise ValueError(f"duplicate completion from worker {worker_id}")
            state.done_workers.add(worker_id)
        else:
            raise ValueError(f"unknown or malformed message tag {tag!r}")
    except ValueError as exc:
        state.errors.append(f"received a malformed worker message: {exc}")


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    if seconds < 365.25 * 86400:
        return f"{seconds / 86400:.1f}d"
    return f"{seconds / (365.25 * 86400):.2g}y"


def print_status(total_tries: int, started_at: float, nominal_attempts: int) -> None:
    elapsed = max(time.perf_counter() - started_at, 1e-9)
    rate = total_tries / elapsed
    estimate = "unknown"
    if rate > 0:
        estimate = format_duration(nominal_attempts / rate)
    print(
        f"[status] tries={total_tries:,} elapsed={elapsed:.1f}s "
        f"rate={rate:,.0f}/s nominal_time_at_rate={estimate}",
        file=sys.stderr,
        flush=True,
    )


def wait_for_search_trigger(
    procs: Sequence[mp.Process],
    out_q: mp.Queue,
    state: SearchState,
    prefix_hex: str,
    postfix_hex: str,
    started_at: float,
    nominal_attempts: int,
    signal_state: SignalState | None = None,
) -> None:
    last_status = started_at
    last_health_check = 0.0
    dead_without_done_since: dict[int, float] = {}

    while state.match_private_key is None and not state.errors:
        if signal_state is not None:
            signal_state.raise_if_requested()
        try:
            message = out_q.get(timeout=0.25)
        except queue.Empty:
            queue_was_empty = True
        else:
            queue_was_empty = False
            record_worker_message(
                message,
                state,
                prefix_hex,
                postfix_hex,
                worker_count=len(procs),
            )
            if message and isinstance(message, tuple) and message[0] == MSG_DONE:
                worker_id = message[1] if len(message) > 1 else None
                if isinstance(worker_id, int):
                    dead_without_done_since.pop(worker_id, None)

        health_now = time.monotonic()
        if queue_was_empty or health_now - last_health_check >= WORKER_HEALTH_INTERVAL:
            all_workers_exited = True
            for worker_id, proc in enumerate(procs):
                if proc.is_alive():
                    all_workers_exited = False
                    dead_without_done_since.pop(worker_id, None)
                elif worker_id not in state.done_workers:
                    first_seen = dead_without_done_since.setdefault(
                        worker_id, health_now
                    )
                    if health_now - first_seen >= WORKER_EXIT_GRACE:
                        state.errors.append(
                            f"worker {worker_id} exited unexpectedly with "
                            f"exit code {proc.exitcode} and no completion message"
                        )
                        return
            if all_workers_exited and state.done_workers == set(range(len(procs))):
                return
            last_health_check = health_now

        now = time.perf_counter()
        if now - last_status >= STATUS_INTERVAL:
            print_status(state.total_tries, started_at, nominal_attempts)
            last_status = now


def collect_worker_shutdown(
    procs: Sequence[mp.Process],
    stop_evt: mp.Event,
    out_q: mp.Queue,
    state: SearchState,
    prefix_hex: str,
    postfix_hex: str,
    *,
    report_missing: bool = True,
) -> None:
    stop_evt.set()
    deadline = time.monotonic() + SHUTDOWN_TIMEOUT
    last_message_at = time.monotonic()
    expected_worker_ids = set(range(len(procs)))

    while (
        not expected_worker_ids.issubset(state.done_workers)
        and time.monotonic() < deadline
    ):
        try:
            message = out_q.get(timeout=0.1)
        except queue.Empty:
            if (
                not any(proc.is_alive() for proc in procs)
                and time.monotonic() - last_message_at >= QUEUE_FLUSH_GRACE
            ):
                break
        else:
            last_message_at = time.monotonic()
            record_worker_message(
                message,
                state,
                prefix_hex,
                postfix_hex,
                worker_count=len(procs),
            )

    graceful_join_deadline = time.monotonic() + 0.5
    for proc in procs:
        remaining = graceful_join_deadline - time.monotonic()
        if remaining > 0:
            proc.join(timeout=remaining)

    # Children intentionally ignore SIGTERM so process-group termination can
    # be coordinated by the parent. After the cooperative deadline, skip the
    # ineffective POSIX terminate() step and use the strongest available stop.
    for proc in procs:
        if proc.is_alive():
            if hasattr(proc, "kill"):
                proc.kill()
            else:  # pragma: no cover - legacy Python/platform fallback
                proc.terminate()
    for proc in procs:
        proc.join(timeout=0.5)

    survivors = [proc.name for proc in procs if proc.is_alive()]
    if survivors:
        state.attempt_count_exact = False
        raise RuntimeError(
            "worker processes did not stop after forced shutdown: "
            + ", ".join(survivors)
        )

    # A worker's DONE marker is ordered after all of its other queue messages.
    # If every marker arrived, all attempt deltas arrived as well.
    if state.done_workers != expected_worker_ids:
        state.attempt_count_exact = False
        if report_missing:
            missing = sorted(expected_worker_ids - state.done_workers)
            unexpected = sorted(state.done_workers - expected_worker_ids)
            details = []
            if missing:
                details.append(
                    "missing " + ", ".join(str(worker_id) for worker_id in missing)
                )
            if unexpected:
                details.append(
                    "unexpected "
                    + ", ".join(str(worker_id) for worker_id in unexpected)
                )
            state.errors.append("invalid worker completion set: " + "; ".join(details))


def close_queue(out_q: mp.Queue) -> None:
    try:
        out_q.close()
        out_q.join_thread()
    except (OSError, ValueError):
        pass


def build_parser() -> argparse.ArgumentParser:
    cpu_count = available_cpu_count()
    workers_default = default_worker_count(cpu_count)
    parser = argparse.ArgumentParser(
        description="Reticulum LXMF vanity address generator",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=(
            f"%(prog)s (RNS {rns_version()}, cryptography {cryptography_version()})"
        ),
    )
    parser.add_argument(
        "--prefix",
        default="",
        help="Hex prefix for the final 32-character lxmf.delivery hash.",
    )
    parser.add_argument(
        "--postfix",
        default="",
        help="Hex postfix for the final 32-character lxmf.delivery hash.",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Path for the raw RNS identity private-key file (must not exist).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=workers_default,
        help=f"Worker processes to run in parallel (default: {workers_default}).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Allow searches constraining more than "
            f"{MAX_UNFORCED_CONSTRAINED_HEX} hex characters."
        ),
    )
    parser.add_argument(
        "--show-private-import-strings",
        action="store_true",
        help=(
            "Print rnid-compatible Base64/Base32 private-key encodings "
            "(sensitive; unsafe for logs)."
        ),
    )
    return parser


def print_success(
    *,
    prefix_hex: str,
    postfix_hex: str,
    address_hex: str,
    private_key: bytes,
    saved_path: str,
    total_tries: int,
    count_exact: bool,
    elapsed: float,
    show_private_import_strings: bool,
) -> None:
    rate = total_tries / elapsed if elapsed > 0 else 0.0
    attempt_suffix = "" if count_exact else " (reported; shutdown incomplete)"

    print("\n=== Vanity LXMF Identity Found ===")
    if prefix_hex:
        print(f"Prefix      : {prefix_hex}")
    if postfix_hex:
        print(f"Postfix     : {postfix_hex}")
    print(f"LXMF addr   : {address_hex}")
    print(f"Attempts    : {total_tries}{attempt_suffix}")
    print(f"Elapsed [s] : {elapsed:.2f}")
    print(f"Rate [1/s]  : {rate:,.0f}")
    print(f"Saved file  : {saved_path!r}")
    print("File format : raw private-key bytes for RNS.Identity.from_file()")

    if show_private_import_strings:
        print(
            "Warning     : the strings below are the private key; do not log or share them"
        )
        print("\n--- Generic private-key encodings ---")
        print(f"Base64:\n{encode_base64(private_key)}")
        print(f"Base32:\n{encode_base32(private_key)}")


def _print_interruption_summary(
    label: str,
    state: SearchState,
    started_at: float | None,
) -> None:
    if started_at is None:
        print(f"{label} before the search started.", file=sys.stderr)
        return
    elapsed = time.perf_counter() - started_at
    rate = state.total_tries / elapsed if elapsed > 0 else 0.0
    suffix = "" if state.attempt_count_exact else " (reported)"
    print(
        f"{label} after {state.total_tries:,} attempts{suffix} in "
        f"{elapsed:.2f}s ({rate:,.0f}/s).",
        file=sys.stderr,
    )


def run_generation(
    args: argparse.Namespace,
    prefix_hex: str,
    postfix_hex: str,
    workers: int,
    crypto_description: str,
    nominal_attempts: int,
    signal_state: SignalState,
) -> int:
    """Run workers, validate a winner, and safely publish its identity."""
    staging: OutputStaging | None = None
    stop_evt: mp.Event | None = None
    out_q: mp.Queue | None = None
    started_procs: list[mp.Process] = []
    state = SearchState()
    started_at: float | None = None
    workers_collected = False

    def stop_workers(*, report_missing: bool) -> None:
        nonlocal workers_collected
        if workers_collected:
            return
        if stop_evt is not None:
            stop_evt.set()
        if stop_evt is not None and out_q is not None:
            collect_worker_shutdown(
                started_procs,
                stop_evt,
                out_q,
                state,
                prefix_hex,
                postfix_hex,
                report_missing=report_missing,
            )
        workers_collected = True

    try:
        try:
            staging = prepare_output_staging(args.out)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        signal_state.raise_if_requested()

        required_positions = constrained_positions(prefix_hex, postfix_hex)
        difficulty_bits = 4 * required_positions
        print(
            f"Searching lxmf.delivery for prefix={prefix_hex or '-'} "
            f"postfix={postfix_hex or '-'} with {workers} worker process(es).",
            file=sys.stderr,
        )
        print(
            f"RNS {rns_version()}; {crypto_description}.",
            file=sys.stderr,
        )
        if required_positions == DEST_HASH_HEX_LEN:
            print(
                f"Nominal per-attempt odds: 1 in {nominal_attempts:,} "
                f"({difficulty_bits} constrained bits).",
                file=sys.stderr,
            )
            print(
                "WARNING: an arbitrary exact 32-character target may have no "
                "RNS identity-hash preimage and is computationally infeasible.",
                file=sys.stderr,
            )
        else:
            print(
                f"Expected average attempts: {nominal_attempts:,} "
                f"({difficulty_bits} constrained bits).",
                file=sys.stderr,
            )

        process_context = mp.get_context("spawn")
        stop_evt = process_context.Event()
        out_q = process_context.Queue()
        procs = [
            process_context.Process(
                target=worker,
                args=(worker_id, prefix_hex, postfix_hex, stop_evt, out_q),
                name=f"vanity-worker-{worker_id}",
            )
            for worker_id in range(workers)
        ]
        started_at = time.perf_counter()

        for proc in procs:
            signal_state.raise_if_requested()
            proc.start()
            started_procs.append(proc)

        wait_for_search_trigger(
            started_procs,
            out_q,
            state,
            prefix_hex,
            postfix_hex,
            started_at,
            nominal_attempts,
            signal_state,
        )
        stop_workers(report_missing=True)
        signal_state.raise_if_requested()

        if state.match_private_key is None or state.match_addr_hex is None:
            error = (
                state.errors[0]
                if state.errors
                else "all workers exited without a match"
            )
            print(f"ERROR: {error}", file=sys.stderr)
            return 1

        # A valid, independently verified match remains useful if another
        # worker failed only while coordinated shutdown was already underway.
        for error in state.errors:
            print(f"WARNING: {error}", file=sys.stderr)

        identity = RNS.Identity.from_bytes(state.match_private_key)
        if identity is None:
            raise RuntimeError("could not reconstruct the winning identity")

        derived_addr_hex = lxmf_hash_hex_for_identity(identity)
        if derived_addr_hex != state.match_addr_hex or not matches_vanity(
            derived_addr_hex, prefix_hex, postfix_hex
        ):
            raise RuntimeError("final LXMF result validation failed")

        staging.write_private_key(state.match_private_key)
        saved_path = staging.publish()

        try:
            reloaded = RNS.Identity.from_file(saved_path)
            if reloaded is None:
                raise RuntimeError("saved identity could not be reloaded by RNS")
            reloaded_addr_hex = lxmf_hash_hex_for_identity(reloaded)
            if reloaded_addr_hex != state.match_addr_hex or not matches_vanity(
                reloaded_addr_hex, prefix_hex, postfix_hex
            ):
                raise RuntimeError(
                    "saved identity does not reproduce the requested LXMF address"
                )
        except Exception as exc:
            removed = staging.remove_published_final()
            cleanup = (
                "removed invalid final output"
                if removed
                else f"could not remove final output {saved_path!r}"
            )
            raise OutputWriteError(
                f"Output verification failed; {cleanup}: {exc}"
            ) from exc

        extra_private_path = staging.finalize()
        if extra_private_path is not None:
            print(
                "WARNING: final output is valid, but an additional private-key "
                f"link remains at {extra_private_path!r}; remove it securely.",
                file=sys.stderr,
            )

        elapsed = time.perf_counter() - started_at
        print_success(
            prefix_hex=prefix_hex,
            postfix_hex=postfix_hex,
            address_hex=state.match_addr_hex,
            private_key=state.match_private_key,
            saved_path=saved_path,
            total_tries=state.total_tries,
            count_exact=state.attempt_count_exact,
            elapsed=elapsed,
            show_private_import_strings=args.show_private_import_strings,
        )
        if signal_state.signum is not None:
            print(
                "WARNING: a termination signal arrived while the verified "
                "private output was being committed; publication completed "
                "safely and this invocation is reporting success.",
                file=sys.stderr,
            )
        return 0

    except KeyboardInterrupt:
        try:
            stop_workers(report_missing=False)
        except Exception as shutdown_exc:
            print(f"WARNING: worker shutdown failed: {shutdown_exc}", file=sys.stderr)
        _print_interruption_summary("Interrupted", state, started_at)
        return 130
    except TerminationRequested:
        try:
            stop_workers(report_missing=False)
        except Exception as shutdown_exc:
            print(f"WARNING: worker shutdown failed: {shutdown_exc}", file=sys.stderr)
        _print_interruption_summary("Terminated", state, started_at)
        return 143
    except Exception as exc:
        try:
            stop_workers(report_missing=False)
        except Exception as shutdown_exc:
            print(f"WARNING: worker shutdown failed: {shutdown_exc}", file=sys.stderr)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        if not workers_collected:
            try:
                stop_workers(report_missing=False)
            except Exception as shutdown_exc:
                print(
                    f"WARNING: final worker cleanup failed: {shutdown_exc}",
                    file=sys.stderr,
                )
        if out_q is not None:
            close_queue(out_q)
        if staging is not None:
            recovery_path = staging.cleanup()
            if recovery_path is not None:
                print(
                    "RECOVERY: private-key staging was preserved at "
                    f"{recovery_path!r}. It is mode 0600; do not share it.",
                    file=sys.stderr,
                )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    signal_state = SignalState()
    previous_signal_handlers: dict[int, object] = {}

    try:
        for signal_name in ("SIGINT", "SIGTERM"):
            termination_signal = getattr(signal, signal_name, None)
            if termination_signal is None:
                continue
            try:
                previous_signal_handlers[termination_signal] = signal.signal(
                    termination_signal, signal_state.request
                )
            except (OSError, ValueError):
                # Signal registration is only available in the main thread.
                pass

        prefix_hex, postfix_hex = normalize_and_validate_patterns(
            args.prefix, args.postfix
        )
        workers = validate_workers(args.workers)

        required_positions = constrained_positions(prefix_hex, postfix_hex)
        nominal_attempts = expected_attempts(prefix_hex, postfix_hex)
        if required_positions > MAX_UNFORCED_CONSTRAINED_HEX and not args.force:
            print(
                "ERROR: this search constrains "
                f"{required_positions} hex characters and has a nominal mean of "
                f"{nominal_attempts:,} attempts under a uniform-hash model. "
                "Re-run with --force if this is intentional.",
                file=sys.stderr,
            )
            return 2

        signal_state.raise_if_requested()
        crypto_description = validate_runtime_environment()
        signal_state.raise_if_requested()
        return run_generation(
            args,
            prefix_hex,
            postfix_hex,
            workers,
            crypto_description,
            nominal_attempts,
            signal_state,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted before generation could start.", file=sys.stderr)
        return 130
    except TerminationRequested:
        print("Terminated before generation could start.", file=sys.stderr)
        return 143
    finally:
        for termination_signal, previous_handler in previous_signal_handlers.items():
            try:
                signal.signal(termination_signal, previous_handler)
            except (OSError, ValueError):
                pass


if __name__ == "__main__":
    mp.freeze_support()
    sys.exit(main())
