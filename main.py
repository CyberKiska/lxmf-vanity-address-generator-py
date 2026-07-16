from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
import multiprocessing as mp
import os
import queue
import signal
import sys
import tempfile
import time
from typing import Sequence

try:
    import RNS
except ImportError as exc:  # pragma: no cover - exercised without the dependency
    raise SystemExit(
        "ERROR: Reticulum is not installed. Install a supported version with "
        "'python -m pip install -r requirements.txt'."
    ) from exc


LXMF_APP_NAME = "lxmf"
LXMF_ASPECTS = ("delivery",)
DEST_HASH_HEX_LEN = RNS.Reticulum.TRUNCATED_HASHLENGTH // 4
HEX_ALPHABET = frozenset("0123456789abcdef")
PROGRESS_BATCH_SIZE = 1024
STATUS_INTERVAL = 1.0
SHUTDOWN_TIMEOUT = 5.0
QUEUE_FLUSH_GRACE = 0.25
MAX_UNFORCED_CONSTRAINED_HEX = 8
ABSOLUTE_MAX_WORKERS = 256

MSG_PROGRESS = "progress"
MSG_MATCH = "match"
MSG_ERROR = "error"
MSG_DONE = "done"


class TerminationRequested(BaseException):
    """Raised in the parent process when SIGTERM requests clean shutdown."""


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


def normalize_hex_pattern(name: str, value: str) -> str:
    normalized = (value or "").lower()
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

    combined_length = len(prefix_hex) + len(postfix_hex)
    if combined_length > DEST_HASH_HEX_LEN:
        raise ValueError(
            "combined prefix and postfix length must be at most "
            f"{DEST_HASH_HEX_LEN} hex characters; got {combined_length}."
        )

    return prefix_hex, postfix_hex


def available_cpu_count() -> int:
    process_cpu_count = getattr(os, "process_cpu_count", None)
    count = process_cpu_count() if process_cpu_count is not None else os.cpu_count()
    return max(1, count or 1)


def maximum_worker_count() -> int:
    return min(ABSOLUTE_MAX_WORKERS, max(1, available_cpu_count() * 2))


def validate_workers(raw_workers: int) -> int:
    workers = int(raw_workers)
    maximum = maximum_worker_count()
    if workers < 1 or workers > maximum:
        raise ValueError(f"workers must be an integer in the range 1..{maximum}.")
    return workers


def constrained_positions(prefix_hex: str, postfix_hex: str) -> int:
    # Validated prefix and postfix constraints cannot overlap because their
    # combined length is at most the full destination hash length.
    return len(prefix_hex) + len(postfix_hex)


def expected_attempts(prefix_hex: str, postfix_hex: str) -> int:
    return 16 ** constrained_positions(prefix_hex, postfix_hex)


def encode_base64(private_key_bytes: bytes) -> str:
    return base64.b64encode(private_key_bytes).decode("ascii")


def encode_base32(private_key_bytes: bytes) -> str:
    return base64.b32encode(private_key_bytes).decode("ascii")


def validate_output_path(path: str) -> str:
    abs_path = os.path.abspath(path)
    parent = os.path.dirname(abs_path) or "."

    if not os.path.isdir(parent):
        raise ValueError(f"output directory does not exist: {parent}")
    if os.path.lexists(abs_path):
        raise ValueError(f"refusing to overwrite existing file: {abs_path}")

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


def secure_write_identity(path: str, private_key_bytes: bytes) -> str:
    """Atomically publish a new mode-0600 RNS identity without overwriting."""
    abs_path = os.path.abspath(path)
    parent = os.path.dirname(abs_path) or "."
    expected_key_length = RNS.Identity.KEYSIZE // 8

    if not isinstance(private_key_bytes, bytes):
        raise RuntimeError("Identity private key must be bytes.")
    if len(private_key_bytes) != expected_key_length:
        raise RuntimeError(
            f"Identity private key must be {expected_key_length} bytes; "
            f"got {len(private_key_bytes)}."
        )
    if not os.path.isdir(parent):
        raise RuntimeError(f"Output directory does not exist: {parent}")

    basename = os.path.basename(abs_path) or "identity"
    fd = -1
    temp_path: str | None = None

    try:
        fd, temp_path = tempfile.mkstemp(
            prefix=f".{basename}.", suffix=".tmp", dir=parent
        )
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)

        with os.fdopen(fd, "wb") as handle:
            fd = -1
            written = handle.write(private_key_bytes)
            if written != len(private_key_bytes):
                raise OSError(
                    f"Short identity write: expected {len(private_key_bytes)}, wrote {written}"
                )
            handle.flush()
            os.fsync(handle.fileno())

        try:
            os.link(temp_path, abs_path, follow_symlinks=False)
        except TypeError:  # Older platforms may not expose follow_symlinks.
            os.link(temp_path, abs_path)

        try:
            os.unlink(temp_path)
            temp_path = None
        except OSError as exc:
            try:
                os.unlink(abs_path)
            except OSError:
                pass
            raise RuntimeError(
                f"Could not remove temporary private-key file {temp_path}: {exc}"
            ) from exc

        _fsync_directory(parent)
        return abs_path
    except FileExistsError as exc:
        raise RuntimeError(f"Refusing to overwrite existing file: {abs_path}") from exc
    except RuntimeError:
        raise
    except OSError as exc:
        raise RuntimeError(f"Could not save output file {abs_path}: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def remove_new_output(path: str) -> bool:
    """Best-effort cleanup for a file created by this invocation."""
    try:
        os.unlink(path)
        _fsync_directory(os.path.dirname(path) or ".")
        return True
    except OSError:
        return False


def _matches_patterns(addr_hex: str, prefix_hex: str, postfix_hex: str) -> bool:
    return (
        (not prefix_hex or addr_hex.startswith(prefix_hex))
        and (not postfix_hex or addr_hex.endswith(postfix_hex))
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
                out_q.put(
                    (MSG_MATCH, worker_id, identity.get_private_key(), addr_hex)
                )
                stop_evt.set()
                break

            if local_tries - reported_tries >= PROGRESS_BATCH_SIZE:
                out_q.put((MSG_PROGRESS, worker_id, local_tries - reported_tries))
                reported_tries = local_tries
    except Exception as exc:
        out_q.put(
            (MSG_ERROR, worker_id, f"{type(exc).__name__}: {exc}")
        )
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
) -> None:
    if not isinstance(message, tuple) or not message:
        state.errors.append("received a malformed worker message")
        return

    tag = message[0]
    try:
        if tag == MSG_PROGRESS and len(message) == 3:
            worker_id, count = message[1], message[2]
            if not isinstance(worker_id, int) or not isinstance(count, int) or count < 0:
                raise ValueError("invalid progress payload")
            state.total_tries += count
        elif tag == MSG_MATCH and len(message) == 4:
            worker_id = message[1]
            if not isinstance(worker_id, int):
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
            if not isinstance(worker_id, int) or not isinstance(error, str):
                raise ValueError("invalid error payload")
            state.errors.append(f"worker {worker_id}: {error}")
        elif tag == MSG_DONE and len(message) == 2:
            worker_id = message[1]
            if not isinstance(worker_id, int):
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


def print_status(total_tries: int, started_at: float, mean_attempts: int) -> None:
    elapsed = max(time.perf_counter() - started_at, 1e-9)
    rate = total_tries / elapsed
    estimate = "unknown"
    if rate > 0:
        estimate = format_duration(mean_attempts / rate)
    print(
        f"[status] tries={total_tries:,} elapsed={elapsed:.1f}s "
        f"rate={rate:,.0f}/s mean_time_at_rate={estimate}",
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
    mean_attempts: int,
) -> None:
    last_status = started_at

    while state.match_private_key is None and not state.errors:
        try:
            message = out_q.get(timeout=0.25)
        except queue.Empty:
            if not any(proc.is_alive() for proc in procs):
                return
        else:
            record_worker_message(message, state, prefix_hex, postfix_hex)

        now = time.perf_counter()
        if now - last_status >= STATUS_INTERVAL:
            print_status(state.total_tries, started_at, mean_attempts)
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

    while not expected_worker_ids.issubset(state.done_workers) and time.monotonic() < deadline:
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
            record_worker_message(message, state, prefix_hex, postfix_hex)

    graceful_join_deadline = time.monotonic() + 0.5
    for proc in procs:
        remaining = graceful_join_deadline - time.monotonic()
        if remaining > 0:
            proc.join(timeout=remaining)

    for proc in procs:
        if proc.is_alive():
            proc.terminate()
    for proc in procs:
        proc.join(timeout=0.5)

    for proc in procs:
        if proc.is_alive() and hasattr(proc, "kill"):
            proc.kill()
    for proc in procs:
        if proc.is_alive():
            proc.join(timeout=0.5)

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


def raise_termination_requested(_signum: int, _frame: object) -> None:
    raise TerminationRequested


def build_parser() -> argparse.ArgumentParser:
    cpu_count = available_cpu_count()
    parser = argparse.ArgumentParser(
        description="Reticulum LXMF vanity address generator"
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
        default="./identity",
        help="Path for the raw RNS identity private-key file (default: ./identity).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=cpu_count,
        help=f"Worker processes to run in parallel (default: {cpu_count}).",
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
        help="Print Base64/Base32 private-key encodings (sensitive; unsafe for logs).",
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
    print(f"Saved file  : {saved_path}")
    print("File format : raw private-key bytes for RNS.Identity.from_file()")

    if show_private_import_strings:
        print("Warning     : the strings below are the private key; do not log or share them")
        print("\n--- Generic private-key encodings ---")
        print(f"Base64:\n{encode_base64(private_key)}")
        print(f"Base32:\n{encode_base32(private_key)}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if DEST_HASH_HEX_LEN != 32:
            raise ValueError(
                "unsupported RNS destination hash length: expected 32 hex characters, "
                f"got {DEST_HASH_HEX_LEN}."
            )
        prefix_hex, postfix_hex = normalize_and_validate_patterns(
            args.prefix, args.postfix
        )
        workers = validate_workers(args.workers)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    required_positions = constrained_positions(prefix_hex, postfix_hex)
    mean_attempts = expected_attempts(prefix_hex, postfix_hex)
    if required_positions > MAX_UNFORCED_CONSTRAINED_HEX and not args.force:
        print(
            "ERROR: this search constrains "
            f"{required_positions} hex characters and requires {mean_attempts:,} "
            "attempts on average. Re-run with --force if this is intentional.",
            file=sys.stderr,
        )
        return 2

    try:
        output_path = validate_output_path(args.out)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    difficulty_bits = 4 * required_positions
    print(
        f"Searching lxmf.delivery for prefix={prefix_hex or '-'} "
        f"postfix={postfix_hex or '-'} with {workers} worker process(es).",
        file=sys.stderr,
    )
    print(
        f"Expected average attempts: {mean_attempts:,} "
        f"({difficulty_bits} constrained bits).",
        file=sys.stderr,
    )

    stop_evt = mp.Event()
    out_q = mp.Queue()
    procs = [
        mp.Process(
            target=worker,
            args=(worker_id, prefix_hex, postfix_hex, stop_evt, out_q),
            name=f"vanity-worker-{worker_id}",
        )
        for worker_id in range(workers)
    ]
    started_procs: list[mp.Process] = []
    state = SearchState()
    started_at = time.perf_counter()
    previous_sigterm_handler: object | None = None

    sigterm = getattr(signal, "SIGTERM", None)
    if sigterm is not None:
        try:
            previous_sigterm_handler = signal.signal(
                sigterm, raise_termination_requested
            )
        except (OSError, ValueError):
            previous_sigterm_handler = None

    try:
        for proc in procs:
            proc.start()
            started_procs.append(proc)

        wait_for_search_trigger(
            started_procs,
            out_q,
            state,
            prefix_hex,
            postfix_hex,
            started_at,
            mean_attempts,
        )
        collect_worker_shutdown(
            started_procs,
            stop_evt,
            out_q,
            state,
            prefix_hex,
            postfix_hex,
        )
    except KeyboardInterrupt:
        collect_worker_shutdown(
            started_procs,
            stop_evt,
            out_q,
            state,
            prefix_hex,
            postfix_hex,
            report_missing=False,
        )
        elapsed = time.perf_counter() - started_at
        rate = state.total_tries / elapsed if elapsed > 0 else 0.0
        suffix = "" if state.attempt_count_exact else " (reported)"
        print(
            f"Interrupted after {state.total_tries:,} attempts{suffix} in "
            f"{elapsed:.2f}s ({rate:,.0f}/s).",
            file=sys.stderr,
        )
        return 130
    except TerminationRequested:
        if sigterm is not None:
            try:
                signal.signal(sigterm, signal.SIG_IGN)
            except (OSError, ValueError):
                pass
        collect_worker_shutdown(
            started_procs,
            stop_evt,
            out_q,
            state,
            prefix_hex,
            postfix_hex,
            report_missing=False,
        )
        elapsed = time.perf_counter() - started_at
        rate = state.total_tries / elapsed if elapsed > 0 else 0.0
        suffix = "" if state.attempt_count_exact else " (reported)"
        print(
            f"Terminated after {state.total_tries:,} attempts{suffix} in "
            f"{elapsed:.2f}s ({rate:,.0f}/s).",
            file=sys.stderr,
        )
        return 143
    except Exception as exc:
        collect_worker_shutdown(
            started_procs,
            stop_evt,
            out_q,
            state,
            prefix_hex,
            postfix_hex,
            report_missing=False,
        )
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        if sigterm is not None and previous_sigterm_handler is not None:
            try:
                signal.signal(sigterm, previous_sigterm_handler)
            except (OSError, ValueError):
                pass
        close_queue(out_q)

    if state.match_private_key is None or state.match_addr_hex is None:
        error = state.errors[0] if state.errors else "all workers exited without a match"
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    # A valid, independently verified match is useful even if another worker
    # failed while shutdown was already in progress.
    for error in state.errors:
        print(f"WARNING: {error}", file=sys.stderr)

    identity = RNS.Identity.from_bytes(state.match_private_key)
    if identity is None:
        print("ERROR: Could not reconstruct the winning identity.", file=sys.stderr)
        return 1

    derived_addr_hex = lxmf_hash_hex_for_identity(identity)
    if derived_addr_hex != state.match_addr_hex or not matches_vanity(
        derived_addr_hex, prefix_hex, postfix_hex
    ):
        print("ERROR: Final LXMF result validation failed.", file=sys.stderr)
        return 1

    try:
        saved_path = secure_write_identity(output_path, state.match_private_key)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

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
        removed = remove_new_output(saved_path)
        cleanup = (
            "removed output file"
            if removed
            else f"could not remove output file {saved_path!r}"
        )
        print(f"ERROR: Output verification failed; {cleanup}: {exc}", file=sys.stderr)
        return 1

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
    return 0


if __name__ == "__main__":
    mp.freeze_support()
    sys.exit(main())
