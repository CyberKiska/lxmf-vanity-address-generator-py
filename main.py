import argparse
import base64
import multiprocessing as mp
import os
import queue
import signal
import sys
import time

import RNS


LXMF_APP_NAME = "lxmf"
LXMF_ASPECTS = ("delivery",)
DEST_HASH_HEX_LEN = RNS.Reticulum.TRUNCATED_HASHLENGTH // 4
HEX_ALPHABET = frozenset("0123456789abcdef")
PROGRESS_BATCH_SIZE = 1024
STATUS_INTERVAL = 1.0
SHUTDOWN_TIMEOUT = 5.0


def lxmf_hash_hex_for_identity(identity: RNS.Identity) -> str:
    return RNS.Destination.hash(identity, LXMF_APP_NAME, *LXMF_ASPECTS).hex()


def gen_identity() -> RNS.Identity:
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


def validate_workers(raw_workers: int) -> int:
    workers = int(raw_workers)
    if workers < 1:
        raise ValueError("workers must be an integer greater than or equal to 1.")
    return workers


def expected_attempts(prefix_hex: str, postfix_hex: str) -> int:
    return 16 ** constrained_positions(prefix_hex, postfix_hex)


def encode_base64(private_key_bytes: bytes) -> str:
    return base64.b64encode(private_key_bytes).decode("ascii")


def encode_base32(private_key_bytes: bytes) -> str:
    return base64.b32encode(private_key_bytes).decode("ascii")


def build_constraint_mask(prefix_hex: str, postfix_hex: str):
    mask = [None] * DEST_HASH_HEX_LEN

    for index, ch in enumerate(prefix_hex):
        mask[index] = ch

    postfix_start = DEST_HASH_HEX_LEN - len(postfix_hex)
    for offset, ch in enumerate(postfix_hex):
        index = postfix_start + offset
        current = mask[index]
        if current is not None and current != ch:
            raise ValueError(
                "prefix and postfix are incompatible at "
                f"hash position {index}: {current!r} != {ch!r}."
            )
        mask[index] = ch

    return tuple(mask)


def constrained_positions(prefix_hex: str, postfix_hex: str) -> int:
    return sum(ch is not None for ch in build_constraint_mask(prefix_hex, postfix_hex))


def validate_output_path(path: str) -> str:
    abs_path = os.path.abspath(path)
    parent = os.path.dirname(abs_path) or "."

    if not os.path.isdir(parent):
        raise ValueError(f"output directory does not exist: {parent}")
    if os.path.lexists(abs_path):
        raise ValueError(f"refusing to overwrite existing file: {abs_path}")

    return abs_path


def secure_write_identity(path: str, private_key_bytes: bytes) -> str:
    abs_path = os.path.abspath(path)
    parent = os.path.dirname(abs_path) or "."

    if not os.path.isdir(parent):
        raise RuntimeError(f"Output directory does not exist: {parent}")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(abs_path, flags, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(f"Refusing to overwrite existing file: {abs_path}") from exc
    except OSError as exc:
        raise RuntimeError(f"Could not open output file {abs_path}: {exc}") from exc

    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(private_key_bytes)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.unlink(abs_path)
        except OSError:
            pass
        raise

    return abs_path


def matches_vanity(addr_hex: str, prefix_hex: str, postfix_hex: str) -> bool:
    return (
        (not prefix_hex or addr_hex.startswith(prefix_hex))
        and (not postfix_hex or addr_hex.endswith(postfix_hex))
    )


def worker(prefix_hex: str, postfix_hex: str, stop_evt: mp.Event, out_q: mp.Queue) -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    local_tries = 0
    reported_tries = 0

    try:
        while not stop_evt.is_set():
            identity = gen_identity()
            addr_hex = lxmf_hash_hex_for_identity(identity)
            local_tries += 1

            if matches_vanity(addr_hex, prefix_hex, postfix_hex):
                out_q.put(
                    ("match", identity.get_private_key(), addr_hex, local_tries - reported_tries)
                )
                stop_evt.set()
                return

            if local_tries - reported_tries >= PROGRESS_BATCH_SIZE:
                out_q.put(("progress", local_tries - reported_tries))
                reported_tries = local_tries

        leftover = local_tries - reported_tries
        if leftover:
            out_q.put(("progress", leftover))
    except Exception as exc:
        leftover = local_tries - reported_tries
        if leftover:
            out_q.put(("progress", leftover))
        out_q.put(("error", repr(exc)))
        stop_evt.set()


def drain_queue(out_q: mp.Queue, total_tries: int):
    errors = []
    while True:
        try:
            message = out_q.get_nowait()
        except queue.Empty:
            return total_tries, errors

        tag = message[0]
        if tag == "progress":
            total_tries += message[1]
        elif tag == "match":
            total_tries += message[3]
        elif tag == "error":
            errors.append(message[1])


def print_status(total_tries: int, started_at: float) -> None:
    elapsed = max(time.perf_counter() - started_at, 1e-9)
    rate = total_tries / elapsed
    print(
        f"[status] tries={total_tries:,} elapsed={elapsed:.1f}s rate={rate:,.0f}/s",
        file=sys.stderr,
        flush=True,
    )


def stop_workers(procs, stop_evt, out_q: mp.Queue, total_tries: int):
    stop_evt.set()
    deadline = time.monotonic() + SHUTDOWN_TIMEOUT

    while True:
        alive = [proc for proc in procs if proc.is_alive()]
        total_tries, errors = drain_queue(out_q, total_tries)
        if errors:
            return total_tries, errors
        if not alive:
            return total_tries, []
        if time.monotonic() >= deadline:
            break
        for proc in alive:
            proc.join(timeout=0.05)

    for proc in procs:
        if proc.is_alive():
            proc.terminate()
    for proc in procs:
        proc.join(timeout=0.2)

    return drain_queue(out_q, total_tries)


def main() -> int:
    parser = argparse.ArgumentParser(description="Reticulum LXMF vanity address generator")
    parser.add_argument(
        "--prefix",
        default="",
        help="Desired lowercase-hex prefix for the 32-char lxmf.delivery destination hash.",
    )
    parser.add_argument(
        "--postfix",
        default="",
        help="Desired lowercase-hex postfix for the 32-char lxmf.delivery destination hash.",
    )
    parser.add_argument(
        "--out",
        default="./identity",
        help="Path to save the found RNS identity file (default: ./identity)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=max(1, os.cpu_count() or 1),
        help="Number of worker processes to run in parallel (default: CPU count).",
    )
    args = parser.parse_args()

    try:
        prefix_hex = normalize_hex_pattern("prefix", args.prefix)
        postfix_hex = normalize_hex_pattern("postfix", args.postfix)
        workers = validate_workers(args.workers)
        output_path = validate_output_path(args.out)
        required_positions = constrained_positions(prefix_hex, postfix_hex)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if not prefix_hex and not postfix_hex:
        print("ERROR: at least one of --prefix or --postfix must be provided.", file=sys.stderr)
        return 2

    difficulty_bits = 4 * required_positions
    print(
        f"Searching lxmf.delivery for prefix={prefix_hex or '-'} postfix={postfix_hex or '-'} "
        f"with {workers} worker process(es).",
        file=sys.stderr,
    )
    print(
        f"Expected average attempts: {expected_attempts(prefix_hex, postfix_hex):,} "
        f"({difficulty_bits} constrained bits).",
        file=sys.stderr,
    )

    stop_evt = mp.Event()
    out_q = mp.Queue()
    procs = [
        mp.Process(target=worker, args=(prefix_hex, postfix_hex, stop_evt, out_q))
        for _ in range(workers)
    ]

    started_at = time.perf_counter()
    last_status = started_at
    total_tries = 0
    match_private_key = None
    match_addr_hex = None

    try:
        for proc in procs:
            proc.start()

        while match_private_key is None:
            try:
                message = out_q.get(timeout=0.25)
            except queue.Empty:
                if not any(proc.is_alive() for proc in procs):
                    raise RuntimeError("All workers exited without returning a match.")

                now = time.perf_counter()
                if now - last_status >= STATUS_INTERVAL:
                    print_status(total_tries, started_at)
                    last_status = now
                continue

            tag = message[0]
            if tag == "progress":
                total_tries += message[1]
            elif tag == "match":
                match_private_key = message[1]
                match_addr_hex = message[2]
                total_tries += message[3]
                stop_evt.set()
            elif tag == "error":
                raise RuntimeError(f"Worker failure: {message[1]}")

            now = time.perf_counter()
            if now - last_status >= STATUS_INTERVAL:
                print_status(total_tries, started_at)
                last_status = now

        total_tries, errors = stop_workers(procs, stop_evt, out_q, total_tries)
        if errors:
            raise RuntimeError(f"Worker failure: {errors[0]}")

    except KeyboardInterrupt:
        total_tries, _ = stop_workers(procs, stop_evt, out_q, total_tries)
        elapsed = time.perf_counter() - started_at
        rate = total_tries / elapsed if elapsed > 0 else 0.0
        print(
            f"Interrupted after {total_tries:,} attempts in {elapsed:.2f}s "
            f"({rate:,.0f}/s).",
            file=sys.stderr,
        )
        return 130
    except Exception as exc:
        total_tries, _ = stop_workers(procs, stop_evt, out_q, total_tries)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    identity = RNS.Identity.from_bytes(match_private_key)
    if identity is None:
        print("ERROR: Could not reconstruct identity from worker result.", file=sys.stderr)
        return 1

    derived_addr_hex = lxmf_hash_hex_for_identity(identity)
    if derived_addr_hex != match_addr_hex:
        print("ERROR: Worker returned an inconsistent LXMF destination hash.", file=sys.stderr)
        return 1

    try:
        saved_path = secure_write_identity(output_path, match_private_key)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    reloaded = RNS.Identity.from_file(saved_path)
    if reloaded is None:
        print("ERROR: Saved identity could not be reloaded by RNS.", file=sys.stderr)
        return 1

    reloaded_addr_hex = lxmf_hash_hex_for_identity(reloaded)
    if reloaded_addr_hex != match_addr_hex:
        print("ERROR: Reloaded identity yields a different LXMF destination hash.", file=sys.stderr)
        return 1

    elapsed = time.perf_counter() - started_at
    rate = total_tries / elapsed if elapsed > 0 else 0.0

    print("\n=== Vanity LXMF Identity Found ===")
    if prefix_hex:
        print(f"Prefix      : {prefix_hex}")
    if postfix_hex:
        print(f"Postfix     : {postfix_hex}")
    print(f"LXMF addr   : {match_addr_hex}")
    print(f"Attempts    : {total_tries}")
    print(f"Elapsed [s] : {elapsed:.2f}")
    print(f"Rate [1/s]  : {rate:,.0f}")
    print(f"Saved file  : {saved_path}")
    print("File format : raw RNS private-key bytes compatible with RNS.Identity.from_file()")
    print("Warning     : import strings below contain the private key; handle carefully")
    print("\n--- Import formats ---")
    print(f"Base64 (MeshChat import string):\n{encode_base64(match_private_key)}")
    print(f"Base32 (Sideband import string):\n{encode_base32(match_private_key)}")

    return 0


if __name__ == "__main__":
    mp.freeze_support()
    sys.exit(main())
