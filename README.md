# Vanity LXMF address generator

A security-focused command-line generator for a Reticulum identity whose final
`lxmf.delivery` destination hash has a chosen hexadecimal prefix, postfix, or
both.

This release is tested with the current **Reticulum 1.4.2** release and accepts
compatible Reticulum 1.x updates. It uses the official public API for key
generation and address derivation:

```python
identity = RNS.Identity(create_keys=True)
address = RNS.Destination.hash(identity, "lxmf", "delivery").hex()
```

The matched value is exactly the final 16-byte destination hash rendered by
`bytes.hex()` as 32 lowercase hexadecimal characters. See the
[Reticulum API reference](https://reticulum.network/manual/reference.html) for
the upstream API semantics.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting guidance.

## Installation

Use Python 3.10 or newer in an isolated environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

`requirements.txt` requires `rns>=1.4.2,<2.0` and a non-vulnerable PyCA
`cryptography>=50.0.0` instead of locking the application to one patch release.
At startup, the generator rejects local package shadowing and runs a public-API
semantic self-test: it creates and serializes an identity, reconstructs it, and
confirms that both official destination-hash helpers produce the same canonical
`lxmf.delivery` address. This gives compatible updates room to install while
failing closed if an update changes a relied-on API or serialization invariant.

For reproducible deployments, resolve these ranges into an environment lock or
artifact manifest after the release checks pass. Re-run the suite whenever the
resolved RNS or cryptography version changes.

## Usage

```text
python main.py \
  [--prefix=<PREFIX>] \
  [--postfix=<POSTFIX>] \
  [--workers=<NUMBER_OF_PROCESSES>] \
  --out=<DESTINATION>
```

Optional safety and output flags:

```text
--force
--show-private-import-strings
--version
```

Examples:

```sh
python main.py --prefix=cafe --out=./cafe.identity
python main.py --postfix=beef --workers=4 --out=./beef.identity
python main.py --prefix=ace --postfix=bad --out=./ace-bad.identity
```

`--workers` starts OS processes, not Python threads. Identity generation is
CPU-bound, and processes provide predictable multicore scaling across Python
and cryptographic backend implementations.

### Pattern rules

- At least one of `--prefix` and `--postfix` must be non-empty.
- Each pattern is case-normalized, must contain only `0-9` and `a-f`, and may
  contain at most 32 characters.
- Matching is performed on the complete canonical 32-character lowercase
  destination hash. It is never performed on raw bytes or an intermediate
  identity hash.
- Supplying both patterns is logical AND: the address must start with the
  prefix and end with the postfix.
- Odd lengths are valid and constrain individual hexadecimal nibbles.
- Prefix and postfix may overlap. A compatible overlap is accepted; a
  contradictory overlap is rejected before workers start.
- Empty strings, whitespace, `0x` notation, non-ASCII lookalikes, invalid hex,
  contradictory overlap, and patterns longer than 32 characters are rejected.
- Searches constraining more than six distinct hex positions require
  `--force`. This guard prevents accidental searches with a nominal mean above
  16,777,216 attempts; it does not make forced searches practical.

A fully constrained 32-character target has nominal per-attempt odds of
`1 / 2^128` under the uniform-hash model. It is computationally infeasible,
and the program does not promise that an arbitrary exact target is reachable.

## Private-key and output safety

`--out` is required and must name a path that does not exist. The resulting
file contains the raw 64 private-key bytes returned by
`RNS.Identity.get_private_key()`. It can be loaded directly with
`RNS.Identity.from_file()` and must reproduce the reported `lxmf.delivery`
address.

Before starting an expensive search, the generator verifies that the output
directory and publication method work. It creates a short, unpredictable
mode-`0600` staging file and uses a disposable hidden probe in that directory.
The requested final path remains absent throughout preflight and never contains
marker data. After finding a match the generator:

1. independently reconstructs the worker's identity and re-derives the hash;
2. writes and flushes the private key to staging;
3. reloads the staged file through `RNS.Identity.from_file()`;
4. publishes without overwrite, including if another process races for the
   final path;
5. reloads the final file and verifies the address again; and
6. removes the staging name only after final verification.

Hard-link publication is atomic and no-overwrite on filesystems that support
it. A portable exclusive-create fallback retains no-overwrite behavior where
hard links are unavailable, although the final name can briefly be visible
while its 64 bytes are written. Directory metadata is flushed where the
platform supports it.

If a late publication or verification error occurs, the winning private key is
kept in the staging file and its path is printed as `RECOVERY:`. Treat every
file named `.lxmf-identity-*.staging` as secret: a force kill, power loss, or
process crash can leave either a harmless preflight marker or private key
material there. A leftover `.lxmf-identity-*.probe` contains no private key.
Do not display a staging file's contents while investigating it.

The generator never overwrites an existing path or follows a final-path
symlink. These controls do not make an attacker-controlled parent directory
safe. Write identities only to a private, trusted directory. Backups,
filesystem snapshots, endpoint security software, swap, and terminal logging
can retain secrets outside the program's control. POSIX mode `0600` is enforced
where supported; verify equivalent ACL protection on non-POSIX systems.

The identity file is secret. Anyone who obtains it controls that identity and
can decrypt traffic protected for it. The file does not include display names,
message history, application configuration, or LXMF ratchet state.

### Optional import strings

Private-key encodings are not printed by default. With
`--show-private-import-strings`, the program prints the URL-safe Base64 and
Base32 forms used by RNS `rnid`. They are unencrypted copies of the private key
and can leak through terminal scrollback, shell redirection, CI logs, screen
sharing, or support transcripts.

## Performance and shutdown behavior

If `k` distinct hexadecimal positions are constrained, the nominal mean is
`16^k` generated identities. Each additional position increases the expected
work by 16 times. Prefix/postfix overlap is counted once.

The default worker count follows the CPU quota visible to the process and is
clamped to 32 to avoid surprising memory use on very large hosts. Explicit
values are limited to twice the available CPU count, capped at 256. More workers
can reduce performance through scheduling, memory pressure, or thermal
throttling, so benchmark on the deployment host.

Workers batch progress messages to keep inter-process overhead out of the hot
loop. The parent validates all worker messages and independently reconstructs
any claimed winner. A worker that exits without its completion message is
reported as a runtime failure—even while the progress queue remains
continuously busy—instead of allowing the search to run silently at reduced
capacity.

Workers use Python's clean `spawn` process context on every platform. This has
a small startup cost, but avoids inheriting the private output descriptor or
forking live cryptographic library state. The parent refuses to publish a key
unless all workers have stopped, including after forced shutdown.

On POSIX systems, Ctrl+C and SIGTERM request coordinated shutdown. Signals are
handled at safe checkpoints so they cannot split private-key filesystem
transactions. If a signal arrives after final publication begins, the program
finishes verification, reports the saved result, and exits successfully.

Exit codes are:

- `0`: verified identity saved successfully;
- `1`: runtime, worker, cryptographic, or output failure;
- `2`: CLI, validation, compatibility, or safety-guard failure;
- `130`: interrupted by SIGINT before publication; and
- `143`: terminated by SIGTERM before publication.

Status, warnings, and errors go to `stderr`. The final result goes to `stdout`.

## Verification

Run the complete suite in the same environment intended for release:

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python -m compileall -q main.py tests
python -m ruff check main.py tests
python -m ruff format --check main.py tests
python -m bandit -q -r main.py
python -m pip_audit --requirement requirements.txt --progress-spinner off
```

The 56-test suite includes independent hash-formula checks, official helper
equivalence, canonical prefix/postfix AND matching, compatible and conflicting
overlap cases, real postfix-only and two-process searches, worker protocol and
hard-exit handling, output races, publication fallbacks, interruption rollback,
privacy-by-default output, and real SIGINT/SIGTERM subprocess tests.

The GitHub Actions workflow repeats these quality checks and runs the functional
suite on Python 3.10 under Linux and Python 3.14 under Linux, macOS, and Windows.
Official actions are pinned to the immutable commit hashes of their latest
releases. Require the complete workflow to pass before publishing a release.
