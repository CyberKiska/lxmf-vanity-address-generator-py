# Vanity LXMF address generator

A security-focused command-line generator for a Reticulum identity whose final
`lxmf.delivery` destination hash has a chosen hexadecimal prefix, postfix, or
both.

Startup known-answer tests check the key layout and address derivation of the
installed Reticulum package. Local verification on 2026-10-13 used **RNS 1.5.7**
and **cryptography 50.0.2** on CPython 3.14.7 under macOS. The installation
minimum is RNS 1.5.2; historical checks on older releases do not establish
production support. Key generation and address derivation use the official
public API:

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

Use Python 3.14 in an isolated environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

`requirements.txt` requires `rns>=1.5.2` with no upper version bound and PyCA
`cryptography>=50.0.0`. Normal installation selects stable releases. Startup
checks both destination-hash helpers against an independent public vector,
private-to-public derivation against published RFC 7748 and RFC 8032 keys, and
exact serialization of a generated identity. These checks cover the protocol
properties this tool relies on; they do not establish dependency security or
full compatibility with every release that passes them.

The banner prints the imported RNS version, import location and selected crypto
backend. These values are informational. Use a trusted Python environment and
trusted package sources: startup checks cannot protect against malicious
import-time code or modified providers. Older or prerelease versions are not
blocked at runtime, but need separate verification and are outside the current
support claim. The supported installation uses PyCA; manually selecting RNS's
internal provider has reduced assurance because it has received less scrutiny
than OpenSSL, even when it passes the same vectors.

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
- An empty pattern is treated as absent; both patterns cannot be empty.
- Whitespace, `0x` notation, non-ASCII lookalikes, invalid hex,
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
Preflight marker allocation is not a storage reservation: a later write can
still fail if the disk fills or storage becomes unavailable.
The requested final path remains absent throughout preflight and never contains
marker data. After finding a match the generator:

1. independently reconstructs the worker's identity and re-derives the hash;
2. writes and flushes the private key to staging before worker shutdown;
3. reloads the staged file through `RNS.Identity.from_file()`;
4. publishes without overwrite, including if another process races for the
   final path;
5. reloads the final file and verifies the address again; and
6. removes the staging name only after final verification.

Hard-link publication is atomic and no-overwrite on filesystems that support
it. A portable exclusive-create fallback retains no-overwrite behavior where
hard links are unavailable, although the final name can briefly be visible
while its 64 bytes are written. Directory metadata is flushed where the
platform supports it. Unsupported directory flushing produces a warning before
generation. On macOS, each flush also requests `F_FULLFSYNC` to flush the drive
cache; absent or unsupported full flushing warns and retains the `fsync`
result. Actual storage or permission errors fail the operation; they are never
silently treated as unsupported. These requests improve durability but do not
guarantee recovery after every device failure or power loss.

On handled failures, the generator retains staging that may contain private
key material and reports its path as `RECOVERY:`. A staging write can be partial,
and a failed flush cannot establish durability; verify a recovery identity with
RNS before using it. Recovery reporting identifies a possible secret file, not
a guarantee that it contains a complete usable key. If flushing staging-name
removal fails after the final identity has already been committed, the error identifies the
saved final file instead. A failed run can therefore leave an identity at the
requested path; inspect the reported paths before retrying. Treat every
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

Before key generation, parent and workers make a best-effort request to suppress
ordinary POSIX file core dumps by setting the soft `RLIMIT_CORE` limit to zero.
This does not prevent Linux dumps piped to a crash collector, Windows Error
Reporting, privileged debugging, or snapshots; review those controls separately
on the deployment host.

The identity file is secret. Anyone who obtains it controls that identity and
can decrypt traffic protected for it. The file does not include display names,
message history, application configuration, or LXMF ratchet state.

### Randomness

Key material comes exclusively from `RNS.Identity(create_keys=True)`; this tool
draws no randomness for keys itself. In the inspected provider paths, RNS's PyCA
proxies use OpenSSL key generation, whose private random generator is seeded
from operating-system entropy; the internal provider uses `os.urandom(32)` for
each private half. The exact entropy path depends on the installed provider and
platform ([PyCA randomness documentation](https://cryptography.io/en/latest/random-numbers/)).
Workers use clean `spawn` processes, avoiding inherited generator state. A
parent-only startup check rejects repeated halves across two generated keys;
it detects some gross failures, not entropy quality, deterministic output,
worker RNG health, or standards certification.

### Using the identity

Check a generated file with the official utility:

```sh
python -m RNS.Utilities.rnid -i ./cafe.identity -H lxmf.delivery
```

This identity/hash inspection path does not start a Reticulum instance. Confirm
that the reported destination matches the generator's address.

Stop the receiving application and securely back up its existing identity
before replacing it. [NomadNet's identity path](https://github.com/markqvist/NomadNet/blob/master/nomadnet/NomadNetworkApp.py)
is `<config>/storage/identity`, usually under `~/.nomadnetwork` or
`~/.config/nomadnetwork`. For [lxmd](https://github.com/markqvist/LXMF/blob/master/LXMF/Utilities/lxmd.py)
it is `<config>/identity`, usually under
`~/.lxmd` or `~/.config/lxmd`; custom or system configuration directories can
change these locations. Preserve private permissions when transferring the
file. Replacing an identity changes the application's address; the generated
file carries no application or ratchet state.

### Optional import strings

Private-key encodings are not printed by default. With
`--show-private-import-strings`, the program prints the URL-safe Base64 and
Base32 forms used by RNS `rnid`. They are unencrypted copies of the private key
and can leak through terminal scrollback, shell redirection, CI logs, screen
sharing, or support transcripts. A warning is printed when stdout is not a
terminal.

About one URL-safe Base64 string in 64 begins with `-`, which `rnid -M <string>`
reads as an option. Use the attached form instead:

```sh
python -m RNS.Utilities.rnid --import-prv=<string> -H lxmf.delivery
```

A private key on a command line can be recorded in shell history and is
visible to other local users through the process list; prefer importing the
saved identity file.

## Performance and shutdown behavior

If `k` distinct hexadecimal positions are constrained, the nominal mean is
`16^k` generated identities. Each additional position increases the expected
work by 16 times. Prefix/postfix overlap is counted once.

The default worker count uses the available logical CPU count, respecting CPU
affinity where Python exposes it, and is capped at 32. This does not measure
cgroup CPU bandwidth quotas; set `--workers` explicitly in quota-limited
containers. Explicit values are limited to twice the available CPU count, capped
at 256. More workers
can reduce performance through scheduling, memory pressure, or thermal
throttling, so benchmark on the deployment host.

Workers report progress every 1,024 attempts and check cancellation every 64
attempts, avoiding shared synchronization on every generated identity. Each
worker has separate result and cancellation pipes. Result messages use bounded
JSON frames, and the parent independently reconstructs any claimed winner.
Worker failure is isolated to that worker's pipe and is detected even while
other workers are reporting progress. A verified match can still be saved if
another worker fails, with the failure reported as a warning.

The parent cancels workers by closing its cancellation writers. Workers also
observe this EOF if the parent crashes, so an active search does not depend on
the parent running its cleanup handler. Pipe buffers provide backpressure rather
than allowing an unbounded progress queue to grow. All workers share a five-second
shutdown deadline, followed by forced termination and a one-second join deadline.

Workers use Python's clean `spawn` process context on every platform. This has
a small startup cost, but avoids inheriting the private output descriptor or
forking live cryptographic library state. Startup stops launching additional
workers when a result or failure is already available. A `[ready]` message on
`stderr` confirms that the started workers are active. The normal search path
stages a verified winner before worker shutdown. A worker that cannot be stopped
is reported as a warning and has no staging descriptor; workers still share the
parent's filesystem privileges and are cooperative processes, not a sandbox.
An interrupt path preserves a late verified winner for recovery and retains the
signal-derived exit status.

On POSIX systems, SIGINT (Ctrl+C), SIGTERM and SIGHUP request coordinated
shutdown. On Windows, Ctrl+C and Ctrl+Break are routed to the same handlers,
but this is so far covered only by synthetic tests, not a recorded console run;
closing the console window cannot be intercepted through Python's `signal`
module. Signals
are handled at safe checkpoints so they cannot split private-key filesystem
transactions. If a signal arrives after a verified match is held on the normal
search path, the program finishes publication and verification and reports
success if storage succeeds.

Exit codes are:

- `0`: verified identity saved, including when result output fails;
- `1`: runtime, worker, cryptographic, or output-storage failure;
- `2`: CLI, validation, output-preflight, compatibility, or safety-guard failure;
- `128 + signal`: interrupted before the normal path holds a verified match
  (SIGINT 130, SIGTERM 143, SIGHUP 129, normally SIGBREAK 149).

Status, warnings and errors go to `stderr` and are best effort: a closed reader
or unencodable diagnostic does not stop the search. Results go to `stdout`; if
that stream fails after publication, the saved identity remains a success and a
warning is attempted on `stderr`. A stream that is already closed at launch
(`>&-`, `2>&-`) is discarded rather than mixed into the other one. Result paths
use encoding escapes where needed. Check the output path if either stream is
unavailable.

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
python -m pip_audit --progress-spinner off
python -m pip freeze
```

The suite includes independent public and RFC private compatibility vectors,
reference-formula checks, official `rnid` interoperability, exact pattern and
overlap validation, real multiprocess searches, worker isolation and cancellation,
malformed messages, output races and fallbacks, injected storage failures,
match preservation, recovery, and private-output assertions that do not print
keys on failure. It covers broken real pipes, closed streams, Unicode paths,
interrupted waits and signal-handler restoration. POSIX SIGINT, SIGTERM and
SIGHUP tests wait for active workers in isolated process groups before signalling.
Synthetic Windows signal tests validate control flow; a real console run is
still required to establish OS console behavior.

GitHub Actions runs these quality checks and the functional suite against the
latest stable resolved dependencies on Python 3.14 under Linux, macOS and
Windows, on pushes, pull requests and weekly. It records resolved dependencies
and keeps official actions pinned to immutable commit hashes. Weekly checks can
detect regressions after a release is available; they are not an installation
gate. [GitHub may disable scheduled workflows after 60 days of inactivity in
public repositories](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).
Require the complete workflow to pass for the exact release commit before
publishing; local macOS checks do not establish remote CI results.

Audit both the runtime requirements (which resolve their ranges independently)
and the actual installed release environment. Retain a dated dependency lock or
artifact manifest and backend details for reproducibility. A clean advisory scan
covers known reports for the resolved versions at that time; it neither
inventories every system OpenSSL build nor proves the absence of vulnerabilities.
