# Vanity LXMF address generator

A security-focused CLI for generating a Reticulum identity whose final
`lxmf.delivery` destination hash has a chosen hexadecimal prefix and/or
postfix.

The generator uses the official Reticulum APIs for both key generation and
destination hashing:

```python
identity = RNS.Identity(create_keys=True)
address = RNS.Destination.hash(identity, "lxmf", "delivery").hex()
```

The resulting address is a 128-bit destination hash represented as exactly 32
lowercase hexadecimal characters.

## Installation

Use Python 3.10 or newer, create a virtual environment, and install the
declared Reticulum version range:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

The declared compatibility range is RNS 1.0.1 through the 1.3 release line.
This refactor was verified locally with RNS 1.0.1 and checked against the RNS
1.3 API reference. Changes to Reticulum hashing or identity serialization
outside this range should be reviewed before use.

## Usage

```text
python main.py \
  [--prefix=<PREFIX>] \
  [--postfix=<POSTFIX>] \
  [--workers=<NUMBER_OF_PROCESSES>] \
  [--out=<DESTINATION>] \
  [--force] \
  [--show-private-import-strings]
```

Examples:

```sh
python main.py --prefix=cafe --out=./cafe.identity
python main.py --postfix=beef --workers=4 --out=./beef.identity
python main.py --prefix=ace --postfix=bad --out=./ace-bad.identity
```

Rules:

- At least one of `--prefix` or `--postfix` must be non-empty.
- Input is case-normalized and must contain only `0-9` and `a-f`.
- Prefix and postfix match the final lowercase 32-character destination hash.
- When both are supplied, both must match.
- Odd-length patterns are valid and constrain individual hex nibbles.
- Combined prefix and postfix length must not exceed 32 characters.
- Searches constraining more than eight hex characters require `--force`.
- Existing output paths are never overwritten.

## Output and private-key safety

`--out` receives the raw private-key bytes returned by
`RNS.Identity.get_private_key()`. The file can be loaded with
`RNS.Identity.from_file()` and will reproduce the same `lxmf.delivery`
address. The generator writes it with mode `0600`, publishes it without
overwriting an existing path, flushes it to storage, reloads it, and verifies
the address before reporting success.

The identity file is secret. Anyone who obtains it controls the identity.

Private-key encodings are **not** printed by default. The optional
`--show-private-import-strings` flag prints generic Base64 and Base32 encodings
for clients that support such imports. These strings are the private key, are
not encrypted, and may be captured by terminal scrollback, redirected output,
CI logs, or screen sharing. Client-specific formats and padding requirements
can vary by client version.

The identity file preserves the Reticulum identity and address. It does not
contain application configuration, display names, message history, or LXMF
ratchet state.

Write identities only into a directory you trust. The final filename is
protected against overwrite and symlink replacement, but no portable file API
can make an attacker-controlled parent-directory path trustworthy.

## Performance and difficulty

Generation is brute force. If `k` hexadecimal positions are constrained, the
expected average is `16^k` newly generated identities. Each extra character
makes the search 16 times harder.

The program uses worker processes rather than Python threads. Identity key
generation is CPU-bound, and processes avoid dependence on GIL behavior in the
installed cryptographic backend. Scaling depends on the CPU, process count,
thermal limits, and other system load; more processes do not guarantee linear
speedup.

Progress, rate, and a mean-time estimate at the observed rate are written to
`stderr`. Ctrl+C requests a coordinated shutdown and returns exit code 130.
SIGTERM also requests coordinated shutdown and returns 143. Normal success
returns 0, validation and argument errors return 2, and runtime failures
return 1.

## Testing

The tests use only the Python standard library plus RNS:

```sh
python -m unittest discover -s tests -v
```

They cover RNS hash-helper equivalence, input edge cases, prefix/postfix AND
behavior, parent-side winner validation, concurrent error/match handling,
secure no-overwrite output, privacy-by-default output, and a real
multi-process search.
