# Vanity LXMF address generator.

A simple CLI tool to generate [LXMF](https://github.com/markqvist/LXMF) vanity addresses in Reticulum network.

* Searches for an identity whose `lxmf.delivery` destination hash matches a given lowercase-hex prefix and/or postfix.
* Saves the private key to a file compatible with `RNS.Identity.from_file()` and RNS apps ([Sideband](https://github.com/markqvist/Sideband), [MeshChat](https://github.com/liamcottle/reticulum-meshchat), [NomadNet](https://github.com/markqvist/nomadnet)) that consume RNS identity files.
* Uses multiple worker processes for CPU-bound brute-force search.

## Usage:
`python main.py [--postfix=<POSTFIX>] [--prefix=<PREFIX>] [--workers=<NUMBER_OF_WORKERS>] [--out=<DESTINATION>]`

## Notes:
* If you want to use a more optimized version, you can use the [Go language LXMF vanity address generator](https://github.com/CyberKiska/lxmf-vanity-address-generator) implementation. The performance difference with the Python implementation is approximately 30-35 times. Note: The Python version uses the official reference library, while the Go version uses raw cryptographic primitives.
* It is necessary to have an installed [Reticulum](https://github.com/markqvist/Reticulum).
* Either `--prefix` or `--postfix` must be set.
* `--prefix` and `--postfix` are matched against the final 32-character lowercase hex destination hash, and both must match when both are set. So use [Hexspeak](https://en.wikipedia.org/wiki/Hexspeak) to select the prefix/postfix.
* Overlapping prefix/postfix constraints are validated for consistency before the search starts.
* Existing output files are not overwritten.
* Progress and search speed are reported on `stderr`, and the found address plus file path are printed on success.
* Base64 and Base32 import strings are printed on success for clients that cannot import from a file.
* Expected number of generations is approximately `16^k`, where `k` is the number of uniquely constrained hex positions after overlap is accounted for. Example: For 4 hex symbols expect ~16^4 attempts on average (≈65k).
* It is better to run script on a virtual machine that is not connected to the internet.
