# Vanity LXMF address generator.

A simple CLI tool to generate [LXMF](https://github.com/markqvist/LXMF) vanity addresses in Reticulum network.

* Searches for an identity whose lxmf.delivery destination hash starts with a given hex prefix.
* Saves the private key to a file compatible with RNS apps ([Sideband](https://github.com/markqvist/Sideband), [MeshChat](https://github.com/liamcottle/reticulum-meshchat), [NomadNet](https://github.com/markqvist/nomadnet)).
* Prints base64/base32 encodings for import where supported.

## Usage:
`python main.py [--postfix=<POSTFIX>] [--prefix=<PREFIX>] [--workers=<NUMBER_OF_THREADS>] [--out=<DESTINATION>]`

## Notes:
* If you want to use a more optimized version, you can use the [Go language LXMF vanity address generator](https://github.com/CyberKiska/lxmf-vanity-address-generator) implementation. The performance difference with the Python implementation is approximately 30-35 times. Note: The Python version uses the official reference library, while the Go version uses raw cryptographic primitives.
* It is necessary to have an installed [Reticulum](https://github.com/markqvist/Reticulum).
* Either `--prefix` or `--postfix` must be set; both accept from 1 to 32 hex chars.
* Prefix is matched on lowercase hex of the 16-byte destination hash. So use [Hexspeak](https://en.wikipedia.org/wiki/Hexspeak) to select the prefix/postfix.
* Workers run in parallel and stop when the first match is found.
* Expected number of generations: 16^n, where n is the prefix length. Example: For 4 hex symbols expect ~16^4 attempts on average (≈65k).
* It is better to run script on a virtual machine that is not connected to the internet.
