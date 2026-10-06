# Security policy

## Supported scope

Security fixes are prepared for the current default branch. The supported
configuration is the latest stable RNS release actually tested successfully by
CI, with PyCA cryptography on CPython 3.14 under Linux, macOS and Windows.
CI runs on pushes, pull requests and weekly; a newly released dependency is
not verified until those jobs pass. RNS 1.5.2 is the chosen installation minimum,
and cryptography 50.0.0 is the installation floor from the dated advisory review.
Audit the actual resolved versions before deployment.

Startup known answers check specific protocol properties, not security or full
compatibility. Older and prerelease dependencies are not blocked at runtime,
but passing those checks alone does not establish support. Historical
compatibility experiments include RNS 1.4.2; that is not a supported-version
promise. Modified builds and manually selected RNS internal crypto providers
are outside the supported configuration. The internal provider has received
less scrutiny than OpenSSL; matching test vectors does not give it equivalent
security assurance.

## Reporting a vulnerability

Use this repository's private GitHub vulnerability-reporting feature when it is
available. If it is not available, contact the repository owner through a
private channel without first publishing technical details. A minimal public
issue may request a private contact method, but must not include an exploit,
private identity, recovery file, or private import string.

Include the operating system, Python/RNS/cryptography versions, filesystem
type, exact CLI options with secrets removed, expected behavior, observed
behavior, and the smallest safe reproducer. Never attach a generated identity
or `.lxmf-identity-*.staging` file.

If a private identity may have been exposed, stop using it and replace it. File
deletion alone does not revoke copies in logs, backups, snapshots, swap, or
another party's possession.
