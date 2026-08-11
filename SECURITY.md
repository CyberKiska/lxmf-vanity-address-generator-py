# Security policy

## Supported scope

Security fixes are prepared for the current default branch and runtime versions
allowed by `requirements.txt`. The release suite currently verifies RNS 1.4.2
with PyCA cryptography 50.0.0. Older commits, modified builds, and dependency
versions outside the declared ranges are outside the reviewed configuration.

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
