import argparse, base64, binascii, multiprocessing as mp, os, sys, time
import RNS

# - Utilities -
def lxmf_hash_hex_for_identity(identity: RNS.Identity) -> str:
    # Compute 16-byte truncated destination hash for ("lxmf","delivery")
    # Using the public API (Destination.hash)
    h = RNS.Destination.hash(identity, "lxmf", "delivery")
    return h.hex()

def gen_identity():
    # RNS.Identity() pulls randomness from OS CSPRNG
    return RNS.Identity(create_keys=True)

def encode_base64(prv_bytes: bytes) -> str:
    return base64.b64encode(prv_bytes).decode("ascii")

def encode_base32(prv_bytes: bytes) -> str:
    # Sideband examples use base32 (RFC 4648, no padding trimming)
    return base64.b32encode(prv_bytes).decode("ascii")

def secure_write_identity(path: str, identity: RNS.Identity):
    # Write private key to file (this is what RNS apps expect)
    ok = identity.to_file(path)
    if not ok:
        raise RuntimeError("Failed to save identity to file")
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

# - Worker -
def worker(prefix_hex: str, postfix_hex: str, stop_evt: mp.Event, out_q: mp.Queue):
    # Local tight loop; when found we push result and stop
    prefix = (prefix_hex or "").lower()
    postfix = (postfix_hex or "").lower()
    tries = 0
    while not stop_evt.is_set():
        ident = gen_identity()
        addr = lxmf_hash_hex_for_identity(ident)
        tries += 1
        if (not prefix or addr.startswith(prefix)) and (not postfix or addr.endswith(postfix)):
            out_q.put((ident.get_private_key(), addr, tries))
            stop_evt.set()
            return

# - Main -
def main():
    ap = argparse.ArgumentParser(description="Reticulum LXMF vanity address generator")
    ap.add_argument("--prefix", default="",
                    help="Desired hex prefix for lxmf.delivery (e.g. 'c0ffee'). Case-insensitive.")
    ap.add_argument("--postfix", default="",
                    help="Desired hex postfix (suffix) for lxmf.delivery (e.g. 'dead'). Case-insensitive.")
    ap.add_argument("--out", default="./identity",
                    help="Path to save found identity file (default: ./identity)")
    ap.add_argument("--workers", type=int, default=max(1, os.cpu_count() or 1),
                    help="Parallel workers (default: CPU count)")
    args = ap.parse_args()

    # Validate prefix/postfix
    p = (args.prefix or "").lower()
    s = (args.postfix or "").lower()

    if not p and not s:
        print("ERROR: at least one of --prefix or --postfix must be provided.", file=sys.stderr)
        sys.exit(2)

    if p and not all(c in "0123456789abcdef" for c in p):
        print("ERROR: prefix must be hex characters only [0-9a-f].", file=sys.stderr)
        sys.exit(2)
    if s and not all(c in "0123456789abcdef" for c in s):
        print("ERROR: postfix must be hex characters only [0-9a-f].", file=sys.stderr)
        sys.exit(2)

    if p and (len(p) < 1 or len(p) > 32):
        print("ERROR: prefix length must be 1..32 hex characters (max 16 bytes).", file=sys.stderr)
        sys.exit(2)
    if s and (len(s) < 1 or len(s) > 32):
        print("ERROR: postfix length must be 1..32 hex characters (max 16 bytes).", file=sys.stderr)
        sys.exit(2)

    # Start pool
    stop_evt = mp.Event()
    out_q = mp.Queue()
    workers = max(1, int(args.workers))
    procs = [ mp.Process(target=worker, args=(p, s, stop_evt, out_q), daemon=True) for _ in range(workers) ]

    t0 = time.time()
    for pr in procs: pr.start()

    # Wait for a result
    prv, addr_hex, tries = out_q.get()  # blocks until found
    stop_evt.set()
    for pr in procs: 
        try: pr.terminate()
        except Exception: pass

    # Build Identity object from bytes to write and to print encodings
    ident = RNS.Identity.from_bytes(prv)
    if ident is None:
        print("ERROR: Could not reconstruct identity from bytes.", file=sys.stderr)
        sys.exit(1)

    # Save to file
    secure_write_identity(args.out, ident)

    # Encodings for import in various apps
    b64 = encode_base64(prv)
    b32 = encode_base32(prv)

    elapsed = time.time() - t0

    print("\n=== Vanity LXMF Identity Found ===")
    if p:
        print(f"Prefix      : {p}")
    if s:
        print(f"Postfix     : {s}")
    print(f"LXMF addr   : {addr_hex}")
    print(f"Tries       : {tries}")
    print(f"Elapsed [s] : {elapsed:.2f}")
    print(f"Saved file  : {os.path.abspath(args.out)} (chmod 600)")
    print("\n--- Import formats ---")
    print(f"Base64 (MeshChat import string):\n{b64}")
    print(f"Base32 (Sideband import string):\n{b32}\n")

    # Cross-check: ensure file reload works
    re = RNS.Identity.from_file(args.out)
    assert re is not None, "Sanity: saved identity can't be reloaded"
    check = lxmf_hash_hex_for_identity(re)
    assert check == addr_hex, "Sanity: reloaded identity yields different LXMF hash"

if __name__ == "__main__":
    main()
