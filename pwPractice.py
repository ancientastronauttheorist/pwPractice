#!/usr/bin/env python3
"""
Password Practice Utility
- Creates a small file containing only an encrypted "success!" token.
- During practice, derives a key from your typed password and attempts to decrypt.
- If decryption returns "success!", the password is correct.
- Never writes your password to disk.

Requires: pip install cryptography
"""

import argparse
import base64
import getpass
import json
import os
import sys
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

MAGIC = "pwpractice-v1"
PLAINTEXT = b"success!"
DEFAULT_SALT_BYTES = 16
NONCE_BYTES = 12  # AESGCM/ChaCha20-Poly1305 nonce size
# Scrypt params: reasonably strong defaults for interactive use
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32  # 256-bit key for AESGCM

@dataclass
class Token:
    magic: str
    salt_b64: str
    nonce_b64: str
    kdf: str
    params: dict
    ciphertext_b64: str

def _derive_key(password_bytes: bytes, salt: bytes, n: int, r: int, p: int, key_len: int = KEY_LEN) -> bytes:
    kdf = Scrypt(salt=salt, length=key_len, n=n, r=r, p=p)
    return kdf.derive(password_bytes)

def _aesgcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
    aes = AESGCM(key)
    return aes.encrypt(nonce, plaintext, aad)

def _aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, aad)

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def _wipe_bytearray(buf: bytearray):
    for i in range(len(buf)):
        buf[i] = 0

def _best_effort_mlock():
    """
    Best effort to lock this process's memory to avoid swapping (Linux/macOS).
    No-op on Windows or if not permitted.
    """
    try:
        import ctypes, ctypes.util, platform
        if platform.system() in ("Linux", "Darwin"):
            libc_path = ctypes.util.find_library("c")
            if not libc_path:
                return
            libc = ctypes.CDLL(libc_path, use_errno=True)
            # MCL_CURRENT=1, MCL_FUTURE=2 on Linux/macOS
            MCL_CURRENT = 1
            MCL_FUTURE = 2
            if hasattr(libc, "mlockall"):
                res = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
                if res != 0:
                    # Not fatal; likely permission issue
                    pass
    except Exception:
        pass

def init_token(path: str, mlock: bool = False):
    if mlock:
        _best_effort_mlock()

    pw1 = getpass.getpass("Create practice password: ")
    pw2 = getpass.getpass("Repeat password: ")
    if pw1 != pw2:
        print("Passwords do not match.")
        sys.exit(1)

    # Convert to bytearray so we can best-effort wipe afterwards
    pw_bytes = bytearray(pw1.encode("utf-8"))
    # Clean the str copies ASAP
    pw1 = None
    pw2 = None

    try:
        salt = secrets.token_bytes(DEFAULT_SALT_BYTES)
        nonce = secrets.token_bytes(NONCE_BYTES)
        key = _derive_key(bytes(pw_bytes), salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
        ct = _aesgcm_encrypt(key, nonce, PLAINTEXT, aad=MAGIC.encode("utf-8"))

        token = Token(
            magic=MAGIC,
            salt_b64=_b64e(salt),
            nonce_b64=_b64e(nonce),
            kdf="scrypt",
            params={"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "key_len": KEY_LEN},
            ciphertext_b64=_b64e(ct),
        )

        # Write as text (JSON) so it looks like a "txt file"
        data = json.dumps(token.__dict__, indent=2)
        # Ensure atomic-ish write
        tmp_path = path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)

        print(f"Created token at {path}. Keep this file safe.")
    finally:
        # Best-effort wipe of sensitive bytes
        _wipe_bytearray(pw_bytes)

def practice(path: str, mlock: bool = False):
    if mlock:
        _best_effort_mlock()

    # Load token
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    # Basic validation
    if raw.get("magic") != MAGIC:
        print("Invalid token file (magic mismatch).")
        sys.exit(1)
    if raw.get("kdf") != "scrypt":
        print("Unsupported KDF.")
        sys.exit(1)

    salt = _b64d(raw["salt_b64"])
    nonce = _b64d(raw["nonce_b64"])
    params = raw["params"]
    ct = _b64d(raw["ciphertext_b64"])

    print("Password practice. Type your password (or 'q' to quit).")
    while True:
        pw = getpass.getpass("> ")
        if pw == "q":
            print("Bye.")
            return

        pw_bytes = bytearray(pw.encode("utf-8"))
        pw = None
        try:
            key = _derive_key(bytes(pw_bytes), salt, params["n"], params["r"], params["p"], params.get("key_len", KEY_LEN))
            try:
                pt = _aesgcm_decrypt(key, nonce, ct, aad=MAGIC.encode("utf-8"))
                if pt == PLAINTEXT:
                    print("✅ Correct!")
                else:
                    # Shouldn't happen with authenticated decryption, but just in case
                    print("❌ Incorrect.")
            except Exception:
                print("❌ Incorrect.")
        finally:
            _wipe_bytearray(pw_bytes)

def main():
    parser = argparse.ArgumentParser(description="Practice a password without ever writing it to disk.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Create an encrypted success-token file.")
    p_init.add_argument("path", help="Path to token file (e.g., token.txt).")
    p_init.add_argument("--mlock", action="store_true", help="Best effort: lock memory to reduce swapping.")

    p_prac = sub.add_parser("practice", help="Practice decrypting with your password.")
    p_prac.add_argument("path", help="Path to existing token file.")
    p_prac.add_argument("--mlock", action="store_true", help="Best effort: lock memory to reduce swapping.")

    args = parser.parse_args()

    if args.cmd == "init":
        init_token(args.path, mlock=args.mlock)
    elif args.cmd == "practice":
        practice(args.path, mlock=args.mlock)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
