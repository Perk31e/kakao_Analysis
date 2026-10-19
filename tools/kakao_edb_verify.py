"""Verify a SQLCipher4 raw key against a KakaoTalk .edb and optionally dump schema.

KakaoTalk 26.8.2 opens each .edb with a per-DB 256-bit RAW key via `PRAGMA key = "x'<64hex>'"`
(SQLCipher 4 defaults: AES-256-CBC, HMAC-SHA512, page 4096, reserve 80).
With a raw key, SQLCipher uses the 32 bytes directly as the cipher key and derives the HMAC
key as PBKDF2-HMAC-SHA512(key, file_salt_each_byte_xor_0x3a, fast_kdf_iter=2, 64).

This verifier needs only stdlib + pycryptodome (no sqlcipher build):
  - page-1 AES decrypt -> check SQLite header (page_size, reserved, fixed 40 20 20)
  - page-1 HMAC-SHA512 cross-check

Usage:
  py -I kakao_edb_verify.py <path.edb> <64-hex-key | x'..' >
Exit code 0 = key verified, 1 = not valid.
"""
import sys, hashlib, hmac

PAGE = 4096; RESERVE = 80; IVSZ = 16; HMACSZ = 64

def load_key(s):
    s = s.strip()
    if s.lower().startswith("x'") and s.endswith("'"):
        s = s[2:-1]
    s = s.replace(" ", "")
    b = bytes.fromhex(s)
    if len(b) != 32:
        raise SystemExit(f"key must be 32 bytes (64 hex); got {len(b)}")
    return b

def verify(path, key):
    from Crypto.Cipher import AES
    data = open(path, "rb").read()
    if len(data) < PAGE:
        raise SystemExit("file smaller than one page")
    salt = data[:16]
    # --- page 1 AES header check ---
    off = 16  # page 1 reserves first 16 bytes for the salt (plaintext)
    ct = data[off:PAGE - RESERVE]
    iv = data[PAGE - RESERVE:PAGE - RESERVE + IVSZ]
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    header_ok = pt[0:2] == b"\x10\x00" and pt[4] == RESERVE and pt[5:8] == b"\x40\x20\x20"
    # --- page 1 HMAC-SHA512 check ---
    hsalt = bytes(b ^ 0x3a for b in salt)
    hkey = hashlib.pbkdf2_hmac("sha512", key, hsalt, 2, 64)
    stored = data[PAGE - HMACSZ:PAGE]
    hmac_variant = None
    for inc_salt in (False, True):
        start = 0 if inc_salt else 16
        msg = data[start:PAGE - RESERVE + IVSZ] + b"\x01\x00\x00\x00"
        if hmac.new(hkey, msg, hashlib.sha512).digest() == stored:
            hmac_variant = inc_salt; break
    print(f"file      : {path}")
    print(f"salt      : {salt.hex()}")
    print(f"header_ok : {header_ok}  (decrypted page-1 SQLite header)")
    print(f"hmac_ok   : {hmac_variant is not None}" +
          (f" (page-1 incl_salt={hmac_variant})" if hmac_variant is not None else ""))
    return header_ok and hmac_variant is not None

if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    ok = verify(sys.argv[1], load_key(sys.argv[2]))
    print("RESULT    :", "VERIFIED" if ok else "NOT VALID")
    sys.exit(0 if ok else 1)
