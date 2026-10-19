"""Decrypt a KakaoTalk SQLCipher4 .edb to a standard SQLite file, given its 32-byte raw key.

KakaoTalk .edb layout (SQLCipher 4 defaults): AES-256-CBC, page 4096, reserve 80 (IV 16 +
HMAC 64). Page 1's first 16 bytes are the plaintext kdf_salt; every page stores
[ciphertext][IV 16][HMAC 64]. With the raw key, each page body decrypts with AES-256-CBC
using that page's stored IV. The 80 reserved bytes per page are left intact — SQLite simply
ignores reserved bytes (the decrypted header keeps reserved=80), so the result opens as a
normal database. Recover keys with kakao_keyspec_scan.py.

Note: if a `<edb>-wal` file exists and is large, recent data may live there (WAL, not yet
checkpointed). This tool decrypts only the main .edb. To force a checkpoint, open the DB in
KakaoTalk and let it settle, or decrypt the -wal separately (same per-page scheme).

Requires: pycryptodome. Usage:
  py -I kakao_edb_decrypt.py <in.edb> <64-hex-key | x'..'> <out.sqlite>
"""
import sys, sqlite3
from Crypto.Cipher import AES

PAGE = 4096; RESERVE = 80; IVSZ = 16


def load_key(s):
    s = s.strip()
    if s.lower().startswith("x'") and s.endswith("'"):
        s = s[2:-1]
    b = bytes.fromhex(s.replace(" ", ""))
    if len(b) != 32:
        raise SystemExit(f"key must be 32 bytes (64 hex); got {len(b)}")
    return b


def decrypt(edb, key, out):
    data = open(edb, "rb").read()
    npages = len(data) // PAGE
    if npages == 0:
        raise SystemExit("input smaller than one page")
    res = bytearray()
    for i in range(npages):
        pg = data[i * PAGE:(i + 1) * PAGE]
        off = 16 if i == 0 else 0          # page 1 reserves first 16 bytes for the salt
        iv = pg[PAGE - RESERVE:PAGE - RESERVE + IVSZ]
        pt = AES.new(key, AES.MODE_CBC, iv).decrypt(pg[off:PAGE - RESERVE])
        head = b"SQLite format 3\x00" if i == 0 else b""
        res += head + pt + pg[PAGE - RESERVE:]   # restore magic (pg1) + keep reserved tail
    open(out, "wb").write(res)
    return npages


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    n = decrypt(sys.argv[1], load_key(sys.argv[2]), sys.argv[3])
    print(f"[*] wrote {sys.argv[3]} ({n} pages)")
    con = sqlite3.connect(sys.argv[3]); cur = con.cursor()
    cur.execute("PRAGMA integrity_check"); print("[*] integrity_check:", cur.fetchone()[0])
    cur.execute("SELECT type, name FROM sqlite_master ORDER BY type, name")
    rows = cur.fetchall()
    print(f"[*] sqlite_master: {len(rows)} object(s)")
    for t, nm in rows:
        print(f"      {t:7} {nm}")
    con.close()
