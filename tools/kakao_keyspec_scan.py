"""Recover KakaoTalk per-DB SQLCipher keys from a *running* KakaoTalk process — no debugger.

KakaoTalk PC (>= 25.7 / 26.x) protects its executable with Themida. The per-DB key
derivation (sub_141CCB9A0) is Themida-VM virtualized, and the process self-stalls under a
debugger (usermode ScyllaHide is bypassed by direct syscalls), so neither static nor live
debugging recovers the keys cleanly.

However, SQLCipher keeps a human-readable *keyspec* for every OPEN database in its codec
context: the ASCII string  x'<64 hex key><32 hex salt>'  (32-byte raw key + 16-byte file
salt). That string lives in ordinary committed heap for the lifetime of the open DB and can
be read from another process with ReadProcessMemory + VirtualQueryEx — no debugger attach,
so Themida's anti-debug is never triggered.

This tool scans the target process memory for those keyspecs, matches each 16-byte salt to
the first 16 bytes of an .edb on disk (the SQLCipher4 kdf_salt), and verifies the key by
AES-256-CBC-decrypting page 1 and checking the SQLite header. Only DBs that are open at scan
time are recoverable (open more chats / let the app settle to capture more).

Requires: pycryptodome (`pip install pycryptodome`). Windows only (ReadProcessMemory).

Usage:
  py -I kakao_keyspec_scan.py <pid> <users_dir> [--save keys.txt]
      <pid>        PID of the running KakaoTalk.exe
      <users_dir>  ...(AppData/Local/Kakao/KakaoTalk/users/<hash>)
Exit code 0 if at least one key verified, else 1.
"""
import sys, re, os, hashlib, hmac, ctypes as C
from ctypes import wintypes as W

PAGE = 4096; RESERVE = 80; IVSZ = 16; HMACSZ = 64
MEM_COMMIT = 0x1000; PAGE_GUARD = 0x100
READABLE = (0x02, 0x04, 0x20, 0x40)  # READONLY/READWRITE/EXECUTE_READ/EXECUTE_READWRITE


class MBI(C.Structure):
    _fields_ = [("BaseAddress", C.c_void_p), ("AllocationBase", C.c_void_p),
                ("AllocationProtect", W.DWORD), ("__a", W.DWORD),
                ("RegionSize", C.c_size_t), ("State", W.DWORD),
                ("Protect", W.DWORD), ("Type", W.DWORD)]


def _k32():
    k = C.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.restype = W.HANDLE
    k.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    k.ReadProcessMemory.restype = W.BOOL
    k.ReadProcessMemory.argtypes = [W.HANDLE, W.LPCVOID, W.LPVOID, C.c_size_t, C.POINTER(C.c_size_t)]
    k.VirtualQueryEx.restype = C.c_size_t
    k.VirtualQueryEx.argtypes = [W.HANDLE, W.LPCVOID, C.POINTER(MBI), C.c_size_t]
    return k


def scan_keyspecs(pid):
    """Return dict salt_hex(16B) -> key_hex(32B) found in the process' readable memory."""
    k32 = _k32()
    h = k32.OpenProcess(0x0010 | 0x0400, False, pid)  # VM_READ | QUERY_INFORMATION
    if not h:
        raise SystemExit(f"OpenProcess({pid}) failed, err={C.get_last_error()} "
                         f"(run as same user / elevated)")

    def rd(a, n):
        buf = (C.c_char * n)(); got = C.c_size_t(0)
        if not k32.ReadProcessMemory(h, C.c_void_p(a), buf, n, C.byref(got)):
            return None
        return bytes(buf[:got.value])

    pat = re.compile(rb"x'([0-9a-fA-F]{64})([0-9a-fA-F]{32})'")
    out = {}
    addr = 0; mbi = MBI()
    while addr < 0x7FFFFFFFFFFF:
        if k32.VirtualQueryEx(h, C.c_void_p(addr), C.byref(mbi), C.sizeof(mbi)) == 0:
            break
        base = mbi.BaseAddress or 0; size = mbi.RegionSize
        if mbi.State == MEM_COMMIT and (mbi.Protect & 0xFF) in READABLE and not (mbi.Protect & PAGE_GUARD):
            off = 0; CH = 0x100000; tail = b""
            while off < size:
                n = min(CH, size - off)
                data = rd(base + off, n)
                if data:
                    for m in pat.finditer(tail + data):
                        out.setdefault(m.group(2).decode().lower(), m.group(1).decode().lower())
                    tail = data[-160:]  # carry a tail so matches spanning chunk edges survive
                else:
                    tail = b""
                off += n
        addr = base + size
    return out


def verify_page1(path, key):
    """True if `key` AES-256-CBC-decrypts page 1 to a valid SQLCipher4 SQLite header."""
    from Crypto.Cipher import AES
    with open(path, "rb") as f:
        data = f.read(PAGE)
    if len(data) < PAGE:
        return False
    iv = data[PAGE - RESERVE:PAGE - RESERVE + IVSZ]
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(data[16:PAGE - RESERVE])
    return pt[0:2] == b"\x10\x00" and pt[4] == RESERVE and pt[5:8] == b"\x40\x20\x20"


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    pid = int(sys.argv[1]); users_dir = sys.argv[2]
    save = None
    if "--save" in sys.argv:
        save = sys.argv[sys.argv.index("--save") + 1]

    by_salt = scan_keyspecs(pid)
    print(f"[*] {len(by_salt)} SQLCipher keyspec(s) recovered from PID {pid}")

    rows = []  # (relpath, key, ok)
    for root, _, files in os.walk(users_dir):
        for fn in files:
            if not fn.lower().endswith(".edb"):
                continue
            p = os.path.join(root, fn)
            try:
                with open(p, "rb") as f:
                    fsalt = f.read(16).hex()
            except OSError:
                continue
            key = by_salt.get(fsalt)
            rel = os.path.relpath(p, users_dir)
            if not key:
                rows.append((rel, None, None)); continue
            ok = verify_page1(p, bytes.fromhex(key))
            rows.append((rel, key, ok))

    matched = [r for r in rows if r[1]]
    verified = [r for r in matched if r[2]]
    for rel, key, ok in sorted(rows):
        if key is None:
            print(f"  [ -- ] {rel}  (not open in process; key not resident)")
        else:
            print(f"  [{'PASS' if ok else 'FAIL'}] {rel}\n         key={key}")
    print(f"\n[*] {len(matched)}/{len(rows)} .edb matched to a resident key; "
          f"{len(verified)} verified by page-1 decryption")

    if save and verified:
        with open(save, "w", encoding="utf-8") as f:
            for rel, key, ok in sorted(verified):
                f.write(f"{key}  {rel}\n")
        print(f"[*] wrote {len(verified)} verified key(s) to {save}")
    sys.exit(0 if verified else 1)


if __name__ == "__main__":
    main()
