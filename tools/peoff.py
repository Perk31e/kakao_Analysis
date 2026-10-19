"""File offset <-> VA conversion for a PE (no deps). Usage: peoff.py <pe> <off|va>... (prefix va: for VA input)"""
import struct, sys
def sections(path):
    d = open(path, 'rb').read(4096)
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    optsz = struct.unpack_from('<H', d, pe + 20)[0]
    base = struct.unpack_from('<Q', d, pe + 24 + 24)[0]
    secs = []
    for i in range(nsec):
        o = pe + 24 + optsz + i * 40
        name = d[o:o+8].rstrip(b'\0').decode(errors='replace')
        vsz, va, rsz, raw = struct.unpack_from('<IIII', d, o + 8)
        secs.append((name, va, vsz, raw, rsz))
    return base, secs
if __name__ == '__main__':
    base, secs = sections(sys.argv[1])
    if len(sys.argv) == 2:
        print(hex(base)); [print(s[0], hex(s[1]), hex(s[2]), hex(s[3]), hex(s[4])) for s in secs]
    for a in sys.argv[2:]:
        if a.startswith('va:'):
            v = int(a[3:], 16) - base
            for n, va, vsz, raw, rsz in secs:
                if va <= v < va + max(vsz, rsz): print(a, '->', hex(raw + v - va), n)
        else:
            o = int(a, 16)
            for n, va, vsz, raw, rsz in secs:
                if raw <= o < raw + rsz: print(a, '->', hex(base + va + o - raw), n)
