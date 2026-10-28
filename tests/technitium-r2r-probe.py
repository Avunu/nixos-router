"""Print "R2R <name>" or "IL <name>" for each .NET assembly given.

A ReadyToRun image is a managed assembly that also carries precompiled native
code, announced by a non-empty ManagedNativeHeader directory in its COR20
header. Reading that, rather than comparing file sizes, is what tells a build
that really ran crossgen2 from one that quietly fell back to plain IL.
"""
import struct, sys

def is_r2r(path):
    d = open(path, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    assert d[pe:pe + 4] == b'PE\0\0', 'not a PE file'
    nsec, = struct.unpack_from('<H', d, pe + 6)
    osz, = struct.unpack_from('<H', d, pe + 20)
    opt = pe + 24
    magic, = struct.unpack_from('<H', d, opt)
    dirs = opt + (112 if magic == 0x20b else 96)
    clr_rva, _ = struct.unpack_from('<II', d, dirs + 14 * 8)
    sec = opt + osz
    for i in range(nsec):
        vs, va, rs, ro = struct.unpack_from('<IIII', d, sec + i * 40 + 8)
        if va <= clr_rva < va + max(vs, rs):
            c = clr_rva - va + ro
            break
    else:
        raise SystemExit('CLR header not mapped')
    # COR20 header: ManagedNativeHeader directory sits at offset 64
    mn_rva, _ = struct.unpack_from('<II', d, c + 64)
    return mn_rva != 0

for p in sys.argv[1:]:
    print(('R2R ' if is_r2r(p) else 'IL  '), p.split('/')[-1], sep='')
