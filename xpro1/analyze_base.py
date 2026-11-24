#!/usr/bin/env python3
"""
Derive the ARM load/base address for a decompressed X-Pro 1 firmware segment.

Method (no disassembler needed): firmware is full of absolute 32-bit pointers
(literal pools, jump/data tables). The correct base B is the one that makes the
most of those pointers resolve inside the image AND land exactly on a real ARM
function prologue (STMFD sp!, {..,lr} = 0xE92Dxxxx, LE bytes `xx xx 2d e9`).

Usage: python3 -I analyze_base.py <seg0.bin> [<seg1.bin> ...]
"""
import sys, struct
from bisect import bisect_left

def u32s(buf):
    return struct.unpack_from("<%dI" % (len(buf)//4), buf, 0)

def prologue_set(buf):
    """Offsets (4-aligned) where an ARM STMFD {..,lr} prologue begins."""
    s = set()
    for i in range(0, len(buf)-3, 4):
        if buf[i+3] == 0xE9 and buf[i+2] == 0x2D and (buf[i+1] & 0x40):
            s.add(i)
    return s

def analyze(path):
    buf = open(path, "rb").read()
    n = len(buf)
    print(f"\n==================== {path.split('/')[-1]}  ({n} bytes) ====================")
    print("header words [0x00..0x40]:")
    for off in range(0, 0x40, 16):
        row = u32s(buf[off:off+16])
        print("  %#06x: %s" % (off, "  ".join("%#010x" % w for w in row)))

    words = u32s(buf)
    # pointer-like candidates (sane RAM range for this SoC generation)
    LO, HI = 0x00010000, 0x20000000
    ptrs = [w for w in words if LO <= w <= HI]
    print(f"\npointer-like words: {len(ptrs)} of {len(words)}")

    # candidate bases: round each pointer down to 16K page, tally window [B, B+n)
    srt = sorted(ptrs)
    cand = sorted({(w & ~0x3FFF) for w in ptrs})
    best = []
    for B in cand:
        lo = bisect_left(srt, B)
        hi = bisect_left(srt, B + n)
        best.append((hi - lo, B))
    best.sort(reverse=True)
    print("top base candidates by in-range pointer count:")
    for cnt, B in best[:6]:
        print("  base=%#010x  in-range-ptrs=%d" % (B, cnt))

    # refine the winner with the prologue-hit test
    proset = prologue_set(buf)
    print(f"\nARM prologues in image: {len(proset)}")
    print("prologue-hit test (pointers that land exactly on a function prologue):")
    for cnt, B in best[:6]:
        hits = 0
        for w in ptrs:
            o = w - B
            if 0 <= o < n and o in proset:
                hits += 1
        print("  base=%#010x  in-range=%d  prologue-hits=%d  (%.1f%% of prologues)"
              % (B, cnt, hits, 100.0*hits/max(1, len(proset))))
    return buf, best[0][1] if best else None

def cross(seg_paths):
    """Does segment A's pointers resolve into segment B's range? (shared map check)"""
    infos = []
    for p in seg_paths:
        buf = open(p, "rb").read()
        words = u32s(buf)
        ptrs = [w for w in words if 0x00010000 <= w <= 0x20000000]
        infos.append((p.split('/')[-1], buf, ptrs))
    print("\n==================== cross-segment pointer check ====================")
    # reuse each segment's own best base from analyze()? here just report ranges.
    return infos

if __name__ == "__main__":
    for p in sys.argv[1:]:
        analyze(p)
