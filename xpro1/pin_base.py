#!/usr/bin/env python3
"""
Pin an exact (not necessarily page-aligned) ARM base for a segment via the
mode of (pointer_value - prologue_offset): if a pointer targets a function
start, then base == pointer - that prologue's offset. The true base is the
most frequent such difference.

Usage: python3 -I pin_base.py <seg.bin> <base_lo_hex> <base_hi_hex> [sample]
"""
import sys, struct
from bisect import bisect_left, bisect_right
from collections import Counter

def u32s(buf): return struct.unpack_from("<%dI" % (len(buf)//4), buf, 0)

def prologue_offsets(buf):
    return [i for i in range(0, len(buf)-3, 4)
            if buf[i+3] == 0xE9 and buf[i+2] == 0x2D and (buf[i+1] & 0x40)]

def main():
    path = sys.argv[1]
    blo = int(sys.argv[2], 16); bhi = int(sys.argv[3], 16)
    sample = int(sys.argv[4]) if len(sys.argv) > 4 else 20000
    buf = open(path, "rb").read(); n = len(buf)
    words = u32s(buf)
    ptrs = [w for w in words if blo <= w < bhi + n]
    pro = prologue_offsets(buf)
    print(f"{path.split('/')[-1]}: {n} bytes, {len(ptrs)} candidate ptrs in window, {len(pro)} prologues")
    step = max(1, len(ptrs)//sample)
    votes = Counter()
    for w in ptrs[::step]:
        lo = bisect_left(pro, max(0, w - bhi))
        hi = bisect_right(pro, min(n-1, w - blo))
        for o in pro[lo:hi]:
            votes[w - o] += 1
    print("top base candidates by (ptr - prologue) mode:")
    for b, c in votes.most_common(8):
        print("  base=%#010x  votes=%d" % (b, c))
    # full prologue-hit score at the winner
    if votes:
        B = votes.most_common(1)[0][0]
        proset = set(pro)
        hits = sum(1 for w in ptrs if 0 <= w - B < n and (w - B) in proset)
        print("winner base=%#010x -> %d/%d pointers hit a prologue (%.1f%%)"
              % (B, hits, len(pro), 100.0*hits/len(pro)))

if __name__ == "__main__":
    main()
