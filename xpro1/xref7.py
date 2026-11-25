#!/usr/bin/env python3
"""
ARMv7-aware cross-reference index for the X-Pro 1 RAM dump (FW 3.82).

The firmware builds addresses with MOVW/MOVT pairs (ARMv7), not literal pools,
so v5-era LDR-literal scans and a v5t Ghidra import miss almost every string
reference. This decodes, over the whole flat image:
  - ARM  MOVW/MOVT pairs (same Rd, within 24 insns)          -> constant refs
  - Thumb-2 MOVW/MOVT pairs (T3 encodings, halfword aligned) -> constant refs
  - ARM  LDR Rd,[pc,#imm] literal words                      -> constant refs
  - ARM  BL/BLX, Thumb-2 BL/BLX                              -> call edges

Usage:
  python3 -I xref7.py build <dump.bin>        (writes xref7.pkl next to this file)
  python3 -I xref7.py refs <hexaddr>...       (who builds this constant)
  python3 -I xref7.py str <text>...           (find string, then its refs)
  python3 -I xref7.py callers <hexaddr>...    (BL/BLX call sites to address)
"""
import sys, struct, pickle, os, array
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
PKL = os.path.join(HERE, "xref7.pkl")
DUMP = os.environ.get("XPRO1_DUMP", os.path.expanduser("~/Downloads/xpro1_ram_0-32M.bin"))


def build(path):
    d = open(path, "rb").read()
    N = len(d)
    w = array.array("I", d[: N - N % 4])
    h = array.array("H", d[: N - N % 2])
    refs = defaultdict(list)   # const -> [(site, kind)]
    calls = defaultdict(list)  # target -> [(site, kind)]

    # ---- ARM mode (word aligned)
    last_movw = {}  # Rd -> (idx, lo)
    for i in range(len(w)):
        x = w[i]
        cond = x >> 28
        if cond == 0xF:
            # BLX imm (ARM -> Thumb)
            if (x & 0x0E000000) == 0x0A000000:
                imm = x & 0xFFFFFF
                if imm & 0x800000: imm -= 0x1000000
                H = (x >> 24) & 1
                t = (i * 4 + 8 + imm * 4 + H * 2) & 0xFFFFFFFF
                if t < N: calls[t].append((i * 4, "blxA"))
            continue
        op = x & 0x0FF00000
        if op == 0x03000000:
            rd = (x >> 12) & 0xF
            last_movw[rd] = (i, ((x >> 4) & 0xF000) | (x & 0xFFF))
        elif op == 0x03400000:
            rd = (x >> 12) & 0xF
            m = last_movw.get(rd)
            if m and i - m[0] <= 24:
                v = ((((x >> 4) & 0xF000) | (x & 0xFFF)) << 16) | m[1]
                refs[v].append((m[0] * 4, "movwA"))
        elif (x & 0x0F000000) == 0x0B000000:
            imm = x & 0xFFFFFF
            if imm & 0x800000: imm -= 0x1000000
            t = (i * 4 + 8 + imm * 4) & 0xFFFFFFFF
            if t < N: calls[t].append((i * 4, "blA"))
        elif (x & 0x0F7F0000) == 0x051F0000:
            imm = x & 0xFFF
            lit = (i * 4 + 8) + (imm if (x >> 23) & 1 else -imm)
            if 0 <= lit <= N - 4 and lit % 4 == 0:
                refs[w[lit // 4]].append((i * 4, "ldrA"))

    # ---- Thumb-2 (halfword aligned)
    last_movw = {}
    for j in range(len(h) - 1):
        a, b = h[j], h[j + 1]
        if (a & 0xF800) != 0xF000:
            continue
        if (a & 0xFBF0) == 0xF240 and not (b & 0x8000):
            rd = (b >> 8) & 0xF
            imm = ((a & 0xF) << 12) | (((a >> 10) & 1) << 11) | (((b >> 12) & 7) << 8) | (b & 0xFF)
            last_movw[rd] = (j, imm)
        elif (a & 0xFBF0) == 0xF2C0 and not (b & 0x8000):
            rd = (b >> 8) & 0xF
            imm = ((a & 0xF) << 12) | (((a >> 10) & 1) << 11) | (((b >> 12) & 7) << 8) | (b & 0xFF)
            m = last_movw.get(rd)
            if m and j - m[0] <= 32:
                refs[(imm << 16) | m[1]].append((m[0] * 2, "movwT"))
        elif (b & 0xC000) == 0xC000:
            # BL (b bit12=1) / BLX (bit12=0)
            S = (a >> 10) & 1
            imm10 = a & 0x3FF
            J1 = (b >> 13) & 1; J2 = (b >> 11) & 1
            imm11 = b & 0x7FF
            I1 = 1 - (J1 ^ S); I2 = 1 - (J2 ^ S)
            off = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
            if S: off -= 1 << 25
            pc = j * 2 + 4
            if b & 0x1000:
                t = pc + off; kind = "blT"
            else:
                t = (pc & ~3) + off; kind = "blxT"
            t &= 0xFFFFFFFF
            if t < N: calls[t].append((j * 2, kind))

    pickle.dump((dict(refs), dict(calls)), open(PKL, "wb"), protocol=4)
    print("consts:", len(refs), "call targets:", len(calls))


def load():
    return pickle.load(open(PKL, "rb"))


def cstr(d, a):
    s = a
    while s > 0 and 32 <= d[s - 1] < 127: s -= 1
    e = d.find(b"\0", a)
    return s, d[s:e]


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "build":
        build(sys.argv[2] if len(sys.argv) > 2 else DUMP); sys.exit()
    refs, calls = load()
    d = open(DUMP, "rb").read()
    if cmd == "refs":
        for x in sys.argv[2:]:
            a = int(x, 16)
            print(hex(a), [(hex(s), k) for s, k in refs.get(a, []) + refs.get(a | 1, [])][:40])
    elif cmd == "callers":
        for x in sys.argv[2:]:
            a = int(x, 16)
            r = calls.get(a, [])
            print(hex(a), len(r), [(hex(s), k) for s, k in r][:40])
    elif cmd == "str":
        for t in sys.argv[2:]:
            p = 0
            while True:
                i = d.find(t.encode(), p)
                if i < 0: break
                p = i + 1
                s, txt = cstr(d, i)
                hits = refs.get(s, []) + (refs.get(i, []) if i != s else [])
                print("%08x %-50r refs=%s" % (s, txt[:50], [(hex(a), k) for a, k in hits][:12]))
