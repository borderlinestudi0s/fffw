#!/usr/bin/env python3
"""Disassemble a slice of the RAM dump as ARMv7 or Thumb-2 via Xcode llvm-objdump.
usage: python3 -I work/dis.py <hexstart> <hexlen|declen> [arm|thumb]"""
import sys, struct, subprocess, tempfile, os
D = os.environ.get("XPRO1_DUMP", os.path.expanduser("~/Downloads/xpro1_ram_0-32M.bin"))
s = int(sys.argv[1], 16); n = int(sys.argv[2], 0); mode = sys.argv[3] if len(sys.argv) > 3 else "arm"
code = open(D, "rb").read()[s:s + n]
shstr = b"\0.text\0.shstrtab\0"
ehsz, shsz = 52, 40
off_text = ehsz; off_shstr = off_text + len(code); off_sh = (off_shstr + len(shstr) + 3) & ~3
eh = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8
eh += struct.pack("<HHIIIIIHHHHHH", 1, 40, 1, 0, 0, off_sh, 0x05000000, ehsz, 0, 0, shsz, 3, 2)
sh = b"\0" * shsz
sh += struct.pack("<IIIIIIIIII", 1, 1, 6, s, off_text, len(code), 0, 0, 4, 0)
sh += struct.pack("<IIIIIIIIII", 7, 3, 0, 0, off_shstr, len(shstr), 0, 0, 1, 0)
blob = eh + code + shstr
blob += b"\0" * (off_sh - len(blob)) + sh
f = tempfile.NamedTemporaryFile(suffix=".o", delete=False); f.write(blob); f.close()
obj = subprocess.check_output(["xcrun", "--find", "llvm-objdump"]).decode().strip()
tri = "thumbv7-none-eabi" if mode == "thumb" else "armv7-none-eabi"
out = subprocess.run([obj, "-d", "--triple=" + tri, f.name], capture_output=True, text=True).stdout
os.unlink(f.name)
for line in out.splitlines():
    if line.strip().startswith(tuple("0123456789abcdef")) and ":" in line: print(line)
