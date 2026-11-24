# X-Pro 1 (EXR Pro) firmware unpacker + Ghidra loader

Standalone tooling for the Fujifilm **X-Pro 1** firmware: it unpacks the `.DAT`
update into the ARM code images and loads them into Ghidra at the correct
addresses. The X-Pro 1 was not covered by existing tooling, so this is a
starting point for analysis.

**No firmware is included here.** Download `FPUPDATE.DAT` yourself from
Fujifilm. The firmware and everything derived from it (decompressed segments,
string/symbol dumps) are git-ignored and must never be committed (copyright).

## What it does

1. The `.DAT` payload is bit-flipped (byte-wise NOT). Invert it to read it.
2. The ARM code is stored in `fflz` segments (Fujifilm's hardware LZ, 16 KB
   page aligned). `ffunpack.py` locates each segment by its self-describing
   20-byte header, decompresses it, and checks the output size against the
   header. The decompressor is a Python port of the `fflz` codec in this repo's
   `ffcompress/` (credit: tiredboffin, MIT).
3. `analyze_base.py` / `pin_base.py` derive each segment's ARM load address by
   the mode of `(pointer_value - prologue_offset)`: the correct base is the one
   that makes the most absolute pointers resolve onto real function prologues.
4. `XPro1Loader.java` loads both segments into one ARM:LE:32 Ghidra program.

## Verified memory map

Bases were derived by the method above and cross-confirmed by each segment's own
header word[1]. Header layout: `w0=flags, w1=load address, w2=size, w3=entry`.

| block | load address | size | entry | notes |
|-------|--------------|------|-------|-------|
| seg0 (UI/lens) | `0x00774000` | 0x254AC0 | `0x008554C4` | full `KEY_*` input table at 0x7747FC |
| seg1 (main) | `0x00E0EC80` | 0x3DBB00 | `0x00F57540` | record pipeline: `Reccf_Sv*`, `Recbf_*`, `TASK:RECCONT` |

seg0 references seg1 about 8,200 times, so both load into one program. A
headless Ghidra 12.2 run (ARM:LE:32:v5t) auto-discovered about 22,500 functions
across the two.

## Usage

```sh
# 1. unpack (produces inverted_seg00_*.bin and inverted_seg01_*.bin in OUT_DIR)
python3 -I ffunpack.py /path/to/FPUPDATE.DAT OUT_DIR

# 2. (optional) confirm the load addresses
python3 -I pin_base.py OUT_DIR/inverted_seg01_*.bin 0x00e00000 0x00e40000 30000

# 3. load into Ghidra (needs Ghidra 12.2 + JDK 25)
GHIDRA_DIR=/path/to/ghidra_12.2_PUBLIC SEG_DIR=OUT_DIR JAVA_HOME=/path/to/jdk25 ./run_ghidra.sh
```

In the Ghidra GUI instead: import `inverted_seg01_*.bin` as **Raw Binary**,
Language **ARM:LE:32:v5t**, base `00e0ec80`; then run `XPro1Loader.java` from the
Script Manager and pick `OUT_DIR`; then Auto Analyze.

Status: first-generation EXR Pro model. ARM 32-bit, little-endian. The native
Ghidra decompiler is not prebuilt for Apple Silicon, so pseudocode needs a
native build; disassembly and function/xref analysis work without it.
