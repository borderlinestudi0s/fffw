# Fujifilm X-Pro 1 (EXR Pro) reverse-engineering starting point

Tooling and findings for the Fujifilm **X-Pro 1**, firmware **3.82**. The X-Pro 1
was essentially unmapped (fujihack's `model/xpro1_382.h` has no function stubs),
so this is a foundation to build on, not a finished mod.

**No firmware, memory dumps, or device identifiers are included here, ever.**
Download `FPUPDATE.DAT` yourself from Fujifilm. Everything derived from the
firmware or a RAM dump stays local (see `.gitignore`).

## What is verified

- **Firmware container:** the `.DAT` payload is bit-flipped (byte-wise NOT). The
  ARM code is stored in `fflz` segments (Fujifilm's hardware LZ, 16 KB pages);
  `ffunpack.py` locates and decompresses them. Decoder ported from this repo's
  `ffcompress/fflz` (credit: tiredboffin, MIT).
- **Two app-layer segments decompress and were confirmed byte-for-byte against a
  live RAM dump:** `seg0` (UI/keys/lens) at `0x00774000`, `seg1` (record
  pipeline) at `0x00E0EC80`. That match also confirms the shipped `FPUPDATE.DAT`
  is the same build the camera runs: public firmware **3.82**. (The FF80
  service port reports internal version "3.64", which is the internal number
  for 3.82, not a different release.)
- **The CPU is ARMv7 and the code builds addresses with `MOVW`/`MOVT` pairs**,
  not literal pools. Import as **`ARM:LE:32:v7`**. An ARMv5 (`v5t`) import cannot
  decode `MOVW`/`MOVT`, so most code turns to garbage, nearly every string
  reference disappears and the noise looks like Thumb. With v7 the scoped image
  analyzes in about 2 minutes (33,139 functions, 1.59M instructions) and string
  references and decompilation just work.
- **The firmware is scatter-loaded.** Most of it is stored uncompressed
  (bit-flipped) in the DAT, not in `fflz` segments. Thumb-2 code exists, but the
  platform library, seg1 and SQLite are ARM mode.
- **23 platform functions identified**, including the full file API, task
  creation, sleep, task events, soft timers, key injection and `sqlite_exec`:
  see [`xpro1_382_stubs.h`](xpro1_382_stubs.h), each tagged confirmed or
  probable with the evidence.

## Verified memory map (FW 3.82, runtime addresses)

| region | contents | notes |
|--------|----------|-------|
| `0x00000000` | ARM exception vector table | live RAM only |
| `0x00040000`-`0x00100000` | low RTOS code | ARM, incl. `0x41c38` |
| `0x00100000`-`0x00774000` | large code block | looked Thumb under the old v5t import; re-check under v7 |
| `0x00774000`-`0x009C89C0` | seg0 (UI/keys/lens) | fflz in DAT |
| `0x00E0EC80`-`0x011EA780` | seg1 (record pipeline) | fflz in DAT |
| `0x01400000`-`0x01700000` | system/library block (SQLite core ~`0x1697000`) | uncompressed |
| gaps between the above | zeros / data buffers | no code |

## Workflow

Two ways to get an analyzable image:

1. **From the firmware file (static):**
   ```sh
   python3 -I ffunpack.py /path/to/FPUPDATE.DAT OUT_DIR   # -> inverted_seg0x_*.bin
   ```
   This recovers the two `fflz` code segments. The uncompressed regions (low
   RTOS, Thumb block, system/SQLite) are not in these segments; they are read
   directly from a RAM dump (below), which also gives true runtime addresses.

2. **From a live RAM dump (preferred, read-only, no flashing):** see
   [DUMP.md](DUMP.md). A dump of `0x0`-`0x2000000` captures every code region at
   its true runtime address, including the resident ROM the update file does not
   contain.

Then analyze in Ghidra:

- Build the native decompiler for your platform if the public release lacks it
  (Apple Silicon does): see [BUILD_DECOMPILER.md](BUILD_DECOMPILER.md).
- Load only the code regions (skip the zero/data gaps) and disable the runaway
  analyzers, or Ghidra will churn for hours on a raw image. The `XPro1*.java`
  GhidraScripts here do this; `run_ghidra.sh` drives a headless run.

## Hard-won lessons (so you do not repeat them)

- **Do not feed the raw 32 MB image to Ghidra auto-analysis.** With no headers,
  the aggressive instruction finder invents tens of thousands of bogus functions
  in the data/zero regions, then the decompiler-based analyzers try to process
  all of them. It ran 9+ hours without finishing. Map only the real code regions.
- **Use the ARMv7 language.** Missing string references were never an analyzer
  problem: the v5t language could not decode the `MOVW`/`MOVT` pairs that carry
  every address. Raw scanners need the same care: `xref7.py` decodes ARM and
  Thumb-2 `MOVW`/`MOVT` pairs plus `BL`/`BLX` across the whole dump in seconds.
- **Prologue scanning is unreliable.** Many functions open with
  `push {r11, lr}` or `str r11, [sp, #-4]!` rather than a wide `STMFD`, and
  Thumb-2 code exists. Use Ghidra's function boundaries.
- **Debug name strings (`Reccf_*`, `KEY_*`, etc.) are stored in enum-indexed
  name tables, not referenced one-to-one by the functions they describe**, so
  they cannot be mapped to functions by a simple string-to-reference search.

## What is next

The core platform API is mapped. Still open: `fuji_get_error`,
`fuji_file_wait`/`fuji_file_reset`, `fuji_init_sqlite`, `sqlite_snprintf`,
`sqlite_mallocAlarm`, `SQLITE_MEM_METHODS`, `MEM_INPUT_MAP` and
`fuji_screen_write`. Once those are in, the table can move to
fujihack's existing `model/xpro1_382.h` (same version).

Useful entry points for further work: the AUTO_ACT script engine in seg1
(`0x010b4000`-`0x010b6100`, keyword table at `0x010b5f0c`) drives files, keys
and sleeps from an SD-card script, which makes it the natural first hook for a
non-flashing mod.

## Files

- `ffunpack.py` - locate + decompress `fflz` segments from `FPUPDATE.DAT`.
- `analyze_base.py`, `pin_base.py` - derive a segment's ARM load address by
  pointer-to-prologue analysis (ARM only; unreliable in Thumb regions).
- `XPro1Loader.java` / `XPro1ScopedLoader2.java` - load code regions into Ghidra
  at true addresses (scoped loader also disables the runaway analyzers).
- `XPro1DumpHunt.java` - report function count and string-reference owners.
- `XPro1Decomp.java` / `XPro1DecompAuto.java` - decompile given addresses
  (Auto tries ARM then Thumb).
- `XPro1Report.java`, `run_ghidra.sh` - headless report + driver.
- `XPro1Query.java` - read-only batch queries against an analyzed program
  (`ref`, `lit`, `fn`, `dec`, `dis`, `calls`, `range`).
- `XPro1ApplyStubs.java` - apply `NSTUB(name, addr)` lines from a header as
  function names.
- `xref7.py` - ARMv7-aware xref index over a raw dump (`MOVW`/`MOVT`, LDR
  literal, `BL`/`BLX`): `str`, `refs`, `callers`.
- `dis.py` - disassemble a slice of a raw dump as ARMv7 or Thumb-2 with
  `llvm-objdump` (no objcopy needed).
- `xpro1_382_stubs.h` - WIP stub header (for fujihack `model/xpro1_382.h`).
