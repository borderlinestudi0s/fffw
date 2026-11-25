# Fujifilm X-Pro 1 (EXR Pro) reverse-engineering starting point

Tooling and findings for the Fujifilm **X-Pro 1**, firmware **3.64**. The X-Pro 1
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
  is the same build the camera runs (3.64).
- **The firmware is scatter-loaded and mixes ARM and Thumb.** Most of it is
  stored uncompressed (bit-flipped) in the DAT, not in `fflz` segments.
- **Confirmed functions (runtime addresses, FW 3.64):**
  - `0x00966A8C` = `strcpy` (plain byte-copy loop; verified by decompilation).
  - `0x00041C38` = an ARM name/string helper (copies a string into a small stack
    buffer, then tail-calls `0x000412F4`).

## Verified memory map (FW 3.64, runtime addresses)

| region | contents | notes |
|--------|----------|-------|
| `0x00000000` | ARM exception vector table | live RAM only |
| `0x00040000`-`0x00100000` | low RTOS code | ARM, incl. `0x41c38` |
| `0x00100000`-`0x00774000` | large **Thumb** code block | ~9.7k Thumb prologues |
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
- **The decompiler-based analyzers (Decompiler Parameter ID / Switch Analysis)
  are what resolve string references on a raw ARM image, and they are also the
  ones that hang.** Disabling them stops the hang but leaves string refs
  unresolved. This is the central tension; a per-model manifest (fffw `ffun`)
  is the real fix.
- **ARM `STMFD` prologue scanning is unreliable in the Thumb regions.** Function
  addresses derived that way in Thumb code are often bogus. Use Ghidra's
  Thumb-aware analysis for function boundaries there.
- **Debug name strings (`Reccf_*`, `KEY_*`, etc.) are stored in enum-indexed
  name tables, not referenced one-to-one by the functions they describe**, so
  they cannot be mapped to functions by a simple string-to-reference search.

## What is next

Clean function identification (the `NSTUB` table in `xpro1_364_stubs.h`) is
interactive Ghidra work: navigate the loaded program, set Thumb modes per
region, follow xrefs, and identify the platform API (`fuji_fopen`,
`fuji_create_task`, the SQLite calls) by behaviour. That is genuine
per-function RE, not a batch job.

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
- `xpro1_364_stubs.h` - WIP stub header (for eventual `fujihack/model/`).
