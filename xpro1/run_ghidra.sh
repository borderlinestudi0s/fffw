#!/bin/bash
# Headless: load both X-Pro 1 segments into one ARM:LE:32 Ghidra program and analyze.
#
# Ghidra 12.2 requires a JDK 25+. Set these before running:
#   GHIDRA_DIR : path to your ghidra_12.2_PUBLIC install
#   SEG_DIR    : folder holding the decompressed inverted_seg*.bin files (from ffunpack.py)
#   JAVA_HOME  : a JDK 25+ home
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${GHIDRA_DIR:?set GHIDRA_DIR to your ghidra_12.2_PUBLIC install}"
: "${SEG_DIR:?set SEG_DIR to the folder with inverted_seg*.bin}"
: "${JAVA_HOME:?set JAVA_HOME to a JDK 25+ home}"
export PATH="$JAVA_HOME/bin:$PATH"
export MAXMEM="${MAXMEM:-4G}"

SEG1=$(ls "$SEG_DIR"/inverted_seg01_*.bin | head -1)
PROJDIR="${PROJDIR:-$HERE/proj}"
rm -rf "$PROJDIR"; mkdir -p "$PROJDIR"

"$GHIDRA_DIR/support/analyzeHeadless" "$PROJDIR" xpro1 \
  -import "$SEG1" \
  -processor "ARM:LE:32:v7" \
  -loader BinaryLoader -loader-baseAddr 0xe0ec80 \
  -scriptPath "$HERE" \
  -preScript XPro1Loader.java "$SEG_DIR" \
  -postScript XPro1Report.java \
  -overwrite
