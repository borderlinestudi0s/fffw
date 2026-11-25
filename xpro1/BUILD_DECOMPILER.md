# Building Ghidra's native decompiler for Apple Silicon

Ghidra's public release ships the native decompiler (`decompile`) only for
`win_x86_64` and `linux_x86_64`. On an Apple Silicon Mac the decompiler is
missing, so `analyzeHeadless` and REA can disassemble but not produce pseudo-C,
and REA's Ghidra provider reports the native decompiler as unavailable.

You can build it from the source that ships inside the release. Requirements:
the Xcode Command Line Tools (Apple clang), plus `bison` and `flex` (both
present on macOS by default).

```sh
cd <ghidra>/Ghidra/Features/Decompiler/src/decompile/cpp

# the Darwin branch of the Makefile hardcodes -arch x86_64; override to arm64
make ghidra_opt ARCH_TYPE="-arch arm64" -j8

file ghidra_opt          # -> Mach-O 64-bit executable arm64

# install where Ghidra looks for it
mkdir -p ../../../os/mac_arm_64
cp ghidra_opt ../../../os/mac_arm_64/decompile
chmod +x ../../../os/mac_arm_64/decompile
```

After this, headless Ghidra on the Mac decompiles normally. The same `make`
target with a matching `ARCH_TYPE` builds `sleigh_opt` (install as
`os/mac_arm_64/sleigh`) if you also need the SLEIGH compiler, though the
prebuilt `.sla` language files are enough for analysis and decompilation.

Note: this only builds the decompiler. REA's Ghidra provider additionally needs
`GHIDRA_INSTALL_DIR` set in the environment that launches the REA MCP server;
that cannot be changed in a running session.
