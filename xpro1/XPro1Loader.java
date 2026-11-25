// X-Pro 1 firmware loader for Ghidra (Java GhidraScript; runs with no PyGhidra setup)
//
// Loads both decompressed fflz segments into ONE ARM:LE:32 program at their
// verified load addresses so the ~8,200 cross-segment references resolve.
//   seg0 (UI/lens) @ 0x00774000  size 0x254AC0  entry 0x008554C4
//   seg1 (main)    @ 0x00E0EC80  size 0x3DBB00  entry 0x00F57540
//
// Use: import inverted_seg01_*.bin as Raw Binary, Language ARM:LE:32:v7 (NOT v5t: the code uses MOVW/MOVT),
// Base 00e0ec80; then run this script and pick the folder with the .bin files.
//@category Fujifilm
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.io.FileInputStream;

public class XPro1Loader extends GhidraScript {

    @Override
    public void run() throws Exception {
        String folder;
        String[] args = getScriptArgs();
        if (args.length >= 1) {
            folder = args[0];
        } else {
            folder = askDirectory("Folder with decompressed .bin segments", "Choose").getPath();
        }
        loadSeg("seg0_ui",   0x00774000L, "inverted_seg00", 0x008554C4L, "seg0_entry", folder);
        loadSeg("seg1_main", 0x00E0EC80L, "inverted_seg01", 0x00F57540L, "main_entry", folder);
        addEntryPoint(toAddr(0x00F57540L));
        println("XPro1Loader done. Run Auto Analyze next (ARM defaults + Aggressive Instruction Finder).");
    }

    private void loadSeg(String name, long base, String prefix, long entry, String ename, String folder)
            throws Exception {
        File dir = new File(folder);
        File target = null;
        File[] files = dir.listFiles();
        if (files != null) {
            for (File f : files) {
                if (f.getName().startsWith(prefix) && f.getName().endsWith(".bin")) { target = f; break; }
            }
        }
        if (target == null) { printerr("missing file for " + name + " (prefix " + prefix + ")"); return; }

        Address start = toAddr(base);
        Memory mem = currentProgram.getMemory();
        MemoryBlock blk = mem.getBlock(start);
        if (blk == null) {
            FileInputStream fis = new FileInputStream(target);
            try {
                blk = createMemoryBlock(name, start, fis, target.length(), false);
            } finally {
                fis.close();
            }
            println("loaded " + name + " @ " + start + " len=0x" + Long.toHexString(target.length())
                    + " from " + target.getName());
        } else {
            println("block at " + start + " already present (" + blk.getName() + ") - reusing for " + name);
        }
        blk.setRead(true);
        blk.setWrite(false);
        blk.setExecute(true);

        setEOLComment(start, name + " header: w0=flags w1=loadaddr w2=size w3=entry");
        Address ea = toAddr(entry);
        disassemble(ea);
        Function fn = createFunction(ea, ename);
        if (fn == null) {
            createLabel(ea, ename, true);
            println("note: createFunction returned null at " + ea + ", set label " + ename);
        }
    }
}
