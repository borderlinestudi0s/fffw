// Scoped-complete loader: raw import is ram_lowcode.bin @0x0 (vector+low+Thumb+seg0,
// 0x0..0x9c89c0). This adds seg1 and the sys/SQLite block, and DISABLES the slow
// decompiler-based analyzers that made the full raw run hang for hours.
// Arg: folder with ram_seg1.bin / ram_sys.bin
//@category Fujifilm
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.io.FileInputStream;

public class XPro1ScopedLoader2 extends GhidraScript {
    @Override
    public void run() throws Exception {
        String folder = getScriptArgs()[0];
        add("seg1", 0x00e0ec80L, "ram_seg1.bin", folder);
        add("sys",  0x01400000L, "ram_sys.bin",  folder);
        // kill the analyzers that blow up on a big raw image (the hang cause)
        // disable ONLY the runaway (decompiler-based / aggressive) analyzers that
        // caused the multi-hour hang. Keep references, stack, Thumb detection ON so
        // the analysis actually completes with string xrefs + correct ARM/Thumb modes.
        String[] off = {
            "Decompiler Parameter ID", "Decompiler Switch Analysis",
            "Aggressive Instruction Finder", "ARM Aggressive Instruction Finder"
        };
        for (String o : off) {
            try { setAnalysisOption(currentProgram, o, "false"); } catch (Exception e) {}
        }
        println("scoped loader2: added seg1+sys; disabled slow/garbage analyzers");
    }
    private void add(String name, long base, String fn, String folder) throws Exception {
        File f = new File(folder, fn);
        if (!f.exists()) { printerr("missing " + fn); return; }
        Address start = toAddr(base);
        if (currentProgram.getMemory().getBlock(start) != null) { println(name + " present"); return; }
        FileInputStream fis = new FileInputStream(f);
        try {
            MemoryBlock b = createMemoryBlock(name, start, fis, f.length(), false);
            b.setRead(true); b.setWrite(false); b.setExecute(true);
            println("added " + name + " @ " + start + " len=0x" + Long.toHexString(f.length()));
        } finally { fis.close(); }
    }
}
