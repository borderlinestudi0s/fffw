// Post-analysis report for the X-Pro 1 program (Java GhidraScript postScript)
//@category Fujifilm
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;

public class XPro1Report extends GhidraScript {

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        println("=================== XPRO1 GHIDRA REPORT ===================");
        println("language    : " + currentProgram.getLanguageID());
        println("functions   : " + fm.getFunctionCount());
        println("instructions: " + listing.getNumInstructions());
        println("defined data: " + listing.getNumDefinedData());
        println("--- memory blocks ---");
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            println("  " + b.getName() + "  " + b.getStart() + " - " + b.getEnd()
                    + "  x=" + b.isExecute() + " init=" + b.isInitialized());
        }
        println("--- entry functions ---");
        long[] entries = { 0x008554C4L, 0x00F57540L };
        for (long e : entries) {
            Function f = fm.getFunctionAt(toAddr(e));
            println(String.format("  %08x -> %s", e, f != null ? f.getName() : "(no function)"));
        }
        println("functions in seg0 [0x774000,0x9c89c0): " + countIn(fm, 0x00774000L, 0x009c89c0L));
        println("functions in seg1 [0xe0ec80,0x11ea780): " + countIn(fm, 0x00e0ec80L, 0x011ea780L));
        println("=================== END REPORT ===================");
    }

    private int countIn(FunctionManager fm, long lo, long hi) {
        int n = 0;
        for (Function f : fm.getFunctions(true)) {
            long o = f.getEntryPoint().getOffset();
            if (o >= lo && o < hi) n++;
        }
        return n;
    }
}
