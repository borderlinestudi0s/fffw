// Decompile specific addresses in the loaded image (Java GhidraScript).
// Args: one or more 0xADDR to decompile. Works with -noanalysis (disassembles
// and defines each target function on demand, then decompiles it).
//@category Fujifilm
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class XPro1Decomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        for (String a : args) {
            long addr = Long.decode(a);
            Address ea = toAddr(addr);
            disassemble(ea);
            Function f = getFunctionAt(ea);
            if (f == null) f = createFunction(ea, null);
            println("==================== " + a + "  (" + (f != null ? f.getName() : "no-fn") + ") ====================");
            if (f == null) { println("  (could not create function here)"); continue; }
            DecompileResults r = di.decompileFunction(f, 90, monitor);
            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                println(r.getDecompiledFunction().getC());
            } else {
                println("  decompile failed: " + (r != null ? r.getErrorMessage() : "null result"));
            }
        }
        di.dispose();
    }
}
