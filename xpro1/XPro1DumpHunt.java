// Post-analysis hunt on the full RAM dump (flat image at base 0). Names the
// verified primitives, counts callers, and resolves string-anchored functions
// now that the whole address space is present. (Java GhidraScript)
//@category Fujifilm
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import java.util.HashSet;
import java.util.Set;

public class XPro1DumpHunt extends GhidraScript {

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing l = currentProgram.getListing();
        println("=================== XPRO1 DUMP REPORT (FW 3.82) ===================");
        println("functions    : " + fm.getFunctionCount());
        println("instructions : " + l.getNumInstructions());

        println("--- verified primitives (named, with code-ref caller counts) ---");
        nameAndCount(0x00966a8cL, "fuji_wt_log");
        nameAndCount(0x00041c38L, "rtos_prim_41c38");
        nameAndCount(0x00f501c4L, "auto_act_handler");

        println("--- string-anchored owners (resolved via full xref graph) ---");
        long[] sAddr = { 0x00f50f1dL, 0x01697b2cL, 0x016972d0L, 0x0109aeacL, 0x0102b9d4L };
        String[] sName = { "*.* (fuji_dir_open?)", "out of memory (sqlite)",
                           "CREATE TABLE (sqlite)", "SoftTimerStart (wait_task_start?)",
                           "Reccf_SvRecMovie" };
        for (int i = 0; i < sAddr.length; i++) {
            Address a = toAddr(sAddr[i]);
            Reference[] refs = getReferencesTo(a);
            Set<String> owners = new HashSet<String>();
            for (Reference r : refs) {
                if (getInstructionContaining(r.getFromAddress()) != null) {
                    Function f = getFunctionContaining(r.getFromAddress());
                    if (f != null) owners.add(f.getEntryPoint().toString());
                }
            }
            println(String.format("  %-34s refs=%d  codeOwners=%s", sName[i], refs.length, owners));
        }
        println("=================== END ===================");
    }

    private void nameAndCount(long addr, String name) throws Exception {
        Address a = toAddr(addr);
        disassemble(a);
        Function f = getFunctionAt(a);
        if (f == null) f = createFunction(a, name);
        if (f != null && f.getSymbol() != null && f.getSymbol().getSource() == SourceType.DEFAULT) {
            f.setName(name, SourceType.USER_DEFINED);
        }
        int callers = 0;
        for (Reference r : getReferencesTo(a)) {
            if (getInstructionContaining(r.getFromAddress()) != null) callers++;
        }
        println(String.format("  %-18s @%08x  code-ref callers=%d  (fn=%s)",
                name, addr, callers, f != null ? "yes" : "no"));
    }
}
