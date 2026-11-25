// Decompile addresses, trying ARM first then Thumb (TMode=1). Java GhidraScript.
// Args: one or more 0xADDR.
//@category Fujifilm
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import java.math.BigInteger;

public class XPro1DecompAuto extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        Register tmode = currentProgram.getProgramContext().getRegister("TMode");
        for (String a : getScriptArgs()) {
            long addr = Long.decode(a);
            String arm = tryAt(di, tmode, addr, false);
            if (ok(arm)) {
                println("==================== " + a + "  [ARM] ====================");
                println(arm);
            } else {
                String th = tryAt(di, tmode, addr, true);
                println("==================== " + a + "  [THUMB]" + (ok(th) ? "" : " (both modes rough)") + " ====================");
                println(th != null ? th : "(decompile failed in both modes)");
            }
        }
        di.dispose();
    }

    private boolean ok(String c) {
        return c != null && !c.contains("halt_baddata") && !c.contains("bad instruction")
               && !c.contains("Bad instruction");
    }

    private String tryAt(DecompInterface di, Register tmode, long addr, boolean thumb) {
        try {
            Address ea = toAddr(addr);
            clearListing(ea, ea.add(0x400));
            if (tmode != null) {
                currentProgram.getProgramContext().setValue(tmode, ea, ea.add(0x400),
                        thumb ? BigInteger.ONE : BigInteger.ZERO);
            }
            disassemble(ea);
            Function f = getFunctionAt(ea);
            if (f == null) f = createFunction(ea, null);
            if (f == null) return null;
            DecompileResults r = di.decompileFunction(f, 90, monitor);
            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null)
                return r.getDecompiledFunction().getC();
        } catch (Exception e) {
            return "(exception: " + e + ")";
        }
        return null;
    }
}
