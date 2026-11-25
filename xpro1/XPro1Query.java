// Read-only query tool for the analyzed proj_sc2 program.
// Reads commands from a text file (arg 0), writes results to arg 1.
// Commands (one per line, hex addresses):
//   ref  <addr>        references TO addr (from, containing function)
//   lit  <addr>        find aligned words == addr (or addr|1), then refs to those slots
//   fn   <addr>        function containing addr: entry, size, thumb?, callers
//   dec  <addr>        decompile function containing addr
//   dis  <addr> <n>    disassemble n code units from addr
//   calls <addr>       call sites inside function (callee addresses)
//@category XPro1
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.Register;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

public class XPro1Query extends GhidraScript {
    PrintWriter out;
    DecompInterface di;

    Address A(String s) { return toAddr(Long.parseLong(s.replace("0x",""), 16)); }

    String fdesc(Address a) {
        Function f = getFunctionContaining(a);
        if (f == null) return "(no fn)";
        return f.getName() + "@" + f.getEntryPoint();
    }

    boolean thumb(Address a) {
        Register r = currentProgram.getRegister("TMode");
        if (r == null) return false;
        BigInteger v = currentProgram.getProgramContext().getValue(r, a, false);
        return v != null && v.intValue() == 1;
    }

    void ref(Address a) {
        int n = 0;
        for (Reference r : getReferencesTo(a)) {
            out.printf("  ref %s <- %s [%s] in %s%n", a, r.getFromAddress(), r.getReferenceType(), fdesc(r.getFromAddress()));
            if (++n > 60) { out.println("  ...more"); break; }
        }
        if (n == 0) out.println("  (no refs to " + a + ")");
    }

    void lit(Address a) throws Exception {
        long v = a.getOffset();
        Memory mem = currentProgram.getMemory();
        for (long want : new long[]{v, v | 1}) {
            byte[] pat = new byte[]{(byte)want, (byte)(want>>8), (byte)(want>>16), (byte)(want>>24)};
            Address s = mem.getMinAddress();
            int n = 0;
            while (s != null && n < 40) {
                Address h = mem.findBytes(s, pat, null, true, monitor);
                if (h == null) break;
                if ((h.getOffset() & 3) == 0) {
                    out.printf("  word==%08x at %s (in %s)%n", want, h, fdesc(h));
                    ref(h);
                    n++;
                }
                s = h.add(1);
            }
        }
    }

    void fn(Address a) {
        Function f = getFunctionContaining(a);
        if (f == null) { out.println("  no function contains " + a); return; }
        out.printf("  fn %s entry=%s size=%d thumb=%b params=%d sig=%s%n", f.getName(), f.getEntryPoint(),
            f.getBody().getNumAddresses(), thumb(f.getEntryPoint()), f.getParameterCount(), f.getSignature());
        int n = 0;
        for (Reference r : getReferencesTo(f.getEntryPoint())) {
            out.printf("    caller %s [%s] in %s%n", r.getFromAddress(), r.getReferenceType(), fdesc(r.getFromAddress()));
            if (++n > 40) { out.println("    ...more"); break; }
        }
        out.println("    callers=" + n);
    }

    void calls(Address a) {
        Function f = getFunctionContaining(a);
        if (f == null) { out.println("  no fn"); return; }
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            for (Reference r : ins.getReferencesFrom()) {
                if (r.getReferenceType().isCall() || r.getReferenceType().isData())
                    out.printf("    %s %-28s -> %s [%s] %s%n", ins.getAddress(), ins.toString(), r.getToAddress(),
                        r.getReferenceType(), r.getReferenceType().isCall() ? fdesc(r.getToAddress()) : str(r.getToAddress()));
            }
        }
    }

    void range(Address a, Address b) {
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(new AddressSet(a, b), true);
        while (it.hasNext()) {
            Function f = it.next();
            int n = 0;
            for (Reference r : getReferencesTo(f.getEntryPoint())) n++;
            StringBuilder cs = new StringBuilder();
            InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (ii.hasNext()) {
                Instruction ins = ii.next();
                for (Reference r : ins.getReferencesFrom()) {
                    if (r.getReferenceType().isCall()) cs.append(" ").append(r.getToAddress());
                    else if (r.getReferenceType().isData()) { String t = str(r.getToAddress()); if (t.startsWith("\"") || t.startsWith("*")) cs.append(" ").append(t); }
                }
            }
            out.printf("  %s size=%-5d callers=%-4d %s%n", f.getEntryPoint(), f.getBody().getNumAddresses(), n, cs.length() > 220 ? cs.substring(0, 220) : cs);
        }
    }

    String str(Address a) {
        try {
            Data d = getDataAt(a);
            if (d != null && d.hasStringValue()) return "\"" + d.getValue() + "\"";
            // follow pointer slot
            Memory m = currentProgram.getMemory();
            int w = m.getInt(a);
            Address p = toAddr(w & 0xffffffffL);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 48; i++) {
                byte b = m.getByte(p.add(i));
                if (b == 0) break;
                if (b < 32 || b > 126) { sb.setLength(0); break; }
                sb.append((char) b);
            }
            if (sb.length() >= 3) return String.format("*%08x=\"%s\"", w, sb);
            return String.format("[%08x]", w);
        } catch (Exception e) { return ""; }
    }

    void dec(Address a) {
        Function f = getFunctionContaining(a);
        if (f == null) { out.println("  no function contains " + a); return; }
        DecompileResults r = di.decompileFunction(f, 90, monitor);
        if (r != null && r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
        else out.println("  decompile failed: " + (r == null ? "null" : r.getErrorMessage()));
    }

    void dis(Address a, int n) {
        Listing l = currentProgram.getListing();
        CodeUnit cu = l.getCodeUnitContaining(a);
        Address cur = cu == null ? a : cu.getAddress();
        for (int i = 0; i < n && cur != null; i++) {
            cu = l.getCodeUnitAt(cur);
            if (cu == null) { cu = l.getCodeUnitAfter(cur); if (cu == null) break; }
            String extra = "";
            if (cu instanceof Instruction) {
                for (Reference r : ((Instruction) cu).getReferencesFrom()) extra += " ->" + r.getToAddress() + " " + str(r.getToAddress());
            }
            out.printf("    %s %s %-36s%s%n", cu.getAddress(), thumb(cu.getAddress()) ? "T" : "A", cu.toString(), extra);
            cur = cu.getMaxAddress().add(1);
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        List<String> cmds = Files.readAllLines(Paths.get(args[0]));
        out = new PrintWriter(new FileWriter(args[1]));
        di = new DecompInterface();
        di.openProgram(currentProgram);
        out.println("functions: " + currentProgram.getFunctionManager().getFunctionCount());
        for (String line : cmds) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] p = line.split("\\s+");
            out.println("== " + line);
            try {
                switch (p[0]) {
                    case "ref": ref(A(p[1])); break;
                    case "lit": lit(A(p[1])); break;
                    case "fn": fn(A(p[1])); break;
                    case "dec": dec(A(p[1])); break;
                    case "dis": dis(A(p[1]), p.length > 2 ? Integer.parseInt(p[2]) : 30); break;
                    case "calls": calls(A(p[1])); break;
                    case "range": range(A(p[1]), A(p[2])); break;
                    default: out.println("  ?");
                }
            } catch (Exception e) { out.println("  error: " + e); }
            out.flush();
        }
        di.dispose();
        out.close();
    }
}
