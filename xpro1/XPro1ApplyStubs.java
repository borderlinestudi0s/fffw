// Apply NSTUB(name, addr) lines from a fujihack-style stub header as function
// names in the current program. Commented-out stubs are skipped.
// Arg 0: path to the header (e.g. xpro1_364_stubs.h)
//@category XPro1
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.util.regex.*;

public class XPro1ApplyStubs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String path = getScriptArgs().length > 0 ? getScriptArgs()[0] : askFile("stub header", "Apply").getPath();
        Pattern p = Pattern.compile("^\\s*NSTUB\\(\\s*(\\w+)\\s*,\\s*0x([0-9a-fA-F]+)\\s*\\)");
        int n = 0;
        for (String line : Files.readAllLines(Paths.get(path))) {
            Matcher m = p.matcher(line);
            if (!m.find()) continue;
            Address a = toAddr(Long.parseLong(m.group(2), 16));
            Function f = getFunctionAt(a);
            if (f == null) {
                disassemble(a);
                f = createFunction(a, m.group(1));
            }
            if (f == null) { printerr("could not create function at " + a); continue; }
            f.setName(m.group(1), SourceType.USER_DEFINED);
            int c = line.indexOf("/*");
            if (c > 0) f.setComment(line.substring(c).replace("/*", "").replace("*/", "").trim());
            println("named " + a + " " + m.group(1));
            n++;
        }
        println("applied " + n + " stubs");
    }
}
