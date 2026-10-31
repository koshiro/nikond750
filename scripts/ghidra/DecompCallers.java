// Decompila los llamadores (1 nivel) de las funciones dadas por dirección (solo lectura). Args: salida addr1 addr2 ...
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
public class DecompCallers extends GhidraScript {
    public void run() throws Exception {
        String[] a = getScriptArgs();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        try (PrintWriter w = new PrintWriter(new FileWriter(a[0]))) {
            Set<Address> done = new HashSet<>();
            for (int i = 1; i < a.length; i++) {
                Address ad = toAddr(a[i]);
                w.println("===== llamadores de " + a[i]);
                ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(ad);
                while (it.hasNext()) {
                    Reference r = it.next();
                    Function f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                    w.println("  desde " + r.getFromAddress() + " en " + (f == null ? "-" : f.getName() + "@" + f.getEntryPoint()));
                    if (f != null && done.add(f.getEntryPoint())) {
                        DecompileResults res = di.decompileFunction(f, 60, monitor);
                        if (res.decompileCompleted()) w.println(res.getDecompiledFunction().getC());
                    }
                }
            }
        }
    }
}
