// Decompila las funciones que referencian cadenas que contienen un patrón (solo lectura).
// Args: archivo_salida patrón1 patrón2 ...
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
public class DecompRefs extends GhidraScript {
    public void run() throws Exception {
        String[] a = getScriptArgs();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        Set<Address> done = new HashSet<>();
        try (PrintWriter w = new PrintWriter(new FileWriter(a[0]))) {
            for (int i = 1; i < a.length; i++) {
                for (Data d : currentProgram.getListing().getDefinedData(true)) {
                    if (!d.hasStringValue() || !String.valueOf(d.getValue()).equals(a[i])) continue;
                    w.println("===== cadena '" + a[i] + "' @ " + d.getAddress());
                    ReferenceIterator it = d.getReferenceIteratorTo();
                    while (it.hasNext()) {
                        Reference r = it.next();
                        Function f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                        w.println("  ref desde " + r.getFromAddress() + " en " + (f == null ? "-" : f.getName() + "@" + f.getEntryPoint()));
                        if (f != null && done.add(f.getEntryPoint())) {
                            DecompileResults res = di.decompileFunction(f, 60, monitor);
                            if (res.decompileCompleted()) w.println(res.getDecompiledFunction().getC());
                        }
                    }
                }
            }
        }
    }
}
