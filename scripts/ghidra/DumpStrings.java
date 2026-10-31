// Vuelca cadenas definidas con dirección y primera función que las referencia (solo lectura). Arg 1: archivo de salida.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
public class DumpStrings extends GhidraScript {
    public void run() throws Exception {
        String[] a = getScriptArgs();
        try (PrintWriter w = new PrintWriter(new FileWriter(a[0]))) {
            for (Data d : currentProgram.getListing().getDefinedData(true)) {
                if (!d.hasStringValue()) continue;
                String s = String.valueOf(d.getValue()).replace("\n", "\\n");
                String fn = "-";
                ReferenceIterator it = d.getReferenceIteratorTo();
                if (it.hasNext()) {
                    Function f = currentProgram.getFunctionManager().getFunctionContaining(it.next().getFromAddress());
                    if (f != null) fn = f.getEntryPoint().toString();
                }
                w.println(d.getAddress() + "\t" + fn + "\t" + s);
            }
        }
    }
}
