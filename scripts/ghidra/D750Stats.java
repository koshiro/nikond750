// Estadísticas del programa importado (solo lectura): funciones, instrucciones y cadenas con referencias.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class D750Stats extends GhidraScript {
    public void run() throws Exception {
        int fn = currentProgram.getFunctionManager().getFunctionCount();
        long ins = currentProgram.getListing().getNumInstructions();
        long str = 0, strRef = 0;
        for (Data d : currentProgram.getListing().getDefinedData(true)) {
            if (d.hasStringValue()) { str++; if (d.getReferenceIteratorTo().hasNext()) strRef++; }
        }
        println("STATS funciones=" + fn + " instrucciones=" + ins + " cadenas=" + str + " cadenas_con_xref=" + strRef);
        println("STATS rango=" + currentProgram.getMinAddress() + "-" + currentProgram.getMaxAddress());
    }
}
