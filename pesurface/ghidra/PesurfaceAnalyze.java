// pesurface Ghidra headless analysis script
// Runs via: analyzeHeadless ... -postScript PesurfaceAnalyze.java /path/to/output.json
//
// Outputs JSON with traced API calls, call graphs, and function decompilations.
//@category pesurface
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

import java.io.*;
import java.util.*;

public class PesurfaceAnalyze extends GhidraScript {

    private static final Set<String> DANGEROUS_APIS = new HashSet<>(Arrays.asList(
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "CreateProcessA", "CreateProcessW", "CreateProcessAsUserA", "CreateProcessAsUserW",
        "CreateProcessWithLogonW", "CreateProcessWithTokenW",
        "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
        "WinExec", "system", "_wsystem",
        "ImpersonateNamedPipeClient", "ImpersonateLoggedOnUser",
        "SetThreadToken", "RpcImpersonateClient", "CoImpersonateClient",
        "CreateNamedPipeA", "CreateNamedPipeW", "ConnectNamedPipe",
        "MoveFileA", "MoveFileW", "MoveFileExA", "MoveFileExW",
        "CopyFileA", "CopyFileW", "DeleteFileA", "DeleteFileW",
        "ReplaceFileA", "ReplaceFileW", "CreateFileA", "CreateFileW",
        "CreateHardLinkA", "CreateHardLinkW",
        "CreateSymbolicLinkA", "CreateSymbolicLinkW",
        "RegCreateKeyExA", "RegCreateKeyExW",
        "RegSetValueExA", "RegSetValueExW",
        "CreateServiceA", "CreateServiceW",
        "ChangeServiceConfigA", "ChangeServiceConfigW",
        "CoCreateInstance", "CoCreateInstanceEx",
        "SetSecurityDescriptorDacl",
        "ConvertStringSecurityDescriptorToSecurityDescriptorA",
        "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        "IoCreateDevice", "IoCreateDeviceSecure", "DeviceIoControl",
        "LogonUserA", "LogonUserW", "CredReadA", "CredReadW",
        "CryptUnprotectData",
        "RpcServerRegisterIf", "RpcServerRegisterIf2", "RpcServerRegisterIf3",
        "RpcServerRegisterIfEx",
        "SetNamedSecurityInfoA", "SetNamedSecurityInfoW",
        "NtCreateFile", "NtSetInformationFile"
    ));

    private static final Set<String> ENTRY_NAMES = new HashSet<>(Arrays.asList(
        "ServiceMain", "SvcMain", "ServiceMainW", "ServiceMainA",
        "DriverEntry", "GsDriverEntry",
        "DllMain", "DllGetClassObject", "DllRegisterServer",
        "main", "wmain", "WinMain", "wWinMain", "entry"
    ));

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputPath;
        if (args.length > 0) {
            outputPath = args[0];
        } else {
            outputPath = System.getProperty("user.home") + File.separator +
                "pesurface_" + currentProgram.getName().replace(".", "_") + ".json";
        }

        println("[pesurface] Analyzing: " + currentProgram.getName());

        // Trace API calls
        println("[pesurface] Tracing dangerous API calls...");
        List<Map<String,Object>> apiCalls = traceApiCalls();
        println("[pesurface] Found " + apiCalls.size() + " call sites");

        // Build call graphs
        println("[pesurface] Building call graphs...");
        List<Map<String,Object>> callGraphs = buildCallGraphs();
        println("[pesurface] Built " + callGraphs.size() + " call graphs");

        // Decompile interesting functions
        println("[pesurface] Decompiling functions...");
        List<Map<String,Object>> functions = decompileFunctions();
        println("[pesurface] Decompiled " + functions.size() + " functions");

        // Write JSON
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"program\": \"").append(escJson(currentProgram.getName())).append("\",\n");
        sb.append("  \"language\": \"").append(escJson(currentProgram.getLanguageID().toString())).append("\",\n");
        sb.append("  \"api_calls\": ").append(listToJson(apiCalls)).append(",\n");
        sb.append("  \"call_graphs\": ").append(listToJson(callGraphs)).append(",\n");
        sb.append("  \"functions\": ").append(listToJson(functions)).append("\n");
        sb.append("}\n");

        FileWriter fw = new FileWriter(outputPath);
        fw.write(sb.toString());
        fw.close();

        println("[pesurface] Results written to " + outputPath);
    }

    private List<Map<String,Object>> traceApiCalls() {
        List<Map<String,Object>> results = new ArrayList<>();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Listing listing = currentProgram.getListing();

        // Check external functions
        FunctionIterator extFuncs = fm.getExternalFunctions();
        while (extFuncs.hasNext()) {
            Function func = extFuncs.next();
            String name = func.getName();
            if (!DANGEROUS_APIS.contains(name)) continue;

            ReferenceIterator refIter = refMgr.getReferencesTo(func.getEntryPoint());
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                Function caller = fm.getFunctionContaining(fromAddr);
                String callerName = caller != null ? caller.getName() : "unknown";

                List<String> resolvedArgs = resolveNearbyStrings(fromAddr, listing, refMgr);

                Map<String,Object> entry = new LinkedHashMap<>();
                entry.put("api", name);
                entry.put("caller", callerName);
                entry.put("address", "0x" + fromAddr.toString());
                entry.put("resolved_args", resolvedArgs);
                results.add(entry);
            }
        }

        // Also check internal thunks
        FunctionIterator allFuncs = fm.getFunctions(true);
        while (allFuncs.hasNext()) {
            Function func = allFuncs.next();
            if (func.isExternal()) continue;
            String name = func.getName();
            if (!DANGEROUS_APIS.contains(name)) continue;

            ReferenceIterator refIter2 = refMgr.getReferencesTo(func.getEntryPoint());
            while (refIter2.hasNext()) {
                Reference ref = refIter2.next();
                if (!ref.getReferenceType().isCall()) continue;
                Address fromAddr = ref.getFromAddress();
                Function caller = fm.getFunctionContaining(fromAddr);
                String callerName = caller != null ? caller.getName() : "unknown";

                List<String> resolvedArgs = resolveNearbyStrings(fromAddr, listing, refMgr);

                Map<String,Object> entry = new LinkedHashMap<>();
                entry.put("api", name);
                entry.put("caller", callerName);
                entry.put("address", "0x" + fromAddr.toString());
                entry.put("resolved_args", resolvedArgs);
                results.add(entry);
            }
        }

        return results;
    }

    private List<String> resolveNearbyStrings(Address callAddr, Listing listing, ReferenceManager refMgr) {
        List<String> strings = new ArrayList<>();
        Instruction inst = listing.getInstructionBefore(callAddr);
        int checked = 0;
        Set<String> seen = new HashSet<>();

        while (inst != null && checked < 20) {
            Reference[] refs = refMgr.getReferencesFrom(inst.getAddress());
            for (Reference ref : refs) {
                if (ref.getReferenceType().isData()) {
                    String s = getStringAt(ref.getToAddress());
                    if (s != null && s.length() > 1 && s.length() < 512 && !seen.contains(s)) {
                        seen.add(s);
                        strings.add(s);
                        if (strings.size() >= 5) return strings;
                    }
                }
            }
            inst = listing.getInstructionBefore(inst.getAddress());
            checked++;
        }
        return strings;
    }

    private String getStringAt(Address addr) {
        Listing listing = currentProgram.getListing();
        Data data = listing.getDataAt(addr);
        if (data != null) {
            Object val = data.getValue();
            if (val instanceof String) {
                return (String) val;
            }
        }
        // Try raw ASCII
        Memory mem = currentProgram.getMemory();
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 512; i++) {
                byte b = mem.getByte(addr.add(i));
                if (b == 0) break;
                if (b >= 0x20 && b < 0x7f) {
                    sb.append((char) b);
                } else {
                    break;
                }
            }
            if (sb.length() >= 2) return sb.toString();
        } catch (Exception e) {
            // ignore
        }
        return null;
    }

    private List<Map<String,Object>> buildCallGraphs() {
        List<Map<String,Object>> graphs = new ArrayList<>();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        FunctionIterator funcs = fm.getFunctions(true);
        while (funcs.hasNext()) {
            Function func = funcs.next();
            if (!ENTRY_NAMES.contains(func.getName())) continue;

            List<Map<String,Object>> tree = walkCalls(func, fm, refMgr, 4, new HashSet<>());

            Map<String,Object> graph = new LinkedHashMap<>();
            graph.put("entry", func.getName());
            graph.put("address", "0x" + func.getEntryPoint().toString());
            graph.put("tree", tree);
            graphs.add(graph);
        }
        return graphs;
    }

    private List<Map<String,Object>> walkCalls(Function func, FunctionManager fm,
            ReferenceManager refMgr, int depth, Set<Address> visited) {
        if (depth <= 0 || func == null) return Collections.emptyList();

        Address addr = func.getEntryPoint();
        if (visited.contains(addr)) {
            Map<String,Object> node = new LinkedHashMap<>();
            node.put("name", func.getName());
            node.put("address", "0x" + addr.toString());
            node.put("recursive", true);
            return Collections.singletonList(node);
        }

        visited.add(addr);
        List<Map<String,Object>> children = new ArrayList<>();
        Set<Address> seenTargets = new HashSet<>();

        AddressSetView body = func.getBody();
        InstructionIterator instIter = currentProgram.getListing().getInstructions(body, true);
        while (instIter.hasNext()) {
            Instruction inst = instIter.next();
            Reference[] refs = refMgr.getReferencesFrom(inst.getAddress());
            for (Reference ref : refs) {
                if (!ref.getReferenceType().isCall()) continue;
                Function target = fm.getFunctionAt(ref.getToAddress());
                if (target == null) target = fm.getFunctionContaining(ref.getToAddress());
                if (target == null) continue;
                if (seenTargets.contains(target.getEntryPoint())) continue;
                seenTargets.add(target.getEntryPoint());

                Map<String,Object> child = new LinkedHashMap<>();
                child.put("name", target.getName());
                child.put("address", "0x" + target.getEntryPoint().toString());

                if (!target.isExternal() && depth > 1 && !visited.contains(target.getEntryPoint())) {
                    List<Map<String,Object>> sub = walkCalls(target, fm, refMgr, depth - 1, visited);
                    if (!sub.isEmpty()) {
                        child.put("calls", sub);
                    }
                }
                children.add(child);
            }
        }

        visited.remove(addr);
        return children;
    }

    private List<Map<String,Object>> decompileFunctions() {
        List<Map<String,Object>> summaries = new ArrayList<>();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        // Find functions that call dangerous APIs
        Set<Address> interesting = new HashSet<>();
        FunctionIterator extFuncs = fm.getExternalFunctions();
        while (extFuncs.hasNext()) {
            Function func = extFuncs.next();
            if (!DANGEROUS_APIS.contains(func.getName())) continue;
            ReferenceIterator refIter3 = refMgr.getReferencesTo(func.getEntryPoint());
            while (refIter3.hasNext()) {
                Reference ref = refIter3.next();
                Function caller = fm.getFunctionContaining(ref.getFromAddress());
                if (caller != null) interesting.add(caller.getEntryPoint());
            }
        }

        // Add entry points
        FunctionIterator allFuncs = fm.getFunctions(true);
        while (allFuncs.hasNext()) {
            Function func = allFuncs.next();
            if (ENTRY_NAMES.contains(func.getName())) {
                interesting.add(func.getEntryPoint());
            }
        }

        // Decompile
        DecompInterface decomp = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        decomp.setOptions(opts);
        decomp.openProgram(currentProgram);

        int count = 0;
        for (Address addr : interesting) {
            if (count >= 150) break;
            Function func = fm.getFunctionAt(addr);
            if (func == null || func.isExternal()) continue;

            DecompileResults result = decomp.decompileFunction(func, 30, monitor);
            String cCode = null;
            if (result != null && result.getDecompiledFunction() != null) {
                cCode = result.getDecompiledFunction().getC();
            }

            if (cCode != null && cCode.length() > 8000) {
                cCode = cCode.substring(0, 8000) + "\n// ... truncated ...";
            }

            Map<String,Object> entry = new LinkedHashMap<>();
            entry.put("name", func.getName());
            entry.put("address", "0x" + func.getEntryPoint().toString());
            entry.put("size", (int) func.getBody().getNumAddresses());
            entry.put("decompiled", cCode);
            summaries.add(entry);
            count++;
        }

        decomp.dispose();
        return summaries;
    }

    // Minimal JSON serialization
    private String escJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    @SuppressWarnings("unchecked")
    private String toJsonValue(Object val) {
        if (val == null) return "null";
        if (val instanceof String) return "\"" + escJson((String)val) + "\"";
        if (val instanceof Number) return val.toString();
        if (val instanceof Boolean) return val.toString();
        if (val instanceof List) return listToJson((List<Map<String,Object>>) val);
        if (val instanceof Map) return mapToJson((Map<String,Object>) val);
        return "\"" + escJson(val.toString()) + "\"";
    }

    private String mapToJson(Map<String,Object> map) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        boolean first = true;
        for (Map.Entry<String,Object> e : map.entrySet()) {
            if (!first) sb.append(", ");
            sb.append("\"").append(escJson(e.getKey())).append("\": ");
            sb.append(toJsonValue(e.getValue()));
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }

    private String listToJson(List<?> list) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        boolean first = true;
        for (Object item : list) {
            if (!first) sb.append(", ");
            if (item instanceof Map) {
                sb.append(mapToJson((Map<String,Object>) item));
            } else if (item instanceof String) {
                sb.append("\"").append(escJson((String)item)).append("\"");
            } else {
                sb.append(toJsonValue(item));
            }
            first = false;
        }
        sb.append("]");
        return sb.toString();
    }
}
