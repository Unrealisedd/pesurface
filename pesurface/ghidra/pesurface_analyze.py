# pesurface Ghidra headless analysis script
# Runs inside Ghidra's Jython environment via analyzeHeadless -postScript
#
# Outputs JSON to a file specified by the script argument:
#   analyzeHeadless ... -postScript pesurface_analyze.py /path/to/output.json
#
# The JSON contains:
#   - api_calls: traced dangerous API calls with resolved string arguments
#   - call_graph: call trees from entry points (ServiceMain, DriverEntry, etc.)
#   - functions: decompiled function summaries

import json
import os
import sys

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.symbol import SymbolType, RefType
from ghidra.program.model.listing import CodeUnit
from ghidra.util.task import ConsoleTaskMonitor

DANGEROUS_APIS = set([
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "CreateProcessA", "CreateProcessW", "CreateProcessAsUserA", "CreateProcessAsUserW",
    "CreateProcessWithLogonW", "CreateProcessWithTokenW",
    "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "WinExec", "system", "_wsystem",
    "ImpersonateNamedPipeClient", "ImpersonateLoggedOnUser",
    "SetThreadToken", "RpcImpersonateClient", "CoImpersonateClient",
    "CreateNamedPipeA", "CreateNamedPipeW",
    "ConnectNamedPipe",
    "MoveFileA", "MoveFileW", "MoveFileExA", "MoveFileExW",
    "CopyFileA", "CopyFileW", "CopyFileExA", "CopyFileExW",
    "DeleteFileA", "DeleteFileW",
    "ReplaceFileA", "ReplaceFileW",
    "CreateFileA", "CreateFileW",
    "CreateHardLinkA", "CreateHardLinkW",
    "CreateSymbolicLinkA", "CreateSymbolicLinkW",
    "RegCreateKeyExA", "RegCreateKeyExW",
    "RegSetValueExA", "RegSetValueExW",
    "RegOpenKeyExA", "RegOpenKeyExW",
    "CreateServiceA", "CreateServiceW",
    "ChangeServiceConfigA", "ChangeServiceConfigW",
    "CoCreateInstance", "CoCreateInstanceEx",
    "SetSecurityDescriptorDacl",
    "ConvertStringSecurityDescriptorToSecurityDescriptorA",
    "ConvertStringSecurityDescriptorToSecurityDescriptorW",
    "IoCreateDevice", "IoCreateDeviceSecure",
    "DeviceIoControl",
    "LogonUserA", "LogonUserW",
    "CredReadA", "CredReadW",
    "CryptUnprotectData",
    "RpcServerRegisterIf", "RpcServerRegisterIf2", "RpcServerRegisterIf3",
    "RpcServerRegisterIfEx",
    "SetNamedSecurityInfoA", "SetNamedSecurityInfoW",
    "NtCreateFile", "NtSetInformationFile",
])

ENTRY_POINT_NAMES = set([
    "ServiceMain", "SvcMain", "ServiceMainW", "ServiceMainA",
    "DriverEntry", "GsDriverEntry",
    "DllMain", "DllGetClassObject", "DllRegisterServer",
    "main", "wmain", "WinMain", "wWinMain",
    "entry",
])

monitor = ConsoleTaskMonitor()


def get_output_path():
    args = getScriptArgs()
    if args and len(args) > 0:
        return args[0]
    prog_name = currentProgram.getName().replace(".", "_")
    return os.path.join(os.path.expanduser("~"), "pesurface_%s.json" % prog_name)


def setup_decompiler():
    decomp = DecompInterface()
    opts = DecompileOptions()
    opts.setMaxPayloadMBytes(64)
    decomp.setOptions(opts)
    decomp.openProgram(currentProgram)
    return decomp


def decompile_function(decomp, func, timeout=30):
    result = decomp.decompileFunction(func, timeout, monitor)
    if result and result.depiledFunction():
        return result.getDecompiledFunction().getC()
    return None


def get_string_at(addr):
    """Try to read a string at the given address."""
    listing = currentProgram.getListing()
    data = listing.getDataAt(addr)
    if data is not None:
        val = data.getValue()
        if val is not None and isinstance(val, (str, unicode)):
            return val
    # Try reading raw bytes
    mem = currentProgram.getMemory()
    try:
        buf = []
        for i in range(512):
            b = mem.getByte(addr.add(i))
            if b == 0:
                break
            buf.append(chr(b & 0xFF))
        if len(buf) >= 2:
            return "".join(buf)
    except:
        pass
    return None


def resolve_string_arg(func, call_addr, arg_index):
    """Try to resolve a string argument at a call site using references."""
    listing = currentProgram.getListing()
    ref_mgr = currentProgram.getReferenceManager()

    # Walk backwards from call looking for string references
    inst = listing.getInstructionBefore(call_addr)
    checked = 0
    while inst and checked < 20:
        refs = ref_mgr.getReferencesFrom(inst.getAddress())
        for ref in refs:
            if ref.getReferenceType().isData():
                s = get_string_at(ref.getToAddress())
                if s and len(s) > 1:
                    return s
        inst = listing.getInstructionBefore(inst.getAddress())
        checked += 1
    return None


def trace_api_calls():
    """Find all calls to dangerous APIs and try to resolve their arguments."""
    results = []
    fm = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()
    listing = currentProgram.getListing()

    for func in fm.getExternalFunctions():
        name = func.getName()
        if name not in DANGEROUS_APIS:
            continue

        # Get all references to this function (call sites)
        refs = ref_mgr.getReferencesTo(func.getEntryPoint())
        for ref in refs:
            from_addr = ref.getFromAddress()
            caller_func = fm.getFunctionContaining(from_addr)
            caller_name = caller_func.getName() if caller_func else "unknown"

            # Try to resolve string arguments near the call
            resolved_args = []
            inst = listing.getInstructionBefore(from_addr)
            checked = 0
            while inst and checked < 15:
                for r in ref_mgr.getReferencesFrom(inst.getAddress()):
                    if r.getReferenceType().isData():
                        s = get_string_at(r.getToAddress())
                        if s and len(s) > 1 and len(s) < 512:
                            resolved_args.append(s)
                inst = listing.getInstructionBefore(inst.getAddress())
                checked += 1

            results.append({
                "api": name,
                "caller": caller_name,
                "address": "0x%x" % from_addr.getOffset(),
                "resolved_args": resolved_args[:5],
            })

    # Also check thunks / internal function wrappers
    for func in fm.getFunctions(True):
        name = func.getName()
        if name in DANGEROUS_APIS:
            refs = ref_mgr.getReferencesTo(func.getEntryPoint())
            for ref in refs:
                if not ref.getReferenceType().isCall():
                    continue
                from_addr = ref.getFromAddress()
                caller_func = fm.getFunctionContaining(from_addr)
                caller_name = caller_func.getName() if caller_func else "unknown"

                resolved_args = []
                inst = listing.getInstructionBefore(from_addr)
                checked = 0
                while inst and checked < 15:
                    for r in ref_mgr.getReferencesFrom(inst.getAddress()):
                        if r.getReferenceType().isData():
                            s = get_string_at(r.getToAddress())
                            if s and len(s) > 1 and len(s) < 512:
                                resolved_args.append(s)
                    inst = listing.getInstructionBefore(inst.getAddress())
                    checked += 1

                results.append({
                    "api": name,
                    "caller": caller_name,
                    "address": "0x%x" % from_addr.getOffset(),
                    "resolved_args": resolved_args[:5],
                })

    return results


def build_call_graph(max_depth=4):
    """Build call graphs from known entry points."""
    fm = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()
    graphs = []

    for func in fm.getFunctions(True):
        name = func.getName()
        if name not in ENTRY_POINT_NAMES:
            continue

        tree = _walk_calls(func, ref_mgr, fm, max_depth, set())
        graphs.append({
            "entry": name,
            "address": "0x%x" % func.getEntryPoint().getOffset(),
            "tree": tree,
        })

    # Also try the actual program entry point
    entry_addr = currentProgram.getSymbolTable().getPrimarySymbol(
        currentProgram.getMinAddress().getNewAddress(
            currentProgram.getExecutableFormat() and
            currentProgram.getAddressMap().getDefaultAddressSpace().getMinAddress().getOffset() or 0
        )
    )

    return graphs


def _walk_calls(func, ref_mgr, fm, depth, visited):
    if depth <= 0 or func is None:
        return []

    addr = func.getEntryPoint()
    if addr in visited:
        return [{"name": func.getName(), "address": "0x%x" % addr.getOffset(), "recursive": True}]

    visited.add(addr)
    children = []
    body = func.getBody()

    for addr_range in body:
        start = addr_range.getMinAddress()
        end = addr_range.getMaxAddress()
        cur = start
        while cur and cur.compareTo(end) <= 0:
            refs = ref_mgr.getReferencesFrom(cur)
            for ref in refs:
                if ref.getReferenceType().isCall():
                    target = fm.getFunctionAt(ref.getToAddress())
                    if target is None:
                        target = fm.getFunctionContaining(ref.getToAddress())
                    if target and target.getEntryPoint() not in visited:
                        tname = target.getName()
                        child = {
                            "name": tname,
                            "address": "0x%x" % target.getEntryPoint().getOffset(),
                        }
                        if not target.isExternal() and depth > 1:
                            sub = _walk_calls(target, ref_mgr, fm, depth - 1, visited)
                            if sub:
                                child["calls"] = sub
                        children.append(child)
            cur = cur.next()

    visited.discard(addr)
    return children


def get_function_summaries(decomp, limit=200):
    """Get decompiled summaries of interesting functions."""
    fm = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()
    summaries = []

    # Prioritize functions that call dangerous APIs
    interesting = set()
    for func in fm.getExternalFunctions():
        if func.getName() in DANGEROUS_APIS:
            for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
                caller = fm.getFunctionContaining(ref.getFromAddress())
                if caller:
                    interesting.add(caller.getEntryPoint())

    # Also add entry points
    for func in fm.getFunctions(True):
        if func.getName() in ENTRY_POINT_NAMES:
            interesting.add(func.getEntryPoint())

    count = 0
    for addr in interesting:
        if count >= limit:
            break
        func = fm.getFunctionAt(addr)
        if func is None or func.isExternal():
            continue

        result = decomp.decompileFunction(func, 30, monitor)
        c_code = None
        if result and result.getDecompiledFunction():
            c_code = result.getDecompiledFunction().getC()

        # Truncate very long decompilations
        if c_code and len(c_code) > 8000:
            c_code = c_code[:8000] + "\n// ... truncated ..."

        summaries.append({
            "name": func.getName(),
            "address": "0x%x" % func.getEntryPoint().getOffset(),
            "size": func.getBody().getNumAddresses(),
            "decompiled": c_code,
        })
        count += 1

    return summaries


def run():
    output_path = get_output_path()
    println("[pesurface] Starting analysis of %s" % currentProgram.getName())

    println("[pesurface] Tracing API calls...")
    api_calls = trace_api_calls()
    println("[pesurface] Found %d dangerous API call sites" % len(api_calls))

    println("[pesurface] Building call graphs from entry points...")
    call_graphs = build_call_graph()
    println("[pesurface] Built %d call graphs" % len(call_graphs))

    println("[pesurface] Decompiling interesting functions...")
    decomp = setup_decompiler()
    summaries = get_function_summaries(decomp)
    println("[pesurface] Decompiled %d functions" % len(summaries))
    decomp.dispose()

    result = {
        "program": currentProgram.getName(),
        "language": str(currentProgram.getLanguageID()),
        "api_calls": api_calls,
        "call_graphs": call_graphs,
        "functions": summaries,
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    println("[pesurface] Results written to %s" % output_path)


run()
